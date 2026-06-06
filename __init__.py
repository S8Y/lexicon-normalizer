"""lexicon-normalizer — Hermes plugin for token/lexicon management.

Prevents cross-prompt lexical persistence by replacing user-specific
vocabulary, identifiers, UUIDs, and rare tokens with canonical
``_VEN_<N>`` placeholders before prompts reach the LLM provider, and
restoring them in responses.

Each prompt is treated as a stateless lexical environment — no
word-frequency history or vocabulary carryover across prompts.

Architecture
------------
The plugin works by wrapping the low-level API-call functions in
``agent.chat_completion_helpers`` at registration time (same pattern as
``prompt-sanitizer``). This is the single choke point through which all
provider requests and responses flow.

In addition, the ``transform_llm_output`` hook provides belt-and-suspenders
restoration on the final assembled response text, and the ``pre_llm_call``
hook injects a brief context note so the LLM understands the placeholder
convention.

No changes to the conversation loop are required.
"""

from __future__ import annotations

import functools
import logging
import threading
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state — scoped per-process, never persisted
# ---------------------------------------------------------------------------

# Single normalizer instance shared across all sessions in the process.
# Reset on every API call (each prompt is stateless).
_normalizer = None
_normalizer_lock = threading.Lock()

# Whether the monkey-patch has been applied (idempotent)
_patch_applied = False
_patch_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Normalizer helpers
# ---------------------------------------------------------------------------


def _get_normalizer():
    """Return the process-global LexiconNormalizer instance.

    Lazy-imports the normalizer module so a missing dependency doesn't
    prevent the plugin from loading.
    """
    global _normalizer
    if _normalizer is not None:
        return _normalizer

    with _normalizer_lock:
        if _normalizer is not None:
            return _normalizer
        try:
            # Support both package loading (from .normalizer) and
            # direct file loading (importlib.spec_from_file_location)
            # where relative imports don't work.
            import sys as _sys
            from pathlib import Path as _Path
            _plugin_dir = str(_Path(__file__).resolve().parent)
            if _plugin_dir not in _sys.path:
                _sys.path.insert(0, _plugin_dir)

            from normalizer import LexiconNormalizer as _Cls

            _normalizer = _Cls()
            logger.debug("Lexicon normalizer: instance created")
        except ImportError:
            logger.warning(
                "Lexicon normalizer: normalizer module not available."
            )
            _normalizer = None
    return _normalizer


def _reset_normalizer():
    """Reset the normalizer between API calls (stateless per prompt)."""
    n = _get_normalizer()
    if n is not None:
        n.reset()


def _sanitize_messages(messages: List[Dict[str, Any]]) -> Dict[str, str]:
    """Sanitize *messages* in-place and return the placeholder->original map.

    Returns an empty dict if the normalizer is unavailable.
    """
    normalizer = _get_normalizer()
    if normalizer is None:
        return {}

    try:
        for msg in messages:
            for field in ("content", "tool_response", "function_call"):
                val = msg.get(field)
                if isinstance(val, str) and val.strip():
                    msg[field] = normalizer.sanitize_text(val)

        vault = dict(normalizer._placeholder_map)  # copy
        if vault:
            logger.debug(
                "Lexicon normalizer applied: %d token(s) normalised",
                len(vault),
            )
        return vault
    except Exception:
        logger.warning(
            "Lexicon normalisation failed, proceeding unnormalised",
            exc_info=True,
        )
        return {}


def _restore_text(text: str, vault: Dict[str, str]) -> str:
    """Restore placeholders in *text* using *vault*.

    The vault may be either ``original->placeholder`` (from
    ``_sanitize_messages``) or ``placeholder->original`` (from
    the normalizer's reverse map).  This function handles both
    by detecting the direction.
    """
    if not text or not vault:
        return text

    # Detect vault direction by examining an entry
    sample_key = next(iter(vault))
    sample_val = vault[sample_key]

    if sample_val.startswith("_VEN_"):
        # vault is original -> placeholder: reverse it
        placeholder_map = {v: k for k, v in vault.items()}
    else:
        # vault is placeholder -> original: use as-is
        placeholder_map = vault

    # Sort longest placeholder first to avoid partial replacement
    restored = text
    for placeholder, original in sorted(
        placeholder_map.items(), key=lambda x: (-len(x[0]), x[0])
    ):
        restored = restored.replace(placeholder, original)
    return restored


def _restore_response(response: Any, vault: Dict[str, str]) -> Any:
    """Restore placeholders in a response object."""
    if not vault:
        return response

    # Dict-like response (non-streaming)
    if isinstance(response, dict):
        for key in ("content", "text", "message", "response"):
            val = response.get(key)
            if isinstance(val, str) and val.strip():
                response[key] = _restore_text(val, vault)
        # Recursively handle nested choices/messages
        if isinstance(response.get("choices"), list):
            for choice in response["choices"]:
                if isinstance(choice, dict):
                    _restore_response(choice, vault)
        return response

    # String response
    if isinstance(response, str):
        return _restore_text(response, vault)

    return response


# ---------------------------------------------------------------------------
# Monkey-patch
# ---------------------------------------------------------------------------


def _make_sanitized_wrapper(original_func):
    """Wrap an API call function with pre-call sanitization + post-call restore.

    Handles both ``interruptible_api_call(agent, api_kwargs)`` and
    ``interruptible_streaming_api_call(agent, api_kwargs, ...)`` signatures.
    """

    @functools.wraps(original_func)
    def wrapper(agent, *args, **kwargs):
        # Reset normalizer for each API call — stateless per prompt
        _reset_normalizer()

        # Extract api_kwargs (first positional arg after `agent`)
        api_kwargs = args[0] if args else kwargs.get("api_kwargs", {})

        messages = api_kwargs.get("messages", [])
        vault: Dict[str, str] = {}

        # --- Pre-call: sanitize messages in-place ---
        if messages and isinstance(messages, list):
            vault = _sanitize_messages(messages)
            if vault:
                logger.debug(
                    "Lexicon normalizer: %d placeholders applied pre-call",
                    len(vault),
                )

        # --- Call original ---
        response = original_func(agent, *args, **kwargs)

        # --- Post-call: restore response ---
        if vault:
            try:
                response = _restore_response(response, vault)
                logger.debug(
                    "Lexicon normalizer: %d placeholders restored in response",
                    len(vault),
                )
            except Exception:
                logger.warning(
                    "Response restoration failed", exc_info=True
                )

        return response

    return wrapper


def _apply_patch() -> None:
    """Apply the monkey-patch to ``agent.chat_completion_helpers``.

    Idempotent — safe to call multiple times.
    """
    global _patch_applied
    with _patch_lock:
        if _patch_applied:
            return

        try:
            import agent.chat_completion_helpers as _helpers
        except ImportError:
            logger.warning(
                "Cannot patch API calls — agent.chat_completion_helpers "
                "not available.  Lexicon normalizer will only apply "
                "transform_llm_output hooks."
            )
            return

        _helpers.interruptible_api_call = _make_sanitized_wrapper(
            _helpers.interruptible_api_call
        )
        _helpers.interruptible_streaming_api_call = _make_sanitized_wrapper(
            _helpers.interruptible_streaming_api_call
        )
        _patch_applied = True
        logger.debug("Lexicon normalizer: patched API call functions")


# ---------------------------------------------------------------------------
# Plugin hooks
# ---------------------------------------------------------------------------


def _on_transform_llm_output(
    response_text: str = "",
    session_id: str = "",
    **kwargs,
) -> Optional[str]:
    """transform_llm_output hook — belt-and-suspenders restoration.

    The API-call wrapper already restores values in the raw response, but this
    hook fires on the final assembled response text and catches any stragglers
    that may have survived the API-level restoration.
    """
    if not response_text:
        return None

    normalizer = _get_normalizer()
    if normalizer is None:
        return None

    vault = getattr(normalizer, "_reverse_map", {})
    if not vault:
        return None

    restored = _restore_text(response_text, vault)
    if restored == response_text:
        return None  # No change
    return restored


def _on_pre_llm_call(
    session_id: str = "",
    user_message: str = "",
    conversation_history: list = None,
    is_first_turn: bool = False,
    **kwargs,
) -> Optional[Dict[str, str]]:
    """Pre_llm_call hook — inject context explaining the placeholder system.

    Tells the LLM that ``_VEN_<N>`` placeholders represent real user-defined
    tokens and should be treated as such.
    """
    if not is_first_turn:
        return None

    normalizer = _get_normalizer()
    if normalizer is None:
        return None

    return {
        "context": (
            "[LEXICON NOTICE] This conversation uses an automated lexicon "
            "management layer that replaces user-specific vocabulary, "
            "identifiers, and rare tokens with canonical placeholders "
            "like _VEN_1, _VEN_2, _VEN_3 before sending prompts to the "
            "AI provider. When you see these placeholders in the "
            "conversation, treat them as the original tokens they "
            "represent. All original values are restored in the model's "
            "responses before they reach the user."
        )
    }


def _on_session_end(**kwargs) -> None:
    """Reset the normalizer state when the session ends."""
    _reset_normalizer()


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------


def register(ctx) -> None:
    """Register the lexicon-normalizer plugin.

    Called once by the Hermes plugin system during startup.
    """
    # 1. Patch API-call functions so messages are sanitized before they
    #    reach any provider and restored after the response arrives.
    _apply_patch()

    # 2. Register the transform hook for the display-text layer.
    ctx.register_hook("transform_llm_output", _on_transform_llm_output)

    # 3. Register the pre-call hook so the LLM is informed about placeholders.
    ctx.register_hook("pre_llm_call", _on_pre_llm_call)

    # 4. On session end, clear the normalizer state.
    ctx.register_hook("on_session_end", _on_session_end)

    logger.info("Lexicon normalizer: plugin registered")
