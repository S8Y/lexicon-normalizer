"""Lexicon Normalizer — no-op skeleton.

This plugin previously handled token replacement and restoration.
That functionality has been moved to a dedicated redaction plugin.
This skeleton remains for compatibility — it does nothing.
"""

from __future__ import annotations


class LexiconNormalizer:
    """No-op normalizer. Sanitization has been moved to a dedicated plugin."""

    def __init__(self) -> None:
        pass

    def sanitize_text(self, text: str) -> str:
        """Pass-through — no replacement performed here."""
        return text

    def restore_text(self, text: str) -> str:
        """Pass-through — no restoration performed here."""
        return text

    def reset(self) -> None:
        """No-op."""
        pass

    @property
    def token_count(self) -> int:
        return 0
