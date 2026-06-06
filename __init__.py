"""lexicon-normalizer — Hermes plugin stub.

This plugin previously managed token replacement and restoration
(placeholders like _VEN_<N>). That functionality has been moved to
a dedicated redaction plugin for clean separation of concerns.

This stub remains registered for compatibility. It does nothing.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _noop_reset(**kwargs) -> None:
    """No-op. Previously reset normalizer state."""
    pass


def register(ctx) -> None:
    """Register the lexicon-normalizer plugin (no-op)."""
    # No hooks are registered — all replacement logic has been removed.
    logger.info("Lexicon normalizer: plugin loaded (no-op — replacement disabled)")
