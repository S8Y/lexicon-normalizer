# Lexicon Normalizer (deprecated)

**Status:** No-op stub. All replacement/redaction logic has been removed.

This plugin previously handled token replacement and restoration
(placing user-specific vocabulary behind `_VEN_<N>` placeholders).

That functionality has been moved to a dedicated redaction plugin
for clean separation of concerns.

This stub remains registered for backward compatibility so existing
configs that reference `lexicon-normalizer` in their `plugins.enabled`
list don't break on upgrade.

## Migration

If your config enables `lexicon-normalizer`, replace it with the
new redaction plugin:

```yaml
plugins:
  enabled:
    - the-new-redaction-plugin-name
```

Then remove `lexicon-normalizer` from the list. The stub does nothing.
