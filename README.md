# Lexicon Normalizer

Analysis-only token/lexicon management plugin for Hermes Agent.

Provides the `LexiconNormalizer` class for detecting rare tokens, UUIDs,
code identifiers, hashes, emails, and long-form tokens in prompt text.
**Does not modify text** — use alongside a dedicated redaction plugin
for placeholder substitution.

## Quick Start

```yaml
# config.yaml
plugins:
  enabled:
    - lexicon-normalizer
```

The plugin registers a no-op entry point. The `LexiconNormalizer` class
is available for import from other code:

```python
from plugins.lexicon_normalizer.normalizer import LexiconNormalizer

n = LexiconNormalizer()
report = n.analyze_text("Lookup 550e8400-e29b-41d4-a716-446655440000")
# report["uuids"] -> ["550e8400-e29b-41d4-a716-446655440000"]
# report["rare_words"] -> []
```

## Features

- **UUID/GUID detection** — hex UUID patterns
- **Hash detection** — 32+ character hex strings
- **Long token detection** — tokens >= 40 chars (potential secrets/keys)
- **Code identifier detection** — camelCase, PascalCase, snake_case
- **Rare word detection** — words >= 8 chars not in the safe lexicon
- **Derived-form checking** — handles inflected English (-tion, -sion,
  -ment, -able, -ity, -ive, -ness, -al, -ic, -ous, -ful, -less, -ist,
  -ism, -ize, -ance, -ence, -er, -est, -th, and more)
- **Safe lexicon** — ~2,000 common English words + programming keywords
  + tech/tool names + SQL + HTML/CSS
- **Acronym safety** — 100+ common acronyms (API, JSON, SQL, etc.)
- **Code-block protection** — tokens inside ```...``` and `...` are
  excluded from analysis
- **Bracket protection** — tokens inside `[...]`, `(...)`, and `{...}`
  are excluded from analysis

## API

| Method | Description |
|---|---|
| `sanitize_text(text)` | Pass-through (no modification) |
| `restore_text(text)` | Pass-through (no modification) |
| `reset()` | No-op |
| `analyze_text(text)` | Returns `Dict[str, List[str]]` with detected tokens by category |
| `is_safe_word(token)` | Check if a token is in the safe lexicon or a known derivation |

`analyze_text()` returns a dict with keys: `emails`, `uuids`, `hashes`,
`long_tokens`, `identifiers`, `rare_words`.

## Configuration

No configuration needed. The class accepts optional constructor params:

```python
LexiconNormalizer(max_token_length=40, min_rare_word=8)
```

## License

MIT
