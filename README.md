# lexicon-normalizer

A self-contained Hermes Agent plugin for token/lexicon management.

Prevents cross-prompt lexical persistence by treating each prompt as a
stateless lexical environment. Replaces user-specific vocabulary,
identifiers, UUIDs, and rare tokens with canonical `_VEN_<N>` placeholders
before they reach the LLM. Restores originals in responses.
No external models, no memory, no state shared between prompts.

## Quick start

Clone the repo into your Hermes `plugins/` directory:

```bash
cd /path/to/hermes/plugins
git clone https://github.com/your-org/lexicon-normalizer.git
```

Enable in your Hermes profile config:

```yaml
# ~/.hermes/profiles/default/config.yaml
plugins:
  enabled:
    - lexicon-normalizer
```

That's it. The plugin automatically monkey-patches the LLM API calls
at startup and handles all sanitisation and restoration transparently.

## File layout

```
lexicon-normalizer/
├── README.md               # this file
├── plugin.yaml             # manifest (name, version, hooks)
├── __init__.py             # plugin registration + monkey-patching
└── normalizer.py           # core LexiconNormalizer class
```

Everything lives inside this directory. Drop it in `plugins/` and it works.

## Features

- **UUID detection** — replaces `550e8400-e29b-41d4-a716-446655440000`
  patterns with placeholders
- **camelCase / PascalCase / snake_case** — normalises user-defined
  identifiers like `myCustomVar`, `MyCustomClass`, `my_custom_var`
- **Rare-word detection** — flags tokens >=8 chars not in the safe
  lexicon as candidate user-specific vocabulary
- **Long-token detection** — catches tokens >=40 chars (API keys,
  JWTs, long hashes)
- **Derived-form checking** — recognises inflected English words
  (-tion, -ness, -ity, -ful, -ment, -al, -ive, -ist, -ism, -ize,
  -ly, -able, -ify, -ation, -ification, y→i→ness, etc.) and keeps
  them intact
- **Safe lexicons** — ~2000 common English words + 500 programming
  terms + 80 safe acronyms
- **Stateless per prompt** — `reset()` between every API call; no
  word-frequency history persists
- **Syntax integrity** — never touches programming language keywords,
  operators, SQL syntax, or structural code
- **Zero dependencies** — pure Python stdlib only (re, typing, logging)

## How it works

```
User prompt ──→ monkey-patched API wrapper ──→ LLM provider
                    │
                    ├── pre-call: reset normalizer → sanitize messages
                    │              (replace identifiers/UUIDs/rare tokens
                    │               with _VEN_<N> placeholders)
                    │
                    ├── call original API
                    │
                    └── post-call: restore placeholders in response
                                  (belt-and-suspenders via
                                   transform_llm_output hook)

Three hooks:
  - pre_llm_call       — inject notice about _VEN_ placeholders
  - transform_llm_output — final restoration on display text
  - on_session_end     — reset normalizer state
```

## What stays, what gets replaced

**Preserved:**
- ~2000 common English words and their inflected forms
- ~500 programming terms (function, class, import, async, await, etc.)
- ~80 safe acronyms (API, JSON, UUID, SQL, HTTP, etc.)
- Programming language keywords, operators, syntax
- Short tokens (< 8 chars for rare words)
- Tokens containing digits (unless mostly non-digit)

**Replaced:**
- UUIDs (hex patterns matching 8-4-4-4-12 format)
- camelCase, PascalCase, snake_case identifiers
- Tokens >= 40 chars (likely secrets/keys/hashes)
- Words >= 8 chars not in the safe lexicon and not recognisable
  as derived English forms

## Testing

```bash
python3 plugins/lexicon-normalizer/normalizer.py

# Expected output:
#   PASS: ...
#   PASS: ...
#   Results: 19 passed, 0 failed
```

## License

MIT
