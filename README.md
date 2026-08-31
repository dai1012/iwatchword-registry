# iwatchword-registry

Public registry for iWatchWord composable skills and AI provider/model declarations. Policies live here.

## Structure

- `registry.json` — root manifest (version, updatedAt, indexes)
- `skills/index.json` — skill inventory (id, version, kind, path)
- `skills/*.json` — declarative SkillDefinition (content/constraint), no executable code
- `providers/index.json` — provider inventory (id, path)
- `providers/deepseek.json` — DeepSeek provider definition (openai-compatible)
- `models/index.json` — model inventory (id, path)
- `models/deepseek-v4-flash.json` — DeepSeek V4 Flash model definition
- `scripts/validate_registry.py` — registry validator (stdlib only)
- `.github/workflows/validate-registry.yml` — CI validation on pull_request + push(main)

Bundled fallback lives in App. Remote is primary with LKG.

Raw URL (via configuration boundary, not hard-coded in Swift business code):
`https://raw.githubusercontent.com/dai1012/iwatchword-registry/main/registry.json`

## Contract

- `registry.json` fields: `version` (int >=1, current 2), `registry`, `skillsIndex`, `providersIndex`, `modelsIndex`, `updatedAt` (contains 2026-09-01)
- All index files (`skills/index.json`, `providers/index.json`, `models/index.json`) are JSON objects with `version >=1` and non-empty entry lists
- Entry `path` is relative to registry root, must not be absolute, must not contain `..`, backslash `\`, or `//`
- Entry `id` is non-empty, unique within its index, and must equal the referenced definition's `id`
- All JSON files are objects (not arrays) and non-empty; version fields are integers >=1
- **Provider** (`providers/*.json`) camelCase schema: `id` (string), `displayName` (string), `protocolFamily` (`openai-compatible`), `endpoint` (https URL, host exactly `api.deepseek.com`), `enabled` (bool), `isDefault` (bool), `supportedModelIds` (non-empty string array)
- **Model** (`models/*.json`) schema: `id` (string), `providerId` (string, must reference existing enabled provider), `displayName` (string), `enabled` (bool), `isDefault` (bool), `capabilities` (string array)
- Enabled model must only reference an enabled provider; `supportedModelIds` and model inventory are bidirectionally consistent (`provider.supportedModelIds` ↔ `model.providerId`)
- No JSON key (recursively) may contain `executable`, `script`, `command`, `shell`, or `binary` (case-insensitive)
- Required inventory: provider `deepseek` (`enabled: true`, `isDefault: true`) and model `deepseek-v4-flash` (`enabled: true`, `isDefault: true`, `providerId: deepseek`) must exist
- Provider endpoint host whitelist is strictly `api.deepseek.com` (https, no userinfo, no percent-encoding); trust decision lives in App (`ProviderTrustPolicy`)

## Validation

Local checkout validation (default and explicit root):

```bash
python3 scripts/validate_registry.py --root .
python3 scripts/validate_registry.py
python3 scripts/validate_registry.py --root /path/to/checkout
```

Online recursive fetch validation:

```bash
python3 scripts/validate_registry.py --base-url https://raw.githubusercontent.com/dai1012/iwatchword-registry/main
python3 scripts/validate_registry.py --base-url https://raw.githubusercontent.com/dai1012/iwatchword-registry/main/registry.json
```

The validator checks: referenced paths exist / HTTP 200 + non-empty, JSON object, version >=1, path traversal guards, entry ID uniqueness and id consistency, Provider/Model required camelCase fields, protocolFamily, https + exact host, bool types, supportedModelIds non-empty, providerId existence, enabled checks, bidirectional `supportedModelIds` ↔ inventory, forbidden executable keys, and required DeepSeek/V4 presence. It prints `PASS` on success and `FAIL` with details on failure (exit 1).
