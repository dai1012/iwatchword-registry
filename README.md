# iwatchword-registry

Public registry for iWatchWord composable skills. Policies live here.

## Structure

- `registry.json` — root index
- `skills/index.json` — skill inventory
- `skills/*.json` — declarative SkillDefinition (content/constraint), no executable code
- `providers/` `models/` — reserved, not implemented in v1

Bundled fallback lives in App. Remote is primary with LKG.

Raw URL (via configuration boundary, not hard-coded in Swift business code):
`https://raw.githubusercontent.com/dai1012/iwatchword-registry/main/registry.json`
