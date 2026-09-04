# Translation policy

The English documentation under `docs/` is the canonical source of truth for LiberaCrypt.

Translations live under `docs/i18n/<language>/` and mirror the path of the English source they translate. For example:

```text
docs/design/portability.md
docs/i18n/ko/design/portability.md
docs/i18n/ja/design/portability.md
```

The wiki generator publishes every English Markdown document and publishes a translated counterpart only when the matching translation file exists. Links from a translated page fall back to the English wiki page when that target has not been translated yet.

The initial translated set intentionally focuses on the project overview, architecture, and portability. Additional pages can be translated incrementally without changing the wiki build system.

Translations should preserve technical meaning rather than mechanically mirror English sentence structure. If a translation and the English documentation disagree, the English documentation is authoritative.
