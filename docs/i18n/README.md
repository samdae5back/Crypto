# Translation policy

The English documentation under `docs/` is the canonical source of truth for LiberaCrypt.

Translations live under `docs/i18n/<language>/` and mirror the path of the English source they translate. Korean and Japanese currently mirror the complete canonical document set.

Translations are maintained by the `Translate & Sync Docs` GitHub Actions workflow. The default automatic path uses `gpt-5.6-sol`, translates only canonical documents changed since the last successful translation state, validates preserved technical structure, commits accepted translations, and republishes the Wiki in the same workflow run.

For setup and manual reruns, see [Translation automation](AUTOMATION.md).

Generated translations should preserve technical meaning rather than mechanically mirror English sentence structure. If a translation and the English documentation disagree, the English documentation is authoritative.
