# Translation automation

English Markdown under `docs/` is the canonical documentation. Korean and Japanese mirrors are generated through the `Translate & Sync Docs` GitHub Actions workflow.

## Repository secret

Add an Actions repository secret named `OPENAI_API_KEY`. The workflow passes it to the translator only as an environment variable; the key is never written to the repository or wiki.

## Automatic mode

When canonical English Markdown under `docs/` changes on `main`, the workflow runs automatically with these defaults:

- language: `all` (`ko` and `ja`)
- scope: `changed`
- model: `gpt-5.6-sol`

Only documents changed since the last successful translation state are sent to the API. Deleted canonical pages have their translated counterparts removed.

## Manual mode

Open **Actions → Translate & Sync Docs → Run workflow**. The manual form supports:

- language: `all`, `ko`, or `ja`
- scope: `changed` or `all`
- model: `gpt-5.6-sol`, `gpt-5.6-terra`, or `gpt-5.6-luna`

Use `all` scope to regenerate every translation, for example after changing the translation style or switching models.

## Validation

Generated translations are rejected unless they preserve structural material from the English source, including fenced code blocks, inline code, URLs, Markdown link targets, heading levels, numeric values and percentages, commit/revision hashes, and table structure. A failed translation is retried up to three times and is not committed if validation still fails.

After successful translation, the workflow commits `docs/i18n/` updates to `main`, builds the multilingual wiki, and publishes the generated wiki pages in the same workflow run.

The English documentation remains authoritative if a generated translation ever disagrees with it.
