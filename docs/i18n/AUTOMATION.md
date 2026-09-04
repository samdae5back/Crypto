# Translation automation

English Markdown under `docs/` is the canonical documentation. Korean and Japanese mirrors are generated through the `Translate & Sync Docs` GitHub Actions workflow.

## Environment secret

Create a GitHub Actions environment named `docs-translation` and store `OPENAI_API_KEY` as an environment secret there. The translation job declares that environment explicitly and receives the key only for the API-calling steps.

The translation job has read-only repository permissions. A separate proposal job, which never receives `OPENAI_API_KEY`, has the write permissions needed to update the bot-managed translation branch and open a pull request.

## Automatic mode

When canonical English Markdown under `docs/` changes on `main`, the workflow runs automatically with these defaults:

- language: `all` (`ko` and `ja`)
- scope: `changed`
- model: `gpt-5.6-sol`

Only documents changed since the last successful translation state are sent to the API. Deleted canonical pages have their translated counterparts removed.

If the `docs-translation` environment uses required reviewers, GitHub waits for the environment approval before the translation job receives its secret.

## Manual mode

Open **Actions → Translate & Sync Docs → Run workflow** and run it from the `main` branch. The workflow refuses to translate when dispatched from another branch.

The manual form supports:

- language: `all`, `ko`, or `ja`
- scope: `changed` or `all`
- model: `gpt-5.6-sol`, `gpt-5.6-terra`, or `gpt-5.6-luna`

Use `all` scope to regenerate every translation, for example after changing the translation style or switching models.

## Validation

Generated translations are rejected unless they preserve structural material from the English source, including fenced code blocks, inline code, URLs, Markdown link targets, heading levels, numeric values and percentages, commit/revision hashes, and table structure. A failed translation is retried up to three times and is not proposed if validation still fails.

## Pull request and Wiki publication

Successful translation changes are packaged as a short-lived workflow artifact. A second job checks out the same `main` revision, applies the generated `docs/i18n/` tree, and updates the bot-managed `automation/docs-translations` branch.

The workflow creates a pull request from that branch, or updates the existing open translation pull request when one already exists. It never pushes generated translations directly to `main`.

After the translation pull request is reviewed and merged, the separate `Wiki Sync` workflow sees the `docs/i18n/**` change on `main`, rebuilds the multilingual Wiki, and publishes it.

The English documentation remains authoritative if a generated translation ever disagrees with it.
