#!/usr/bin/env python3
"""Build the LiberaCrypt GitHub Wiki from repository Markdown documentation."""

from __future__ import annotations

import argparse
import os
import posixpath
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
I18N = DOCS / "i18n"

LANGUAGES = {
    "en": {"prefix": "EN", "label": "English", "root": DOCS},
    "ko": {"prefix": "KO", "label": "한국어", "root": I18N / "ko"},
    "ja": {"prefix": "JA", "label": "日本語", "root": I18N / "ja"},
}

MARKDOWN_LINK_RE = re.compile(r"(\[[^\]]+\]\()([^)#\s]+\.md)(#[^)]+)?(\))")


def canonical_paths() -> list[Path]:
    paths: list[Path] = []
    for path in DOCS.rglob("*.md"):
        rel = path.relative_to(DOCS)
        if rel.parts and rel.parts[0] == "i18n":
            continue
        paths.append(rel)
    return sorted(paths, key=lambda p: p.as_posix().lower())


def page_name(language: str, rel: Path) -> str:
    prefix = str(LANGUAGES[language]["prefix"])
    if rel == Path("README.md"):
        return f"{prefix}-Home"
    stem = rel.with_suffix("").as_posix().replace("/", "-")
    return f"{prefix}-{stem}"


def translation_exists(language: str, rel: Path) -> bool:
    root = Path(LANGUAGES[language]["root"])
    return (root / rel).is_file()


def language_bar(rel: Path) -> str:
    links: list[str] = []
    for language, info in LANGUAGES.items():
        if translation_exists(language, rel):
            links.append(f"[{info['label']}]({page_name(language, rel)})")
    return " · ".join(links)


def translation_notice(language: str) -> str:
    if language == "ko":
        return (
            "> 이 페이지는 영어 원문을 바탕으로 한 번역입니다. "
            "번역과 영어 문서의 내용이 다를 경우 영어 문서를 기준으로 합니다."
        )
    if language == "ja":
        return (
            "> このページは英語の原文をもとにした翻訳です。"
            "翻訳と英語文書の内容が異なる場合は、英語文書を正とします。"
        )
    return "> Canonical source: the English Markdown documentation in the main repository."


def resolve_doc_target(current_rel: Path, target: str) -> Path | None:
    if "://" in target or target.startswith(("mailto:", "#", "/")):
        return None
    normalized = posixpath.normpath(posixpath.join(current_rel.parent.as_posix(), target))
    if normalized == ".." or normalized.startswith("../"):
        return None
    return Path(normalized)


def rewrite_links(
    text: str,
    language: str,
    current_rel: Path,
    canonical: set[Path],
    repository: str,
) -> str:
    def replace(match: re.Match[str]) -> str:
        before, target, anchor, after = match.groups()
        resolved = resolve_doc_target(current_rel, target)

        if resolved is not None and resolved in canonical:
            target_language = language if translation_exists(language, resolved) else "en"
            wiki_target = page_name(target_language, resolved)
            return f"{before}{wiki_target}{anchor or ''}{after}"

        normalized = posixpath.normpath(
            posixpath.join("docs", current_rel.parent.as_posix(), target)
        )
        if not normalized.startswith("docs/"):
            repo_target = f"https://github.com/{repository}/blob/main/{normalized}"
            return f"{before}{repo_target}{anchor or ''}{after}"

        return match.group(0)

    return MARKDOWN_LINK_RE.sub(replace, text)


def render_page(
    language: str,
    rel: Path,
    canonical: set[Path],
    repository: str,
) -> str:
    source = Path(LANGUAGES[language]["root"]) / rel
    body = source.read_text(encoding="utf-8").strip()
    body = rewrite_links(body, language, rel, canonical, repository)
    header = language_bar(rel)
    notice = translation_notice(language)
    return f"{header}\n\n{notice}\n\n{body}\n"


def render_home() -> str:
    return """# LiberaCrypt Wiki

This wiki is generated from the documentation tracked in the main LiberaCrypt repository.

## Language

- [English](EN-Home)
- [한국어](KO-Home)
- [日本語](JA-Home)

English is the canonical documentation. Korean and Japanese pages are maintained as translations and may cover a smaller set of topics while translation work is in progress.

## Source of truth

Documentation changes are reviewed in the main repository. After they are merged to `main`, the wiki synchronization workflow republishes the generated pages automatically.
"""


def render_sidebar() -> str:
    return """**LiberaCrypt**

- [Wiki Home](Home)
- [English](EN-Home)
- [한국어](KO-Home)
- [日本語](JA-Home)

---

- [Repository](https://github.com/samdae5back/LiberaCrypt)
- [README](https://github.com/samdae5back/LiberaCrypt/blob/main/README.md)
"""


def render_footer() -> str:
    return (
        "Generated from the LiberaCrypt repository documentation. "
        "English documentation is canonical."
    )


def build(output: Path) -> None:
    repository = os.environ.get("GITHUB_REPOSITORY", "samdae5back/LiberaCrypt")
    canonical_list = canonical_paths()
    canonical = set(canonical_list)

    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    for rel in canonical_list:
        for language in LANGUAGES:
            if not translation_exists(language, rel):
                continue
            target = output / f"{page_name(language, rel)}.md"
            target.write_text(
                render_page(language, rel, canonical, repository),
                encoding="utf-8",
            )

    (output / "Home.md").write_text(render_home(), encoding="utf-8")
    (output / "_Sidebar.md").write_text(render_sidebar(), encoding="utf-8")
    (output / "_Footer.md").write_text(render_footer() + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.output.resolve())


if __name__ == "__main__":
    main()
