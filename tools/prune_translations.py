#!/usr/bin/env python3
"""Remove translation Markdown files whose canonical English source no longer exists."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
I18N = DOCS / "i18n"


def canonical_paths() -> set[Path]:
    result: set[Path] = set()
    for path in DOCS.rglob("*.md"):
        rel = path.relative_to(DOCS)
        if rel.parts and rel.parts[0] == "i18n":
            continue
        result.add(rel)
    return result


def main() -> None:
    canonical = canonical_paths()
    for language in ("ko", "ja"):
        root = I18N / language
        if not root.is_dir():
            continue
        for path in root.rglob("*.md"):
            rel = path.relative_to(root)
            if rel not in canonical:
                print(f"Removing orphaned translation: {language}/{rel.as_posix()}")
                path.unlink()


if __name__ == "__main__":
    main()
