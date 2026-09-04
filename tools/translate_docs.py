#!/usr/bin/env python3
"""Translate canonical LiberaCrypt Markdown with the OpenAI Responses API."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
I18N = DOCS / "i18n"
STATE_PATH = I18N / ".translation-state.json"
API_URL = "https://api.openai.com/v1/responses"

LANGUAGES = {
    "ko": {
        "name": "Korean",
        "style": (
            "Write fluent, professional Korean used in well-edited open-source technical "
            "documentation. Avoid literal translationese and awkward English/Korean code-switching. "
            "Use established Korean cryptography and systems terminology when natural, while keeping "
            "precise English terms where Korean usage would be less clear."
        ),
    },
    "ja": {
        "name": "Japanese",
        "style": (
            "Write fluent, professional Japanese used in well-edited open-source technical "
            "documentation. Avoid literal translationese and unnecessary English/Japanese mixing. "
            "Use established Japanese cryptography and systems terminology when natural, while keeping "
            "precise English terms where Japanese usage would be less clear."
        ),
    },
}

FENCE_RE = re.compile(r"(^```[^\n]*\n.*?^```\s*$)", re.MULTILINE | re.DOTALL)
INLINE_CODE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
URL_RE = re.compile(r"https?://[^\s)>]+")
LINK_TARGET_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+", re.MULTILINE)
NUMBER_RE = re.compile(r"(?<![\w])(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?%?)(?![\w])")
HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9a-f]{7,40}(?![0-9A-Fa-f])")


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def head_sha() -> str:
    return run_git("rev-parse", "HEAD")


def canonical_paths() -> list[Path]:
    paths: list[Path] = []
    for path in DOCS.rglob("*.md"):
        rel = path.relative_to(DOCS)
        if rel.parts and rel.parts[0] == "i18n":
            continue
        paths.append(rel)
    return sorted(paths, key=lambda p: p.as_posix().lower())


def source_digest(rel: Path) -> str:
    return hashlib.sha256((DOCS / rel).read_bytes()).hexdigest()


def load_state() -> dict:
    if not STATE_PATH.is_file():
        return {"version": 1, "languages": {}}
    data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("languages"), dict):
        raise RuntimeError(f"Unsupported translation state format: {STATE_PATH}")
    return data


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def changed_since(base: str | None) -> set[Path]:
    canonical = set(canonical_paths())
    if not base:
        return canonical
    try:
        output = run_git("diff", "--name-only", f"{base}..HEAD", "--", "docs")
    except subprocess.CalledProcessError:
        return canonical

    changed: set[Path] = set()
    for line in output.splitlines():
        if not line.startswith("docs/"):
            continue
        rel = Path(line).relative_to("docs")
        if rel.parts and rel.parts[0] == "i18n":
            continue
        if rel.suffix == ".md" and rel in canonical:
            changed.add(rel)
    return changed


def selected_paths(language: str, scope: str, state: dict) -> list[Path]:
    all_paths = canonical_paths()
    if scope == "all":
        return all_paths

    language_state = state.get("languages", {}).get(language, {})
    changed = changed_since(language_state.get("source_commit"))
    for rel in all_paths:
        if not (I18N / language / rel).is_file():
            changed.add(rel)
    return sorted(changed, key=lambda p: p.as_posix().lower())


def multiset(values: list[str]) -> collections.Counter[str]:
    return collections.Counter(values)


def table_signature(text: str) -> list[int]:
    signature: list[int] = []
    in_fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            signature.append(stripped.count("|"))
    return signature


def validate_translation(source: str, translated: str) -> list[str]:
    errors: list[str] = []
    if FENCE_RE.findall(source) != FENCE_RE.findall(translated):
        errors.append("fenced code blocks changed")
    if multiset(INLINE_CODE_RE.findall(source)) != multiset(INLINE_CODE_RE.findall(translated)):
        errors.append("inline-code spans changed")
    if multiset(URL_RE.findall(source)) != multiset(URL_RE.findall(translated)):
        errors.append("URLs changed")
    if multiset(LINK_TARGET_RE.findall(source)) != multiset(LINK_TARGET_RE.findall(translated)):
        errors.append("Markdown link targets changed")
    if HEADING_RE.findall(source) != HEADING_RE.findall(translated):
        errors.append("heading levels/count changed")
    if multiset(NUMBER_RE.findall(source)) != multiset(NUMBER_RE.findall(translated)):
        errors.append("numeric literals or percentages changed")
    if multiset(HASH_RE.findall(source)) != multiset(HASH_RE.findall(translated)):
        errors.append("commit/revision hashes changed")
    if table_signature(source) != table_signature(translated):
        errors.append("Markdown table structure changed")
    if len(translated.strip()) < max(80, int(len(source.strip()) * 0.45)):
        errors.append("translation is unexpectedly short")
    return errors


def instructions_for(language: str) -> str:
    info = LANGUAGES[language]
    return f"""You translate LiberaCrypt cryptography-library documentation from English to {info['name']}.

{info['style']}

Requirements:
- Translate the complete document faithfully. Do not summarize, omit, expand, or add commentary.
- Preserve Markdown structure and ordering.
- Preserve fenced code blocks byte-for-byte, including fence language tags and code contents.
- Preserve every inline-code span exactly, including API names, C identifiers, macros, file paths, commands, mathematical snippets, and configuration names.
- Preserve every URL and every Markdown link target exactly. Link text may be translated.
- Preserve all numbers, percentages, benchmark values, hexadecimal constants, commit hashes, run IDs, parameter names, and mathematical expressions exactly.
- Preserve table row/column structure.
- Keep algorithm and standards names such as AES-GCM, ML-KEM, RFC 8017, C11, Montgomery, Barrett, Karatsuba, ECDSA, and Ed25519 precise.
- Prefer natural technical prose over word-for-word translation. The result should read as if originally written by a technically fluent native speaker.
- Return only the translated Markdown document, with no surrounding explanation or code fence.
"""


def api_response_text(payload: dict) -> str:
    pieces: list[str] = []
    for item in payload.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                pieces.append(content["text"])
    if not pieces:
        raise RuntimeError("OpenAI response did not contain output text")
    return "".join(pieces)


def call_openai(api_key: str, model: str, language: str, source: str,
                previous_errors: list[str] | None = None) -> str:
    input_text = source
    if previous_errors:
        input_text = (
            "The previous translation failed structural validation for these reasons: "
            + "; ".join(previous_errors)
            + ". Correct those issues while translating the complete source below.\n\n"
            + source
        )

    body = {
        "model": model,
        "instructions": instructions_for(language),
        "input": input_text,
        "reasoning": {"effort": "low"},
        "max_output_tokens": 32768,
        "store": False,
    }
    encoded = json.dumps(body).encode("utf-8")
    last_error: Exception | None = None

    for attempt in range(1, 4):
        request = urllib.request.Request(
            API_URL,
            data=encoded,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                payload = json.loads(response.read().decode("utf-8"))
            return api_response_text(payload).strip() + "\n"
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            last_error = RuntimeError(f"OpenAI API HTTP {exc.code}: {body_text[:1200]}")
            if exc.code < 500 and exc.code != 429:
                raise last_error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
            last_error = exc
        if attempt < 3:
            time.sleep(2 ** attempt)

    raise RuntimeError(f"OpenAI API request failed after retries: {last_error}")


def translate_one(api_key: str, model: str, language: str, rel: Path) -> None:
    source = (DOCS / rel).read_text(encoding="utf-8")
    errors: list[str] | None = None
    for attempt in range(1, 4):
        translated = call_openai(api_key, model, language, source, errors)
        errors = validate_translation(source, translated)
        if not errors:
            target = I18N / language / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(translated, encoding="utf-8")
            print(f"[{language}] {rel.as_posix()} translated with {model}")
            return
        print(
            f"[{language}] {rel.as_posix()} validation failed "
            f"(attempt {attempt}/3): {', '.join(errors)}",
            file=sys.stderr,
        )
    raise RuntimeError(
        f"Translation validation failed for {language}/{rel.as_posix()}: "
        + ", ".join(errors or [])
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--language", choices=["all", "ko", "ja"], default="all")
    parser.add_argument("--scope", choices=["changed", "all"], default="changed")
    parser.add_argument("--model", default="gpt-5.6-sol")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise SystemExit("OPENAI_API_KEY is not set")

    languages = list(LANGUAGES) if args.language == "all" else [args.language]
    state = load_state()
    current_head = head_sha()
    work = {language: selected_paths(language, args.scope, state) for language in languages}
    total = sum(len(paths) for paths in work.values())

    if total == 0:
        print("Translations are already up to date.")
        return

    print(
        f"Translation plan: {total} document(s), model={args.model}, "
        f"scope={args.scope}, languages={','.join(languages)}"
    )

    for language in languages:
        for rel in work[language]:
            translate_one(api_key, args.model, language, rel)

        language_state = state.setdefault("languages", {}).setdefault(language, {})
        language_state["source_commit"] = current_head
        language_state["model"] = args.model
        language_state["source_tree_digest"] = hashlib.sha256(
            "\n".join(
                f"{rel.as_posix()}:{source_digest(rel)}" for rel in canonical_paths()
            ).encode("utf-8")
        ).hexdigest()

    save_state(state)


if __name__ == "__main__":
    main()
