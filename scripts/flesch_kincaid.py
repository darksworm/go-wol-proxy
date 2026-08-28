#!/usr/bin/env python3
"""Report how hard a Markdown file is to read.

    pip install textstat
    python3 scripts/flesch_kincaid.py README.md

Grade level comes from `textstat`, which uses a real syllable dictionary
(pyphen) rather than counting vowels. The target is grade 9 or below; the
script exits non-zero above that, so CI can gate on it.

It also reports how much of the text is built from the 1000 most common
English words. A higher share is easier for people who do not speak English
as a first language. That list lives in scripts/top1000.txt and comes from
first20hours/google-10000-english, which is derived from Google's n-gram
frequency data.

Prose only: fenced code, inline code, tables, HTML, badges and link targets
are stripped first. Leaving them in inflates the score and tells you nothing
about how the writing reads.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

try:
    import textstat
except ImportError:
    sys.exit("textstat is not installed. Run: pip install textstat")

GRADE_TARGET = 9.0


def strip_markdown(text: str) -> str:
    """Remove everything that is not prose."""
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)  # fenced code
    text = re.sub(r"`[^`]*`", " ", text)  # inline code
    text = re.sub(r"^\s*\|.*$", " ", text, flags=re.MULTILINE)  # table rows
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", " ", text)  # images and badges
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links keep the label
    text = re.sub(r"<[^>]+>", " ", text)  # inline HTML
    # Headings and list items end a thought but carry no full stop. Give them one,
    # or they get glued to the next sentence and the score reads worse than it is.
    text = re.sub(r"^\s{0,3}#+\s*(.+?)\s*$", r"\1.", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*>\s?\[!\w+\]\s*$", "", text, flags=re.MULTILINE)  # alert tags
    text = re.sub(r"^\s*>\s?", "", text, flags=re.MULTILINE)  # quote markers
    text = re.sub(r"^\s*[-*+]\s+(.+?)\s*$", r"\1.", text, flags=re.MULTILINE)  # bullets
    text = re.sub(r"^\s*\d+\.\s+(.+?)\s*$", r"\1.", text, flags=re.MULTILINE)  # numbered
    text = re.sub(r"[*_~]", "", text)  # emphasis
    return text


def sentences(prose: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", prose)
    return [s.strip() for s in parts if s.strip()]


def words(text: str) -> list[str]:
    return re.findall(r"[A-Za-z][A-Za-z'-]*", text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=pathlib.Path)
    parser.add_argument(
        "--word-list",
        type=pathlib.Path,
        default=pathlib.Path(__file__).parent / "top1000.txt",
    )
    parser.add_argument(
        "--show",
        type=int,
        default=3,
        help="how many of the longest sentences to print (default 3)",
    )
    args = parser.parse_args()

    if not args.path.exists():
        return print(f"no such file: {args.path}") or 1

    prose = strip_markdown(args.path.read_text(encoding="utf-8"))
    all_words = words(prose)
    if not all_words:
        return print("no prose found") or 1

    grade = textstat.flesch_kincaid_grade(prose)
    ease = textstat.flesch_reading_ease(prose)
    found = sentences(prose)

    print(f"file                  {args.path}")
    print(f"sentences             {len(found)}")
    print(f"words                 {len(all_words)}")
    print(f"words per sentence    {len(all_words) / max(len(found), 1):.1f}")
    print(f"reading ease          {ease:.1f}  (higher is easier)")

    verdict = "OK" if grade <= GRADE_TARGET else "TOO HIGH"
    print(f"Flesch-Kincaid grade  {grade:.1f}  {verdict} (target: <= {GRADE_TARGET:g})")

    if args.word_list.exists():
        common = {
            line.strip().lower()
            for line in args.word_list.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        hits = sum(1 for w in all_words if w.lower() in common)
        share = 100.0 * hits / len(all_words)
        print(f"top-1000 word share   {share:.1f}%  (higher is friendlier to ESL readers)")
    else:
        print(f"top-1000 word share   skipped, no word list at {args.word_list}")

    if args.show:
        print(f"\nlongest {args.show} sentences:")
        longest = sorted(found, key=lambda s: len(words(s)), reverse=True)
        for sentence in longest[: args.show]:
            flat = re.sub(r"\s+", " ", sentence).strip()
            print(f"  [{len(words(sentence))} words] {flat}")

    return 0 if grade <= GRADE_TARGET else 1


if __name__ == "__main__":
    sys.exit(main())
