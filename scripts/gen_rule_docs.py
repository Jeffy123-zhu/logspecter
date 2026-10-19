#!/usr/bin/env python3
"""Generate the rule catalog (Markdown) from the built-in rule packs.

Usage:
    python scripts/gen_rule_docs.py --out docs/rule-catalog
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

from logspecter.rules import load_ruleset


def esc_cell(value: object) -> str:
    """Make a value safe for a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _val(obj: object) -> str:
    """Enums (severity, confidence) expose .value; plain values pass through."""
    return str(getattr(obj, "value", obj))


def _fence(text: str) -> str:
    """A code fence longer than any backtick run inside text."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _sorted_rules(ruleset) -> list:
    return sorted(ruleset, key=lambda r: (r.pack, r.id))


def render_index(rules) -> str:
    lines = [
        "# Rule catalog",
        "",
        f"{len(rules)} built-in rules.",
        "",
        "| ID | Name | Pack | Severity | Confidence | Enabled by default | Tags |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rules:
        enabled = "yes" if r.enabled else "no (off by default)"
        tags = ", ".join(sorted(r.tags))
        lines.append(
            f"| [{esc_cell(r.id)}]({r.pack}.md) | {esc_cell(r.name)} | "
            f"{esc_cell(r.pack)} | {esc_cell(_val(r.severity))} | "
            f"{esc_cell(_val(r.confidence))} | {enabled} | {esc_cell(tags)} |"
        )
    return "\n".join(lines) + "\n"


def render_pack(pack: str, rules) -> str:
    out = [f"# Pack: {pack}", "", f"{len(rules)} rules in this pack.", ""]
    for r in rules:
        gate = r.entropy
        out.append(f"## {r.id}")
        out.append("")
        out.append(f"**{r.name}**")
        out.append("")
        if not r.enabled:
            out.append("> Disabled by default.")
            out.append("")
        out.append(f"- Severity: {_val(r.severity)}")
        out.append(f"- Confidence: {_val(r.confidence)}")
        out.append(f"- Enabled by default: {'yes' if r.enabled else 'no'}")
        if r.tags:
            out.append(f"- Tags: {', '.join(sorted(r.tags))}")
        out.append("")
        if r.description:
            out.append(r.description.strip())
            out.append("")
        fence = _fence(r.pattern)
        out.append("Pattern:")
        out.append("")
        out.append(fence)
        out.append(r.pattern)
        out.append(fence)
        out.append("")
        out.append(
            f"Entropy gate: enabled={gate.enabled}, "
            f"min_entropy={gate.min_entropy}, min_length={gate.min_length}"
        )
        out.append("")
        if r.keywords:
            need = "required" if r.require_keyword else "optional"
            out.append(f"Keywords ({need}): {', '.join(f'`{k}`' for k in r.keywords)}")
            out.append("")
        if r.references:
            out.append("References:")
            out.append("")
            for ref in r.references:
                if str(ref).startswith(("http://", "https://")):
                    out.append(f"- [{ref}]({ref})")
                else:
                    out.append(f"- {ref}")
            out.append("")
    return "\n".join(out)


def _write(path: Path, text: str) -> None:
    # Fixed newline + encoding so output is byte-identical on every OS.
    path.write_text(text, encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    args = parser.parse_args(argv)

    rules = _sorted_rules(load_ruleset(include_builtin=True))

    args.out.mkdir(parents=True, exist_ok=True)
    _write(args.out / "index.md", render_index(rules))

    by_pack = defaultdict(list)
    for r in rules:
        by_pack[r.pack].append(r)
    for pack, items in by_pack.items():
        _write(args.out / f"{pack}.md", render_pack(pack, items))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
