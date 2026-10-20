import dataclasses
import importlib.util
import re
from pathlib import Path

from logspecter.rules import load_ruleset

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gen_rule_docs.py"
_spec = importlib.util.spec_from_file_location("gen_rule_docs", SCRIPT)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def _builtin_rules():
    return list(load_ruleset(include_builtin=True))


def _generate(out: Path) -> None:
    assert gen.main(["--out", str(out)]) == 0


def test_every_rule_in_index_and_exactly_one_pack_page(tmp_path):
    _generate(tmp_path)
    index = (tmp_path / "index.md").read_text(encoding="utf-8")
    pack_pages = {
        p.name: p.read_text(encoding="utf-8") for p in tmp_path.glob("*.md") if p.name != "index.md"
    }
    for rule in _builtin_rules():
        assert f"[{rule.id}](" in index
        hits = [name for name, text in pack_pages.items() if f"## {rule.id}\n" in text]
        assert len(hits) == 1, rule.id
        assert hits[0] == f"{rule.pack}.md"


def test_output_is_deterministic(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    _generate(first)
    _generate(second)
    names_a = sorted(p.name for p in first.glob("*.md"))
    names_b = sorted(p.name for p in second.glob("*.md"))
    assert names_a == names_b
    for name in names_a:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_pipe_in_rule_name_does_not_break_table():
    rule = dataclasses.replace(_builtin_rules()[0], name="weird | name")
    index = gen.render_index([rule])
    row = next(line for line in index.splitlines() if f"[{rule.id}](" in line)
    assert "weird \\| name" in row
    # 7 columns -> 8 unescaped pipes
    assert len(re.findall(r"(?<!\\)\|", row)) == 8


def test_default_off_rules_are_marked(tmp_path):
    off = [r for r in _builtin_rules() if not r.enabled]
    assert off, "expected at least one default-off built-in rule"
    _generate(tmp_path)
    index = (tmp_path / "index.md").read_text(encoding="utf-8")
    for rule in off:
        row = next(line for line in index.splitlines() if f"[{rule.id}](" in line)
        assert "off by default" in row
        page = (tmp_path / f"{rule.pack}.md").read_text(encoding="utf-8")
        assert "Disabled by default" in page
