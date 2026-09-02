"""规则库加载、校验与筛选测试。"""

from __future__ import annotations

import re

import pytest

from logspecter.findings import Confidence, Severity
from logspecter.rules import CompiledRule, Rule, RuleSet, RuleSyntaxError, load_ruleset


class TestBuiltinRuleset:
    def test_loads_and_has_multiple_packs(self, ruleset: RuleSet) -> None:
        assert len(ruleset) >= 50
        assert {"aws", "gcp", "azure", "vendors", "generic", "database"} <= set(ruleset.packs)

    def test_all_patterns_compile_as_bytes(self, ruleset: RuleSet) -> None:
        for rule in ruleset:
            compiled = CompiledRule.build(rule)
            assert isinstance(compiled.regex.pattern, bytes)

    def test_rule_ids_are_unique_and_kebab_case(self, ruleset: RuleSet) -> None:
        ids = [rule.id for rule in ruleset]
        assert len(ids) == len(set(ids))
        for rule_id in ids:
            assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", rule_id), rule_id

    def test_capture_group_exists(self, ruleset: RuleSet) -> None:
        for rule in ruleset:
            if isinstance(rule.capture, int) and rule.capture == 0:
                continue
            compiled = CompiledRule.build(rule)
            if isinstance(rule.capture, int):
                assert compiled.regex.groups >= rule.capture, rule.id
            else:
                assert rule.capture in compiled.regex.groupindex, rule.id

    def test_every_rule_has_description_or_name(self, ruleset: RuleSet) -> None:
        for rule in ruleset:
            assert rule.name.strip(), rule.id

    def test_every_rule_has_a_positive_sample(self, ruleset: RuleSet) -> None:
        """新增规则必须同时补一条正样本，否则自检与回归测试覆盖不到它。"""
        from logspecter.samples import POSITIVE_SAMPLES

        covered = {rule_id for rule_id, _payload in POSITIVE_SAMPLES}
        missing = sorted(rule.id for rule in ruleset if rule.id not in covered)
        assert not missing, f"以下规则缺少正样本（见 src/logspecter/samples.py）: {missing}"

    def test_samples_reference_existing_rules(self, ruleset: RuleSet) -> None:
        from logspecter.samples import POSITIVE_SAMPLES

        known = {rule.id for rule in ruleset}
        unknown = sorted({rule_id for rule_id, _ in POSITIVE_SAMPLES} - known)
        assert not unknown, f"正样本引用了不存在的规则: {unknown}"

    def test_sorted_by_severity(self, ruleset: RuleSet) -> None:
        ranks = [rule.severity.rank for rule in ruleset]
        assert ranks == sorted(ranks)


class TestRuleFromDict:
    def test_minimal_rule(self) -> None:
        rule = Rule.from_dict({"id": "my-rule", "name": "My Rule", "pattern": "abc"})
        assert rule.severity is Severity.HIGH
        assert rule.confidence is Confidence.MEDIUM
        assert rule.enabled is True

    @pytest.mark.parametrize(
        ("payload", "message"),
        [
            ({"id": "x", "name": "n"}, "缺少必填字段"),
            ({"id": "Bad_ID", "name": "n", "pattern": "a"}, "不合法"),
            ({"id": "x", "name": "n", "pattern": "([a-"}, "无法编译"),
            ({"id": "x", "name": "n", "pattern": "a", "bogus": 1}, "未知字段"),
            ({"id": "x", "name": "n", "pattern": "a", "capture": 1.5}, "capture"),
            (
                {"id": "x", "name": "n", "pattern": "a", "entropy": {"wat": 1}},
                "entropy 配置错误",
            ),
        ],
    )
    def test_invalid_payloads(self, payload: dict, message: str) -> None:
        with pytest.raises(RuleSyntaxError, match=message):
            Rule.from_dict(payload)

    def test_round_trip_through_dict(self, ruleset: RuleSet) -> None:
        for rule in ruleset:
            restored = Rule.from_dict(rule.to_dict())
            assert restored == rule


class TestRuleSetSelection:
    def test_filter_by_pack(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(packs=["aws"])
        assert selected.rules
        assert {r.pack for r in selected} == {"aws"}

    def test_filter_by_tag(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(tags=["github"])
        assert selected.rules
        assert all("github" in r.tags for r in selected)

    def test_min_severity(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(min_severity=Severity.HIGH)
        assert all(r.severity.rank <= Severity.HIGH.rank for r in selected)

    def test_exclude_rule(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(exclude=["aws-access-key-id"])
        assert all(r.id != "aws-access-key-id" for r in selected)

    def test_wildcard_selector(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(include=["aws-*"])
        assert selected.rules
        assert all(r.id.startswith("aws-") for r in selected)

    def test_include_enables_default_off_rule(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(include=["generic-high-entropy-token"])
        assert [r.id for r in selected.enabled_rules()] == ["generic-high-entropy-token"]

    def test_enable_all(self, ruleset: RuleSet) -> None:
        assert len(ruleset.select(enable_all=True).enabled_rules()) == len(ruleset)

    def test_pack_selector_prefix(self, ruleset: RuleSet) -> None:
        selected = ruleset.select(include=["pack:vendors"])
        assert selected.rules
        assert {r.pack for r in selected.enabled_rules()} == {"vendors"}


class TestCustomRuleFiles:
    def test_user_rule_overrides_builtin(self, tmp_path) -> None:
        override = tmp_path / "override.yaml"
        override.write_text(
            "version: 1\npack: custom\nrules:\n"
            "  - id: aws-access-key-id\n"
            "    name: Overridden\n"
            "    pattern: 'ZZZZ'\n"
            "    severity: low\n",
            encoding="utf-8",
        )
        merged = load_ruleset([override])
        rule = next(r for r in merged if r.id == "aws-access-key-id")
        assert rule.name == "Overridden"
        assert rule.severity is Severity.LOW

    def test_defaults_section_is_applied(self, tmp_path) -> None:
        path = tmp_path / "pack.yaml"
        path.write_text(
            "version: 1\npack: t\ndefaults:\n  severity: low\n  entropy:\n    min_entropy: 2.0\n"
            "rules:\n"
            "  - id: r-one\n    name: One\n    pattern: 'aaa'\n"
            "  - id: r-two\n    name: Two\n    pattern: 'bbb'\n    entropy:\n      min_length: 4\n",
            encoding="utf-8",
        )
        rules = {r.id: r for r in load_ruleset([path], include_builtin=False)}
        assert rules["r-one"].severity is Severity.LOW
        assert rules["r-one"].entropy.min_entropy == 2.0
        # 条目级 entropy 应与 defaults 合并而不是整体覆盖
        assert rules["r-two"].entropy.min_entropy == 2.0
        assert rules["r-two"].entropy.min_length == 4

    def test_missing_path_raises(self, tmp_path) -> None:
        with pytest.raises(RuleSyntaxError, match="规则路径不存在"):
            load_ruleset([tmp_path / "nope.yaml"])

    def test_bad_yaml_raises(self, tmp_path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("version: 1\nrules: not-a-list\n", encoding="utf-8")
        with pytest.raises(RuleSyntaxError, match="缺少 rules 列表"):
            load_ruleset([path], include_builtin=False)

    def test_unsupported_version_raises(self, tmp_path) -> None:
        path = tmp_path / "v9.yaml"
        path.write_text("version: 9\nrules: []\n", encoding="utf-8")
        with pytest.raises(RuleSyntaxError, match="不支持的 version"):
            load_ruleset([path], include_builtin=False)

    def test_directory_is_walked(self, tmp_path) -> None:
        (tmp_path / "a.yaml").write_text(
            "version: 1\nrules:\n  - id: a-one\n    name: A\n    pattern: 'aaa'\n",
            encoding="utf-8",
        )
        (tmp_path / "b.yml").write_text(
            "version: 1\nrules:\n  - id: b-one\n    name: B\n    pattern: 'bbb'\n",
            encoding="utf-8",
        )
        ids = {r.id for r in load_ruleset([tmp_path], include_builtin=False)}
        assert ids == {"a-one", "b-one"}


class TestRuleSetSerialization:
    def test_ruleset_round_trip(self, ruleset: RuleSet) -> None:
        restored = RuleSet.from_dict(ruleset.to_dict())
        assert [r.id for r in restored] == [r.id for r in ruleset]

    def test_ruleset_is_picklable(self, ruleset: RuleSet) -> None:
        import pickle

        restored = pickle.loads(pickle.dumps(ruleset))
        assert len(restored) == len(ruleset)
