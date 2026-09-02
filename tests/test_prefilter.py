"""字面量预筛的正确性（不得漏报）与提取质量测试。"""

from __future__ import annotations

import re

import pytest

from logspecter import prefilter
from logspecter.prefilter import (
    LiteralPrefilter,
    ScreenTree,
    extract_literal_groups,
    trie_pattern,
)
from logspecter.rules import RuleSet
from logspecter.samples import POSITIVE_SAMPLES


class TestTriePattern:
    def test_shared_prefix_is_factored(self) -> None:
        assert trie_pattern(["key", "keystore", "kms"]) == "k(?:ey(?:store)?|ms)"

    def test_single_word(self) -> None:
        assert trie_pattern(["AKIA"]) == "AKIA"

    def test_special_characters_are_escaped(self) -> None:
        pattern = trie_pattern(["a.b", "a+c"])
        assert re.compile(pattern).search("xxa.byy")
        assert not re.compile(pattern).search("axb")

    def test_equivalent_to_flat_alternation(self) -> None:
        words = ["key", "keystore", "kms", "akia", "api", "a"]
        trie = re.compile(trie_pattern(words))
        flat = re.compile("|".join(sorted(words, key=len, reverse=True)))
        for sample in ("keystore", "key", "kms", "akia", "api", "a", "zzz", "xxkeyxx", ""):
            assert bool(trie.search(sample)) == bool(flat.search(sample)), sample

    def test_empty_input_raises(self) -> None:
        with pytest.raises(ValueError, match="至少一个非空字面量"):
            trie_pattern([])


class TestLiteralExtraction:
    def test_branch_with_factored_prefix(self) -> None:
        # CPython 会把分支公共前缀 'A' 提到分支外，提取器必须把它拼回去。
        groups = extract_literal_groups(r"\b((?:AKIA|ASIA|AROA)[A-Z0-9]{16})\b")
        assert groups
        assert set(groups[0].alternatives) == {"AKIA", "ASIA", "AROA"}

    def test_small_charclass_is_expanded(self) -> None:
        groups = extract_literal_groups(r"\b(gh[pousr]_[A-Za-z0-9]{36})\b")
        assert set(groups[0].alternatives) == {"ghp", "gho", "ghu", "ghs", "ghr"}

    def test_prefix_width_is_exact(self) -> None:
        groups = extract_literal_groups(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})\b")
        group = next(g for g in groups if "_live_" in g.alternatives[0])
        assert (group.min_prefix, group.max_prefix) == (2, 2)
        assert group.anchorable

    def test_unbounded_prefix_marks_group_unanchorable(self) -> None:
        groups = extract_literal_groups(r"[a-z]*SECRETKEY=([A-Za-z0-9]{20,})")
        group = groups[0]
        assert group.max_prefix is None
        assert not group.anchorable

    def test_ignore_case_lowercases_alternatives(self) -> None:
        groups = extract_literal_groups("SecretKey=([A-Za-z0-9]{20,})", ignore_case=True)
        assert groups[0].alternatives[0].islower()

    def test_unextractable_pattern_returns_empty(self) -> None:
        assert extract_literal_groups(r"[0-9a-f]{64}") == ()

    def test_invalid_pattern_degrades_gracefully(self) -> None:
        assert extract_literal_groups("(unclosed") == ()


class TestPrefilterSoundness:
    """预筛绝不能否决一个真正能匹配的输入 —— 这是「不引入漏报」的核心保证。"""

    def test_every_builtin_rule_accepts_its_positive_sample(self, full_ruleset: RuleSet) -> None:
        by_id = {rule.id: rule for rule in full_ruleset}
        checked = 0
        for rule_id, payload in POSITIVE_SAMPLES:
            rule = by_id[rule_id]
            extra = rule.keywords if rule.require_keyword else ()
            pf = LiteralPrefilter.build(
                rule.pattern, ignore_case=rule.ignore_case, extra_group=extra
            )
            regex = re.compile(rule.pattern.encode(), re.IGNORECASE if rule.ignore_case else 0)
            data = payload.encode()
            if regex.search(data) is None:
                continue  # 该样本靠结构化路径命中，不走文本预筛
            hay = data.lower() if pf.ignore_case else data
            assert pf.present(hay), f"{rule_id} 的预筛误杀了正样本"
            checked += 1
        assert checked >= 30, f"只校验到 {checked} 条规则，样本集可能失效"

    def test_anchor_span_covers_real_match_offsets(self, full_ruleset: RuleSet) -> None:
        """锚定区间必须真的包含匹配起点，否则锚定 match 会漏报。"""
        by_id = {rule.id: rule for rule in full_ruleset}
        for rule_id, payload in POSITIVE_SAMPLES:
            rule = by_id[rule_id]
            pf = LiteralPrefilter.build(rule.pattern, ignore_case=rule.ignore_case)
            span = pf.anchor_span
            if span is None:
                continue
            regex = re.compile(rule.pattern.encode(), re.IGNORECASE if rule.ignore_case else 0)
            data = payload.encode()
            match = regex.search(data)
            if match is None:
                continue
            hay = data.lower() if pf.ignore_case else data
            cursor = pf.trigger_cursor(hay)
            index = cursor.next_from(match.start())
            assert index >= 0, rule_id
            assert match.start() >= index - span[1], f"{rule_id} 锚定上界过窄"
            assert match.start() <= index - span[0], f"{rule_id} 锚定下界过宽"


class TestTriggerCursor:
    def test_absent_literal_is_scanned_only_once(self) -> None:
        """缺席候选必须被永久淘汰，否则每轮都会重扫整块（曾导致 50 倍劣化）。"""
        data = b"line with aws\n" * 1000
        pf = LiteralPrefilter._from_groups(
            (prefilter.LiteralGroup(("aws", "sessiontoken"), 0, 0),), ignore_case=True
        )
        cursor = pf.trigger_cursor(data)
        calls = 0
        original = data.find

        position = 0
        seen = []
        while position < len(data):
            index = cursor.next_from(position)
            if index < 0:
                break
            seen.append(index)
            position = data.find(b"\n", index) + 1
            calls += 1
        assert calls == 1000
        assert original(b"aws") == seen[0]

    def test_regex_cursor_advances(self) -> None:
        pf = LiteralPrefilter._from_groups(
            (prefilter.LiteralGroup(("aa", "bb", "cc", "dd", "ee"), 0, 0),), ignore_case=False
        )
        assert pf.trigger_regex is not None  # 候选数超过 find 阈值 → 走 trie
        cursor = pf.trigger_cursor(b"xxaayybbzz")
        assert cursor.next_from(0) == 2
        assert cursor.next_from(3) == 6
        assert cursor.next_from(7) == -1


class TestScreenTree:
    def test_clean_buffer_prunes_everything(self, ruleset: RuleSet) -> None:
        prefilters = [
            LiteralPrefilter.build(rule.pattern, ignore_case=rule.ignore_case)
            for rule in ruleset.enabled_rules()
        ]
        tree = ScreenTree.build(prefilters, leaf_size=8)
        assert tree.nodes > 0
        # 全零缓冲区不含任何字面量：除「无法预筛」的规则外都应被剪掉。
        active = tree.select(b"\x00" * 4096)
        assert set(active) == set(tree.always)

    def test_matching_buffer_keeps_rule(self, ruleset: RuleSet) -> None:
        rules = ruleset.enabled_rules()
        prefilters = [
            LiteralPrefilter.build(rule.pattern, ignore_case=rule.ignore_case) for rule in rules
        ]
        tree = ScreenTree.build(prefilters, leaf_size=4)
        target = next(i for i, r in enumerate(rules) if r.id == "aws-access-key-id")
        active = tree.select(b"prefix akia4xzq7mhb3lkpwcvr suffix")
        assert target in active

    def test_all_prefilters_inactive_yields_no_root(self) -> None:
        tree = ScreenTree.build([LiteralPrefilter()])
        assert tree.root is None
        assert tree.select(b"anything") == [0]
