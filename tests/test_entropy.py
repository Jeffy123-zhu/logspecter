"""香农熵与启发式校验层的测试（壁垒一）。"""

from __future__ import annotations

import math

import pytest

from logspecter import entropy


class TestShannonEntropy:
    def test_single_symbol_is_zero(self) -> None:
        assert entropy.shannon_entropy("aaaaaaaa") == 0.0

    def test_empty_is_zero(self) -> None:
        assert entropy.shannon_entropy("") == 0.0

    def test_two_symbols_uniform_is_one_bit(self) -> None:
        assert entropy.shannon_entropy("abab") == pytest.approx(1.0)

    def test_uniform_alphabet_reaches_log2_of_size(self) -> None:
        value = "".join(chr(ord("a") + i) for i in range(16))
        assert entropy.shannon_entropy(value) == pytest.approx(math.log2(16))

    def test_monotonic_with_diversity(self) -> None:
        low = entropy.shannon_entropy("aaaabbbb")
        high = entropy.shannon_entropy("abcdefgh")
        assert high > low


class TestCharsetDetection:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("deadbeef0123", "hex"),
            ("ABCDEFGH2345", "base32"),
            ("AbC123xyz", "base62"),
            ("AbC1+2/3==", "base64"),
            ("AbC1-2_3", "base64url"),
            ("a!b@c#d$", "printable"),
        ],
    )
    def test_detect(self, value: str, expected: str) -> None:
        assert entropy.detect_charset(value) == expected


class TestCharsetCoverage:
    def test_full_hex_alphabet_is_saturated(self) -> None:
        # 64 字符的十六进制串最多只有 16 种字符，用「唯一数/长度」会得到 0.25，
        # 覆盖率口径应给出 1.0。
        value = "0123456789abcdef" * 4
        assert entropy.unique_ratio(value) == pytest.approx(0.25)
        assert entropy.charset_coverage(value) == pytest.approx(1.0)

    def test_repeated_character_is_near_zero(self) -> None:
        # 'a' 属于十六进制字符集（16 种），因此分母是 16 而不是 32。
        assert entropy.charset_coverage("a" * 32) == pytest.approx(1 / 16)

    def test_random_token_has_high_coverage(self) -> None:
        assert entropy.charset_coverage("Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUe") > 0.7


class TestRunDetection:
    def test_longest_repeat_run(self) -> None:
        assert entropy.longest_repeat_run("ab####cd") == 4
        assert entropy.longest_repeat_run("") == 0

    def test_longest_sequential_run(self) -> None:
        assert entropy.longest_sequential_run("xxabcdefyy") == 6
        assert entropy.longest_sequential_run("987654321") == 9
        assert entropy.longest_sequential_run("a") == 1


class TestEncodedTextDetection:
    def test_base64_of_json_is_flagged(self) -> None:
        # base64("{"user":"alice","role":"viewer"}")
        assert entropy.looks_like_encoded_text("eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidmlld2VyIn0=")

    def test_base64_of_url_is_flagged(self) -> None:
        assert entropy.looks_like_encoded_text("aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vdjEvaXRlbXM=")

    def test_random_key_material_is_not_flagged(self) -> None:
        assert not entropy.looks_like_encoded_text("Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQr")

    def test_short_value_is_not_flagged(self) -> None:
        assert not entropy.looks_like_encoded_text("abc")


class TestWordLikeness:
    def test_english_text_scores_high(self) -> None:
        assert entropy.word_likeness("SpringBootApplicationConfiguration") > 0.5

    def test_random_token_scores_low(self) -> None:
        assert entropy.word_likeness("Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQr") < 0.35

    def test_too_few_letters_returns_zero(self) -> None:
        assert entropy.word_likeness("123-456") == 0.0


class TestPlaceholders:
    @pytest.mark.parametrize(
        "value",
        [
            "AKIAIOSFODNN7EXAMPLE",
            "changeme123456",
            "REDACTED_BY_LOG_SCRUBBER",
            "your-api-key-here",
            "xxxxxxxxxxxxxxxx",
        ],
    )
    def test_placeholders_detected(self, value: str) -> None:
        assert entropy.contains_placeholder(value)

    def test_real_looking_secret_not_flagged(self) -> None:
        assert not entropy.contains_placeholder("Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUe")


class TestEvaluate:
    def test_structural_gate_skips_entropy_but_keeps_placeholder_filter(self) -> None:
        gate = entropy.EntropyGate.structural()
        assert entropy.evaluate("AKIA4XZQ7MHB3LKPWCVR", gate).accepted
        rejected = entropy.evaluate("AKIAIOSFODNN7EXAMPLE", gate)
        assert not rejected.accepted
        assert rejected.reasons == ("placeholder-or-doc-example",)

    def test_high_entropy_token_accepted(self) -> None:
        verdict = entropy.evaluate("Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQr")
        assert verdict.accepted
        assert verdict.entropy > 4.5
        assert verdict.confidence_delta > 0

    @pytest.mark.parametrize(
        ("value", "reason_prefix"),
        [
            ("short", "too-short"),
            ("aaaaaaaaaaaaaaaaaaaaaaaa", "low-charset-coverage"),
            ("3f2504e0-4f89-11d3-9a0c-0305e82c3301", "uuid-shape"),
            ("2026-08-30T11:22:33.123456Z", "timestamp-shape"),
            ("1234567890123456789", "numeric-only"),
            ("abcdefghijklmnopqrstuvwx", "sequential-run"),
            ("eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidmlld2VyIn0=", "base64-decodes-to-text"),
            ("SpringBootApplicationConfigurationLoader", "natural-language-like"),
        ],
    )
    def test_rejections(self, value: str, reason_prefix: str) -> None:
        verdict = entropy.evaluate(value)
        assert not verdict.accepted, f"{value!r} 本应被拒绝"
        assert verdict.reasons[0].startswith(reason_prefix), verdict.reasons

    def test_hex_hash_not_rejected_as_language(self) -> None:
        # 十六进制只用 a-f，元音占比天然偏高，语言相似度指标必须跳过这类字符集。
        gate = entropy.EntropyGate(min_length=64, min_normalized=0.85, min_entropy=3.4)
        verdict = entropy.evaluate(
            "69dfac969f4388253cda1c3e23b01057cbf6b6c3eafcf4693313b19621d4e2fb", gate
        )
        assert verdict.accepted, verdict.reasons

    def test_charset_whitelist(self) -> None:
        gate = entropy.EntropyGate(charsets=frozenset({"hex"}), min_length=8, min_entropy=2.0)
        assert not entropy.evaluate("Zx7QwPl2Kd9RmT4b", gate).accepted


class TestEntropyGateMapping:
    def test_from_mapping_merges_defaults(self) -> None:
        gate = entropy.EntropyGate.from_mapping({"min_entropy": 4.2})
        assert gate.min_entropy == 4.2
        assert gate.enabled is True

    def test_from_mapping_rejects_unknown_field(self) -> None:
        with pytest.raises(ValueError, match="未知的 entropy 配置字段"):
            entropy.EntropyGate.from_mapping({"nope": 1})

    def test_charsets_accepts_single_string(self) -> None:
        gate = entropy.EntropyGate.from_mapping({"charsets": "hex"})
        assert gate.charsets == frozenset({"hex"})
