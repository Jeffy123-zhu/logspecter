"""单层 Base64 / Base64URL 解码与扫描测试（#41）。"""

from __future__ import annotations

import base64
import csv
import io
import json
import random
import string
from pathlib import Path

from typer.testing import CliRunner

from logspecter import engine, report
from logspecter.cli import EXIT_FINDINGS, EXIT_OK, app
from logspecter.decode import decode_base64_text, is_printable_text
from logspecter.rules import RuleSet
from logspecter.samples import make_secret
from logspecter.scanner import Scanner, ScanOptions

_RNG = random.Random(20260901)
AWS_KEY = "AKIA" + make_secret(string.ascii_uppercase + string.digits, 16, _RNG)
AWS_SECRET = make_secret(string.ascii_letters + string.digits + "+/", 40, _RNG)


class TestDecodeBase64Helper:
    def test_standard_base64_printable_text(self) -> None:
        raw = f"aws_secret_access_key={AWS_SECRET}".encode()
        token = base64.b64encode(raw)
        assert decode_base64_text(token) == raw

    def test_base64url_and_missing_padding(self) -> None:
        # 故意构造包含 '-' / '_' 且去掉末尾 '=' 的 Base64URL 串。
        raw = b'{"subject":"user?id=42&role=admin","key":"' + AWS_KEY.encode() + b'"}'
        token = base64.urlsafe_b64encode(raw).rstrip(b"=")
        assert b"=" not in token
        assert decode_base64_text(token) == raw

    def test_max_bytes_limit_respected(self) -> None:
        raw = b"aws_access_key_id=" + AWS_KEY.encode() + b"\n"
        token = base64.b64encode(raw)
        assert decode_base64_text(token, max_bytes=len(raw)) == raw
        assert decode_base64_text(token, max_bytes=len(raw) - 1) is None
        assert decode_base64_text(token, max_bytes=0) is None

    def test_random_binary_base64_rejected(self) -> None:
        # 真实高熵二进制字节（非可打印文本）不应被解码返回。
        binary = bytes(range(128, 256))
        token = base64.b64encode(binary)
        assert not is_printable_text(binary)
        assert decode_base64_text(token) is None

    def test_invalid_or_short_tokens_rejected(self) -> None:
        assert decode_base64_text(b"short") is None
        assert decode_base64_text(b"abcde===") is None
        # 去除 '=' 后余数为 1 的非法长度（13 字符）
        assert decode_base64_text(b"YWJjZGVmZ2hpag"[:13]) is None
        assert decode_base64_text(b"not base64 at all!!!") is None


class TestScannerDecodeBase64:
    def test_base64_aws_secret_access_key_reports_outer_token_and_encoding(
        self, ruleset: RuleSet
    ) -> None:
        inner = f"aws_secret_access_key={AWS_SECRET}".encode()
        b64_token = base64.b64encode(inner)
        prefix = b"2026-08-30 INFO auth_payload="
        line = b"first line\n" + prefix + b64_token + b"\n"

        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        scan = scanner.scan_chunk(line, source="app.log")
        assert len(scan.findings) == 1
        finding = scan.findings[0]
        assert finding.rule_id == "aws-secret-access-key"
        assert finding.secret == AWS_SECRET
        assert finding.line == 2
        assert finding.column == len(prefix) + 1
        assert finding.context["encoding"] == "base64"
        assert finding.cloud_context["encoding"] == "base64"

    def test_base64_json_containing_aws_access_key(self, ruleset: RuleSet) -> None:
        inner = json.dumps({"user": "svc", "accessKeyId": AWS_KEY}).encode()
        b64_token = base64.urlsafe_b64encode(inner).rstrip(b"=")
        line = b"GET /callback?state=" + b64_token + b" HTTP/1.1"

        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        findings = scanner.scan_line(line, source="access.log", local_line=7)
        assert [f.rule_id for f in findings] == ["aws-access-key-id"]
        assert findings[0].secret == AWS_KEY
        assert findings[0].line == 7
        assert findings[0].column == len(b"GET /callback?state=") + 1
        assert findings[0].context["encoding"] == "base64"

    def test_basic_auth_with_lower_ranked_decoded_rule_prefers_decoded_finding(
        self, ruleset: RuleSet
    ) -> None:
        stripe_test = "sk_test_" + make_secret(string.ascii_letters + string.digits, 24, _RNG)
        b64_token = base64.b64encode(f"{stripe_test}:".encode())
        line = b"Authorization: Basic " + b64_token

        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        findings = scanner.scan_line(line, source="auth.log")
        assert len(findings) == 1
        assert findings[0].rule_id == "stripe-test-secret-key"
        assert findings[0].secret == stripe_test
        assert findings[0].column == len(b"Authorization: Basic ") + 1
        assert findings[0].context["encoding"] == "base64"
        assert "also-matched:authorization-header-basic" in findings[0].evidence

    def test_json_string_leaf_resolves_json_path_and_collapses_outer_basic(
        self, ruleset: RuleSet
    ) -> None:
        b64_token = base64.b64encode(f"aws_secret_access_key={AWS_SECRET}".encode()).decode()
        line = json.dumps({"authorization": f"Basic {b64_token}"}).encode()

        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        findings = scanner.scan_line(line, source="structured.log")
        assert len(findings) == 1
        assert findings[0].rule_id == "aws-secret-access-key"
        assert findings[0].secret == AWS_SECRET
        assert findings[0].json_path == "authorization"
        assert findings[0].context["encoding"] == "base64"

    def test_multiple_distinct_secrets_in_single_base64_blob_all_preserved(
        self, ruleset: RuleSet
    ) -> None:
        inner = f"aws_access_key_id={AWS_KEY}\naws_secret_access_key={AWS_SECRET}".encode()
        b64_token = base64.b64encode(inner)
        line = b"Authorization: Basic " + b64_token

        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        findings = scanner.scan_line(line, source="multi.log")
        assert {f.rule_id for f in findings} == {"aws-access-key-id", "aws-secret-access-key"}
        assert all(f.context["encoding"] == "base64" for f in findings)

    def test_payload_starting_with_ansi_escape_or_utf8_bom_detected(self, ruleset: RuleSet) -> None:
        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        for prefix in (b"\x1b[31m", b"\xef\xbb\xbf"):
            b64_token = base64.b64encode(prefix + f"aws_secret_access_key={AWS_SECRET}".encode())
            findings = scanner.scan_line(b"payload=" + b64_token, source="ansi.log")
            assert len(findings) == 1
            assert findings[0].rule_id == "aws-secret-access-key"
            assert findings[0].context["encoding"] == "base64"

    def test_single_layer_only_no_recursion(self, ruleset: RuleSet) -> None:
        layer1 = base64.b64encode(f"aws_secret_access_key={AWS_SECRET}".encode())
        layer2 = base64.b64encode(b"nested=" + layer1)
        scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        assert scanner.scan_line(b"payload=" + layer2, source="t.log") == []

    def test_random_binary_base64_produces_no_extra_findings(self, ruleset: RuleSet) -> None:
        # 24 字节高熵二进制串编码为 32 字符 Base64
        binary = bytes(
            [
                0x9F,
                0x12,
                0xA4,
                0x88,
                0xC3,
                0x07,
                0xE1,
                0x5B,
                0xD0,
                0x44,
                0x7A,
                0xFE,
                0x81,
                0x39,
                0xB6,
                0x02,
                0xEE,
                0x71,
                0x93,
                0xAC,
                0x19,
                0x8D,
                0x50,
                0xF4,
            ]
        )
        token = base64.b64encode(binary)
        line = b"DEBUG opaque_binary=" + token

        off_scanner = Scanner(ruleset, ScanOptions(decode_base64=False))
        on_scanner = Scanner(ruleset, ScanOptions(decode_base64=True))
        assert off_scanner.scan_line(line, source="t.log") == []
        assert on_scanner.scan_line(line, source="t.log") == []

    def test_flag_off_keeps_behaviour_unchanged(self, ruleset: RuleSet) -> None:
        b64_token = base64.b64encode(f"aws_secret_access_key={AWS_SECRET}".encode())
        scanner = Scanner(ruleset, ScanOptions(decode_base64=False))
        assert scanner.scan_line(b"payload=" + b64_token, source="t.log") == []

    def test_exporters_include_encoding_context(self, tmp_path: Path, ruleset: RuleSet) -> None:
        b64_token = base64.b64encode(f"aws_secret_access_key={AWS_SECRET}".encode()).decode()
        log_file = tmp_path / "encoded.log"
        log_file.write_text(f"2026-08-30 INFO blob={b64_token}\n", encoding="utf-8")

        cfg = engine.ScanConfig(ruleset=ruleset, options=ScanOptions(decode_base64=True))
        res = engine.scan([str(log_file)], cfg, workers=1)
        assert len(res.groups) == 1

        as_json = json.loads(report.to_json(res))
        assert as_json["findings"][0]["cloud_context"]["encoding"] == "base64"

        as_csv = list(csv.DictReader(io.StringIO(report.to_csv(res))))
        assert as_csv[0]["encoding"] == "base64"

        as_sarif = json.loads(report.to_sarif(res))
        props = as_sarif["runs"][0]["results"][0]["properties"]
        assert props["cloudContext"]["encoding"] == "base64"

    def test_cli_decode_base64_flag(self, tmp_path: Path) -> None:
        b64_token = base64.b64encode(f"aws_secret_access_key={AWS_SECRET}".encode()).decode()
        log_file = tmp_path / "cli.log"
        log_file.write_text(f"2026-08-30 INFO blob={b64_token}\n", encoding="utf-8")

        runner = CliRunner()
        without_flag = runner.invoke(
            app, ["scan", str(log_file), "--workers", "1", "--format", "json", "--quiet"]
        )
        assert without_flag.exit_code == EXIT_OK

        with_flag = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--decode-base64",
                "--workers",
                "1",
                "--format",
                "json",
                "--quiet",
            ],
        )
        assert with_flag.exit_code == EXIT_FINDINGS
        payload = json.loads(with_flag.stdout)
        assert payload["findings"][0]["rule_id"] == "aws-secret-access-key"
        assert payload["findings"][0]["cloud_context"]["encoding"] == "base64"
