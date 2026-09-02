"""检测核心测试：检出能力、降噪能力、结构感知、重叠折叠。"""

from __future__ import annotations

import json

import pytest

from logspecter.findings import Severity
from logspecter.rules import RuleSet, load_ruleset
from logspecter.samples import NEGATIVE_SAMPLES, POSITIVE_SAMPLES
from logspecter.scanner import Scanner, ScanOptions

AWS_KEY = "AKIA4XZQ7MHB3LKPWCVR"
OPENAI_KEY = "sk-proj-Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQrWtNv0BdMkAyS"


def rule_ids(findings) -> set[str]:
    """命中的规则 id，含被折叠进证据链的 also-matched。"""
    ids = {f.rule_id for f in findings}
    for finding in findings:
        for evidence in finding.evidence:
            if evidence.startswith("also-matched:"):
                ids.add(evidence.split(":", 1)[1])
    return ids


class TestRecall:
    def test_every_positive_sample_is_detected(self, aggressive_scanner: Scanner) -> None:
        missed = []
        for expected, payload in POSITIVE_SAMPLES:
            findings = aggressive_scanner.scan_line(payload.encode(), source="t")
            if expected not in rule_ids(findings):
                missed.append(expected)
        assert not missed, f"漏报: {missed}"

    def test_detects_key_inside_large_chunk(self, scanner: Scanner) -> None:
        filler = b"2026-08-30 INFO nothing interesting here at all\n" * 5000
        chunk = filler + f"deploy accessKeyId={AWS_KEY}\n".encode() + filler
        scan = scanner.scan_chunk(chunk, source="big.log")
        assert [f.rule_id for f in scan.findings] == ["aws-access-key-id"]
        assert scan.findings[0].line == 5001
        assert scan.findings[0].secret == AWS_KEY


class TestPrecision:
    def test_no_false_positive_on_negative_samples(self, aggressive_scanner: Scanner) -> None:
        offenders = []
        for payload in NEGATIVE_SAMPLES:
            findings = aggressive_scanner.scan_line(payload.encode(), source="t")
            if findings:
                offenders.append((findings[0].rule_id, payload))
        assert not offenders, f"误报: {offenders}"

    def test_documentation_example_key_is_suppressed(self, scanner: Scanner) -> None:
        findings = scanner.scan_line(b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE", source="t")
        assert findings == []
        assert scanner.counters.suppressed_reasons["placeholder-or-doc-example"] >= 1

    def test_entropy_layer_records_suppression_reason(self, scanner: Scanner) -> None:
        scanner.scan_line(b"api_key=eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidmlld2VyIn0=", source="t")
        assert scanner.counters.suppressed_total >= 1


class TestStructuredAwareness:
    @staticmethod
    def cloudtrail_record() -> bytes:
        return json.dumps(
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "Alice",
                    "arn": "arn:aws:iam::123456789012:user/Alice",
                },
                "eventTime": "2026-08-30T11:22:33Z",
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.9",
                "recipientAccountId": "123456789012",
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/Deploy",
                    "headers": {"Authorization": f"Bearer {OPENAI_KEY}"},
                },
            }
        ).encode()

    def test_reports_cloud_context_and_json_path(self, scanner: Scanner) -> None:
        findings = scanner.scan_line(self.cloudtrail_record(), source="trail.json")
        assert findings
        finding = findings[0]
        assert finding.cloud_context["schema"] == "aws-cloudtrail"
        assert finding.cloud_context["actor"] == "AWS IAM User (Alice)"
        assert finding.cloud_context["action"] == "AssumeRole"
        assert finding.cloud_context["region"] == "us-east-1"
        assert finding.json_path == "requestParameters.headers.Authorization"
        summary = finding.context_summary()
        assert "AWS IAM User (Alice)" in summary
        assert "AssumeRole" in summary
        assert "requestParameters.headers.Authorization" in summary

    def test_overlapping_rules_are_collapsed(self, scanner: Scanner) -> None:
        findings = scanner.scan_line(self.cloudtrail_record(), source="trail.json")
        # openai-api-key 最精确，应保留它，其余并入证据链。
        assert [f.rule_id for f in findings] == ["openai-api-key"]
        collapsed = {
            e.split(":", 1)[1] for e in findings[0].evidence if e.startswith("also-matched:")
        }
        assert "authorization-header-bearer" in collapsed

    def test_collapse_can_be_disabled(self, ruleset: RuleSet) -> None:
        scanner = Scanner(ruleset, ScanOptions(collapse_overlaps=False))
        findings = scanner.scan_line(self.cloudtrail_record(), source="trail.json")
        assert len(findings) > 1

    def test_sensitive_json_key_catches_unclassified_secret(self, scanner: Scanner) -> None:
        record = json.dumps(
            {
                "logName": "projects/p/logs/app",
                "insertId": "abc",
                "resource": {"type": "gce_instance", "labels": {"project_id": "p"}},
                "protoPayload": {
                    "authenticationInfo": {"principalEmail": "svc@p.iam.gserviceaccount.com"},
                    "methodName": "v1.compute.instances.insert",
                    "request": {"credential": "Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQr"},
                },
            }
        ).encode()
        findings = scanner.scan_line(record, source="gcp.json")
        assert findings
        assert findings[0].json_path == "protoPayload.request.credential"
        assert findings[0].cloud_context["schema"] == "gcp-cloud-logging"
        assert "GCP Principal" in findings[0].cloud_context["actor"]

    def test_nested_json_string_is_parsed(self, scanner: Scanner) -> None:
        inner = json.dumps({"client_secret": "Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQr"})
        record = json.dumps({"userIdentity": {"type": "Root"}, "eventName": "X", "body": inner})
        findings = scanner.scan_line(record.encode(), source="t.json")
        assert findings
        assert findings[0].json_path.startswith("body.")

    def test_structured_can_be_disabled(self, ruleset: RuleSet) -> None:
        scanner = Scanner(ruleset, ScanOptions(structured=False))
        findings = scanner.scan_line(self.cloudtrail_record(), source="t.json")
        assert findings
        assert findings[0].cloud_context == {}


class TestChunkMechanics:
    def test_line_numbers_and_offsets(self, scanner: Scanner) -> None:
        chunk = (
            b"\n".join(
                [
                    b"first line",
                    b"second line",
                    f"third accessKeyId={AWS_KEY}".encode(),
                    b"fourth line",
                ]
            )
            + b"\n"
        )
        scan = scanner.scan_chunk(chunk, source="t.log", base_offset=1000)
        assert scan.line_count == 4
        finding = scan.findings[0]
        assert finding.line == 3
        assert finding.byte_offset == 1000 + chunk.index(b"third")

    def test_crlf_line_endings(self, scanner: Scanner) -> None:
        chunk = b"a\r\n" + f"key={AWS_KEY}\r\n".encode()
        scan = scanner.scan_chunk(chunk, source="t.log")
        assert scan.findings[0].line == 2
        assert scan.findings[0].secret == AWS_KEY

    def test_same_secret_repeated_reports_once_per_line(self, scanner: Scanner) -> None:
        chunk = (f"key={AWS_KEY}\n".encode()) * 3
        scan = scanner.scan_chunk(chunk, source="t.log")
        assert len(scan.findings) == 3
        assert {f.line for f in scan.findings} == {1, 2, 3}

    def test_empty_chunk(self, scanner: Scanner) -> None:
        scan = scanner.scan_chunk(b"", source="t.log")
        assert scan.findings == []
        assert scan.line_count == 0

    def test_binary_garbage_is_safe(self, scanner: Scanner) -> None:
        scan = scanner.scan_chunk(bytes(range(256)) * 40, source="t.bin")
        assert isinstance(scan.findings, list)

    def test_invalid_utf8_does_not_crash(self, scanner: Scanner) -> None:
        chunk = b"\xff\xfe bad bytes " + f"key={AWS_KEY}".encode() + b" \xc3\n"
        scan = scanner.scan_chunk(chunk, source="t.log")
        assert scan.findings[0].secret == AWS_KEY

    def test_oversized_line_is_truncated(self, ruleset: RuleSet) -> None:
        scanner = Scanner(ruleset, ScanOptions(max_line_bytes=64))
        chunk = b"x" * 200 + f" key={AWS_KEY}\n".encode()
        scan = scanner.scan_chunk(chunk, source="t.log")
        assert scan.findings == []

    def test_screening_disabled_gives_same_result(self, ruleset: RuleSet) -> None:
        chunk = b"\n".join(p.encode() for _r, p in POSITIVE_SAMPLES) + b"\n"
        with_screen = Scanner(ruleset, ScanOptions()).scan_chunk(chunk, source="t")
        without = Scanner(ruleset, ScanOptions(screen_chunks=False)).scan_chunk(chunk, source="t")
        assert {f.fingerprint for f in with_screen.findings} == {
            f.fingerprint for f in without.findings
        }


class TestKeywordProximity:
    def test_required_keyword_missing_is_suppressed(self, scanner: Scanner) -> None:
        # twilio-api-key-sid 要求邻近出现 twilio / auth_token / account_sid
        assert scanner.scan_line(b"id=SK0123456789abcdef0123456789abcdef", source="t") == []

    def test_required_keyword_present_is_reported(self, scanner: Scanner) -> None:
        findings = scanner.scan_line(
            b"twilio auth_token SK7c3f9a1b4e2d8065af31cb27de904152", source="t"
        )
        assert "twilio-api-key-sid" in rule_ids(findings)


class TestConfidenceAndSeverity:
    def test_structural_rule_gets_high_confidence(self, scanner: Scanner) -> None:
        finding = scanner.scan_line(f"key={AWS_KEY}".encode(), source="t")[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.confidence_score >= 0.85

    def test_min_confidence_filters(self, ruleset: RuleSet) -> None:
        strict = Scanner(ruleset, ScanOptions(min_confidence=0.99))
        loose = Scanner(ruleset, ScanOptions())
        payload = b"encryption_key=Kd9RmT4bVn6HcYaJ3sUeGf1L"
        assert loose.scan_line(payload, source="t")
        assert strict.scan_line(payload, source="t") == []


class TestScanLineEquivalence:
    def test_scan_line_matches_scan_chunk(self, scanner: Scanner) -> None:
        payload = f"deploy accessKeyId={AWS_KEY}".encode()
        via_line = scanner.scan_line(payload, source="t")
        via_chunk = Scanner(load_ruleset(), ScanOptions()).scan_chunk(payload + b"\n", source="t")
        assert [f.fingerprint for f in via_line] == [f.fingerprint for f in via_chunk.findings]


class TestCounters:
    def test_counters_accumulate_and_merge(self, scanner: Scanner) -> None:
        scanner.scan_line(f"key={AWS_KEY}".encode(), source="t")
        snapshot = scanner.counters
        assert snapshot.lines >= 1
        assert snapshot.accepted >= 1

        other = Scanner(load_ruleset(), ScanOptions())
        other.scan_line(f"key={AWS_KEY}".encode(), source="t")
        merged_lines = snapshot.lines
        snapshot.merge(other.counters)
        assert snapshot.lines == merged_lines + other.counters.lines

    def test_as_dict_is_serializable(self, scanner: Scanner) -> None:
        scanner.scan_line(b"password=changeme", source="t")
        payload = scanner.counters.as_dict()
        assert json.dumps(payload)
        assert "suppression_reasons" in payload


@pytest.mark.parametrize("rule_id,payload", POSITIVE_SAMPLES, ids=[r for r, _ in POSITIVE_SAMPLES])
def test_positive_sample_individually(
    aggressive_scanner: Scanner, rule_id: str, payload: str
) -> None:
    """逐条参数化，失败时能直接看出是哪条规则退化了。"""
    findings = aggressive_scanner.scan_line(payload.encode(), source="t")
    assert rule_id in rule_ids(findings)
