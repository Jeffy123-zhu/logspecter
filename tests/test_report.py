"""输出层测试：脱敏、JSON/CSV/SARIF 导出、终端渲染、基线抑制。"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from logspecter import engine, redact, report
from logspecter.baseline import Baseline, BaselineError
from logspecter.findings import Confidence, Finding, FindingGroup, Severity
from logspecter.rules import RuleSet
from logspecter.scanner import ScanOptions

SECRET = "AKIA4XZQ7MHB3LKPWCVR"


@pytest.fixture
def result(tmp_path: Path, ruleset: RuleSet) -> engine.ScanResult:
    log = tmp_path / "app.log"
    log.write_text(
        "\n".join(
            [
                "2026-08-30 INFO boot ok",
                f"2026-08-30 INFO deploy accessKeyId={SECRET}",
                json.dumps(
                    {
                        "eventVersion": "1.08",
                        "userIdentity": {"type": "IAMUser", "userName": "Alice"},
                        "eventName": "AssumeRole",
                        "eventSource": "sts.amazonaws.com",
                        "awsRegion": "us-east-1",
                        "requestParameters": {
                            "headers": {
                                "Authorization": "Bearer "
                                "sk-proj-Zx7QwPl2Kd9RmT4bVn6HcYaJ3sUeGf1LoXi8ZpQrWtNv0BdMkAyS"
                            }
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    config = engine.ScanConfig(ruleset=ruleset, options=ScanOptions(), chunk_size=1 << 16)
    return engine.scan([str(log)], config, workers=1)


class TestRedaction:
    def test_mask_keeps_head_and_tail(self) -> None:
        masked = redact.mask(SECRET)
        assert masked.startswith("AKIA")
        assert "PWCVR"[-4:] in masked
        assert "(len=20)" in masked
        assert SECRET not in masked

    def test_mask_caps_star_run(self) -> None:
        masked = redact.mask("x" * 500)
        assert masked.count("*") <= 8
        assert "(len=500)" in masked

    def test_short_secret_fully_masked(self) -> None:
        assert redact.mask("abc") == "*** (len=3)"

    def test_empty(self) -> None:
        assert redact.mask("") == "<empty>"

    def test_fingerprint_is_stable_and_rule_scoped(self) -> None:
        assert redact.fingerprint("r", SECRET) == redact.fingerprint("r", SECRET)
        assert redact.fingerprint("r", SECRET) != redact.fingerprint("other", SECRET)
        assert len(redact.fingerprint("r", SECRET)) == 16

    def test_mask_line(self) -> None:
        line = f"key={SECRET} end"
        masked = redact.mask_line(line, SECRET)
        assert SECRET not in masked
        assert masked.startswith("key=AKIA")


class TestJsonExport:
    def test_structure_and_redaction(self, result: engine.ScanResult) -> None:
        payload = json.loads(report.to_json(result))
        assert payload["tool"]["name"] == "logspecter"
        assert payload["summary"]["findings"] == len(result.groups)
        assert "detection" in payload["stats"]
        assert payload["findings"]
        finding = payload["findings"][0]
        assert "secret" not in finding
        assert finding["secret_masked"]
        assert finding["fingerprint"]
        assert "context_summary" in finding
        assert SECRET not in report.to_json(result)

    def test_include_secret_opt_in(self, result: engine.ScanResult) -> None:
        text = report.to_json(result, include_secret=True)
        assert SECRET in text

    def test_cloud_context_present(self, result: engine.ScanResult) -> None:
        payload = json.loads(report.to_json(result))
        contexts = [f["cloud_context"] for f in payload["findings"] if f["cloud_context"]]
        assert contexts
        assert any(c.get("actor") == "AWS IAM User (Alice)" for c in contexts)


class TestCsvExport:
    def test_header_and_rows(self, result: engine.ScanResult) -> None:
        text = report.to_csv(result)
        rows = list(csv.DictReader(io.StringIO(text)))
        assert rows
        assert "fingerprint" in rows[0]
        assert "cloud_actor" in rows[0]
        assert "secret" not in rows[0]
        assert SECRET not in text

    def test_include_secret_adds_column(self, result: engine.ScanResult) -> None:
        rows = list(csv.DictReader(io.StringIO(report.to_csv(result, include_secret=True))))
        assert "secret" in rows[0]


class TestSarifExport:
    def test_valid_shape(self, result: engine.ScanResult) -> None:
        document = json.loads(report.to_sarif(result))
        assert document["version"] == "2.1.0"
        run = document["runs"][0]
        assert run["tool"]["driver"]["name"] == "LogSpecter"
        assert run["tool"]["driver"]["rules"]
        assert run["results"]
        first = run["results"][0]
        assert first["level"] in {"error", "warning", "note"}
        assert first["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert "logspecterFingerprint/v1" in first["partialFingerprints"]

    def test_uri_uses_forward_slashes(self, result: engine.ScanResult) -> None:
        document = json.loads(report.to_sarif(result))
        location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "\\" not in location["artifactLocation"]["uri"]


class TestExportDispatch:
    @pytest.mark.parametrize("fmt", ["json", "csv", "sarif"])
    def test_known_formats(self, result: engine.ScanResult, fmt: str) -> None:
        assert report.export(result, fmt)

    def test_unknown_format_raises(self, result: engine.ScanResult) -> None:
        with pytest.raises(ValueError, match="未知导出格式"):
            report.export(result, "xml")


class TestConsoleRendering:
    def _render(self, result: engine.ScanResult, **kwargs) -> str:
        console = Console(record=True, width=160, file=io.StringIO(), highlight=False)
        report.render_report(console, result, **kwargs)
        return console.export_text()

    def test_summary_and_rows(self, result: engine.ScanResult) -> None:
        text = self._render(result)
        assert "扫描摘要" in text
        assert "aws-access-key-id" in text
        assert SECRET not in text

    def test_show_secrets(self, result: engine.ScanResult) -> None:
        assert SECRET in self._render(result, show_secrets=True)

    def test_narrow_terminal_uses_compact_layout(self, result: engine.ScanResult) -> None:
        console = Console(record=True, width=70, file=io.StringIO(), highlight=False)
        report.render_report(console, result)
        text = console.export_text()
        assert "aws-access-key-id" in text
        # 紧凑布局不应出现被压成单字符宽的表格残迹
        assert "云端上下文" not in text

    def test_verbose_detail_panels(self, result: engine.ScanResult) -> None:
        text = self._render(result, verbose=True)
        assert "判定依据" in text
        assert "指纹" in text

    def test_clean_result_message(self, ruleset: RuleSet, tmp_path: Path) -> None:
        log = tmp_path / "clean.log"
        log.write_text("nothing to see here\n", encoding="utf-8")
        clean = engine.scan(
            [str(log)],
            engine.ScanConfig(ruleset=ruleset, options=ScanOptions()),
            workers=1,
        )
        assert "未发现" in self._render(clean)

    def test_stats_panel(self, result: engine.ScanResult) -> None:
        console = Console(record=True, width=160, file=io.StringIO(), highlight=False)
        report.render_stats(console, result)
        text = console.export_text()
        assert "扫描统计" in text
        assert "吞吐" in text

    def test_rules_table(self, ruleset: RuleSet) -> None:
        console = Console(record=True, width=200, file=io.StringIO(), highlight=False)
        report.render_rules_table(console, ruleset)
        text = console.export_text()
        assert "aws-access-key-id" in text
        assert "条规则" in text


class TestBaseline:
    def test_round_trip(self, result: engine.ScanResult, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        Baseline.from_groups(result.groups, note="test").save(path)
        loaded = Baseline.load(path)
        assert len(loaded) == len(result.groups)
        assert loaded.note == "test"

    def test_no_plaintext_secret_in_file(self, result: engine.ScanResult, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        Baseline.from_groups(result.groups).save(path)
        assert SECRET not in path.read_text(encoding="utf-8")

    def test_apply_suppresses_known_fingerprints(self, result: engine.ScanResult) -> None:
        baseline = Baseline.from_groups(result.groups)
        kept, suppressed = baseline.apply(result.groups)
        assert kept == []
        assert suppressed == len(result.groups)

    def test_apply_keeps_new_findings(self, result: engine.ScanResult) -> None:
        baseline = Baseline.from_groups(result.groups[:1])
        kept, suppressed = baseline.apply(result.groups)
        assert suppressed == 1
        assert len(kept) == len(result.groups) - 1

    def test_empty_baseline_is_noop(self, result: engine.ScanResult) -> None:
        kept, suppressed = Baseline().apply(result.groups)
        assert suppressed == 0
        assert len(kept) == len(result.groups)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(BaselineError, match="不存在"):
            Baseline.load(tmp_path / "nope.json")

    def test_malformed_file(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(BaselineError, match="无法解析"):
            Baseline.load(path)

    def test_unsupported_version(self, tmp_path: Path) -> None:
        path = tmp_path / "v9.json"
        path.write_text(json.dumps({"version": 9}), encoding="utf-8")
        with pytest.raises(BaselineError, match="不支持的基线版本"):
            Baseline.load(path)


class TestFindingModel:
    def test_context_summary_without_cloud_context(self) -> None:
        finding = Finding(
            rule_id="r",
            rule_name="R",
            severity=Severity.HIGH,
            secret="abc",
            source="f.log",
            line=7,
            byte_offset=0,
            column=3,
        )
        assert finding.context_summary() == "f.log:7:3"

    def test_locator_prefers_json_path(self) -> None:
        finding = Finding(
            rule_id="r",
            rule_name="R",
            severity=Severity.HIGH,
            secret="abc",
            source="f.json",
            line=2,
            byte_offset=0,
            json_path="a.b",
        )
        assert finding.locator == "f.json:2 → a.b"

    def test_group_to_dict(self) -> None:
        finding = Finding(
            rule_id="r",
            rule_name="R",
            severity=Severity.MEDIUM,
            secret="abcdefghij",
            source="f",
            line=1,
            byte_offset=0,
            confidence=Confidence.MEDIUM,
            confidence_score=0.6,
        )
        group = FindingGroup(representative=finding, occurrences=3)
        payload = group.to_dict()
        assert payload["occurrences"] == 3
        assert payload["secret_length"] == 10

    def test_severity_parse_errors(self) -> None:
        with pytest.raises(ValueError, match="未知 severity"):
            Severity.parse("nope")
        with pytest.raises(ValueError, match="未知 confidence"):
            Confidence.parse("nope")

    def test_confidence_from_score(self) -> None:
        assert Confidence.from_score(0.95) is Confidence.HIGH
        assert Confidence.from_score(0.6) is Confidence.MEDIUM
        assert Confidence.from_score(0.1) is Confidence.LOW
