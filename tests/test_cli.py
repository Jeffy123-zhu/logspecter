"""CLI 端到端测试：参数解析、输出格式、退出码、基线、规则子命令。"""

from __future__ import annotations

import csv
import gzip
import io
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logspecter.cli import app, parse_size

SECRET = "AKIA4XZQ7MHB3LKPWCVR"
runner = CliRunner()


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    path = tmp_path / "app.log"
    path.write_text(
        "\n".join(
            [
                "2026-08-30 INFO service started",
                "2026-08-30 INFO trace 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                f"2026-08-30 WARN deploy accessKeyId={SECRET}",
                "2026-08-30 INFO done",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    path = tmp_path / "clean.log"
    path.write_text("2026-08-30 INFO nothing here\n" * 20, encoding="utf-8")
    return path


class TestParseSize:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("1024", 1024),
            ("1k", 1024),
            ("512kb", 512 * 1024),
            ("8MB", 8 * 1024**2),
            ("1.5mb", int(1.5 * 1024**2)),
            ("2GiB", 2 * 1024**3),
        ],
    )
    def test_valid(self, text: str, expected: int) -> None:
        assert parse_size(text) == expected

    @pytest.mark.parametrize("text", ["", "abc", "0", "-5", "10tb"])
    def test_invalid(self, text: str) -> None:
        with pytest.raises(ValueError):
            parse_size(text)


class TestScanCommand:
    def test_table_output_and_exit_code(self, log_file: Path) -> None:
        result = runner.invoke(app, ["scan", str(log_file), "--workers", "1", "--no-progress"])
        assert result.exit_code == 1  # 默认 --fail-on high，发现 critical → 1
        assert "aws-access-key-id" in result.output
        assert SECRET not in result.output

    def test_clean_file_exits_zero(self, clean_file: Path) -> None:
        result = runner.invoke(app, ["scan", str(clean_file), "--workers", "1", "--no-progress"])
        assert result.exit_code == 0
        assert "未发现" in result.output

    def test_fail_on_none_always_exits_zero(self, log_file: Path) -> None:
        result = runner.invoke(
            app, ["scan", str(log_file), "--workers", "1", "--fail-on", "none", "--no-progress"]
        )
        assert result.exit_code == 0

    def test_json_output_to_stdout(self, log_file: Path) -> None:
        result = runner.invoke(
            app,
            ["scan", str(log_file), "--workers", "1", "--format", "json", "--no-progress", "-q"],
        )
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert payload["summary"]["findings"] == 1
        assert payload["findings"][0]["rule_id"] == "aws-access-key-id"
        assert payload["findings"][0]["line"] == 3

    def test_csv_output_to_file(self, log_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.csv"
        result = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--format",
                "csv",
                "-o",
                str(out),
                "--no-progress",
            ],
        )
        assert result.exit_code == 1
        rows = list(csv.DictReader(io.StringIO(out.read_text(encoding="utf-8"))))
        assert rows[0]["rule_id"] == "aws-access-key-id"

    def test_sarif_output(self, log_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.sarif"
        runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "-f",
                "sarif",
                "-o",
                str(out),
                "--no-progress",
            ],
        )
        document = json.loads(out.read_text(encoding="utf-8"))
        assert document["version"] == "2.1.0"

    def test_table_output_to_file(self, log_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.txt"
        runner.invoke(
            app, ["scan", str(log_file), "--workers", "1", "-o", str(out), "--no-progress"]
        )
        assert "aws-access-key-id" in out.read_text(encoding="utf-8")

    def test_show_secrets(self, log_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--format",
                "json",
                "--show-secrets",
                "--no-progress",
                "-q",
            ],
        )
        assert SECRET in result.stdout

    def test_stats_flag(self, log_file: Path) -> None:
        result = runner.invoke(
            app, ["scan", str(log_file), "--workers", "1", "--stats", "--no-progress"]
        )
        assert "扫描统计" in result.output

    def test_exclude_rule(self, log_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--exclude-rule",
                "aws-access-key-id",
                "--no-progress",
            ],
        )
        assert result.exit_code == 0

    def test_pack_filter(self, log_file: Path) -> None:
        result = runner.invoke(
            app,
            ["scan", str(log_file), "--workers", "1", "--pack", "gcp", "--no-progress"],
        )
        assert result.exit_code == 0

    def test_min_severity(self, log_file: Path) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--min-severity",
                "critical",
                "--no-progress",
            ],
        )
        assert result.exit_code == 1

    def test_directory_input(self, tmp_path: Path, log_file: Path) -> None:
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--workers", "1", "--format", "json", "-q", "--no-progress"],
        )
        payload = json.loads(result.stdout)
        assert payload["summary"]["findings"] >= 1

    def test_gzip_input(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log.gz"
        with gzip.open(path, "wb") as handle:
            handle.write(f"pad\nkey={SECRET}\n".encode())
        result = runner.invoke(
            app, ["scan", str(path), "--workers", "1", "-f", "json", "-q", "--no-progress"]
        )
        payload = json.loads(result.stdout)
        assert payload["findings"][0]["line"] == 2

    def test_parallel_matches_serial(self, tmp_path: Path) -> None:
        path = tmp_path / "big.log"
        lines = [f"pad {i:05d}" for i in range(3000)]
        lines[2500] = f"key={SECRET}"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        def run(workers: str) -> dict:
            result = runner.invoke(
                app,
                [
                    "scan",
                    str(path),
                    "--workers",
                    workers,
                    "--chunk-size",
                    "4k",
                    "-f",
                    "json",
                    "-q",
                    "--no-progress",
                ],
            )
            return json.loads(result.stdout)

        serial, parallel = run("1"), run("4")
        assert serial["findings"][0]["line"] == 2501
        assert parallel["findings"][0]["line"] == 2501
        assert serial["summary"]["findings"] == parallel["summary"]["findings"]

    def test_missing_path_errors(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.log"), "--no-progress"])
        assert result.exit_code == 2
        assert "输入路径不存在" in result.output

    def test_bad_chunk_size_errors(self, log_file: Path) -> None:
        result = runner.invoke(app, ["scan", str(log_file), "--chunk-size", "abc", "--no-progress"])
        assert result.exit_code == 2

    def test_all_rules_excluded_errors(self, log_file: Path) -> None:
        result = runner.invoke(
            app, ["scan", str(log_file), "--pack", "does-not-exist", "--no-progress"]
        )
        assert result.exit_code == 2
        assert "没有任何启用的规则" in result.output

    def test_custom_rule_file(self, tmp_path: Path, clean_file: Path) -> None:
        rules = tmp_path / "custom.yaml"
        rules.write_text(
            "version: 1\npack: custom\nrules:\n"
            "  - id: my-marker\n"
            "    name: My Marker\n"
            "    pattern: '(nothing here)'\n"
            "    severity: medium\n"
            "    entropy:\n      enabled: false\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "scan",
                str(clean_file),
                "--rules",
                str(rules),
                "--include-rule",
                "my-marker",
                "--workers",
                "1",
                "-f",
                "json",
                "-q",
                "--no-progress",
            ],
        )
        payload = json.loads(result.stdout)
        assert payload["findings"][0]["rule_id"] == "my-marker"


class TestBaselineWorkflow:
    def test_write_then_suppress(self, log_file: Path, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        first = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--write-baseline",
                str(baseline),
                "--no-progress",
            ],
        )
        assert first.exit_code == 1
        assert baseline.exists()

        second = runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--baseline",
                str(baseline),
                "--no-progress",
            ],
        )
        assert second.exit_code == 0
        assert "未发现" in second.output

    def test_new_secret_still_reported(self, log_file: Path, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        runner.invoke(
            app,
            [
                "scan",
                str(log_file),
                "--workers",
                "1",
                "--write-baseline",
                str(baseline),
                "--no-progress",
            ],
        )
        log_file.write_text(
            log_file.read_text(encoding="utf-8") + "new leak accessKeyId=AKIA7PQR2XYZ8MNBVCLK\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["scan", str(log_file), "--workers", "1", "--baseline", str(baseline), "--no-progress"],
        )
        assert result.exit_code == 1

    def test_bad_baseline_errors(self, log_file: Path, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{oops", encoding="utf-8")
        result = runner.invoke(
            app, ["scan", str(log_file), "--baseline", str(bad), "--no-progress"]
        )
        assert result.exit_code == 2


class TestRulesCommands:
    def test_list(self) -> None:
        result = runner.invoke(app, ["rules", "list"])
        assert result.exit_code == 0
        assert "aws-access-key-id" in result.output

    def test_list_filtered_by_pack(self) -> None:
        result = runner.invoke(app, ["rules", "list", "--pack", "gcp"])
        assert "gcp-api-key" in result.output

    def test_show_structural_rule(self) -> None:
        result = runner.invoke(app, ["rules", "show", "aws-access-key-id"])
        assert result.exit_code == 0
        assert "预筛" in result.output
        assert "结构性规则" in result.output

    @pytest.mark.parametrize(
        "rule_id",
        [
            "aws-secret-access-key",  # 启用熵校验
            "generic-hex-secret",  # require_keyword + 默认关闭
            "sensitive-json-key-value",  # json_keys 结构化规则
            "db-connection-uri-password",  # exclude/关键词组合
        ],
    )
    def test_show_renders_every_branch(self, rule_id: str) -> None:
        """覆盖 rules show 的全部分支：熵门限、关键词、JSON 键、预筛描述。"""
        result = runner.invoke(app, ["rules", "show", rule_id])
        assert result.exit_code == 0, result.output
        assert result.exception is None
        assert rule_id in result.output

    def test_show_all_builtin_rules_without_error(self) -> None:
        from logspecter.rules import load_ruleset

        for rule in load_ruleset():
            result = runner.invoke(app, ["rules", "show", rule.id])
            assert result.exit_code == 0, f"{rule.id}: {result.output}"

    def test_show_unknown(self) -> None:
        result = runner.invoke(app, ["rules", "show", "nope"])
        assert result.exit_code == 2

    def test_validate_ok(self, tmp_path: Path) -> None:
        path = tmp_path / "ok.yaml"
        path.write_text(
            "version: 1\nrules:\n  - id: a-b\n    name: N\n    pattern: 'abc'\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["rules", "validate", str(path)])
        assert result.exit_code == 0
        assert "通过" in result.output

    def test_validate_bad(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(
            "version: 1\nrules:\n  - id: A_B\n    name: N\n    pattern: 'abc'\n", encoding="utf-8"
        )
        result = runner.invoke(app, ["rules", "validate", str(path)])
        assert result.exit_code == 2


class TestMiscCommands:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "logspecter" in result.output
        assert "内置规则" in result.output

    def test_selftest_passes(self) -> None:
        result = runner.invoke(app, ["selftest"])
        assert result.exit_code == 0, result.output
        assert "负样本零误报" in result.output

    def test_benchmark_small(self) -> None:
        result = runner.invoke(app, ["benchmark", "--size", "2MB", "--workers", "1"])
        assert result.exit_code == 0
        assert "吞吐" in result.output

    def test_help(self) -> None:
        assert runner.invoke(app, ["--help"]).exit_code == 0
        assert runner.invoke(app, ["scan", "--help"]).exit_code == 0
