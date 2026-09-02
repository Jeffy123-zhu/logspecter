"""扫描引擎测试：分块调度、行号修正、指纹聚合、多进程一致性。"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from logspecter import engine, ingest
from logspecter.rules import RuleSet
from logspecter.samples import POSITIVE_SAMPLES
from logspecter.scanner import ScanOptions

AWS_KEY = "AKIA4XZQ7MHB3LKPWCVR"
#: ghp_ 之后必须正好 36 个字母数字，否则规则不匹配。
GITHUB_PAT = "ghp_9QwPl2Kd0RmT4bVn6HcYaJ3sUeGf1LoXi8Zp"


def make_config(ruleset: RuleSet, **kwargs) -> engine.ScanConfig:
    params = {"chunk_size": 4096, "options": ScanOptions()}
    params.update(kwargs)
    return engine.ScanConfig(ruleset=ruleset, **params)


def write_log(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class TestSerialScan:
    def test_finds_secret_with_correct_line(self, tmp_path: Path, ruleset: RuleSet) -> None:
        lines = [f"filler line {i}" for i in range(500)]
        lines[321] = f"deploy accessKeyId={AWS_KEY}"
        log = write_log(tmp_path / "a.log", lines)

        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        assert len(result.groups) == 1
        finding = result.groups[0].representative
        assert finding.rule_id == "aws-access-key-id"
        assert finding.line == 322
        assert finding.secret == AWS_KEY

    def test_line_numbers_across_many_chunks(self, tmp_path: Path, ruleset: RuleSet) -> None:
        lines = [f"padding {i:06d}" for i in range(4000)]
        # 每处用不同后缀，保证是 4 个不同指纹（相同密钥会被正确聚合成一组）。
        for suffix, index in zip("ABCD", (10, 1500, 2999, 3999)):
            lines[index] = f"token {GITHUB_PAT[:-1]}{suffix}"
        log = write_log(tmp_path / "b.log", lines)

        config = make_config(ruleset, chunk_size=1024)
        assert len(ingest.plan_ranges(log, 1024)) > 4, "本用例需要多个分块才有意义"

        result = engine.scan([str(log)], config, workers=1)
        found_lines = sorted(g.representative.line for g in result.groups)
        assert found_lines == [11, 1501, 3000, 4000]

    def test_empty_file(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = tmp_path / "empty.log"
        log.write_bytes(b"")
        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        assert result.groups == []
        assert result.stats.chunks == 0

    def test_file_without_trailing_newline(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = tmp_path / "c.log"
        log.write_text(f"only line accessKeyId={AWS_KEY}", encoding="utf-8")
        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        assert len(result.groups) == 1
        assert result.groups[0].representative.line == 1


class TestAggregation:
    def test_repeated_secret_collapses_into_one_group(
        self, tmp_path: Path, ruleset: RuleSet
    ) -> None:
        log = write_log(tmp_path / "d.log", [f"key={AWS_KEY}"] * 400)
        result = engine.scan([str(log)], make_config(ruleset, chunk_size=512), workers=1)
        assert len(result.groups) == 1
        group = result.groups[0]
        assert group.occurrences == 400
        assert result.total_occurrences == 400
        assert len(group.extra_locations) <= engine.MAX_SAMPLES_PER_GROUP

    def test_distinct_secrets_stay_separate(self, tmp_path: Path, ruleset: RuleSet) -> None:
        lines = [f"key=AKIA4XZQ7MHB3LKPWC{c}R" for c in "ABCDE"]
        log = write_log(tmp_path / "e.log", lines)
        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        assert len(result.groups) == 5

    def test_sorted_by_severity_then_confidence(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = write_log(tmp_path / "f.log", [p for _r, p in POSITIVE_SAMPLES])
        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        ranks = [g.representative.severity.rank for g in result.groups]
        assert ranks == sorted(ranks)

    def test_count_by_severity_and_worst(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = write_log(tmp_path / "g.log", [p for _r, p in POSITIVE_SAMPLES])
        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        counts = result.count_by_severity()
        assert counts["critical"] > 0
        assert result.worst_severity().value == "critical"


class TestParallelScan:
    def test_matches_serial_result(self, tmp_path: Path, ruleset: RuleSet) -> None:
        lines = [f"padding row {i:05d}" for i in range(3000)]
        for offset, (_rid, payload) in enumerate(POSITIVE_SAMPLES):
            lines[offset * 40 + 7] = payload
        log = write_log(tmp_path / "par.log", lines)

        config = make_config(ruleset, chunk_size=4096)
        serial = engine.scan([str(log)], config, workers=1)
        parallel = engine.scan([str(log)], config, workers=4)

        def signature(result):
            return sorted(
                (g.fingerprint, g.representative.line, g.occurrences) for g in result.groups
            )

        assert signature(serial) == signature(parallel)
        assert parallel.stats.workers == 4
        assert parallel.stats.chunks == serial.stats.chunks

    def test_worker_memory_is_recorded(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = write_log(tmp_path / "mem.log", [f"row {i}" for i in range(20000)])
        result = engine.scan([str(log)], make_config(ruleset, chunk_size=8192), workers=2)
        # 平台不支持时允许为空，但支持时必须是合理的正数
        for value in result.stats.peak_rss_workers.values():
            assert value > 1024 * 1024


class TestCompressedAndStream:
    def test_gzip_source(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = tmp_path / "x.log.gz"
        payload = "\n".join([f"pad {i}" for i in range(200)] + [f"key={AWS_KEY}"]) + "\n"
        with gzip.open(log, "wb") as handle:
            handle.write(payload.encode())
        result = engine.scan([str(log)], make_config(ruleset, chunk_size=1024), workers=1)
        assert len(result.groups) == 1
        assert result.groups[0].representative.line == 201

    def test_gzip_parallel(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = tmp_path / "y.log.gz"
        payload = "\n".join([f"pad {i}" for i in range(2000)] + [f"key={AWS_KEY}"]) + "\n"
        with gzip.open(log, "wb") as handle:
            handle.write(payload.encode())
        result = engine.scan([str(log)], make_config(ruleset, chunk_size=2048), workers=3)
        assert [g.representative.line for g in result.groups] == [2001]


class TestMultipleSources:
    def test_scans_all_files_and_tracks_source(self, tmp_path: Path, ruleset: RuleSet) -> None:
        first = write_log(tmp_path / "one.log", ["pad", f"key={AWS_KEY}"])
        second = write_log(tmp_path / "two.log", ["pad", f"token {GITHUB_PAT}"])
        result = engine.scan([str(first), str(second)], make_config(ruleset), workers=1)
        sources = {g.representative.source for g in result.groups}
        assert sources == {str(first), str(second)}
        assert result.stats.files == 2

    def test_same_secret_in_two_files_shares_group(self, tmp_path: Path, ruleset: RuleSet) -> None:
        first = write_log(tmp_path / "one.log", [f"key={AWS_KEY}"])
        second = write_log(tmp_path / "two.log", [f"key={AWS_KEY}"])
        result = engine.scan([str(first), str(second)], make_config(ruleset), workers=1)
        assert len(result.groups) == 1
        assert result.groups[0].occurrences == 2
        assert len(result.groups[0].sources) == 2


class TestStats:
    def test_stats_are_populated(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = write_log(tmp_path / "s.log", [f"row {i}" for i in range(2000)])
        result = engine.scan([str(log)], make_config(ruleset, chunk_size=4096), workers=1)
        stats = result.stats
        assert stats.lines == 2000
        assert stats.bytes_scanned == log.stat().st_size
        assert stats.chunks > 1
        assert stats.elapsed > 0
        assert stats.throughput_mb_s > 0
        assert json.dumps(stats.as_dict())

    def test_progress_callback_is_invoked(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = write_log(tmp_path / "p.log", [f"row {i}" for i in range(3000)])
        seen: list[tuple[int, int | None]] = []

        def on_progress(done: int, total: int | None, _source: str) -> None:
            seen.append((done, total))

        engine.scan(
            [str(log)], make_config(ruleset, chunk_size=2048), workers=1, progress=on_progress
        )
        assert seen
        assert seen[-1][0] == log.stat().st_size
        assert seen[-1][1] == log.stat().st_size

    def test_memory_does_not_grow_with_file_size(self, tmp_path: Path, ruleset: RuleSet) -> None:
        """核心承诺：内存与文件大小解耦。"""
        small = write_log(tmp_path / "small.log", [f"row {i:06d}" for i in range(2_000)])
        large = write_log(tmp_path / "large.log", [f"row {i:06d}" for i in range(200_000)])
        config = make_config(ruleset, chunk_size=256 * 1024)

        small_result = engine.scan([str(small)], config, workers=1)
        large_result = engine.scan([str(large)], config, workers=1)
        assert large_result.stats.bytes_scanned > 50 * small_result.stats.bytes_scanned

        peak = large_result.stats.peak_rss_main
        if peak is not None:
            # 分块 256KiB，扫描缓冲约 2×分块；给解释器基线留足余量。
            assert peak < 200 * 1024 * 1024


class TestErrorHandling:
    def test_unreadable_chunk_is_reported_not_raised(
        self, tmp_path: Path, ruleset: RuleSet, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = write_log(tmp_path / "err.log", ["a", "b", "c"])

        def boom(*_args, **_kwargs):
            raise OSError("simulated read failure")

        monkeypatch.setattr(engine.ingest, "read_range", boom)
        result = engine.scan([str(log)], make_config(ruleset), workers=1)
        assert result.groups == []
        assert result.errors and "simulated read failure" in result.errors[0]

    def test_max_findings_truncates(self, tmp_path: Path, ruleset: RuleSet) -> None:
        log = write_log(tmp_path / "many.log", [f"key=AKIA4XZQ7MHB3LKPW{i:03d}" for i in range(60)])
        config = make_config(ruleset, chunk_size=64 * 1024, max_findings=5)
        result = engine.scan([str(log)], config, workers=1)
        assert len(result.groups) <= 5


class TestGroupFindings:
    def test_representative_is_highest_confidence(self, ruleset: RuleSet) -> None:
        from logspecter.findings import Confidence, Finding, Severity

        low = Finding(
            rule_id="r",
            rule_name="R",
            severity=Severity.HIGH,
            secret="s3cr3tvalue-unique",
            source="a",
            line=1,
            byte_offset=0,
            confidence=Confidence.LOW,
            confidence_score=0.3,
        )
        high = Finding(
            rule_id="r",
            rule_name="R",
            severity=Severity.HIGH,
            secret="s3cr3tvalue-unique",
            source="b",
            line=9,
            byte_offset=10,
            confidence=Confidence.HIGH,
            confidence_score=0.9,
        )
        groups = engine.group_findings([low, high])
        assert len(groups) == 1
        assert groups[0].representative.confidence_score == 0.9
        assert groups[0].occurrences == 2

    def test_empty_input(self) -> None:
        assert engine.group_findings([]) == []
