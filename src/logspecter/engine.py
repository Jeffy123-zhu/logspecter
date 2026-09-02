"""扫描编排引擎：分块调度、多进程执行、行号修正、指纹聚合。

调度策略按输入源类型分流：

* **可 seek 文件** → :func:`ingest.plan_ranges` 规划行对齐区间，任务只传
  ``(路径, 起止偏移)``（几十字节），worker 各自 mmap 自己那一段。数据不经过
  进程间管道，这是吞吐能上去的关键。
* **压缩文件 / stdin** → 主进程按块读出行对齐字节块并分发。此时数据必须走管道，
  因此用**有界提交窗口**（in-flight ≤ workers × 2）把内存钉住。

行号修正：worker 只汇报块内相对行号 + 该块的总行数；主进程收齐同一文件的所有
块后，用行数前缀和一次性把相对行号换算为绝对行号。这样既不需要预先全量数行，
也能给出准确的 ``file:line``。
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from logspecter import ingest, sysinfo
from logspecter.findings import Finding, FindingGroup, Severity
from logspecter.ingest import SourceKind
from logspecter.rules import RuleSet
from logspecter.scanner import ScanCounters, Scanner, ScanOptions

__all__ = [
    "MAX_SAMPLES_PER_GROUP",
    "ChunkResult",
    "ScanConfig",
    "ScanResult",
    "ScanStats",
    "group_findings",
    "scan",
]

#: 每个指纹分组最多保留多少条额外定位样本。
MAX_SAMPLES_PER_GROUP = 5
#: 默认最多保留多少条原始命中，超出后停止累积（防御「整个文件都是密钥」的极端输入）。
DEFAULT_MAX_FINDINGS = 200_000


@dataclass(slots=True, frozen=True)
class ScanConfig:
    """一次扫描的完整配置。所有字段均可 pickle，可直接下发给 worker。"""

    ruleset: RuleSet
    options: ScanOptions = field(default_factory=ScanOptions)
    chunk_size: int = ingest.DEFAULT_CHUNK_SIZE
    #: ``mmap``（默认，靠映射窗口控内存）或 ``buffered``（固定缓冲，极限省内存）。
    reader: str = "mmap"
    max_findings: int = DEFAULT_MAX_FINDINGS


@dataclass(slots=True)
class ChunkResult:
    """单个块的扫描结果。"""

    source: str
    chunk_index: int
    line_count: int = 0
    byte_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    counters: ScanCounters = field(default_factory=ScanCounters)
    pid: int = 0
    peak_rss: int | None = None
    error: str | None = None


@dataclass(slots=True)
class ScanStats:
    """全局统计。"""

    files: int = 0
    chunks: int = 0
    bytes_scanned: int = 0
    lines: int = 0
    workers: int = 1
    elapsed: float = 0.0
    counters: ScanCounters = field(default_factory=ScanCounters)
    peak_rss_main: int | None = None
    #: pid → 该 worker 进程的峰值常驻内存。
    peak_rss_workers: dict[int, int] = field(default_factory=dict)
    suppressed_by_baseline: int = 0
    truncated: bool = False

    @property
    def throughput_bytes(self) -> float:
        return self.bytes_scanned / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def throughput_mb_s(self) -> float:
        return self.throughput_bytes / (1024 * 1024)

    @property
    def peak_rss_total(self) -> int | None:
        """主进程 + 所有 worker 的峰值内存之和（保守上界）。"""
        if self.peak_rss_main is None and not self.peak_rss_workers:
            return None
        return (self.peak_rss_main or 0) + sum(self.peak_rss_workers.values())

    @property
    def peak_rss_max_process(self) -> int | None:
        """单进程峰值内存的最大值。"""
        values = [v for v in (self.peak_rss_main, *self.peak_rss_workers.values()) if v]
        return max(values) if values else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "chunks": self.chunks,
            "bytes_scanned": self.bytes_scanned,
            "lines": self.lines,
            "workers": self.workers,
            "elapsed_seconds": round(self.elapsed, 4),
            "throughput_mib_per_second": round(self.throughput_mb_s, 2),
            "peak_rss_main": self.peak_rss_main,
            "peak_rss_workers": dict(self.peak_rss_workers),
            "peak_rss_max_process": self.peak_rss_max_process,
            "peak_rss_total": self.peak_rss_total,
            "suppressed_by_baseline": self.suppressed_by_baseline,
            "truncated": self.truncated,
            "detection": self.counters.as_dict(),
        }


@dataclass(slots=True)
class ScanResult:
    """扫描结果：按指纹聚合后的分组 + 统计 + 错误。"""

    groups: list[FindingGroup] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_occurrences(self) -> int:
        return sum(g.occurrences for g in self.groups)

    def worst_severity(self) -> Severity | None:
        if not self.groups:
            return None
        return min((g.representative.severity for g in self.groups), key=lambda s: s.rank)

    def count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for group in self.groups:
            key = group.representative.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts


# --------------------------------------------------------------------------------------
# worker 侧
# --------------------------------------------------------------------------------------

_WORKER_SCANNER: Scanner | None = None
_WORKER_CONFIG: ScanConfig | None = None


def _init_worker(config: ScanConfig) -> None:
    """worker 进程初始化：每个进程只编译一次规则，随后常驻复用。"""
    global _WORKER_SCANNER, _WORKER_CONFIG
    _WORKER_CONFIG = config
    _WORKER_SCANNER = Scanner(config.ruleset, config.options)


def _scan_bytes(
    scanner: Scanner,
    data: bytes,
    *,
    source: str,
    base_offset: int,
    chunk_index: int,
    max_findings: int,
) -> ChunkResult:
    scan = scanner.scan_chunk(data, source=source, base_offset=base_offset, chunk_index=chunk_index)
    findings = scan.findings[:max_findings] if len(scan.findings) > max_findings else scan.findings
    return ChunkResult(
        source=source,
        chunk_index=chunk_index,
        line_count=scan.line_count,
        byte_count=scan.byte_count,
        findings=findings,
    )


def _worker_scan_range(task: tuple[str, int, int, int]) -> ChunkResult:
    """worker 入口：扫描某个文件的一个字节区间。"""
    source, start, end, index = task
    assert _WORKER_SCANNER is not None and _WORKER_CONFIG is not None
    scanner = _WORKER_SCANNER
    scanner.counters = ScanCounters()
    try:
        data = ingest.read_range(source, start, end, reader=_WORKER_CONFIG.reader)
        result = _scan_bytes(
            scanner,
            data,
            source=source,
            base_offset=start,
            chunk_index=index,
            max_findings=_WORKER_CONFIG.max_findings,
        )
    except Exception as exc:
        result = ChunkResult(source=source, chunk_index=index, error=f"{type(exc).__name__}: {exc}")
    result.counters = scanner.counters
    result.byte_count = end - start
    result.pid = os.getpid()
    result.peak_rss = sysinfo.peak_rss()
    return result


def _worker_scan_block(task: tuple[str, bytes, int, int]) -> ChunkResult:
    """worker 入口：扫描一个内存字节块（压缩文件 / stdin 路径）。"""
    source, block, base_offset, index = task
    assert _WORKER_SCANNER is not None and _WORKER_CONFIG is not None
    scanner = _WORKER_SCANNER
    scanner.counters = ScanCounters()
    try:
        result = _scan_bytes(
            scanner,
            block,
            source=source,
            base_offset=base_offset,
            chunk_index=index,
            max_findings=_WORKER_CONFIG.max_findings,
        )
    except Exception as exc:
        result = ChunkResult(source=source, chunk_index=index, error=f"{type(exc).__name__}: {exc}")
    result.counters = scanner.counters
    result.byte_count = len(block)
    result.pid = os.getpid()
    result.peak_rss = sysinfo.peak_rss()
    return result


# --------------------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------------------

ProgressCallback = Callable[[int, int | None, str], None]


def scan(
    paths: Sequence[str],
    config: ScanConfig,
    *,
    workers: int | None = None,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """执行扫描。

    Args:
        paths: 已展开的输入文件列表（``-`` 表示 stdin）。
        config: 规则集与检测选项。
        workers: 进程数。``None`` 表示自动（CPU 核数，上限 8），``1`` 表示单进程。
        progress: 进度回调 ``(已扫描字节, 总字节或 None, 当前文件)``。

    Returns:
        :class:`ScanResult`
    """
    if workers is None:
        workers = min(8, sysinfo.cpu_count())
    workers = max(1, workers)

    total_bytes = _estimate_total_bytes(paths)
    stats = ScanStats(workers=workers)
    result = ScanResult(stats=stats, sources=list(paths))

    started = time.perf_counter()
    scanned_bytes = 0

    if workers == 1:
        scanner = Scanner(config.ruleset, config.options)
        chunk_stream: Iterator[ChunkResult] = _run_serial(paths, config, scanner)
    else:
        chunk_stream = _run_parallel(paths, config, workers)

    per_source_chunks: dict[str, dict[int, int]] = {}
    per_source_findings: dict[str, list[Finding]] = {}

    for chunk in chunk_stream:
        stats.chunks += 1
        if chunk.error:
            result.errors.append(f"{chunk.source} [chunk {chunk.chunk_index}]: {chunk.error}")
            continue

        stats.bytes_scanned += chunk.byte_count
        stats.lines += chunk.line_count
        stats.counters.merge(chunk.counters)
        if chunk.peak_rss and chunk.pid and chunk.pid != os.getpid():
            previous = stats.peak_rss_workers.get(chunk.pid, 0)
            stats.peak_rss_workers[chunk.pid] = max(previous, chunk.peak_rss)

        per_source_chunks.setdefault(chunk.source, {})[chunk.chunk_index] = chunk.line_count
        if chunk.findings:
            bucket = per_source_findings.setdefault(chunk.source, [])
            if len(bucket) < config.max_findings:
                bucket.extend(chunk.findings)
            else:
                stats.truncated = True

        scanned_bytes += chunk.byte_count
        if progress is not None:
            progress(scanned_bytes, total_bytes, chunk.source)

    stats.elapsed = time.perf_counter() - started
    stats.files = len(paths)
    stats.peak_rss_main = sysinfo.peak_rss()

    findings = _resolve_absolute_lines(per_source_findings, per_source_chunks)
    result.groups = group_findings(findings)
    return result


def _estimate_total_bytes(paths: Sequence[str]) -> int | None:
    """能确定总量时返回字节数，含 stdin/压缩文件时返回 ``None``。"""
    total = 0
    for path in paths:
        if ingest.classify(path) is not SourceKind.SEEKABLE:
            return None
        try:
            total += os.path.getsize(path)
        except OSError:
            return None
    return total


def _iter_tasks_for_source(
    source: str, config: ScanConfig
) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """为单个输入源生成任务。``kind`` 为 ``range`` 或 ``block``。"""
    kind = ingest.classify(source)
    if kind is SourceKind.SEEKABLE:
        for byte_range in ingest.plan_ranges(source, config.chunk_size):
            yield "range", (source, byte_range.start, byte_range.end, byte_range.index)
        return

    stream = ingest.open_binary(source)
    try:
        for byte_range, block in ingest.iter_stream_blocks(stream, config.chunk_size):
            yield "block", (source, block, byte_range.start, byte_range.index)
    finally:
        stream.close()


def _run_serial(
    paths: Sequence[str], config: ScanConfig, scanner: Scanner
) -> Iterator[ChunkResult]:
    """单进程路径：不启动子进程，便于调试、测试与小文件场景。"""
    for source in paths:
        for kind, task in _iter_tasks_for_source(source, config):
            scanner.counters = ScanCounters()
            try:
                if kind == "range":
                    _src, start, end, index = task
                    data = ingest.read_range(_src, start, end, reader=config.reader)
                    chunk = _scan_bytes(
                        scanner,
                        data,
                        source=_src,
                        base_offset=start,
                        chunk_index=index,
                        max_findings=config.max_findings,
                    )
                    chunk.byte_count = end - start
                else:
                    _src, block, base_offset, index = task
                    chunk = _scan_bytes(
                        scanner,
                        block,
                        source=_src,
                        base_offset=base_offset,
                        chunk_index=index,
                        max_findings=config.max_findings,
                    )
                    chunk.byte_count = len(block)
            except Exception as exc:
                yield ChunkResult(
                    source=source,
                    chunk_index=task[-1],
                    error=f"{type(exc).__name__}: {exc}",
                )
                continue
            chunk.counters = scanner.counters
            chunk.pid = os.getpid()
            yield chunk


def _run_parallel(paths: Sequence[str], config: ScanConfig, workers: int) -> Iterator[ChunkResult]:
    """多进程路径：有界提交窗口 + 结果乱序回收。"""
    max_inflight = max(2, workers * 2)
    with ProcessPoolExecutor(
        max_workers=workers, initializer=_init_worker, initargs=(config,)
    ) as pool:
        pending: set[Future[ChunkResult]] = set()
        for source in paths:
            for kind, task in _iter_tasks_for_source(source, config):
                func = _worker_scan_range if kind == "range" else _worker_scan_block
                pending.add(pool.submit(func, task))  # type: ignore[arg-type]
                # 有界窗口：压缩流/stdin 场景下防止把整个文件读进任务队列。
                while len(pending) >= max_inflight:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    for future in done:
                        yield _harvest(future)
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                yield _harvest(future)


def _harvest(future: Future[ChunkResult]) -> ChunkResult:
    try:
        return future.result()
    except Exception as exc:
        return ChunkResult(source="<worker>", chunk_index=-1, error=f"{type(exc).__name__}: {exc}")


def _resolve_absolute_lines(
    per_source_findings: dict[str, list[Finding]],
    per_source_chunks: dict[str, dict[int, int]],
) -> list[Finding]:
    """用各块行数的前缀和，把块内相对行号换算成整文件绝对行号。"""
    resolved: list[Finding] = []
    for source, findings in per_source_findings.items():
        counts = per_source_chunks.get(source, {})
        offsets: dict[int, int] = {}
        running = 0
        for index in sorted(counts):
            offsets[index] = running
            running += counts[index]
        for finding in findings:
            base = offsets.get(finding.chunk_index, 0)
            finding.line = base + (finding.local_line or finding.line)
            resolved.append(finding)
    return resolved


def group_findings(findings: Iterable[Finding]) -> list[FindingGroup]:
    """按指纹聚合命中。

    同一把密钥在日志里出现十万次也只呈现为一条，附带出现次数与若干定位样本，
    这是让报告在真实生产日志上依然可读的前提。
    """
    groups: dict[str, FindingGroup] = {}
    for finding in findings:
        key = finding.fingerprint
        group = groups.get(key)
        if group is None:
            group = FindingGroup(representative=finding)
            group.sources.add(finding.source)
            if finding.json_path:
                group.json_paths.add(finding.json_path)
            groups[key] = group
            continue

        group.occurrences += 1
        group.sources.add(finding.source)
        if finding.json_path:
            group.json_paths.add(finding.json_path)
        if len(group.extra_locations) < MAX_SAMPLES_PER_GROUP:
            group.extra_locations.append(finding.locator)
        # 保留置信度更高的作为代表条目。
        if finding.confidence_score > group.representative.confidence_score:
            representative = group.representative
            group.representative = finding
            group.extra_locations.insert(0, representative.locator)
            del group.extra_locations[MAX_SAMPLES_PER_GROUP:]

    ordered = sorted(
        groups.values(),
        key=lambda g: (
            g.representative.severity.rank,
            -g.representative.confidence_score,
            -g.occurrences,
            g.representative.rule_id,
        ),
    )
    return ordered
