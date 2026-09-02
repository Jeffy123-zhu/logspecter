"""终端渲染（Rich）。

设计目标是「一屏之内看懂事故」：先给结论（多少条、最严重什么等级、是否需要
阻断），再给逐条证据。每条证据都同时呈现三样东西 —— 云端身份/动作、精确的
JSON 路径、以及熵值判定依据，让人能立刻判断是真泄露还是需要调阈值。
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from rich.box import ROUNDED, SIMPLE
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from logspecter import __version__
from logspecter.findings import FindingGroup, Severity
from logspecter.sysinfo import format_bytes

__all__ = ["SEVERITY_STYLES", "render_report", "render_rules_table", "render_stats"]

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_CONFIDENCE_STYLES = {"high": "green", "medium": "yellow", "low": "dim"}

#: 低于该终端宽度就放弃表格布局，避免列被压成一个字符宽。
_MIN_TABLE_WIDTH = 104


def _severity_label(severity: Severity) -> Text:
    return Text(f" {severity.value.upper()} ", style=SEVERITY_STYLES[severity])


def render_report(
    console: Console,
    result: Any,
    *,
    show_secrets: bool = False,
    verbose: bool = False,
    max_rows: int = 200,
    show_summary: bool = True,
) -> None:
    """渲染扫描结果主体。"""
    groups: Sequence[FindingGroup] = result.groups
    if show_summary:
        console.print(_summary_panel(result))

    if not groups:
        console.print(
            Panel(
                Text("未发现符合规则的凭据泄露。", style="green"),
                title="结果",
                border_style="green",
                box=ROUNDED,
            )
        )
        return

    # 窄终端里表格会把列压到一个字符宽，改用纵向紧凑布局。
    if console.width < _MIN_TABLE_WIDTH:
        _render_compact(console, groups[:max_rows], show_secrets=show_secrets)
    else:
        console.print(_findings_table(groups[:max_rows], show_secrets=show_secrets))
    if len(groups) > max_rows:
        console.print(
            Text(
                f"… 另有 {len(groups) - max_rows} 条未在终端展示，请用 --output 导出完整报告。",
                style="dim",
            )
        )

    if verbose:
        for group in groups[:max_rows]:
            console.print(_detail_panel(group, show_secrets=show_secrets))

    if result.errors:
        console.print(
            Panel(
                Text("\n".join(result.errors[:20]), style="yellow"),
                title=f"扫描过程中的错误（{len(result.errors)}）",
                border_style="yellow",
                box=ROUNDED,
            )
        )


def _summary_panel(result: Any) -> Panel:
    stats = result.stats
    counts = result.count_by_severity()
    worst = result.worst_severity()

    header = Table.grid(padding=(0, 2))
    header.add_column(justify="right", style="dim")
    header.add_column()

    header.add_row(
        "唯一泄露", f"[bold]{len(result.groups)}[/] 条（总出现 {result.total_occurrences} 次）"
    )
    if counts:
        parts = [
            f"[{SEVERITY_STYLES[Severity(name)]}] {name} × {value} [/]"
            for name, value in sorted(counts.items(), key=lambda kv: Severity(kv[0]).rank)
        ]
        header.add_row("等级分布", " ".join(parts))
    header.add_row(
        "扫描量",
        f"{stats.files} 个来源 / {stats.chunks} 个块 / "
        f"{format_bytes(stats.bytes_scanned)} / {stats.lines:,} 行",
    )
    header.add_row(
        "性能",
        f"{stats.elapsed:.2f}s · {stats.throughput_mb_s:.1f} MiB/s · {stats.workers} 进程",
    )
    header.add_row(
        "内存峰值",
        f"单进程最高 {format_bytes(stats.peak_rss_max_process)}"
        f"（全部进程合计 {format_bytes(stats.peak_rss_total)}）",
    )
    suppressed = stats.counters.suppressed_total
    if suppressed:
        candidates = stats.counters.regex_candidates or 1
        ratio = suppressed / candidates * 100
        header.add_row(
            "降噪",
            f"正则候选 {candidates:,} → 熵值/上下文层拦下 {suppressed:,} 条（{ratio:.1f}%）",
        )
    if stats.suppressed_by_baseline:
        header.add_row("基线抑制", f"{stats.suppressed_by_baseline} 条已知项")
    if stats.truncated:
        header.add_row("提示", "[yellow]命中数量达到上限，结果已截断[/]")

    border = "red" if worst and worst.rank <= Severity.HIGH.rank else "green"
    return Panel(
        header,
        title=f"LogSpecter v{__version__} 扫描摘要",
        border_style=border,
        box=ROUNDED,
    )


def _render_compact(
    console: Console, groups: Iterable[FindingGroup], *, show_secrets: bool
) -> None:
    """窄终端下的紧凑布局：每条命中三行。"""
    for group in groups:
        finding = group.representative
        secret = finding.secret if show_secrets else finding.secret_masked
        head = Text()
        head.append_text(_severity_label(finding.severity))
        head.append(" ")
        head.append(finding.rule_id, style="bold cyan")
        head.append(f"  ×{group.occurrences}", style="dim")
        head.append(f"  conf {finding.confidence_score:.2f}", style="dim")
        head.append(f"  H {finding.entropy:.2f}", style="dim")
        console.print(head)
        console.print(Text(f"  {finding.context_summary()}"))
        detail = Text("  ")
        detail.append(f"{finding.source}:{finding.line}", style="dim")
        detail.append("  ")
        detail.append(secret, style="magenta" if show_secrets else "dim magenta")
        console.print(detail)
        console.print()


def _findings_table(groups: Iterable[FindingGroup], *, show_secrets: bool) -> Table:
    table = Table(
        box=SIMPLE,
        show_lines=False,
        header_style="bold",
        expand=True,
        pad_edge=False,
    )
    table.add_column("等级", width=10, no_wrap=True)
    table.add_column("规则", style="bold cyan", min_width=20, overflow="fold")
    table.add_column("云端上下文 / 定位", overflow="fold", ratio=3, min_width=30)
    table.add_column("凭据", min_width=18, max_width=30, overflow="fold")
    table.add_column("置信/熵", width=11, no_wrap=True)
    table.add_column("次数", width=5, justify="right", no_wrap=True)

    for group in groups:
        finding = group.representative
        secret = finding.secret if show_secrets else finding.secret_masked
        confidence_style = _CONFIDENCE_STYLES.get(finding.confidence.value, "white")
        table.add_row(
            _severity_label(finding.severity),
            finding.rule_id,
            _location_cell(group),
            Text(secret, style="magenta" if show_secrets else "dim magenta"),
            Text(
                f"{finding.confidence_score:.2f} / {finding.entropy:.2f}",
                style=confidence_style,
            ),
            str(group.occurrences),
        )
    return table


def _location_cell(group: FindingGroup) -> Text:
    finding = group.representative
    cell = Text()
    cell.append(finding.context_summary(), style="white")
    cell.append("\n")
    cell.append(f"{finding.source}:{finding.line}", style="dim")
    if finding.byte_offset:
        cell.append(f" @byte {finding.byte_offset}", style="dim")
    schema = finding.cloud_context.get("schema")
    if schema:
        cell.append(f"  [{schema}]", style="dim blue")
    return cell


def _detail_panel(group: FindingGroup, *, show_secrets: bool) -> Panel:
    finding = group.representative
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="dim", width=14)
    grid.add_column(overflow="fold")

    grid.add_row("规则", f"{finding.rule_id} — {finding.rule_name}")
    grid.add_row("指纹", group.fingerprint)
    grid.add_row("凭据", finding.secret if show_secrets else finding.secret_masked)
    grid.add_row(
        "熵值",
        f"{finding.entropy:.4f} bit/char（归一化 {finding.normalized_entropy:.3f}，"
        f"字符集 {finding.charset}）",
    )
    grid.add_row("判定依据", ", ".join(finding.evidence) or "-")
    if finding.matched_context:
        grid.add_row("证据片段", Text(finding.matched_context, style="dim"))
    if finding.cloud_context:
        for key in ("schema", "actor", "action", "resource", "region", "source_ip", "timestamp"):
            value = finding.cloud_context.get(key)
            if value:
                grid.add_row(key, value)
    if group.json_paths:
        grid.add_row("JSON 路径", "\n".join(sorted(group.json_paths)[:8]))
    if group.extra_locations:
        grid.add_row("其他位置", "\n".join(group.extra_locations))
    if finding.tags:
        grid.add_row("标签", ", ".join(finding.tags))

    return Panel(
        grid,
        title=f"{finding.severity.value.upper()} · {finding.rule_id}",
        border_style=SEVERITY_STYLES[finding.severity].split()[-1],
        box=ROUNDED,
    )


def render_stats(console: Console, result: Any) -> None:
    """渲染详细统计（``--stats``）。"""
    stats = result.stats
    counters = stats.counters

    perf = Table.grid(padding=(0, 2))
    perf.add_column(justify="right", style="dim")
    perf.add_column()
    perf.add_row("耗时", f"{stats.elapsed:.3f} s")
    perf.add_row("吞吐", f"{stats.throughput_mb_s:.2f} MiB/s")
    perf.add_row("字节 / 行", f"{stats.bytes_scanned:,} B / {stats.lines:,} 行")
    perf.add_row("块 / 进程", f"{stats.chunks} / {stats.workers}")
    perf.add_row("JSON 记录解析", f"{counters.json_records:,} 条")
    perf.add_row("主进程内存峰值", format_bytes(stats.peak_rss_main))
    if stats.peak_rss_workers:
        detail = ", ".join(
            f"pid {pid}: {format_bytes(value)}"
            for pid, value in sorted(stats.peak_rss_workers.items())
        )
        perf.add_row("worker 内存峰值", detail)
    perf.add_row("单进程峰值上限", format_bytes(stats.peak_rss_max_process))

    noise = Table(box=SIMPLE, header_style="bold", expand=True)
    noise.add_column("降噪环节")
    noise.add_column("数量", justify="right")
    noise.add_row("正则初筛候选", f"{counters.regex_candidates:,}")
    noise.add_row("熵值/启发式拦截", f"{sum(counters.suppressed_by_entropy.values()):,}")
    noise.add_row("关键词邻近拦截", f"{sum(counters.suppressed_by_keyword.values()):,}")
    noise.add_row("置信度阈值拦截", f"{sum(counters.suppressed_by_confidence.values()):,}")
    noise.add_row("最终报出", f"{counters.accepted:,}")

    reasons = Table(box=SIMPLE, header_style="bold", expand=True)
    reasons.add_column("拦截原因")
    reasons.add_column("次数", justify="right")
    for reason, count in counters.suppressed_reasons.most_common(12):
        reasons.add_row(reason, f"{count:,}")

    console.print(
        Panel(
            Group(perf, Text(""), noise, Text(""), reasons),
            title="扫描统计",
            border_style="blue",
            box=ROUNDED,
        )
    )


def render_rules_table(console: Console, ruleset: Any, *, show_pattern: bool = False) -> None:
    """渲染规则清单（``logspecter rules list``）。"""
    table = Table(box=SIMPLE, header_style="bold", expand=True)
    table.add_column("规则 ID", style="bold cyan", overflow="fold")
    table.add_column("等级", width=10)
    table.add_column("包", width=14)
    table.add_column("熵门限", width=16, no_wrap=True)
    table.add_column("状态", width=8)
    table.add_column("名称", overflow="fold")
    if show_pattern:
        table.add_column("正则", overflow="fold")

    for rule in ruleset:
        gate = rule.entropy
        if gate.enabled:
            gate_text = f"H≥{gate.min_entropy:g} n≥{gate.min_normalized:g}"
        else:
            gate_text = "结构性"
        row = [
            rule.id,
            _severity_label(rule.severity),
            rule.pack,
            gate_text,
            Text("启用", style="green") if rule.enabled else Text("默认关闭", style="dim"),
            rule.name,
        ]
        if show_pattern:
            row.append(Text(rule.pattern, style="dim"))
        table.add_row(*row)

    console.print(table)
    console.print(
        Text(
            f"共 {len(ruleset.rules)} 条规则，启用 {len(ruleset.enabled_rules())} 条；"
            f"规则包: {', '.join(ruleset.packs)}",
            style="dim",
        )
    )
