"""命令行入口（Typer）。

子命令：

* ``scan``      —— 主扫描命令，支持文件/目录/压缩包/stdin 管道。
* ``rules``     —— 规则库查看与校验。
* ``benchmark`` —— 生成合成日志并压测吞吐与内存，用于验证性能承诺。
* ``selftest``  —— 内置正/负样本自检，验证检出能力与降噪能力。

退出码约定（便于 CI 使用）：

* ``0`` 未发现达到阈值的泄露
* ``1`` 发现达到 ``--fail-on`` 阈值的泄露
* ``2`` 参数错误 / 输入不可读 / 规则非法
"""

import contextlib
import dataclasses
import enum
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)

from logspecter import __version__, engine, ingest, report
from logspecter.baseline import Baseline, BaselineError
from logspecter.findings import Severity
from logspecter.rules import RuleSyntaxError, load_ruleset
from logspecter.scanner import ScanOptions
from logspecter.structured import JSON_BACKEND
from logspecter.sysinfo import cpu_count, format_bytes

app = typer.Typer(
    name="logspecter",
    help="云端结构化日志的凭据泄露扫描器：正则 + 香农熵 + Schema 感知，流式低内存。",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
rules_app = typer.Typer(help="规则库查看与校验。", no_args_is_help=True)
app.add_typer(rules_app, name="rules")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class OutputFormat(str, enum.Enum):
    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"


class FailOn(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class ReaderMode(str, enum.Enum):
    MMAP = "mmap"
    BUFFERED = "buffered"


# --------------------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------------------

_SIZE_UNITS = {
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "gib": 1024**3,
}


def parse_size(text: str) -> int:
    """解析 ``8MB`` / ``512k`` / ``1048576`` 这类大小表达式，返回字节数。

    Raises:
        ValueError: 无法解析或非正数。
    """
    raw = str(text).strip().lower().replace("_", "")
    if not raw:
        raise ValueError("大小不能为空")
    digits = raw
    unit = "b"
    for index, char in enumerate(raw):
        if not (char.isdigit() or char == "."):
            digits, unit = raw[:index], raw[index:]
            break
    if not digits:
        raise ValueError(f"无法解析大小: {text!r}")
    if unit not in _SIZE_UNITS:
        raise ValueError(f"未知单位 {unit!r}，可用: b/kb/mb/gb")
    value = int(float(digits) * _SIZE_UNITS[unit])
    if value <= 0:
        raise ValueError(f"大小必须为正数: {text!r}")
    return value


def _fail(console: Console, message: str) -> None:
    console.print(f"[bold red]错误[/] {message}")
    raise typer.Exit(EXIT_ERROR)


def _apply_entropy_override(ruleset, min_entropy: float | None):
    """用命令行给定的全局熵门限覆盖各规则（仅影响启用了熵校验的规则）。"""
    if min_entropy is None:
        return ruleset
    updated = []
    for rule in ruleset.rules:
        if rule.entropy.enabled:
            gate = dataclasses.replace(rule.entropy, min_entropy=min_entropy)
            updated.append(dataclasses.replace(rule, entropy=gate))
        else:
            updated.append(rule)
    return dataclasses.replace(ruleset, rules=tuple(updated))


def _build_ruleset(
    console: Console,
    *,
    rule_paths: list[str],
    builtin: bool,
    include: list[str],
    exclude: list[str],
    enable: list[str],
    packs: list[str],
    tags: list[str],
    min_severity: Severity | None,
    aggressive: bool,
    min_entropy: float | None,
):
    try:
        ruleset = load_ruleset(rule_paths, include_builtin=builtin)
    except RuleSyntaxError as exc:
        _fail(console, str(exc))
        raise  # pragma: no cover - _fail 已抛出

    ruleset = ruleset.select(
        include=include,
        exclude=exclude,
        enable=enable,
        packs=packs,
        tags=tags,
        min_severity=min_severity,
        enable_all=aggressive,
    )
    ruleset = _apply_entropy_override(ruleset, min_entropy)
    if not ruleset.enabled_rules():
        _fail(console, "筛选后没有任何启用的规则，请检查 --include-rule / --pack / --min-severity")
    return ruleset


# --------------------------------------------------------------------------------------
# scan
# --------------------------------------------------------------------------------------


@app.command(help="扫描日志文件、目录、压缩包或标准输入。")
def scan(
    paths: list[str] | None = typer.Argument(
        None,
        metavar="[PATHS]...",
        help="待扫描的文件或目录；'-' 表示标准输入。省略时若检测到管道则自动读 stdin。",
    ),
    rule_paths: list[str] | None = typer.Option(
        None, "--rules", "-r", help="附加 YAML 规则文件或目录（可重复，同 id 覆盖内置规则）。"
    ),
    builtin_rules: bool = typer.Option(
        True, "--builtin-rules/--no-builtin-rules", help="是否加载内置规则包。"
    ),
    include_rule: list[str] | None = typer.Option(
        None, "--include-rule", help="仅启用这些规则（支持 id / pack:名 / tag:名 / 通配符）。"
    ),
    exclude_rule: list[str] | None = typer.Option(None, "--exclude-rule", help="排除这些规则。"),
    enable_rule: list[str] | None = typer.Option(
        None, "--enable-rule", help="额外启用默认关闭的规则。"
    ),
    pack: list[str] | None = typer.Option(None, "--pack", help="仅使用指定规则包。"),
    tag: list[str] | None = typer.Option(None, "--tag", help="仅使用带指定标签的规则。"),
    aggressive: bool = typer.Option(
        False, "--aggressive", help="启用全部规则（含默认关闭的纯高熵规则），召回优先。"
    ),
    min_severity: FailOn | None = typer.Option(
        None, "--min-severity", help="只加载不低于该等级的规则。"
    ),
    min_entropy: float | None = typer.Option(
        None, "--min-entropy", help="全局覆盖香农熵门限（bit/char），仅影响启用熵校验的规则。"
    ),
    min_confidence: float = typer.Option(
        0.0, "--min-confidence", min=0.0, max=1.0, help="丢弃低于该置信度的命中。"
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-j", help=f"并发进程数（默认自动，本机 {cpu_count()} 核）；1 为单进程。"
    ),
    chunk_size: str = typer.Option(
        "4MB", "--chunk-size", help="分块大小，决定内存上界与并行粒度（如 8MB / 512k）。"
    ),
    reader: ReaderMode = typer.Option(
        ReaderMode.MMAP, "--reader", help="可 seek 文件的读取方式：mmap 或 buffered。"
    ),
    structured: bool = typer.Option(
        True,
        "--structured/--no-structured",
        help="是否启用云原生 Schema 感知（JSON 路径 + 上下文）。",
    ),
    nested_json: bool = typer.Option(
        True, "--nested-json/--no-nested-json", help="是否递归解析内嵌的 JSON 字符串。"
    ),
    max_line_bytes: str = typer.Option("256k", "--max-line-bytes", help="单行扫描字节上限。"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", "-f", help="输出格式。"
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="报告写入文件；省略则写标准输出。"
    ),
    show_secrets: bool = typer.Option(
        False, "--show-secrets", help="输出凭据明文（默认脱敏，请谨慎使用）。"
    ),
    baseline_path: str | None = typer.Option(
        None, "--baseline", help="基线文件，命中其中的指纹将被抑制。"
    ),
    write_baseline: str | None = typer.Option(
        None, "--write-baseline", help="把本次结果写成基线文件（用于 CI 只对新增泄露报警）。"
    ),
    fail_on: FailOn = typer.Option(
        FailOn.HIGH, "--fail-on", help="达到该等级即以退出码 1 结束；none 表示永不失败。"
    ),
    stats: bool = typer.Option(False, "--stats", help="输出吞吐、内存峰值与降噪统计。"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="为每条命中输出完整证据面板。"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="只输出报告本体，不打印进度与摘要。"),
    progress_bar: bool = typer.Option(True, "--progress/--no-progress", help="是否显示进度条。"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", help="目录是否递归遍历。"),
    all_files: bool = typer.Option(
        False, "--all-files", help="遍历目录时纳入所有文件（默认只看常见日志后缀）。"
    ),
) -> None:
    # 报告走 stdout 时，所有交互信息必须走 stderr，否则会污染管道输出。
    to_stdout = output is None and output_format is not OutputFormat.TABLE
    ui = Console(stderr=to_stdout, highlight=False, soft_wrap=False)
    out_console = Console(highlight=False)

    try:
        chunk_bytes = parse_size(chunk_size)
        line_limit = parse_size(max_line_bytes)
    except ValueError as exc:
        _fail(ui, str(exc))
        return

    raw_paths = list(paths or [])
    if not raw_paths:
        if sys.stdin is not None and not sys.stdin.isatty():
            raw_paths = [ingest.STDIN_SENTINEL]
        else:
            _fail(
                ui,
                "未指定输入。给出文件/目录路径，或用管道传入日志（如 cat app.log | logspecter scan -）",
            )
            return

    try:
        sources = ingest.resolve_inputs(raw_paths, recursive=recursive, follow_all=all_files)
    except FileNotFoundError as exc:
        _fail(ui, str(exc))
        return
    if not sources:
        _fail(ui, "输入路径下没有匹配到任何文件（可尝试 --all-files）")
        return

    severity_floor = (
        None if min_severity in (None, FailOn.NONE) else Severity.parse(min_severity.value)  # type: ignore[union-attr]
    )
    ruleset = _build_ruleset(
        ui,
        rule_paths=list(rule_paths or []),
        builtin=builtin_rules,
        include=list(include_rule or []),
        exclude=list(exclude_rule or []),
        enable=list(enable_rule or []),
        packs=list(pack or []),
        tags=list(tag or []),
        min_severity=severity_floor,
        aggressive=aggressive,
        min_entropy=min_entropy,
    )

    loaded_baseline: Baseline | None = None
    if baseline_path:
        try:
            loaded_baseline = Baseline.load(baseline_path)
        except BaselineError as exc:
            _fail(ui, str(exc))
            return

    options = ScanOptions(
        structured=structured,
        nested_json=nested_json,
        max_line_bytes=line_limit,
        min_confidence=min_confidence,
    )
    config = engine.ScanConfig(
        ruleset=ruleset,
        options=options,
        chunk_size=chunk_bytes,
        reader=reader.value,
    )

    if not quiet:
        ui.print(
            f"[dim]LogSpecter v{__version__} · {len(ruleset.enabled_rules())} 条规则 · "
            f"JSON 后端 {JSON_BACKEND} · 分块 {format_bytes(chunk_bytes)}[/]"
        )

    show_progress = progress_bar and not quiet and ui.is_terminal
    result = _run_scan(ui, sources, config, workers, show_progress)

    if loaded_baseline is not None:
        result.groups, suppressed = loaded_baseline.apply(result.groups)
        result.stats.suppressed_by_baseline = suppressed

    if write_baseline:
        try:
            written = Baseline.from_groups(
                result.groups, note=f"generated by logspecter {__version__}"
            ).save(write_baseline)
        except OSError as exc:
            _fail(ui, f"基线写入失败: {exc}")
            return
        if not quiet:
            ui.print(f"[green]已写入基线[/] {written}（{len(result.groups)} 条指纹）")

    # ---- 输出 ----
    if output_format is OutputFormat.TABLE:
        if output is None:
            target = out_console
        else:
            # 写文件时固定宽度并录制，避免受终端宽度影响。
            target = Console(record=True, width=150, highlight=False, file=_NullWriter())
        report.render_report(
            target,
            result,
            show_secrets=show_secrets,
            verbose=verbose,
            show_summary=not quiet,
        )
        if stats:
            report.render_stats(target, result)
        if output is not None:
            _write_output(ui, output, target.export_text())
    else:
        payload = report.export(result, output_format.value, include_secret=show_secrets)
        if output is None:
            sys.stdout.write(payload if payload.endswith("\n") else payload + "\n")
        else:
            _write_output(ui, output, payload)
        if stats and not quiet:
            report.render_stats(ui, result)

    if result.errors and not quiet:
        ui.print(f"[yellow]注意[/] 扫描过程中有 {len(result.errors)} 个块出错，详见报告。")

    raise typer.Exit(_exit_code(result, fail_on))


def _run_scan(
    ui: Console,
    sources: list[str],
    config: "engine.ScanConfig",
    workers: int | None,
    show_progress: bool,
) -> "engine.ScanResult":
    if not show_progress:
        return engine.scan(sources, config, workers=workers)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TransferSpeedColumn(),
        TimeElapsedColumn(),
        console=ui,
        transient=True,
    ) as progress:
        task = progress.add_task("扫描中", total=None)

        def on_progress(done: int, total: int | None, source: str) -> None:
            progress.update(
                task,
                completed=done,
                total=total,
                description=f"扫描 {Path(source).name if source != '-' else 'stdin'}",
            )

        return engine.scan(sources, config, workers=workers, progress=on_progress)


class _NullWriter:
    """吞掉输出的假文件对象：Rich 只需要 record 缓冲，不需要真正写到某处。"""

    encoding = "utf-8"

    def write(self, _text: str) -> int:
        return 0

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False


def _write_output(ui: Console, output: str, payload: str) -> None:
    try:
        path = Path(output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    except OSError as exc:
        _fail(ui, f"报告写入失败: {exc}")
        return
    ui.print(f"[green]报告已写入[/] {path}")


def _exit_code(result: "engine.ScanResult", fail_on: FailOn) -> int:
    if fail_on is FailOn.NONE:
        return EXIT_OK
    threshold = Severity.parse(fail_on.value)
    for group in result.groups:
        if group.representative.severity.rank <= threshold.rank:
            return EXIT_FINDINGS
    return EXIT_OK


# --------------------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------------------


@rules_app.command("list", help="列出规则库中的全部规则。")
def rules_list(
    rule_paths: list[str] | None = typer.Option(None, "--rules", "-r", help="附加规则文件或目录。"),
    builtin_rules: bool = typer.Option(True, "--builtin-rules/--no-builtin-rules"),
    pack: list[str] | None = typer.Option(None, "--pack", help="只看指定规则包。"),
    show_pattern: bool = typer.Option(False, "--show-pattern", help="同时显示正则源串。"),
) -> None:
    console = Console(highlight=False)
    try:
        ruleset = load_ruleset(list(rule_paths or []), include_builtin=builtin_rules)
    except RuleSyntaxError as exc:
        _fail(console, str(exc))
        return
    if pack:
        ruleset = ruleset.select(packs=list(pack))
    report.render_rules_table(console, ruleset, show_pattern=show_pattern)


@rules_app.command("show", help="显示单条规则的完整定义与字面量预筛条件。")
def rules_show(
    rule_id: str = typer.Argument(..., help="规则 id。"),
    rule_paths: list[str] | None = typer.Option(None, "--rules", "-r"),
) -> None:
    from logspecter.prefilter import LiteralPrefilter

    console = Console(highlight=False)
    try:
        ruleset = load_ruleset(list(rule_paths or []))
    except RuleSyntaxError as exc:
        _fail(console, str(exc))
        return

    rule = next((r for r in ruleset if r.id == rule_id), None)
    if rule is None:
        _fail(console, f"未找到规则 {rule_id!r}（用 logspecter rules list 查看全部）")
        return

    # 与扫描器保持一致：require_keyword 规则的关键词也算合法预筛条件。
    prefilter = LiteralPrefilter.build(
        rule.pattern,
        ignore_case=rule.ignore_case,
        extra_group=rule.keywords if rule.require_keyword else (),
    )
    gate = rule.entropy
    console.print(f"[bold cyan]{rule.id}[/] — {rule.name}")
    console.print(f"  包        {rule.pack}")
    console.print(f"  等级/置信 {rule.severity.value} / {rule.confidence.value}")
    console.print(f"  状态      {'启用' if rule.enabled else '默认关闭'}")
    console.print(f"  正则      {rule.pattern}")
    console.print(f"  捕获组    {rule.capture}")
    if rule.exclude_pattern:
        console.print(f"  排除      {rule.exclude_pattern}")
    if rule.keywords:
        need = "必须" if rule.require_keyword else "可选"
        console.print(
            f"  关键词    {', '.join(rule.keywords)}（{need}，窗口 ±{rule.keyword_window}）"
        )
    if rule.json_keys:
        console.print(f"  JSON 键   {', '.join(rule.json_keys)}")
    if gate.enabled:
        console.print(
            f"  熵门限    H≥{gate.min_entropy} 归一化≥{gate.min_normalized} "
            f"长度 {gate.min_length}~{gate.max_length} "
            f"字符集覆盖率≥{gate.min_charset_coverage}"
        )
        console.print(
            f"            拒绝: 占位符={gate.reject_placeholders} "
            f"编码文本={gate.reject_encoded_text} UUID={gate.reject_uuid} "
            f"语言相似度>{gate.max_word_likeness}"
        )
    else:
        console.print("  熵门限    结构性规则，跳过熵校验（仅保留占位符过滤）")
    console.print(f"  预筛      {prefilter.describe()}")
    if rule.tags:
        console.print(f"  标签      {', '.join(rule.tags)}")
    if rule.description:
        console.print(f"  说明      {rule.description}")
    for ref in rule.references:
        console.print(f"  参考      {ref}")


@rules_app.command("validate", help="校验自定义规则文件是否合法，并检查预筛健全性。")
def rules_validate(
    rule_paths: list[str] = typer.Argument(..., help="待校验的 YAML 文件或目录。"),
    builtin_rules: bool = typer.Option(
        False, "--builtin-rules/--no-builtin-rules", help="是否一并加载内置规则。"
    ),
) -> None:
    console = Console(highlight=False)
    try:
        ruleset = load_ruleset(list(rule_paths), include_builtin=builtin_rules)
    except RuleSyntaxError as exc:
        _fail(console, str(exc))
        return

    console.print(
        f"[green]通过[/] 共 {len(ruleset)} 条规则，启用 {len(ruleset.enabled_rules())} 条"
    )
    for rule in ruleset:
        from logspecter.prefilter import LiteralPrefilter

        prefilter = LiteralPrefilter.build(
            rule.pattern,
            ignore_case=rule.ignore_case,
            extra_group=rule.keywords if rule.require_keyword else (),
        )
        marker = (
            prefilter.describe() if prefilter.active else "[yellow]全量扫描（每行都会执行正则）[/]"
        )
        console.print(f"  {rule.id:44s} {marker}")


# --------------------------------------------------------------------------------------
# selftest / benchmark
# --------------------------------------------------------------------------------------


@app.command(help="内置自检：验证检出能力（正样本）与降噪能力（负样本）。")
def selftest(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="显示每个样本的判定明细。"),
) -> None:
    from logspecter.samples import NEGATIVE_SAMPLES, POSITIVE_SAMPLES
    from logspecter.scanner import Scanner

    console = Console(highlight=False)
    # 自检启用**全部**规则（含默认关闭的高噪声规则）：正样本用来验证召回，
    # 负样本用来验证「即使在最激进的配置下也不误报」。
    scanner = Scanner(load_ruleset().select(enable_all=True), ScanOptions())

    missed: list[str] = []
    false_positives: list[str] = []

    for index, (expected_rule, payload) in enumerate(POSITIVE_SAMPLES, start=1):
        hits = scanner.scan_line(
            payload.encode(), source="<selftest>", local_line=index, byte_offset=0
        )
        matched = {h.rule_id for h in hits}
        also = {
            evidence.split(":", 1)[1]
            for h in hits
            for evidence in h.evidence
            if evidence.startswith("also-matched:")
        }
        if expected_rule not in (matched | also):
            missed.append(f"{expected_rule}: {payload[:90]}")
        elif verbose:
            console.print(f"[green]✓[/] {expected_rule}")

    for index, payload in enumerate(NEGATIVE_SAMPLES, start=1):
        hits = scanner.scan_line(
            payload.encode(), source="<selftest>", local_line=index, byte_offset=0
        )
        if hits:
            false_positives.append(f"{hits[0].rule_id}: {payload[:90]}")
        elif verbose:
            console.print(f"[green]✓[/] 负样本已抑制: {payload[:60]}")

    total_positive = len(POSITIVE_SAMPLES)
    total_negative = len(NEGATIVE_SAMPLES)
    console.print()
    console.print(
        f"检出率 [bold]{total_positive - len(missed)}/{total_positive}[/]"
        f"  ·  负样本零误报 [bold]{total_negative - len(false_positives)}/{total_negative}[/]"
    )
    if missed:
        console.print("[red]漏报:[/]")
        for item in missed:
            console.print(f"  - {item}")
    if false_positives:
        console.print("[red]误报:[/]")
        for item in false_positives:
            console.print(f"  - {item}")

    raise typer.Exit(EXIT_OK if not missed and not false_positives else EXIT_FINDINGS)


@app.command(help="生成合成日志并压测吞吐与内存峰值。")
def benchmark(
    size: str = typer.Option("256MB", "--size", help="生成的合成日志大小（如 1GB）。"),
    workers: int | None = typer.Option(None, "--workers", "-j", help="并发进程数。"),
    chunk_size: str = typer.Option("4MB", "--chunk-size", help="分块大小。"),
    reader: ReaderMode = typer.Option(ReaderMode.MMAP, "--reader"),
    keep: str | None = typer.Option(
        None, "--keep", help="把生成的日志保留到指定路径（默认用完即删）。"
    ),
    secret_ratio: float = typer.Option(
        0.0002, "--secret-ratio", min=0.0, max=1.0, help="植入真实密钥的行比例。"
    ),
) -> None:
    import tempfile

    from logspecter.samples import POSITIVE_SAMPLES, write_synthetic_log

    console = Console(highlight=False)
    try:
        target_bytes = parse_size(size)
        chunk_bytes = parse_size(chunk_size)
    except ValueError as exc:
        _fail(console, str(exc))
        return

    if keep:
        log_path = Path(keep).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        # 这里刻意不用 with：需要文件在句柄关闭后继续存在，用完在 finally 里删。
        handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
            prefix="logspecter-bench-", suffix=".log", delete=False
        )
        handle.close()
        log_path = Path(handle.name)

    try:
        console.print(f"[dim]生成合成日志 {format_bytes(target_bytes)} → {log_path}[/]")
        started = time.perf_counter()
        written, lines, planted = write_synthetic_log(
            log_path, target_bytes, secret_ratio=secret_ratio
        )
        console.print(
            f"[dim]生成完成: {format_bytes(written)} / {lines:,} 行 / "
            f"植入 {planted} 条真实密钥 / {time.perf_counter() - started:.1f}s[/]"
        )

        ruleset = load_ruleset()
        config = engine.ScanConfig(
            ruleset=ruleset,
            options=ScanOptions(),
            chunk_size=chunk_bytes,
            reader=reader.value,
        )
        result = engine.scan([str(log_path)], config, workers=workers)

        stats = result.stats
        console.print()
        console.print(f"[bold]吞吐[/]        {stats.throughput_mb_s:.1f} MiB/s")
        console.print(f"[bold]耗时[/]        {stats.elapsed:.2f} s")
        console.print(f"[bold]行数[/]        {stats.lines:,}")
        console.print(f"[bold]进程数[/]      {stats.workers}（块 {stats.chunks} 个）")
        console.print(f"[bold]主进程峰值[/]  {format_bytes(stats.peak_rss_main)}")
        if stats.peak_rss_workers:
            worst = max(stats.peak_rss_workers.values())
            console.print(
                f"[bold]worker 峰值[/]  最高 {format_bytes(worst)} "
                f"（{len(stats.peak_rss_workers)} 个进程，合计 {format_bytes(stats.peak_rss_total)}）"
            )
        # 植入的密钥来自固定样本池，同一把密钥会被重复植入，因此「唯一凭据数」
        # 应接近样本池规模，而「总出现次数」才应接近植入行数。
        console.print(
            f"[bold]检出[/]        {len(result.groups)} 条唯一凭据 / "
            f"{result.total_occurrences} 次出现（植入 {planted} 行，样本池 {len(POSITIVE_SAMPLES)} 种）"
        )
        console.print(
            f"[bold]降噪[/]        候选 {stats.counters.regex_candidates:,} → "
            f"拦截 {stats.counters.suppressed_total:,}"
        )
    finally:
        if not keep:
            with contextlib.suppress(OSError):
                log_path.unlink()


@app.command(help="显示版本与运行环境信息。")
def version() -> None:
    console = Console(highlight=False)
    console.print(f"logspecter {__version__}")
    console.print(f"python     {sys.version.split()[0]} ({sys.platform})")
    console.print(f"json 后端  {JSON_BACKEND}")
    console.print(f"CPU 核数   {cpu_count()}")
    try:
        ruleset = load_ruleset()
        console.print(f"内置规则   {len(ruleset)} 条 / {len(ruleset.packs)} 个包")
    except RuleSyntaxError as exc:  # pragma: no cover
        console.print(f"[red]规则加载失败[/] {exc}")


def main() -> None:
    """控制台入口。"""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
