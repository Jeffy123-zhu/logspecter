r"""检测核心：字节级、出现位置驱动的数据块扫描流水线。

## 为什么不逐行跑正则

最直觉的实现是「逐行 × 逐规则」，但那是 O(行数 × 规则数) 次 Python 级调用，
实测只有 3 MiB/s。本模块把成本模型改成 **O(规则数 × 数据量的 memchr 级扫描)
\+ O(触发字面量出现次数)**：

1. **块级层次剪枝**（:class:`~logspecter.prefilter.ScreenTree`）
   一个 8 MiB 数据块先走筛选树。干净的块一次约 2.5 ms 的 trie 搜索就能排除全部规则；
   只有出现了可疑字面量的块才继续下探到具体规则。

2. **出现位置驱动**
   对每条存活规则，用它「最具选择性的字面量」在整块里枚举出现位置（``bytes.find`` /
   trie ``search``，C 级）。只在**包含该字面量的那一行**上运行真正的正则。
   因为出现位置单调递增，处理完一行后直接把游标推到行尾，天然完成同行去重。

3. **延迟结构化解析**
   JSON 解析同样由「敏感键字面量的出现位置」驱动 —— 没有 ``password`` /
   ``authorization`` 之类键名的行，一次 JSON 都不会解。

4. **命中后才付的成本**
   行号（换行计数）、云上下文抽取、JSON 路径反查，全部只对最终命中执行。

## 判定链

正则候选 → 排除式正则 → 关键词邻近 → 香农熵 + 启发式 → 置信度阈值 → 重叠折叠。
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from logspecter import cloud, entropy, structured
from logspecter.findings import Confidence, Finding
from logspecter.prefilter import LiteralPrefilter, ScreenTree, trie_pattern
from logspecter.rules import CompiledRule, RuleSet

__all__ = ["ChunkScan", "ScanCounters", "ScanOptions", "Scanner"]

_NEWLINE = b"\n"


@dataclass(slots=True, frozen=True)
class ScanOptions:
    """检测行为开关。全部字段可 pickle，用于跨进程下发。"""

    #: 是否启用云原生 Schema 感知（JSON 路径 + 云端上下文）。
    structured: bool = True
    #: 是否递归解析内嵌 JSON 字符串。
    nested_json: bool = True
    #: 单行扫描字节上限，超出部分截断（防御被塞进日志的巨型 payload）。
    max_line_bytes: int = 262_144
    #: 单条记录最多展开多少个 JSON 节点。
    max_json_nodes: int = 4096
    #: JSON 最大递归深度。
    max_json_depth: int = 16
    #: 同一规则在同一行最多报告多少次命中。
    max_matches_per_rule: int = 8
    #: 低于该置信度的命中直接丢弃（0~1）。
    min_confidence: float = 0.0
    #: 证据片段展示的上下文字符数（单侧）。
    context_chars: int = 72
    #: 命中关键词邻近校验时的置信度加成。
    keyword_bonus: float = 0.08
    #: 命中敏感 JSON 键时的置信度加成。
    structured_bonus: float = 0.10
    #: 折叠同一位置的重叠命中，只保留最精确的一条。
    collapse_overlaps: bool = True
    #: 是否启用块级层次剪枝（关闭仅用于对照测试）。
    screen_chunks: bool = True
    #: 筛选树叶子容量。实测叶子越小、节点越多，剪枝收益反而被节点自身的搜索开销
    #: 吃掉（真实日志里 60 条规则通常有 30+ 条能在 8 MiB 内找到触发字面量）。
    #: 默认取 32 → 只建 3 个节点：既保留「整块无任何可疑字面量时一次排除全部规则」
    #: 的快速通道，又几乎不引入额外成本。
    screen_leaf_size: int = 32


@dataclass(slots=True)
class ScanCounters:
    """降噪与性能统计，用于 ``--stats`` 与误报率评估。"""

    lines: int = 0
    bytes_: int = 0
    json_records: int = 0
    regex_candidates: int = 0
    accepted: int = 0
    #: 块级剪枝后仍需扫描的规则数累计（除以 chunks 得平均值）。
    active_rules: int = 0
    chunks: int = 0
    suppressed_by_entropy: Counter[str] = field(default_factory=Counter)
    suppressed_by_keyword: Counter[str] = field(default_factory=Counter)
    suppressed_by_confidence: Counter[str] = field(default_factory=Counter)
    suppressed_reasons: Counter[str] = field(default_factory=Counter)

    @property
    def suppressed_total(self) -> int:
        return (
            sum(self.suppressed_by_entropy.values())
            + sum(self.suppressed_by_keyword.values())
            + sum(self.suppressed_by_confidence.values())
        )

    def merge(self, other: ScanCounters) -> None:
        self.lines += other.lines
        self.bytes_ += other.bytes_
        self.json_records += other.json_records
        self.regex_candidates += other.regex_candidates
        self.accepted += other.accepted
        self.active_rules += other.active_rules
        self.chunks += other.chunks
        self.suppressed_by_entropy.update(other.suppressed_by_entropy)
        self.suppressed_by_keyword.update(other.suppressed_by_keyword)
        self.suppressed_by_confidence.update(other.suppressed_by_confidence)
        self.suppressed_reasons.update(other.suppressed_reasons)

    def as_dict(self) -> dict[str, Any]:
        return {
            "lines": self.lines,
            "bytes": self.bytes_,
            "json_records": self.json_records,
            "regex_candidates": self.regex_candidates,
            "accepted": self.accepted,
            "avg_active_rules_per_chunk": (
                round(self.active_rules / self.chunks, 1) if self.chunks else 0.0
            ),
            "suppressed_total": self.suppressed_total,
            "suppressed_by_entropy": dict(self.suppressed_by_entropy.most_common()),
            "suppressed_by_keyword": dict(self.suppressed_by_keyword.most_common()),
            "suppressed_by_confidence": dict(self.suppressed_by_confidence.most_common()),
            "suppression_reasons": dict(self.suppressed_reasons.most_common(20)),
        }


@dataclass(slots=True)
class ChunkScan:
    """一个数据块的扫描结果。"""

    findings: list[Finding] = field(default_factory=list)
    line_count: int = 0
    byte_count: int = 0


@dataclass(slots=True)
class _RuleEntry:
    compiled: CompiledRule
    prefilter: LiteralPrefilter
    #: 关键词的字节形式（已小写）。
    keywords: tuple[bytes, ...]
    json_keys: tuple[str, ...]


@dataclass(slots=True)
class _Hit:
    """尚未补全上下文的中间命中。"""

    finding: Finding
    line_start: int
    line_end: int


class Scanner:
    """块级检测器。每个 worker 进程构建一份，编译成本只付一次。"""

    __slots__ = (
        "_json_entries",
        "_key_literals",
        "_key_regex",
        "_screen",
        "_text_entries",
        "counters",
        "options",
    )

    def __init__(self, ruleset: RuleSet, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()
        self.counters = ScanCounters()

        text_entries: list[_RuleEntry] = []
        json_entries: list[_RuleEntry] = []
        key_literals: set[str] = set()

        for compiled in ruleset.compile():
            rule = compiled.rule
            # require_keyword 规则的关键词必然出现在同一行，可当作合法预筛条件，
            # 这让 generic-hex-secret 这类无字面量特征的规则也能进入筛选树。
            extra = rule.keywords if rule.require_keyword else ()
            entry = _RuleEntry(
                compiled=compiled,
                prefilter=LiteralPrefilter.build(
                    rule.pattern, ignore_case=rule.ignore_case, extra_group=extra
                ),
                keywords=tuple(k.lower().encode("utf-8") for k in rule.keywords),
                json_keys=rule.json_keys,
            )
            if rule.json_keys:
                json_entries.append(entry)
                key_literals.update(rule.json_keys)
            else:
                text_entries.append(entry)

        self._text_entries = tuple(text_entries)
        self._json_entries = tuple(json_entries)
        self._screen = ScreenTree.build(
            [e.prefilter for e in self._text_entries],
            leaf_size=self.options.screen_leaf_size,
        )
        self._key_literals = tuple(sorted(key_literals))
        self._key_regex = (
            re.compile(trie_pattern(self._key_literals).encode("utf-8"))
            if self._key_literals
            else None
        )

    # ------------------------------------------------------------------ 对外接口

    @property
    def screen_summary(self) -> str:
        """筛选树规模摘要，用于诊断。"""
        return (
            f"screened={self._screen.screened} always={len(self._screen.always)} "
            f"json_rules={len(self._json_entries)} key_literals={len(self._key_literals)}"
        )

    def scan_chunk(
        self,
        data: bytes,
        *,
        source: str,
        base_offset: int = 0,
        chunk_index: int = 0,
    ) -> ChunkScan:
        """扫描一个行边界对齐的数据块。

        Args:
            data: 块内容。必须以完整行组成（引擎保证行对齐）。
            source: 数据来源标识。
            base_offset: 该块在原文件中的起始字节偏移。
            chunk_index: 块序号，供引擎做行号前缀和修正。

        Returns:
            :class:`ChunkScan`，其中 ``Finding.local_line`` 为**块内**行号（1 起）。
        """
        counters = self.counters
        counters.chunks += 1
        counters.bytes_ += len(data)
        line_count = data.count(_NEWLINE)
        if data and not data.endswith(_NEWLINE):
            line_count += 1
        counters.lines += line_count

        result = ChunkScan(line_count=line_count, byte_count=len(data))
        if not data:
            return result

        lowered = data.lower()

        # ---- 步骤 1：块级层次剪枝 ----
        if self.options.screen_chunks:
            active_indices = self._screen.select(lowered)
        else:
            active_indices = list(range(len(self._text_entries)))
        counters.active_rules += len(active_indices)

        hits: list[_Hit] = []

        # ---- 步骤 2：出现位置驱动的文本规则扫描 ----
        for index in active_indices:
            entry = self._text_entries[index]
            self._scan_entry(entry, data, lowered, hits, source, base_offset, chunk_index)

        # ---- 步骤 3：出现位置驱动的结构化扫描 ----
        if self.options.structured and self._json_entries and self._key_regex is not None:
            self._scan_structured(data, lowered, hits, source, base_offset, chunk_index)

        if not hits:
            return result

        # ---- 步骤 4：行号解析 + 上下文补全 + 重叠折叠 ----
        result.findings = self._finalize(data, hits)
        counters.accepted += len(result.findings)
        return result

    def scan_line(
        self,
        data: bytes,
        *,
        source: str,
        local_line: int = 1,
        byte_offset: int = 0,
        chunk_index: int = 0,
    ) -> list[Finding]:
        """扫描单独一行。等价于把该行当作一个数据块，便于测试与自检。"""
        scan = self.scan_chunk(
            data if data.endswith(_NEWLINE) else data + _NEWLINE,
            source=source,
            base_offset=byte_offset,
            chunk_index=chunk_index,
        )
        for finding in scan.findings:
            finding.line = local_line
            finding.local_line = local_line
        return scan.findings

    # ------------------------------------------------------------------ 文本规则

    def _scan_entry(
        self,
        entry: _RuleEntry,
        data: bytes,
        lowered: bytes,
        hits: list[_Hit],
        source: str,
        base_offset: int,
        chunk_index: int,
    ) -> None:
        """用规则的触发字面量枚举出现位置，并逐行执行正则。

        这是整个扫描器最热的循环，因此刻意做了内联优化：行边界直接用 ``rfind`` /
        ``find`` 算而不调用辅助函数，且在进入重量级的 ``_process_line`` 之前先用一次
        ``regex.search`` 快速否决 —— 「字面量在但正则不匹配」是最常见的情形
        （如 CloudTrail 里遍地的 ``"key": "year=2026/..."``），这条捷径把它压到
        一次 C 级调用。
        """
        prefilter = entry.prefilter
        hay = lowered if prefilter.ignore_case else data
        total = len(data)
        has_trigger = bool(prefilter.trigger) or prefilter.trigger_regex is not None
        cursor = prefilter.trigger_cursor(hay) if has_trigger else None
        regex = entry.compiled.regex
        multi_group = len(prefilter.byte_groups) > 1
        max_line = self.options.max_line_bytes
        newline = _NEWLINE
        anchor = prefilter.anchor_span
        position = 0

        while position < total:
            if cursor is not None:
                index = cursor.next_from(position)
                if index < 0:
                    return
            else:
                index = position  # 无预筛条件的规则：整块逐行扫描

            line_start = hay.rfind(newline, 0, index) + 1
            found = hay.find(newline, index)
            line_end = total if found < 0 else found
            # 出现位置单调递增，直接推进到下一行，天然完成同行去重。
            position = line_end + 1
            if line_end > line_start and hay[line_end - 1] == 13:  # 去掉行尾 \r
                line_end -= 1
            if line_end - line_start > max_line:
                line_end = line_start + max_line

            if multi_group and not prefilter.present_except_driver(hay, line_start, line_end):
                continue

            # 关键优化：字面量在匹配中的前缀宽度已知时，只在少数确定位置上做锚定
            # match，而不是让正则在整行里 search。CloudTrail 这类日志里
            # 「字面量在、但正则不匹配」是最高频的情形，这条捷径把它从
            # 数微秒的回溯降到一次 C 调用。
            if anchor is not None:
                lo = index - anchor[1]
                if lo < line_start:
                    lo = line_start
                hi = index - anchor[0]
                matched = False
                while lo <= hi:
                    if regex.match(data, lo, line_end) is not None:
                        matched = True
                        break
                    lo += 1
                if not matched:
                    continue
            elif regex.search(data, line_start, line_end) is None:
                continue

            self._process_line(
                entry, data, lowered, line_start, line_end, hits, source, base_offset, chunk_index
            )

    def _process_line(
        self,
        entry: _RuleEntry,
        data: bytes,
        lowered: bytes,
        line_start: int,
        line_end: int,
        hits: list[_Hit],
        source: str,
        base_offset: int,
        chunk_index: int,
    ) -> None:
        """慢路径：确认该行存在正则匹配后，逐个匹配做完整校验。"""
        self._apply_rule(
            entry,
            data=data,
            lowered=lowered,
            span=(line_start, line_end),
            hits=hits,
            source=source,
            base_offset=base_offset,
            chunk_index=chunk_index,
            json_path=None,
            structured_hit=False,
        )

    def _apply_rule(
        self,
        entry: _RuleEntry,
        *,
        data: bytes,
        lowered: bytes,
        span: tuple[int, int],
        hits: list[_Hit],
        source: str,
        base_offset: int,
        chunk_index: int,
        json_path: str | None,
        structured_hit: bool,
        value_offset: int = 0,
        haystack: bytes | None = None,
    ) -> None:
        """在 ``span`` 范围内执行规则正则并做全部校验。

        ``haystack`` 为 ``None`` 时在原始数据块上匹配；结构化路径会传入解出来的
        JSON 值（此时 ``span`` 指该值内部的范围，``value_offset`` 用于定位所在行）。
        """
        rule = entry.compiled.rule
        options = self.options
        counters = self.counters
        target = data if haystack is None else haystack
        start, end = span
        found = 0

        for match in entry.compiled.regex.finditer(target, start, end):
            if found >= options.max_matches_per_rule:
                break
            secret_bytes, offset = entry.compiled.extract(match)
            if not secret_bytes:
                continue
            counters.regex_candidates += 1

            if entry.compiled.exclude is not None and entry.compiled.exclude.search(secret_bytes):
                counters.suppressed_by_entropy[rule.id] += 1
                counters.suppressed_reasons["exclude-pattern"] += 1
                continue

            keyword_hit = False
            if entry.keywords:
                # 关键词始终在「原始行」范围内查找，这样结构化命中也能借到行上下文。
                line_start, line_end = (
                    (start, end) if haystack is None else self._line_span(lowered, value_offset)
                )
                center = offset if haystack is None else -1
                keyword_hit = _keyword_nearby(
                    lowered,
                    line_start,
                    line_end,
                    center=center,
                    window=rule.keyword_window,
                    keywords=entry.keywords,
                )
                if rule.require_keyword and not keyword_hit:
                    counters.suppressed_by_keyword[rule.id] += 1
                    counters.suppressed_reasons["missing-required-keyword"] += 1
                    continue

            secret = _decode(secret_bytes)
            verdict = entropy.evaluate(secret, rule.entropy)
            if not verdict.accepted:
                counters.suppressed_by_entropy[rule.id] += 1
                for reason in verdict.reasons:
                    counters.suppressed_reasons[reason.split("(")[0]] += 1
                continue

            score = rule.confidence.base_score + verdict.confidence_delta
            if keyword_hit:
                score += options.keyword_bonus
            if structured_hit:
                score += options.structured_bonus
            score = round(min(max(score, 0.0), 1.0), 4)
            if score < options.min_confidence:
                counters.suppressed_by_confidence[rule.id] += 1
                counters.suppressed_reasons["below-min-confidence"] += 1
                continue

            evidence = list(verdict.reasons)
            if keyword_hit:
                evidence.append("keyword-nearby")
            if structured_hit:
                evidence.append("sensitive-json-key")

            if haystack is None:
                line_start, line_end = start, end
                absolute = base_offset + line_start
                column = offset - line_start + 1
            else:
                line_start, line_end = self._line_span(data, value_offset)
                absolute = base_offset + line_start
                column = offset + 1

            hits.append(
                _Hit(
                    finding=Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        secret=secret,
                        source=source,
                        line=0,
                        byte_offset=absolute,
                        column=column,
                        json_path=json_path,
                        matched_context=self._snippet(target, offset, len(secret_bytes)),
                        entropy=verdict.entropy,
                        normalized_entropy=verdict.normalized,
                        charset=verdict.charset,
                        evidence=tuple(evidence),
                        confidence=Confidence.from_score(score),
                        confidence_score=score,
                        tags=rule.tags,
                        chunk_index=chunk_index,
                    ),
                    line_start=line_start,
                    line_end=line_end,
                )
            )
            found += 1

    # ------------------------------------------------------------------ 结构化规则

    def _scan_structured(
        self,
        data: bytes,
        lowered: bytes,
        hits: list[_Hit],
        source: str,
        base_offset: int,
        chunk_index: int,
    ) -> None:
        """由敏感键字面量的出现位置驱动 JSON 解析，避免逐行解析整块。"""
        assert self._key_regex is not None
        total = len(data)
        position = 0
        while position < total:
            match = self._key_regex.search(lowered, position)
            if match is None:
                return
            index = match.start()
            line_start, line_end = _line_bounds(lowered, index, total, self.options.max_line_bytes)
            position = line_end + 1
            if line_start >= line_end:
                continue

            # 先看首字节，避免为非 JSON 行付出切片 + 解析器调用的成本。
            if data[line_start] not in (0x7B, 0x5B):  # '{' '['
                continue
            record = structured.try_parse(data[line_start:line_end])
            if record is None:
                continue
            self.counters.json_records += 1

            for leaf in structured.iter_string_leaves(
                record,
                max_nodes=self.options.max_json_nodes,
                max_depth=self.options.max_json_depth,
                nested_json=self.options.nested_json,
            ):
                value = leaf.value.encode("utf-8", "surrogatepass")
                for entry in self._json_entries:
                    if not _key_matches(leaf.key, leaf.path, entry.json_keys):
                        continue
                    lowered_value = value.lower()
                    if not entry.prefilter.present(lowered_value):
                        continue
                    self._apply_rule(
                        entry,
                        data=data,
                        lowered=lowered,
                        span=(0, len(value)),
                        hits=hits,
                        source=source,
                        base_offset=base_offset,
                        chunk_index=chunk_index,
                        json_path=leaf.path,
                        structured_hit=True,
                        value_offset=line_start,
                        haystack=value,
                    )

    # ------------------------------------------------------------------ 收尾

    def _finalize(self, data: bytes, hits: list[_Hit]) -> list[Finding]:
        """解析行号、补全云上下文与 JSON 路径、折叠重叠命中。"""
        hits.sort(key=lambda h: (h.line_start, h.finding.byte_offset))

        # 行号：按偏移递增增量统计换行符，整块只扫一遍。
        cursor = 0
        line_number = 0
        for hit in hits:
            line_number += data.count(_NEWLINE, cursor, hit.line_start)
            cursor = hit.line_start
            hit.finding.line = line_number + 1
            hit.finding.local_line = line_number + 1

        findings: list[Finding] = []
        index = 0
        total = len(hits)
        while index < total:
            line_start = hits[index].line_start
            group_end = index
            while group_end < total and hits[group_end].line_start == line_start:
                group_end += 1
            group = hits[index:group_end]
            line_findings = [h.finding for h in group]

            if self.options.structured:
                payload = data[line_start : group[0].line_end]
                record = structured.try_parse(payload)
                if record is not None:
                    self._enrich(line_findings, record)

            if self.options.collapse_overlaps and len(line_findings) > 1:
                line_findings = _collapse_overlaps(line_findings)
            findings.extend(line_findings)
            index = group_end

        return findings

    def _enrich(self, findings: list[Finding], record: Any) -> None:
        context = cloud.extract_context(record)
        needs_path = any(f.json_path is None for f in findings)
        path_map: list[tuple[str, str]] = []
        if needs_path:
            path_map = [
                (leaf.value, leaf.path)
                for leaf in structured.iter_string_leaves(
                    record,
                    max_nodes=self.options.max_json_nodes,
                    max_depth=self.options.max_json_depth,
                    nested_json=self.options.nested_json,
                )
            ]

        for finding in findings:
            if context:
                finding.cloud_context = dict(context)
            if finding.json_path is None:
                best: str | None = None
                for value, path in path_map:
                    if finding.secret in value and (best is None or len(path) > len(best)):
                        best = path
                if best:
                    finding.json_path = best

    # ------------------------------------------------------------------ 小工具

    def _line_span(self, data: bytes, offset: int) -> tuple[int, int]:
        return _line_bounds(data, offset, len(data), self.options.max_line_bytes)

    def _snippet(self, target: bytes, offset: int, length: int) -> str:
        pad = self.options.context_chars
        left = max(0, offset - pad)
        right = min(len(target), offset + length + pad)
        # 片段可能从多字节字符中间切开，用 replace 保证可显示。
        text = target[left:right].decode("utf-8", "replace").replace("\t", " ").strip()
        prefix = "…" if left > 0 else ""
        suffix = "…" if right < len(target) else ""
        return f"{prefix}{text}{suffix}"


# --------------------------------------------------------------------------------------
# 模块级辅助
# --------------------------------------------------------------------------------------


def _line_bounds(hay: bytes, index: int, total: int, max_bytes: int) -> tuple[int, int]:
    """返回包含 ``index`` 的那一行的 ``[start, end)``（不含换行符与行尾 ``\\r``）。

    行长超过 ``max_bytes`` 时截断 —— 生产日志里偶尔会出现被塞进单行的巨型 payload，
    不设上限会让单行的正则回溯拖垮整个块。
    """
    start = hay.rfind(_NEWLINE, 0, index) + 1
    newline = hay.find(_NEWLINE, index)
    end = total if newline < 0 else newline
    if end > start and hay[end - 1 : end] == b"\r":
        end -= 1
    if end - start > max_bytes:
        end = start + max_bytes
    return start, end


def _decode(raw: bytes) -> str:
    """把捕获到的字节解成字符串：优先 UTF-8，失败退化 latin-1 以保证无损往返。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _collapse_overlaps(findings: list[Finding]) -> list[Finding]:
    """折叠同一位置上互相包含的命中。

    一个 ``Authorization: Bearer sk-proj-xxx`` 会同时命中 ``openai-api-key``、
    ``authorization-header-bearer`` 与 ``sensitive-json-key-value``。三条都报出来
    只会让报告变噪，因此保留最精确的一条（等级更高 → 置信度更高 → 捕获更短），
    其余以 ``also-matched:<rule_id>`` 并入证据链，信息不丢失。
    """
    ordered = sorted(
        findings,
        key=lambda f: (f.severity.rank, -f.confidence_score, len(f.secret)),
    )
    kept: list[Finding] = []
    for finding in ordered:
        absorbed_by: Finding | None = None
        for candidate in kept:
            if candidate.json_path != finding.json_path:
                continue
            if finding.secret in candidate.secret or candidate.secret in finding.secret:
                absorbed_by = candidate
                break
        if absorbed_by is None:
            kept.append(finding)
        else:
            absorbed_by.evidence = (*absorbed_by.evidence, f"also-matched:{finding.rule_id}")
    return kept


def _key_matches(key: str, path: str, json_keys: Iterable[str]) -> bool:
    """规则的 ``json_keys`` 是否命中当前叶子。

    先按末段键名精确/子串匹配，再退化为整条路径的子串匹配，
    这样 ``headers.Authorization`` 与 ``x-api-key`` 都能覆盖。
    """
    path_lower = path.lower()
    # 热路径：显式循环比 any(生成器) 少一层生成器帧开销。
    for needle in json_keys:  # noqa: SIM110
        if needle == key or needle in key or needle in path_lower:
            return True
    return False


def _keyword_nearby(
    lowered: bytes,
    line_start: int,
    line_end: int,
    *,
    center: int,
    window: int,
    keywords: Iterable[bytes],
) -> bool:
    """匹配位置附近是否出现关键词；``center < 0`` 表示在整行范围内查找。"""
    if center < 0:
        start, stop = line_start, line_end
    else:
        start = max(line_start, center - window)
        stop = min(line_end, center + window)
    return any(lowered.find(keyword, start, stop) >= 0 for keyword in keywords)
