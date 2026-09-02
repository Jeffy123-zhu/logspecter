r"""必现字面量提取、trie 合并与块级层次剪枝。

真实日志里 99.9% 的行不含任何密钥。如果逐行把 60+ 条正则跑一遍，吞吐会被 regex
引擎吃光（实测 3 MiB/s）。本模块提供三件基础设施：

1. :func:`extract_literal_groups` —— 静态分析正则 AST，提取「匹配成功时必然出现」
   的字面量。例如 ``\b((?:AKIA|ASIA|AROA)[A-Z0-9]{16})\b`` → ``("AKIA","ASIA","AROA")``。
   只在**能证明必现**时才产出，证明不了就返回空（退化为全量扫描），因此不引入漏报。

2. :func:`trie_pattern` —— 把候选字面量合并成前缀树形正则
   （``key|keystore|kms`` → ``k(?:ey(?:store)?|ms)``）。这一步至关重要：CPython 的
   ``re`` 会为整个模式计算 ``INFO`` 首字符集合并用紧凑 C 循环跳过不可能的位置，
   实测「8MB 全部未命中」只要 **2.5 ms（约 3.1 GiB/s）**，与单次 ``bytes.find`` 同量级，
   而扁平 ``a|b|c|...`` 形式要慢一个数量级。

3. :class:`ScreenTree` —— 把所有规则组织成二叉树，每个节点持有其子树全部字面量的
   trie 正则。扫描一个数据块时自顶向下剪枝：节点未命中即可一次性排除整棵子树。
   干净的数据块只需一次 2.5 ms 的搜索就能排除全部规则；只有真正出现可疑字面量的
   块才会继续下探。

三个必须处理的 CPython 细节：

* ``re._parser`` 会把分支公共前缀提出去（``storedKey|serverKey`` → ``s`` +
  ``toredKey|erverKey``），分析分支时要把待定字面量段拼回每个分支。
* 小字符集 ``[pousr]`` 等价于单字符分支，可以展开（``gh[pousr]_`` → ``ghp_`` …）。
* 找不到 3 字符以上字面量时降级到 2 字符再试一次。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

try:  # Python 3.11+
    from re import _parser as _regex_parser  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python 3.10
    import sre_parse as _regex_parser  # type: ignore[no-redef]

__all__ = [
    "LiteralGroup",
    "LiteralPrefilter",
    "ScreenTree",
    "check_soundness",
    "extract_literal_groups",
    "trie_pattern",
]

#: 首选字面量长度门限。短于该长度的字面量选择性差。
MIN_LITERAL_LEN = 3
#: 首选门限下颗粒无收时的降级门限。
FALLBACK_LITERAL_LEN = 2
#: 每条规则最多保留几组预筛条件（组间 AND，越多越精准但检查成本略增）。
MAX_GROUPS = 2
#: 单组内候选过多说明分支太散，选择性差，放弃该组。
MAX_ALTERNATIVES = 24
#: 可展开为分支的字符集最大规模。
MAX_CHARCLASS_EXPANSION = 8
#: 候选数不超过该值时用 ``bytes.find`` 逐个查找，超过则合并为 trie 正则。
FIND_ALTERNATIVE_LIMIT = 4

_REPEAT_OPS = frozenset({"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"})


# --------------------------------------------------------------------------------------
# 正则 AST 分析
# --------------------------------------------------------------------------------------


#: 被视为「无界」的重复上限阈值。
_UNBOUNDED = 4096
#: 前缀宽度跨度超过该值就不值得用锚定匹配（尝试位置过多）。
MAX_ANCHOR_SPAN = 48


@dataclass(slots=True, frozen=True)
class LiteralGroup:
    """一组「至少命中其一」的必现字面量，附带它在匹配中的位置信息。

    ``min_prefix`` / ``max_prefix`` 是字面量之前、仍属于同一次匹配的字节数范围。
    例如 ``\\b((?:sk|rk)_live_...)`` 中 ``_live_`` 的前缀宽度恒为 2。有了这个范围，
    扫描时就能把「在整行里 search」换成「在 1~几个确定位置上锚定 match」，
    这是热路径上最大的一笔优化（实测单块从 1.2s 降到 0.2s 量级）。

    ``max_prefix is None`` 表示前缀宽度无界（模式里有不定长重复），此时只能退回
    整行 ``search``。
    """

    alternatives: tuple[str, ...]
    min_prefix: int = 0
    max_prefix: int | None = 0

    @property
    def anchorable(self) -> bool:
        """能否用锚定匹配（前缀宽度有界且跨度可接受）。"""
        return (
            self.max_prefix is not None and (self.max_prefix - self.min_prefix) <= MAX_ANCHOR_SPAN
        )

    @property
    def score(self) -> float:
        return _score(self.alternatives)


def _score(group: Sequence[str]) -> float:
    """组的选择性评分：最短候选越长、候选数越少越好。"""
    if not group:
        return 0.0
    return min(len(g) for g in group) / (len(group) ** 0.5)


def _add(width: int | None, delta: int | None) -> int | None:
    """宽度相加，``None`` 表示无界。"""
    if width is None or delta is None:
        return None
    return width + delta


def _shift(groups: list[LiteralGroup], min_off: int, max_off: int | None) -> list[LiteralGroup]:
    """把子模式内的前缀宽度平移到父序列坐标系。"""
    if not groups:
        return groups
    return [
        LiteralGroup(
            alternatives=g.alternatives,
            min_prefix=g.min_prefix + min_off,
            max_prefix=_add(g.max_prefix, max_off),
        )
        for g in groups
    ]


def _op_name(op) -> str:
    return getattr(op, "name", str(op))


def _charclass_literals(items) -> list[str] | None:
    """把 ``[abc]`` 这类纯字面量小字符集展开为候选列表；不适用时返回 ``None``。"""
    if not items:
        return None
    chars: list[str] = []
    for op, arg in items:
        if _op_name(op) != "LITERAL":
            return None  # NEGATE / RANGE / CATEGORY 一律放弃
        try:
            chars.append(chr(arg))
        except (TypeError, ValueError):  # pragma: no cover
            return None
        if len(chars) > MAX_CHARCLASS_EXPANSION:
            return None
    return chars


def _leading_literals(seq) -> str:
    """返回子模式最靠前的连续字面量段（可能为空串）。"""
    out: list[str] = []
    for op, arg in seq:
        name = _op_name(op)
        if name == "LITERAL":
            try:
                out.append(chr(arg))
                continue
            except (TypeError, ValueError):  # pragma: no cover
                break
        if name == "SUBPATTERN":
            out.append(_leading_literals(arg[3]))
            break
        if name in _REPEAT_OPS and arg[0] >= 1:
            out.append(_leading_literals(arg[2]))
            break
        break
    return "".join(out)


def _analyze(seq, min_len: int) -> tuple[list[LiteralGroup], int, int | None]:
    """递归分析正则 AST。

    Returns:
        ``(候选组, 该序列的最小宽度, 该序列的最大宽度)``。最大宽度为 ``None``
        表示无界。候选组中的前缀宽度以本序列起点为原点。
    """
    groups: list[LiteralGroup] = []
    run: list[str] = []
    run_min = 0
    run_max: int | None = 0
    cur_min = 0
    cur_max: int | None = 0

    def flush() -> None:
        nonlocal run
        if len(run) >= min_len:
            groups.append(LiteralGroup(("".join(run),), run_min, run_max))
        run = []

    def handle_alternatives(branches, start_min: int, start_max: int | None) -> bool:
        """处理分支/小字符集，把待定前缀拼进每个候选。返回是否成功。"""
        prefix = "".join(run)
        base_min = run_min if prefix else start_min
        base_max = run_max if prefix else start_max
        alternatives: list[str] = []
        for branch in branches:
            lead = branch if isinstance(branch, str) else _leading_literals(branch)
            candidate = prefix + lead
            if len(candidate) >= min_len:
                alternatives.append(candidate)
                continue
            if isinstance(branch, str):
                return False
            sub_groups, _smin, _smax = _analyze(branch, min_len)
            if not sub_groups:
                return False
            alternatives.extend(max(sub_groups, key=lambda g: g.score).alternatives)
        if not alternatives or len(alternatives) > MAX_ALTERNATIVES:
            return False
        groups.append(LiteralGroup(tuple(sorted(set(alternatives))), base_min, base_max))
        return True

    def widths(branches) -> tuple[int, int | None]:
        """分支集合的最小/最大宽度。"""
        mins: list[int] = []
        maxs: list[int | None] = []
        for branch in branches:
            _g, bmin, bmax = _analyze(branch, min_len)
            mins.append(bmin)
            maxs.append(bmax)
        if not mins:
            return 0, 0
        return min(mins), (None if any(m is None for m in maxs) else max(m for m in maxs))  # type: ignore[type-var]

    for op, arg in seq:
        name = _op_name(op)
        element_min, element_max = cur_min, cur_max

        if name == "LITERAL":
            try:
                char = chr(arg)
            except (TypeError, ValueError):  # pragma: no cover
                flush()
                cur_min += 1
                cur_max = _add(cur_max, 1)
                continue
            if not run:
                run_min, run_max = element_min, element_max
            run.append(char)
            cur_min += 1
            cur_max = _add(cur_max, 1)
            continue

        if name == "BRANCH":
            handled = handle_alternatives(arg[1], element_min, element_max)
            if handled:
                run = []
            else:
                flush()
            bmin, bmax = widths(arg[1])
            cur_min += bmin
            cur_max = _add(cur_max, bmax)
            continue

        if name == "IN":
            expanded = _charclass_literals(arg)
            if expanded is not None and handle_alternatives(expanded, element_min, element_max):
                run = []
            else:
                flush()
            cur_min += 1
            cur_max = _add(cur_max, 1)
            continue

        flush()

        if name == "SUBPATTERN":
            sub_groups, smin, smax = _analyze(arg[3], min_len)
            groups.extend(_shift(sub_groups, element_min, element_max))
            cur_min += smin
            cur_max = _add(cur_max, smax)
        elif name in _REPEAT_OPS:
            minimum, maximum, sub = arg
            sub_groups, smin, smax = _analyze(sub, min_len)
            if minimum >= 1:
                groups.extend(_shift(sub_groups, element_min, element_max))
            cur_min += smin * minimum
            if maximum is None or maximum >= _UNBOUNDED or smax is None:
                cur_max = None
            else:
                cur_max = _add(cur_max, smax * maximum)
        elif name == "ATOMIC_GROUP":
            sub_groups, smin, smax = _analyze(arg, min_len)
            groups.extend(_shift(sub_groups, element_min, element_max))
            cur_min += smin
            cur_max = _add(cur_max, smax)
        elif name in ("ANY", "NOT_LITERAL"):
            cur_min += 1
            cur_max = _add(cur_max, 1)
        elif name in ("AT", "ASSERT", "ASSERT_NOT"):
            pass  # 零宽断言不占宽度，也无法证明必现
        else:
            # GROUPREF / 未知操作：宽度不可知，保守标记为无界
            cur_max = None

    flush()
    return groups, cur_min, cur_max


def extract_literal_groups(
    pattern: str,
    *,
    ignore_case: bool = False,
    max_groups: int = MAX_GROUPS,
) -> tuple[LiteralGroup, ...]:
    """提取用于预筛的字面量候选组，按选择性从高到低排序。

    Returns:
        :class:`LiteralGroup` 元组。空元组表示无法预筛，必须全量执行正则。
    """
    try:
        parsed = _regex_parser.parse(pattern, 0)
    except Exception:
        return ()

    groups, _min_width, _max_width = _analyze(parsed, MIN_LITERAL_LEN)
    if not groups:
        groups, _min_width, _max_width = _analyze(parsed, FALLBACK_LITERAL_LEN)
    if not groups:
        return ()

    groups.sort(key=lambda g: g.score, reverse=True)
    chosen = groups[:max_groups]
    if ignore_case or "(?i" in pattern:
        chosen = [
            LiteralGroup(
                tuple(sorted({a.lower() for a in g.alternatives})), g.min_prefix, g.max_prefix
            )
            for g in chosen
        ]
    return tuple(g for g in chosen if g.alternatives)


# --------------------------------------------------------------------------------------
# trie 合并
# --------------------------------------------------------------------------------------


def trie_pattern(words: Iterable[str]) -> str:
    r"""把字面量集合合并为前缀树形正则源串。

    >>> trie_pattern(["key", "keystore", "kms"])
    'k(?:ey(?:store)?|ms)'

    这种形式让 ``re`` 能算出有效的 ``INFO`` 首字符集合，从而以接近 memchr 的速度
    跳过不可能匹配的位置 —— 扁平的 ``a|b|c`` 形式做不到这一点。
    """
    unique = sorted({w for w in words if w})
    if not unique:
        raise ValueError("trie_pattern 需要至少一个非空字面量")

    root: dict[str, dict] = {}
    for word in unique:
        node = root
        for char in word:
            node = node.setdefault(char, {})
        node[""] = {}  # 终止标记

    def emit(node: dict[str, dict]) -> str:
        keys = [k for k in sorted(node) if k != ""]
        if not keys:
            return ""
        parts = [re.escape(char) + emit(node[char]) for char in keys]
        if len(parts) == 1:
            body = parts[0]
            return f"(?:{body})?" if "" in node else body
        body = "(?:" + "|".join(parts) + ")"
        return f"{body}?" if "" in node else body

    return emit(root)


def _compile_trie(words: Sequence[str]) -> re.Pattern[bytes]:
    return re.compile(trie_pattern(words).encode("utf-8"))


# --------------------------------------------------------------------------------------
# 单条规则的预筛器
# --------------------------------------------------------------------------------------


class TriggerCursor:
    """驱动组候选的出现位置游标（单调推进）。

    为什么需要它：如果每轮都对每个候选执行一次 ``hay.find(literal, position)``，
    那么**不存在**的候选每轮都会把剩余数据全扫一遍。一条规则若有 3 个候选、其中
    2 个不存在，而第 3 个在每行都出现，代价就是「行数 × 2 × 整块扫描」——
    实测把单块耗时从 30 ms 炸到 32 秒。

    这里为每个候选缓存「下一处出现位置」：一旦某候选返回 ``-1`` 就永久淘汰，
    其余候选只在游标越过它时才重新查找。于是每个候选在整块上的总扫描量是 O(块大小)。
    """

    __slots__ = ("_hay", "_literals", "_positions", "_regex")

    def __init__(
        self,
        hay: bytes,
        literals: tuple[bytes, ...],
        regex: re.Pattern[bytes] | None,
    ) -> None:
        self._hay = hay
        self._regex = regex
        self._literals = literals if regex is None else ()
        self._positions = [hay.find(lit) for lit in self._literals]

    def next_from(self, position: int) -> int:
        """返回 ``position`` 及其之后最早的出现位置；没有则返回 ``-1``。"""
        if self._regex is not None:
            match = self._regex.search(self._hay, position)
            return match.start() if match is not None else -1
        best = -1
        positions = self._positions
        for index, literal in enumerate(self._literals):
            found = positions[index]
            if found < 0:
                continue  # 该候选在整块中已不再出现
            if found < position:
                found = self._hay.find(literal, position)
                positions[index] = found
                if found < 0:
                    continue
            if best < 0 or found < best:
                best = found
        return best


@dataclass(slots=True)
class LiteralPrefilter:
    """单条规则的字面量预筛器（字节级）。

    ``groups`` 里组间是 AND 关系、组内是 OR 关系。第一组选择性最高，扫描时用它做
    「出现位置枚举」的驱动源，其余组只作存在性校验。
    """

    groups: tuple[LiteralGroup, ...] = ()
    ignore_case: bool = False
    #: 字节化的候选，与 ``groups`` 一一对应。
    byte_groups: tuple[tuple[bytes, ...], ...] = ()
    #: 候选较多的组对应 trie 正则；候选少的组为 ``None``（用 ``bytes.find`` 更快）。
    group_regexes: tuple[re.Pattern[bytes] | None, ...] = ()
    #: 用于枚举出现位置的组下标。
    driver_index: int = 0

    @classmethod
    def build(
        cls,
        pattern: str,
        *,
        ignore_case: bool = False,
        extra_group: Sequence[str] = (),
    ) -> LiteralPrefilter:
        """构造预筛器。

        Args:
            pattern: 规则正则源串。
            ignore_case: 规则是否大小写不敏感。
            extra_group: 额外的必现候选组。用于 ``require_keyword`` 规则 ——
                关键词必然出现在同一行，因此可以当作合法的预筛条件。这类关键词
                与匹配位置没有固定距离，故前缀宽度标记为无界。
        """
        insensitive = ignore_case or "(?i" in pattern
        groups = list(extract_literal_groups(pattern, ignore_case=insensitive))
        if extra_group:
            normalized = tuple(sorted({k.lower() if insensitive else k for k in extra_group}))
            if normalized:
                groups.append(LiteralGroup(normalized, 0, None))
        groups.sort(key=lambda g: g.score, reverse=True)
        return cls._from_groups(tuple(groups), insensitive)

    @classmethod
    def _from_groups(cls, groups: tuple[LiteralGroup, ...], ignore_case: bool) -> LiteralPrefilter:
        byte_groups = tuple(tuple(a.encode("utf-8") for a in g.alternatives) for g in groups)
        # 候选很少时 ``bytes.find`` 明显快于 trie 正则：CPython 的 find 用带 Bloom
        # 跳跃的双向算法（约 3.7 GiB/s），而 trie 正则要走 SRE 的首字符集循环，
        # 首字符集含常见字母时（如 a/p/x）一次 8 MiB 未命中要 40 ms 以上。
        regexes: list[re.Pattern[bytes] | None] = []
        for group in groups:
            if len(group.alternatives) > FIND_ALTERNATIVE_LIMIT:
                regexes.append(_compile_trie(group.alternatives))
            else:
                regexes.append(None)

        # 选出「出现位置驱动组」：优先挑前缀宽度有界（可锚定匹配）的组，其中再优先
        # 取跨度小的（锚定尝试次数少），最后才比选择性。选择性最高的那一组仍会作为
        # AND 条件被校验，因此这个取舍不损失过滤能力，只是把昂贵的整行 search
        # 换成一两次锚定 match。
        anchorable = [(i, g) for i, g in enumerate(groups) if g.anchorable]
        if anchorable:
            driver = min(
                anchorable,
                key=lambda item: (
                    (item[1].max_prefix or 0) - item[1].min_prefix,
                    -item[1].score,
                ),
            )[0]
        else:
            driver = 0
        return cls(
            groups=groups,
            ignore_case=ignore_case,
            byte_groups=byte_groups,
            group_regexes=tuple(regexes),
            driver_index=driver,
        )

    @property
    def active(self) -> bool:
        return bool(self.groups)

    @property
    def screen_group(self) -> LiteralGroup | None:
        """选择性最高的一组，供块级筛选树使用。"""
        return self.groups[0] if self.groups else None

    @property
    def trigger(self) -> tuple[bytes, ...]:
        """驱动出现位置枚举的候选组。"""
        return self.byte_groups[self.driver_index] if self.byte_groups else ()

    @property
    def trigger_regex(self) -> re.Pattern[bytes] | None:
        return self.group_regexes[self.driver_index] if self.group_regexes else None

    @property
    def trigger_group(self) -> LiteralGroup | None:
        return self.groups[self.driver_index] if self.groups else None

    @property
    def anchor_span(self) -> tuple[int, int] | None:
        """触发字面量之前可能存在的匹配前缀宽度范围。

        返回 ``(min_prefix, max_prefix)``；``None`` 表示宽度无界，扫描时只能退回
        整行 ``search``。
        """
        group = self.trigger_group
        if group is None or not group.anchorable:
            return None
        assert group.max_prefix is not None
        return group.min_prefix, group.max_prefix

    def _group_present(self, index: int, hay: bytes, start: int, stop: int) -> bool:
        regex = self.group_regexes[index]
        if regex is not None:
            return regex.search(hay, start, stop) is not None
        # 热路径：显式循环比 any(生成器) 少一层生成器帧开销。
        for literal in self.byte_groups[index]:  # noqa: SIM110
            if hay.find(literal, start, stop) >= 0:
                return True
        return False

    def present(self, hay: bytes, start: int = 0, end: int | None = None) -> bool:
        """``hay[start:end]`` 内是否满足全部预筛条件（不满足则规则可跳过）。"""
        if not self.byte_groups:
            return True
        stop = len(hay) if end is None else end
        return all(
            self._group_present(index, hay, start, stop) for index in range(len(self.byte_groups))
        )

    def present_except_driver(self, hay: bytes, start: int = 0, end: int | None = None) -> bool:
        """校验除驱动组之外的其余组（驱动组已由出现位置枚举保证命中）。"""
        if len(self.byte_groups) <= 1:
            return True
        stop = len(hay) if end is None else end
        driver = self.driver_index
        for index in range(len(self.byte_groups)):
            if index == driver:
                continue
            if not self._group_present(index, hay, start, stop):
                return False
        return True

    def trigger_cursor(self, hay: bytes) -> TriggerCursor:
        """为驱动组创建一个出现位置游标。"""
        return TriggerCursor(hay, self.trigger, self.trigger_regex)

    def describe(self) -> str:
        if not self.groups:
            return "<full-scan>"
        parts = []
        for index, group in enumerate(self.groups):
            text = "|".join(group.alternatives)
            if index == self.driver_index:
                span = self.anchor_span
                text += f" [driver @{span[0]}..{span[1]}]" if span else " [driver @search]"
            parts.append(text)
        return " AND ".join(parts)


# --------------------------------------------------------------------------------------
# 块级层次剪枝
# --------------------------------------------------------------------------------------


#: 筛选树叶子最多容纳多少条规则。
#:
#: 这是一个纯粹的成本权衡：节点搜索一次未命中的 8 MiB 数据块约 2.5~5 ms，而每条被
#: 剪掉的规则可省下一次约 2.4 ms 的全块字面量扫描。因此叶子太小（1~2 条规则）时
#: 剪枝收益还不够抵消节点自身开销；实测取 6 左右最稳。
DEFAULT_LEAF_SIZE = 6


def _screen_literals(prefilter: LiteralPrefilter) -> tuple[str, ...]:
    """筛选树使用的字面量：取选择性最高的一组，统一小写。"""
    group = prefilter.screen_group
    if group is None:  # pragma: no cover - 调用方已过滤
        return ()
    return tuple(sorted({a.lower() for a in group.alternatives}))


@dataclass(slots=True)
class _Node:
    rules: tuple[int, ...]
    #: 单字面量节点用 ``bytes.find``（比正则更快）；多字面量节点用 trie 正则。
    literal: bytes | None = None
    regex: re.Pattern[bytes] | None = None
    left: _Node | None = None
    right: _Node | None = None

    def present(self, hay: bytes) -> bool:
        if self.literal is not None:
            return hay.find(self.literal) >= 0
        assert self.regex is not None
        return self.regex.search(hay) is not None


@dataclass(slots=True)
class ScreenTree:
    """规则的层次化字面量筛选树。

    每个节点持有其子树内全部规则「第一候选组」字面量的 trie 正则。扫描数据块时
    自顶向下：节点未命中 → 整棵子树的规则全部排除。因此一个干净的数据块只需一次
    根节点搜索（约 2.5 ms / 8 MiB）就能排除所有带预筛条件的规则。

    筛选统一在**小写化**的数据上进行。对大小写敏感的规则而言这是一个「超集」条件
    （真实命中必然蕴含小写命中），因此剪枝不会引入漏报。

    ``always`` 列出无法预筛的规则下标，它们在任何情况下都必须参与扫描。
    """

    root: _Node | None = None
    always: tuple[int, ...] = ()
    #: 参与筛选树的规则总数，仅用于诊断。
    screened: int = 0
    #: 树中节点总数，仅用于诊断。
    nodes: int = 0

    @classmethod
    def build(
        cls, prefilters: Sequence[LiteralPrefilter], leaf_size: int = DEFAULT_LEAF_SIZE
    ) -> ScreenTree:
        indexed = [(i, pf) for i, pf in enumerate(prefilters) if pf.active]
        always = tuple(i for i, pf in enumerate(prefilters) if not pf.active)
        if not indexed:
            return cls(root=None, always=always, screened=0, nodes=0)

        # 按首字母排序，让同一子树内的字面量共享前缀，trie 更紧凑、首字符集更小。
        indexed.sort(key=lambda item: _screen_literals(item[1])[0])
        counter = [0]
        root = cls._build_node(indexed, max(1, leaf_size), counter)
        return cls(root=root, always=always, screened=len(indexed), nodes=counter[0])

    @staticmethod
    def _build_node(
        items: Sequence[tuple[int, LiteralPrefilter]], leaf_size: int, counter: list[int]
    ) -> _Node:
        counter[0] += 1
        literals = sorted({lit for _, pf in items for lit in _screen_literals(pf)})
        rules = tuple(index for index, _ in items)
        if len(literals) == 1:
            node = _Node(rules=rules, literal=literals[0].encode("utf-8"))
        else:
            node = _Node(rules=rules, regex=_compile_trie(literals))
        if len(items) > leaf_size:
            middle = len(items) // 2
            node.left = ScreenTree._build_node(items[:middle], leaf_size, counter)
            node.right = ScreenTree._build_node(items[middle:], leaf_size, counter)
        return node

    def select(self, hay: bytes) -> list[int]:
        """返回在 ``hay`` 中「有可能命中」的规则下标（含无法预筛的规则）。

        Args:
            hay: **已小写化**的数据块。
        """
        active = list(self.always)
        if self.root is not None:
            self._descend(self.root, hay, active)
        active.sort()
        return active

    @staticmethod
    def _descend(node: _Node, hay: bytes, out: list[int]) -> None:
        if not node.present(hay):
            return
        if node.left is None:
            out.extend(node.rules)
            return
        ScreenTree._descend(node.left, hay, out)
        ScreenTree._descend(node.right, hay, out)  # type: ignore[arg-type]


def check_soundness(
    pattern: str, samples: Sequence[str], *, ignore_case: bool = False
) -> list[str]:
    """校验预筛不会误杀真正能匹配的样本，返回被错误拒绝的样本列表。"""
    prefilter = LiteralPrefilter.build(pattern, ignore_case=ignore_case)
    regex = re.compile(pattern, re.IGNORECASE if prefilter.ignore_case else 0)
    broken: list[str] = []
    for sample in samples:
        if regex.search(sample) is None:
            continue
        data = sample.encode("utf-8")
        hay = data.lower() if prefilter.ignore_case else data
        if not prefilter.present(hay):
            broken.append(sample)
    return broken
