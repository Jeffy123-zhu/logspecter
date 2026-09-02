"""规则库：YAML 定义 + 加载 + 校验 + 编译。

设计要点：

* ``Rule`` 是**纯数据、可 pickle** 的规则规格（不含已编译正则），因此可以直接
  作为 multiprocessing 的初始化参数下发；``CompiledRule`` 在每个 worker 进程内
  编译一次并常驻，避免逐块重复编译。
* 每条规则自带熵值门限（``entropy:``）。结构性强的规则（``AKIA`` 前缀、
  ``BEGIN RSA PRIVATE KEY``）用 ``entropy.enabled: false`` 跳过熵校验；
  通用规则（``password=xxx``）则依赖熵值 + 关键词邻近双重把关。
* ``json_keys`` 让规则只在特定 JSON 键上生效，这是结构感知层降噪的关键钩子。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from logspecter.entropy import EntropyGate
from logspecter.findings import Confidence, Severity

__all__ = [
    "BUILTIN_RULES_DIR",
    "CompiledRule",
    "Rule",
    "RuleSet",
    "RuleSyntaxError",
    "load_ruleset",
]

BUILTIN_RULES_DIR = Path(__file__).parent / "rules"

_SCHEMA_VERSION = 1
_RULE_ID_RE = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")

_ALLOWED_RULE_KEYS = {
    "id",
    "name",
    "description",
    "severity",
    "confidence",
    "pattern",
    "capture",
    "ignore_case",
    "multiline",
    "exclude_pattern",
    "keywords",
    "keyword_window",
    "require_keyword",
    "json_keys",
    "entropy",
    "tags",
    "enabled",
    "references",
}


class RuleSyntaxError(ValueError):
    """YAML 规则文件不合法。错误信息里始终带上文件名与规则 id。"""


def _gate_to_dict(gate: EntropyGate) -> dict[str, Any]:
    """把 :class:`EntropyGate` 转为可 JSON/pickle 的普通映射。"""
    out: dict[str, Any] = {}
    for name in EntropyGate.__dataclass_fields__:
        value = getattr(gate, name)
        out[name] = sorted(value) if isinstance(value, frozenset) else value
    return out


@dataclass(slots=True, frozen=True)
class Rule:
    """一条检测规则的规格。"""

    id: str
    name: str
    pattern: str
    severity: Severity = Severity.HIGH
    confidence: Confidence = Confidence.MEDIUM
    #: 密钥本体所在的捕获组：整数下标或命名组；0 表示整个匹配。
    capture: int | str = 0
    description: str = ""
    ignore_case: bool = False
    multiline: bool = False
    #: 命中后若同时匹配该正则则丢弃，用于精细化排除已知误报形态。
    exclude_pattern: str | None = None
    #: 关键词邻近校验用的词表（不区分大小写）。
    keywords: tuple[str, ...] = ()
    #: 关键词搜索窗口（匹配位置左右各 N 个字符）。
    keyword_window: int = 96
    #: 为 True 时，窗口内必须出现 ``keywords`` 之一才算命中。
    require_keyword: bool = False
    #: 仅在这些 JSON 键路径片段上生效（不区分大小写的子串匹配）；空则不限制。
    json_keys: tuple[str, ...] = ()
    entropy: EntropyGate = field(default_factory=EntropyGate)
    tags: tuple[str, ...] = ()
    #: 默认是否启用。噪声较大的通用规则默认关闭，由 ``--aggressive`` 打开。
    enabled: bool = True
    references: tuple[str, ...] = ()
    #: 所属规则包（来源文件名），便于报告与 ``rules list`` 分组。
    pack: str = "custom"

    # -- 序列化：用于跨进程传递 ------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "pattern": self.pattern,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "capture": self.capture,
            "description": self.description,
            "ignore_case": self.ignore_case,
            "multiline": self.multiline,
            "exclude_pattern": self.exclude_pattern,
            "keywords": list(self.keywords),
            "keyword_window": self.keyword_window,
            "require_keyword": self.require_keyword,
            "json_keys": list(self.json_keys),
            "entropy": _gate_to_dict(self.entropy),
            "tags": list(self.tags),
            "enabled": self.enabled,
            "references": list(self.references),
            "pack": self.pack,
        }

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], *, pack: str = "custom", origin: str = "<memory>"
    ) -> Rule:
        unknown = set(data) - _ALLOWED_RULE_KEYS - {"pack"}
        if unknown:
            raise RuleSyntaxError(f"{origin}: 规则 {data.get('id')!r} 含未知字段 {sorted(unknown)}")

        for required in ("id", "name", "pattern"):
            if not data.get(required):
                raise RuleSyntaxError(f"{origin}: 规则缺少必填字段 {required!r} ({data!r})")

        rule_id = str(data["id"])
        if not _RULE_ID_RE.match(rule_id):
            raise RuleSyntaxError(
                f"{origin}: 规则 id {rule_id!r} 不合法，要求小写字母/数字，以 '-' 分隔"
            )

        pattern = str(data["pattern"])
        try:
            re.compile(pattern)
        except re.error as exc:
            raise RuleSyntaxError(f"{origin}: 规则 {rule_id!r} 的 pattern 无法编译: {exc}") from exc

        exclude = data.get("exclude_pattern")
        if exclude:
            try:
                re.compile(str(exclude))
            except re.error as exc:
                raise RuleSyntaxError(
                    f"{origin}: 规则 {rule_id!r} 的 exclude_pattern 无法编译: {exc}"
                ) from exc

        try:
            gate = EntropyGate.from_mapping(data.get("entropy"))
        except ValueError as exc:
            raise RuleSyntaxError(f"{origin}: 规则 {rule_id!r} 的 entropy 配置错误: {exc}") from exc

        capture = data.get("capture", 0)
        if isinstance(capture, bool) or not isinstance(capture, (int, str)):
            raise RuleSyntaxError(f"{origin}: 规则 {rule_id!r} 的 capture 必须是整数或组名")

        return cls(
            id=rule_id,
            name=str(data["name"]),
            pattern=pattern,
            severity=Severity.parse(data.get("severity", "high")),
            confidence=Confidence.parse(data.get("confidence", "medium")),
            capture=capture,
            description=str(data.get("description", "")).strip(),
            ignore_case=bool(data.get("ignore_case", False)),
            multiline=bool(data.get("multiline", False)),
            exclude_pattern=str(exclude) if exclude else None,
            keywords=tuple(str(k).lower() for k in data.get("keywords", ())),
            keyword_window=int(data.get("keyword_window", 96)),
            require_keyword=bool(data.get("require_keyword", False)),
            json_keys=tuple(str(k).lower() for k in data.get("json_keys", ())),
            entropy=gate,
            tags=tuple(str(t) for t in data.get("tags", ())),
            enabled=bool(data.get("enabled", True)),
            references=tuple(str(r) for r in data.get("references", ())),
            pack=str(data.get("pack", pack)),
        )


@dataclass(slots=True)
class CompiledRule:
    """规则 + 已编译的**字节**正则。仅在进程内构造，不参与 pickle。

    刻意用 ``bytes`` 模式而非 ``str``：

    * 日志原始数据本来就是字节，不解码就少一次全量拷贝（8 MiB 块能省下 2~3 ms）；
    * 匹配偏移天然等于文件字节偏移，无需字符↔字节换算；
    * 字节模式下 ``\\w`` ``\\b`` 恒为 ASCII 语义，跨语言日志里行为更可预测；
    * 脏数据（非法 UTF-8）不会引发解码开销或异常。
    """

    rule: Rule
    regex: re.Pattern[bytes]
    exclude: re.Pattern[bytes] | None

    @classmethod
    def build(cls, rule: Rule) -> CompiledRule:
        flags = 0
        if rule.ignore_case:
            flags |= re.IGNORECASE
        if rule.multiline:
            flags |= re.MULTILINE
        exclude = (
            re.compile(rule.exclude_pattern.encode("utf-8"), flags)
            if rule.exclude_pattern
            else None
        )
        return cls(
            rule=rule,
            regex=re.compile(rule.pattern.encode("utf-8"), flags),
            exclude=exclude,
        )

    def extract(self, match: re.Match[bytes]) -> tuple[bytes, int]:
        """返回 ``(密钥字节, 起始字节偏移)``。"""
        capture = self.rule.capture
        try:
            if isinstance(capture, int) and capture == 0:
                return match.group(0), match.start(0)
            value = match.group(capture)
            if value is None:
                return match.group(0), match.start(0)
            return value, match.start(capture)
        except (IndexError, re.error):  # pragma: no cover - 规则写错时兜底
            return match.group(0), match.start(0)


@dataclass(slots=True)
class RuleSet:
    """一组规则，附带来源信息。"""

    rules: tuple[Rule, ...] = ()
    origins: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    @property
    def packs(self) -> tuple[str, ...]:
        return tuple(sorted({r.pack for r in self.rules}))

    def enabled_rules(self) -> tuple[Rule, ...]:
        return tuple(r for r in self.rules if r.enabled)

    def compile(self) -> tuple[CompiledRule, ...]:
        return tuple(CompiledRule.build(r) for r in self.rules if r.enabled)

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [r.to_dict() for r in self.rules], "origins": list(self.origins)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleSet:
        return cls(
            rules=tuple(Rule.from_dict(d, pack=d.get("pack", "custom")) for d in data["rules"]),
            origins=tuple(data.get("origins", ())),
        )

    def select(
        self,
        *,
        include: Sequence[str] = (),
        exclude: Sequence[str] = (),
        enable: Sequence[str] = (),
        packs: Sequence[str] = (),
        tags: Sequence[str] = (),
        min_severity: Severity | None = None,
        enable_all: bool = False,
    ) -> RuleSet:
        """按 id / 包名 / 标签 / 等级筛选，返回新的 ``RuleSet``。

        ``include`` / ``exclude`` / ``enable`` 中的每一项都可以是规则 id、
        ``pack:<包名>``、``tag:<标签>``，或带 ``*`` 的通配符。
        """
        include_set = tuple(include)
        exclude_set = tuple(exclude)
        enable_set = tuple(enable)

        selected: list[Rule] = []
        for rule in self.rules:
            if packs and rule.pack not in packs:
                continue
            if tags and not (set(tags) & set(rule.tags)):
                continue
            if min_severity is not None and rule.severity.rank > min_severity.rank:
                continue
            if include_set and not _matches_any(rule, include_set):
                continue
            if exclude_set and _matches_any(rule, exclude_set):
                continue

            enabled = rule.enabled
            if enable_all or (enable_set and _matches_any(rule, enable_set)):
                enabled = True
            if include_set and _matches_any(rule, include_set):
                # 显式点名的规则视为启用，否则 --include-rule 对默认关闭规则无效。
                enabled = True
            selected.append(rule if enabled == rule.enabled else _with_enabled(rule, enabled))

        return RuleSet(rules=tuple(selected), origins=self.origins)


def _with_enabled(rule: Rule, enabled: bool) -> Rule:
    from dataclasses import replace

    return replace(rule, enabled=enabled)


def _matches_any(rule: Rule, selectors: Iterable[str]) -> bool:
    for raw in selectors:
        selector = raw.strip().lower()
        if not selector:
            continue
        if selector.startswith("pack:"):
            if _glob(selector[5:], rule.pack):
                return True
        elif selector.startswith("tag:"):
            needle = selector[4:]
            if any(_glob(needle, t.lower()) for t in rule.tags):
                return True
        elif _glob(selector, rule.id):
            return True
    return False


def _glob(pattern: str, value: str) -> bool:
    if "*" not in pattern:
        return pattern == value
    regex = "".join(".*" if ch == "*" else re.escape(ch) for ch in pattern)
    return re.fullmatch(regex, value) is not None


# --------------------------------------------------------------------------------------
# 加载
# --------------------------------------------------------------------------------------


def _load_file(path: Path) -> list[Rule]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleSyntaxError(f"{path}: YAML 解析失败: {exc}") from exc
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise RuleSyntaxError(f"{path}: 顶层必须是映射，实际为 {type(raw).__name__}")

    version = raw.get("version", _SCHEMA_VERSION)
    if int(version) != _SCHEMA_VERSION:
        raise RuleSyntaxError(f"{path}: 不支持的 version={version}（当前支持 {_SCHEMA_VERSION}）")

    pack = str(raw.get("pack") or path.stem)
    entries = raw.get("rules")
    if not isinstance(entries, list):
        raise RuleSyntaxError(f"{path}: 缺少 rules 列表")

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise RuleSyntaxError(f"{path}: defaults 必须是映射")

    rules: list[Rule] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuleSyntaxError(f"{path}: rules 中出现非映射条目 {entry!r}")
        merged = {**defaults, **entry}
        if "entropy" in defaults and "entropy" in entry:
            merged["entropy"] = {**(defaults["entropy"] or {}), **(entry["entropy"] or {})}
        rules.append(Rule.from_dict(merged, pack=pack, origin=str(path)))
    return rules


def _iter_rule_files(target: Path) -> Iterator[Path]:
    if target.is_dir():
        yield from sorted(p for p in target.rglob("*.y*ml") if p.is_file())
    else:
        yield target


def load_ruleset(
    paths: Sequence[str | Path] = (),
    *,
    include_builtin: bool = True,
) -> RuleSet:
    """加载规则集。

    Args:
        paths: 附加的 YAML 文件或目录。同 id 的规则会**覆盖**内置规则，
            这是团队定制阈值的推荐方式。
        include_builtin: 是否加载内置规则包。

    Raises:
        RuleSyntaxError: 文件不存在或内容不合法。
    """
    sources: list[Path] = []
    if include_builtin:
        sources.append(BUILTIN_RULES_DIR)
    for p in paths:
        path = Path(p).expanduser()
        if not path.exists():
            raise RuleSyntaxError(f"规则路径不存在: {path}")
        sources.append(path)

    by_id: dict[str, Rule] = {}
    origins: list[str] = []
    for source in sources:
        for file in _iter_rule_files(source):
            origins.append(str(file))
            for rule in _load_file(file):
                by_id[rule.id] = rule  # 后加载的同 id 规则覆盖先前的

    if not by_id:
        raise RuleSyntaxError("规则集为空：没有加载到任何规则")

    ordered = sorted(by_id.values(), key=lambda r: (r.severity.rank, r.pack, r.id))
    return RuleSet(rules=tuple(ordered), origins=tuple(origins))
