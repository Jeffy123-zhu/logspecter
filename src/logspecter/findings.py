"""检测结果的数据模型。

``Finding`` 是单次命中；``FindingGroup`` 是按指纹聚合后的结果 —— 生产日志里
同一把密钥可能出现几万次，报告必须按「唯一密钥」维度呈现，否则毫无可读性。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, replace

from logspecter.redact import fingerprint as _fingerprint
from logspecter.redact import mask

__all__ = ["SEVERITY_ORDER", "Confidence", "Finding", "FindingGroup", "Severity"]


class Severity(str, enum.Enum):
    """危害等级，用于 ``--fail-on`` 与报告排序。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self]

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:  # pragma: no cover - 规则加载期报错路径
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"未知 severity {raw!r}，可选: {valid}") from exc


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def from_score(cls, score: float) -> Confidence:
        if score >= 0.80:
            return cls.HIGH
        if score >= 0.55:
            return cls.MEDIUM
        return cls.LOW

    @classmethod
    def parse(cls, raw: str) -> Confidence:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:  # pragma: no cover
            valid = ", ".join(c.value for c in cls)
            raise ValueError(f"未知 confidence {raw!r}，可选: {valid}") from exc

    @property
    def base_score(self) -> float:
        return {Confidence.HIGH: 0.85, Confidence.MEDIUM: 0.6, Confidence.LOW: 0.35}[self]


@dataclass(slots=True)
class Finding:
    """一次命中。

    Attributes:
        rule_id / rule_name / severity: 来自 YAML 规则库。
        secret: 密钥明文。序列化时默认不输出，只输出 ``secret_masked``。
        source: 数据来源（文件路径 / ``<stdin>``）。
        line: 绝对行号（1 起）。多进程扫描时由引擎用前缀和修正。
        byte_offset: 该行在原文件中的起始字节偏移，跨分块唯一且无需全量扫描即可定位。
        column: 密钥在行内的字符偏移（1 起）；结构化命中时指向 JSON 值内偏移。
        json_path: 云原生 Schema 感知给出的精确路径，如
            ``requestParameters.headers.Authorization``。
        cloud_context: 云端上下文（身份、动作、区域……），见 :mod:`logspecter.cloud`。
        entropy / normalized_entropy / charset / evidence: 熵校验证据链。
        confidence_score: 0~1，由规则基准置信度 + 熵值加成 + 结构化加成合成。
    """

    rule_id: str
    rule_name: str
    severity: Severity
    secret: str
    source: str
    line: int
    byte_offset: int
    column: int = 0
    json_path: str | None = None
    matched_context: str = ""
    cloud_context: dict[str, str] = field(default_factory=dict)
    entropy: float = 0.0
    normalized_entropy: float = 0.0
    charset: str = ""
    evidence: tuple[str, ...] = ()
    confidence: Confidence = Confidence.MEDIUM
    confidence_score: float = 0.0
    tags: tuple[str, ...] = ()
    # 分块扫描时先记录块内相对行号，引擎汇总后再换算为绝对行号。
    chunk_index: int = 0
    local_line: int = 0

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.rule_id, self.secret)

    @property
    def secret_masked(self) -> str:
        return mask(self.secret)

    @property
    def locator(self) -> str:
        """人类可读的定位串。"""
        base = f"{self.source}:{self.line}"
        if self.json_path:
            return f"{base} → {self.json_path}"
        if self.column:
            return f"{base}:{self.column}"
        return base

    def context_summary(self) -> str:
        """云端语义摘要。

        普通工具输出「第 800 行」，这里输出：
        ``AWS IAM User (Alice) → AssumeRole → requestParameters.headers.Authorization``
        """
        parts: list[str] = []
        actor = self.cloud_context.get("actor")
        if actor:
            parts.append(actor)
        action = self.cloud_context.get("action")
        if action:
            parts.append(f"action: {action}")
        resource = self.cloud_context.get("resource")
        if resource and not action:
            parts.append(f"resource: {resource}")
        if self.json_path:
            parts.append(self.json_path)
        if not parts:
            return self.locator
        return " → ".join(parts)

    def to_dict(self, *, include_secret: bool = False) -> dict[str, object]:
        payload: dict[str, object] = {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "confidence_score": round(self.confidence_score, 4),
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "byte_offset": self.byte_offset,
            "json_path": self.json_path,
            "secret_masked": self.secret_masked,
            "secret_length": len(self.secret),
            "entropy": round(self.entropy, 4),
            "normalized_entropy": round(self.normalized_entropy, 4),
            "charset": self.charset,
            "evidence": list(self.evidence),
            "cloud_context": dict(self.cloud_context),
            "context_summary": self.context_summary(),
            "tags": list(self.tags),
        }
        if include_secret:
            payload["secret"] = self.secret
        return payload

    def with_absolute_line(self, offset: int) -> Finding:
        """多进程模式下，把块内相对行号换算为整文件绝对行号。"""
        return replace(self, line=offset + self.local_line)


@dataclass(slots=True)
class FindingGroup:
    """按 ``fingerprint`` 聚合的结果。"""

    representative: Finding
    occurrences: int = 1
    #: 除首次命中外，额外记录的定位信息（默认上限见 engine.MAX_SAMPLES_PER_GROUP）。
    extra_locations: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    json_paths: set[str] = field(default_factory=set)

    @property
    def fingerprint(self) -> str:
        return self.representative.fingerprint

    def to_dict(self, *, include_secret: bool = False) -> dict[str, object]:
        payload = self.representative.to_dict(include_secret=include_secret)
        payload["occurrences"] = self.occurrences
        payload["sources"] = sorted(self.sources)
        payload["json_paths"] = sorted(p for p in self.json_paths if p)
        payload["sample_locations"] = list(self.extra_locations)
        return payload
