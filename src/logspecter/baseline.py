"""基线（baseline）与抑制列表。

合规自测的现实：仓库里总有一批「已知、已评估、暂不处置」的命中。基线文件把
这些命中的**指纹**记下来，后续扫描自动抑制，从而让 CI 的门禁只对**新增**泄露
报警。基线只存指纹（SHA-256 前 16 位）与元数据，不存明文密钥。
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from logspecter.findings import FindingGroup

__all__ = ["Baseline", "BaselineError"]

_SCHEMA_VERSION = 1


class BaselineError(ValueError):
    """基线文件不可用或格式不正确。"""


@dataclass(slots=True)
class Baseline:
    """一份指纹抑制清单。"""

    fingerprints: set[str] = field(default_factory=set)
    generated_at: str = ""
    note: str = ""
    #: 指纹 → 记录时的摘要信息，仅用于人工审阅。
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __contains__(self, fingerprint: object) -> bool:
        return fingerprint in self.fingerprints

    def __len__(self) -> int:
        return len(self.fingerprints)

    # ------------------------------------------------------------------ 读写

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        """从 JSON 文件读取基线。

        Raises:
            BaselineError: 文件不存在或结构不合法。
        """
        file = Path(path).expanduser()
        if not file.exists():
            raise BaselineError(f"基线文件不存在: {file}")
        try:
            raw = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"基线文件无法解析: {file}: {exc}") from exc
        if not isinstance(raw, dict):
            raise BaselineError(f"基线文件顶层必须是对象: {file}")

        version = raw.get("version", _SCHEMA_VERSION)
        if int(version) != _SCHEMA_VERSION:
            raise BaselineError(f"不支持的基线版本 {version}（当前支持 {_SCHEMA_VERSION}）")

        entries = raw.get("entries") or {}
        if not isinstance(entries, dict):
            raise BaselineError(f"基线 entries 必须是对象: {file}")

        fingerprints = set(raw.get("fingerprints") or entries.keys())
        return cls(
            fingerprints={str(f) for f in fingerprints},
            generated_at=str(raw.get("generated_at", "")),
            note=str(raw.get("note", "")),
            entries={str(k): dict(v) for k, v in entries.items() if isinstance(v, dict)},
        )

    @classmethod
    def from_groups(cls, groups: Iterable[FindingGroup], *, note: str = "") -> Baseline:
        """由一次扫描结果生成基线。"""
        baseline = cls(
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            note=note,
        )
        for group in groups:
            representative = group.representative
            baseline.fingerprints.add(group.fingerprint)
            baseline.entries[group.fingerprint] = {
                "rule_id": representative.rule_id,
                "severity": representative.severity.value,
                "source": representative.source,
                "line": representative.line,
                "json_path": representative.json_path,
                "secret_masked": representative.secret_masked,
                "occurrences": group.occurrences,
            }
        return baseline

    def save(self, path: str | Path) -> Path:
        """写出基线文件，返回实际写入路径。"""
        file = Path(path).expanduser()
        file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": _SCHEMA_VERSION,
            "generated_at": self.generated_at or time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "note": self.note,
            "fingerprints": sorted(self.fingerprints),
            "entries": self.entries,
        }
        file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return file

    # ------------------------------------------------------------------ 过滤

    def apply(self, groups: Sequence[FindingGroup]) -> tuple[list[FindingGroup], int]:
        """过滤掉已在基线中的分组，返回 ``(保留的分组, 被抑制数量)``。"""
        if not self.fingerprints:
            return list(groups), 0
        kept = [g for g in groups if g.fingerprint not in self.fingerprints]
        return kept, len(groups) - len(kept)
