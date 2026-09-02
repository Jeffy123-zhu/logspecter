"""结构化报告导出：JSON / CSV / SARIF。

三种格式对应三类下游：

* **JSON** —— 给自研平台、Lambda、SIEM 直接消费，包含完整证据链与云上下文。
* **CSV** —— 给合规同事的电子表格，SOC 2 / ISO 27001 自测证据留档。
* **SARIF 2.1.0** —— GitHub Code Scanning、Azure DevOps 等原生识别的静态分析格式，
  上传后直接在 PR 里显示注解。

所有格式默认写掩码值；``include_secret=True`` 才输出明文（需显式 ``--show-secrets``）。
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from typing import Any

from logspecter import __version__
from logspecter.findings import FindingGroup, Severity

__all__ = ["REPORT_FORMATS", "export", "to_csv", "to_json", "to_sarif"]

REPORT_FORMATS = ("json", "csv", "sarif")

_CSV_COLUMNS = (
    "fingerprint",
    "rule_id",
    "rule_name",
    "severity",
    "confidence",
    "confidence_score",
    "occurrences",
    "source",
    "line",
    "column",
    "byte_offset",
    "json_path",
    "secret_masked",
    "secret_length",
    "entropy",
    "normalized_entropy",
    "charset",
    "cloud_schema",
    "cloud_actor",
    "cloud_action",
    "cloud_region",
    "cloud_source_ip",
    "cloud_timestamp",
    "context_summary",
    "evidence",
    "tags",
)

#: SARIF 只有三档，映射自本工具的五档等级。
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_json(result: Any, *, include_secret: bool = False, indent: int = 2) -> str:
    """导出为 JSON 文本。``result`` 为 :class:`logspecter.engine.ScanResult`。"""
    payload = {
        "tool": {"name": "logspecter", "version": __version__},
        "summary": {
            "findings": len(result.groups),
            "occurrences": result.total_occurrences,
            "by_severity": result.count_by_severity(),
            "sources": result.sources,
            "errors": result.errors,
        },
        "stats": result.stats.as_dict(),
        "findings": [g.to_dict(include_secret=include_secret) for g in result.groups],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False, sort_keys=False)


def to_csv(result: Any, *, include_secret: bool = False) -> str:
    """导出为 CSV 文本（含表头）。"""
    buffer = io.StringIO(newline="")
    columns = list(_CSV_COLUMNS)
    if include_secret:
        columns.append("secret")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for group in result.groups:
        finding = group.representative
        context = finding.cloud_context
        row: dict[str, Any] = {
            "fingerprint": group.fingerprint,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "confidence_score": round(finding.confidence_score, 4),
            "occurrences": group.occurrences,
            "source": finding.source,
            "line": finding.line,
            "column": finding.column,
            "byte_offset": finding.byte_offset,
            "json_path": finding.json_path or "",
            "secret_masked": finding.secret_masked,
            "secret_length": len(finding.secret),
            "entropy": round(finding.entropy, 4),
            "normalized_entropy": round(finding.normalized_entropy, 4),
            "charset": finding.charset,
            "cloud_schema": context.get("schema", ""),
            "cloud_actor": context.get("actor", ""),
            "cloud_action": context.get("action", ""),
            "cloud_region": context.get("region", ""),
            "cloud_source_ip": context.get("source_ip", ""),
            "cloud_timestamp": context.get("timestamp", ""),
            "context_summary": finding.context_summary(),
            "evidence": "; ".join(finding.evidence),
            "tags": ",".join(finding.tags),
        }
        if include_secret:
            row["secret"] = finding.secret
        writer.writerow(row)
    return buffer.getvalue()


def to_sarif(result: Any, *, include_secret: bool = False) -> str:
    """导出为 SARIF 2.1.0 文本。"""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for group in result.groups:
        finding = group.representative
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_name,
                "shortDescription": {"text": finding.rule_name},
                "fullDescription": {"text": finding.rule_name},
                "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                "properties": {
                    "tags": list(finding.tags) or ["security"],
                    "severity": finding.severity.value,
                },
            }
        message = f"{finding.rule_name}: {finding.context_summary()}"
        if include_secret:
            message += f" (secret={finding.secret})"
        else:
            message += f" (masked={finding.secret_masked})"

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": message},
                "partialFingerprints": {"logspecterFingerprint/v1": group.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_uri(finding.source)},
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column or 1),
                            },
                        },
                        "logicalLocations": (
                            [{"name": finding.json_path, "kind": "member"}]
                            if finding.json_path
                            else []
                        ),
                    }
                ],
                "properties": {
                    "confidence": finding.confidence.value,
                    "confidenceScore": round(finding.confidence_score, 4),
                    "entropy": round(finding.entropy, 4),
                    "normalizedEntropy": round(finding.normalized_entropy, 4),
                    "charset": finding.charset,
                    "occurrences": group.occurrences,
                    "evidence": list(finding.evidence),
                    "cloudContext": dict(finding.cloud_context),
                },
            }
        )

    document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LogSpecter",
                        "version": __version__,
                        "informationUri": "https://github.com/logspecter/logspecter",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": err}} for err in result.errors
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def _sarif_uri(source: str) -> str:
    """SARIF 要求相对 URI 使用正斜杠。"""
    return source.replace("\\", "/")


def export(
    result: Any,
    fmt: str,
    *,
    include_secret: bool = False,
) -> str:
    """按格式名导出。

    Raises:
        ValueError: 格式名未知。
    """
    normalized = fmt.strip().lower()
    if normalized == "json":
        return to_json(result, include_secret=include_secret)
    if normalized == "csv":
        return to_csv(result, include_secret=include_secret)
    if normalized == "sarif":
        return to_sarif(result, include_secret=include_secret)
    raise ValueError(f"未知导出格式 {fmt!r}，可选: {', '.join(REPORT_FORMATS)}")


def severity_order(groups: Sequence[FindingGroup]) -> list[FindingGroup]:
    """按危害等级排序（引擎已排好，此处供外部复用）。"""
    return sorted(groups, key=lambda g: g.representative.severity.rank)
