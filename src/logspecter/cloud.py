"""壁垒二（上半）：云端日志 Schema 识别与上下文抽取。

普通扫描器把日志当纯文本，报出来是「第 800 行发现疑似密钥」。本模块从已解析的
JSON 记录里识别它属于哪一种云端日志 Schema，并抽出**可直接用于响应处置**的上下文：
谁（身份）、做了什么（API 动作）、在哪（区域/资源）、什么时候。

于是报告变成：

    AWS IAM User (Alice) → action: AssumeRole → requestParameters.headers.Authorization

支持的 Schema：AWS CloudTrail、GCP Cloud Logging、Kubernetes 审计日志、
Azure Activity Log、Elastic Common Schema、Logback/Log4j2 JSON。识别失败时
回退到通用启发式抽取，不影响检测本身。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

__all__ = ["SCHEMA_DETECTORS", "detect_schema", "extract_context"]

_MAX_VALUE_LEN = 160


def _text(value: Any) -> str | None:
    """把 JSON 值安全地转成短字符串；不可用则返回 ``None``。"""
    if value is None or isinstance(value, (dict, list)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    if not text:
        return None
    return text[:_MAX_VALUE_LEN]


def _dig(record: Mapping[str, Any], *path: str) -> Any:
    """按路径逐层取值，任一层不是映射或不存在则返回 ``None``。"""
    node: Any = record
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
        if node is None:
            return None
    return node


def _first(record: Mapping[str, Any], *paths: tuple[str, ...]) -> str | None:
    for path in paths:
        value = _text(_dig(record, *path))
        if value:
            return value
    return None


def _put(ctx: dict[str, str], key: str, value: str | None) -> None:
    if value:
        ctx[key] = value


# --------------------------------------------------------------------------------------
# AWS CloudTrail
# --------------------------------------------------------------------------------------


def _is_cloudtrail(record: Mapping[str, Any]) -> bool:
    if "eventVersion" in record and "eventSource" in record:
        return True
    return "userIdentity" in record and ("eventName" in record or "eventTime" in record)


def _cloudtrail_actor(record: Mapping[str, Any]) -> str | None:
    identity = record.get("userIdentity")
    if not isinstance(identity, Mapping):
        return None

    kind = _text(identity.get("type")) or "Unknown"
    name = (
        _text(identity.get("userName"))
        or _text(_dig(identity, "sessionContext", "sessionIssuer", "userName"))
        or _text(identity.get("principalId"))
    )
    arn = _text(identity.get("arn"))
    if name and ":" in name:
        name = name.rsplit(":", 1)[-1]
    if not name and arn:
        # arn:aws:iam::123:user/alice → alice；arn:aws:iam::123:root → root
        name = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]

    label = {
        "IAMUser": "AWS IAM User",
        "AssumedRole": "AWS Assumed Role",
        "Root": "AWS Root Account",
        "FederatedUser": "AWS Federated User",
        "AWSService": "AWS Service",
        "AWSAccount": "AWS Account",
        "Directory": "AWS Directory User",
        "Unknown": "AWS Principal",
    }.get(kind, f"AWS {kind}")

    return f"{label} ({name})" if name else label


def _extract_cloudtrail(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "aws-cloudtrail"}
    _put(ctx, "actor", _cloudtrail_actor(record))
    _put(ctx, "action", _text(record.get("eventName")))
    _put(ctx, "service", _text(record.get("eventSource")))
    _put(ctx, "region", _text(record.get("awsRegion")))
    _put(ctx, "source_ip", _text(record.get("sourceIPAddress")))
    _put(ctx, "timestamp", _text(record.get("eventTime")))
    _put(ctx, "account", _text(record.get("recipientAccountId")))
    _put(ctx, "request_id", _text(record.get("requestID")) or _text(record.get("eventID")))
    _put(ctx, "user_agent", _text(record.get("userAgent")))
    error = _text(record.get("errorCode"))
    if error:
        ctx["outcome"] = f"error: {error}"
    _put(ctx, "resource", _text(_dig(record, "requestParameters", "roleArn")))
    return ctx


# --------------------------------------------------------------------------------------
# GCP Cloud Logging
# --------------------------------------------------------------------------------------


def _is_gcp_logging(record: Mapping[str, Any]) -> bool:
    if "logName" in record and ("resource" in record or "insertId" in record):
        return True
    return isinstance(record.get("protoPayload"), Mapping) and "insertId" in record


def _extract_gcp(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "gcp-cloud-logging"}
    principal = _first(
        record,
        ("protoPayload", "authenticationInfo", "principalEmail"),
        ("protoPayload", "requestMetadata", "callerSuppliedUserAgent"),
        ("labels", "principal_email"),
    )
    if principal:
        ctx["actor"] = f"GCP Principal ({principal})"
    _put(ctx, "action", _first(record, ("protoPayload", "methodName"), ("operation", "id")))
    _put(
        ctx,
        "resource",
        _first(record, ("protoPayload", "resourceName"), ("resource", "type")),
    )
    _put(ctx, "service", _first(record, ("protoPayload", "serviceName"), ("logName",)))
    _put(
        ctx,
        "region",
        _first(record, ("resource", "labels", "location"), ("resource", "labels", "zone")),
    )
    _put(
        ctx,
        "source_ip",
        _first(record, ("protoPayload", "requestMetadata", "callerIp")),
    )
    _put(ctx, "timestamp", _text(record.get("timestamp")))
    _put(ctx, "severity", _text(record.get("severity")))
    _put(
        ctx,
        "account",
        _first(record, ("resource", "labels", "project_id"), ("labels", "project_id")),
    )
    _put(ctx, "trace", _text(record.get("trace")))
    _put(ctx, "request_id", _text(record.get("insertId")))
    return ctx


# --------------------------------------------------------------------------------------
# Kubernetes 审计日志
# --------------------------------------------------------------------------------------


def _is_k8s_audit(record: Mapping[str, Any]) -> bool:
    api = _text(record.get("apiVersion")) or ""
    if api.startswith("audit.k8s.io"):
        return True
    return record.get("kind") == "Event" and "verb" in record and "user" in record


def _extract_k8s(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "kubernetes-audit"}
    user = _first(record, ("user", "username"), ("impersonatedUser", "username"))
    if user:
        ctx["actor"] = f"K8s User ({user})"
    verb = _text(record.get("verb"))
    resource = _first(record, ("objectRef", "resource"))
    name = _first(record, ("objectRef", "name"))
    namespace = _first(record, ("objectRef", "namespace"))
    if verb:
        ctx["action"] = f"{verb} {resource}" if resource else verb
    target = "/".join(p for p in (namespace, name) if p)
    _put(ctx, "resource", target or resource)
    _put(ctx, "timestamp", _text(record.get("requestReceivedTimestamp")))
    _put(ctx, "request_id", _text(record.get("auditID")))
    ips = record.get("sourceIPs")
    if isinstance(ips, list) and ips:
        _put(ctx, "source_ip", _text(ips[0]))
    _put(ctx, "outcome", _first(record, ("responseStatus", "code")))
    _put(ctx, "service", _first(record, ("objectRef", "apiGroup")))
    return ctx


# --------------------------------------------------------------------------------------
# Azure Activity / Diagnostic Log
# --------------------------------------------------------------------------------------


def _is_azure_activity(record: Mapping[str, Any]) -> bool:
    keys = set(record)
    if {"operationName", "resourceId"} <= keys:
        return True
    return {"operationName", "category"} <= keys and "time" in keys


def _extract_azure(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "azure-activity-log"}
    caller = _first(
        record,
        ("identity", "claims", "name"),
        ("identity", "claims", "upn"),
        ("identity", "authorization", "evidence", "principalId"),
        ("caller",),
    )
    if caller:
        ctx["actor"] = f"Azure Identity ({caller})"
    _put(ctx, "action", _text(record.get("operationName")))
    _put(ctx, "resource", _text(record.get("resourceId")))
    _put(ctx, "region", _text(record.get("location")))
    _put(ctx, "source_ip", _text(record.get("callerIpAddress")))
    _put(ctx, "timestamp", _text(record.get("time")))
    _put(ctx, "severity", _text(record.get("level")))
    _put(ctx, "service", _text(record.get("category")))
    _put(ctx, "request_id", _text(record.get("correlationId")))
    _put(ctx, "outcome", _text(record.get("resultType")))
    return ctx


# --------------------------------------------------------------------------------------
# Elastic Common Schema / OpenTelemetry
# --------------------------------------------------------------------------------------


def _is_ecs(record: Mapping[str, Any]) -> bool:
    return "@timestamp" in record and any(
        isinstance(record.get(k), Mapping) for k in ("event", "service", "host", "user")
    )


def _extract_ecs(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "elastic-common-schema"}
    user = _first(record, ("user", "name"), ("user", "id"), ("client", "user", "name"))
    if user:
        ctx["actor"] = f"User ({user})"
    _put(ctx, "action", _first(record, ("event", "action"), ("http", "request", "method")))
    _put(ctx, "service", _first(record, ("service", "name"), ("event", "dataset")))
    _put(ctx, "resource", _first(record, ("url", "path"), ("host", "hostname")))
    _put(ctx, "source_ip", _first(record, ("source", "ip"), ("client", "ip")))
    _put(ctx, "timestamp", _text(record.get("@timestamp")))
    _put(ctx, "severity", _first(record, ("log", "level"), ("event", "severity")))
    _put(ctx, "trace", _first(record, ("trace", "id")))
    return ctx


# --------------------------------------------------------------------------------------
# Logback / Log4j2 JSON（含 MDC）
# --------------------------------------------------------------------------------------


def _is_jvm_json_log(record: Mapping[str, Any]) -> bool:
    keys = set(record)
    if {"logger_name", "level"} <= keys or {"loggerName", "level"} <= keys:
        return True
    return bool(keys & {"mdc", "contextMap"}) and bool(keys & {"level", "message"})


def _extract_jvm(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "jvm-json-log"}
    mdc = record.get("mdc")
    if not isinstance(mdc, Mapping):
        mdc = record.get("contextMap")
    if isinstance(mdc, Mapping):
        user = _first(mdc, ("userId",), ("user",), ("username",), ("principal",), ("tenant",))
        if user:
            ctx["actor"] = f"MDC user ({user})"
        _put(
            ctx,
            "trace",
            _first(mdc, ("traceId",), ("trace_id",), ("requestId",), ("X-B3-TraceId",)),
        )
    _put(ctx, "service", _first(record, ("logger_name",), ("loggerName",), ("logger",)))
    _put(ctx, "severity", _text(record.get("level")))
    _put(ctx, "timestamp", _first(record, ("@timestamp",), ("timestamp",), ("instant",)))
    # 线程名不是「动作」，塞进 action 会让摘要读起来像 "action: main"。
    _put(ctx, "thread", _first(record, ("thread_name",), ("threadName",)))
    return ctx


# --------------------------------------------------------------------------------------
# 通用回退
# --------------------------------------------------------------------------------------


def _extract_generic(record: Mapping[str, Any]) -> dict[str, str]:
    ctx: dict[str, str] = {"schema": "generic-json"}
    user = _first(
        record,
        ("user",),
        ("username",),
        ("user_name",),
        ("userId",),
        ("principal",),
        ("account",),
        ("actor",),
    )
    if user:
        ctx["actor"] = f"User ({user})"
    _put(ctx, "action", _first(record, ("action",), ("event",), ("operation",), ("method",)))
    _put(ctx, "resource", _first(record, ("resource",), ("path",), ("url",), ("target",)))
    _put(
        ctx,
        "timestamp",
        _first(record, ("timestamp",), ("time",), ("@timestamp",), ("ts",), ("date",)),
    )
    _put(ctx, "severity", _first(record, ("level",), ("severity",), ("loglevel",)))
    _put(ctx, "source_ip", _first(record, ("ip",), ("client_ip",), ("remote_addr",), ("sourceIp",)))
    _put(ctx, "trace", _first(record, ("trace_id",), ("traceId",), ("request_id",), ("requestId",)))
    return ctx


#: 检测顺序即优先级：越特化的 Schema 越靠前。
SCHEMA_DETECTORS: tuple[
    tuple[str, Callable[[Mapping[str, Any]], bool], Callable[[Mapping[str, Any]], dict[str, str]]],
    ...,
] = (
    ("aws-cloudtrail", _is_cloudtrail, _extract_cloudtrail),
    ("gcp-cloud-logging", _is_gcp_logging, _extract_gcp),
    ("kubernetes-audit", _is_k8s_audit, _extract_k8s),
    ("azure-activity-log", _is_azure_activity, _extract_azure),
    ("elastic-common-schema", _is_ecs, _extract_ecs),
    ("jvm-json-log", _is_jvm_json_log, _extract_jvm),
)


def detect_schema(record: Any) -> str:
    """返回记录所属的 Schema 名称；无法识别时返回 ``generic-json``。"""
    if not isinstance(record, Mapping):
        return "unknown"
    for name, predicate, _ in SCHEMA_DETECTORS:
        try:
            if predicate(record):
                return name
        except Exception:
            continue
    return "generic-json"


def extract_context(record: Any) -> dict[str, str]:
    """从 JSON 记录抽取云端上下文。

    永不抛异常：日志里什么脏数据都有，识别失败最多退化为空上下文。
    """
    if not isinstance(record, Mapping):
        return {}
    for _, predicate, extractor in SCHEMA_DETECTORS:
        try:
            if predicate(record):
                return extractor(record)
        except Exception:
            continue
    try:
        return _extract_generic(record)
    except Exception:
        return {"schema": "generic-json"}
