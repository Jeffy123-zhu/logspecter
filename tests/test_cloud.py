"""云端 Schema 识别与上下文抽取测试（壁垒二）。"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from logspecter import cloud


class TestCloudTrail:
    RECORD: ClassVar[dict[str, Any]] = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "Alice",
            "arn": "arn:aws:iam::123456789012:user/Alice",
        },
        "eventTime": "2026-08-30T11:22:33Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.9",
        "recipientAccountId": "123456789012",
        "requestID": "abc-123",
        "userAgent": "aws-cli/2.15.0",
    }

    def test_schema_detected(self) -> None:
        assert cloud.detect_schema(self.RECORD) == "aws-cloudtrail"

    def test_context_fields(self) -> None:
        context = cloud.extract_context(self.RECORD)
        assert context["actor"] == "AWS IAM User (Alice)"
        assert context["action"] == "AssumeRole"
        assert context["service"] == "sts.amazonaws.com"
        assert context["region"] == "us-east-1"
        assert context["source_ip"] == "203.0.113.9"
        assert context["account"] == "123456789012"

    def test_assumed_role_uses_session_issuer(self) -> None:
        record = {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "userIdentity": {
                "type": "AssumedRole",
                "sessionContext": {"sessionIssuer": {"userName": "DeployRole"}},
            },
        }
        assert cloud.extract_context(record)["actor"] == "AWS Assumed Role (DeployRole)"

    def test_arn_fallback_when_username_missing(self) -> None:
        record = {
            "eventVersion": "1.08",
            "eventSource": "s3.amazonaws.com",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::1:user/svc-bot"},
        }
        assert cloud.extract_context(record)["actor"] == "AWS IAM User (svc-bot)"

    def test_error_code_becomes_outcome(self) -> None:
        record = dict(self.RECORD, errorCode="AccessDenied")
        assert cloud.extract_context(record)["outcome"] == "error: AccessDenied"


class TestGcpLogging:
    RECORD: ClassVar[dict[str, Any]] = {
        "logName": "projects/prod/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "xyz",
        "timestamp": "2026-08-30T11:22:33Z",
        "severity": "NOTICE",
        "resource": {"type": "gce_instance", "labels": {"project_id": "prod", "zone": "us-c1-a"}},
        "protoPayload": {
            "authenticationInfo": {"principalEmail": "svc@prod.iam.gserviceaccount.com"},
            "methodName": "v1.compute.instances.insert",
            "resourceName": "projects/prod/zones/us-c1-a/instances/web-1",
            "serviceName": "compute.googleapis.com",
            "requestMetadata": {"callerIp": "198.51.100.7"},
        },
    }

    def test_schema_and_actor(self) -> None:
        assert cloud.detect_schema(self.RECORD) == "gcp-cloud-logging"
        context = cloud.extract_context(self.RECORD)
        assert context["actor"] == "GCP Principal (svc@prod.iam.gserviceaccount.com)"
        assert context["action"] == "v1.compute.instances.insert"
        assert context["region"] == "us-c1-a"
        assert context["source_ip"] == "198.51.100.7"
        assert context["account"] == "prod"


class TestKubernetesAudit:
    RECORD: ClassVar[dict[str, Any]] = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "auditID": "aaa-bbb",
        "verb": "create",
        "user": {"username": "system:serviceaccount:ci:deployer"},
        "objectRef": {"resource": "secrets", "namespace": "prod", "name": "db-creds"},
        "sourceIPs": ["10.0.0.5"],
        "requestReceivedTimestamp": "2026-08-30T11:22:33Z",
        "responseStatus": {"code": 201},
    }

    def test_context(self) -> None:
        assert cloud.detect_schema(self.RECORD) == "kubernetes-audit"
        context = cloud.extract_context(self.RECORD)
        assert context["actor"] == "K8s User (system:serviceaccount:ci:deployer)"
        assert context["action"] == "create secrets"
        assert context["resource"] == "prod/db-creds"
        assert context["source_ip"] == "10.0.0.5"


class TestAzureActivityLog:
    RECORD: ClassVar[dict[str, Any]] = {
        "time": "2026-08-30T11:22:33Z",
        "operationName": "MICROSOFT.KEYVAULT/VAULTS/SECRETS/WRITE",
        "resourceId": "/SUBSCRIPTIONS/1/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/KV",
        "identity": {"claims": {"name": "ci-bot@contoso.com"}},
        "callerIpAddress": "192.0.2.10",
        "level": "Informational",
        "category": "Administrative",
        "correlationId": "cid-1",
        "resultType": "Success",
    }

    def test_context(self) -> None:
        assert cloud.detect_schema(self.RECORD) == "azure-activity-log"
        context = cloud.extract_context(self.RECORD)
        assert context["actor"] == "Azure Identity (ci-bot@contoso.com)"
        assert "KEYVAULT" in context["action"]
        assert context["source_ip"] == "192.0.2.10"
        assert context["outcome"] == "Success"


class TestElasticCommonSchema:
    def test_context(self) -> None:
        record = {
            "@timestamp": "2026-08-30T11:22:33Z",
            "event": {"action": "user-login", "dataset": "auth"},
            "user": {"name": "bob"},
            "service": {"name": "gateway"},
            "source": {"ip": "203.0.113.4"},
            "log": {"level": "info"},
            "trace": {"id": "t-1"},
        }
        assert cloud.detect_schema(record) == "elastic-common-schema"
        context = cloud.extract_context(record)
        assert context["actor"] == "User (bob)"
        assert context["action"] == "user-login"
        assert context["trace"] == "t-1"


class TestJvmJsonLog:
    def test_mdc_context(self) -> None:
        record = {
            "@timestamp": "2026-08-30T11:22:33Z",
            "level": "DEBUG",
            "logger_name": "c.e.PaymentClient",
            "thread_name": "http-nio-8080-exec-3",
            "mdc": {"userId": "u-991", "traceId": "abc123"},
            "message": "calling upstream",
        }
        assert cloud.detect_schema(record) == "jvm-json-log"
        context = cloud.extract_context(record)
        assert context["actor"] == "MDC user (u-991)"
        assert context["trace"] == "abc123"
        assert context["service"] == "c.e.PaymentClient"

    def test_log4j2_context_map(self) -> None:
        record = {"level": "WARN", "contextMap": {"user": "carol"}, "message": "x"}
        assert cloud.extract_context(record)["actor"] == "MDC user (carol)"


class TestFallbacks:
    def test_generic_json(self) -> None:
        record = {"user": "dave", "action": "delete", "path": "/v1/x", "level": "ERROR"}
        assert cloud.detect_schema(record) == "generic-json"
        context = cloud.extract_context(record)
        assert context["actor"] == "User (dave)"
        assert context["action"] == "delete"

    @pytest.mark.parametrize("value", [None, [], "text", 42])
    def test_non_mapping_returns_empty(self, value: object) -> None:
        assert cloud.extract_context(value) == {}

    def test_non_mapping_schema_is_unknown(self) -> None:
        assert cloud.detect_schema("not a record") == "unknown"

    def test_hostile_record_does_not_raise(self) -> None:
        # 字段类型全错的脏数据不应中断扫描
        record = {"eventVersion": 1, "eventSource": [], "userIdentity": "oops"}
        assert isinstance(cloud.extract_context(record), dict)

    def test_long_values_are_truncated(self) -> None:
        record = {"user": "x" * 500, "action": "y"}
        assert len(cloud.extract_context(record)["actor"]) < 200
