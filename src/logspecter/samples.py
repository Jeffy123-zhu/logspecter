"""内置样本集与合成日志生成器。

两个用途：

1. ``logspecter selftest`` —— 用**正样本**验证检出能力、用**负样本**验证降噪能力。
   负样本全部取自真实生产日志里最常把普通扫描器骗到的形态：UUID 会话 ID、
   Base64 编码的 JSON、驼峰类名、Git 提交哈希、模板占位符……
2. ``logspecter benchmark`` —— 生成任意大小的合成日志压测吞吐与内存。

这里所有「密钥」都由固定种子的伪随机数生成器现场产生，**不包含任何真实凭据**，
同时刻意避开占位符特征词，确保能真正走完熵值校验链路。
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

from logspecter import entropy

__all__ = [
    "NEGATIVE_SAMPLES",
    "POSITIVE_SAMPLES",
    "make_secret",
    "write_synthetic_log",
]

_SEED = 20260901
_B64 = string.ascii_letters + string.digits + "+/"
_B64URL = string.ascii_letters + string.digits + "-_"
_ALNUM = string.ascii_letters + string.digits
_UPPER_NUM = string.ascii_uppercase + string.digits
_LOWER_HEX = "0123456789abcdef"


def make_secret(alphabet: str, length: int, rng: random.Random) -> str:
    """生成一个「看起来像真钥匙」的随机串。

    约束：不含占位符特征、无长重复段、唯一字符占比足够高 —— 否则会被熵值层
    正确地判为误报，导致自检结果失去意义。
    """
    # 长串不可能达到 50% 唯一率（字符集就那么大），按字符集规模取上界。
    required_unique = int(min(length * 0.5, len(set(alphabet)) * 0.7))
    for _ in range(400):
        candidate = "".join(rng.choice(alphabet) for _ in range(length))
        if entropy.contains_placeholder(candidate):
            continue
        if entropy.longest_repeat_run(candidate) > 3:
            continue
        if entropy.longest_sequential_run(candidate) > 5:
            continue
        if len(set(candidate)) < required_unique:
            continue
        if entropy.word_likeness(candidate) > 0.5:
            continue
        return candidate
    raise RuntimeError(  # pragma: no cover
        f"无法生成满足约束的样本密钥 (alphabet={len(alphabet)}, length={length})"
    )


def _build_positive_samples() -> tuple[tuple[str, str], ...]:
    rng = random.Random(_SEED)
    g = make_secret

    aws_key = "AKIA" + g(_UPPER_NUM, 16, rng)
    aws_secret = g(_B64, 40, rng)
    aws_session = g(_B64, 180, rng)
    gcp_key = "AIza" + g(_B64URL, 35, rng)
    gcp_refresh = "1//" + g(_B64URL, 40, rng)
    gcp_client_secret = "GOCSPX-" + g(_B64URL, 28, rng)
    azure_storage = g(_B64, 86, rng) + "=="
    azure_secret = g(_ALNUM, 3, rng) + "8Q~" + g(_B64URL + "~.", 33, rng)
    github_pat = "ghp_" + g(_ALNUM, 36, rng)
    github_fine = "github_pat_" + g(_ALNUM + "_", 82, rng)
    gitlab_pat = "glpat-" + g(_B64URL, 20, rng)
    slack_token = "xoxb-" + g(string.digits, 12, rng) + "-" + g(_ALNUM, 24, rng)
    stripe_key = "sk_live_" + g(_ALNUM, 24, rng)
    sendgrid = "SG." + g(_B64URL, 22, rng) + "." + g(_B64URL, 43, rng)
    openai = "sk-proj-" + g(_B64URL, 56, rng)
    anthropic = "sk-ant-api03-" + g(_B64URL, 95, rng)
    npm_token = "npm_" + g(_ALNUM, 36, rng)
    hf_token = "hf_" + g(_ALNUM, 34, rng)
    telegram = g(string.digits, 10, rng) + ":AA" + g(_B64URL, 33, rng)
    grafana = "glsa_" + g(_ALNUM, 32, rng) + "_" + g(_LOWER_HEX, 8, rng)
    docker_pat = "dckr_pat_" + g(_B64URL, 27, rng)
    shopify = "shpat_" + g(_LOWER_HEX, 32, rng)
    # 真实 JWT 的 payload 段也以 eyJ 开头（Base64 编码的 '{'），样本必须保持一致。
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ" + g(_B64URL, 60, rng) + "." + g(_B64URL, 43, rng)
    )
    datadog = g(_LOWER_HEX, 32, rng)
    pem_body = g(_B64, 64, rng)
    bearer = g(_B64URL, 48, rng)
    basic = g(_B64, 32, rng)
    db_password = g(_ALNUM + "!@#$%", 18, rng)
    hmac_key = g(_LOWER_HEX, 64, rng)
    generic_secret = g(_ALNUM, 28, rng)
    json_secret = g(_B64URL, 44, rng)

    return (
        # ---------------- AWS ----------------
        ("aws-access-key-id", f"2026-08-30T10:00:00Z INFO deploy accessKeyId={aws_key}"),
        (
            "aws-secret-access-key",
            f'2026-08-30T10:00:01Z DEBUG cfg aws_secret_access_key="{aws_secret}"',
        ),
        (
            "aws-session-token",
            f"2026-08-30T10:00:02Z DEBUG sts x-amz-security-token: {aws_session}",
        ),
        (
            "aws-sigv4-credential-scope",
            "GET /bucket HTTP/1.1 Authorization: AWS4-HMAC-SHA256 "
            f"Credential={aws_key[:20]}/20260830/us-east-1/s3/aws4_request, SignedHeaders=host",
        ),
        # ---------------- GCP ----------------
        ("gcp-api-key", f'{{"maps_key":"{gcp_key}"}}'),
        ("gcp-oauth-refresh-token", f"refresh_token={gcp_refresh}"),
        ("gcp-oauth-client-secret", f"client_secret={gcp_client_secret}"),
        (
            "gcp-service-account-key-json",
            json.dumps(
                {
                    "type": "service_account",
                    "project_id": "prod-analytics",
                    "private_key_id": g(_LOWER_HEX, 40, rng),
                    "private_key": f"-----BEGIN PRIVATE KEY-----\\n{pem_body}\\n-----END PRIVATE KEY-----\\n",
                    "client_email": "svc@prod-analytics.iam.gserviceaccount.com",
                }
            ),
        ),
        # ---------------- Azure ----------------
        (
            "azure-storage-account-key",
            f"DefaultEndpointsProtocol=https;AccountName=prodlogs;AccountKey={azure_storage}",
        ),
        ("azure-ad-client-secret", f"AZURE_CLIENT_SECRET={azure_secret}"),
        # ---------------- 私钥 ----------------
        (
            "private-key-pem-header",
            f"ERROR tls handshake failed: -----BEGIN RSA PRIVATE KEY----- {pem_body}",
        ),
        ("putty-private-key", "PuTTY-User-Key-File-2: ssh-rsa"),
        # ---------------- 厂商 ----------------
        (
            "github-personal-access-token",
            f"git remote add origin https://{github_pat}@github.com/o/r",
        ),
        ("github-fine-grained-pat", f"GH_TOKEN={github_fine}"),
        ("gitlab-personal-access-token", f"PRIVATE-TOKEN: {gitlab_pat}"),
        ("slack-token", f'{{"slack":{{"bot_token":"{slack_token}"}}}}'),
        ("stripe-live-secret-key", f"STRIPE_SECRET={stripe_key}"),
        ("sendgrid-api-key", f"SENDGRID_API_KEY={sendgrid}"),
        ("openai-api-key", f'{{"headers":{{"Authorization":"Bearer {openai}"}}}}'),
        ("anthropic-api-key", f"ANTHROPIC_API_KEY={anthropic}"),
        ("npm-access-token", f"//registry.npmjs.org/:_authToken={npm_token}"),
        ("huggingface-access-token", f"HF_TOKEN={hf_token}"),
        ("telegram-bot-token", f"https://api.telegram.org/bot{telegram}/sendMessage"),
        ("grafana-service-account-token", f"Authorization: Bearer {grafana}"),
        ("dockerhub-personal-access-token", f"docker login -u ci -p {docker_pat}"),
        ("shopify-access-token", f"X-Shopify-Access-Token: {shopify}"),
        ("jwt-compact-token", f"Cookie: session={jwt}"),
        ("datadog-api-key", f"DD_API_KEY={datadog}"),
        # ---------------- 通用 / 数据库 ----------------
        ("authorization-header-bearer", f"upstream call authorization: Bearer {bearer}"),
        ("authorization-header-basic", f"proxy-authorization: Basic {basic}"),
        ("generic-secret-assignment", f"encryption_key={generic_secret}"),
        ("generic-hex-secret", f"hmac signature key {hmac_key} verified"),
        (
            "db-connection-uri-password",
            f"postgresql://appsvc:{db_password}@db-prod-1.internal:5432/orders",
        ),
        ("jdbc-url-password", f"jdbc:mysql://db2:3306/app?user=svc&password={db_password}"),
        (
            "http-basic-auth-in-url",
            f"curl -sS https://ciuser:{db_password}@artifacts.internal/pkg.tgz",
        ),
        (
            "sensitive-json-key-value",
            json.dumps(
                {
                    "eventVersion": "1.08",
                    "userIdentity": {"type": "IAMUser", "userName": "svc-deployer"},
                    "eventName": "PutParameter",
                    "eventSource": "ssm.amazonaws.com",
                    "awsRegion": "eu-central-1",
                    "requestParameters": {"name": "/prod/db", "credential": json_secret},
                }
            ),
        ),
        ("kubeconfig-client-key-data", f"client-key-data: {g(_B64, 220, rng)}"),
        ("pkcs12-keystore-password", f"keystore_password={g(_ALNUM, 20, rng)}"),
        # ---------------- 补齐剩余规则的覆盖 ----------------
        (
            "azure-storage-connection-string",
            "AZURE_CONN=DefaultEndpointsProtocol=https;AccountName=prodlogs2;"
            f"AccountKey={g(_B64, 86, rng)}==;EndpointSuffix=core.windows.net",
        ),
        (
            "azure-servicebus-shared-access-key",
            "Endpoint=sb://bus.servicebus.windows.net/;SharedAccessKeyName=send;"
            f"SharedAccessKey={g(_B64, 43, rng)}=",
        ),
        ("azure-sas-signature", f"GET /c/b?sv=2024-05-04&sig={g(_B64, 60, rng)}&se=2026-09-01"),
        (
            "azure-subscription-management-cert",
            f"managementCertificate=MII{g(_B64, 240, rng)}",
        ),
        ("pgp-private-key-block", f"-----BEGIN PGP PRIVATE KEY BLOCK----- {g(_B64, 40, rng)}"),
        ("ssh-private-key-body", f"key=b3BlbnNzaC1rZXktdjE{g(_B64, 80, rng)}"),
        (
            "openai-api-key-legacy",
            f"OPENAI_API_KEY=sk-{g(_ALNUM, 20, rng)}T3BlbkFJ{g(_ALNUM, 20, rng)}",
        ),
        ("pypi-upload-token", f"password=pypi-AgEIcHlwaS5vcmc{g(_B64URL, 60, rng)}"),
        (
            "terraform-cloud-api-token",
            f"credentials: {g(_ALNUM, 14, rng)}.atlasv1.{g(_B64URL, 60, rng)}",
        ),
        (
            "aws-cognito-identity-pool-secret",
            f"cognito_client_secret={g(string.ascii_lowercase + string.digits, 40, rng)}",
        ),
        (
            "aws-mws-auth-token",
            "MWS_AUTH_TOKEN=amzn.mws."
            f"{g(_LOWER_HEX, 8, rng)}-{g(_LOWER_HEX, 4, rng)}-{g(_LOWER_HEX, 4, rng)}"
            f"-{g(_LOWER_HEX, 4, rng)}-{g(_LOWER_HEX, 12, rng)}",
        ),
        (
            "mongodb-scram-credential",
            '{"user":"svc","credentials":{"SCRAM-SHA-256":'
            f'{{"storedKey":"{g(_B64, 44, rng)}","iterationCount":15000}}}}}}',
        ),
        ("redis-auth-command", f"redis command received: AUTH default {g(_ALNUM, 24, rng)}"),
        (
            "gcp-firebase-cloud-messaging-key",
            f"FCM_SERVER_KEY=AAAA{g(_B64URL, 7, rng)}:APA91b{g(_B64URL, 140, rng)}",
        ),
        (
            "gcp-service-account-private-key-id",
            f'{{"private_key_id": "{g(_LOWER_HEX, 40, rng)}", "client_email": "a@b.iam"}}',
        ),
        ("gcp-oauth-access-token", f"Authorization: Bearer ya29.{g(_B64URL, 60, rng)}"),
        ("atlassian-api-token", f"JIRA_TOKEN=ATATT3x{g(_B64URL, 180, rng)}"),
        (
            "discord-bot-token",
            f"DISCORD_TOKEN=MTA{g(_B64URL, 21, rng)}.{g(_B64URL, 6, rng)}.{g(_B64URL, 30, rng)}",
        ),
        ("gitlab-pipeline-trigger-token", f"trigger token glptt-{g(_LOWER_HEX, 40, rng)}"),
        ("mailgun-api-key", f"MAILGUN_API_KEY=key-{g(_LOWER_HEX, 32, rng)}"),
        (
            "slack-incoming-webhook",
            f"posting to https://hooks.slack.com/services/T{g(_ALNUM, 10, rng)}"
            f"/B{g(_ALNUM, 10, rng)}/{g(_ALNUM, 24, rng)}",
        ),
        (
            "twilio-api-key-sid",
            f"twilio auth_token rotated, new key SK{g(_LOWER_HEX, 32, rng)}",
        ),
        ("twilio-account-sid", f"twilio account_sid AC{g(_LOWER_HEX, 32, rng)} ready"),
        ("stripe-test-secret-key", f"STRIPE_TEST=sk_test_{g(_ALNUM, 24, rng)}"),
        ("generic-high-entropy-token", f"opaque blob {g(_B64URL, 48, rng)} received"),
        (
            "aws-principal-unique-id",
            f'{{"userIdentity":{{"principalId":"AROA{g(_UPPER_NUM, 16, rng)}"}}}}',
        ),
    )


def _build_negative_samples() -> tuple[str, ...]:
    """真实日志里最常见的「假密钥」形态，一条都不应该被报出来。"""
    return (
        # 会话 / 追踪标识：UUID 与 Git SHA
        "INFO  request X-Request-Id: 3f2504e0-4f89-11d3-9a0c-0305e82c3301 status=200",
        "INFO  build commit=9f2c1ab7d4e5f60189bc3a2d7e4f5061a8b9c0d1 branch=main",
        '{"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7"}',
        # Base64 编码的 JSON / 文本 —— 解码后是可读文本，不是密钥
        "DEBUG payload=eyJ1c2VyIjoiYWxpY2UiLCJyb2xlIjoidmlld2VyIiwicGFnZSI6M30=",
        "DEBUG cursor_token=aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vdjEvaXRlbXM/cGFnZT0y",
        # 驼峰类名 / 长英文标识符
        "ERROR apiKey resolution failed for SpringBootApplicationConfigurationLoader",
        "INFO  password validation handler: PasswordStrengthValidatorConfiguration",
        # 模板占位符与文档示例
        "INFO  config aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
        "DEBUG env AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}",
        'INFO  helm values: apiKey: "<your-api-key-here>"',
        "WARN  using default credentials password=changeme",
        "INFO  token=REDACTED_BY_LOG_SCRUBBER",
        # 重复 / 顺序模式
        "DEBUG session_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "DEBUG api_key=abcdefghijklmnopqrstuvwxyz012345",
        "DEBUG secret=000000000000000000000000000000",
        # 时间戳、数字、路径、MIME
        "INFO  window start=2026-08-30T11:22:33.123456Z end=2026-08-30T12:22:33.123456Z",
        "INFO  credential file path=/var/run/secrets/kubernetes.io/serviceaccount/token",
        "INFO  content-type=application/vnd.api+json;charset=utf-8 accept-encoding=gzip",
        "INFO  css theme token: --color-primary:#1f2933;--color-accent:#0b7285",
        # 无关键词的哈希（generic-hex-secret 要求邻近关键词）
        "INFO  artifact sha256=9b74c9897bac770ffc029102a200c5de6ce4e6e4a1a4b8e5a5e0f0e3d2c1b0a9",
        # 结构化日志里的普通高熵字段（不是敏感键）
        '{"@timestamp":"2026-08-30T11:22:33Z","level":"INFO","logger_name":"c.e.Svc",'
        '"mdc":{"traceId":"7b3f9c2e1d4a5b6c","userId":"u-88121"},"message":"ok"}',
        '{"eventName":"DescribeInstances","userIdentity":{"type":"AWSService"},'
        '"requestParameters":{"instanceIdSet":{"items":[{"instanceId":"i-0abc123def4567890"}]}}}',
        # 看起来像 Basic 认证但其实是模板
        "INFO  authorization: Basic ${BASE64_CREDENTIALS}",
        # 弱口令占位与空值
        "DEBUG db password= null",
        'DEBUG client_secret=""',
    )


POSITIVE_SAMPLES: tuple[tuple[str, str], ...] = _build_positive_samples()
NEGATIVE_SAMPLES: tuple[str, ...] = _build_negative_samples()


# --------------------------------------------------------------------------------------
# 合成日志生成
# --------------------------------------------------------------------------------------

_GENERATION_BLOCK = 4 * 1024 * 1024


def _cloudtrail_line(rng: random.Random) -> str:
    actions = ("AssumeRole", "GetObject", "PutObject", "DescribeInstances", "CreateLogStream")
    return json.dumps(
        {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": rng.choice(("IAMUser", "AssumedRole", "AWSService")),
                "principalId": f"AIDA{''.join(rng.choices(_UPPER_NUM, k=17))}",
                "arn": f"arn:aws:iam::{rng.randrange(10**11, 10**12)}:user/svc-{rng.randrange(1000)}",
                "userName": f"svc-{rng.randrange(1000)}",
            },
            "eventTime": "2026-08-30T11:22:33Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": rng.choice(actions),
            "awsRegion": rng.choice(("us-east-1", "eu-central-1", "ap-southeast-2")),
            "sourceIPAddress": f"203.0.113.{rng.randrange(256)}",
            "userAgent": "aws-sdk-go/1.44.0",
            "requestID": f"{rng.randrange(16**16):016x}",
            "requestParameters": {
                "bucketName": f"prod-logs-{rng.randrange(100)}",
                "key": f"year=2026/month=08/day=30/part-{rng.randrange(10000):05d}.parquet",
            },
            "responseElements": None,
            "recipientAccountId": "123456789012",
        },
        separators=(",", ":"),
    )


def _app_line(rng: random.Random) -> str:
    levels = ("INFO", "DEBUG", "WARN", "ERROR")
    messages = (
        "handled request in {ms}ms status=200 path=/api/v1/orders/{oid}",
        "cache miss key=orders:{oid} region={region}",
        "publishing event orderCreated id={oid} attempts=1",
        "db query took {ms}ms rows=42 statement=SELECT_ORDERS_BY_TENANT",
        "retry scheduled attempt=2 backoff={ms}ms reason=upstream_timeout",
    )
    template = rng.choice(messages)
    return (
        f"2026-08-30T11:22:{rng.randrange(60):02d}.{rng.randrange(1000):03d}Z "
        f"{rng.choice(levels):5s} c.e.orders.OrderService [http-nio-8080-exec-{rng.randrange(32)}] "
        + template.format(
            ms=rng.randrange(1, 900),
            oid=f"{rng.randrange(16**12):012x}",
            region=rng.choice(("us-east-1", "eu-central-1")),
        )
    )


def _noise_line(rng: random.Random) -> str:
    """高熵但无害的行 —— 用来检验降噪层是否会误报。"""
    kind = rng.randrange(4)
    if kind == 0:
        return f"INFO  request_id={rng.randrange(16**32):032x} status=204"
    if kind == 1:
        payload = json.dumps({"user": f"u-{rng.randrange(99999)}", "page": rng.randrange(50)})
        import base64

        return f"DEBUG cursor={base64.b64encode(payload.encode()).decode()}"
    if kind == 2:
        return (
            "INFO  X-Trace-Id: "
            f"{rng.randrange(16**8):08x}-{rng.randrange(16**4):04x}-"
            f"{rng.randrange(16**4):04x}-{rng.randrange(16**4):04x}-{rng.randrange(16**12):012x}"
        )
    return f'INFO  etag="{rng.randrange(16**16):016x}" content-length={rng.randrange(100000)}'


def _secret_line(rng: random.Random) -> str:
    rule_id, payload = rng.choice(POSITIVE_SAMPLES)
    del rule_id
    return payload


def write_synthetic_log(
    path: str | Path,
    target_bytes: int,
    *,
    secret_ratio: float = 0.0002,
    seed: int = _SEED,
) -> tuple[int, int, int]:
    """生成用于压测的合成日志。

    混合四类行：CloudTrail JSON（40%）、应用日志（40%）、高熵噪声（20%），
    并按 ``secret_ratio`` 植入真实形态的密钥行。

    Returns:
        ``(写入字节数, 行数, 植入的密钥行数)``
    """
    rng = random.Random(seed)
    written = 0
    lines = 0
    planted = 0
    buffer: list[bytes] = []
    buffered = 0

    with open(path, "wb") as handle:
        while written < target_bytes:
            if rng.random() < secret_ratio:
                text = _secret_line(rng)
                planted += 1
            else:
                roll = rng.random()
                if roll < 0.40:
                    text = _cloudtrail_line(rng)
                elif roll < 0.80:
                    text = _app_line(rng)
                else:
                    text = _noise_line(rng)
            encoded = text.encode("utf-8") + b"\n"
            buffer.append(encoded)
            buffered += len(encoded)
            written += len(encoded)
            lines += 1
            if buffered >= _GENERATION_BLOCK:
                handle.write(b"".join(buffer))
                buffer.clear()
                buffered = 0
        if buffer:
            handle.write(b"".join(buffer))

    return written, lines, planted
