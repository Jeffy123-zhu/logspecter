"""壁垒一：香农熵 + 启发式二次校验。

普通扫描器只靠正则，`Base64 长串` 这类规则会把前端 session token、类名、
URL、时间戳、Base64 编码的 JSON 全部报成密钥。本模块的职责是：拿到正则初筛
出来的候选串之后，用信息论 + 一组廉价的启发式特征判定它「像不像一把真钥匙」。

判定链路（任一环节否决即丢弃）：

1. 长度门限        —— 太短的串没有统计意义。
2. 字符集识别      —— hex / base64 / base64url / base62 / printable，决定理论熵上限。
3. 香农熵 + 归一化熵 —— 密钥接近字符集理论上限，普通串明显偏低。
4. 唯一字符占比    —— ``aaaaaabbbbbb`` 这类串熵不低但显然不是密钥。
5. 连续/重复模式    —— ``abcdefgh`` ``123456789`` ``xxxxxxxx``。
6. 自然语言相似度   —— 驼峰类名、英文句子的元音比例与常见二元组命中率远高于随机串。
7. Base64 解码回读  —— 解出来是可打印文本/JSON 的，是「编码后的数据」而不是密钥。
8. 占位符 / 文档示例 —— ``EXAMPLE`` ``changeme`` ``AKIAIOSFODNN7EXAMPLE`` 直接否决。

所有函数都是纯函数、无 I/O、无全局状态，便于多进程复用与单元测试。
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from dataclasses import dataclass, field

__all__ = [
    "CHARSET_SIZES",
    "EntropyGate",
    "EntropyVerdict",
    "charset_coverage",
    "contains_placeholder",
    "detect_charset",
    "evaluate",
    "longest_repeat_run",
    "longest_sequential_run",
    "looks_like_encoded_text",
    "shannon_entropy",
    "unique_ratio",
    "word_likeness",
]


# --------------------------------------------------------------------------------------
# 字符集
# --------------------------------------------------------------------------------------

#: 各字符集的字符总数，log2(size) 即该字符集下的理论最大香农熵。
CHARSET_SIZES: dict[str, int] = {
    "hex": 16,
    "base32": 32,
    "base58": 58,
    "base62": 62,
    "base64": 64,
    "base64url": 64,
    "printable": 94,
}

_RE_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")
_RE_BASE32 = re.compile(r"\A[A-Z2-7]+={0,6}\Z")
_RE_BASE62 = re.compile(r"\A[0-9A-Za-z]+\Z")
_RE_BASE64 = re.compile(r"\A[0-9A-Za-z+/]+={0,2}\Z")
_RE_BASE64URL = re.compile(r"\A[0-9A-Za-z_-]+={0,2}\Z")

_RE_UUID = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_RE_TIMESTAMPISH = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}")
_RE_NUMERIC = re.compile(r"\A[0-9.,:+-]+\Z")
_RE_WORDSPLIT = re.compile(r"[^A-Za-z]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

#: 占位符 / 文档示例 / 显式脱敏后的值。命中即否决，属于最高优先级降噪。
_PLACEHOLDER_TOKENS: tuple[str, ...] = (
    "example",
    "changeme",
    "change_me",
    "placeholder",
    "redacted",
    "your-",
    "your_",
    "yourkey",
    "dummy",
    "sample",
    "notarealkey",
    "fakekey",
    "xxxxxx",
    "000000",
    "111111",
    "abcdef123456",
    "deadbeef",
    "insertkeyhere",
    "s3cr3t",
    "topsecret",
    "lorem",
    "<insert",
    "todo",
    "n/a",
    "null",
    "none",
    "undefined",
    "test-key",
    "testkey",
    "test_key",
    "aws_secret_access_key_here",
)

#: AWS / GCP 官方文档里反复出现的示例凭据，几乎必然是假的。
_KNOWN_DOC_SECRETS: frozenset[str] = frozenset(
    {
        "akiaiosfodnn7example",
        "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",
        "akidexample",
        "asiaiosfodnn7example",
        "akiai44qh8dhbexample",
        "je7mtge55rzhy2rmeky7zwpz44sfmnnzuxbbv4a",
    }
)

#: 英文里最高频的二元字母组合。随机 Base64 串命中率通常 < 12%，英文文本 > 30%。
_COMMON_BIGRAMS: frozenset[str] = frozenset(
    [
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "io",
        "le",
        "ve",
        "co",
        "me",
        "de",
        "hi",
        "ri",
        "ro",
        "ic",
        "ne",
        "ea",
        "ra",
        "ce",
        "li",
        "ch",
        "ll",
        "be",
        "ma",
        "si",
        "om",
        "ur",
        "ca",
        "el",
        "ta",
        "la",
        "ns",
        "di",
        "ot",
        "sa",
        "ig",
        "sh",
        "em",
        "ai",
        "ie",
        "ss",
        "us",
        "wa",
        "ho",
        "ut",
        "ad",
        "ge",
        "ns",
        "ap",
        "pr",
        "tr",
        "ul",
        "ay",
        "ol",
        "id",
        "am",
        "ei",
        "os",
        "pe",
        "ei",
        "ns",
        "ur",
    ]
)

_VOWELS = frozenset("aeiouAEIOU")


# --------------------------------------------------------------------------------------
# 基础指标
# --------------------------------------------------------------------------------------


def shannon_entropy(value: str) -> float:
    """返回 ``value`` 按字符分布计算的香农熵（bit/字符）。

    H = -Σ p(c) · log2 p(c)

    >>> round(shannon_entropy("aaaa"), 4)
    0.0
    >>> round(shannon_entropy("ab"), 4)
    1.0
    """
    if not value:
        return 0.0
    length = len(value)
    total = 0.0
    for count in Counter(value).values():
        p = count / length
        total -= p * math.log2(p)
    return total


def unique_ratio(value: str) -> float:
    """唯一字符数 / 总长度。仅作为参考指标，判定请用 :func:`charset_coverage`。"""
    if not value:
        return 0.0
    return len(set(value)) / len(value)


def charset_coverage(value: str, charset: str | None = None) -> float:
    """字符集覆盖率：唯一字符数 / **可达到的**唯一字符数上限。

    直接用「唯一字符数 / 长度」会系统性冤枉长串：一个 64 字符的十六进制哈希最多
    只有 16 种字符，比值天然只有 0.25，但它其实是完美均匀的。把分母换成
    ``min(长度, 字符集规模)`` 之后，该哈希的覆盖率是 1.0，而 ``aaaa…`` 依然接近 0。

    >>> round(charset_coverage("0123456789abcdef" * 4), 3)
    1.0
    >>> round(charset_coverage("a" * 32), 4)  # 全 'a' 被识别为 hex（16 种字符）
    0.0625
    """
    if not value:
        return 0.0
    charset = charset or detect_charset(value)
    achievable = min(len(value), CHARSET_SIZES.get(charset, 94))
    return len(set(value)) / achievable if achievable else 0.0


def longest_repeat_run(value: str) -> int:
    """最长连续同字符长度，例如 ``ab####cd`` 返回 4。"""
    best = run = 0
    prev = ""
    for ch in value:
        run = run + 1 if ch == prev else 1
        prev = ch
        if run > best:
            best = run
    return best


def longest_sequential_run(value: str) -> int:
    """最长「码位递增/递减 1」的序列长度，用于识别 ``abcdef`` ``987654``。"""
    best = run = 1
    direction = 0
    for i in range(1, len(value)):
        delta = ord(value[i]) - ord(value[i - 1])
        if delta in (1, -1) and (direction == 0 or direction == delta):
            direction = delta
            run += 1
        elif delta in (1, -1):
            direction = delta
            run = 2
        else:
            direction = 0
            run = 1
        if run > best:
            best = run
    return best if len(value) > 1 else len(value)


def detect_charset(value: str) -> str:
    """识别字符串所属的最小字符集，用于计算归一化熵。"""
    if _RE_HEX.match(value):
        return "hex"
    if _RE_BASE32.match(value):
        return "base32"
    if _RE_BASE62.match(value):
        return "base62"
    if _RE_BASE64URL.match(value) and ("-" in value or "_" in value):
        return "base64url"
    if _RE_BASE64.match(value):
        return "base64"
    if _RE_BASE64URL.match(value):
        return "base64url"
    return "printable"


def word_likeness(value: str) -> float:
    """返回 0~1 的「自然语言相似度」。

    组合两个廉价特征：常见英文二元组命中率与元音占比。驼峰命名的 Java 类名、
    英文日志消息会得到较高分值，而真随机密钥通常低于 0.25。
    """
    letters = [c for c in value if c.isalpha()]
    if len(letters) < 4:
        return 0.0

    lowered = "".join(letters).lower()
    pairs = [lowered[i : i + 2] for i in range(len(lowered) - 1)]
    bigram_hit = sum(1 for p in pairs if p in _COMMON_BIGRAMS) / len(pairs) if pairs else 0.0

    vowel_ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)
    # 随机 Base64 的元音期望约 0.16，英文约 0.38；线性映射到 0~1 并裁剪。
    vowel_score = min(max((vowel_ratio - 0.16) / 0.22, 0.0), 1.0)

    # 二元组命中率期望：随机 ~0.10，英文 ~0.35。
    bigram_score = min(max((bigram_hit - 0.10) / 0.25, 0.0), 1.0)

    return round(0.6 * bigram_score + 0.4 * vowel_score, 4)


def looks_like_encoded_text(value: str) -> bool:
    """判断 Base64 候选串解码后是否为可打印文本 / JSON。

    真密钥解出来是高熵二进制，而「Base64 编码的 JSON / URL / 会话上下文」
    解出来是人类可读文本 —— 后者是生产日志里最常见的误报来源之一。
    """
    if len(value) < 12:
        return False
    charset = detect_charset(value)
    if charset not in {"base64", "base64url", "base62"}:
        return False

    candidate = value.replace("-", "+").replace("_", "/")
    candidate += "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(candidate, validate=False)
    except Exception:
        return False
    if len(raw) < 6:
        return False

    if raw[:1] in (b"{", b"[") or raw[:5] == b"<?xml":
        return True

    printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return printable / len(raw) >= 0.90


def _contains_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in _KNOWN_DOC_SECRETS:
        return True
    return any(token in lowered for token in _PLACEHOLDER_TOKENS)


def contains_placeholder(value: str) -> bool:
    """公开接口：字符串是否带有占位符 / 官方文档示例凭据的特征。"""
    return _contains_placeholder(value)


# --------------------------------------------------------------------------------------
# 校验门（Gate）与判定结果
# --------------------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class EntropyGate:
    """一条规则的熵值/启发式门限配置。

    每条 YAML 规则可以覆写这些字段；``enabled=False`` 时表示该规则依靠结构
    特征（例如 ``AKIA`` 前缀、``BEGIN RSA PRIVATE KEY``）即可确诊，无需熵校验，
    但占位符与文档示例过滤依然生效。
    """

    enabled: bool = True
    min_entropy: float = 3.5
    #: 归一化熵门限（entropy / log2(charset_size)），跨字符集可比。
    min_normalized: float = 0.55
    min_length: int = 16
    max_length: int = 4096
    #: 字符集覆盖率门限，见 :func:`charset_coverage`（不是「唯一字符/长度」）。
    min_charset_coverage: float = 0.45
    max_repeat_run: int = 5
    max_sequential_run: int = 6
    max_word_likeness: float = 0.62
    #: 解码后是可打印文本的 Base64 串是否直接否决。
    reject_encoded_text: bool = True
    reject_placeholders: bool = True
    reject_uuid: bool = True
    #: 允许的字符集白名单，空集合表示不限制。
    charsets: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def structural(cls) -> EntropyGate:
        """结构性规则使用的门（关闭熵校验，仅保留占位符过滤）。"""
        return cls(enabled=False, min_length=0)

    @classmethod
    def from_mapping(cls, data: dict | None, base: EntropyGate | None = None) -> EntropyGate:
        """从 YAML 映射构造门限；未给出的字段继承 ``base``（默认取类默认值）。"""
        base = base or cls()
        if not data:
            return base
        known = set(cls.__dataclass_fields__)
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"未知的 entropy 配置字段: {sorted(unknown)}")
        merged: dict[str, object] = {f: getattr(base, f) for f in known}
        merged.update(data)
        charsets = merged.get("charsets") or ()
        if isinstance(charsets, str):
            charsets = [charsets]
        merged["charsets"] = frozenset(charsets)
        merged["enabled"] = bool(merged["enabled"])
        return cls(**merged)  # type: ignore[arg-type]


@dataclass(slots=True, frozen=True)
class EntropyVerdict:
    """一次校验的完整结论，``reasons`` 会原样进入报告作为审计证据。"""

    accepted: bool
    entropy: float
    normalized: float
    charset: str
    reasons: tuple[str, ...] = ()
    #: 置信度调整量，-1.0 ~ +1.0。高熵会加分，接近门限则减分。
    confidence_delta: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "entropy": round(self.entropy, 4),
            "normalized_entropy": round(self.normalized, 4),
            "charset": self.charset,
            "reasons": list(self.reasons),
            "confidence_delta": round(self.confidence_delta, 4),
        }


def evaluate(value: str, gate: EntropyGate | None = None) -> EntropyVerdict:
    """对候选串执行完整的熵值 + 启发式校验。

    Args:
        value: 正则捕获出来的疑似密钥本体（不含前后关键词）。
        gate: 门限配置，``None`` 时使用默认值。

    Returns:
        :class:`EntropyVerdict`。``accepted=False`` 表示判定为误报，
        ``reasons`` 给出被否决或被接受的具体依据。
    """
    gate = gate or EntropyGate()
    value = value.strip().strip("\"'`,;")
    charset = detect_charset(value) if value else "printable"
    entropy = shannon_entropy(value)
    max_entropy = math.log2(CHARSET_SIZES.get(charset, 94))
    normalized = entropy / max_entropy if max_entropy else 0.0
    reasons: list[str] = []

    def reject(reason: str) -> EntropyVerdict:
        return EntropyVerdict(False, entropy, normalized, charset, (reason,), -1.0)

    if gate.reject_placeholders and _contains_placeholder(value):
        return reject("placeholder-or-doc-example")

    if not gate.enabled:
        return EntropyVerdict(True, entropy, normalized, charset, ("structural-match",), 0.15)

    if len(value) < gate.min_length:
        return reject(f"too-short(<{gate.min_length})")
    if len(value) > gate.max_length:
        return reject(f"too-long(>{gate.max_length})")

    if gate.charsets and charset not in gate.charsets:
        return reject(f"charset-not-allowed({charset})")

    if gate.reject_uuid and _RE_UUID.match(value):
        return reject("uuid-shape")
    if _RE_TIMESTAMPISH.match(value):
        return reject("timestamp-shape")
    if _RE_NUMERIC.match(value):
        return reject("numeric-only")

    coverage = charset_coverage(value, charset)
    if coverage < gate.min_charset_coverage:
        return reject(f"low-charset-coverage({coverage:.2f})")

    repeat = longest_repeat_run(value)
    if repeat > gate.max_repeat_run:
        return reject(f"repeated-run({repeat})")

    sequential = longest_sequential_run(value)
    if sequential > gate.max_sequential_run:
        return reject(f"sequential-run({sequential})")

    # 十六进制 / Base32 只用极少数字母，元音比例天然偏高，语言相似度指标在这类
    # 字符集上没有区分力，直接跳过以免冤枉哈希类密钥。
    wordish = 0.0 if charset in {"hex", "base32"} else word_likeness(value)
    if wordish > gate.max_word_likeness:
        return reject(f"natural-language-like({wordish:.2f})")

    if gate.reject_encoded_text and looks_like_encoded_text(value):
        return reject("base64-decodes-to-text")

    if entropy < gate.min_entropy:
        return reject(f"entropy-below-threshold({entropy:.2f}<{gate.min_entropy})")
    if normalized < gate.min_normalized:
        return reject(f"normalized-entropy-below-threshold({normalized:.2f}<{gate.min_normalized})")

    reasons.append(f"entropy={entropy:.2f}/{max_entropy:.2f}({charset})")
    reasons.append(f"charset_coverage={coverage:.2f}")
    if wordish <= 0.20:
        reasons.append("non-linguistic")

    # 越接近字符集理论上限，越像真钥匙。
    headroom = (normalized - gate.min_normalized) / max(1e-9, 1.0 - gate.min_normalized)
    confidence_delta = round(min(max(headroom, 0.0), 1.0) * 0.4 - 0.05, 4)
    if len(value) >= 40:
        confidence_delta += 0.05

    return EntropyVerdict(
        accepted=True,
        entropy=entropy,
        normalized=normalized,
        charset=charset,
        reasons=tuple(reasons),
        confidence_delta=round(min(confidence_delta, 0.45), 4),
    )
