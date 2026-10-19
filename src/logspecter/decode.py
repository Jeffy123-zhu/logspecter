"""单层 Base64 / Base64URL 可打印文本解码。

用于 ``--decode-base64``：当日志中出现 Base64 编码的配置片段、Basic 认证头、
查询参数或 JSON 字符串时，将其中属于「人类可读文本」的载荷还原出来供文本规则二次扫描，
而对真正的高熵二进制随机字节直接跳过。
"""

from __future__ import annotations

import base64
import re

__all__ = ["decode_base64_text", "is_printable_text"]

#: 可打印 ASCII 字符集（含制表符、换行符、回车符）。
_PRINTABLE_BYTES = bytes([0x09, 0x0A, 0x0D, *range(0x20, 0x7F)])
_RE_B64_TOKEN = re.compile(rb"\A[A-Za-z0-9+/_-]+={0,2}\Z")
_URLSAFE_TRANS = bytes.maketrans(b"-_", b"+/")


def is_printable_text(raw: bytes, *, min_ratio: float = 0.90) -> bool:
    """判断字节串是否主要由可打印 ASCII 字符（含制表、换行、回车）构成。"""
    if len(raw) < 6:
        return False
    non_printable = len(raw.translate(None, _PRINTABLE_BYTES))
    return (len(raw) - non_printable) / len(raw) >= min_ratio


def decode_base64_text(token: bytes, *, max_bytes: int = 64 * 1024) -> bytes | None:
    """解码单层 Base64 或 Base64URL 候选串（兼容缺失的 ``=`` 填充）。

    仅当解码后的载荷未超过 ``max_bytes`` 且属于可打印文本时返回字节串；
    否则返回 ``None``。
    """
    if max_bytes <= 0 or len(token) < 8:
        return None
    stripped = token.rstrip(b"=")
    pad_len = len(token) - len(stripped)
    if pad_len > 2 or not stripped or len(stripped) % 4 == 1:
        return None
    # 提前按编码长度估算解码体积上界，避免对超大串分配无效缓冲区。
    if ((len(stripped) * 3) // 4) > max_bytes:
        return None
    if not _RE_B64_TOKEN.match(token):
        return None

    normalized = (
        stripped.translate(_URLSAFE_TRANS) if (b"-" in stripped or b"_" in stripped) else stripped
    )
    rem = len(normalized) % 4
    if rem:
        normalized += b"=" * (4 - rem)
    try:
        raw = base64.b64decode(normalized, validate=True)
    except Exception:
        return None
    if len(raw) > max_bytes or not is_printable_text(raw):
        return None
    return raw
