"""脱敏与指纹。

扫描器本身不能变成新的泄露源：终端输出、JSON/CSV 报告默认只写掩码值，
真值仅在 ``--show-secrets`` 时呈现。指纹用于跨分块去重与 baseline 抑制，
使用 SHA-256 前 16 个十六进制字符（64 bit），碰撞概率对本场景足够。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO

__all__ = ["fingerprint", "mask", "mask_line", "redact_file", "redact_stream"]

_FINGERPRINT_LEN = 16


def fingerprint(rule_id: str, secret: str) -> str:
    """同一条规则 + 同一个密钥值 → 同一指纹，与出现位置无关。"""
    digest = hashlib.sha256(f"{rule_id}\x00{secret}".encode("utf-8", "surrogatepass")).hexdigest()
    return digest[:_FINGERPRINT_LEN]


#: 掩码中间段最多渲染多少个 ``*``。真实长度由 ``(len=N)`` 给出，因此不必等长填充
#: —— 108 字符的密钥若逐字符打星号，会在终端里撑出四五行。
_MAX_STARS = 8


def mask(secret: str, keep: int = 4) -> str:
    """保留首尾若干字符，中间以 ``*`` 填充并注明真实长度。

    >>> mask("AKIAIOSFODNN7EXAMPLE")
    'AKIA********MPLE (len=20)'
    >>> mask("short")
    '***** (len=5)'
    """
    if not secret:
        return "<empty>"
    if len(secret) <= keep * 2 + 2:
        return "*" * len(secret) + f" (len={len(secret)})"
    head, tail = secret[:keep], secret[-keep:]
    stars = min(len(secret) - keep * 2, _MAX_STARS)
    return f"{head}{'*' * stars}{tail} (len={len(secret)})"


def mask_line(line: str, secret: str, keep: int = 4) -> str:
    """把行文本里出现的密钥替换为掩码，用于展示带上下文的证据片段。"""
    if not secret or secret not in line:
        return line
    masked = mask(secret, keep).split(" (len=")[0]
    return line.replace(secret, masked)


def _build_replacement_pairs(
    secrets: Iterable[str],
    *,
    keep: int = 4,
) -> list[tuple[bytes, bytes]]:
    """构造按长度降序排列的 ``(待替换字节串, 掩码字节串)`` 列表。

    同时包含原始密钥与其 JSON 转义形式（``json.dumps(secret)[1:-1]``），确保 JSON 行
    在脱敏后依然是合法 JSON；长密钥优先，避免包含短密钥子串时被截断替换。
    """
    unique_secrets = sorted({s for s in secrets if s}, key=lambda s: (-len(s), s))
    pairs: list[tuple[bytes, bytes]] = []
    seen_needles: set[bytes] = set()

    for secret in unique_secrets:
        masked = mask(secret, keep=keep)
        masked_bytes = masked.encode("utf-8", "surrogatepass")
        escaped_masked_bytes = json.dumps(masked, ensure_ascii=False)[1:-1].encode(
            "utf-8", "surrogatepass"
        )

        for ensure_ascii in (False, True):
            escaped = json.dumps(secret, ensure_ascii=ensure_ascii)[1:-1]
            if escaped != secret:
                needle = escaped.encode("utf-8", "surrogatepass")
                if needle and needle not in seen_needles:
                    seen_needles.add(needle)
                    pairs.append((needle, escaped_masked_bytes))

        raw_needle = secret.encode("utf-8", "surrogatepass")
        if raw_needle and raw_needle not in seen_needles:
            seen_needles.add(raw_needle)
            pairs.append((raw_needle, masked_bytes))

    pairs.sort(key=lambda item: (-len(item[0]), item[0]))
    return pairs


def redact_stream(
    src: BinaryIO,
    dst: BinaryIO,
    secrets: Iterable[str],
    *,
    keep: int = 4,
) -> int:
    """按二进制流逐行读取 ``src``，将命中的密钥替换为 ``mask(secret)`` 后写入 ``dst``。

    未命中字节（含 CRLF/LF 行尾与非 UTF-8 字节）原样保留。返回总替换次数。
    """
    pairs = _build_replacement_pairs(secrets, keep=keep)
    if not pairs:
        for line in src:
            dst.write(line)
        return 0

    repl_map = dict(pairs)
    pattern = re.compile(b"|".join(re.escape(needle) for needle, _ in pairs))
    replacements = 0

    def _replace(match: re.Match[bytes]) -> bytes:
        return repl_map[match.group(0)]

    for line in src:
        new_line, count = pattern.subn(_replace, line)
        if count:
            replacements += count
            dst.write(new_line)
        else:
            dst.write(line)

    return replacements


def redact_file(
    source: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    secrets: Iterable[str],
    *,
    keep: int = 4,
) -> int:
    """将单个日志文件脱敏后写入目标路径，返回替换次数。"""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(source, "rb") as src_handle, open(dest_path, "wb") as dst_handle:
        return redact_stream(src_handle, dst_handle, secrets, keep=keep)
