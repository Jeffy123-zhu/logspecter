"""脱敏与指纹。

扫描器本身不能变成新的泄露源：终端输出、JSON/CSV 报告默认只写掩码值，
真值仅在 ``--show-secrets`` 时呈现。指纹用于跨分块去重与 baseline 抑制，
使用 SHA-256 前 16 个十六进制字符（64 bit），碰撞概率对本场景足够。
"""

from __future__ import annotations

import hashlib

__all__ = ["fingerprint", "mask", "mask_line"]

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
