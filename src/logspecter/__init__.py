"""LogSpecter —— 面向云端结构化日志的密钥泄露扫描器。

三层技术壁垒：
1. 多维混合检测引擎：正则初筛 + 香农熵二次校验 + 启发式降噪（``entropy`` 模块）。
2. 云原生 Schema 结构感知：orjson 零拷贝解析，输出云端身份/动作/JSON 路径（``structured`` / ``cloud``）。
3. 内存克制的流式引擎：字节区间行对齐 + mmap 窗口读取，内存占用与文件大小解耦（``ingest``）。
"""

from __future__ import annotations

__all__ = [
    "Finding",
    "FindingGroup",
    "ScanConfig",
    "ScanResult",
    "ScanStats",
    "Severity",
    "__version__",
    "scan",
]

__version__ = "0.1.0"


def __getattr__(name: str):  # pragma: no cover - 惰性导出，避免导入 CLI 时拉起全部依赖
    if name in {"Finding", "FindingGroup", "Severity"}:
        from logspecter import findings

        return getattr(findings, name)
    if name in {"ScanConfig", "ScanResult", "ScanStats", "scan"}:
        from logspecter import engine

        return getattr(engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
