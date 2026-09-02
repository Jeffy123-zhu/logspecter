"""进程内存与 CPU 信息采集（仅依赖标准库）。

内存上限是本项目对外承诺的核心指标之一，所以它必须是**可测量、可复现**的：
``--stats`` 会输出主进程与每个 worker 的峰值常驻内存，而不是空口宣称。

* Windows：``GetProcessMemoryInfo`` → ``PeakWorkingSetSize``
* Linux：``/proc/self/status`` 的 ``VmHWM``，回退到 ``getrusage(ru_maxrss)``（KiB）
* macOS/BSD：``getrusage(ru_maxrss)``（字节）

任何平台上取不到就返回 ``None``，调用方需按「未知」处理，不得伪造数字。
"""

from __future__ import annotations

import os
import platform
import sys

__all__ = ["cpu_count", "current_rss", "format_bytes", "peak_rss"]

_IS_WINDOWS = sys.platform == "win32"


def _windows_memory_counters() -> tuple[int, int] | None:
    """返回 ``(峰值工作集, 当前工作集)``，单位字节；失败返回 ``None``。

    必须显式声明 ``argtypes`` / ``restype``：``GetCurrentProcess`` 返回的伪句柄是
    ``HANDLE``（x64 下 64 位），若沿用 ctypes 默认的 ``c_int`` 会被截断，调用直接失败。
    """
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:  # pragma: no cover - 非 CPython 环境
        return None

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        psapi = ctypes.WinDLL("psapi", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(_ProcessMemoryCounters)
        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        )
    except (AttributeError, OSError):  # pragma: no cover - 平台差异
        return None
    if not ok:  # pragma: no cover
        return None
    return int(counters.PeakWorkingSetSize), int(counters.WorkingSetSize)


def _read_proc_status(field: str) -> int | None:
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith(field):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1]) * 1024
    except OSError:  # pragma: no cover
        return None
    return None


def _rusage_maxrss() -> int | None:
    try:
        import resource
    except ImportError:  # pragma: no cover - Windows
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if value <= 0:
        return None
    # Linux 返回 KiB，macOS/BSD 返回字节。
    return value if platform.system() == "Darwin" else value * 1024


def peak_rss() -> int | None:
    """当前进程的峰值常驻内存（字节）；无法获取时返回 ``None``。"""
    if _IS_WINDOWS:
        counters = _windows_memory_counters()
        return counters[0] if counters else None
    return _read_proc_status("VmHWM:") or _rusage_maxrss()


def current_rss() -> int | None:
    """当前进程的常驻内存（字节）；无法获取时返回 ``None``。"""
    if _IS_WINDOWS:
        counters = _windows_memory_counters()
        return counters[1] if counters else None
    return _read_proc_status("VmRSS:")


def cpu_count() -> int:
    """可用 CPU 数量，优先使用调度亲和性（容器 / cgroup 场景更准）。"""
    affinity = getattr(os, "sched_getaffinity", None)
    if affinity is not None:
        try:
            return max(1, len(affinity(0)))
        except OSError:  # pragma: no cover
            pass
    return max(1, os.cpu_count() or 1)


def format_bytes(value: float | None) -> str:
    """人类可读的字节数；``None`` → ``n/a``。"""
    if value is None:
        return "n/a"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} PiB"  # pragma: no cover
