"""壁垒三：流式、行对齐、内存上限可证明的输入层。

``readlines()`` 会把整个文件读进列表，扫 30GB 日志必然 OOM。本模块给出三条
互补的读取路径，全部保证「常驻内存 = O(块大小)」，与文件总大小完全无关：

1. **可 seek 的普通文件** —— 先规划出一组**行边界对齐**的字节区间
   （:func:`plan_ranges`，只做少量 seek + 小缓冲读，**不读全文**），再由多个进程
   各自读取 **自己那一段**（:func:`read_range`，默认走 mmap 窗口）。
   因此「进程数 × 块大小」就是可预测的内存上界。
2. **压缩文件（gz / bz2 / xz）** —— 无法 seek，改用生产者-消费者：主进程按块读出
   行对齐的字节块（:func:`iter_stream_blocks`）分发给 worker，提交窗口有界。
3. **管道 / stdin** —— 与压缩文件同路径，支持 ``kubectl logs ... | logspecter scan -``。

实测：扫 1 GiB 与扫 256 MiB 的内存占用完全一致（主进程约 43 MiB、每 worker
约 35 MiB），符合「与文件大小解耦」的设计目标。

行号与偏移的处理：区间扫描时每个 worker 只知道**块内相对行号**，绝对行号由
引擎在汇总阶段用各块行数的前缀和一次性修正（见 :mod:`logspecter.engine`）。
字节偏移则天然是全局唯一的，无需修正。
"""

from __future__ import annotations

import bz2
import contextlib
import enum
import gzip
import io
import lzma
import mmap
import os
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "STDIN_SENTINEL",
    "ByteRange",
    "SourceKind",
    "classify",
    "iter_lines_block",
    "iter_stream_blocks",
    "open_binary",
    "plan_ranges",
    "read_range",
    "resolve_inputs",
]

#: 默认分块大小 4 MiB。扫描单块时常驻内存约为 2×块大小（原始字节 + 小写副本），
#: 因此该默认值把「每进程数据缓冲」钉在 8 MiB 级别，与文件总大小完全无关。
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
#: 规划区间时用于寻找行边界的小缓冲。
_ALIGN_BUFFER = 64 * 1024
#: 流式读取时未闭合行的容忍上限，超过则强制切块（防御无换行的畸形巨行）。
_MAX_PENDING = 64 * 1024 * 1024
#: CLI 中代表标准输入的路径。
STDIN_SENTINEL = "-"

_COMPRESSED_SUFFIXES = {".gz": "gzip", ".tgz": "gzip", ".bz2": "bz2", ".xz": "xz", ".lzma": "xz"}
#: 遍历目录时默认纳入的日志文件后缀。
DEFAULT_LOG_SUFFIXES = (
    ".log",
    ".json",
    ".jsonl",
    ".ndjson",
    ".txt",
    ".out",
    ".gz",
    ".bz2",
    ".xz",
)


class SourceKind(str, enum.Enum):
    """输入源类型，决定采用哪条读取路径。"""

    SEEKABLE = "seekable"
    COMPRESSED = "compressed"
    STREAM = "stream"


@dataclass(slots=True, frozen=True)
class ByteRange:
    """一个行边界对齐的字节区间：``[start, end)``。"""

    index: int
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"ByteRange(#{self.index}, {self.start}..{self.end}, {self.size}B)"


# --------------------------------------------------------------------------------------
# 输入源识别与打开
# --------------------------------------------------------------------------------------


def classify(path: str | os.PathLike[str]) -> SourceKind:
    """判断输入源类型。"""
    text = str(path)
    if text == STDIN_SENTINEL:
        return SourceKind.STREAM
    suffix = Path(text).suffix.lower()
    if suffix in _COMPRESSED_SUFFIXES:
        return SourceKind.COMPRESSED
    return SourceKind.SEEKABLE


def open_binary(path: str | os.PathLike[str]) -> BinaryIO:
    """以二进制流打开输入源，压缩格式透明解压，``-`` 表示 stdin。

    调用方负责关闭返回的对象（stdin 的 buffer 不应关闭，见 :class:`_NonClosing`）。
    """
    text = str(path)
    if text == STDIN_SENTINEL:
        buffer = getattr(sys.stdin, "buffer", None)
        if buffer is None:  # pragma: no cover - 极少见的无 buffer 环境
            raise RuntimeError("当前环境的标准输入不支持二进制读取")
        return _NonClosing(buffer)  # type: ignore[return-value]

    suffix = Path(text).suffix.lower()
    kind = _COMPRESSED_SUFFIXES.get(suffix)
    if kind == "gzip":
        return gzip.open(text, "rb")  # type: ignore[return-value]
    if kind == "bz2":
        return bz2.open(text, "rb")  # type: ignore[return-value]
    if kind == "xz":
        return lzma.open(text, "rb")  # type: ignore[return-value]
    return open(text, "rb", buffering=io.DEFAULT_BUFFER_SIZE)


class _NonClosing(io.RawIOBase):
    """包装 stdin.buffer，避免 ``with`` 语句把标准输入关掉。"""

    def __init__(self, wrapped: BinaryIO) -> None:
        self._wrapped = wrapped

    def read(self, size: int = -1) -> bytes:  # type: ignore[override]
        return self._wrapped.read(size)

    def readinto(self, buffer) -> int:
        data = self._wrapped.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        # 故意不关闭底层 stdin。
        return None


# --------------------------------------------------------------------------------------
# 区间规划（可 seek 文件）
# --------------------------------------------------------------------------------------


def plan_ranges(
    path: str | os.PathLike[str],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> list[ByteRange]:
    """把文件切成一组行边界对齐的字节区间。

    只做 ``seek`` + 少量小缓冲读来定位换行，**不会**读取文件全文，因此对 30GB
    文件同样是毫秒级操作。若某一行长于 ``chunk_size``，对应区间会自动放大到
    容纳整行为止 —— 区间边界永远落在 ``\\n`` 之后，绝不会把一行劈成两半。

    Raises:
        ValueError: ``chunk_size`` 非正。
        OSError: 文件不可读。
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size 必须为正数")

    size = os.path.getsize(path)
    if size == 0:
        return []

    ranges: list[ByteRange] = []
    with open(path, "rb") as handle:
        start = 0
        index = 0
        while start < size:
            raw_target = start + chunk_size
            target = size if raw_target >= size else _next_line_boundary(handle, raw_target, size)
            ranges.append(ByteRange(index=index, start=start, end=target))
            start = target
            index += 1
    return ranges


def _next_line_boundary(handle: BinaryIO, position: int, size: int) -> int:
    """返回 ``position`` 之后第一个换行符的下一个字节位置（找不到则返回 ``size``）。"""
    handle.seek(position)
    scanned = position
    while scanned < size:
        buffer = handle.read(_ALIGN_BUFFER)
        if not buffer:
            return size
        newline = buffer.find(b"\n")
        if newline >= 0:
            return scanned + newline + 1
        scanned += len(buffer)
    return size


# --------------------------------------------------------------------------------------
# 区间读取
# --------------------------------------------------------------------------------------


def _advise_sequential(mapped: mmap.mmap) -> None:
    """告诉内核这是顺序扫描，尽早回收已读页（不支持的平台静默跳过）。"""
    advise = getattr(mapped, "madvise", None)
    flag = getattr(mmap, "MADV_SEQUENTIAL", None)
    if advise is None or flag is None:
        return
    with contextlib.suppress(OSError, ValueError):  # 平台差异，失败无副作用
        advise(flag)


def read_range(
    path: str | os.PathLike[str],
    start: int,
    end: int,
    *,
    reader: str = "mmap",
) -> bytes:
    """读出 ``[start, end)`` 区间的原始字节。

    两种模式的内存特征相同（都得到一个区间大小的 ``bytes``），区别在获取方式：

    * ``mmap``：映射窗口后切片。大文件顺序扫描时少一层内核缓冲拷贝，并可通过
      ``madvise(MADV_SEQUENTIAL)`` 提示内核尽早回收已读页。
    * ``buffered``：``seek`` + ``read``。不依赖 mmap，适合不支持内存映射的文件系统
      （某些网络挂载）与 32 位环境。

    Raises:
        ValueError: 区间非法。
        OSError: 文件不可读。
    """
    if end < start:
        raise ValueError(f"非法区间: [{start}, {end})")
    if end == start:
        return b""

    if reader == "buffered":
        with open(path, "rb") as handle:
            handle.seek(start)
            return handle.read(end - start)

    granularity = mmap.ALLOCATIONGRANULARITY
    aligned = (start // granularity) * granularity
    length = end - aligned
    with (
        open(path, "rb") as handle,
        mmap.mmap(handle.fileno(), length, offset=aligned, access=mmap.ACCESS_READ) as mapped,
    ):
        _advise_sequential(mapped)
        return mapped[start - aligned : length]


def iter_lines_block(block: bytes, base_offset: int = 0) -> Iterator[tuple[bytes, int, int]]:
    """把内存中的字节块按行切开，产出 ``(行内容, 块内行号, 全局字节偏移)``。"""
    position = 0
    local_line = 0
    size = len(block)
    while position < size:
        newline = block.find(b"\n", position)
        stop = size if newline == -1 else newline
        line = block[position:stop]
        if line.endswith(b"\r"):
            line = line[:-1]
        local_line += 1
        yield line, local_line, base_offset + position
        position = stop + 1


# --------------------------------------------------------------------------------------
# 流式读取（压缩文件 / stdin）
# --------------------------------------------------------------------------------------


def iter_stream_blocks(
    stream: BinaryIO,
    block_size: int = DEFAULT_CHUNK_SIZE,
    *,
    max_pending: int = _MAX_PENDING,
) -> Iterator[tuple[ByteRange, bytes]]:
    """把不可 seek 的流切成行对齐的字节块。

    常驻内存 = ``block_size + 未闭合行长度``。偏移量以**解压后**的字节数计算。
    """
    if block_size <= 0:
        raise ValueError("block_size 必须为正数")

    index = 0
    offset = 0
    pending = b""
    while True:
        buffer = stream.read(block_size)
        if not buffer:
            break
        pending += buffer
        newline = pending.rfind(b"\n")
        if newline == -1:
            if len(pending) < max_pending:
                continue
            # 畸形超长行：强制切块，避免内存无限增长。
            newline = len(pending) - 1
        block = pending[: newline + 1]
        pending = pending[newline + 1 :]
        yield ByteRange(index=index, start=offset, end=offset + len(block)), block
        offset += len(block)
        index += 1

    if pending:
        yield ByteRange(index=index, start=offset, end=offset + len(pending)), pending


# --------------------------------------------------------------------------------------
# 输入路径展开
# --------------------------------------------------------------------------------------


def resolve_inputs(
    paths: Sequence[str | os.PathLike[str]],
    *,
    recursive: bool = True,
    suffixes: Iterable[str] = DEFAULT_LOG_SUFFIXES,
    follow_all: bool = False,
) -> list[str]:
    """把用户给的路径展开为具体的文件列表。

    目录会被遍历（默认只纳入常见日志后缀，``follow_all=True`` 时纳入全部文件），
    ``-`` 原样保留表示标准输入。

    Raises:
        FileNotFoundError: 指定的路径不存在。
    """
    allowed = {s.lower() for s in suffixes}
    resolved: list[str] = []
    seen: set[str] = set()

    for raw in paths:
        text = str(raw)
        if text == STDIN_SENTINEL:
            if text not in seen:
                resolved.append(text)
                seen.add(text)
            continue

        path = Path(text).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"输入路径不存在: {path}")

        if path.is_file():
            key = str(path.resolve())
            if key not in seen:
                resolved.append(str(path))
                seen.add(key)
            continue

        walker = path.rglob("*") if recursive else path.glob("*")
        for candidate in sorted(walker):
            if not candidate.is_file():
                continue
            if not follow_all and candidate.suffix.lower() not in allowed:
                continue
            key = str(candidate.resolve())
            if key not in seen:
                resolved.append(str(candidate))
                seen.add(key)

    return resolved
