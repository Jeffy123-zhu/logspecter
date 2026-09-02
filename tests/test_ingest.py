"""流式输入层测试（壁垒三）：行对齐、区间读取、压缩、路径展开。"""

from __future__ import annotations

import bz2
import gzip
import itertools
import lzma
from pathlib import Path

import pytest

from logspecter import ingest


def _write_lines(path: Path, count: int, width: int = 40) -> bytes:
    payload = b"".join(f"{i:0{width}d}\n".encode() for i in range(count))
    path.write_bytes(payload)
    return payload


class TestPlanRanges:
    def test_every_boundary_follows_a_newline(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        payload = _write_lines(path, 500)
        ranges = ingest.plan_ranges(path, chunk_size=1024)
        assert len(ranges) > 1
        for byte_range in ranges[:-1]:
            assert payload[byte_range.end - 1 : byte_range.end] == b"\n"

    def test_ranges_are_contiguous_and_cover_file(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        payload = _write_lines(path, 300)
        ranges = ingest.plan_ranges(path, chunk_size=777)
        assert ranges[0].start == 0
        assert ranges[-1].end == len(payload)
        for previous, current in itertools.pairwise(ranges):
            assert previous.end == current.start
        assert sum(r.size for r in ranges) == len(payload)

    def test_line_longer_than_chunk_is_not_split(self, tmp_path: Path) -> None:
        path = tmp_path / "long.log"
        payload = b"x" * 5000 + b"\n" + b"y" * 10 + b"\n"
        path.write_bytes(payload)
        ranges = ingest.plan_ranges(path, chunk_size=100)
        assert ranges[0].end == 5001
        assert len(ranges) == 2

    def test_empty_file_has_no_ranges(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.log"
        path.write_bytes(b"")
        assert ingest.plan_ranges(path) == []

    def test_file_without_trailing_newline(self, tmp_path: Path) -> None:
        path = tmp_path / "no-nl.log"
        path.write_bytes(b"abc\ndef")
        ranges = ingest.plan_ranges(path, chunk_size=4)
        assert ranges[-1].end == 7

    def test_invalid_chunk_size(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"a\n")
        with pytest.raises(ValueError, match="chunk_size 必须为正数"):
            ingest.plan_ranges(path, chunk_size=0)


class TestReadRange:
    @pytest.mark.parametrize("reader", ["mmap", "buffered"])
    def test_reassembles_whole_file(self, tmp_path: Path, reader: str) -> None:
        path = tmp_path / "a.log"
        payload = _write_lines(path, 400)
        ranges = ingest.plan_ranges(path, chunk_size=1000)
        joined = b"".join(ingest.read_range(path, r.start, r.end, reader=reader) for r in ranges)
        assert joined == payload

    def test_mmap_handles_unaligned_offsets(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        payload = _write_lines(path, 2000, width=100)
        # 65537 肯定不是 mmap 分配粒度的整数倍，用来验证对齐处理。
        assert 65537 % ingest.mmap.ALLOCATIONGRANULARITY != 0
        assert ingest.read_range(path, 65537, 65637) == payload[65537:65637]

    def test_empty_range(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"abc\n")
        assert ingest.read_range(path, 2, 2) == b""

    def test_invalid_range(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"abc\n")
        with pytest.raises(ValueError, match="非法区间"):
            ingest.read_range(path, 3, 1)


class TestStreamBlocks:
    def test_blocks_are_line_aligned_and_lossless(self) -> None:
        import io

        payload = b"".join(f"line-{i}\n".encode() for i in range(500))
        blocks = list(ingest.iter_stream_blocks(io.BytesIO(payload), block_size=97))
        assert len(blocks) > 1
        for _range, block in blocks[:-1]:
            assert block.endswith(b"\n")
        assert b"".join(block for _r, block in blocks) == payload
        offsets = [r.start for r, _b in blocks]
        assert offsets == sorted(offsets)

    def test_offsets_are_contiguous(self) -> None:
        import io

        payload = b"a\nbb\nccc\n" * 50
        blocks = list(ingest.iter_stream_blocks(io.BytesIO(payload), block_size=16))
        for (prev, _), (nxt, _) in itertools.pairwise(blocks):
            assert prev.end == nxt.start

    def test_giant_line_is_force_split(self) -> None:
        import io

        payload = b"x" * 5000
        blocks = list(
            ingest.iter_stream_blocks(io.BytesIO(payload), block_size=100, max_pending=256)
        )
        assert len(blocks) > 1
        assert b"".join(b for _r, b in blocks) == payload

    def test_invalid_block_size(self) -> None:
        import io

        with pytest.raises(ValueError, match="block_size 必须为正数"):
            list(ingest.iter_stream_blocks(io.BytesIO(b""), block_size=0))


class TestCompression:
    @pytest.mark.parametrize(
        ("suffix", "opener"),
        [(".gz", gzip.open), (".bz2", bz2.open), (".xz", lzma.open)],
    )
    def test_transparent_decompression(self, tmp_path: Path, suffix: str, opener) -> None:
        payload = b"hello\nworld\n"
        path = tmp_path / f"a.log{suffix}"
        with opener(path, "wb") as handle:
            handle.write(payload)
        assert ingest.classify(path) is ingest.SourceKind.COMPRESSED
        with ingest.open_binary(path) as stream:
            assert stream.read() == payload

    def test_plain_file_is_seekable(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"x\n")
        assert ingest.classify(path) is ingest.SourceKind.SEEKABLE

    def test_stdin_sentinel(self) -> None:
        assert ingest.classify("-") is ingest.SourceKind.STREAM


class TestIterLinesBlock:
    def test_yields_offsets_and_strips_crlf(self) -> None:
        block = b"one\r\ntwo\r\nthree"
        rows = list(ingest.iter_lines_block(block, base_offset=100))
        assert [r[0] for r in rows] == [b"one", b"two", b"three"]
        assert [r[1] for r in rows] == [1, 2, 3]
        assert [r[2] for r in rows] == [100, 105, 110]


class TestResolveInputs:
    def test_expands_directory_by_suffix(self, tmp_path: Path) -> None:
        (tmp_path / "a.log").write_bytes(b"x\n")
        (tmp_path / "b.json").write_bytes(b"{}\n")
        (tmp_path / "c.png").write_bytes(b"\x89PNG")
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "d.log").write_bytes(b"y\n")

        resolved = ingest.resolve_inputs([tmp_path])
        names = {Path(p).name for p in resolved}
        assert names == {"a.log", "b.json", "d.log"}

    def test_all_files_includes_everything(self, tmp_path: Path) -> None:
        (tmp_path / "c.png").write_bytes(b"\x89PNG")
        resolved = ingest.resolve_inputs([tmp_path], follow_all=True)
        assert any(p.endswith("c.png") for p in resolved)

    def test_non_recursive(self, tmp_path: Path) -> None:
        (tmp_path / "a.log").write_bytes(b"x\n")
        (tmp_path / "nested").mkdir()
        (tmp_path / "nested" / "d.log").write_bytes(b"y\n")
        resolved = ingest.resolve_inputs([tmp_path], recursive=False)
        assert {Path(p).name for p in resolved} == {"a.log"}

    def test_deduplicates(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"x\n")
        assert len(ingest.resolve_inputs([path, path, tmp_path])) == 1

    def test_stdin_passthrough(self) -> None:
        assert ingest.resolve_inputs(["-"]) == ["-"]

    def test_missing_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="输入路径不存在"):
            ingest.resolve_inputs([tmp_path / "nope"])
