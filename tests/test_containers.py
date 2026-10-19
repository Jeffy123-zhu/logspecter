"""Tests for Docker json-file container log decoding and partial-line reassembly."""

from __future__ import annotations

import json

import pytest

from logspecter.containers import ContainerLine, iter_docker_lines, parse_docker_record


def _docker_line(
    log: str,
    *,
    stream: str = "stdout",
    time: str | None = "2026-05-01T10:00:00.000000000Z",
) -> str:
    payload: dict[str, object] = {"log": log, "stream": stream}
    if time is not None:
        payload["time"] = time
    return json.dumps(payload) + "\n"


class TestParseDockerRecord:
    def test_valid_record_str_and_bytes(self) -> None:
        raw = '{"log":"hello world\\n","stream":"stdout","time":"2026-05-01T10:00:00.1Z"}'
        expected = {
            "log": "hello world\n",
            "stream": "stdout",
            "time": "2026-05-01T10:00:00.1Z",
        }
        assert parse_docker_record(raw) == expected
        assert parse_docker_record(raw.encode("utf-8")) == expected

    def test_record_without_time_defaults_to_none(self) -> None:
        raw = '{"log":"msg\\n","stream":"stderr"}'
        assert parse_docker_record(raw) == {
            "log": "msg\n",
            "stream": "stderr",
            "time": None,
        }

    @pytest.mark.parametrize(
        "invalid",
        [
            "plain text log line",
            b"2026-05-01 INFO not json",
            '{"broken": ',
            "[1, 2, 3]",
            '{"stream":"stdout","time":"2026-05-01T10:00:00Z"}',
            '{"log":123,"stream":"stdout"}',
            '{"log":null,"stream":"stdout"}',
            '{"log":["a"],"stream":"stdout"}',
            '{"log":"ok\\n","stream":123}',
            '{"log":"ok\\n","stream":""}',
            '{"log":"ok\\n","stream":"stdout","time":999}',
        ],
    )
    def test_invalid_or_non_docker_records_return_none(self, invalid: bytes | str) -> None:
        assert parse_docker_record(invalid) is None


class TestIterDockerLines:
    def test_single_complete_record(self) -> None:
        lines = [
            _docker_line(
                "Authorization: Bearer token\n",
                stream="stdout",
                time="2026-05-01T10:00:00.100000000Z",
            )
        ]
        result = list(iter_docker_lines(lines))
        assert result == [
            ContainerLine(
                text="Authorization: Bearer token",
                stream="stdout",
                time="2026-05-01T10:00:00.100000000Z",
                first_line=1,
                last_line=1,
            )
        ]

    def test_three_partial_records_reassembled(self) -> None:
        lines = [
            _docker_line("part-1:", stream="stdout", time="2026-05-01T10:00:00.1Z"),
            _docker_line("part-2:", stream="stdout", time="2026-05-01T10:00:00.2Z"),
            _docker_line("part-3\n", stream="stdout", time="2026-05-01T10:00:00.3Z"),
        ]
        result = list(iter_docker_lines(lines))
        assert result == [
            ContainerLine(
                text="part-1:part-2:part-3",
                stream="stdout",
                time="2026-05-01T10:00:00.1Z",
                first_line=1,
                last_line=3,
            )
        ]

    def test_interleaved_stdout_and_stderr_partials(self) -> None:
        lines = [
            _docker_line("out-A-", stream="stdout", time="2026-05-01T10:00:01Z"),
            _docker_line("err-1-", stream="stderr", time="2026-05-01T10:00:02Z"),
            _docker_line("out-B\n", stream="stdout", time="2026-05-01T10:00:03Z"),
            _docker_line("err-2\n", stream="stderr", time="2026-05-01T10:00:04Z"),
        ]
        result = list(iter_docker_lines(lines))
        assert result == [
            ContainerLine(
                text="out-A-out-B",
                stream="stdout",
                time="2026-05-01T10:00:01Z",
                first_line=1,
                last_line=3,
            ),
            ContainerLine(
                text="err-1-err-2",
                stream="stderr",
                time="2026-05-01T10:00:02Z",
                first_line=2,
                last_line=4,
            ),
        ]

    def test_unterminated_record_flushed_at_eof(self) -> None:
        lines = [
            _docker_line("unterminated-", stream="stderr", time="2026-05-01T10:00:01Z"),
            _docker_line("tail", stream="stderr", time="2026-05-01T10:00:02Z"),
        ]
        result = list(iter_docker_lines(lines))
        assert result == [
            ContainerLine(
                text="unterminated-tail",
                stream="stderr",
                time="2026-05-01T10:00:01Z",
                first_line=1,
                last_line=2,
            )
        ]

    def test_max_bytes_forces_early_flush(self) -> None:
        lines = [
            _docker_line("aaaaaa", stream="stdout", time="2026-05-01T10:00:01Z"),
            _docker_line("bbbbbb", stream="stdout", time="2026-05-01T10:00:02Z"),
            _docker_line("ccc\n", stream="stdout", time="2026-05-01T10:00:03Z"),
        ]
        result = list(iter_docker_lines(lines, max_bytes=10))
        assert result == [
            ContainerLine(
                text="aaaaaabbbbbb",
                stream="stdout",
                time="2026-05-01T10:00:01Z",
                first_line=1,
                last_line=2,
            ),
            ContainerLine(
                text="ccc",
                stream="stdout",
                time="2026-05-01T10:00:03Z",
                first_line=3,
                last_line=3,
            ),
        ]

    def test_malformed_and_non_container_lines_pass_through_unchanged(self) -> None:
        lines: list[bytes | str] = [
            "2026-05-01 INFO starting worker\n",
            b'{"event":"login","user":"alice"}\n',
            b'{"broken json\r\n',
            _docker_line("container line\n", stream="stdout", time="2026-05-01T10:00:05Z").encode(
                "utf-8"
            ),
        ]
        result = list(iter_docker_lines(lines))
        assert result == [
            ContainerLine(
                text="2026-05-01 INFO starting worker",
                stream="",
                time=None,
                first_line=1,
                last_line=1,
            ),
            ContainerLine(
                text='{"event":"login","user":"alice"}',
                stream="",
                time=None,
                first_line=2,
                last_line=2,
            ),
            ContainerLine(
                text='{"broken json',
                stream="",
                time=None,
                first_line=3,
                last_line=3,
            ),
            ContainerLine(
                text="container line",
                stream="stdout",
                time="2026-05-01T10:00:05Z",
                first_line=4,
                last_line=4,
            ),
        ]

    def test_generator_streams_lazily(self) -> None:
        consumed = 0

        def source():
            nonlocal consumed
            for idx in range(5):
                consumed += 1
                yield _docker_line(f"line-{idx}\n", time=f"t{idx}")

        gen = iter_docker_lines(source())
        assert consumed == 0
        first = next(gen)
        assert consumed == 1
        assert first.text == "line-0"
