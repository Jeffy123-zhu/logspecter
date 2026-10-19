"""Container runtime log decoders (Docker ``json-file`` with partial-line reassembly)."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from logspecter import structured

__all__ = ["ContainerLine", "iter_docker_lines", "parse_docker_record"]


@dataclass(slots=True, frozen=True)
class ContainerLine:
    """Reassembled application log line from a container runtime log."""

    text: str  # reassembled application line, trailing "\n" stripped
    stream: str  # "stdout" / "stderr"
    time: str | None  # timestamp of the first record
    first_line: int  # 1-based physical line of the first record
    last_line: int  # 1-based physical line of the last record


@dataclass(slots=True)
class _StreamBuffer:
    stream: str
    time: str | None
    first_line: int
    last_line: int
    chunks: list[str] = field(default_factory=list)
    byte_len: int = 0

    def append(self, chunk: str, line_no: int) -> None:
        self.chunks.append(chunk)
        self.byte_len += len(chunk.encode("utf-8"))
        self.last_line = line_no

    def flush(self) -> ContainerLine:
        return ContainerLine(
            text=_strip_newline("".join(self.chunks)),
            stream=self.stream,
            time=self.time,
            first_line=self.first_line,
            last_line=self.last_line,
        )


def _strip_newline(text: str) -> str:
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n") or text.endswith("\r"):
        return text[:-1]
    return text


def _to_text(line: bytes | str) -> str:
    if isinstance(line, bytes):
        return line.decode("utf-8", errors="replace")
    return line


def parse_docker_record(line: bytes | str) -> dict[str, Any] | None:
    """Parse a Docker ``json-file`` log record.

    Returns ``{"log", "stream", "time"}`` for a valid ``json-file`` record and
    ``None`` otherwise (not JSON, not a JSON object, missing ``log``, or ``log``
    is not a string).
    """
    parsed = structured.try_parse(line)
    if not isinstance(parsed, dict):
        return None

    log_value = parsed.get("log")
    if not isinstance(log_value, str):
        return None

    if "stream" in parsed:
        stream_value = parsed["stream"]
        if not isinstance(stream_value, str) or not stream_value:
            return None
        stream = stream_value
    else:
        stream = "stdout"

    time_value = parsed.get("time")
    if time_value is not None and not isinstance(time_value, str):
        return None

    return {
        "log": log_value,
        "stream": stream,
        "time": time_value,
    }


def iter_docker_lines(
    lines: Iterable[bytes | str],
    *,
    max_bytes: int = 1 << 20,
) -> Iterator[ContainerLine]:
    """Iterate over Docker ``json-file`` log records and reassemble partial lines.

    Payloads are buffered per ``stream`` until a record's ``log`` ends with ``\\n``.
    Unterminated buffers are flushed at EOF, or early when a stream buffer exceeds
    ``max_bytes``. Non-container or malformed lines are yielded unchanged with
    ``stream=""`` and ``time=None``.
    """
    buffers: dict[str, _StreamBuffer] = {}

    for line_no, raw_line in enumerate(lines, start=1):
        record = parse_docker_record(raw_line)
        if record is None:
            yield ContainerLine(
                text=_strip_newline(_to_text(raw_line)),
                stream="",
                time=None,
                first_line=line_no,
                last_line=line_no,
            )
            continue

        payload: str = record["log"]
        stream: str = record["stream"]
        record_time: str | None = record["time"]
        is_complete = payload.endswith("\n")

        buf = buffers.get(stream)
        if buf is None and is_complete:
            yield ContainerLine(
                text=_strip_newline(payload),
                stream=stream,
                time=record_time,
                first_line=line_no,
                last_line=line_no,
            )
            continue

        if buf is None:
            buf = _StreamBuffer(
                stream=stream,
                time=record_time,
                first_line=line_no,
                last_line=line_no,
            )
            buffers[stream] = buf

        buf.append(payload, line_no)
        if is_complete or buf.byte_len > max_bytes:
            del buffers[stream]
            yield buf.flush()

    for buf in buffers.values():
        yield buf.flush()
