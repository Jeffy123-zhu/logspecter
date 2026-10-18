"""Tests for logspecter.sysinfo."""

from __future__ import annotations

import pytest

from logspecter.sysinfo import cpu_count, current_rss, format_bytes, peak_rss


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "n/a"),
        (0, "0 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1024**2, "1.0 MiB"),
        (1024**3, "1.0 GiB"),
        (1024**4, "1.0 TiB"),
        (1024**5, "1024.0 TiB"),
    ],
)
def test_format_bytes(value: float | None, expected: str) -> None:
    assert format_bytes(value) == expected


def test_cpu_count_is_positive_int() -> None:
    count = cpu_count()
    assert isinstance(count, int)
    assert count >= 1


@pytest.mark.parametrize("reader", [peak_rss, current_rss])
def test_rss_is_none_or_positive_int(reader) -> None:
    value = reader()
    assert value is None or (isinstance(value, int) and value > 0)
