"""``logspecter redact`` 子命令测试。"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from typer.testing import CliRunner

from logspecter import engine, redact
from logspecter.cli import EXIT_ERROR, EXIT_OK, app

AWS_KEY = "AKIA" + "4XZQ7MHB3LKPWCVR"
STRIPE_KEY = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc9X2mQpL8"

runner = CliRunner()


def test_redact_plain_log_preserves_other_lines_byte_identical(tmp_path: Path) -> None:
    src = tmp_path / "app.log"
    line1 = b"2026-08-30 INFO boot sequence normal\n"
    line2 = b"2026-08-30 WARN binary payload \xff\xfe\xfd untouched\n"
    line3 = f"2026-08-30 ERROR leaked aws_access_key_id={AWS_KEY}\n".encode()
    line4 = b"2026-08-30 INFO shutdown complete\n"
    src.write_bytes(line1 + line2 + line3 + line4)

    out_dir = tmp_path / "out"
    res = runner.invoke(
        app,
        ["redact", str(src), "--output-dir", str(out_dir), "--workers", "1", "--no-progress"],
    )
    assert res.exit_code == EXIT_OK, res.output

    dst = out_dir / "app.log"
    assert dst.exists()
    out_lines = dst.read_bytes().splitlines(keepends=True)
    assert len(out_lines) == 4
    assert out_lines[0] == line1
    assert out_lines[1] == line2
    assert out_lines[3] == line4
    assert AWS_KEY.encode() not in out_lines[2]
    assert redact.mask(AWS_KEY).encode() in out_lines[2]


def test_redact_multiple_secrets_and_more_than_max_samples(tmp_path: Path) -> None:
    src = tmp_path / "multi.log"
    repeat_count = engine.MAX_SAMPLES_PER_GROUP + 10
    lines = [f"2026-08-30 WARN dual aws={AWS_KEY} stripe={STRIPE_KEY}"]
    lines.extend(f"2026-08-30 INFO line={i} key={AWS_KEY}" for i in range(repeat_count))
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    res = runner.invoke(
        app,
        ["redact", str(src), "--output-dir", str(out_dir), "--workers", "1", "--no-progress"],
    )
    assert res.exit_code == EXIT_OK, res.output

    redacted_text = (out_dir / "multi.log").read_text(encoding="utf-8")
    assert AWS_KEY not in redacted_text
    assert STRIPE_KEY not in redacted_text
    assert redacted_text.count(redact.mask(AWS_KEY)) == repeat_count + 1
    assert redacted_text.count(redact.mask(STRIPE_KEY)) == 1
    assert f"{repeat_count + 2} replacements" in res.output


def test_redact_json_lines_remain_valid_json(tmp_path: Path) -> None:
    custom_rules = tmp_path / "quoted_rule.yaml"
    custom_rules.write_text(
        r"""
version: 1
pack: custom
rules:
  - id: custom-quoted-secret
    name: Custom Secret With Quotes
    severity: high
    confidence: high
    pattern: '\A(tok_quote_[A-Za-z0-9"]+)\Z'
    capture: 1
    json_keys: [quoted]
    entropy:
      enabled: false
""".strip()
        + "\n",
        encoding="utf-8",
    )
    quoted_secret = 'tok_quote_AbCd12"34EfGh56'
    record1 = {
        "ts": "2026-08-30T00:00:00Z",
        "aws": AWS_KEY,
        "nested": json.dumps({"k": STRIPE_KEY}),
    }
    record2 = {"ts": "2026-08-30T00:00:01Z", "quoted": quoted_secret}

    src = tmp_path / "events.jsonl"
    src.write_text(
        json.dumps(record1) + "\n" + json.dumps(record2) + "\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "out"
    res = runner.invoke(
        app,
        [
            "redact",
            str(src),
            "--output-dir",
            str(out_dir),
            "--rules",
            str(custom_rules),
            "--workers",
            "1",
            "--no-progress",
        ],
    )
    assert res.exit_code == EXIT_OK, res.output

    out_lines = (out_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(out_lines) == 2
    parsed1 = json.loads(out_lines[0])
    parsed2 = json.loads(out_lines[1])
    assert parsed1["aws"] == redact.mask(AWS_KEY)
    assert json.loads(parsed1["nested"])["k"] == redact.mask(STRIPE_KEY)
    assert parsed2["quoted"] == redact.mask(quoted_secret)


def test_redact_preserves_crlf_line_endings(tmp_path: Path) -> None:
    src = tmp_path / "crlf.log"
    raw = (
        f"2026-08-30 INFO first line\r\n"
        f"2026-08-30 ERROR key={AWS_KEY}\r\n"
        f"2026-08-30 INFO last line\r\n"
    ).encode()
    src.write_bytes(raw)

    out_dir = tmp_path / "out"
    res = runner.invoke(
        app,
        ["redact", str(src), "--output-dir", str(out_dir), "--workers", "1", "--no-progress"],
    )
    assert res.exit_code == EXIT_OK, res.output

    out_bytes = (out_dir / "crlf.log").read_bytes()
    assert AWS_KEY.encode() not in out_bytes
    for line in out_bytes.splitlines(keepends=True):
        assert line.endswith(b"\r\n")


def test_redact_longer_secret_replaced_first(tmp_path: Path) -> None:
    src = tmp_path / "overlap.log"
    dst = tmp_path / "overlap.out.log"
    short_secret = "SECRET_PREFIX_1234"
    long_secret = "SECRET_PREFIX_1234_EXTENDED_9876"
    src.write_text(f"both={long_secret} short={short_secret}\n", encoding="utf-8")

    count = redact.redact_file(src, dst, [short_secret, long_secret])
    assert count == 2
    output = dst.read_text(encoding="utf-8")
    assert output == f"both={redact.mask(long_secret)} short={redact.mask(short_secret)}\n"


def test_redact_collisions_and_unsupported_inputs(tmp_path: Path) -> None:
    src = tmp_path / "app.log"
    src.write_text(f"key={AWS_KEY}\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    # First run succeeds
    res1 = runner.invoke(
        app,
        ["redact", str(src), "--output-dir", str(out_dir), "--workers", "1", "--no-progress"],
    )
    assert res1.exit_code == EXIT_OK

    # Second run without --force fails on existing output file
    res2 = runner.invoke(
        app,
        ["redact", str(src), "--output-dir", str(out_dir), "--workers", "1", "--no-progress"],
    )
    assert res2.exit_code == EXIT_ERROR
    assert "force" in res2.output.lower()

    # With --force succeeds
    res3 = runner.invoke(
        app,
        [
            "redact",
            str(src),
            "--output-dir",
            str(out_dir),
            "--force",
            "--workers",
            "1",
            "--no-progress",
        ],
    )
    assert res3.exit_code == EXIT_OK

    # Refuses to write over the input file itself even with --force
    res_same = runner.invoke(
        app,
        [
            "redact",
            str(src),
            "--output-dir",
            str(tmp_path),
            "--force",
            "--workers",
            "1",
            "--no-progress",
        ],
    )
    assert res_same.exit_code == EXIT_ERROR

    # Compressed .gz input fails with "not supported yet"
    gz_path = tmp_path / "app.log.gz"
    with gzip.open(gz_path, "wb") as gz:
        gz.write(f"key={AWS_KEY}\n".encode())

    res_gz = runner.invoke(
        app,
        ["redact", str(gz_path), "--output-dir", str(out_dir), "--force"],
    )
    assert res_gz.exit_code == EXIT_ERROR
    assert "not supported yet" in res_gz.output.lower()

    # Stream '-' input fails with "not supported yet"
    res_stdin = runner.invoke(
        app,
        ["redact", "-", "--output-dir", str(out_dir)],
    )
    assert res_stdin.exit_code == EXIT_ERROR
    assert "not supported yet" in res_stdin.output.lower()


def test_redact_respects_rule_selection_flags(tmp_path: Path) -> None:
    src = tmp_path / "selective.log"
    src.write_text(f"aws={AWS_KEY} stripe={STRIPE_KEY}\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    res = runner.invoke(
        app,
        [
            "redact",
            str(src),
            "--output-dir",
            str(out_dir),
            "--exclude-rule",
            "aws-access-key-id",
            "--workers",
            "1",
            "--no-progress",
        ],
    )
    assert res.exit_code == EXIT_OK, res.output
    text = (out_dir / "selective.log").read_text(encoding="utf-8")
    assert AWS_KEY in text
    assert STRIPE_KEY not in text
    assert redact.mask(STRIPE_KEY) in text
