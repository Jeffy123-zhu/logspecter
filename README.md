[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/14441/badge)](https://bestpractices.coreinfrastructure.org/projects/14441)
 
 
 # LogSpecter

[![PyPI version](https://img.shields.io/pypi/v/logspecter.svg)](https://pypi.org/project/logspecter/)
[![Python Version](https://img.shields.io/pypi/pyversions/logspecter.svg)](https://pypi.org/project/logspecter/)
[![CI Status](https://github.com/Jeffy123-zhu/logspecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Jeffy123-zhu/logspecter/actions)
[![License](https://img.shields.io/github/license/Jeffy123-zhu/logspecter.svg)](https://github.com/Jeffy123-zhu/logspecter/blob/main/LICENSE)

**Schema-aware secret scanner for cloud logs.** Regex finds candidates; Shannon entropy and a
heuristic layer decide whether they are real keys; a JSON-structure layer tells you *who* leaked
*what* through *which field*. Streams tens of gigabytes with a flat memory ceiling.

```
$ logspecter scan cloudtrail-2026-08-30.json.gz --stats

  CRITICAL   openai-api-key   AWS IAM User (Alice) → action: AssumeRole
                              → requestParameters.headers.Authorization
                              cloudtrail-2026-08-30.json.gz:81421 @byte 24118904
                              sk-p********kAyS (len=64)   conf 1.00 / H 5.19
```

Not "a suspicious string on line 800". The actual identity, the actual API call, the actual JSON path.

---

## Why another secret scanner

Most log scanners are a pile of regexes. That fails in production for three reasons, and
LogSpecter attacks each one directly.

### 1. Regex alone cannot tell a key from a session token

A rule like "base64 string of 32+ chars" fires on every pagination cursor, every trace ID, every
base64-encoded JSON blob in your logs. LogSpecter runs a second stage on every candidate:

| Check | What it kills |
| --- | --- |
| Shannon entropy + charset-normalised entropy | low-diversity strings that merely *look* long |
| Charset coverage (unique chars ÷ *achievable* unique chars) | `aaaa…`, `ababab…`, and it does **not** penalise 64-char hex hashes |
| Repeat / sequential runs | `xxxxxxxx`, `abcdefgh`, `987654321` |
| Natural-language likeness (bigram + vowel ratio) | `SpringBootApplicationConfigurationLoader` |
| Base64 decode-back | strings that decode to readable text or JSON — encoded *data*, not keys |
| Placeholder & vendor-doc detection | `AKIAIOSFODNN7EXAMPLE`, `changeme`, `<your-api-key>`, `${VAR}` |
| Keyword proximity | a 32-char hex blob only counts near `key`/`secret`/`hmac` |

Every decision is recorded on the finding, so you can audit *why* something was reported or
dropped:

```json
"evidence": ["entropy=5.61/6.00(base64url)", "charset_coverage=0.85",
             "non-linguistic", "keyword-nearby", "also-matched:authorization-header-bearer"]
```

Entropy thresholds are **per rule**, not global. `Authorization: Basic` intentionally disables the
decode-back check (Basic auth *is* base64 text); database URLs relax entropy to catch weak human
passwords while relying on the `scheme://user:pass@host` shape for precision.

### 2. Treating logs as plain text throws away all the context

LogSpecter parses records with [orjson](https://github.com/ijl/orjson) (Rust-backed) and
recognises the schema it is looking at:

* AWS CloudTrail — IAM identity, `eventName`, region, source IP, account
* GCP Cloud Logging — `principalEmail`, `methodName`, resource, project
* Kubernetes audit — user, verb, `objectRef`
* Azure Activity Log — identity claims, `operationName`, result
* Elastic Common Schema, Logback / Log4j2 JSON (including MDC)

Nested JSON-inside-a-JSON-string is expanded too, because `requestParameters` and MDC fields are
full of it. You get a precise path (`protoPayload.request.credential`) instead of a line number,
plus the actor and action needed to actually respond to the incident.

### 3. `readlines()` on a 30 GB log is an OOM

The input layer plans **line-aligned byte ranges** without reading the file (a few seeks and small
tail reads), then hands one range per worker. Compressed files and stdin go through a
producer/consumer path with a bounded submission window. Resident memory is a function of chunk
size, never of file size:

| Scan | Wall time | Throughput | Main RSS | Peak worker RSS |
| --- | --- | --- | --- | --- |
| 256 MiB, 1 worker | 20.7 s | 12.4 MiB/s | 45 MiB | — |
| 256 MiB, 8 workers | 5.1 s | 49.9 MiB/s | 42 MiB | 34 MiB |
| 1 GiB, 8 workers | 18.6 s | 55.0 MiB/s | 43 MiB | 35 MiB |

Same memory for 1 GiB as for 256 MiB. Measured with `GetProcessMemoryInfo` /
`/proc/self/status` and reported by `--stats` — not a claim, an output field.
Numbers from `logspecter benchmark` on 8 cores / Windows / CPython 3.13, scanning a synthetic mix
of CloudTrail records, application logs, and high-entropy-but-harmless noise. Reproduce with
`logspecter benchmark --size 1GB -j 8`; pure-Python throughput is CPU-bound, so expect it to track
your single-core speed times the worker count.

<details>
<summary><b>How it gets there in pure Python</b> (the part that took the most work)</summary>

A naive "for each line, for each rule, run the regex" loop benchmarks at **3.4 MiB/s**. Three
changes took it to 12.4 MiB/s per core:

1. **Bytes end to end.** Rules compile to `bytes` patterns, so there is no per-chunk decode, match
   offsets *are* file offsets, and `\b`/`\w` get predictable ASCII semantics.

2. **Occurrence-driven scanning instead of line iteration.** Each rule's regex AST is statically
   analysed for literals that *must* appear in any match (`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b` →
   `AKIA|ASIA`). Those literals are located with `bytes.find` (~3.7 GiB/s) and the regex runs only
   on the lines that contain them. A monotonic cursor per literal means an absent literal is
   scanned once, not once per line — getting this wrong cost a 50× slowdown before it was fixed.

3. **Anchored matching.** The analyser also computes how many bytes of the match may precede the
   literal. `_live_` in `(?:sk|rk)_live_…` is always at offset 2, so instead of `search()`-ing a
   whole line the scanner tries `match()` at one exact position. This is what removed most of the
   remaining cost: "literal present but regex does not match" is the single most common case in
   real logs (every CloudTrail S3 record contains `"key":`).

Literals are merged into prefix-tree regexes (`key|keystore|kms` → `k(?:ey(?:store)?|ms)`) so
CPython's `INFO` first-character-set optimisation applies: an 8 MiB buffer with no match at all is
rejected in 2.5 ms. That gives the fast path for clean or binary data.

The analyser only emits a literal when it can *prove* it is mandatory; otherwise the rule falls
back to a full scan. `tests/test_prefilter.py` asserts, for every built-in rule, that the prefilter
never rejects an input the regex would have matched, and that anchor windows always contain the
real match offset.

</details>

---

## Install

```bash
pip install logspecter
```

From source:

```bash
git clone https://github.com/logspecter/logspecter
cd logspecter
pip install -e ".[dev]"
```

Requires Python 3.10+. Runtime dependencies: `typer`, `rich`, `PyYAML`, `orjson`.

## Usage

```bash
# a file, a directory, a compressed archive
logspecter scan /var/log/app.log
logspecter scan /var/log/ --recursive
logspecter scan cloudtrail-2026-08-30.json.gz

# a pipe
kubectl logs deploy/api --since=1h | logspecter scan -
aws logs tail /aws/lambda/api --format short | logspecter scan -

# CI gate: fail only on new critical leaks
logspecter scan ./logs --baseline .logspecter-baseline.json --fail-on critical

# machine-readable output
logspecter scan ./logs -f json -o findings.json
logspecter scan ./logs -f csv  -o soc2-evidence.csv
logspecter scan ./logs -f sarif -o results.sarif   # GitHub code scanning
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` bad input.

### Options worth knowing

| Flag | Effect |
| --- | --- |
| `-j, --workers N` | processes; default `min(8, cpu)`, `1` disables multiprocessing |
| `--chunk-size 4MB` | the memory knob — resident data ≈ 2 × chunk × workers |
| `--min-entropy 4.5` | raise the global entropy floor (precision over recall) |
| `--min-confidence 0.8` | drop low-confidence findings |
| `--aggressive` | enable noisy entropy-only rules (recall over precision) |
| `--pack aws --tag github` | narrow the rule set |
| `--no-structured` | skip JSON parsing entirely; fastest, loses cloud context |
| `--show-secrets` | print plaintext (off by default — reports are redacted) |
| `--stats` | throughput, memory, and the full noise-reduction breakdown |

### Other commands

```bash
logspecter rules list                        # 64 built-in rules across 7 packs
logspecter rules show aws-secret-access-key  # pattern, entropy gate, prefilter
logspecter rules validate ./my-rules.yaml    # lint custom rules
logspecter selftest                          # 64 positive + 25 negative samples
logspecter benchmark --size 1GB -j 8         # throughput and memory on your box
```

## Custom rules

Rules are plain YAML. A rule with the same `id` as a built-in one overrides it, which is the
recommended way to retune thresholds for your environment.

```yaml
version: 1
pack: acme

rules:
  - id: acme-internal-token
    name: ACME Internal Service Token
    severity: critical
    confidence: high
    pattern: '\bacme_(?:live|prod)_([A-Za-z0-9]{40})\b'
    capture: 1
    tags: [acme, internal]
    entropy:
      min_entropy: 4.4
      min_normalized: 0.72        # entropy ÷ log2(charset size)
      min_length: 40
      min_charset_coverage: 0.6   # unique chars ÷ achievable unique chars
      reject_encoded_text: true

  - id: acme-mdc-secret
    name: Secret in ACME MDC field
    severity: high
    pattern: '\A\s*(\S{12,4096})\s*\Z'
    capture: 1
    json_keys: [acme_token, acme_signature]   # only applied to these JSON keys
    entropy:
      min_entropy: 3.5
```

```bash
logspecter rules validate acme.yaml
logspecter scan ./logs --rules acme.yaml
```

Full field reference: [`docs/rules.md`](docs/rules.md).

## Library use

```python
from logspecter import engine
from logspecter.rules import load_ruleset
from logspecter.scanner import ScanOptions

config = engine.ScanConfig(ruleset=load_ruleset(), options=ScanOptions())
result = engine.scan(["/var/log/app.log"], config, workers=4)

for group in result.groups:
    f = group.representative
    print(f.severity.value, f.rule_id, f.context_summary(), f"×{group.occurrences}")

print(result.stats.throughput_mb_s, result.stats.peak_rss_max_process)
```

## Accuracy

`logspecter selftest` runs the bundled corpus with **every** rule enabled:

```
检出率 64/64  ·  负样本零误报 25/25
```

64 positive samples (one per rule, generated from a fixed seed — no real credentials in the repo)
and 25 negative samples drawn from the shapes that actually fool regex-only scanners: UUID request
IDs, git SHAs, base64-encoded JSON cursors, camel-case class names, template placeholders,
`AKIAIOSFODNN7EXAMPLE`, ISO timestamps, CSS colours, service-account token paths, and unkeyed
SHA-256 digests. Each of these is a distinct rejection reason in the entropy layer, and each is a
regression test.

`--stats` reports the funnel on your own data, so the numbers are yours rather than ours:

```
降噪  正则候选 1,245 → 熵值/上下文层拦下 16 条（1.3%）
```

## Design notes

```
logspecter/
├── ingest.py      byte-range planning, mmap window reads, gz/bz2/xz/stdin streaming
├── engine.py      chunk scheduling, bounded-window multiprocessing, line-number prefix sums,
│                  fingerprint aggregation
├── prefilter.py   regex AST → mandatory literals + prefix widths, trie merging, screen tree
├── scanner.py     the detection pipeline
├── entropy.py     Shannon entropy and the heuristic gate
├── rules.py       YAML loading, validation, bytes compilation
├── cloud.py       cloud log schema detection and context extraction
├── structured.py  orjson parsing and JSON flattening
├── report/        Rich console, JSON, CSV, SARIF
└── rules/*.yaml   built-in rule packs
```

Two details that are easy to get wrong and are worth knowing about:

**Line numbers under multiprocessing.** Workers only know their offset in the file, so they report
a chunk-local line number plus that chunk's total line count. The parent computes a prefix sum
over chunk line counts and rewrites the findings. No pre-pass over the file, exact `file:line`.

**Report readability.** One leaked key repeated 50 000 times is one finding, not 50 000 rows.
Findings are aggregated by `SHA-256(rule_id ‖ secret)[:16]` with an occurrence count and a few
sample locations. Overlapping rules on the same value collapse to the most specific one
(`openai-api-key` beats `authorization-header-bearer` beats `sensitive-json-key-value`), with the
others preserved in the evidence chain.

## Security

Reports are redacted by default: masked value plus real length, never plaintext, unless you pass
`--show-secrets`. Baseline files store only fingerprints. The scanner makes no network calls.

If you find a vulnerability, please open a private security advisory rather than a public issue.

## Contributing

```bash
pip install -e ".[dev]"
pytest              # 360 tests
ruff check .
logspecter selftest
```

New rules need a positive sample in `src/logspecter/samples.py`; the test suite fails if any rule
lacks one, and `tests/test_prefilter.py` will tell you if your pattern defeats the prefilter.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md).

## License

Apache-2.0.
