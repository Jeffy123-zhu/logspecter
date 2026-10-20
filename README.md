   # LogSpecter
# LogSpecter 🔍

[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/14441/badge)](https://bestpractices.coreinfrastructure.org/projects/14441)
[![PyPI version](https://img.shields.io/pypi/v/logspecter.svg)](https://pypi.org/project/logspecter/)
[![Python Version](https://img.shields.io/pypi/pyversions/logspecter.svg)](https://pypi.org/project/logspecter/)
[![CI Status](https://github.com/Jeffy123-zhu/logspecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Jeffy123-zhu/logspecter/actions)
[![License](https://img.shields.io/github/license/Jeffy123-zhu/logspecter.svg)](https://github.com/Jeffy123-zhu/logspecter/blob/main/LICENSE)
**High-performance, schema-aware log secret scanner & streaming redaction engine for modern cloud infrastructure.**

**Schema-aware secret scanner for cloud logs.** Regex finds candidates; Shannon entropy and a
heuristic layer decide whether they are real keys; a JSON-structure layer tells you *who* leaked
*what* through *which field*. Streams tens of gigabytes with a flat memory ceiling.
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-v1-green)](https://github.com/Jeffy123-zhu/logspecter)
[![Book Demo](https://img.shields.io/badge/Book_a_Demo-15_min_Call-orange)](https://calendly.com/your-calendly-link)

```
$ logspecter scan cloudtrail-2026-08-30.json.gz --stats
> **Prevent secrets from polluting your SIEM, S3, or CloudWatch.**
> LogSpecter uses Shannon entropy, heuristic noise reduction, and Rust-backed JSON schema parsing to detect and redact API keys and credentials in real time—with a flat memory ceiling.

  CRITICAL   openai-api-key   AWS IAM User (Alice) → action: AssumeRole
                              → requestParameters.headers.Authorization
                              cloudtrail-2026-08-30.json.gz:81421 @byte 24118904
                              sk-p********kAyS (len=64)   conf 1.00 / H 5.19
```

Not "a suspicious string on line 800". The actual identity, the actual API call, the actual JSON path.
[⚡ Quickstart](#install) • [📖 Documentation](docs/rules.md) • [📅 Book Architecture Review](https://calendly.com/your-calendly-link)

---

### Real output

`logspecter scan examples/app.log` on the bundled sample (run on Windows, first 17 lines; the CLI UI is currently in Chinese):
### 💡 High-Level Architecture

```text
LogSpecter v0.1.0 · 61 条规则 · JSON 后端 orjson · 分块 4.0 MiB
┌──────────────────────── LogSpecter v0.1.0 扫描摘要 ─────────────────────────┐
│ 唯一泄露  4 条（总出现 4 次）                                               │
│ 等级分布   critical × 2   high × 2                                          │
│   扫描量  1 个来源 / 1 个块 / 2.6 KiB / 18 行                               │
│     性能  0.02s · 0.2 MiB/s · 1 进程                                        │
│ 内存峰值  单进程最高 32.6 MiB（全部进程合计 32.6 MiB）                      │
└─────────────────────────────────────────────────────────────────────────────┘
[ Unsanitized Logs / Streams ]  ──►  ┌───────────────────────────────┐
 (CloudWatch, K8s, App Logs)          │   LogSpecter Engine           │
                                      │  • Schema-aware JSON Context  │
                                      │  • Shannon Entropy Filter     │
                                      │  • Streaming Redact (0-latency)│
                                      └───────────────┬───────────────┘
                                                      │
[ Clean, Redacted Logs ]        ◄─────────────────────┘  (Safe for SIEM / SOC 2 Audits)
⚡ Quick DemoSchema-aware secret scanner for cloud logs. Regex finds candidates; Shannon entropy and a heuristic layer decide whether they are real keys; a JSON-structure layer tells you who leaked what through which field. Streams tens of gigabytes with a flat memory ceiling.Bash$ logspecter scan cloudtrail-2026-08-30.json.gz --stats

  CRITICAL   openai-api-key   AWS IAM User (Alice) → action: AssumeRole
                              → requestParameters.headers.Authorization
                              cloudtrail-2026-08-30.json.gz:81421 @byte 24118904
                              sk-p********kAyS (len=64)   conf 1.00 / H 5.19
Context-Aware Precision: Not "a suspicious string on line 800". The actual identity, the actual API call, the actual JSON path.Real Outputlogspecter scan examples/app.log on the bundled sample (first 17 lines):PlaintextLogSpecter v0.1.0 · 61 rules · JSON backend orjson · Chunk 4.0 MiB
┌──────────────────────── LogSpecter v0.1.0 Scan Summary ─────────────────────────┐
│ Unique leaks   4 (Total occurrences 4)                                          │
│ Severity       critical × 2   high × 2                                          │
│   Scanned      1 source / 1 chunk / 2.6 KiB / 18 lines                          │
│     Perf       0.02s · 0.2 MiB/s · 1 process                                    │
│ Peak Memory    Max single process 32.6 MiB (Total 32.6 MiB)                     │
└─────────────────────────────────────────────────────────────────────────────────┘
CRITICAL  private-key-pem-header  ×1  conf 1.00  H 3.38
 detail
 examples\app.log:13  ----********---- (len=31)
@@ -45,129 +48,13 @@ LogSpecter v0.1.0 · 61 条规则 · JSON 后端 orjson · 分块 4.0 MiB
 examples\app.log:6  sk_l********aJ3s (len=33)

HIGH  authorization-header-basic  ×1  conf 1.00  H 4.50
```

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
Why another secret scannerMost log scanners are a pile of regexes. That fails in production for three reasons, and LogSpecter attacks each one directly.1. Regex alone cannot tell a key from a session tokenA rule like "base64 string of 32+ chars" fires on every pagination cursor, every trace ID, every base64-encoded JSON blob in your logs. LogSpecter runs a second stage on every candidate:CheckWhat it killsShannon entropy + charset-normalised entropylow-diversity strings that merely look longCharset coverageaaaa…, ababab…, and it does not penalise 64-char hex hashesRepeat / sequential runsxxxxxxxx, abcdefgh, 987654321Natural-language likenessSpringBootApplicationConfigurationLoaderBase64Decode-backstrings that decode to readable text or JSON — encoded data, not keysPlaceholder & vendor-doc detectionAKIAIOSFODNN7EXAMPLE, changeme, <your-api-key>, ${VAR}Keyword proximitya 32-char hex blob only counts near key/secret/hmacEvery decision is recorded on the finding, so you can audit why something was reported or dropped:JSON"evidence": ["entropy=5.61/6.00(base64url)", "charset_coverage=0.85",
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
git clone https://github.com/Jeffy123-zhu/logspecter
Entropy thresholds are per rule, not global. Authorization: Basic intentionally disables the decode-back check (Basic auth is base64 text); database URLs relax entropy to catch weak human passwords while relying on the scheme://user:pass@host shape for precision.2. Treating logs as plain text throws away all the contextLogSpecter parses records with orjson (Rust-backed) and recognises the schema it is looking at:AWS CloudTrail — IAM identity, eventName, region, source IP, accountGCP Cloud Logging — principalEmail, methodName, resource, projectKubernetes audit — user, verb, objectRefAzure Activity Log — identity claims, operationName, resultElastic Common Schema, Logback / Log4j2 JSON (including MDC)Nested JSON-inside-a-JSON-string is expanded too, because requestParameters and MDC fields are full of it. You get a precise path (protoPayload.request.credential) instead of a line number, plus the actor and action needed to actually respond to the incident.3. readlines() on a 30 GB log is an OOMThe input layer plans line-aligned byte ranges without reading the file (a few seeks and small tail reads), then hands one range per worker. Compressed files and stdin go through a producer/consumer path with a bounded submission window. Resident memory is a function of chunk size, never of file size:ScanWall timeThroughputMain RSSPeak worker RSS256 MiB, 1 worker20.7 s12.4 MiB/s45 MiB—256 MiB, 8 workers5.1 s49.9 MiB/s42 MiB34 MiB1 GiB, 8 workers18.6 s55.0 MiB/s43 MiB35 MiBSame memory for 1 GiB as for 256 MiB. Measured with GetProcessMemoryInfo / /proc/self/status and reported by --stats — not a claim, an output field. Numbers from logspecter benchmark on 8 cores / Windows / CPython 3.13.How it gets there in pure PythonA naive "for each line, for each rule, run the regex" loop benchmarks at 3.4 MiB/s. Three changes took it to 12.4 MiB/s per core:Bytes end to end. Rules compile to bytes patterns, so there is no per-chunk decode, match offsets are file offsets, and \b/\w get predictable ASCII semantics.Occurrence-driven scanning instead of line iteration. Each rule's regex AST is statically analysed for literals that must appear in any match (\b((?:AKIA|ASIA)[A-Z0-9]{16})\b → AKIA|ASIA). Those literals are located with bytes.find (~3.7 GiB/s) and the regex runs only on the lines that contain them.Anchored matching. The analyser also computes how many bytes of the match may precede the literal. _live_ in (?:sk|rk)_live_… is always at offset 2, so instead of search()-ing a whole line the scanner tries match() at one exact position.Literals are merged into prefix-tree regexes so CPython's INFO first-character-set optimisation applies: an 8 MiB buffer with no match at all is rejected in 2.5 ms.InstallBashpip install logspecter
From source:Bashgit clone [https://github.com/Jeffy123-zhu/logspecter](https://github.com/Jeffy123-zhu/logspecter)
cd logspecter
pip install -e ".[dev]"
```

Requires Python 3.10+. Runtime dependencies: `typer`, `rich`, `PyYAML`, `orjson`.

## Usage

```bash
# a file, a directory, a compressed archive
Requires Python 3.10+. Runtime dependencies: typer, rich, PyYAML, orjson.UsageBash# a file, a directory, a compressed archive
logspecter scan /var/log/app.log
logspecter scan /var/log/ --recursive
logspecter scan cloudtrail-2026-08-30.json.gz
@@ -183,48 +70,13 @@ logspecter scan ./logs --baseline .logspecter-baseline.json --fail-on critical
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
| `--decode-base64` | decode a single layer of base64/base64url printable text and scan it |
| `--show-secrets` | print plaintext (off by default — reports are redacted) |
| `--stats` | throughput, memory, and the full noise-reduction breakdown |

### Redacting logs

Write masked copies of plain log files to an output directory (preserving line endings, untouched bytes, and valid JSON records):

```bash
logspecter redact /var/log/app.log --output-dir ./sanitized
Exit codes: 0 clean, 1 findings at or above --fail-on (default high), 2 bad input.Options worth knowingFlagEffect-j, --workers Nprocesses; default min(8, cpu), 1 disables multiprocessing--chunk-size 4MBthe memory knob — resident data ≈ 2 × chunk × workers--min-entropy 4.5raise the global entropy floor (precision over recall)--min-confidence 0.8drop low-confidence findings--aggressiveenable noisy entropy-only rules (recall over precision)--pack aws --tag githubnarrow the rule set--no-structuredskip JSON parsing entirely; fastest, loses cloud context--decode-base64decode a single layer of base64/base64url printable text and scan it--show-secretsprint plaintext (off by default — reports are redacted)--statsthroughput, memory, and the full noise-reduction breakdownRedacting logsWrite masked copies of plain log files to an output directory (preserving line endings, untouched bytes, and valid JSON records):Bashlogspecter redact /var/log/app.log --output-dir ./sanitized
logspecter redact ./logs/*.log --output-dir ./sanitized --force --min-severity high
```

### Other commands

```bash

logspecter rules show aws-secret-access-key  # pattern, entropy gate, prefilter
Other commandsBashlogspecter rules show aws-secret-access-key  # pattern, entropy gate, prefilter
logspecter rules validate ./my-rules.yaml    # lint custom rules
logspecter selftest                          # 66 positive + 25 negative samples
logspecter benchmark --size 1GB -j 8         # throughput and memory on your box
```

## GitHub Action

```yaml
# .github/workflows/secret-scan.yml
GitHub ActionYAML# .github/workflows/secret-scan.yml
on: [push, pull_request]
permissions:
 contents: read
@@ -244,47 +96,14 @@ jobs:
       if: always()
       with:
         sarif_file: logspecter.sarif
```

Inputs: `path` (default `.`), `format` (`table`/`json`/`csv`/`sarif`), `output`, `fail-on` (default `high`),
`baseline`, `args` (extra `logspecter scan` flags), `python-version`. Output: `exit-code`.

## pre-commit

```yaml
# .pre-commit-config.yaml
pre-commitYAML# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Jeffy123-zhu/logspecter
  - repo: [https://github.com/Jeffy123-zhu/logspecter](https://github.com/Jeffy123-zhu/logspecter)
   rev: v1.0.0   # or any newer tag
   hooks:
     - id: logspecter
```

## How it compares

Only differences we could verify are filled in; `—` means "not checked", not "no".

| | LogSpecter | gitleaks | trufflehog | detect-secrets |
|---|---|---|---|---|
| Primary target | log files / streams (`.gz`, stdin) | git repos, files | git repos, files, many sources | files in a repo |
| JSON path + identity context per finding (e.g. CloudTrail user → field) | yes | — | — | — |
| Shannon-entropy validation | yes | yes | — | yes |
| Flat-memory streaming of multi-GB logs | yes | — | — | — |
| Live credential verification | no | no | yes | — |
| Git history scanning | no | yes | yes | — |
| SARIF output | yes | yes | — | — |
| Baseline / suppress known findings | yes | yes | — | yes |
| Language | Python | Go | Go | Python |

## Custom rules

Rules are plain YAML. A rule with the same `id` as a built-in one overrides it, which is the
recommended way to retune thresholds for your environment.

```yaml
version: 1
How it comparesFeatureLogSpectergitleakstrufflehogdetect-secretsPrimary targetlog files / streams (.gz, stdin)git repos, filesgit repos, filesfiles in a repoJSON path + identity contextyes———Shannon-entropy validationyesyes—yesFlat-memory streaming logsyes———Live credential verificationnonoyes—Git history scanningnoyesyes—SARIF outputyesyes——Baseline / suppress findingsyesyes—yesLanguagePythonGoGoPythonCustom rulesRules are plain YAML. A rule with the same id as a built-in one overrides it, which is the recommended way to retune thresholds for your environment.YAMLversion: 1
pack: acme

rules:
 - id: acme-internal-token
   name: ACME Internal Service Token
@@ -308,19 +127,9 @@ rules:
   json_keys: [acme_token, acme_signature]   # only applied to these JSON keys
   entropy:
     min_entropy: 3.5
```

```bash
logspecter rules validate acme.yaml
Bashlogspecter rules validate acme.yaml
logspecter scan ./logs --rules acme.yaml
```

Full field reference: [`docs/rules.md`](docs/rules.md).

## Library use

```python
from logspecter import engine
Library usePythonfrom logspecter import engine
from logspecter.rules import load_ruleset
from logspecter.scanner import ScanOptions

@@ -332,33 +141,7 @@ for group in result.groups:
   print(f.severity.value, f.rule_id, f.context_summary(), f"×{group.occurrences}")

print(result.stats.throughput_mb_s, result.stats.peak_rss_max_process)
```

## Accuracy

`logspecter selftest` runs the bundled corpus with **every** rule enabled:

```
检出率 66/66  ·  负样本零误报 25/25
```

66 positive samples (one per rule, generated from a fixed seed — no real credentials in the repo)
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
Accuracylogspecter selftest runs the bundled corpus with every rule enabled:Detection rate 66/66 · Zero false positives on negative samples 25/2566 positive samples and 25 negative samples drawn from the shapes that actually fool regex-only scanners: UUID request IDs, git SHAs, base64-encoded JSON cursors, camel-case class names, template placeholders, AKIAIOSFODNN7EXAMPLE, ISO timestamps, CSS colours, service-account token paths, and unkeyed SHA-256 digests. Each of these is a distinct rejection reason in the entropy layer, and each is a regression test.--stats reports the funnel on your own data:Noise Reduction: 1,245 regex candidates → 16 blocked by entropy/context layer (1.3%)Design notesPlaintextlogspecter/
├── ingest.py      byte-range planning, mmap window reads, gz/bz2/xz/stdin streaming
├── engine.py      chunk scheduling, bounded-window multiprocessing, line-number prefix sums,
│                  fingerprint aggregation
@@ -370,58 +153,8 @@ logspecter/
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

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide (setup, adding rules, PR flow), and the
[`good first issue`](https://github.com/Jeffy123-zhu/logspecter/labels/good%20first%20issue) label
for a place to start.

```bash
pip install -e ".[dev]"
Reports are redacted by default: masked value plus real length, never plaintext, unless you pass --show-secrets. Baseline files store only fingerprints. The scanner makes no network calls.SecurityIf you find a vulnerability, please open a private security advisory rather than a public issue.ContributingSee CONTRIBUTING.md for the full guide (setup, adding rules, PR flow), and the good first issue label for a place to start.Bashpip install -e ".[dev]"
pytest              # 360 tests
ruff check .
logspecter selftest
```

New rules need a positive sample in `src/logspecter/samples.py`; the test suite fails if any rule
lacks one, and `tests/test_prefilter.py` will tell you if your pattern defeats the prefilter.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md).

## Contributors

Thanks to everyone who has contributed code, tests and docs:

<a href="https://github.com/CodeByPeace"><img src="https://github.com/CodeByPeace.png?size=60" width="60" height="60" alt="CodeByPeace" /></a>
<a href="https://github.com/st0rm-bless3d"><img src="https://github.com/st0rm-bless3d.png?size=60" width="60" height="60" alt="st0rm-bless3d" /></a>
<a href="https://github.com/Triple-S-Sajjad"><img src="https://github.com/Triple-S-Sajjad.png?size=60" width="60" height="60" alt="Triple-S-Sajjad" /></a>
<a href="https://github.com/cnYui"><img src="https://github.com/cnYui.png?size=60" width="60" height="60" alt="cnYui" /></a>

Want to join them? Pick any open
[`good first issue`](https://github.com/Jeffy123-zhu/logspecter/labels/good%20first%20issue) and
comment on it to claim it.

## License

Apache-2.0.
LicenseApache-2.0.🏢 Enterprise & SOC 2 ComplianceNeed enterprise-grade log sanitization across your organization? We offer dedicated solutions for growing SaaS & Security teams:Custom Rule Packs: Tailored detectors for proprietary internal API keys & tokens.Centralized Policy Enforcement: Deploy uniform log-redaction policies across all CI/CD pipelines and Kubernetes clusters.SOC 2 / PCI-DSS Audit Artifacts: Automated compliance logging and zero-leak proof reports.📧 Get in touch: Reach out directly at jeffyzhu62@gmail.com or Book a 15-minute intro call to discuss your compliance requirements.
