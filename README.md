# LogSpecter 🔍

**High-performance, schema-aware log secret scanner & streaming redaction engine for modern cloud infrastructure.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![GitHub Action](https://img.shields.io/badge/GitHub_Action-v1-green)](https://github.com/Jeffy123-zhu/logspecter)
[![Book Demo](https://img.shields.io/badge/Book_a_Demo-15_min_Call-orange)](https://calendly.com/your-calendly-link)

> **Prevent secrets from polluting your SIEM, S3, or CloudWatch.**
> LogSpecter uses Shannon entropy, heuristic noise reduction, and Rust-backed JSON schema parsing to detect and redact API keys and credentials in real time—with a flat memory ceiling.

[⚡ Quickstart](#install) • [📖 Documentation](docs/rules.md) • [📅 Book Architecture Review](https://calendly.com/your-calendly-link)

---

### 💡 High-Level Architecture

```text
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

 CRITICAL  stripe-live-secret-key  ×1  conf 1.00  H 4.86
  examples\app.log:6:91
  examples\app.log:6  sk_l********aJ3s (len=33)

 HIGH  authorization-header-basic  ×1  conf 1.00  H 4.50
Why another secret scannerMost log scanners are a pile of regexes. That fails in production for three reasons, and LogSpecter attacks each one directly.1. Regex alone cannot tell a key from a session tokenA rule like "base64 string of 32+ chars" fires on every pagination cursor, every trace ID, every base64-encoded JSON blob in your logs. LogSpecter runs a second stage on every candidate:CheckWhat it killsShannon entropy + charset-normalised entropylow-diversity strings that merely look longCharset coverageaaaa…, ababab…, and it does not penalise 64-char hex hashesRepeat / sequential runsxxxxxxxx, abcdefgh, 987654321Natural-language likenessSpringBootApplicationConfigurationLoaderBase64Decode-backstrings that decode to readable text or JSON — encoded data, not keysPlaceholder & vendor-doc detectionAKIAIOSFODNN7EXAMPLE, changeme, <your-api-key>, ${VAR}Keyword proximitya 32-char hex blob only counts near key/secret/hmacEvery decision is recorded on the finding, so you can audit why something was reported or dropped:JSON"evidence": ["entropy=5.61/6.00(base64url)", "charset_coverage=0.85",
             "non-linguistic", "keyword-nearby", "also-matched:authorization-header-bearer"]
Entropy thresholds are per rule, not global. Authorization: Basic intentionally disables the decode-back check (Basic auth is base64 text); database URLs relax entropy to catch weak human passwords while relying on the scheme://user:pass@host shape for precision.2. Treating logs as plain text throws away all the contextLogSpecter parses records with orjson (Rust-backed) and recognises the schema it is looking at:AWS CloudTrail — IAM identity, eventName, region, source IP, accountGCP Cloud Logging — principalEmail, methodName, resource, projectKubernetes audit — user, verb, objectRefAzure Activity Log — identity claims, operationName, resultElastic Common Schema, Logback / Log4j2 JSON (including MDC)Nested JSON-inside-a-JSON-string is expanded too, because requestParameters and MDC fields are full of it. You get a precise path (protoPayload.request.credential) instead of a line number, plus the actor and action needed to actually respond to the incident.3. readlines() on a 30 GB log is an OOMThe input layer plans line-aligned byte ranges without reading the file (a few seeks and small tail reads), then hands one range per worker. Compressed files and stdin go through a producer/consumer path with a bounded submission window. Resident memory is a function of chunk size, never of file size:ScanWall timeThroughputMain RSSPeak worker RSS256 MiB, 1 worker20.7 s12.4 MiB/s45 MiB—256 MiB, 8 workers5.1 s49.9 MiB/s42 MiB34 MiB1 GiB, 8 workers18.6 s55.0 MiB/s43 MiB35 MiBSame memory for 1 GiB as for 256 MiB. Measured with GetProcessMemoryInfo / /proc/self/status and reported by --stats — not a claim, an output field. Numbers from logspecter benchmark on 8 cores / Windows / CPython 3.13.How it gets there in pure PythonA naive "for each line, for each rule, run the regex" loop benchmarks at 3.4 MiB/s. Three changes took it to 12.4 MiB/s per core:Bytes end to end. Rules compile to bytes patterns, so there is no per-chunk decode, match offsets are file offsets, and \b/\w get predictable ASCII semantics.Occurrence-driven scanning instead of line iteration. Each rule's regex AST is statically analysed for literals that must appear in any match (\b((?:AKIA|ASIA)[A-Z0-9]{16})\b → AKIA|ASIA). Those literals are located with bytes.find (~3.7 GiB/s) and the regex runs only on the lines that contain them.Anchored matching. The analyser also computes how many bytes of the match may precede the literal. _live_ in (?:sk|rk)_live_… is always at offset 2, so instead of search()-ing a whole line the scanner tries match() at one exact position.Literals are merged into prefix-tree regexes so CPython's INFO first-character-set optimisation applies: an 8 MiB buffer with no match at all is rejected in 2.5 ms.InstallBashpip install logspecter
From source:Bashgit clone [https://github.com/Jeffy123-zhu/logspecter](https://github.com/Jeffy123-zhu/logspecter)
cd logspecter
pip install -e ".[dev]"
Requires Python 3.10+. Runtime dependencies: typer, rich, PyYAML, orjson.UsageBash# a file, a directory, a compressed archive
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
Exit codes: 0 clean, 1 findings at or above --fail-on (default high), 2 bad input.Options worth knowingFlagEffect-j, --workers Nprocesses; default min(8, cpu), 1 disables multiprocessing--chunk-size 4MBthe memory knob — resident data ≈ 2 × chunk × workers--min-entropy 4.5raise the global entropy floor (precision over recall)--min-confidence 0.8drop low-confidence findings--aggressiveenable noisy entropy-only rules (recall over precision)--pack aws --tag githubnarrow the rule set--no-structuredskip JSON parsing entirely; fastest, loses cloud context--decode-base64decode a single layer of base64/base64url printable text and scan it--show-secretsprint plaintext (off by default — reports are redacted)--statsthroughput, memory, and the full noise-reduction breakdownRedacting logsWrite masked copies of plain log files to an output directory (preserving line endings, untouched bytes, and valid JSON records):Bashlogspecter redact /var/log/app.log --output-dir ./sanitized
logspecter redact ./logs/*.log --output-dir ./sanitized --force --min-severity high
Other commandsBashlogspecter rules show aws-secret-access-key  # pattern, entropy gate, prefilter
logspecter rules validate ./my-rules.yaml    # lint custom rules
logspecter selftest                          # 66 positive + 25 negative samples
logspecter benchmark --size 1GB -j 8         # throughput and memory on your box
GitHub ActionYAML# .github/workflows/secret-scan.yml
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  logspecter:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Jeffy123-zhu/logspecter@v1
        with:
          path: logs/
          format: sarif
          output: logspecter.sarif
          fail-on: high          # critical | high | medium | low | info | none
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: logspecter.sarif
pre-commitYAML# .pre-commit-config.yaml
repos:
  - repo: [https://github.com/Jeffy123-zhu/logspecter](https://github.com/Jeffy123-zhu/logspecter)
    rev: v1.0.0   # or any newer tag
    hooks:
      - id: logspecter
How it comparesFeatureLogSpectergitleakstrufflehogdetect-secretsPrimary targetlog files / streams (.gz, stdin)git repos, filesgit repos, filesfiles in a repoJSON path + identity contextyes———Shannon-entropy validationyesyes—yesFlat-memory streaming logsyes———Live credential verificationnonoyes—Git history scanningnoyesyes—SARIF outputyesyes——Baseline / suppress findingsyesyes—yesLanguagePythonGoGoPythonCustom rulesRules are plain YAML. A rule with the same id as a built-in one overrides it, which is the recommended way to retune thresholds for your environment.YAMLversion: 1
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
Bashlogspecter rules validate acme.yaml
logspecter scan ./logs --rules acme.yaml
Library usePythonfrom logspecter import engine
from logspecter.rules import load_ruleset
from logspecter.scanner import ScanOptions

config = engine.ScanConfig(ruleset=load_ruleset(), options=ScanOptions())
result = engine.scan(["/var/log/app.log"], config, workers=4)

for group in result.groups:
    f = group.representative
    print(f.severity.value, f.rule_id, f.context_summary(), f"×{group.occurrences}")

print(result.stats.throughput_mb_s, result.stats.peak_rss_max_process)
Accuracylogspecter selftest runs the bundled corpus with every rule enabled:Detection rate 66/66 · Zero false positives on negative samples 25/2566 positive samples and 25 negative samples drawn from the shapes that actually fool regex-only scanners: UUID request IDs, git SHAs, base64-encoded JSON cursors, camel-case class names, template placeholders, AKIAIOSFODNN7EXAMPLE, ISO timestamps, CSS colours, service-account token paths, and unkeyed SHA-256 digests. Each of these is a distinct rejection reason in the entropy layer, and each is a regression test.--stats reports the funnel on your own data:Noise Reduction: 1,245 regex candidates → 16 blocked by entropy/context layer (1.3%)Design notesPlaintextlogspecter/
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
Reports are redacted by default: masked value plus real length, never plaintext, unless you pass --show-secrets. Baseline files store only fingerprints. The scanner makes no network calls.SecurityIf you find a vulnerability, please open a private security advisory rather than a public issue.ContributingSee CONTRIBUTING.md for the full guide (setup, adding rules, PR flow), and the good first issue label for a place to start.Bashpip install -e ".[dev]"
pytest              # 360 tests
ruff check .
logspecter selftest
LicenseApache-2.0.🏢 Enterprise & SOC 2 ComplianceNeed enterprise-grade log sanitization across your organization? We offer dedicated solutions for growing SaaS & Security teams:Custom Rule Packs: Tailored detectors for proprietary internal API keys & tokens.Centralized Policy Enforcement: Deploy uniform log-redaction policies across all CI/CD pipelines and Kubernetes clusters.SOC 2 / PCI-DSS Audit Artifacts: Automated compliance logging and zero-leak proof reports.📧 Get in touch: Reach out directly at jeffyzhu62@gmail.com or Book a 15-minute intro call to discuss your compliance requirements.
