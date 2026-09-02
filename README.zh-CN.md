# LogSpecter

**面向云端结构化日志的凭据泄露扫描器。** 正则负责初筛，香农熵与启发式层负责判断「像不像真钥匙」，
JSON 结构层负责回答「谁、通过哪个字段、泄露了什么」。扫几十 GB 日志内存不涨。

```
$ logspecter scan cloudtrail-2026-08-30.json.gz --stats

  CRITICAL   openai-api-key   AWS IAM User (Alice) → action: AssumeRole
                              → requestParameters.headers.Authorization
                              cloudtrail-2026-08-30.json.gz:81421 @byte 24118904
                              sk-p********kAyS (len=64)   conf 1.00 / H 5.19
```

不是「第 800 行有个可疑字符串」，而是具体的身份、具体的 API 动作、具体的 JSON 路径。

---

## 为什么还要再写一个

市面上的日志扫描器大多是一堆正则的堆叠。这在生产环境会在三个地方翻车，本项目逐个正面处理。

### 一、光靠正则分不清密钥和会话令牌

「32 位以上 Base64 串」这种规则会把分页游标、trace ID、Base64 编码的 JSON 全部报出来。
LogSpecter 对每个候选跑第二道校验：

| 校验项 | 挡掉什么 |
| --- | --- |
| 香农熵 + 按字符集归一化的熵 | 只是「看起来长」但字符分布很差的串 |
| 字符集覆盖率（唯一字符 ÷ **可达到的**唯一字符数） | `aaaa…`、`ababab…`；同时**不会**冤枉 64 位十六进制哈希 |
| 重复 / 连续序列检测 | `xxxxxxxx`、`abcdefgh`、`987654321` |
| 自然语言相似度（二元组 + 元音比例） | `SpringBootApplicationConfigurationLoader` |
| Base64 解码回读 | 解出来是可读文本或 JSON 的 —— 那是编码后的**数据**，不是密钥 |
| 占位符与厂商文档示例识别 | `AKIAIOSFODNN7EXAMPLE`、`changeme`、`<your-api-key>`、`${VAR}` |
| 关键词邻近 | 32 位十六进制串只有出现在 `key`/`secret`/`hmac` 附近才算 |

每一步判定都会写进命中记录，方便审计「为什么报了」或「为什么没报」：

```json
"evidence": ["entropy=5.61/6.00(base64url)", "charset_coverage=0.85",
             "non-linguistic", "keyword-nearby", "also-matched:authorization-header-bearer"]
```

熵门限是**按规则**配置的，不是一个全局值。`Authorization: Basic` 规则会刻意关闭「解码回读」这条启发式
（Basic 认证的本质就是 base64 文本）；数据库连接串规则把熵门限压得很低以便抓到人设的弱口令，精度则交给
`scheme://user:pass@host` 这个极强的结构特征来保证。

### 二、把日志当纯文本，等于把上下文全部丢掉

用 [orjson](https://github.com/ijl/orjson)（Rust 实现）解析记录，并识别它属于哪种日志 Schema：

* AWS CloudTrail —— IAM 身份、`eventName`、区域、来源 IP、账号
* GCP Cloud Logging —— `principalEmail`、`methodName`、资源、项目
* Kubernetes 审计日志 —— 用户、动作、`objectRef`
* Azure Activity Log —— 身份声明、`operationName`、结果
* Elastic Common Schema、Logback / Log4j2 JSON（含 MDC）

「JSON 字符串里再套 JSON」也会被递归展开 —— `requestParameters` 和 MDC 字段里到处都是这种结构。
最终给出的是精确路径（`protoPayload.request.credential`）加上身份与动作，可以直接进入应急处置流程。

### 三、对 30GB 日志执行 `readlines()` 就是 OOM

输入层先规划出**行边界对齐**的字节区间（只做少量 seek 和尾部小读，**不读全文**），再把区间分给各个进程。
压缩文件和 stdin 走生产者-消费者路径，提交窗口有界。常驻内存只和分块大小相关，与文件大小无关：

| 场景 | 耗时 | 吞吐 | 主进程 RSS | worker 峰值 RSS |
| --- | --- | --- | --- | --- |
| 256 MiB，1 进程 | 20.7 s | 12.4 MiB/s | 45 MiB | — |
| 256 MiB，8 进程 | 5.1 s | 49.9 MiB/s | 42 MiB | 34 MiB |
| 1 GiB，8 进程 | 18.6 s | 55.0 MiB/s | 43 MiB | 35 MiB |

扫 1 GiB 和扫 256 MiB 的内存完全一样。数据来自 `GetProcessMemoryInfo` / `/proc/self/status`，
由 `--stats` 直接输出 —— 这不是宣传口径，是一个输出字段。

<details>
<summary><b>纯 Python 是怎么做到的</b>（这部分花的功夫最多）</summary>

最直觉的「逐行 × 逐规则跑正则」实测只有 **3.4 MiB/s**。三个改动把单核拉到 12.4 MiB/s：

1. **全程走字节。** 规则编译成 `bytes` 正则，于是不需要按块解码，匹配偏移**就是**文件偏移，
   `\b`/`\w` 也恒为 ASCII 语义、行为可预测。

2. **用出现位置驱动，取代逐行遍历。** 静态分析每条正则的 AST，提取「匹配成功时必然出现」的字面量
   （`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b` → `AKIA|ASIA`），用 `bytes.find`（约 3.7 GiB/s）定位这些字面量，
   只在包含它们的那一行上执行正则。每个字面量配一个单调游标，因此**不存在的**字面量整块只扫一次而不是
   每行扫一次 —— 这一点最初写错，代价是 50 倍的性能劣化。

3. **锚定匹配。** 分析器还会算出「字面量之前最多有多少字节仍属于同一次匹配」。
   `(?:sk|rk)_live_…` 中的 `_live_` 前缀宽度恒为 2，于是扫描器不再在整行里 `search()`，
   而是在一个确定位置上 `match()`。这一步砍掉了剩余开销的大部分：真实日志里最高频的情形恰恰是
   「字面量在、但正则不匹配」（每条 CloudTrail 的 S3 记录都含 `"key":`）。

字面量会被合并成前缀树形正则（`key|keystore|kms` → `k(?:ey(?:store)?|ms)`），
这样 CPython 的 `INFO` 首字符集优化才能生效：一个 8 MiB 缓冲区若完全不含目标字面量，2.5 ms 就能否决。
这条快速通道让干净数据和二进制文件几乎零成本。

分析器只在**能证明必现**时才产出字面量，证明不了就退回全量扫描。`tests/test_prefilter.py` 对每一条内置规则
断言两件事：预筛绝不否决正则本来能匹配的输入；锚定区间必然包含真实的匹配起点。

</details>

---

## 安装

```bash
pip install logspecter
```

从源码：

```bash
git clone https://github.com/logspecter/logspecter
cd logspecter
pip install -e ".[dev]"
```

需要 Python 3.10+。运行时依赖：`typer`、`rich`、`PyYAML`、`orjson`。

## 使用

```bash
# 文件、目录、压缩包
logspecter scan /var/log/app.log
logspecter scan /var/log/ --recursive
logspecter scan cloudtrail-2026-08-30.json.gz

# 管道
kubectl logs deploy/api --since=1h | logspecter scan -
aws logs tail /aws/lambda/api --format short | logspecter scan -

# CI 门禁：只对新增的高危泄露报警
logspecter scan ./logs --baseline .logspecter-baseline.json --fail-on critical

# 机器可读输出
logspecter scan ./logs -f json -o findings.json
logspecter scan ./logs -f csv  -o soc2-evidence.csv
logspecter scan ./logs -f sarif -o results.sarif   # GitHub 代码扫描可直接消费
```

退出码：`0` 干净，`1` 存在达到 `--fail-on`（默认 `high`）的命中，`2` 输入或配置有误。

### 常用参数

| 参数 | 作用 |
| --- | --- |
| `-j, --workers N` | 进程数，默认 `min(8, CPU)`，`1` 表示单进程 |
| `--chunk-size 4MB` | 内存旋钮 —— 常驻数据约为 2 × 分块 × 进程数 |
| `--min-entropy 4.5` | 抬高全局熵门限（精度优先） |
| `--min-confidence 0.8` | 丢掉低置信度命中 |
| `--aggressive` | 打开默认关闭的纯高熵规则（召回优先） |
| `--pack aws --tag github` | 收窄规则集 |
| `--no-structured` | 完全跳过 JSON 解析，最快，但失去云端上下文 |
| `--show-secrets` | 输出明文（默认脱敏） |
| `--stats` | 吞吐、内存峰值与完整的降噪漏斗 |

### 其他子命令

```bash
logspecter rules list                        # 7 个规则包、64 条内置规则
logspecter rules show aws-secret-access-key  # 正则、熵门限、预筛条件
logspecter rules validate ./my-rules.yaml    # 校验自定义规则
logspecter selftest                          # 64 条正样本 + 25 条负样本
logspecter benchmark --size 1GB -j 8         # 在你自己的机器上测吞吐与内存
```

## 自定义规则

规则就是普通 YAML。与内置规则同 `id` 会**覆盖**内置规则，这是按环境重新调阈值的推荐方式。

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
      min_normalized: 0.72        # 熵 ÷ log2(字符集规模)
      min_length: 40
      min_charset_coverage: 0.6   # 唯一字符 ÷ 可达到的唯一字符数
      reject_encoded_text: true

  - id: acme-mdc-secret
    name: Secret in ACME MDC field
    severity: high
    pattern: '\A\s*(\S{12,4096})\s*\Z'
    capture: 1
    json_keys: [acme_token, acme_signature]   # 只作用于这些 JSON 键
    entropy:
      min_entropy: 3.5
```

```bash
logspecter rules validate acme.yaml
logspecter scan ./logs --rules acme.yaml
```

完整字段说明见 [`docs/rules.md`](docs/rules.md)。

## 作为库使用

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

## 准确率

`logspecter selftest` 在**全部规则开启**的条件下跑内置语料：

```
检出率 64/64  ·  负样本零误报 25/25
```

64 条正样本（每条规则一条，用固定随机种子生成，仓库里没有任何真实凭据），25 条负样本全部取自真实日志中
最容易骗过纯正则扫描器的形态：UUID 请求 ID、git 提交哈希、Base64 编码的 JSON 游标、驼峰类名、模板占位符、
`AKIAIOSFODNN7EXAMPLE`、ISO 时间戳、CSS 颜色值、服务账号 token 的文件路径、无关键词的 SHA-256 摘要。
每一条对应熵值层里一个独立的拒绝原因，也各自是一个回归测试。

`--stats` 会在你自己的数据上输出这个漏斗，所以数字是你的而不是我们的：

```
降噪  正则候选 1,245 → 熵值/上下文层拦下 16 条（1.3%）
```

## 设计要点

```
logspecter/
├── ingest.py      字节区间规划、mmap 窗口读取、gz/bz2/xz/stdin 流式读取
├── engine.py      分块调度、有界窗口多进程、行号前缀和修正、指纹聚合
├── prefilter.py   正则 AST → 必现字面量 + 前缀宽度、trie 合并、筛选树
├── scanner.py     检测流水线
├── entropy.py     香农熵与启发式校验门
├── rules.py       YAML 加载、校验、字节正则编译
├── cloud.py       云日志 Schema 识别与上下文抽取
├── structured.py  orjson 解析与 JSON 展开
├── report/        Rich 终端、JSON、CSV、SARIF
└── rules/*.yaml   内置规则包
```

两处容易做错、值得单独说明的细节：

**多进程下的行号。** worker 只知道自己在文件中的偏移，因此它汇报「块内相对行号」加上「该块的总行数」。
主进程对各块行数做前缀和，再回写命中的绝对行号。不需要预先通读文件，`file:line` 依然精确。

**报告可读性。** 同一把密钥在日志里出现 5 万次，应该是 1 条结论而不是 5 万行。命中按
`SHA-256(rule_id ‖ secret)[:16]` 聚合，附出现次数与若干定位样本。同一个值上互相包含的多条规则会折叠为
最精确的那一条（`openai-api-key` 优于 `authorization-header-bearer` 优于 `sensitive-json-key-value`），
其余保留在证据链里，信息不丢失。

## 安全

报告默认脱敏：只输出掩码值与真实长度，除非显式指定 `--show-secrets`。基线文件只存指纹。
扫描器不发起任何网络请求。

如果发现安全问题，请通过私有安全公告提交，不要开公开 issue。

## 参与开发

```bash
pip install -e ".[dev]"
pytest              # 360 个测试
ruff check .
logspecter selftest
```

新增规则需要在 `src/logspecter/samples.py` 里补一条正样本 —— 缺少正样本的规则会导致测试失败；
如果你的正则让预筛失效，`tests/test_prefilter.py` 会直接指出来。

## 许可

Apache-2.0。
