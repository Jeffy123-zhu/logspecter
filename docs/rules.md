# 规则编写指南

规则是 YAML 文件。用 `--rules PATH` 指定单个文件或整个目录（目录会递归查找 `*.yaml` / `*.yml`）。
**同 `id` 的规则会覆盖内置规则**，这是按自身环境重新调阈值的推荐方式。

```bash
logspecter rules validate ./my-rules.yaml      # 语法 + 预筛健全性检查
logspecter rules show aws-secret-access-key    # 查看某条规则的完整配置
logspecter scan ./logs --rules ./my-rules.yaml
```

## 文件结构

```yaml
version: 1            # 必填，当前只支持 1
pack: acme            # 规则包名，省略时取文件名（用于 --pack 筛选）

defaults:             # 可选：本文件内所有规则的默认值
  severity: high
  entropy:
    min_entropy: 4.0

rules:
  - id: ...
```

`defaults` 与规则条目按字段合并；其中 `entropy` 是**嵌套合并**而非整体替换，因此条目里只写要覆盖的
那几个门限即可。

## 规则字段

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `id` | str | 必填 | 小写字母/数字，以 `-` 分隔，全局唯一 |
| `name` | str | 必填 | 人类可读名称，出现在报告里 |
| `pattern` | str | 必填 | 正则源串。编译为 **bytes** 模式，`\w` `\b` 恒为 ASCII 语义 |
| `capture` | int \| str | `0` | 密钥本体所在的捕获组下标或组名；`0` 表示整个匹配 |
| `severity` | enum | `high` | `critical` / `high` / `medium` / `low` / `info` |
| `confidence` | enum | `medium` | `high` / `medium` / `low`，决定置信度基准分 |
| `description` | str | `""` | 说明文字，会显示在 `rules show` 里 |
| `ignore_case` | bool | `false` | 大小写不敏感 |
| `multiline` | bool | `false` | 启用 `re.MULTILINE` |
| `exclude_pattern` | str | `null` | 捕获值命中该正则则丢弃 |
| `keywords` | list[str] | `[]` | 关键词邻近校验词表（不区分大小写） |
| `keyword_window` | int | `96` | 关键词搜索窗口（匹配位置左右各 N 字符） |
| `require_keyword` | bool | `false` | 为真时窗口内必须出现关键词之一 |
| `json_keys` | list[str] | `[]` | 只在这些 JSON 键（子串匹配）的值上生效 |
| `entropy` | mapping | 见下 | 熵值与启发式门限 |
| `tags` | list[str] | `[]` | 标签，用于 `--tag` 筛选与报告分组 |
| `enabled` | bool | `true` | 是否默认启用（噪声大的规则建议设 `false`） |
| `references` | list[str] | `[]` | 参考链接 |

## `entropy` 门限

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 设为 `false` 表示结构性规则，跳过熵校验（占位符过滤仍生效） |
| `min_entropy` | `3.5` | 香农熵下限，bit/字符 |
| `min_normalized` | `0.55` | 归一化熵下限 = 熵 ÷ log2(字符集规模)，跨字符集可比 |
| `min_length` | `16` | 长度下限 |
| `max_length` | `4096` | 长度上限 |
| `min_charset_coverage` | `0.45` | 唯一字符数 ÷ **可达到的**唯一字符数 |
| `max_repeat_run` | `5` | 最长连续同字符 |
| `max_sequential_run` | `6` | 最长码位递增/递减序列 |
| `max_word_likeness` | `0.62` | 自然语言相似度上限（hex/base32 字符集自动跳过该检查） |
| `reject_encoded_text` | `true` | Base64 解码后是可打印文本则丢弃 |
| `reject_placeholders` | `true` | 拒绝占位符与厂商文档示例凭据 |
| `reject_uuid` | `true` | 拒绝 UUID 形态 |
| `charsets` | `[]` | 字符集白名单，可选 `hex` `base32` `base58` `base62` `base64` `base64url` `printable` |

### 关于 `min_normalized`

理论熵上限随字符集变化：hex 是 4.0 bit，base64 是 6.0 bit，可打印 ASCII 是 6.55 bit。
直接比较绝对熵会系统性偏袒 base64、冤枉 hex，所以门限应尽量写在 `min_normalized` 上。

**注意捕获值的实际字符集。** 例如 `\b(SK[0-9a-fA-F]{32})\b` 捕获的是「`SK` 前缀 + 32 位 hex」，
`detect_charset` 会判定为 base62（上限 5.95 bit），但实际可用符号只有 18 种，
所以归一化熵只有 0.5 左右 —— 门限必须按混合形态设，或者把 `capture` 改成只取 hex 部分。

### 关于 `min_charset_coverage`

用「唯一字符数 ÷ 长度」会系统性冤枉长串：一个 64 字符的 hex 哈希最多只有 16 种字符，比值天然只有 0.25。
把分母换成 `min(长度, 字符集规模)` 之后，该哈希的覆盖率是 1.0，而 `aaaa…` 依然接近 0。

## 预筛与性能

扫描器不会逐行执行你的正则。它先静态分析正则 AST，提取「匹配成功时必然出现」的字面量，用
`bytes.find` 在整块里定位，只在包含该字面量的行上执行正则；如果还能算出字面量在匹配中的前缀宽度，
就进一步用锚定 `match()` 取代整行 `search()`。

`rules show` 会告诉你分析结果：

```
$ logspecter rules show aws-access-key-id
  预筛      A3T|AKIA|ASIA [driver @0..0]

$ logspecter rules show generic-high-entropy-token
  预筛      <full-scan>
```

`driver @0..0` 表示扫描器能在一个确定位置上做锚定匹配（最快）；`@search` 表示只能在整行里 search；
`<full-scan>` 意味着该规则每行都要跑一次正则，是**一个数量级**的成本差别。写规则时因此有三条经验：

1. **给正则一个字面量锚点。** `\b([0-9a-f]{64})\b` 无法预筛；加上厂商前缀、键名或 `require_keyword`
   （关键词会被当作合法的预筛条件）就可以。
2. **把分支写成显式字面量。** `(?:dd_api_key|datadog_api_key)` 的选择性远高于
   `(?:dd|datadog)[_\-]?(?:api|app)[_\-]?key`，因为后者会被 CPython 的公共前缀提取切碎成
   `key` 这种毫无选择性的片段。
3. **让字面量尽量靠前。** 前缀宽度有界（最好为 0）才能启用锚定匹配。
   `[a-z]*TOKEN=(...)` 中的 `*` 会让前缀宽度变成无界，退回整行 search。

实在拿不到字面量的规则，请设 `enabled: false`，由 `--aggressive` 或 `--enable-rule` 显式开启。

## `json_keys`：结构感知专用规则

带 `json_keys` 的规则**只**作用在解析出来的 JSON 值上，且只在末段键名或路径包含指定子串时生效。
这类规则由「敏感键字面量的出现位置」驱动 —— 行内不含任何敏感键名时，一次 JSON 都不会解析。

```yaml
  - id: acme-mdc-secret
    name: Secret in ACME MDC field
    severity: high
    pattern: '\A\s*(\S{12,4096})\s*\Z'   # 匹配整个值
    capture: 1
    json_keys: [acme_token, acme_signature]
    entropy:
      min_entropy: 3.5
      min_charset_coverage: 0.55
```

对于「值本身就是密钥、没有任何前后文特征」的场景（`{"credential": "..."}`），这是唯一可靠的写法。

## 重叠折叠

同一位置上互相包含的多条命中会折叠为最精确的一条，排序依据是
`(severity, -confidence, len(secret))`；被折叠的规则以 `also-matched:<rule_id>` 保留在证据链里。
因此为专用规则设更高的 `severity` / `confidence`，就能保证它压过通用规则。

## 提交新规则的检查清单

1. `logspecter rules validate my-rules.yaml` 通过。
2. 在 `src/logspecter/samples.py` 的 `POSITIVE_SAMPLES` 里加一条正样本
   （**不要用真实凭据**，用 `make_secret()` 生成）。缺少正样本会导致测试失败。
3. 如果这条规则容易误报，同时在 `NEGATIVE_SAMPLES` 里加一条对应的负样本。
4. `pytest` 全绿，`logspecter selftest` 检出率与负样本零误报都保持满分。
5. `logspecter rules show <id>` 确认预筛不是 `<full-scan>`；若无法避免，把 `enabled` 设为 `false`。
