"""壁垒二（下半）：JSON 结构展开。

用 ``orjson``（Rust 实现，零拷贝反序列化）解析日志记录，再把嵌套结构展开为
``(路径, 键名, 值)`` 三元组，路径形如 ``requestParameters.headers.Authorization``
或 ``records[3].payload.token``。

两个刻意的取舍：

* **只展开字符串**。密钥不会是数字或布尔值，跳过它们省掉大量无用遍历。
* **递归解析内嵌 JSON 串**。CloudTrail 的 ``requestParameters``、K8s 审计的
  ``responseObject``、Logback MDC 里经常塞着「JSON 字符串套 JSON 字符串」，
  不递归就会漏掉真正的密钥。

节点数 / 深度都有硬上限，防止被恶意构造的超深日志拖死。
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

try:
    import orjson as _json

    def loads(data: str | bytes) -> Any:
        return _json.loads(data)

    JSON_BACKEND = "orjson"
except ImportError:  # pragma: no cover - 未装 orjson 时退化到标准库
    import json as _json  # type: ignore[no-redef]

    def loads(data: str | bytes) -> Any:
        return _json.loads(data)

    JSON_BACKEND = "json"

__all__ = ["JSON_BACKEND", "JsonLeaf", "iter_string_leaves", "looks_like_json", "try_parse"]

_JSON_OPENERS = (b"{", b"[")


@dataclass(slots=True, frozen=True)
class JsonLeaf:
    """展开后的一个字符串叶子。"""

    #: 完整点分路径，如 ``requestParameters.headers.Authorization``。
    path: str
    #: 最末一段键名（已小写），用于规则的 ``json_keys`` 匹配。
    key: str
    value: str


def looks_like_json(data: bytes | str) -> bool:
    """廉价预判：跳过明显不是 JSON 的行，避免无谓的解析开销。"""
    if isinstance(data, str):
        stripped = data.lstrip()
        return stripped[:1] in ("{", "[")
    stripped = data.lstrip()
    return stripped[:1] in _JSON_OPENERS


def try_parse(data: bytes | str) -> Any | None:
    """解析 JSON，失败返回 ``None``（日志里混着非 JSON 行是常态，不应报错）。"""
    if not looks_like_json(data):
        return None
    try:
        return loads(data)
    except Exception:
        return None


def iter_string_leaves(
    node: Any,
    *,
    max_nodes: int = 4096,
    max_depth: int = 16,
    nested_json: bool = True,
    _path: str = "",
    _depth: int = 0,
    _budget: list[int] | None = None,
) -> Iterator[JsonLeaf]:
    """深度优先展开 JSON，逐个产出字符串叶子。

    Args:
        node: 已解析的 JSON 对象。
        max_nodes: 最多访问多少个节点，超出即停止（防御超大记录）。
        max_depth: 最大递归深度。
        nested_json: 是否递归解析「值本身又是一段 JSON 字符串」的情况。
    """
    budget = _budget if _budget is not None else [max_nodes]
    if budget[0] <= 0 or _depth > max_depth:
        return

    if isinstance(node, dict):
        for key, value in node.items():
            budget[0] -= 1
            if budget[0] <= 0:
                return
            key_str = key if isinstance(key, str) else str(key)
            path = f"{_path}.{key_str}" if _path else key_str
            yield from _walk(
                value,
                path=path,
                key=key_str,
                max_nodes=max_nodes,
                max_depth=max_depth,
                nested_json=nested_json,
                depth=_depth + 1,
                budget=budget,
            )
    elif isinstance(node, list):
        for index, value in enumerate(node):
            budget[0] -= 1
            if budget[0] <= 0:
                return
            path = f"{_path}[{index}]"
            # 数组元素继承父级键名，这样 ``headers[0]`` 仍能命中 headers 相关规则。
            key = _path.rsplit(".", 1)[-1] if _path else ""
            yield from _walk(
                value,
                path=path,
                key=key,
                max_nodes=max_nodes,
                max_depth=max_depth,
                nested_json=nested_json,
                depth=_depth + 1,
                budget=budget,
            )


def _walk(
    value: Any,
    *,
    path: str,
    key: str,
    max_nodes: int,
    max_depth: int,
    nested_json: bool,
    depth: int,
    budget: list[int],
) -> Iterator[JsonLeaf]:
    if isinstance(value, str):
        if value:
            yield JsonLeaf(path=path, key=key.lower(), value=value)
        if nested_json and len(value) > 2 and value.lstrip()[:1] in ("{", "["):
            inner = try_parse(value)
            if inner is not None:
                yield from iter_string_leaves(
                    inner,
                    max_nodes=max_nodes,
                    max_depth=max_depth,
                    nested_json=nested_json,
                    _path=path,
                    _depth=depth,
                    _budget=budget,
                )
    elif isinstance(value, (dict, list)):
        yield from iter_string_leaves(
            value,
            max_nodes=max_nodes,
            max_depth=max_depth,
            nested_json=nested_json,
            _path=path,
            _depth=depth,
            _budget=budget,
        )
    # 数字 / 布尔 / null 不可能是密钥，直接跳过。
