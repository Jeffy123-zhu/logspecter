"""JSON 结构展开测试。"""

from __future__ import annotations

import json

import pytest

from logspecter import structured


class TestParsing:
    def test_backend_is_reported(self) -> None:
        assert structured.JSON_BACKEND in {"orjson", "json"}

    @pytest.mark.parametrize("payload", [b'{"a":1}', b"  [1,2]", '{"a":1}', "[1]"])
    def test_looks_like_json_positive(self, payload) -> None:
        assert structured.looks_like_json(payload)

    @pytest.mark.parametrize("payload", [b"2026-08-30 INFO x", b"", "plain text"])
    def test_looks_like_json_negative(self, payload) -> None:
        assert not structured.looks_like_json(payload)

    def test_try_parse_returns_none_for_non_json(self) -> None:
        assert structured.try_parse(b"INFO not json") is None

    def test_try_parse_returns_none_for_broken_json(self) -> None:
        assert structured.try_parse(b'{"a": ') is None

    def test_try_parse_accepts_bytes_and_str(self) -> None:
        assert structured.try_parse(b'{"a":1}') == {"a": 1}
        assert structured.try_parse('{"a":1}') == {"a": 1}


class TestLeafIteration:
    def test_flattens_nested_objects(self) -> None:
        record = {"a": {"b": {"c": "value"}}, "n": 3, "ok": True, "none": None}
        leaves = list(structured.iter_string_leaves(record))
        assert [(leaf.path, leaf.value) for leaf in leaves] == [("a.b.c", "value")]

    def test_array_indices_in_path(self) -> None:
        record = {"items": [{"token": "abc"}, {"token": "def"}]}
        paths = [leaf.path for leaf in structured.iter_string_leaves(record)]
        assert paths == ["items[0].token", "items[1].token"]

    def test_array_element_inherits_parent_key(self) -> None:
        record = {"headers": ["Authorization: Bearer x"]}
        leaves = list(structured.iter_string_leaves(record))
        assert leaves[0].key == "headers"

    def test_key_is_lowercased(self) -> None:
        leaves = list(structured.iter_string_leaves({"Authorization": "x"}))
        assert leaves[0].key == "authorization"
        assert leaves[0].path == "Authorization"

    def test_nested_json_string_is_expanded(self) -> None:
        inner = json.dumps({"secret": "s3cr3t"})
        leaves = {leaf.path: leaf.value for leaf in structured.iter_string_leaves({"body": inner})}
        assert leaves["body.secret"] == "s3cr3t"
        assert leaves["body"] == inner  # 原始字符串本身也会被扫描

    def test_nested_json_can_be_disabled(self) -> None:
        inner = json.dumps({"secret": "s3cr3t"})
        paths = [
            leaf.path for leaf in structured.iter_string_leaves({"body": inner}, nested_json=False)
        ]
        assert paths == ["body"]

    def test_node_budget_is_enforced(self) -> None:
        record = {f"k{i}": f"v{i}" for i in range(100)}
        leaves = list(structured.iter_string_leaves(record, max_nodes=10))
        assert len(leaves) < 100

    def test_depth_limit_is_enforced(self) -> None:
        record: dict = {"leaf": "deep"}
        for _ in range(30):
            record = {"n": record}
        leaves = list(structured.iter_string_leaves(record, max_depth=5))
        assert leaves == []

    def test_top_level_array(self) -> None:
        leaves = list(structured.iter_string_leaves(["a", "b"]))
        assert [leaf.path for leaf in leaves] == ["[0]", "[1]"]

    def test_empty_strings_are_skipped(self) -> None:
        assert list(structured.iter_string_leaves({"a": ""})) == []

    def test_non_string_keys_are_stringified(self) -> None:
        leaves = list(structured.iter_string_leaves({1: "x"}))
        assert leaves[0].path == "1"

    def test_scalar_root_yields_nothing(self) -> None:
        assert list(structured.iter_string_leaves("text")) == []
        assert list(structured.iter_string_leaves(42)) == []
