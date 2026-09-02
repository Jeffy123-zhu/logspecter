"""pytest 公共夹具。"""

from __future__ import annotations

import pytest

from logspecter.rules import RuleSet, load_ruleset
from logspecter.scanner import Scanner, ScanOptions


@pytest.fixture(autouse=True)
def stable_console_width(monkeypatch: pytest.MonkeyPatch) -> None:
    """固定终端宽度。

    Rich 会按实际终端宽度排版，窄终端下表格列会被压缩甚至折行，导致断言在不同
    CI runner 上表现不一致。这里统一钉死宽度，让渲染输出可复现。
    """
    monkeypatch.setenv("COLUMNS", "160")
    monkeypatch.setenv("LINES", "50")


@pytest.fixture(scope="session")
def ruleset() -> RuleSet:
    """内置规则集（会话级缓存，避免每个测试重新解析 YAML）。"""
    return load_ruleset()


@pytest.fixture(scope="session")
def full_ruleset(ruleset: RuleSet) -> RuleSet:
    """启用全部规则（含默认关闭的高噪声规则）。"""
    return ruleset.select(enable_all=True)


@pytest.fixture
def scanner(ruleset: RuleSet) -> Scanner:
    return Scanner(ruleset, ScanOptions())


@pytest.fixture
def aggressive_scanner(full_ruleset: RuleSet) -> Scanner:
    return Scanner(full_ruleset, ScanOptions())
