# Copyright 2026 H2C工作室 甘霖老師
# Licensed under the Apache License, Version 2.0 — see LICENSE.
"""H2C_PcSecCheck.py 純函式測試（不需管理員 / 不 shell out）。

只測與外部系統無關的邏輯：日期解析、OS 版本組字、儲存格清理、風險計分。
在 Windows 上執行（winreg 可匯入）。
"""
from __future__ import annotations

import datetime
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import H2C_PcSecCheck as m  # noqa: E402


# ── _parse_ps_date ──
def test_parse_ps_date_epoch_ms():
    # /Date(1789247217000)/ = 2026-09-... （epoch 毫秒）
    dt = m._parse_ps_date("/Date(1789247217000)/")
    assert isinstance(dt, datetime.datetime)
    assert dt.year == 2026


def test_parse_ps_date_epoch_with_offset():
    dt = m._parse_ps_date("/Date(1789247217000+0800)/")
    assert isinstance(dt, datetime.datetime) and dt.year == 2026


@pytest.mark.parametrize("s", [
    "2026-01-15 03:04:05", "2026-01-15T03:04:05", "2026/01/15 03:04:05", "2026-01-15",
])
def test_parse_ps_date_iso_variants(s):
    assert m._parse_ps_date(s).year == 2026


@pytest.mark.parametrize("s", ["", None, "無法取得", "not a date", "/Date(abc)/"])
def test_parse_ps_date_junk_returns_none(s):
    assert m._parse_ps_date(s) is None


# ── _format_os_version ──
def test_format_os_version_with_ubr():
    assert m._format_os_version(10, 0, 26200, 1742) == "10.0.26200.1742"


def test_format_os_version_without_ubr():
    assert m._format_os_version(10, 0, 26200, None) == "10.0.26200"


# ── _sanitize_text / _safe_cell ──
def test_sanitize_text_strips_control_chars():
    assert m._sanitize_text("a\x00b\x07c\x1fd") == "abcd"
    assert m._sanitize_text("正常\t保留換行\n") == "正常\t保留換行\n"  # tab/LF 不移除


def test_safe_cell_formula_injection():
    assert m._safe_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert m._safe_cell("+1") == "'+1"
    assert m._safe_cell("-cmd") == "'-cmd"
    assert m._safe_cell("@x") == "'@x"


def test_safe_cell_numeric_not_prefixed():
    assert m._safe_cell(-1) == -1
    assert m._safe_cell(3.14) == 3.14
    assert m._safe_cell(None) is None


def test_safe_cell_strips_control_chars():
    assert m._safe_cell("ab\x00cd") == "abcd"


# ── calculate_risk ──
def _f(sev):
    return {"category": "x", "severity": sev, "title": "t", "detail": "d"}


def test_calculate_risk_levels():
    # 計分委派共用模組 h2c_scoring（scoring v2），細節見 tests/test_scoring.py
    assert m.calculate_risk([]) == (0, "info")
    # 單一 critical：55 分，等級下限 high
    assert m.calculate_risk([_f(4)]) == (55, "high")
    # 同類兩個 critical：R = 40 + 20 = 60 → 70 分
    assert m.calculate_risk([_f(4), _f(4)]) == (70, "high")


def test_calculate_risk_same_category_does_not_saturate():
    # 舊公式 10 個 critical 即 100；新公式同類遞減，合計不超過最高那筆的 2 倍
    assert m.calculate_risk([_f(4)] * 10) == (80, "critical")
