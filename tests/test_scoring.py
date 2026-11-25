# Copyright 2026 H2C工作室 甘霖老師
# Licensed under the Apache License, Version 2.0 — see LICENSE.
"""共用主機風險計分 h2c_scoring（scoring v2）測試。client / VANS 兩邊同一份測試。"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import h2c_scoring as sc  # noqa: E402


FIXTURE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "scoring_pilot_hosts.json")
                     .read_text(encoding="utf-8"))


def _expand(rows):
    return [{"category": c, "severity": s, "title": f"{c}-{i}", "status": "open"}
            for c, s, n in rows for i in range(n)]


def _f(sev, cat="x", **kw):
    return {"category": cat, "severity": sev, "status": "open", **kw}


# ── 6 台 pilot 實機（去識別化）：鎖定 scoring v2 的分數與等級 ──
@pytest.mark.parametrize("host", sorted(FIXTURE["hosts"]))
def test_pilot_hosts_locked(host):
    score, level = sc.host_score(_expand(FIXTURE["hosts"][host]))
    assert [score, level] == FIXTURE["expected"][host]


def test_pilot_hosts_are_discriminated():
    """舊公式 6 台全是 100/critical；新公式需拉開。"""
    levels = {sc.host_score(_expand(rows))[1] for rows in FIXTURE["hosts"].values()}
    assert len(levels) >= 3


# ── 基本性質 ──
def test_empty_and_inactive():
    assert sc.host_score([]) == (0, "info")
    assert sc.host_score([_f(4, status="fixed"), _f(3, status="false_positive")]) == (0, "info")


def test_missing_status_counts_as_open():
    assert sc.host_score([{"category": "smb_risk", "severity": 4}])[0] > 0


def test_same_category_decays_and_is_bounded():
    """同類再多筆，合計不超過最高那筆的 2 倍。"""
    one, _ = sc.raw_risk([_f(2, "audit_policy")])
    many, _ = sc.raw_risk([_f(2, "audit_policy")] * 500)
    assert one < many <= 2 * one


def test_distinct_categories_accumulate_fully():
    a, _ = sc.raw_risk([_f(2, "firewall")])
    b, _ = sc.raw_risk([_f(2, "firewall"), _f(2, "smb_risk")])
    assert b == pytest.approx(2 * a)


def test_cve_group_overrides_category():
    same_sw = [_f(3, "vulnerable_software", group="sw:chrome:119")] * 2
    diff_sw = [_f(3, "vulnerable_software", group="sw:chrome:119"),
               _f(3, "vulnerable_software", group="sw:7zip:19")]
    assert sc.raw_risk(diff_sw)[0] > sc.raw_risk(same_sw)[0]


def test_heuristic_categories_down_weighted():
    assert sc.finding_points(_f(2, "suspicious_connection")) == pytest.approx(8 * 0.6)
    assert sc.finding_points(_f(2, "suspicious_process")) == pytest.approx(8 * 0.8)
    assert sc.finding_points(_f(2, "macos_suspicious_process")) == pytest.approx(8 * 0.8)
    assert sc.finding_points(_f(2, "firewall")) == pytest.approx(8)


def test_probable_and_modifiers():
    assert sc.finding_points(_f(3, confidence="probable")) == pytest.approx(20 * 0.6)
    assert sc.finding_points(_f(3, internet_facing=True)) == pytest.approx(25)
    # KEV → 有效嚴重度 4，再 ×1.5
    assert sc.finding_points(_f(1, kev=True)) == pytest.approx(60)
    # EPSS ≥ 0.5 → +1 級，再 ×(1+EPSS)
    assert sc.finding_points(_f(2, epss=0.5)) == pytest.approx(20 * 1.5)


def test_criticality_scales_raw():
    base, _ = sc.raw_risk([_f(3)], "medium")
    assert sc.raw_risk([_f(3)], "high")[0] == pytest.approx(base * 1.3)
    assert sc.raw_risk([_f(3)], "low")[0] == pytest.approx(base * 0.8)


def test_saturation_monotonic_and_bounded():
    scores = [sc.score_from_raw(r) for r in (0, 10, 50, 100, 500, 10_000)]
    assert scores == sorted(scores) and scores[0] == 0 and scores[-1] == 100
    assert sc.score_from_raw(50) == 63


# ── 等級上下限 ──
def test_no_critical_finding_never_critical():
    many_high = [_f(3, f"cat{i}") for i in range(30)]
    score, level = sc.host_score(many_high)
    assert score >= 80 and level == "high"


def test_medium_only_capped_at_medium():
    score, level = sc.host_score([_f(2, f"cat{i}") for i in range(40)])
    assert score >= 60 and level == "medium"


def test_single_critical_floor_high():
    assert sc.host_score([_f(4, "smb_risk")]) == (55, "high")


def test_single_high_floor_medium():
    assert sc.host_score([_f(3, "hosts_tampering")])[1] == "medium"


def test_kev_floor_high():
    assert sc.host_score([_f(1, "vulnerable_software", kev=True)])[1] in ("high", "critical")


def test_low_only_is_low_or_info():
    assert sc.host_score([_f(1, "account_anomaly")])[1] in ("info", "low")
