# Copyright 2026 H2C工作室 甘霖老師
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""H2C 共用主機風險計分（scoring v2）。

本檔在 H2C_PcSecCheck_client（repo 根目錄）與 H2C_VANS
（server/app/correlation/h2c_scoring.py）各放一份，**內容必須完全相同**；
修改時兩邊一起改並遞增 SCORING_VERSION。純函式、只用標準函式庫。

公式（2026-11-25「風險計分改版提案」）：

1. 每筆 finding 基礎分 P：Critical 40 / High 20 / Medium 8 / Low 2 / Info 0。
   有效嚴重度：KEV → 4；EPSS ≥ 0.5 → +1（上限 4）。
   修正：KEV ×1.5、×(1+EPSS)、對外服務 ×1.25、
   類別信心係數（啟發式規則 0.6 / 0.8）、可信度 probable ×0.6。
2. 同類遞減：同一 group（CVE 為同一套軟體，其餘為 category）內
   依 P 由大到小，第 i 筆 × 0.5^(i-1)。同類再多筆，合計不超過最高那筆的 2 倍。
3. R = Σ 類別分 × 資產重要性（low 0.8 / medium 1.0 / high 1.3）。
4. 分數 = round(100 × (1 − e^(−R/50)))。
5. 等級：critical ≥ 80、high ≥ 60、medium ≥ 30、low ≥ 10，其餘 info；
   再以最高有效嚴重度約束——
   下限：有 Critical（含 KEV）至少 high；有 High 至少 medium。
   上限：沒有 Critical 最多 high；最高只到 Medium（或更低）最多 medium。
"""
from __future__ import annotations

import math

SCORING_VERSION = 2

SEVERITY_POINTS = {4: 40.0, 3: 20.0, 2: 8.0, 1: 2.0, 0: 0.0}
DECAY = 0.5
SATURATION_K = 50.0
EPSS_HIGH = 0.5

KEV_MULTIPLIER = 1.5
INTERNET_FACING_MULTIPLIER = 1.25
CRITICALITY_WEIGHT = {"low": 0.8, "medium": 1.0, "high": 1.3}
# finding 自身的可信度（VANS CVE：版本無法證實者為 probable）
CONFIDENCE_WEIGHT = {"probable": 0.6}
# 類別信心係數：啟發式、誤報率較高的規則降權；未列者為 1.0（確定性組態問題）。
# 比對時忽略平台前綴（如 macos_suspicious_process）。
CATEGORY_CONFIDENCE = {
    "suspicious_connection": 0.6,
    "open_port": 0.6,
    "account_anomaly": 0.6,
    "account_inventory": 0.6,
    "process_hash_unknown": 0.6,
    "suspicious_process": 0.8,
    "suspicious_startup": 0.8,
}
_PLATFORM_PREFIXES = ("macos_", "linux_", "win_")

ACTIVE_STATUSES = ("open", "triaged")
LEVELS = ("info", "low", "medium", "high", "critical")
LEVEL_THRESHOLDS = ((80, "critical"), (60, "high"), (30, "medium"), (10, "low"))
_LEVEL_FLOOR = {4: "high", 3: "medium"}
_LEVEL_CAP = {4: "critical", 3: "high"}   # 其餘（≤2）→ medium


def _base_category(category: str | None) -> str:
    c = (category or "").lower()
    for p in _PLATFORM_PREFIXES:
        if c.startswith(p):
            return c[len(p):]
    return c


def effective_severity(severity, kev: bool = False, epss: float | None = None) -> int:
    """KEV → 強制 4；EPSS ≥ 0.5 → +1（上限 4）。"""
    try:
        sev = int(severity or 0)
    except (TypeError, ValueError):
        sev = 0
    sev = max(0, min(4, sev))
    if kev:
        return 4
    if epss is not None and epss >= EPSS_HIGH:
        sev = min(4, sev + 1)
    return sev


def finding_points(f: dict) -> float:
    """單筆 finding 的基礎分 P（已含所有修正係數，未含同類遞減）。"""
    kev = bool(f.get("kev"))
    epss = f.get("epss")
    p = SEVERITY_POINTS[effective_severity(f.get("severity"), kev, epss)]
    if kev:
        p *= KEV_MULTIPLIER
    if epss:
        p *= 1 + float(epss)
    if f.get("internet_facing"):
        p *= INTERNET_FACING_MULTIPLIER
    p *= CATEGORY_CONFIDENCE.get(_base_category(f.get("category")), 1.0)
    p *= CONFIDENCE_WEIGHT.get(f.get("confidence") or "", 1.0)
    return p


def is_active(f: dict) -> bool:
    """未帶 status（client 本機分析）視為 open。"""
    return (f.get("status") or "open") in ACTIVE_STATUSES


def group_key(f: dict) -> str:
    return f.get("group") or _base_category(f.get("category")) or "uncategorized"


def raw_risk(findings: list[dict], criticality: str = "medium") -> tuple[float, dict[str, float]]:
    """回傳 (R, {group: 類別分})；只計 open / triaged。"""
    groups: dict[str, list[float]] = {}
    for f in findings:
        if is_active(f):
            groups.setdefault(group_key(f), []).append(finding_points(f))
    weight = CRITICALITY_WEIGHT.get(criticality or "medium", 1.0)
    parts: dict[str, float] = {}
    for g, pts in groups.items():
        pts.sort(reverse=True)
        parts[g] = sum(p * DECAY ** i for i, p in enumerate(pts)) * weight
    return sum(parts.values()), parts


def score_from_raw(r: float) -> int:
    return int(round(100 * (1 - math.exp(-max(0.0, r) / SATURATION_K))))


def level_for(score: int, max_severity: int) -> str:
    level = "info"
    for threshold, name in LEVEL_THRESHOLDS:
        if score >= threshold:
            level = name
            break
    idx = LEVELS.index(level)
    idx = max(idx, LEVELS.index(_LEVEL_FLOOR.get(max_severity, "info")))
    idx = min(idx, LEVELS.index(_LEVEL_CAP.get(max_severity, "medium")))
    return LEVELS[idx]


def host_score(findings: list[dict], criticality: str = "medium") -> tuple[int, str]:
    """主機風險 (0–100, 等級)。findings 欄位：
    category, severity, status?, kev?, epss?, internet_facing?, confidence?, group?
    """
    active = [f for f in findings if is_active(f)]
    if not active:
        return 0, "info"
    r, _ = raw_risk(active, criticality)
    score = score_from_raw(r)
    max_sev = max(effective_severity(f.get("severity"), bool(f.get("kev")), f.get("epss"))
                  for f in active)
    return score, level_for(score, max_sev)
