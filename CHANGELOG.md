# Changelog

格式依 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)。v2.1.0 以前的變更請見 `git log` 與 `docs/dev-log/`。

## [2.2.0] — 2026-11-25

細節見 [dev-log #06](docs/dev-log/2026-11-25-06-unified-risk-scoring.md)；server 端對應 H2C_VANS v0.3.1（ADR-0013）。

### Changed
- 風險計分改為 scoring v2，與 VANS 共用 `h2c_scoring.py`（Windows / Linux / macOS 皆委派）：
  基礎分 40/20/8/2/0、啟發式類別降權（0.6 / 0.8）、同類 0.5 遞減、`100 × (1 − e^(−R/50))` 飽和、
  等級依最高嚴重度上下限約束（沒有 Critical 不會顯示 critical）。pilot 6 台由全部 100/critical
  分散為 1 critical / 3 high / 2 medium。
- 報告與 console 的分數標示為「初步評分」，正式分數以 VANS 為準；`meta.json` 新增 `scoring_ver: 2`。
- 無任何 finding 時等級為 `info`（原為 `low`）。
- Linux / macOS 腳本執行時需與 `h2c_scoring.py` 放在同一目錄。

### Fixed
- 計分不重複套用 EPSS 嚴重度升級（與 VANS 共用模組的修正；client 本機 finding 無 EPSS，不影響分數）。

### Tests
- 新增 `tests/test_scoring.py`（23 項，與 VANS 同一份）與去識別化 pilot fixture；更新 `tests/test_win_pure.py` 計分期望值。

### 待辦
- `dist/H2C_PcSecCheck.exe` 尚未重建，需在 Windows 上執行 `pyinstaller H2C_PcSecCheck.spec --noconfirm` 後提交。
