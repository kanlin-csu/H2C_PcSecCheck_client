# Dev Log — 2026-11-25 #06：風險計分改版（scoring v2，與 VANS 共用）

> 背景：pilot 6 台實機的報告包全部是 100 / critical，其中兩台連一個 High 都沒有。
> 舊公式 Critical 40 / High 20 / Medium 10 / Low 3 線性加總、上限 100，10 個 Medium 就滿分。
> 主因是**同一類問題重複計分**：例如一台主機 97 筆 Medium 對外連線 = 970 分。

## 做了什麼

- 新增 `h2c_scoring.py`（純函式、只用標準函式庫），三個平台腳本的 `calculate_risk()` 都委派它。
  VANS 的 `server/app/correlation/h2c_scoring.py` 是**同一份檔案**，修改時兩邊一起改並遞增 `SCORING_VERSION`。
- 公式：基礎分 40/20/8/2/0 → 啟發式類別降權（0.6 / 0.8）→ 同類 0.5 遞減 →
  `100 × (1 − e^(−R/50))` → 等級依最高嚴重度上下限約束。細節見 README「風險評分」。
- `meta.json` 加 `scoring_ver: 2`；報告與 console 的分數標示為「初步評分」。
- Windows 版 `TOOL_VERSION` 2.1.0 → 2.2.0（`version.txt` 維持專案慣例不逐次 bump）。

## 驗證

- `tests/test_scoring.py`：22 項，含 6 台 pilot 主機的去識別化摘要（`tests/fixtures/scoring_pilot_hosts.json`，
  只有 category / severity / 筆數）鎖定新分數：89 critical、79 / 78 / 71 high、51 / 51 medium。
- `tests/test_win_pure.py` 的 `calculate_risk` 測試已改為新期望值；此檔需在 Windows 執行（`winreg`）。
- Linux / macOS 腳本可正常 import 並呼叫 `calculate_risk()`。

## 注意

- `dist/H2C_PcSecCheck.exe` **尚未重建**，需在 Windows 上 `pyinstaller H2C_PcSecCheck.spec --noconfirm`。
  `h2c_scoring` 為一般 import，PyInstaller 會自動打包。
- Linux / macOS 以腳本執行時，`h2c_scoring.py` 需與腳本放在同一目錄。
- `.gitignore` 忽略 `*.json`，fixture 以 `git add -f` 加入。
