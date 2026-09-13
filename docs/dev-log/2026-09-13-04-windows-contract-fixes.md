# Dev Log — 2026-09-13 #04：Windows 版契約與健壯性修正（v2.0.0 → v2.1.0）

> 背景：與 H2C VANS server 交叉審查後，發現 Windows 採集器在「與 VANS 資料契約」
> 與「自身健壯性」上有數個問題。本輪只改 Windows 版（Linux/macOS 另行處理）。

## 修正項目

### High
- **OS 版本補 UBR、改語系中立來源。** 原本逐行硬拆 `systeminfo`，「OS 版本」為
  `10.0.26200 N/A 組建 26200`（無 UBR），且鍵名隨系統語系變動（英文版為 `OS Version`），
  導致 VANS 無法判斷累積更新、英文/Server 系統整段抓不到。改新增 `_get_os_version_registry()`
  讀 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` 的 `CurrentBuildNumber`/`UBR`/
  `CurrentMajorVersionNumber`/`CurrentMinorVersionNumber`/`DisplayVersion`/`ProductName`，
  輸出語系穩定的 `OS 版本 = 10.0.<build>.<UBR>` 與明確 `UBR` 欄位。
  （註：Win11 的 ProductName 仍寫「Windows 10」，故不用於區分 10/11，由 build 判定。）
- **`systeminfo` 加 timeout=60。** 網域主機上可能卡住；因主流程未隔離會導致產不出 zip。
- **Defender 病毒碼日期解析修復。** `AntivirusSignatureLastUpdated` 實際是
  `/Date(1789247217000)/`（PS 5.1 ConvertTo-Json），原 `strptime` 靜默失效，
  「病毒碼過期」規則永不觸發。新增 `_parse_ps_date()` 統一解析 epoch/ISO，
  並在收集時正規化為 ISO 日期（顯示與分析都乾淨）。

### Medium
- **列舉 HKU 各使用者 hive。** 原讀 HKCU，UAC 提權後指向管理員 hive，漏掉實際登入者的
  per-user 安裝與 Run 啟動項（持久化熱點）。改列舉 `HKEY_USERS\<SID>`。
- **已安裝程式過濾雜訊。** 跳過 `SystemComponent==1` 與含 `ParentKeyName`（KB 更新）者，
  降低 VANS 弱點比對誤判（實測 129 → 82 筆）。
- **SHA256 一律小寫。** `Get-FileHash` 回大寫，對齊 VANS/VirusTotal。
- **netstat 程序名含 `.exe`。** 改用 `Get-CimInstance Win32_Process` 建 PID→Name，
  與「執行中程序」一致，供 VANS 以名稱關聯。
- **每個收集器以 `_safe()` 包裝。** 單一收集器失敗只回空、不中斷，保證一定產出 zip。
- **XLSX/HTML 失敗不影響 zip；輸出到 exe 所在目錄並印絕對路徑。** 提權後 CWD 常是
  System32；另 `_safe_cell` 移除控制字元避免 openpyxl `IllegalCharacterError`。

### Low
- HTML 標題/meta 的 computer_name/local_ip 加 `html.escape`；輸出檔名 ASCII-safe；
  `_safe_cell` 數值型不誤加公式前綴。

## 驗證（真實端到端）
- 在 Windows 11 build 26200 實跑修改後腳本：`OS 版本 = 10.0.26200.9168`、`UBR = 9168`、
  `OS 顯示版本 = 25H2`；程序雜湊全小寫；已安裝程式 82 筆；checksums 通過。
- 上傳到 VANS v0.3.0（docker + 真實 PostgreSQL）：`parse_os` 讀到 UBR 9168，
  **`missing_os_update` finding = 0**（不再誤報），23 筆軟體對到 CPE，152/152 雜湊小寫。
- 新增 `tests/test_win_pure.py`（19 個純函式測試）、`pytest.ini`；`py_compile` 通過。

## 待辦
- Linux / macOS 版對應修正（軟體區塊 key、LISTEN 正規化、移除對外連線、locale）尚未做。
- VANS 端 `os_baseline.json` 需補 build 26200（Win11 25H2）才有比對對象。
