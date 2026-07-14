# Dev Log — 2026-07-14 #01：netstat/編碼 BUG、AV 誤判、與安全設計討論

> 使用者從報告發現「網路連線」欄位大量空白、「網路服務暴露」程序全變 powershell、
> 「稽核原則」名稱大量空白；並延伸討論打包被 CrowdStrike 隔離、以及匯出 ZIP 的
> 安全設計(XSS / 加密 / 是否給受測單位看)。本篇記錄整個排查與決策過程。
> 對應 commit：`362f03a`、`b6fa293`。

---

## A. netstat 程序名稱 / PID 全錯（`$pid` 唯讀衝突，commit 362f03a）

- **現象**：「網路服務暴露」每一筆「程序」欄都是 `powershell`（80/135/445/1433… 不可能全是）；
  報告 JSON 內每筆連線 PID 都是同一個值（WIN 報告為 6828）。
- **根因**：`get_netstat()` 的 PowerShell 用 `$pid` 當連線 PID 變數，但 `$PID` 是 PowerShell
  **內建唯讀自動變數**（執行掃描的 powershell 自身 PID）。指派 `$pid = ...` 每列都報
  `Cannot overwrite variable PID because it is read-only or constant`（非終止錯誤），
  `$pid` 一直維持 powershell 自身 PID → 查表 `$pidMap[$pid]` 每列都對到 powershell。
- **修正**：變數改名 `$procId`（`H2C_PcSecCheck.py:617-629`）。
- **驗證**：本機實測 `$pid = 4` 報唯讀錯；改 `$procId` 後 `get_netstat()` 取得 324 筆、
  59 個不同 PID、程序名稱多樣（System/svchost/com.docker.backend…）。

## B. 編碼：先 UTF-8、再回歸、最後統一 cp950（commit 362f03a → b6fa293）

### B1. Bug 2（原始）：chcp 65001 機器欄位全空
- **根因**：`run_powershell` 用 `text=True` 未指定編碼 → Python 以地區碼 cp950 解碼。
  但在 **chcp 65001（UTF-8）** 的機器上，`ConvertTo-Json` 的**中文鍵名**（協定/本地位址…）
  以 UTF-8 輸出，被 cp950 解 → 鍵名亂碼、`item.get("協定")` 全落空 → 欄位空。
  只有 ASCII 鍵 `PID` 存活（這也是 A 的 6828 會單獨留下的原因）。稽核原則因鍵名皆中文 → 兩欄全空。
- **首次修正（362f03a）**：兩端強制 UTF-8（`[Console]::OutputEncoding = UTF8` + Python `encoding="utf-8"`）。

### B2. 回歸：稽核原則中文名稱被毀
- **現象**：新報告稽核原則 60 列中 47 列名稱空白，只剩 ASCII 片段（IPSEC driver/IPsec/`/`）。
- **根因**：`auditpol` 是**原生命令**，在繁中系統以 **OEM/cp950** 輸出在地化中文；強制 UTF-8
  解碼把 cp950 中文當 UTF-8 → 無效位元組被丟棄，只剩 ASCII。netstat 因全 ASCII 未受影響。
- **佐證**：新報告存活片段逐列對應 CHU 報告中文名稱的 ASCII 部分（如「其他登入**/**登出事件」→ `/`）；
  以 cp950 原生輸出實測，強制 UTF-8 → `�` 亂碼、統一 cp950 → 中文正確。
- **正解（b6fa293）**：**兩端統一釘 cp950**（`[Console]::OutputEncoding = GetEncoding(950)`
  + Python `encoding="cp950"`）。因原生命令一定吐 cp950、改不了，把 ConvertTo-Json 與 Python
  都對齊 cp950，才能同時兼顧「中文鍵名」與「原生中文輸出」，且不受機器 chcp 影響
  （en-us / chcp 65001 也正確，因介面字串皆繁中、Big5 可表示）。
- **驗證**：`get_netstat()` 324 筆正確；cp950 原生輸出實測中文正確；ConvertTo-Json 中文鍵正確。

## C. 打包被 CrowdStrike 隔離（AV/EDR 誤判）

- **偵測記錄**：`MLSensor-Low` / Machine Learning / Sensor-based ML / `CST0007`，
  **Internal prevalence = Unique、External = Low、Severity = Low**，執行時 `Process blocked / File quarantined`。
- **判定**：**低信心度 ML 誤判**，非行為偵測（Analysis 明載行為 "not observable from command line"）。
  主因是「**重編 → 全新雜湊、零普及度、未簽章**」。舊版能順跑是因那顆雜湊已累積普及度/被信任，
  與「有沒有改 code」無關；任何重編都會重置。
- **對照**：git 前後 exe 僅差 602 bytes（同 PyInstaller），排除「結構更像病毒」。
- **有效緩解**：加 `version.txt`（發行者/版本 metadata）+ 關 UPX → 移除「未簽章又無版本資訊」
  這個 ML 特徵，把低信心分數壓回門檻下，重編後即不再被攔。
- **打包決策**：曾試 `--onedir`（降誤判），但使用者場景是「帶單一 exe 到客戶端當場跑」，
  故**回到 onefile**，保留 version metadata + `upx=False`。
- **長期建議（未落地）**：EV 程式碼簽章 + 固定重複使用同一支（累積普及度）+ 客戶端 Falcon 憑證式白名單。
  本機開發測功能可直接跑 `python H2C_PcSecCheck.py`（不產生被盯上的未簽章 PE）。

---

## D. 安全設計討論（顧問性質；VANS 端由使用者自行處理，client 未改）

> 這幾段是跨 client/VANS 的威脅建模與設計取捨，整理供**升等技術報告**素材。

### D1. Ingest/上傳的既有安全控制（VANS，OWASP 對映）
| 威脅 | 控制 | 位置 | OWASP |
|---|---|---|---|
| 上傳 DoS/超大檔 | 單檔 50MB 上限 | `config.py:41` | A05/A10 |
| Zip bomb | 單成員解壓 64MB 上限 | `parser.py:219` | A10 |
| Zip Slip/路徑穿越 | 只按名讀取成員、不 extractall、不落地 | `parser.py:214` | A01 |
| 內容竄改 | SHA256 checksum | `parser.py` | A08 |
| 格式/版本濫用 | `schema_ver` 驗證（server 支援 1,2） | ingest | A08 |
| 未授權上傳 | Bearer(API) + RBAC + 稽核(Portal) | router | A01/A09 |
| 注入 | `json.loads`（非 eval）+ 全站 CSP | `parser.py`/`main.py:60` | A03 |

### D2. Stored XSS（使用者已修）
- **正名**：不是「JSON injection」。`json.loads` 安全；風險是 report.json 的**值**或整份
  `report.html`（皆攻擊者可控）被塞進 HTML 呈現時的 **stored XSS / HTML injection**。
- **攻擊鏈**：惡意 `.h2cpc.zip`（欄位塞 `<img onerror=…>` 或惡意 report.html）→ 有 token/權限上傳
  → 有權限者「檢視」報告時 payload 在其瀏覽器、以 VANS origin 執行 → 竊 session/提權。
  關鍵風險是「**被入侵端點 → 反打管理主控台**」。
- **正確防禦**：**輸出時依情境編碼**（Jinja2 autoescape、絕不 `|safe` 攻擊者資料）為主線；
  整份 report.html **用 iframe sandbox / 獨立來源 / 僅下載**隔離（無法「編碼」整份文件）；
  CSP 當後備。**輸入端過濾 HTML 不可靠**（黑名單易繞、情境會錯位、且會竄改鑑識證據）。

### D3. 匯出 ZIP 是否加密 / 是否給受測單位看
- **加密 ≠ 修 XSS**：兩者正交。XSS 在 server 解密解析渲染後才發生，攻擊者用同把金鑰自己加密照樣中招。
- **加密的正當目的**：`.h2cpc.zip` 是端點偵察大禮（帳號/軟體清單/開放埠/程序命令列…），
  保護的是**外流時的機密性**。上傳段已有 TLS；價值在**檔案落地**（USB/email/本機）。
- **地雷**：傳統 zip 密碼（ZipCrypto）已破；**在發佈的 exe 裡寫死靜態金鑰＝形同虛設**
  （開源直接看到、閉源逆向也挖得出）。真正原則：**別把祕密放進要散佈的產物**（Kerckhoffs）。
- **開源可安全加密的做法**：**非對稱/混合加密到 VANS 公鑰**（client 只放公鑰、不持解密祕密）。
- **決策（傾向）**：以「透明、開源、唯讀」定位 + PDPA，**不對受測單位鎖**其報告；
  若要防外流，僅對「上傳 VANS 的那份」用公鑰加密，本機保留明文人類報告。

---

## 驗證 (Verification)

- `get_netstat()`（cp950 修正後）：324 筆、59 個不同 PID、程序名稱多樣、欄位完整。
- cp950 原生輸出實測：強制 UTF-8→亂碼；統一 cp950→中文正確；ConvertTo-Json 中文鍵→正確。
- exe：onefile 重編、embedded metadata（CompanyName=H2C / ProductName / FileVersion 2.0.0.0）驗證無損。
- 提醒：auditpol 需系統管理員；本機非提權時走 fallback，實測請以 admin 執行 exe。

## 待辦 / 提醒 (Follow-ups)

- **既有報告無法回溯修正**（當時連原始資料都沒抓到），須以修正後 exe 重新掃描。
- exe 每次重編都是新 Unique 雜湊 → 有 CrowdStrike 的端點仍可能被低信心 ML 攔；長期解為 EV 簽章 + 白名單。
- `version.txt` 的 CompanyName / LegalCopyright 目前為 `H2C` 佔位，日後簽章時應與憑證主體一致。
- 升等技術報告待產出：dev-log(本篇)、報告大綱、標準對應表(16 類 × 行政院健診/CIS/NIST/ISO)、系統架構圖。
- VANS 端 XSS 已由使用者修正；ZIP 加密/簽章屬 VANS 議題,client 不處理。
