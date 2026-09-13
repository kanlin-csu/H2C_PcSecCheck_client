# Dev Log — 2026-09-13 #05：待辦事項（審查後尚未執行）

> 背景：2026-09-13 完成 client + VANS 交叉審查。Windows 版已修並發布 v2.1.0（見 #04）。
> 以下為**當時決定先不動**的項目，集中記錄以便後續接續。決策：先 push Windows 版，其餘留待日後。

## A. Linux / macOS 版（`H2C_PcSecCheck_linux.py` / `H2C_PcSecCheck_macos.py`）

審查已確認、尚未修：

- **[High] 移除對外 TCP 連線。** 兩者用 `socket.create_connection(("8.8.8.8",80))` 取本機 IP，
  會完成三向交握，違反「絕不連網」宣稱（Windows 版已改 UDP 不送封包）。
  改用 UDP `connect()` 只查路由，或只用既有的 `ip route get` / `route get default`。
- **[High] 軟體清單 key 對不上 VANS。** Linux 送「已安裝套件」，VANS 只讀「已安裝程式」→
  整份 dpkg/rpm 清單被丟棄，零 CVE 關聯；macOS 根本沒有軟體清單區塊。
  需改 key 為「已安裝程式」並補 名稱/版本/發行者/安裝路徑；macOS 以 pkgutil + brew 產生。
- **[High] 監聽服務 state。** `LISTEN`（ss/lsof）需正規化為 VANS 要求的 `LISTENING`
  （比照已做的 ESTAB→ESTABLISHED），否則監聽服務不寫入 VANS Service 表。
- **[Med] locale 未鎖定。** `_run` 應強制 `LC_ALL=C`，否則 zh_TW 環境下 chage/ufw/systemctl/
  apt/softwareupdate 的英文字串解析全失準。
- **[Med] 系統資訊補「OS 名稱」** 供 VANS `parse_os` 分類 / EOL。
- **[Med] 帳號欄位對齊 VANS**（`所屬群組` 含 sudo/wheel、`是否啟用`、`密碼到期`）；
  macOS `get_local_users` 缺這些欄位。
- **[Med] openpyxl 改可選延遲 import**（最小容器無此套件時整支崩潰）。
- **[Med] macOS `ps` 解析脆弱**（comm 含空白如「Google Chrome Helper」會誤切，漏程序路徑/雜湊）。
- **[Med] 更新檢查連外**（`softwareupdate -l`、`dnf check-update`）；離線保證需改本地快取或預設略過。
- **[Low] base 檔名清理、HTML meta 逃脫、find 逾時明確標註、MRT 缺失文案。**

## B. VANS server（另一 repo `H2C_VANS`）

- **[High] `server/data/os_baseline.json` 補 Windows 11 build 26200（25H2）等新版基準線。**
  目前最新到 22631（2024-10）。無對應 build 時 OS 修補判定為 `unknown`（不誤報，但也無法判修補）。
  數值須用官方 Patch Tuesday 的 `latest_build_revision` / `latest_kb`，不可用單一台機器的 UBR 充當。
  基準線本來就該按月維護（系統已會提示過期）。
- 其餘 v0.3.0 待辦見 VANS repo `docs/plan/2026-09-13-v0.3.0-deploy-verify-plan.md` 與 `ROADMAP.md`
  （per-org HMAC/mTLS、TOTP QR、使用者–組織綁定、Nessus/OpenVAS 實測比較）。

## C. Repo 衛生（client）

- **[Low] `dist/H2C_PcSecCheck.exe`（28MB）提交進 git**，`.git` 已約 85MB。刻意保留供直接下載，
  但每次改版重建會讓歷史膨脹。建議改用 GitHub Releases 掛 exe（此為破壞性歷史重寫，需另行決定，暫不動）。
- **[Low] 三平台腳本高度重複**（報表/打包/風險計算）。因採「單檔可直接複製到目標機執行 / PyInstaller
  打包」的散布模式，抽共用模組會破壞單檔散布，故暫不重構；若日後改散布方式再評估。

## 驗證環境現況（2026-09-13）
- VANS 曾以 `docker compose` 起於 `https://localhost:8443` 做真實 ingest 驗證（見 #04）。
  若已 `docker compose down` 則需重啟；`.env` 為本機產生、未入庫。
