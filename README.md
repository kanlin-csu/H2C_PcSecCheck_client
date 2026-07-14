# H2C_PcSecCheck

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0078d4.svg)](README.md)

PC / Linux / macOS 主機資安健診工具。在受測電腦執行後，自動收集系統資訊並產生標準化報告包（`.h2cpc.zip`）。

> **開發單位**：H2C 工作室  
> **開發者**：甘霖老師

---

## 資安聲明（IT 人員請詳閱）

> [!IMPORTANT]
> **本工具僅執行唯讀分析，絕不修改任何系統設定。**

### 行為保證

| 項目 | 說明 |
|------|------|
| **讀取，不修改** | 本工具僅讀取系統設定、登錄機碼與事件記錄，**不寫入、不刪除、不變更**任何系統設定 |
| **無網路傳輸** | 工具執行期間**不建立任何對外網路連線**，不上傳任何資料至遠端伺服器 |
| **無後門程式** | 不包含任何遠端控制、Shell 反連或資料外洩元件 |
| **報告留存本機** | 產生的 `.h2cpc.zip` 僅儲存於**執行目錄下**，由受測單位自行保管與繳交 |
| **開放原始碼** | 完整原始碼公開於本儲存庫，可自行審閱或重新編譯，無任何隱藏邏輯 |

### 執行權限需求

Windows 版需以**系統管理員（Administrator）** 身份執行，Linux / macOS 版建議以 **root / sudo** 執行，原因如下：

| 收集項目 | 需要管理員的原因 |
|---------|---------------|
| Windows 稽核原則（auditpol） | `auditpol /get` 指令需要提升權限才能讀取 |
| Windows 系統登錄機碼 | `HKLM\SYSTEM\CurrentControlSet` 等機碼一般使用者無讀取權限 |
| Windows 程序命令列 | 讀取其他使用者的程序命令列（`Win32_Process.CommandLine`）需要管理員 |
| Windows 密碼原則 | `net accounts` 及 WMI 安全設定需提升權限 |
| Windows 防火牆 / SMB 設定 | PowerShell `Get-NetFirewallProfile`、`Get-SmbServerConfiguration` 需管理員 |
| Linux 使用者 / 密碼期限 | `chage`、`lastlog`、`/etc/shadow` 相關資訊需 root 才能完整讀取 |
| Linux 稽核 / 防火牆 / 程序資訊 | `auditctl`、`iptables`、`/proc/PID/exe` 等資料需 root 才能完整取得 |
| macOS 安全設定 / 程序資訊 | FileVault、Firewall、audit、`lsof`、部分程序路徑與系統設定需 sudo 才能完整取得 |

> **若以一般使用者執行**，部分項目將顯示為空值或收集不完整，影響健診報告的準確性。

---

## 功能

### Windows 版

| 類別 | 收集內容 |
|------|---------|
| 系統資訊 | hostname、IP、OS 版本、硬體規格 |
| Windows Defender | 版本、啟用狀態、即時保護、病毒碼更新日期 |
| 已安裝更新 | HotFixID、安裝日期 |
| 已安裝程式 | 名稱、版本、發行者、安裝路徑 |
| 使用者帳號 | 帳號、啟用狀態、所屬群組、上次登入、密碼到期 |
| 密碼原則 | 最短長度、最長期限、鎖定閾值 |
| 網路設定 | 網卡、IP、子網遮罩、DNS |
| 啟動項目 | Registry Run/RunOnce（HKLM/HKCU）、啟動資料夾、啟用/停用狀態 |
| 執行中程序 | 名稱、PID、父 PID、執行路徑、命令列、記憶體 |
| 程序雜湊 | 各執行檔 SHA256 |
| 網路連線 | netstat（TCP/UDP、狀態、程序對應） |
| 防火牆狀態 | 各設定檔啟用狀態、預設入/出站規則 |
| SMB 設定 | SMBv1 / SMBv2 啟用狀態 |
| 共用資料夾 | 名稱、路徑、類型 |
| 稽核原則 | 登入事件、物件存取、特殊登入等稽核設定 |
| Hosts 檔案 | 非標準項目偵測 |

### Linux 版

| 類別 | 收集內容 |
|------|---------|
| 系統資訊 | hostname、IP、OS release、Kernel、CPU、記憶體、uptime |
| 修補 / 更新狀態 | `apt` / `dnf` / `yum` 可更新套件數與前幾筆套件 |
| 防毒 / 端點防護 | ClamAV、rkhunter、chkrootkit、AIDE、Tripwire、Lynis 偵測 |
| 套件清單 | `dpkg -l` 或 `rpm -qa` 已安裝套件 |
| 帳號與權限 | `/etc/passwd`、一般帳號、系統帳號、shell、最後登入、密碼期限 |
| 特權帳號 | UID 0、sudo / wheel / admin 群組 |
| 密碼 / PAM 原則 | `/etc/login.defs`、`/etc/security/pwquality.conf` |
| SSH 安全設定 | root login、password authentication、empty password、MaxAuthTries |
| 防火牆 | ufw、firewalld、iptables 狀態 |
| 對外監聽服務 | `ss` / `netstat` 監聽與連線狀態 |
| 啟動服務與排程 | systemd enabled services、crontab、`/etc/cron.*`、`/etc/rc.local` |
| 稽核與日誌 | auditd、auditctl 規則檢查 |
| Kernel Hardening | sysctl 安全參數，如 ASLR、ip_forward、SYN cookies |
| SELinux / AppArmor | MAC 保護機制狀態 |
| 檔案權限風險 | SUID、SGID、全域可寫目錄 |
| 網路分享 / 對外目錄 | Samba、NFS exports |
| 容器環境 | Docker / Podman 執行中容器 |
| 程序情資素材 | 程序 SHA256、套件來源、deleted binary、平台情資比對欄位 |
| Hosts 檔案 | 非標準項目偵測 |

### macOS 版

| 類別 | 收集內容 |
|------|---------|
| 系統資訊 | hostname、IP、macOS 版本、Kernel、硬體型號、CPU、記憶體 |
| 更新狀態 | `softwareupdate` 可用系統更新、Homebrew 可更新套件 |
| 端點防護 | XProtect、Gatekeeper、MRT、常見第三方 EDR / AV 偵測 |
| FileVault | 磁碟加密狀態 |
| SIP | System Integrity Protection 狀態 |
| 防火牆 | Application Firewall、Stealth Mode、PF 狀態 |
| 帳號與權限 | 本機使用者、UID、admin 群組、shell、home 目錄 |
| 密碼原則 | `pwpolicy` 帳號政策 |
| SSH 安全設定 | root login、password authentication、empty password |
| 啟動項目 | LaunchDaemons、LaunchAgents、User LaunchAgents |
| 稽核原則 | `/etc/security/audit_control`、auditd 狀態 |
| Kernel Hardening | macOS sysctl 安全參數 |
| 網路分享 / 對外目錄 | macOS sharing、NFS exports |
| 程序情資素材 | 程序 SHA256、pkgutil 套件來源、平台情資比對欄位 |
| Hosts 檔案 | 非標準項目偵測 |

### 風險自動分析（Findings）

| 規則類別 | 觸發條件 | 嚴重度 |
|---------|---------|--------|
| `suspicious_process` | 程序執行於 Temp/Downloads/Public、命令列含 `-enc`/`IEX`、Office 衍生 PowerShell | High / Critical |
| `suspicious_startup` | 啟動項目路徑可疑、命令含惡意關鍵字 | High / Critical |
| `suspicious_connection` | ESTABLISHED 連線至惡意 Port（4444/1337 等）、敏感 Port 對外監聽（445/3389/5985） | Low / Medium / High |
| `account_anomaly` | 密碼永不到期、Administrator 帳號啟用、180 天未登入 | Low / Medium |
| `password_policy` | 最短密碼長度 < 8、密碼永不過期、鎖定閾值 = 0 | Medium |
| `endpoint_protection` | Defender 防毒或即時保護停用（有第三方防毒時降低嚴重度） | Low / Critical |
| `defender_outdated` | 病毒碼超過 7 / 30 天未更新 | Medium / High |
| `firewall` | 任一設定檔防火牆停用 | High |
| `smb` | SMBv1 啟用 | High |
| `shared_folder` | 存在非系統預設共用資料夾 | Medium |
| `audit_policy` | 登入 / 物件存取 / 特殊登入未啟用稽核 | Medium |
| `hosts_file` | Hosts 檔案含非標準條目 | Medium |

風險評分：severity 4 → 40 分 / 3 → 20 分 / 2 → 10 分 / 1 → 3 分，上限 100。  
對應等級：low（< 20）/ medium（20–49）/ high（50–79）/ critical（≥ 80）

---

## 輸出格式

執行後產生 `{hostname}_{ip}_{timestamp}.h2cpc.zip`：

```
{hostname}_{ip}_{timestamp}.h2cpc.zip
├── meta.json                               ← 版本、risk_score、risk_level、checksums
├── {hostname}_{ip}_{timestamp}.report.json    ← 完整原始資料（16 大類）
├── {hostname}_{ip}_{timestamp}.findings.json  ← 風險清單
├── {hostname}_{ip}_{timestamp}.report.html    ← 自含式互動報告（可離線開啟）
└── {hostname}_{ip}_{timestamp}.report.xlsx    ← 表格版報告（首頁為風險摘要）
```

---

## 使用方式

### Windows 版

> **直接使用**：下載 [`dist/H2C_PcSecCheck.exe`](dist/H2C_PcSecCheck.exe)，不需安裝 Python。  
> **本工具僅讀取資料，不修改系統，不對外傳輸任何資訊。**

1. 以**系統管理員**身份執行 `H2C_PcSecCheck.exe`（UAC 視窗會自動彈出）
2. 等待約 2–5 分鐘（程序雜湊計算較耗時）
3. 執行完成後按 Enter 關閉視窗
4. 將產生的 `.h2cpc.zip` 繳交給資安健診人員

```
[1/16]  取得系統資訊
[2/16]  取得 Windows Defender 資訊
[3/16]  取得已安裝更新
[4/16]  取得已安裝程式
[5/16]  取得使用者帳號
[6/16]  取得密碼原則
[7/16]  取得網路設定
[8/16]  取得啟動項目
[9/16]  取得執行中程序
[10/16] 計算程序 SHA256 雜湊值
[11/16] 取得網路連線狀態
[12/16] 取得防火牆狀態
[13/16] 取得 SMB 設定
[14/16] 取得共用資料夾
[15/16] 取得稽核原則
[16/16] 取得 Hosts 檔案
```

### Linux 版

Linux 版目前提供原始 Python 腳本：

```bash
sudo python3 H2C_PcSecCheck_linux.py
```

建議以 `sudo` 執行，否則部分資訊（如程序 exe、auditd 規則、iptables、密碼期限）可能無法完整讀取。

Linux 版報告會在最上方產生 **「行政院資安健診重點摘要」**，以 `PASS` / `WARN` / `FAIL` / `INFO` 標示重點項目，例如：

| 重點項目 | 說明 |
|---------|------|
| 密碼原則 | 密碼最短長度、密碼最長期限 |
| 帳號盤點 | 非系統帳號、root、sudo / wheel / UID 0 |
| 端點防護 | 防毒、EDR 或完整性檢查工具 |
| SSH 安全 | root login、密碼登入、空密碼 |
| 防火牆 | ufw / firewalld / iptables |
| 稽核記錄 | auditd 服務與 auditctl 規則 |
| 修補狀態 | 可更新套件數 |
| 對外暴露 | LISTEN 服務、Samba / NFS 分享 |

程序 SHA256 會保留於 **「程序情資素材 / Hash 清單」**，供管理平台後續比對 VirusTotal、MalwareBazaar 或內部 IoC。端點工具本身不連線查詢、不上傳 hash。

平台預留欄位：

| 欄位 | 說明 |
|------|------|
| `vt_status` | `malicious` / `suspicious` / `clean` / `unknown` / `not_queried` |
| `threat_source` | `VirusTotal` / `MalwareBazaar` / `internal_ioc` |
| `first_seen` | 管理平台首次發現時間 |
| `last_seen` | 管理平台最後發現時間 |

### macOS 版

macOS 版目前提供原始 Python 腳本：

```bash
sudo python3 H2C_PcSecCheck_macos.py
```

建議以 `sudo` 執行，否則部分系統安全設定、程序路徑、網路連線與稽核資訊可能無法完整讀取。

macOS 版報告同樣會產生 **「行政院資安健診重點摘要」**，重點包含：

| 重點項目 | 說明 |
|---------|------|
| FileVault | 磁碟加密是否啟用 |
| SIP | System Integrity Protection 是否啟用 |
| Gatekeeper | 是否允許未簽章程式防護 |
| 防火牆 | Application Firewall / PF 狀態 |
| 帳號盤點 | 本機一般帳號與 admin 群組 |
| SSH 安全 | root login、密碼登入、空密碼 |
| 稽核記錄 | auditd 與 audit_control |
| 修補狀態 | macOS / Homebrew 可更新項目 |

---

## 系統需求

- Windows 8.1 / Windows Server 2012 R2 以上，Windows 10 / 11、Server 2016 / 2019 / 2022（x64）
  - > 預編 exe 以 Python 3.10 打包，**執行環境最低需 Windows 8.1 / Server 2012 R2**；
  >   **不支援 Windows 7 / 8、Server 2008 R2 / 2012（非 R2）**（無法啟動）。
  >   若確有舊系統需求，需改用 Python 3.8 自行重新編譯。
- Linux：Debian / Ubuntu / Kali / RedHat / CentOS / Fedora 類發行版
- macOS：建議 macOS 12 Monterey 以上
- Windows 版需**系統管理員（Administrator）權限**
- Linux / macOS 版建議 **root / sudo** 權限
- Windows exe 不需要安裝 Python 或任何套件
- Linux / macOS 腳本版需 Python 3 與 `openpyxl`
- 執行期間無需網際網路連線

---

## 開發 / 編譯

```bash
# 安裝依賴
pip install openpyxl pyinstaller

# 編譯 exe
pyinstaller H2C_PcSecCheck.spec --noconfirm
# 輸出：dist/H2C_PcSecCheck.exe（約 28 MB）

# Linux 執行
sudo python3 H2C_PcSecCheck_linux.py

# Linux 打包（需在 Linux 主機上執行）
pyinstaller H2C_PcSecCheck_linux.py --onefile --name H2C_PcSecCheck_linux --noconfirm

# macOS 執行
sudo python3 H2C_PcSecCheck_macos.py

# macOS 打包（需在 macOS 主機上執行）
pyinstaller H2C_PcSecCheck_macos.py --onefile --name H2C_PcSecCheck_macos --noconfirm
```

---

## 授權

本專案採用 [Apache License 2.0](LICENSE) 授權。

```
Copyright 2026 H2C工作室 甘霖老師

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---

## 關於

| 項目 | 說明 |
|------|------|
| 開發單位 | H2C 工作室 |
| 開發者 | 甘霖老師 |
| 版本 | v2.0.0 |
| 授權 | Apache License 2.0 |
