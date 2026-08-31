# Dev Log — 2026-08-31 #03：掃描工具自我誤報（可疑路徑）

> #02 的驗證掃描順帶抓到：報告出現兩條 High
> `程序執行於可疑路徑: H2C_PcSecCheck.exe` —— **掃描工具在標它自己**。

## 根因

使用者從 `Downloads\` 執行 `H2C_PcSecCheck.exe`，`_analyze_processes` 的
`_SUSPICIOUS_PATHS`（`temp|downloads|appdata\local\temp|users\public`）命中執行路徑。
onefile 打包在 Windows 是「bootloader 母程序 + app 子程序」兩支同名 exe → 兩條 High。

## 修法

`_analyze_processes` 加 `_is_self(pid, name)`：
- `pid ∈ {os.getpid(), 自身父 PID}` —— 精確、不可偽造（父 PID 從已收集的程序清單反查，無需額外 API）。
- 或 `"h2c_pcseccheck" in name` —— 兜底，涵蓋以原始碼執行、或 exe 被改名。

只套用在「可疑路徑」這條（自身一定有路徑，不影響「無執行路徑」；`-enc`/`IEX`
命令列檢查維持不動，掃描工具本來就不會觸發）。

## 驗證

合成程序清單：`H2C_PcSecCheck.exe`（母+子兩筆，路徑在 Downloads）→ 0 finding；
`evil.exe`（Downloads）→ 仍 High；`chrome.exe`（正常路徑）→ 不 flag。
