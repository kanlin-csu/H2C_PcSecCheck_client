#!/usr/bin/env python3
"""
H2C_PcSecCheck v2.0
PC 資安健診工具 — 合併版（HTML + XLSX + findings 分析 + .h2cpc.zip 封裝）
相容：Windows 7 SP1 / Server 2008 R2 SP1 以上（含 Win10 / Server 2022）

Copyright 2026 H2C工作室 甘霖老師

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from __future__ import annotations  # 讓 str | None 等語法相容 Python 3.7+

import html
import io
import os
import re
import socket
import subprocess
import json
import winreg
import platform
import zipfile
import hashlib
import datetime
from openpyxl import Workbook

TOOL_VERSION = "2.0.0"
SCHEMA_VERSION = "2"

# ─────────────────────────────────────────────────────────────────────────────
# 風險規則常數
# ─────────────────────────────────────────────────────────────────────────────
_SUSPICIOUS_PATHS = re.compile(
    r"\\(temp|downloads|appdata\\local\\temp|users\\public)\\",
    re.IGNORECASE,
)
_SUSPICIOUS_CMDLINE = (
    ("iex ",              4),
    ("invoke-expression", 4),
)

# 解碼後的 PowerShell 真正危險特徵
_DECODED_PS_DANGEROUS = re.compile(
    r"(net\.webclient|downloadstring|downloadfile|invoke-webrequest|"
    r"system\.reflection\.assembly|virtualalloc|writeprocessmemory|"
    r"\[convert\]::frombase64string|iex\s|invoke-expression|"
    r"start-process.{0,60}\\temp\\|\\appdata\\local\\temp\\)",
    re.IGNORECASE,
)


def _decode_encoded_command(cmdline: str) -> "str | None":
    """從命令列中提取並解碼 -EncodedCommand 的 Base64 內容。"""
    import base64
    m = re.search(r"-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)", cmdline, re.IGNORECASE)
    if not m:
        return None
    try:
        b64 = m.group(1)
        b64 += "=" * (-len(b64) % 4)
        return base64.b64decode(b64).decode("utf-16-le", errors="replace")
    except Exception:
        return None


def _proc_context(pid, parent_pid, parent_name) -> str:
    """產生程序追查建議語法區塊。"""
    lines = []
    if pid:
        lines.append(f"PID：{pid}")
    if parent_pid and parent_name:
        lines.append(f"父程序：{parent_name}（PID {parent_pid}）")
    elif parent_pid:
        lines.append(f"父PID：{parent_pid}")
    if pid:
        lines.append(
            f"\n【追查建議】\n"
            f"# 查父程序完整命令列\n"
            f"$p = Get-WmiObject Win32_Process -Filter 'ProcessId={pid}'\n"
            f"Get-WmiObject Win32_Process -Filter \"ProcessId=$($p.ParentProcessId)\" | "
            f"Select Name, ProcessId, CommandLine\n\n"
            f"# 查是否為排程工作\n"
            f"Get-ScheduledTask | Where-Object {{ $_.Actions.Arguments -match '{pid}' -or "
            f"$_.Actions.Execute -match 'powershell' }} | "
            f"Select TaskName, TaskPath"
        )
    return "\n".join(lines)


def _analyze_encoded_command(proc_name: str, cmdline: str, raw: dict,
                              pid=None, parent_pid=None, parent_name=None) -> list:
    """分析含 -EncodedCommand 的命令列，依解碼內容決定 severity。"""
    findings = []
    decoded  = _decode_encoded_command(cmdline)
    ctx      = _proc_context(pid, parent_pid, parent_name)

    if decoded is None:
        findings.append(_finding(
            "suspicious_process", 2,
            f"程序使用 EncodedCommand（無法解碼）: {proc_name}",
            f"{ctx}\n命令列含 -EncodedCommand 但 Base64 無法解析，需人工確認。\n{cmdline[:200]}",
            {**raw, "PID": pid, "父程序": parent_name, "父PID": parent_pid},
        ))
    elif _DECODED_PS_DANGEROUS.search(decoded):
        findings.append(_finding(
            "suspicious_process", 4,
            f"程序 EncodedCommand 含危險指令: {proc_name}",
            f"{ctx}\n解碼後發現高風險關鍵字：\n{decoded[:400]}",
            {**raw, "PID": pid, "父程序": parent_name, "父PID": parent_pid},
        ))
    else:
        findings.append(_finding(
            "suspicious_process", 0,
            f"程序使用 EncodedCommand（內容無害）: {proc_name}",
            f"{ctx}\n解碼內容：{decoded[:300]}",
            {**raw, "PID": pid, "父程序": parent_name, "父PID": parent_pid},
        ))
    return findings
_OFFICE_PROCS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
}
_PRIVATE_NETS = (
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:", re.I),
    re.compile(r"^0\.0\.0\.0$"),
)
_MALICIOUS_PORTS   = {4444, 5555, 6666, 1337, 31337, 9001}
_SENSITIVE_LISTEN  = {445, 3389, 5985}

SEVERITY_LABEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
SEVERITY_COLOR = {
    4: "#dc3545", 3: "#fd7e14", 2: "#ffc107", 1: "#0dcaf0", 0: "#6c757d",
}
RISK_COLORS = {
    "critical": "#dc3545", "high": "#fd7e14",
    "medium":   "#ffc107", "low":  "#198754",
}


def _is_private_ip(ip: str) -> bool:
    ip = ip.split(":")[0]
    return any(p.match(ip) for p in _PRIVATE_NETS)


# ─────────────────────────────────────────────────────────────────────────────
# 資料收集
# ─────────────────────────────────────────────────────────────────────────────
def get_local_ip_address():
    # 方法一：問 OS 路由表「連外網用哪個 IP」，自動跳過 VMware/虛擬網卡
    try:
        with socket.create_connection(("8.8.8.8", 80), timeout=3) as s:
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    # 方法二（fallback）：找有設 DNS 的網卡第一筆 IPv4
    try:
        ps_cmd = r"""
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
Where-Object { $_.DNSServerSearchOrder } |
Select-Object -First 1 -ExpandProperty IPAddress
"""
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and ":" not in line and not line.startswith("127."):
                return line
    except Exception:
        pass
    # 方法三（last resort）：hostname 解析第一筆非 loopback IPv4
    try:
        for addr_info in socket.getaddrinfo(socket.gethostname(), None):
            ip = addr_info[4][0]
            if ":" not in ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return "未知"


def run_powershell(command, timeout=60):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ""


def get_system_info():
    data = [
        {"項目": "電腦名稱", "內容": platform.node()},
        {"項目": "區網 IP",  "內容": get_local_ip_address()},
    ]
    try:
        result = subprocess.run(
            ["systeminfo"],
            capture_output=True, text=True, encoding="cp950", errors="replace",
        )
        for line in result.stdout.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                k, v = parts[0].strip(), parts[1].strip()
                if k and v:
                    data.append({"項目": k, "內容": v})
    except Exception as e:
        data.append({"項目": "systeminfo 錯誤", "內容": str(e)})
    return data


def get_defender_info():
    ps_cmd = r"""
Get-MpComputerStatus |
Select-Object AMProductVersion, AMServiceVersion,
    AntispywareSignatureVersion, AntivirusSignatureVersion,
    AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled,
    AntivirusSignatureLastUpdated |
ConvertTo-Json
"""
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        for item in data:
            for k, v in item.items():
                if isinstance(v, dict) and "DateTime" in v:
                    item[k] = v["DateTime"]
        return data
    except Exception:
        return [{"AMProductVersion": "無法取得", "AntivirusEnabled": "未知"}]


def get_installed_updates():
    ps_cmd = r"""
Get-WmiObject Win32_QuickFixEngineering |
Select-Object HotFixID, Description, InstalledOn |
ConvertTo-Json
"""
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        return data
    except Exception:
        return []


def get_installed_programs():
    data = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER,  "HKCU"),
    ]
    seen = set()
    for hive, _ in hives:
        for path in registry_paths:
            try:
                with winreg.OpenKey(hive, path) as reg_key:
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):
                        subkey_name = winreg.EnumKey(reg_key, i)
                        try:
                            with winreg.OpenKey(reg_key, subkey_name) as subkey:
                                display_name = _get_reg_value(subkey, "DisplayName")
                                if not display_name:
                                    continue
                                display_version  = _get_reg_value(subkey, "DisplayVersion")  or ""
                                publisher        = _get_reg_value(subkey, "Publisher")        or ""
                                install_location = _get_reg_value(subkey, "InstallLocation") or ""
                                key = (display_name, display_version)
                                if key in seen:
                                    continue
                                seen.add(key)
                                data.append({
                                    "名稱": display_name,
                                    "版本": display_version,
                                    "發行者": publisher,
                                    "安裝路徑": install_location,
                                })
                        except Exception:
                            pass
            except Exception:
                pass
    return data


def _get_reg_value(key, value_name):
    try:
        return winreg.QueryValueEx(key, value_name)[0]
    except Exception:
        return None


def get_local_user_accounts():
    # 優先使用 Get-LocalUser（Win10 / Server 2016+）
    # 自動 fallback 到 Win32_UserAccount WMI（Win7 / Server 2008 相容）
    ps_cmd = r"""
$result = @()
$useWMI = $false
try {
    $users = Get-LocalUser -ErrorAction Stop
    foreach ($u in $users) {
        $groups = ""
        try {
            $groups = (Get-LocalGroup -ErrorAction SilentlyContinue | Where-Object {
                (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like "*\$($u.Name)" }) -ne $null
            }).Name -join ", "
        } catch {}
        $result += [PSCustomObject]@{
            Name            = $u.Name
            Enabled         = $u.Enabled
            Description     = $u.Description
            LastLogon       = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            PasswordLastSet = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            PasswordExpires = if ($u.PasswordExpires) { $u.PasswordExpires.ToString("yyyy-MM-dd HH:mm:ss") } else { "永不到期" }
            Groups          = $groups
        }
    }
} catch {
    $useWMI = $true
}
if ($useWMI) {
    # Win7 / Server 2008 fallback：WMI Win32_UserAccount
    Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
        $result += [PSCustomObject]@{
            Name            = $_.Name
            Enabled         = -not $_.Disabled
            Description     = $_.Description
            LastLogon       = ""
            PasswordLastSet = ""
            PasswordExpires = if ($_.PasswordExpires) { "（請手動確認）" } else { "永不到期" }
            Groups          = ""
        }
    }
}
try { $result | ConvertTo-Json } catch { $result | ForEach-Object { $_.Name + "|" + $_.Enabled + "|" + $_.Description + "|" + $_.LastLogon + "|" + $_.PasswordLastSet + "|" + $_.PasswordExpires + "|" + $_.Groups } }
"""
    result_json = run_powershell(ps_cmd)
    # 嘗試 JSON 解析
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        result = []
        for item in data:
            result.append({
                "帳號名稱":    item.get("Name", ""),
                "是否啟用":    "啟用" if item.get("Enabled") else "停用",
                "描述":        item.get("Description", "") or "",
                "上次登入":    item.get("LastLogon", "") or "",
                "密碼上次設定": item.get("PasswordLastSet", "") or "",
                "密碼到期":    item.get("PasswordExpires", "") or "",
                "所屬群組":    item.get("Groups", "") or "",
            })
        return result
    except Exception:
        pass
    # Pipe 格式 fallback（PS2 無 ConvertTo-Json 時）
    result = []
    for line in result_json.splitlines():
        parts = line.split("|", 6)
        if len(parts) >= 2:
            result.append({
                "帳號名稱":    parts[0] if len(parts) > 0 else "",
                "是否啟用":    "啟用" if parts[1].strip().lower() == "true" else "停用" if len(parts) > 1 else "",
                "描述":        parts[2] if len(parts) > 2 else "",
                "上次登入":    parts[3] if len(parts) > 3 else "",
                "密碼上次設定": parts[4] if len(parts) > 4 else "",
                "密碼到期":    parts[5] if len(parts) > 5 else "",
                "所屬群組":    parts[6] if len(parts) > 6 else "",
            })
    return result


def get_password_policy():
    raw_output = run_powershell("net accounts")
    data = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            data.append({"設定": parts[0].strip(), "值": parts[1].strip()})
    return data


def get_network_settings():
    ps_cmd = r"""
Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
Select-Object Description, IPAddress, IPSubnet, DNSServerSearchOrder |
ConvertTo-Json
"""
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        result = []
        for item in data:
            ip_list     = item.get("IPAddress", []) or []
            subnet_list = item.get("IPSubnet",  []) or []
            dns_list    = item.get("DNSServerSearchOrder", []) or []
            result.append({
                "介面名稱":   item.get("Description", ""),
                "IP位址":     ", ".join(ip_list)     if isinstance(ip_list, list)     else str(ip_list),
                "子網遮罩":   ", ".join(subnet_list) if isinstance(subnet_list, list) else str(subnet_list),
                "DNS server": ", ".join(dns_list)    if isinstance(dns_list, list)    else str(dns_list),
            })
        return result
    except Exception:
        return [{"介面名稱": "無", "IP位址": "無", "子網遮罩": "無", "DNS server": "無法取得"}]


def get_processes():
    ps_cmd = r"""
Get-WmiObject Win32_Process |
Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, WorkingSetSize |
ConvertTo-Json
"""
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        result = []
        for item in data:
            result.append({
                "程序名稱":    item.get("Name", "") or "",
                "PID":         item.get("ProcessId", ""),
                "父PID":       item.get("ParentProcessId", ""),
                "執行路徑":    item.get("ExecutablePath", "") or "",
                "命令列":      item.get("CommandLine", "") or "",
                "記憶體(KB)":  round((item.get("WorkingSetSize") or 0) / 1024),
            })
        return result
    except Exception:
        return []


def get_process_hashes():
    ps_cmd = r"""
Get-WmiObject Win32_Process |
Where-Object { $_.ExecutablePath } |
Select-Object -ExpandProperty ExecutablePath -Unique |
ForEach-Object {
    $path = $_
    try {
        $hash = (Get-FileHash -Path $path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        $hash = "無法計算"
    }
    [PSCustomObject]@{ 執行路徑 = $path; SHA256 = $hash }
} | ConvertTo-Json
"""
    result_json = run_powershell(ps_cmd, timeout=120)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        result = []
        for item in data:
            result.append({
                "執行路徑": item.get("執行路徑", "") or "",
                "SHA256":   item.get("SHA256",   "") or "",
            })
        return result
    except Exception:
        return []


def _read_startup_approved(hive, reg_path: str) -> "dict[str, str]":
    """
    讀取 StartupApproved 鍵，回傳 {名稱: 狀態字串}。
    第一個 byte：02/00 = 啟用，03 = 使用者停用，06/04 = Windows 停用
    """
    status_map = {}
    try:
        with winreg.OpenKey(hive, reg_path) as key:
            i = 0
            while True:
                try:
                    name, value, vtype = winreg.EnumValue(key, i)
                    i += 1
                    if isinstance(value, (bytes, bytearray)) and len(value) >= 1:
                        b = value[0]
                        if b in (0x02, 0x00):
                            status_map[name] = "啟用"
                        elif b == 0x03:
                            status_map[name] = "停用（使用者）"
                        elif b in (0x06, 0x04):
                            status_map[name] = "停用（系統）"
                        else:
                            status_map[name] = f"未知(0x{b:02x})"
                    else:
                        status_map[name] = "啟用"
                except OSError:
                    break
    except Exception:
        pass
    return status_map


def get_startup_items():
    # 讀取 StartupApproved 狀態
    approved = {}
    approved.update(_read_startup_approved(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    ))
    approved.update(_read_startup_approved(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
    ))
    approved.update(_read_startup_approved(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    ))
    approved_folder = _read_startup_approved(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
    )

    data = []
    reg_sources = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKLM\\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
         "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\Run (x86)"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKLM\\RunOnce (x86)"),
    ]
    for hive, path, label in reg_sources:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        status = approved.get(name, "啟用")
                        data.append({
                            "來源":    label,
                            "名稱":    name,
                            "狀態":    status,
                            "命令/路徑": value,
                        })
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass

    startup_folders = [
        (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
         "使用者啟動資料夾"),
        (os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"),
         "所有使用者啟動資料夾"),
    ]
    for folder, label in startup_folders:
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                if os.path.isfile(fpath):
                    status = approved_folder.get(fname, "啟用")
                    data.append({
                        "來源":    label,
                        "名稱":    fname,
                        "狀態":    status,
                        "命令/路徑": fpath,
                    })

    return data


def get_netstat():
    ps_cmd = r"""
$pidMap = @{}
Get-Process | ForEach-Object { $pidMap[$_.Id] = $_.Name }
$result = @()
netstat -ano | Select-String "^\s+(TCP|UDP)" | ForEach-Object {
    $parts = ($_ -replace "^\s+","") -split "\s+"
    $proto   = $parts[0]
    $local   = $parts[1]
    $foreign = $parts[2]
    if ($proto -eq "TCP") { $state = $parts[3]; $pid = [int]$parts[4] }
    else                  { $state = "";         $pid = [int]$parts[3] }
    $procName = if ($pidMap.ContainsKey($pid)) { $pidMap[$pid] } else { "" }
    $result += [PSCustomObject]@{
        協定 = $proto; 本地位址 = $local; 遠端位址 = $foreign
        狀態 = $state; PID = $pid; 程序名稱 = $procName
    }
}
$result | ConvertTo-Json
"""
    result_json = run_powershell(ps_cmd, timeout=60)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        result = []
        for item in data:
            result.append({
                "協定":    item.get("協定",    ""),
                "本地位址": item.get("本地位址", ""),
                "遠端位址": item.get("遠端位址", ""),
                "狀態":    item.get("狀態",    ""),
                "PID":     item.get("PID",     ""),
                "程序名稱": item.get("程序名稱", ""),
            })
        return result
    except Exception:
        return []


def get_firewall_status():
    # 優先：Get-NetFirewallProfile（Win8 / Server 2012+）
    # Fallback：netsh advfirewall（Win7 / Server 2008 相容）
    ps_cmd = r"""
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    try { $profiles | ConvertTo-Json }
    catch {
        $profiles | ForEach-Object {
            $_.Name + "|" + $_.Enabled + "|" + $_.DefaultInboundAction + "|" + $_.DefaultOutboundAction
        }
    }
} catch {
    # Win7 fallback：netsh advfirewall
    $out = netsh advfirewall show allprofiles state 2>&1
    $out
}
"""
    raw = run_powershell(ps_cmd)
    # 嘗試 JSON
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return [{
            "設定檔":       item.get("Name", ""),
            "啟用":         "是" if item.get("Enabled") else "否",
            "預設入站動作": item.get("DefaultInboundAction", ""),
            "預設出站動作": item.get("DefaultOutboundAction", ""),
        } for item in data]
    except Exception:
        pass
    # Pipe 格式 fallback
    result = []
    for line in raw.splitlines():
        parts = line.split("|", 3)
        if len(parts) >= 2:
            result.append({
                "設定檔":       parts[0].strip(),
                "啟用":         "是" if parts[1].strip().lower() == "true" else "否",
                "預設入站動作": parts[2].strip() if len(parts) > 2 else "",
                "預設出站動作": parts[3].strip() if len(parts) > 3 else "",
            })
    if result:
        return result
    # netsh 文字格式解析（Win7）
    result = []
    current_profile = ""
    for line in raw.splitlines():
        line = line.strip()
        m_profile = re.match(r"^(Domain|Private|Public)\s+Profile\s+Settings", line, re.I)
        if m_profile:
            current_profile = m_profile.group(1)
        if current_profile and line.lower().startswith("state"):
            parts = line.split(None, 1)
            state = parts[1].strip() if len(parts) > 1 else ""
            result.append({
                "設定檔":       current_profile,
                "啟用":         "是" if "on" in state.lower() else "否",
                "預設入站動作": "",
                "預設出站動作": "",
            })
            current_profile = ""
    return result if result else [{"設定檔": "無法取得", "啟用": "無法取得", "預設入站動作": "", "預設出站動作": ""}]


def get_smb_status():
    # 優先：Get-SmbServerConfiguration（Win8 / Server 2012+）
    # Fallback：Registry 直讀（Win7 / Server 2008 相容）
    ps_cmd = r"""
$result = @()
$usedSmbCmdlet = $false
try {
    $cfg  = Get-SmbServerConfiguration -ErrorAction Stop
    $smb1 = $cfg.EnableSMB1Protocol
    $smb2 = $cfg.EnableSMB2Protocol
    $result += [PSCustomObject]@{ 設定 = "SMBv1 啟用狀態";   值 = $smb1.ToString() }
    $result += [PSCustomObject]@{ 設定 = "SMBv2/3 啟用狀態"; 值 = $smb2.ToString() }
    $usedSmbCmdlet = $true
} catch {}
if (-not $usedSmbCmdlet) {
    # Win7 fallback：讀 Registry
    try {
        $key  = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $smb1 = (Get-ItemProperty -Path $key -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        $smb2 = (Get-ItemProperty -Path $key -Name "SMB2" -ErrorAction SilentlyContinue).SMB2
        # SMB1 Registry=1 or null（預設啟用）；=0 停用
        $smb1Enabled = if ($smb1 -eq $null) { "True（未設定，預設啟用）" } elseif ($smb1 -eq 0) { "False" } else { "True" }
        $smb2Enabled = if ($smb2 -eq $null) { "True（未設定，預設啟用）" } elseif ($smb2 -eq 0) { "False" } else { "True" }
        $result += [PSCustomObject]@{ 設定 = "SMBv1 啟用狀態（Registry）";   值 = $smb1Enabled }
        $result += [PSCustomObject]@{ 設定 = "SMBv2/3 啟用狀態（Registry）"; 值 = $smb2Enabled }
    } catch {
        $result += [PSCustomObject]@{ 設定 = "SMB 狀態"; 值 = "無法取得（$($_.Exception.Message)）" }
    }
}
try {
    $feat = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State
    $result += [PSCustomObject]@{ 設定 = "SMBv1 Windows 功能"; 值 = $feat }
} catch {}
try { $result | ConvertTo-Json }
catch { $result | ForEach-Object { $_.設定 + "|" + $_.值 } }
"""
    raw = run_powershell(ps_cmd)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return [{"設定": item.get("設定", ""), "值": str(item.get("值", ""))} for item in data]
    except Exception:
        pass
    result = []
    for line in raw.splitlines():
        if "|" in line:
            k, _, v = line.partition("|")
            result.append({"設定": k.strip(), "值": v.strip()})
    return result if result else [{"設定": "無法取得", "值": ""}]


def get_shared_folders():
    # 優先：Get-SmbShare（Win8 / Server 2012+）
    # Fallback：net share（Win7 / Server 2008 相容）
    ps_cmd = r"""
try {
    $shares = Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ShareType
    try { $shares | ConvertTo-Json }
    catch { $shares | ForEach-Object { $_.Name + "|" + $_.Path + "|" + $_.Description + "|" + $_.ShareType } }
} catch {
    # Win7 fallback
    net share 2>&1
}
"""
    raw = run_powershell(ps_cmd)
    # JSON 解析
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        return [{
            "共用名稱": item.get("Name", ""),
            "路徑":     item.get("Path", ""),
            "說明":     item.get("Description", ""),
            "類型":     str(item.get("ShareType", "")),
        } for item in data]
    except Exception:
        pass
    # Pipe 格式 fallback
    result = []
    for line in raw.splitlines():
        if "|" in line:
            parts = line.split("|", 3)
            result.append({
                "共用名稱": parts[0].strip() if len(parts) > 0 else "",
                "路徑":     parts[1].strip() if len(parts) > 1 else "",
                "說明":     parts[2].strip() if len(parts) > 2 else "",
                "類型":     parts[3].strip() if len(parts) > 3 else "",
            })
    if result:
        return result
    # net share 文字格式解析（Win7）
    result = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("Share") or line.startswith("共用") or line.lower().startswith("the command"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            result.append({
                "共用名稱": parts[0],
                "路徑":     parts[1],
                "說明":     parts[2] if len(parts) > 2 else "",
                "類型":     "",
            })
    return result


def get_audit_policy():
    # /r 輸出 CSV 格式：Machine,PolicyTarget,Subcategory,GUID,InclusionSetting,ExclusionSetting
    # 欄位固定，不受系統語系縮排影響；需系統管理員權限
    ps_cmd = r"""
try {
    $csv = auditpol /get /category:* /r 2>&1
    $result = @()
    $first = $true
    foreach ($line in $csv) {
        $line = $line.Trim()
        if ($first) { $first = $false; continue }   # skip header
        if (-not $line) { continue }
        $parts = $line -split ","
        if ($parts.Count -lt 5) { continue }
        $result += [PSCustomObject]@{
            稽核類別 = $parts[2].Trim()
            稽核設定 = $parts[4].Trim()
        }
    }
    if ($result.Count -eq 0) { throw "no rows" }
    $result | ConvertTo-Json
} catch {
    # fallback: 解析文字格式（縮排 2 或 4 個空格的行）
    $lines = auditpol /get /category:* 2>&1
    $result = @()
    foreach ($line in $lines) {
        if ($line -match "^\s{2,}(\S.+?)\s{2,}(\S.+)$") {
            $result += [PSCustomObject]@{ 稽核類別 = $Matches[1].Trim(); 稽核設定 = $Matches[2].Trim() }
        }
    }
    if ($result.Count -eq 0) {
        @([PSCustomObject]@{ 稽核類別 = "無法取得（需系統管理員權限）"; 稽核設定 = "" }) | ConvertTo-Json
    } else {
        $result | ConvertTo-Json
    }
}
"""
    result_json = run_powershell(ps_cmd)
    try:
        data = json.loads(result_json)
        if isinstance(data, dict):
            data = [data]
        return [{"稽核類別": item.get("稽核類別", ""), "稽核設定": item.get("稽核設定", "")} for item in data]
    except Exception:
        return [{"稽核類別": "無法取得（需系統管理員權限）", "稽核設定": ""}]


def get_hosts_file():
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    result = []
    try:
        with open(hosts_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                is_standard = (
                    ip in ("127.0.0.1", "::1", "0.0.0.0", "255.255.255.255", "ff02::1", "ff02::2")
                    and hostname in ("localhost", "ip6-localhost", "ip6-loopback",
                                     "ip6-allnodes", "ip6-allrouters", "broadcasthost")
                )
                result.append({
                    "行號":    lineno,
                    "IP":      ip,
                    "主機名稱": hostname,
                    "完整內容": stripped,
                    "是否標準": "是" if is_standard else "否",
                })
    except Exception as e:
        result.append({"行號": 0, "IP": "", "主機名稱": "", "完整內容": f"無法讀取: {e}", "是否標準": "否"})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Findings 分析層
# ─────────────────────────────────────────────────────────────────────────────
def _finding(category, severity, title, detail, raw_data=None):
    return {
        "category": category,
        "severity": severity,
        "title":    title,
        "detail":   detail,
        "raw_data": raw_data or {},
        "status":   "open",
    }


def _analyze_processes(processes, process_hashes):
    findings = []
    pid_map = {p["PID"]: (p.get("程序名稱") or "").lower()
               for p in processes if p.get("PID")}
    _known_no_path = {
        # Windows 核心虛擬化安全（VBS / Credential Guard，VTL1 隔離，路徑不可見）
        "lsaiso.exe",
        # Windows 核心早期啟動程序
        "system", "system idle process", "idle", "registry",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe",
        # 記憶體相關虛擬程序
        "secure system", "memory compression", "memcompression",
        "vmmem", "vmmemcm", "vmmemcmzygote",
        # Windows Defender 保護程序（PPL，Protected Process Light）
        "msmpeng.exe", "mpdefendercoreservice.exe",
        "securityhealthservice.exe", "nissrv.exe",
        # 端點偵測 EDR（CrowdStrike、SentinelOne 等）
        "csfalconservice.exe", "csfalconcontainer.exe",
        "sentinelagent.exe", "sentinelservicehost.exe",
        # Sophos Endpoint Protection
        "sedservice.exe", "sspservice.exe",
        "sophosav.exe", "sophosui.exe", "sophoshealth.exe",
        "savservice.exe", "almon.exe",
        # 其他常見系統服務
        "svchost.exe",
    }

    for proc in processes:
        name       = (proc.get("程序名稱") or "").lower()
        path       = (proc.get("執行路徑") or "").lower()
        cmdline    = (proc.get("命令列")   or "").lower()
        pid        = proc.get("PID")
        parent_pid = proc.get("父PID")
        parent_name = pid_map.get(parent_pid, "") if parent_pid else ""
        ctx = _proc_context(pid, parent_pid, parent_name)

        # 可疑路徑
        if path and _SUSPICIOUS_PATHS.search(path):
            findings.append(_finding(
                "suspicious_process", 3,
                f"程序執行於可疑路徑: {proc['程序名稱']}",
                f"{ctx}\n執行路徑: {proc['執行路徑']}",
                {"程序名稱": proc["程序名稱"], "執行路徑": proc["執行路徑"],
                 "PID": pid, "父程序": parent_name, "父PID": parent_pid},
            ))

        # 無執行路徑
        if not path and pid and name not in _known_no_path:
            findings.append(_finding(
                "suspicious_process", 1,
                f"程序無執行路徑: {proc['程序名稱']}",
                f"{ctx}\n程序無法取得執行路徑（可能已被移除、受保護或為系統程序）",
                {"程序名稱": proc["程序名稱"], "PID": pid,
                 "父程序": parent_name, "父PID": parent_pid},
            ))

        # 可疑命令列
        raw_proc = {"程序名稱": proc["程序名稱"], "命令列": proc["命令列"],
                    "PID": pid, "父程序": parent_name, "父PID": parent_pid}
        if "-enc" in cmdline:
            findings += _analyze_encoded_command(
                proc["程序名稱"], proc["命令列"] or "", raw_proc,
                pid=pid, parent_pid=parent_pid, parent_name=parent_name,
            )
        else:
            for keyword, sev in _SUSPICIOUS_CMDLINE:
                if keyword in cmdline:
                    findings.append(_finding(
                        "suspicious_process", sev,
                        f"程序命令列含可疑關鍵字: {proc['程序名稱']}",
                        f"{ctx}\n命令列含 '{keyword}'\n{proc['命令列'][:200]}",
                        raw_proc,
                    ))
                    break

        # Office 衍生 PowerShell/cmd
        if name in ("powershell.exe", "cmd.exe") and parent_pid:
            if parent_name in _OFFICE_PROCS:
                findings.append(_finding(
                    "suspicious_process", 3,
                    f"Office 程序衍生 {proc['程序名稱']}",
                    f"{ctx}\n{proc['程序名稱']} 由 {parent_name} 啟動，疑似惡意巨集",
                    {"程序名稱": proc["程序名稱"], "PID": pid,
                     "父程序": parent_name, "父PID": parent_pid},
                ))

    # 無法計算雜湊
    for ph in process_hashes:
        if ph.get("SHA256") == "無法計算":
            findings.append(_finding(
                "process_hash_unknown", 1,
                "程序雜湊無法計算",
                f"檔案可能已被移除或鎖定: {ph['執行路徑']}",
                {"執行路徑": ph["執行路徑"]},
            ))

    return findings


def _analyze_netstat(netstat):
    findings = []
    for conn in netstat:
        state   = conn.get("狀態",    "")
        proto   = conn.get("協定",    "")
        foreign = conn.get("遠端位址", "")
        local   = conn.get("本地位址", "")

        foreign_ip       = foreign.rsplit(":", 1)[0] if ":" in foreign else foreign
        foreign_port_str = foreign.rsplit(":", 1)[1] if ":" in foreign else "0"
        try:
            foreign_port = int(foreign_port_str)
        except Exception:
            foreign_port = 0

        local_ip_part   = local.rsplit(":", 1)[0] if ":" in local else ""
        local_port_str  = local.rsplit(":", 1)[1] if ":" in local else "0"
        try:
            local_port = int(local_port_str)
        except Exception:
            local_port = 0

        # ESTABLISHED 至公網
        if state == "ESTABLISHED" and foreign_ip and not _is_private_ip(foreign_ip):
            proc_name = conn.get("程序名稱", "")
            if foreign_port in _MALICIOUS_PORTS:
                # 連至已知惡意 port → High
                findings.append(_finding(
                    "suspicious_connection", 3,
                    f"連線至已知惡意 Port {foreign_port}",
                    f"程序 {proc_name} 連線到 {foreign}",
                    conn,
                ))
            elif foreign_port in (80, 443):
                # 一般 HTTP/HTTPS → Low（正常網路流量）
                findings.append(_finding(
                    "suspicious_connection", 1,
                    f"對外 HTTPS/HTTP 連線：{proc_name}",
                    f"程序 {proc_name} 連線到公網 {foreign}（標準 port，請確認程序是否合法）",
                    conn,
                ))
            else:
                # 非標準 port → Medium
                findings.append(_finding(
                    "suspicious_connection", 2,
                    f"對外非標準 Port 連線：{proc_name} → {foreign}",
                    f"程序 {proc_name} 使用非標準 port {foreign_port} 連線至公網",
                    conn,
                ))

        # UDP 至公網
        if (proto == "UDP"
                and foreign_ip
                and foreign_ip not in ("*", "0.0.0.0")
                and not _is_private_ip(foreign_ip)):
            findings.append(_finding(
                "suspicious_connection", 1,
                "UDP 連線至公網",
                f"程序 {conn.get('程序名稱','')} UDP 連線到 {foreign}",
                conn,
            ))

        # 敏感服務對外監聽（IPv4 wildcard 或 IPv6 wildcard）
        _is_wildcard = local_ip_part in ("0.0.0.0", "::", "[::]", "*")
        if state == "LISTENING" and _is_wildcard and local_port in _SENSITIVE_LISTEN:
            port_names = {445: "SMB", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS"}
            findings.append(_finding(
                "open_port", 2,
                f"敏感服務對外監聽: {port_names.get(local_port, local_port)}",
                f"Port {local_port} ({port_names.get(local_port,'')}) 在 {local_ip_part} 監聽",
                conn,
            ))

    return findings


def _analyze_accounts(user_accounts):
    findings = []
    now = datetime.datetime.now()

    for acc in user_accounts:
        name    = acc.get("帳號名稱", "")
        enabled = acc.get("是否啟用") == "啟用"
        if not enabled:
            continue

        pw_expires = acc.get("密碼到期", "")
        last_logon = acc.get("上次登入", "")

        # 密碼永不到期
        if pw_expires in ("永不到期", "Never", ""):
            findings.append(_finding(
                "account_anomaly", 1,
                f"帳號密碼永不到期: {name}",
                f"帳號 {name} 設定為密碼永不到期",
                acc,
            ))

        # 內建 Administrator 啟用
        if name.lower() in ("administrator", "系統管理員"):
            findings.append(_finding(
                "account_anomaly", 2,
                "內建 Administrator 帳號為啟用狀態",
                f"帳號 {name} 啟用，建議停用或重新命名",
                acc,
            ))

        # 長期未登入（> 180 天）
        if last_logon and last_logon not in ("", "從未登入"):
            try:
                dt = datetime.datetime.strptime(last_logon, "%Y-%m-%d %H:%M:%S")
                days = (now - dt).days
                if days > 180:
                    findings.append(_finding(
                        "account_anomaly", 1,
                        f"帳號長期未登入: {name}",
                        f"最後登入 {last_logon}（{days} 天前）",
                        acc,
                    ))
            except Exception:
                pass

    return findings


def _analyze_password_policy(password_policy):
    findings = []
    policy = {item["設定"]: item["值"] for item in password_policy}

    # 文字型「無限制 / 永不到期」對應為 0
    _TEXT_ZERO = {"unlimited", "never", "無限制", "永不到期", "不套用", "none", "0"}

    def _int_val(*keys):
        for k in keys:
            v = str(policy.get(k, "")).strip().lower()
            if v in _TEXT_ZERO:
                return 0
            try:
                return int(v)
            except Exception:
                pass
        return None

    min_len = _int_val("最短密碼長度", "Minimum password length")
    if min_len is not None and min_len < 8:
        findings.append(_finding(
            "password_policy", 2,
            "密碼最短長度不足",
            f"最短密碼長度為 {min_len}，建議至少 8 字元",
            {"最短密碼長度": min_len},
        ))

    max_age = _int_val("密碼最長使用期限 (天數)", "Maximum password age (days)")
    if max_age is not None and max_age == 0:
        findings.append(_finding(
            "password_policy", 2,
            "密碼永不過期",
            "密碼最長使用期限設為 0（永不過期）",
            {"密碼最長使用期限": 0},
        ))

    lockout = _int_val("鎖定閾值", "Lockout threshold")
    if lockout is not None and lockout == 0:
        findings.append(_finding(
            "password_policy", 2,
            "帳號鎖定閾值為 0",
            "登入失敗不會鎖定帳號，容易遭受暴力破解",
            {"鎖定閾值": 0},
        ))

    return findings


def _analyze_startup_items(startup_items):
    findings = []
    for item in startup_items:
        cmd    = (item.get("命令/路徑") or "").lower()
        name   = item.get("名稱", "")
        source = item.get("來源", "")

        if cmd and _SUSPICIOUS_PATHS.search(cmd):
            findings.append(_finding(
                "suspicious_startup", 3,
                f"啟動項目執行於可疑路徑: {name}",
                f"來源: {source}\n命令: {item['命令/路徑']}",
                item,
            ))

        if "-enc" in cmd:
            for f in _analyze_encoded_command(name, item.get("命令/路徑") or "", item):
                f["category"] = "suspicious_startup"
                findings.append(f)
        else:
            for keyword, sev in _SUSPICIOUS_CMDLINE:
                if keyword in cmd:
                    findings.append(_finding(
                        "suspicious_startup", sev,
                        f"啟動項目命令含可疑關鍵字: {name}",
                        f"來源: {source}\n命令: {item['命令/路徑'][:200]}",
                        item,
                    ))
                    break

    return findings


_THIRD_PARTY_AV_KEYWORDS = (
    "sophos", "symantec", "norton", "mcafee", "trend micro", "trendmicro",
    "kaspersky", "eset", "bitdefender", "malwarebytes", "crowdstrike",
    "sentinelone", "cylance", "carbon black", "panda", "f-secure", "avast",
    "avg", "avira", "webroot", "comodo",
)

def _has_third_party_av(programs: list) -> str | None:
    """若已安裝第三方防毒，回傳其名稱；否則回傳 None。"""
    for p in programs:
        name = (p.get("名稱") or "").lower()
        for kw in _THIRD_PARTY_AV_KEYWORDS:
            if kw in name:
                return p.get("名稱", kw)
    return None


def _analyze_defender(defender_info, programs=None):
    findings = []
    if not defender_info:
        return findings

    info = defender_info[0] if isinstance(defender_info, list) else defender_info
    third_party_av = _has_third_party_av(programs or [])

    if str(info.get("AntivirusEnabled", "True")).lower() == "false":
        if third_party_av:
            findings.append(_finding(
                "endpoint_protection", 1,
                "Windows Defender 防毒已停用（偵測到第三方防毒）",
                f"AntivirusEnabled = False，但已安裝 {third_party_av}，請確認其保護狀態是否正常。",
                info,
            ))
        else:
            findings.append(_finding(
                "endpoint_protection", 4,
                "Windows Defender 防毒已停用（未偵測到其他防毒）",
                "AntivirusEnabled = False，且未發現其他防毒軟體，端點缺乏保護。",
                info,
            ))

    if str(info.get("RealTimeProtectionEnabled", "True")).lower() == "false":
        if third_party_av:
            findings.append(_finding(
                "endpoint_protection", 1,
                "Windows Defender 即時保護已停用（偵測到第三方防毒）",
                f"RealTimeProtectionEnabled = False，但已安裝 {third_party_av}，請確認其即時保護是否啟用。",
                info,
            ))
        else:
            findings.append(_finding(
                "endpoint_protection", 3,
                "Windows Defender 即時保護已停用（未偵測到其他防毒）",
                "RealTimeProtectionEnabled = False，且未發現其他防毒軟體。",
                info,
            ))

    last_updated = info.get("AntivirusSignatureLastUpdated", "") or ""
    if last_updated:
        try:
            updated_dt = datetime.datetime.strptime(last_updated[:19], "%Y-%m-%d %H:%M:%S")
            days = (datetime.datetime.now() - updated_dt).days
            if days > 30:
                findings.append(_finding(
                    "defender_outdated", 3,
                    f"Defender 病毒碼超過 30 天未更新",
                    f"最後更新: {last_updated}（{days} 天前）",
                    {"AntivirusSignatureLastUpdated": last_updated},
                ))
            elif days > 7:
                findings.append(_finding(
                    "defender_outdated", 2,
                    f"Defender 病毒碼超過 7 天未更新",
                    f"最後更新: {last_updated}（{days} 天前）",
                    {"AntivirusSignatureLastUpdated": last_updated},
                ))
        except Exception:
            pass

    return findings


def _analyze_firewall(firewall_data):
    findings = []
    for profile in firewall_data:
        if profile.get("啟用") == "否":
            name = profile.get("設定檔", "")
            findings.append(_finding(
                "firewall", 3,
                f"Windows 防火牆停用：{name} 設定檔",
                f"{name} 設定檔防火牆已關閉，端點缺乏網路入侵防護。",
                profile,
            ))
    return findings


def _analyze_smb(smb_data):
    findings = []
    for item in smb_data:
        if "SMBv1" in item.get("設定", "") and str(item.get("值", "")).lower() in ("true", "enabled"):
            findings.append(_finding(
                "smb_risk", 4,
                "SMBv1 通訊協定已啟用",
                "SMBv1 存在 EternalBlue 等嚴重漏洞（WannaCry 入口），建議立即停用。\n"
                "停用方式：Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                item,
            ))
    return findings


def _analyze_shared_folders(shared_data):
    findings = []
    default_admin_shares = {"admin$", "c$", "d$", "e$", "f$", "ipc$", "print$"}
    for share in shared_data:
        name = (share.get("共用名稱") or "").lower()
        path = share.get("路徑") or ""
        if name in default_admin_shares:
            continue
        findings.append(_finding(
            "shared_folder", 2,
            f"偵測到非預設共用資料夾：{share.get('共用名稱', '')}",
            f"路徑：{path}　請確認存取權限是否符合最小權限原則，避免資料外洩。",
            share,
        ))
    return findings


_AUDIT_IMPORTANT = {
    "登入":            "Success and Failure",
    "登出":            "Success",
    "帳戶登入":        "Success and Failure",
    "特殊登入":        "Success",
    "稽核原則變更":    "Success and Failure",
    "Logon":           "Success and Failure",
    "Logoff":          "Success",
    "Account Logon":   "Success and Failure",
    "Special Logon":   "Success",
    "Audit Policy Change": "Success and Failure",
}

def _analyze_audit_policy(audit_data):
    findings = []
    audit_map = {item.get("稽核類別", ""): item.get("稽核設定", "") for item in audit_data}
    for category, expected in _AUDIT_IMPORTANT.items():
        setting = audit_map.get(category, "")
        if not setting or setting.lower() == "no auditing":
            findings.append(_finding(
                "audit_policy", 2,
                f"重要稽核原則未啟用：{category}",
                f"建議設定為「{expected}」，目前為「{setting or '未設定'}」。\n"
                f"出事時無法追查事件記錄。",
                {"稽核類別": category, "稽核設定": setting},
            ))
    return findings


def _analyze_hosts_file(hosts_data):
    findings = []
    non_standard = [h for h in hosts_data if h.get("是否標準") == "否" and h.get("IP")]
    if non_standard:
        detail_lines = [f"  {h['IP']}\t{h['主機名稱']}" for h in non_standard[:20]]
        findings.append(_finding(
            "hosts_tampering", 3,
            f"hosts 檔案含 {len(non_standard)} 筆非標準記錄",
            "可能為 DNS 劫持或惡意重新導向，請確認以下記錄是否合法：\n"
            + "\n".join(detail_lines),
            {"非標準記錄": non_standard},
        ))
    return findings


def analyze_findings(report_data):
    findings = []
    findings += _analyze_processes(
        report_data.get("執行中程序", []),
        report_data.get("程序雜湊",   []),
    )
    findings += _analyze_netstat(report_data.get("網路連線", []))
    findings += _analyze_accounts(report_data.get("使用者帳號", []))
    findings += _analyze_password_policy(report_data.get("密碼原則", []))
    findings += _analyze_defender(
        report_data.get("Windows_Defender", []),
        programs=report_data.get("已安裝程式", []),
    )
    findings += _analyze_startup_items(report_data.get("啟動項目", []))
    findings += _analyze_firewall(report_data.get("防火牆狀態", []))
    findings += _analyze_smb(report_data.get("SMB狀態", []))
    findings += _analyze_shared_folders(report_data.get("共用資料夾", []))
    findings += _analyze_audit_policy(report_data.get("稽核原則", []))
    findings += _analyze_hosts_file(report_data.get("Hosts檔案", []))
    return findings


def calculate_risk(findings):
    SEV_SCORE = {4: 40, 3: 20, 2: 10, 1: 3, 0: 0}
    total = sum(SEV_SCORE.get(f.get("severity", 0), 0) for f in findings)
    score = min(100, total)
    if   score >= 80: level = "critical"
    elif score >= 50: level = "high"
    elif score >= 20: level = "medium"
    else:             level = "low"
    return score, level


# ─────────────────────────────────────────────────────────────────────────────
# HTML 產生（自含式，無 CDN）
# ─────────────────────────────────────────────────────────────────────────────
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px;
       background: #f0f2f5; color: #212529; }
.topbar { background: #212529; color: #fff; padding: 10px 20px;
          position: sticky; top: 0; z-index: 100;
          display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.topbar .brand { font-size: 15px; font-weight: 700; margin-right: 8px; }
.topbar a { color: #adb5bd; text-decoration: none; padding: 4px 8px;
            border-radius: 4px; font-size: 12px; }
.topbar a:hover { background: #343a40; color: #fff; }
.container { max-width: 1440px; margin: 0 auto; padding: 20px; }
h1 { font-size: 20px; margin: 16px 0 4px; }
.meta-line { color: #6c757d; margin-bottom: 20px; font-size: 12px; }
.card { background: #fff; border: 1px solid #dee2e6; border-radius: 6px;
        margin-bottom: 22px; }
.card-header { padding: 9px 16px; background: #343a40; color: #fff;
               border-radius: 6px 6px 0 0; font-weight: 600;
               display: flex; justify-content: space-between; align-items: center; }
.card-body { padding: 14px; }
.summary-grid { display: grid;
                grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
                gap: 10px; margin-bottom: 18px; }
.s-item { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px;
          padding: 10px; text-align: center; }
.s-item .val { font-size: 26px; font-weight: 700; }
.s-item .lbl { font-size: 11px; color: #6c757d; margin-top: 3px; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px;
         color: #fff; font-size: 11px; font-weight: 600; }
.search { margin-bottom: 8px; }
.search input { padding: 5px 10px; border: 1px solid #ced4da; border-radius: 4px;
                font-size: 12px; width: 100%; max-width: 300px; }
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #495057; color: #fff; padding: 6px 8px; text-align: left;
     cursor: pointer; white-space: nowrap; user-select: none; }
th:hover { background: #6c757d; }
td { padding: 5px 8px; border-bottom: 1px solid #e9ecef;
     word-break: break-word; max-width: 420px; vertical-align: top; }
tr:hover td { background: #f8f9fa; }
.ns-ESTABLISHED { background: #d1e7dd; }
.ns-LISTENING   { background: #cff4fc; }
.ns-TIME_WAIT, .ns-CLOSE_WAIT { background: #fff3cd; }
"""

_JS = """
function sortT(id, col) {
  var t = document.getElementById(id); if (!t) return;
  var dir = t.dataset.dir === "asc" ? "desc" : "asc"; t.dataset.dir = dir;
  var rows = Array.from(t.querySelectorAll("tbody tr"));
  rows.sort(function(a, b) {
    var x = (a.cells[col] || {}).innerText || "";
    var y = (b.cells[col] || {}).innerText || "";
    var c = x.localeCompare(y, "zh-Hant", {numeric: true, sensitivity: "base"});
    return dir === "asc" ? c : -c;
  });
  var tb = t.querySelector("tbody");
  rows.forEach(function(r) { tb.appendChild(r); });
}
function filterT(inp, id) {
  var f = inp.value.toLowerCase();
  document.getElementById(id).querySelectorAll("tbody tr").forEach(function(r) {
    r.style.display = r.innerText.toLowerCase().includes(f) ? "" : "none";
  });
}
"""


def _section_table(data, tid):
    if not data:
        return '<p style="color:#6c757d;padding:8px">無資料</p>'
    if not (isinstance(data, list) and data and isinstance(data[0], dict)):
        return "".join(f"<p>{item}</p>" for item in data)
    headers = list(data[0].keys())
    h = [
        f'<div class="search"><input placeholder="搜尋..." '
        f'oninput="filterT(this,\'{tid}\')"></div>',
        f'<div class="tbl-wrap"><table id="{tid}"><thead><tr>',
    ]
    for i, hdr in enumerate(headers):
        h.append(f'<th onclick="sortT(\'{tid}\',{i})">{hdr} ↕</th>')
    h.append("</tr></thead><tbody>")
    for item in data:
        h.append("<tr>")
        for hdr in headers:
            val = item.get(hdr, "")
            if isinstance(val, dict):
                val = val.get("DateTime", str(val))
            elif isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            h.append(f"<td>{html.escape(str(val))}</td>")
        h.append("</tr>")
    h.append("</tbody></table></div>")
    return "\n".join(h)


def _netstat_table(data):
    if not data:
        return '<p style="color:#6c757d;padding:8px">無資料</p>'
    headers = ["協定", "本地位址", "遠端位址", "狀態", "PID", "程序名稱"]
    h = [
        '<div class="search"><input placeholder="搜尋..." '
        'oninput="filterT(this,\'ns_t\')"></div>',
        '<div class="tbl-wrap"><table id="ns_t"><thead><tr>',
    ]
    for i, hdr in enumerate(headers):
        h.append(f'<th onclick="sortT(\'ns_t\',{i})">{hdr} ↕</th>')
    h.append("</tr></thead><tbody>")
    for item in data:
        state = item.get("狀態", "")
        cls   = f"ns-{state}" if state in ("ESTABLISHED", "LISTENING", "TIME_WAIT", "CLOSE_WAIT") else ""
        h.append(f'<tr class="{cls}">')
        for hdr in headers:
            h.append(f"<td>{html.escape(str(item.get(hdr,'')))}</td>")
        h.append("</tr>")
    h.append("</tbody></table></div>")
    return "\n".join(h)


def generate_html(computer_name, local_ip, report_data, findings, risk_score, risk_level):
    sc = {s: sum(1 for f in findings if f.get("severity") == s) for s in (4, 3, 2, 1, 0)}
    risk_color = RISK_COLORS.get(risk_level, "#6c757d")
    now_str    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def findings_rows():
        rows = []
        for f in sorted(findings, key=lambda x: -x.get("severity", 0)):
            sev    = f.get("severity", 0)
            color  = SEVERITY_COLOR.get(sev, "#6c757d")
            badge  = f'<span class="badge" style="background:{color}">{SEVERITY_LABEL.get(sev,"?")}</span>'
            detail = html.escape(f.get("detail") or "").replace("\n", "<br>")
            rd     = f.get("raw_data") or {}
            pid_str    = html.escape(str(rd.get("PID", "")))
            parent_str = html.escape(str(rd.get("父程序", "")))
            rows.append(
                f"<tr><td>{badge}</td>"
                f"<td>{html.escape(f.get('category',''))}</td>"
                f"<td>{html.escape(f.get('title',''))}</td>"
                f"<td style='font-size:12px;color:#adb5bd'>{pid_str}"
                f"{'<br>↑'+parent_str if parent_str else ''}</td>"
                f"<td>{detail}</td></tr>"
            )
        if not rows:
            return '<tr><td colspan="5" style="color:#6c757d;text-align:center">無風險項目</td></tr>'
        return "\n".join(rows)

    sections = [
        ("系統資訊",         "sys_t",      report_data.get("系統資訊",       [])),
        ("Windows Defender", "def_t",      report_data.get("Windows_Defender",[])),
        ("已安裝更新",       "upd_t",      report_data.get("已安裝更新",      [])),
        ("已安裝程式",       "prog_t",     report_data.get("已安裝程式",      [])),
        ("使用者帳號",       "usr_t",      report_data.get("使用者帳號",      [])),
        ("密碼原則",         "pol_t",      report_data.get("密碼原則",        [])),
        ("網路設定",         "net_t",      report_data.get("網路設定",        [])),
        ("啟動項目",         "startup_t",  report_data.get("啟動項目",        [])),
        ("執行中程序",       "proc_t",     report_data.get("執行中程序",      [])),
        ("程序 SHA256 雜湊", "hash_t",     report_data.get("程序雜湊",        [])),
        ("防火牆狀態",       "fw_t",       report_data.get("防火牆狀態",      [])),
        ("SMB 設定",         "smb_t",      report_data.get("SMB狀態",         [])),
        ("共用資料夾",       "share_t",    report_data.get("共用資料夾",      [])),
        ("稽核原則",         "audit_t",    report_data.get("稽核原則",        [])),
        ("Hosts 檔案",       "hosts_t",    report_data.get("Hosts檔案",       [])),
    ]

    nav = " ".join(
        f'<a href="#{aid}">{label}</a>'
        for label, aid in [("風險摘要", "findings_sec")]
                          + [(t, f"sec_{i}") for t, i, _ in sections]
                          + [("網路連線", "netstat_sec")]
    )

    cards = ""
    for title, tid, data in sections:
        cards += f"""
<div class="card" id="sec_{tid}">
  <div class="card-header">{title}</div>
  <div class="card-body">{_section_table(data, tid)}</div>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>H2C PC 健診 — {computer_name} ({local_ip})</title>
<style>{_CSS}</style>
</head>
<body>
<div class="topbar">
  <span class="brand">H2C PC 健診</span>
  {nav}
</div>
<div class="container">
  <h1>PC 資安健診報告</h1>
  <p class="meta-line">
    電腦：<strong>{computer_name}</strong> &nbsp;|&nbsp;
    IP：<strong>{local_ip}</strong> &nbsp;|&nbsp;
    產生時間：{now_str}
  </p>

  <div class="card" id="findings_sec">
    <div class="card-header">
      風險摘要
      <span class="badge" style="background:{risk_color};font-size:13px;padding:4px 14px">
        {risk_level.upper()} &nbsp; {risk_score}/100
      </span>
    </div>
    <div class="card-body">
      <div class="summary-grid">
        <div class="s-item"><div class="val" style="color:#dc3545">{sc[4]}</div><div class="lbl">Critical</div></div>
        <div class="s-item"><div class="val" style="color:#fd7e14">{sc[3]}</div><div class="lbl">High</div></div>
        <div class="s-item"><div class="val" style="color:#ffc107">{sc[2]}</div><div class="lbl">Medium</div></div>
        <div class="s-item"><div class="val" style="color:#0dcaf0">{sc[1]}</div><div class="lbl">Low</div></div>
        <div class="s-item"><div class="val" style="color:#6c757d">{sc[0]}</div><div class="lbl">Info</div></div>
      </div>
      <div class="tbl-wrap">
        <table id="findings_t">
          <thead><tr>
            <th onclick="sortT('findings_t',0)">嚴重度 ↕</th>
            <th onclick="sortT('findings_t',1)">類別 ↕</th>
            <th onclick="sortT('findings_t',2)">標題 ↕</th>
            <th>PID／父程序</th>
            <th>說明</th>
          </tr></thead>
          <tbody>{findings_rows()}</tbody>
        </table>
      </div>
    </div>
  </div>

{cards}

  <div class="card" id="netstat_sec">
    <div class="card-header">網路連線</div>
    <div class="card-body">{_netstat_table(report_data.get("網路連線", []))}</div>
  </div>
</div>
<script>{_JS}</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# XLSX 產生
# ─────────────────────────────────────────────────────────────────────────────
def _safe_cell(val):
    """防止 Excel 公式注入：以 =+-@ 開頭的字串加前置 ' 號。"""
    s = str(val) if not isinstance(val, (int, float, type(None))) else val
    if isinstance(s, str) and s and s[0] in ("=", "+", "-", "@", "|", "%"):
        return "'" + s
    return val


def _write_sheet(ws, data, field_order=None):
    if not data:
        ws.append(["無資料"])
        return
    if field_order is None:
        field_order = list(data[0].keys()) if data else []
    ws.append(field_order)
    for item in data:
        row = []
        for field in field_order:
            val = item.get(field, "")
            if isinstance(val, dict):
                val = val.get("DateTime", str(val))
            elif isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            row.append(_safe_cell(val))
        ws.append(row)


def generate_xlsx(report_data, findings):
    wb = Workbook()

    # 第一頁：風險摘要
    ws = wb.active
    ws.title = "風險摘要"
    ws.append(["類別", "嚴重度", "標題", "PID", "父程序", "說明", "狀態"])
    for f in sorted(findings, key=lambda x: -x.get("severity", 0)):
        rd = f.get("raw_data") or {}
        ws.append([
            _safe_cell(f.get("category", "")),
            SEVERITY_LABEL.get(f.get("severity", 0), ""),
            _safe_cell(f.get("title", "")),
            rd.get("PID", ""),
            _safe_cell(rd.get("父程序", "")),
            _safe_cell(f.get("detail", "")),
            f.get("status", "open"),
        ])

    sheet_cfg = [
        ("系統資訊",         report_data.get("系統資訊",        []), ["項目", "內容"]),
        ("Windows Defender", report_data.get("Windows_Defender", []), None),
        ("已安裝更新",       report_data.get("已安裝更新",       []), ["HotFixID", "Description", "InstalledOn"]),
        ("已安裝程式",       report_data.get("已安裝程式",       []), ["名稱", "版本", "發行者", "安裝路徑"]),
        ("使用者帳號",       report_data.get("使用者帳號",       []),
         ["帳號名稱", "是否啟用", "描述", "上次登入", "密碼上次設定", "密碼到期", "所屬群組"]),
        ("密碼原則",         report_data.get("密碼原則",         []), ["設定", "值"]),
        ("網路設定",         report_data.get("網路設定",         []),
         ["介面名稱", "IP位址", "子網遮罩", "DNS server"]),
        ("啟動項目",         report_data.get("啟動項目",         []),
         ["來源", "名稱", "狀態", "命令/路徑"]),
        ("執行中程序",       report_data.get("執行中程序",       []),
         ["程序名稱", "PID", "父PID", "執行路徑", "命令列", "記憶體(KB)"]),
        ("程序雜湊",         report_data.get("程序雜湊",         []), ["執行路徑", "SHA256"]),
        ("網路連線",         report_data.get("網路連線",         []),
         ["協定", "本地位址", "遠端位址", "狀態", "PID", "程序名稱"]),
        ("防火牆狀態",       report_data.get("防火牆狀態",       []),
         ["設定檔", "啟用", "預設入站動作", "預設出站動作"]),
        ("SMB狀態",          report_data.get("SMB狀態",          []), ["設定", "值"]),
        ("共用資料夾",       report_data.get("共用資料夾",       []),
         ["共用名稱", "路徑", "說明", "類型"]),
        ("稽核原則",         report_data.get("稽核原則",         []), ["稽核類別", "稽核設定"]),
        ("Hosts檔案",        report_data.get("Hosts檔案",        []),
         ["行號", "IP", "主機名稱", "完整內容", "是否標準"]),
    ]
    for sheet_name, data, fields in sheet_cfg:
        _write_sheet(wb.create_sheet(sheet_name), data, fields)

    return wb


# ─────────────────────────────────────────────────────────────────────────────
# 打包 .h2cpc.zip
# ─────────────────────────────────────────────────────────────────────────────
def package_zip(base_name, report_data, findings, risk_score, risk_level,
                computer_name, local_ip):
    now = datetime.datetime.now()

    # 產生各檔案內容
    report_json_bytes = json.dumps(report_data, ensure_ascii=False, indent=2).encode("utf-8")

    findings_with_id = []
    for i, f in enumerate(findings):
        entry = dict(f)
        entry["id"] = f"pc:{f['category']}:{i}"
        findings_with_id.append(entry)
    findings_json_bytes = json.dumps(findings_with_id, ensure_ascii=False, indent=2).encode("utf-8")

    html_bytes = generate_html(
        computer_name, local_ip, report_data, findings, risk_score, risk_level,
    ).encode("utf-8")

    buf = io.BytesIO()
    generate_xlsx(report_data, findings).save(buf)
    xlsx_bytes = buf.getvalue()

    meta = {
        "tool":          "H2C_PcSecCheck",
        "version":       TOOL_VERSION,
        "schema_ver":    SCHEMA_VERSION,
        "computer_name": computer_name,
        "local_ip":      local_ip,
        "generated_at":  now.strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score":    risk_score,
        "risk_level":    risk_level,
        "finding_count": {
            "critical": sum(1 for f in findings if f.get("severity") == 4),
            "high":     sum(1 for f in findings if f.get("severity") == 3),
            "medium":   sum(1 for f in findings if f.get("severity") == 2),
            "low":      sum(1 for f in findings if f.get("severity") == 1),
            "info":     sum(1 for f in findings if f.get("severity") == 0),
        },
        "checksums": {
            f"{base_name}.report.json":   hashlib.sha256(report_json_bytes).hexdigest(),
            f"{base_name}.findings.json": hashlib.sha256(findings_json_bytes).hexdigest(),
        },
    }
    meta_json_bytes = json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8")

    zip_filename = f"{base_name}.h2cpc.zip"
    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("meta.json",                      meta_json_bytes)
        zf.writestr(f"{base_name}.report.json",   report_json_bytes)
        zf.writestr(f"{base_name}.findings.json", findings_json_bytes)
        zf.writestr(f"{base_name}.report.html",   html_bytes)
        zf.writestr(f"{base_name}.report.xlsx",   xlsx_bytes)

    return zip_filename


# ─────────────────────────────────────────────────────────────────────────────
# 主程式
# ─────────────────────────────────────────────────────────────────────────────
def _print(msg):
    """立即刷新輸出，避免 PyInstaller console 緩衝延遲。"""
    print(msg, flush=True)


def main():
    import sys
    # 強制 line-buffered，解決 PyInstaller EXE 黑畫面問題
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    # UAC 提權（ShellExecute）後 stdin 緩衝區可能殘留換行，清空避免誤讀
    try:
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getwch()
    except Exception:
        pass

    computer_name = platform.node()
    local_ip      = get_local_ip_address()
    # 檔名加入時間戳，避免重複執行時的覆蓋詢問
    ts        = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    base_name = f"{computer_name}_{local_ip}_{ts}"
    zip_filename = f"{base_name}.h2cpc.zip"

    _print("=" * 56)
    _print("  H2C PC 資安健診工具  v2.0")
    _print(f"  電腦：{computer_name}   IP：{local_ip}")
    _print("=" * 56)
    _print("")

    _print("[1/16] 取得系統資訊...")
    system_info      = get_system_info()
    _print("[2/16] 取得 Windows Defender 資訊...")
    defender_info    = get_defender_info()
    _print("[3/16] 取得已安裝更新...")
    updates          = get_installed_updates()
    _print("[4/16] 取得已安裝程式...")
    programs         = get_installed_programs()
    _print("[5/16] 取得使用者帳號...")
    user_accounts    = get_local_user_accounts()
    _print("[6/16] 取得密碼原則...")
    password_policy  = get_password_policy()
    _print("[7/16] 取得網路設定...")
    network_settings = get_network_settings()
    _print("[8/16] 取得啟動項目...")
    startup_items    = get_startup_items()
    _print("[9/16] 取得執行中程序...")
    processes        = get_processes()
    _print("[10/16] 計算程序 SHA256 雜湊值 (需要一些時間)...")
    process_hashes   = get_process_hashes()
    _print("[11/16] 取得網路連線狀態...")
    netstat          = get_netstat()
    _print("[12/16] 取得防火牆狀態...")
    firewall         = get_firewall_status()
    _print("[13/16] 取得 SMB 設定...")
    smb              = get_smb_status()
    _print("[14/16] 取得共用資料夾...")
    shared_folders   = get_shared_folders()
    _print("[15/16] 取得稽核原則...")
    audit_policy     = get_audit_policy()
    _print("[16/16] 讀取 hosts 檔案...")
    hosts_file       = get_hosts_file()

    report_data = {
        "meta": {
            "tool":          "H2C_PcSecCheck",
            "version":       TOOL_VERSION,
            "schema_ver":    SCHEMA_VERSION,
            "computer_name": computer_name,
            "local_ip":      local_ip,
            "generated_at":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "系統資訊":         system_info,
        "Windows_Defender": defender_info,
        "已安裝更新":       updates,
        "已安裝程式":       programs,
        "使用者帳號":       user_accounts,
        "密碼原則":         password_policy,
        "網路設定":         network_settings,
        "啟動項目":         startup_items,
        "執行中程序":       processes,
        "程序雜湊":         process_hashes,
        "網路連線":         netstat,
        "防火牆狀態":       firewall,
        "SMB狀態":          smb,
        "共用資料夾":       shared_folders,
        "稽核原則":         audit_policy,
        "Hosts檔案":        hosts_file,
    }

    _print("\n[分析] 執行風險評估...")
    findings               = analyze_findings(report_data)
    risk_score, risk_level = calculate_risk(findings)

    _print(f"[分析] 發現 {len(findings)} 個風險項目，等級: {risk_level.upper()} ({risk_score}/100)")

    _print("[打包] 產生 .h2cpc.zip...")
    zip_file = package_zip(
        base_name, report_data, findings, risk_score, risk_level,
        computer_name, local_ip,
    )

    _print("")
    _print("=" * 56)
    _print(f"  完成！輸出：{zip_file}")
    _print(f"  風險等級：{risk_level.upper()} ({risk_score}/100)")
    for sev, label in [(4, "Critical"), (3, "High"), (2, "Medium"), (1, "Low"), (0, "Info")]:
        cnt = sum(1 for f in findings if f.get("severity") == sev)
        if cnt:
            _print(f"    {label:8s}: {cnt}")
    _print("=" * 56)
    _print("  請將 .h2cpc.zip 上傳至管理平台或繳交給健診人員")
    _print("=" * 56)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[錯誤] {e}", flush=True)
    input("\n按 Enter 鍵關閉視窗...")
