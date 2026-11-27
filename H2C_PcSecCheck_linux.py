#!/usr/bin/env python3
"""
H2C_PcSecCheck_linux v2.0
Linux PC 資安健診工具 — 自動收集系統資訊並產生標準化報告包（.h2cpc.zip）

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
from __future__ import annotations

import html
import io
import ipaddress
import os
import re
import shlex
import subprocess
import json
import platform
import zipfile
import hashlib
import datetime
from dataclasses import dataclass
from functools import partial

from openpyxl import Workbook

from h2c_scoring import SCORING_VERSION, host_score  # 與 VANS 共用的計分模組

TOOL_VERSION = "2.0.0"
SCHEMA_VERSION = "2"

# ─────────────────────────────────────────────────────────────────────────────
# 風險規則常數（Linux 路徑版）
# ─────────────────────────────────────────────────────────────────────────────
_SUSPICIOUS_PATHS = re.compile(
    r"/(tmp|var/tmp|dev/shm|home/[^/]+/downloads|home/[^/]+/\.local/share/trash)/",
    re.IGNORECASE,
)
_SUSPICIOUS_CMDLINE = (
    ("base64 -d",       3),
    ("bash -i",         4),
    ("/dev/tcp/",       4),
    ("nc -e",           4),
    ("ncat -e",         4),
    ("mkfifo",          3),
    (r"curl.*\| *sh",   3),
    (r"wget.*\| *sh",   3),
    ("python.*-c.*exec",2),
    ("perl.*-e",        2),
)

_PRIVATE_NETS = (
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:", re.I),
    re.compile(r"^0\.0\.0\.0$"),
)
_MALICIOUS_PORTS  = {4444, 5555, 6666, 1337, 31337, 9001}
# 23=Telnet(危險), 512-514=rsh/rexec/rlogin, 6379=Redis無auth, 27017=MongoDB無auth
_SENSITIVE_LISTEN = {23, 512, 513, 514, 445, 3306, 5432, 6379, 27017}

SEVERITY_LABEL = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
SEVERITY_COLOR = {
    4: "#dc3545", 3: "#fd7e14", 2: "#ffc107", 1: "#0dcaf0", 0: "#6c757d",
}
RISK_COLORS = {
    "critical": "#dc3545", "high": "#fd7e14",
    "medium":   "#ffc107", "low":  "#198754", "info": "#6c757d",
}


# ─────────────────────────────────────────────────────────────────────────────
# 工具函式
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    missing: bool = False


def _command(cmd: list[str], timeout: int = 15, stdin_input: str | None = None) -> CommandResult:
    env = os.environ.copy()
    for name in ("DBUS_SYSTEM_BUS_ADDRESS", "DBUS_SESSION_BUS_ADDRESS", "SYSTEMD_BUS_ADDRESS",
                 "DOCKER_CONTEXT", "DOCKER_HOST", "CONTAINER_HOST", "CONTAINER_CONNECTION"):
        env.pop(name, None)
    env["LC_ALL"] = "C"
    try:
        result = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace",
                                timeout=timeout, input=stdin_input, env=env)
        return CommandResult(result.stdout, result.stderr, result.returncode)
    except FileNotFoundError:
        return CommandResult(stderr="找不到指令", missing=True)
    except subprocess.TimeoutExpired:
        return CommandResult(stderr="指令逾時")
    except OSError as exc:
        return CommandResult(stderr=str(exc))


def _run(cmd: list[str], timeout: int = 15, stdin_input: str | None = None,
         ok_codes: tuple[int, ...] = (0,)) -> str:
    result = _command(cmd, timeout=timeout, stdin_input=stdin_input)
    return result.stdout if result.returncode in ok_codes else ""


def _is_private_ip(ip: str) -> bool:
    ip = ip.split("%")[0]  # 去掉 IPv6 zone ID
    return any(p.match(ip) for p in _PRIVATE_NETS)



def get_local_ip_address() -> str:
    route = _run(["ip", "-4", "route", "show", "default"], timeout=5)
    match = re.search(r"\bdev\s+(\S+)", route)
    address_cmd = ["ip", "-4", "-o", "addr", "show", "scope", "global"]
    commands = [address_cmd + ["dev", match[1]]] if match else []
    commands += [address_cmd, ["hostname", "-I"]]
    for cmd in commands:
        out = _run(cmd, timeout=5)
        addresses = out.split() if cmd[0] == "hostname" else re.findall(r"\binet\s+(\S+)/\d+", out)
        for value in addresses:
            try:
                address = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if not address.is_loopback and not address.is_unspecified:
                return str(address)
    return "未知"


# ─────────────────────────────────────────────────────────────────────────────
# 資料收集
# ─────────────────────────────────────────────────────────────────────────────
def get_system_info() -> list[dict]:
    data: list[dict] = [
        {"項目": "電腦名稱", "內容": platform.node()},
        {"項目": "區網 IP",  "內容": get_local_ip_address()},
    ]

    # /etc/os-release
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    data.append({"項目": k.strip(), "內容": v.strip().strip('"')})
    except Exception:
        pass

    # uname
    uname = _run(["uname", "-a"]).strip()
    if uname:
        data.append({"項目": "uname -a", "內容": uname})

    # 核心版本
    data.append({"項目": "Kernel", "內容": platform.release()})
    data.append({"項目": "架構",   "內容": platform.machine()})

    # CPU 核心數
    nproc = _run(["nproc"]).strip()
    if nproc:
        data.append({"項目": "CPU 核心數", "內容": nproc})

    # 記憶體
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:")):
                    k, v = line.split(":", 1)
                    data.append({"項目": k.strip(), "內容": v.strip()})
    except Exception:
        pass

    # 運行時間
    uptime = _run(["uptime", "-p"]).strip()
    if uptime:
        data.append({"項目": "運行時間", "內容": uptime})

    # 時區
    tz = _run(["timedatectl", "show", "--property=Timezone", "--value"]).strip()
    if tz:
        data.append({"項目": "時區", "內容": tz})

    return data


def get_av_status() -> list[dict]:
    """偵測已安裝的防毒 / 端點保護工具。"""
    tools: list[dict] = []

    checks = [
        (["clamscan", "--version"],   "ClamAV"),
        (["rkhunter", "--version"],   "rkhunter"),
        (["chkrootkit", "-V"],        "chkrootkit"),
        (["aide", "--version"],       "AIDE (檔案完整性)"),
        (["tripwire", "--version"],   "Tripwire"),
        (["lynis", "show", "version"],"Lynis"),
    ]
    for cmd, name in checks:
        probe = _command(cmd, timeout=5)
        if probe.missing:
            continue
        out = probe.stdout.strip()
        if probe.returncode != 0 or not out:
            tools.append({"工具": name, "版本": "", "狀態": "無法取得", "即時保護": ""})
            continue
        svc_map = {"ClamAV": "clamav-daemon", "rkhunter": "rkhunter"}
        svc_status = "N/A"
        if name in svc_map:
            svc_out = _run(["systemctl", "is-active", svc_map[name]], timeout=5, ok_codes=(0, 3, 4)).strip()
            if svc_out == "active":
                svc_status = "啟用（running）"
            elif svc_out in ("inactive", "failed"):
                svc_status = f"停用（{svc_out}）"
            else:
                svc_status = "無法取得"
        tools.append({"工具": name, "版本": out.splitlines()[0][:80], "狀態": "已安裝", "即時保護": svc_status})

    if not tools:
        tools.append({
            "工具":     "未偵測到防毒工具",
            "版本":     "",
            "狀態":     "未安裝",
            "即時保護": "無",
        })
    return tools


def get_installed_packages() -> list[dict]:
    """取得已安裝套件清單（支援 dpkg / rpm）。"""
    # Debian / Ubuntu
    out = _run(["dpkg", "-l"], timeout=30)
    if out:
        pkgs = []
        for line in out.splitlines():
            if line.startswith("ii "):
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    pkgs.append({
                        "名稱": parts[1],
                        "版本": parts[2],
                        "架構": parts[3],
                        "描述": parts[4].strip() if len(parts) > 4 else "",
                    })
        if pkgs:
            return pkgs

    # RedHat / CentOS / Fedora
    out = _run(
        ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n"],
        timeout=30,
    )
    if out:
        pkgs = []
        for line in out.splitlines():
            parts = line.split("\t", 3)
            if len(parts) >= 2:
                pkgs.append({
                    "名稱": parts[0],
                    "版本": parts[1] if len(parts) > 1 else "",
                    "架構": parts[2] if len(parts) > 2 else "",
                    "描述": parts[3] if len(parts) > 3 else "",
                })
        if pkgs:
            return pkgs

    return [{"名稱": "無法取得套件清單（dpkg / rpm 均不可用）", "版本": "", "架構": "", "描述": ""}]


def get_local_user_accounts() -> list[dict]:
    result: list[dict] = []
    no_login_shells = {
        "/bin/false", "/usr/sbin/nologin", "/sbin/nologin",
        "/usr/bin/nologin", "/bin/nologin",
    }

    groups = {gid: name for name, gid, _ in _local_groups()}
    try:
        with open("/etc/passwd") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 6)
                if len(parts) < 7:
                    continue
                username, _, uid_s, gid_s, desc, _, shell = parts
                uid = int(uid_s) if uid_s.isdigit() else -1
                gid = int(gid_s) if gid_s.isdigit() else -1
                enabled = shell not in no_login_shells

                # 群組名稱
                group_name = groups.get(str(gid), str(gid))

                # 上次登入（lastlog）
                last_logon = ""
                out = _run(["lastlog", "-u", username], timeout=5)
                if out:
                    lines = out.strip().splitlines()
                    if len(lines) >= 2:
                        ll = lines[1]
                        if "Never logged in" in ll or "**Never logged in**" in ll:
                            last_logon = "從未登入"
                        else:
                            # lastlog 格式：username  pts/0  ip  Mon Jan  1 00:00:00 +0000 2024
                            tokens = ll.split()
                            if len(tokens) >= 4:
                                last_logon = " ".join(tokens[-(min(5, len(tokens))):])

                # 密碼到期（chage）
                pw_expires = "無法取得"
                out2 = _run(["chage", "-l", username], timeout=5)
                if out2:
                    for cl in out2.splitlines():
                        if "Password expires" in cl:
                            val = cl.split(":", 1)[1].strip()
                            pw_expires = "永不到期" if val.lower() == "never" else val
                            break

                result.append({
                    "帳號名稱":     username,
                    "UID":          uid,
                    "是否啟用":     "啟用" if enabled else "停用",
                    "帳號類型":     "一般使用者" if uid >= 1000 else "系統帳號",
                    "描述":         desc,
                    "Shell":        shell,
                    "上次登入":     last_logon,
                    "密碼到期":     pw_expires,
                    "所屬群組":     group_name,
                })
    except OSError as exc:
        raise RuntimeError("無法讀取本機帳號資料") from exc
    return result


def get_password_policy() -> list[dict]:
    data: list[dict] = []

    # /etc/login.defs
    try:
        with open("/etc/login.defs") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    data.append({"設定": parts[0], "值": parts[1]})
    except OSError as exc:
        raise RuntimeError("無法讀取 /etc/login.defs") from exc

    # pam pwquality
    for pam_path in ["/etc/security/pwquality.conf"]:
        try:
            with open(pam_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        data.append({"設定": f"[pwquality] {k.strip()}", "值": v.strip()})
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RuntimeError(f"無法讀取 {pam_path}") from exc

    return data if data else [{"設定": "無法取得密碼原則", "值": ""}]



def get_update_status() -> list[dict]:
    """查詢本機套件索引。"""
    commands = {
        "apt": ["apt", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "list", "--upgradable"],
        "dnf": ["dnf", "--cacheonly", "--setopt=plugins=0", "--quiet", "check-update"],
        "yum": ["yum", "--cacheonly", "--noplugins", "--quiet", "check-update"],
    }
    for manager, cmd in commands.items():
        probe = _command(cmd, timeout=30)
        if probe.missing:
            continue
        if probe.returncode not in ((0,) if manager == "apt" else (0, 100)):
            raise RuntimeError(f"{manager} 本機套件索引查詢失敗")
        rows = []
        if manager == "apt":
            rows = [line for line in probe.stdout.splitlines() if re.match(r"^\S+/\S*\s", line)]
        elif probe.returncode == 100:
            for line in probe.stdout.splitlines():
                if line.startswith("Obsoleting"):
                    break
                if re.match(r"^\S+\.\S+\s+\S+\s+\S+\s*$", line):
                    rows.append(line)
            if not rows:
                raise RuntimeError(f"{manager} 回報有更新，但無法解析套件清單")
        return [
            {"項目": "套件管理器", "內容": manager},
            {"項目": "資料來源", "內容": "本機套件索引（未刷新）"},
            {"項目": "可更新套件數", "內容": str(len(rows))},
            *({"項目": "可更新套件", "內容": line} for line in rows[:30]),
        ]
    raise RuntimeError("找不到 apt、dnf 或 yum")


def _local_groups() -> list[tuple[str, str, list[str]]]:
    groups = []
    with open("/etc/group", encoding="utf-8", errors="replace") as group_file:
        for line in group_file:
            fields = line.rstrip("\n").split(":")
            if len(fields) == 4 and fields[2].isdigit():
                name, _, gid, members = fields
                groups.append((name, gid, members.split(",") if members else []))
    return groups


def get_privileged_accounts() -> list[dict]:
    """列出 UID 0、sudo/wheel/admin 群組帳號，這是健診必看項。"""
    result: list[dict] = []
    passwd_users: dict[str, dict] = {}
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    passwd_users[parts[0]] = {
                        "UID": int(parts[2]) if parts[2].isdigit() else -1,
                        "Shell": parts[6],
                    }
    except OSError as exc:
        raise RuntimeError("無法讀取本機特權帳號資料") from exc

    for name, info in passwd_users.items():
        if info["UID"] == 0:
            result.append({"帳號": name, "權限來源": "UID 0", "UID": info["UID"], "Shell": info["Shell"]})

    for group_name, _, members in _local_groups():
        if group_name not in ("sudo", "wheel", "admin"):
            continue
        for member in members:
            info = passwd_users.get(member, {})
            result.append({
                "帳號": member, "權限來源": group_name,
                "UID": info.get("UID", ""), "Shell": info.get("Shell", ""),
            })

    seen = set()
    dedup = []
    for row in result:
        key = (row.get("帳號"), row.get("權限來源"))
        if key not in seen:
            seen.add(key)
            dedup.append(row)
    return dedup if dedup else [{"帳號": "未偵測到 sudo/wheel/admin 或額外 UID 0 帳號", "權限來源": "", "UID": "", "Shell": ""}]


def get_ssh_security() -> list[dict]:
    """讀取 SSH 伺服器有效設定；sshd -T 可解析 Include 與預設值。"""
    result: list[dict] = []
    keys = {
        "port": "連接埠",
        "permitrootlogin": "允許 root 登入",
        "passwordauthentication": "允許密碼登入",
        "pubkeyauthentication": "允許金鑰登入",
        "permitemptypasswords": "允許空密碼",
        "x11forwarding": "X11 Forwarding",
        "maxauthtries": "最大驗證嘗試次數",
        "clientaliveinterval": "閒置逾時秒數",
        "allowusers": "允許使用者",
        "allowgroups": "允許群組",
    }

    probe = _command(["sshd", "-T"], timeout=10)
    if probe.returncode != 0:
        raise RuntimeError("無法取得 OpenSSH 有效設定（sshd -T）")
    parsed = {}
    for line in probe.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            parsed[parts[0].lower()] = parts[1].strip()
    if not {"permitrootlogin", "passwordauthentication", "permitemptypasswords"} <= parsed.keys():
        raise RuntimeError("OpenSSH 有效設定缺少登入安全欄位")

    for key, label in keys.items():
        result.append({"設定": label, "值": parsed.get(key, "未設定/預設"), "狀態": "待檢核"})
    return result


def get_kernel_hardening() -> list[dict]:
    checks = {
        "kernel.randomize_va_space": "ASLR",
        "net.ipv4.ip_forward": "IPv4 轉送",
        "net.ipv4.conf.all.accept_redirects": "接受 ICMP Redirect",
        "net.ipv4.conf.all.send_redirects": "送出 ICMP Redirect",
        "net.ipv4.conf.all.rp_filter": "反向路徑過濾",
        "net.ipv4.tcp_syncookies": "SYN Cookies",
        "kernel.kptr_restrict": "限制 kernel pointer 洩漏",
        "kernel.dmesg_restrict": "限制 dmesg",
    }
    result = []
    for key, label in checks.items():
        val = _run(["sysctl", "-n", key], timeout=5).strip()
        result.append({"項目": label, "sysctl": key, "值": val if val else "無法取得"})
    return result


def get_mac_status() -> list[dict]:
    result: list[dict] = []
    aa = _run(["aa-status"], timeout=10)
    if aa:
        first = aa.strip().splitlines()[0] if aa.strip().splitlines() else "AppArmor 已安裝"
        result.append({"機制": "AppArmor", "狀態": first, "詳細": aa[:400]})
    else:
        result.append({"機制": "AppArmor", "狀態": "未偵測或未啟用", "詳細": ""})

    se = _run(["getenforce"], timeout=5).strip()
    if se:
        result.append({"機制": "SELinux", "狀態": se, "詳細": ""})
    else:
        result.append({"機制": "SELinux", "狀態": "未偵測", "詳細": ""})
    return result


def get_container_status() -> list[dict]:
    result: list[dict] = []
    docker_socket = f"/run/user/{os.geteuid()}/docker.sock"
    if not os.path.exists(docker_socket):
        docker_socket = "/var/run/docker.sock"
    commands = {
        "docker": ["docker", "--host", f"unix://{docker_socket}"],
        "podman": ["podman", "--remote=false"],
    }
    for runtime, cmd in commands.items():
        out = _run(cmd + ["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"], timeout=10)
        if out:
            for line in out.splitlines():
                parts = line.split("\t")
                result.append({
                    "Runtime": runtime,
                    "名稱": parts[0] if len(parts) > 0 else "",
                    "映像": parts[1] if len(parts) > 1 else "",
                    "狀態": parts[2] if len(parts) > 2 else "",
                    "Port": parts[3] if len(parts) > 3 else "",
                })
    return result if result else [{"Runtime": "未偵測到執行中容器", "名稱": "", "映像": "", "狀態": "", "Port": ""}]


def get_file_permission_risks() -> list[dict]:
    result: list[dict] = []
    for label, cmd in [
        ("SUID 檔案", ["find", "/usr", "/bin", "/sbin", "/opt", "-xdev", "-perm", "-4000", "-type", "f", "-print"]),
        ("SGID 檔案", ["find", "/usr", "/bin", "/sbin", "/opt", "-xdev", "-perm", "-2000", "-type", "f", "-print"]),
        ("全域可寫目錄", ["find", "/etc", "/var", "/opt", "-xdev", "-type", "d", "-perm", "-0002", "-print"]),
    ]:
        out = _run(cmd, timeout=20)
        for path in out.splitlines()[:80]:
            result.append({"類型": label, "路徑": path, "說明": "請確認是否符合最小權限原則"})
    return result if result else [{"類型": "未偵測到明顯檔案權限風險", "路徑": "", "說明": ""}]


def get_network_settings() -> list[dict]:
    result: list[dict] = []

    # DNS servers
    dns_servers: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])
    except Exception:
        pass

    # ip -j addr show（JSON 格式，需較新版 iproute2）
    out = _run(["ip", "-j", "addr", "show"], timeout=10)
    if out.strip().startswith("["):
        try:
            interfaces = json.loads(out)
            for iface in interfaces:
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                ipv4 = [a["local"] for a in iface.get("addr_info", []) if a.get("family") == "inet"]
                pfx  = [f"/{a['prefixlen']}" for a in iface.get("addr_info", []) if a.get("family") == "inet"]
                result.append({
                    "介面名稱":   name,
                    "IP位址":     ", ".join(ipv4),
                    "子網前綴":   ", ".join(pfx),
                    "DNS server": ", ".join(dns_servers),
                })
            return result
        except Exception:
            pass

    # fallback：ip addr show（文字格式）
    out = _run(["ip", "addr", "show"], timeout=10)
    current: dict | None = None
    for line in out.splitlines():
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            name = m.group(1)
            if name != "lo":
                current = {"介面名稱": name, "IP位址": "", "子網前綴": "", "DNS server": ", ".join(dns_servers)}
                result.append(current)
        elif current:
            m2 = re.match(r"\s+inet\s+(\d[\d.]+)/(\d+)", line)
            if m2:
                current["IP位址"]   = m2.group(1)
                current["子網前綴"] = f"/{m2.group(2)}"

    return result if result else [{"介面名稱": "無法取得", "IP位址": "", "子網前綴": "", "DNS server": ""}]


def get_startup_items() -> list[dict]:
    data: list[dict] = []

    # systemd enabled 服務
    out = _run(["systemctl", "list-unit-files", "--state=enabled", "--no-legend", "--no-pager"], timeout=10)
    for line in out.splitlines():
        parts = line.split(None, 2)
        if not parts:
            continue
        unit = parts[0]
        # 取得單元檔路徑
        path_out = _run(["systemctl", "show", unit, "--property=FragmentPath"], timeout=5)
        path = ""
        for pl in path_out.splitlines():
            if pl.startswith("FragmentPath="):
                path = pl.split("=", 1)[1]
        data.append({"來源": "systemd", "名稱": unit, "狀態": "啟用", "命令/路徑": path})

    # crontab（root）
    out = _run(["crontab", "-l"], timeout=5)
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            data.append({"來源": "crontab (root)", "名稱": line[:60], "狀態": "啟用", "命令/路徑": line})

    # /etc/cron.*
    for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]:
        if os.path.isdir(cron_dir):
            for fname in sorted(os.listdir(cron_dir)):
                fpath = os.path.join(cron_dir, fname)
                if os.path.isfile(fpath):
                    data.append({"來源": cron_dir, "名稱": fname, "狀態": "啟用", "命令/路徑": fpath})

    # /etc/rc.local
    if os.path.isfile("/etc/rc.local"):
        try:
            with open("/etc/rc.local") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and line != "exit 0":
                        data.append({"來源": "/etc/rc.local", "名稱": line[:60], "狀態": "啟用", "命令/路徑": line})
        except Exception:
            pass

    # /etc/init.d/ 可執行腳本
    if os.path.isdir("/etc/init.d"):
        for fname in sorted(os.listdir("/etc/init.d")):
            fpath = os.path.join("/etc/init.d", fname)
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                data.append({"來源": "/etc/init.d", "名稱": fname, "狀態": "啟用", "命令/路徑": fpath})

    return data


def get_processes() -> list[dict]:
    result: list[dict] = []
    page_size = getattr(os, "sysconf", lambda _: 4096)("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

    try:
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            base = f"/proc/{pid}"
            try:
                name = open(f"{base}/comm").read().strip()
            except Exception:
                continue
            try:
                exe = os.readlink(f"{base}/exe")
            except Exception:
                exe = ""
            try:
                cmdline = open(f"{base}/cmdline", "rb").read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            except Exception:
                cmdline = ""
            ppid = 0
            try:
                for sl in open(f"{base}/status"):
                    if sl.startswith("PPid:"):
                        ppid = int(sl.split()[1])
                        break
            except Exception:
                pass
            mem_kb = 0
            try:
                parts = open(f"{base}/statm").read().split()
                mem_kb = int(parts[1]) * page_size // 1024 if len(parts) > 1 else 0
            except Exception:
                pass
            result.append({
                "程序名稱":   name,
                "PID":        pid,
                "父PID":      ppid,
                "執行路徑":   exe,
                "命令列":     cmdline[:500],
                "記憶體(KB)": mem_kb,
            })
    except Exception as e:
        result.append({
            "程序名稱": f"無法讀取 /proc: {e}",
            "PID": 0, "父PID": 0, "執行路徑": "", "命令列": "", "記憶體(KB)": 0,
        })
    return result


def _get_package_owner(path: str, cache: dict[str, str]) -> str:
    """回傳檔案所屬套件，供管理平台白名單 / 基準比對使用。"""
    if not path or path in cache:
        return cache.get(path, "")

    owner = ""
    out = _run(["dpkg", "-S", path], timeout=3)
    if out and ":" in out:
        owner = out.split(":", 1)[0].strip()
    else:
        out = _run(["rpm", "-qf", path], timeout=3)
        if out and "is not owned" not in out and "not owned" not in out:
            owner = out.strip().splitlines()[0]
    cache[path] = owner
    return owner


def _empty_threat_fields() -> dict:
    """平台端後續填入 VirusTotal / MalwareBazaar / internal_ioc 結果。"""
    return {
        "vt_status": "not_queried",
        "threat_source": "",
        "first_seen": "",
        "last_seen": "",
    }


def get_process_hashes() -> list[dict]:
    result: list[dict] = []
    package_cache: dict[str, str] = {}
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        try:
            proc_fd = os.open(f"/proc/{pid_str}", os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            continue
        try:
            open_in_proc = partial(os.open, dir_fd=proc_fd)
            try:
                exe = os.readlink("exe", dir_fd=proc_fd)
            except FileNotFoundError:
                # 程序已結束，或核心執行緒沒有執行檔。
                continue
            except OSError:
                exe = ""
            try:
                with open("comm", encoding="utf-8", errors="replace", opener=open_in_proc) as f:
                    proc_name = f.read().strip()
            except OSError:
                proc_name = ""

            digest = ""
            try:
                # 透過 procfs 開啟執行中的檔案，並從同一個描述符取得路徑。
                with open("exe", "rb", opener=open_in_proc) as f:
                    exe = os.readlink(f"/proc/self/fd/{f.fileno()}")
                    sha = hashlib.sha256()
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha.update(chunk)
                digest = sha.hexdigest().upper()
                hash_status = "ok"
            except PermissionError:
                hash_status = "permission_denied"
            except OSError:
                hash_status = "failed"
        finally:
            os.close(proc_fd)

        is_deleted = exe.endswith(" (deleted)")
        result.append({
            "程序名稱": proc_name,
            "PID": int(pid_str),
            "執行路徑": exe,
            "SHA256": digest,
            "hash_status": hash_status,
            "套件來源": _get_package_owner(exe, package_cache) if digest and not is_deleted else "",
            "是否已刪除": "是" if is_deleted else "否",
            **_empty_threat_fields(),
        })
    return result



def get_netstat() -> list[dict]:
    def parse_ss(out: str, tcp_only: bool = False) -> list[dict]:
        rows = []
        for line in out.splitlines():
            parts = line.split()
            if tcp_only and parts and parts[0].lower() != "tcp":
                parts.insert(0, "tcp")
            if len(parts) < 6 or parts[0].lower() not in ("tcp", "udp"):
                raise ValueError("無法解析 ss 輸出")
            state = parts[1].upper()
            if tcp_only and state not in ("ESTAB", "ESTABLISHED"):
                continue
            process = " ".join(parts[6:])
            name = re.search(r'users:\(\("([^"]+)"', process)
            pid = re.search(r'pid=(\d+)', process)
            rows.append({
                "協定": parts[0].upper(), "本地位址": parts[4], "遠端位址": parts[5],
                "狀態": "ESTABLISHED" if state == "ESTAB" else state,
                "PID": pid[1] if pid else "", "程序名稱": name[1] if name else "",
            })
        return rows

    listeners = _command(["ss", "-H", "-tulnp"])
    established = _command(["ss", "-H", "-tnp"])
    if (listeners.returncode, established.returncode) == (0, 0):
        try:
            return parse_ss(listeners.stdout) + parse_ss(established.stdout, tcp_only=True)
        except ValueError:
            pass

    probe = _command(["netstat", "-antup"])
    if probe.returncode != 0:
        raise RuntimeError("無法透過 ss 或 netstat 取得網路連線")
    if not any(line.startswith("Proto") for line in probe.stdout.splitlines()):
        raise RuntimeError("無法解析 netstat 輸出")
    rows = []
    for line in probe.stdout.splitlines():
        if not re.match(r"^(tcp|udp)", line, re.I):
            continue
        parts = line.split()
        is_tcp = parts[0].startswith("tcp")
        if len(parts) < (6 if is_tcp else 5):
            raise RuntimeError("無法解析 netstat 連線欄位")
        state = parts[5] if is_tcp else "UNCONN"
        if is_tcp and state not in ("LISTEN", "ESTABLISHED"):
            continue
        if not is_tcp and parts[4].rsplit(":", 1)[-1] not in ("*", "0"):
            continue
        process = parts[6 if is_tcp else 5:]
        pid, _, name = (process[0] if process else "").partition("/")
        rows.append({
            "協定": parts[0].upper(), "本地位址": parts[3], "遠端位址": parts[4],
            "狀態": state, "PID": pid if pid.isdigit() else "", "程序名稱": name,
        })
    return rows


def _firewall_row(backend: str, profile: str, enabled: str, detail: str) -> dict:
    return {"防火牆類型": backend, "設定檔": profile, "啟用": enabled, "詳細資訊": detail.strip()[:400]}


def _nft_status(stdout: str) -> tuple[str, str]:
    entries = json.loads(stdout)["nftables"]
    if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
        raise ValueError("無法解析 nftables 規則")
    dormant = {(t["family"], t["name"]) for entry in entries if (t := entry.get("table"))
               and "dormant" in t.get("flags", [])}
    base_chains = {}
    rules = {}
    for entry in entries:
        if chain := entry.get("chain"):
            key = (chain["family"], chain["table"], chain["name"])
            if (chain.get("type") == "filter" and chain.get("hook")
                    and key[0] in {"inet", "ip", "ip6", "bridge", "netdev"} and key[:2] not in dormant):
                base_chains[key] = chain.get("policy", "accept")
        if rule := entry.get("rule"):
            key = (rule["family"], rule["table"], rule["chain"])
            rules.setdefault(key, []).extend(rule["expr"])

    pending = list(base_chains)
    seen = set()
    blocks = False
    has_verdict_map = False
    while pending:
        key = pending.pop()
        if key in seen:
            continue
        seen.add(key)
        for expr in rules.get(key, []):
            blocks |= "drop" in expr or "reject" in expr
            has_verdict_map |= "vmap" in expr
            for verdict in ("jump", "goto"):
                if verdict in expr:
                    pending.append((*key[:2], expr[verdict]["target"]))

    policies = ", ".join(f"{'/'.join(key)}={policy}" for key, policy in base_chains.items()) or "無 filter 基礎鏈"
    active = "drop" in base_chains.values() or blocks
    detail = f"{policies}；有 DROP／REJECT 規則：{'是' if blocks else '否'}"
    return ("是" if active else "未知" if has_verdict_map else "否"), detail


def _iptables_status(stdout: str) -> tuple[str, str]:
    policies = {}
    targets = {}
    for line in stdout.splitlines():
        parts = shlex.split(line)
        if parts[:1] == ["-P"] and len(parts) == 3:
            policies[parts[1]] = parts[2]
        elif parts[:1] == ["-A"] and len(parts) > 2:
            tokens = iter(parts[2:])
            for option in tokens:
                if option == "--comment":
                    next(tokens, "")
                elif option in ("-j", "-g"):
                    targets.setdefault(parts[1], []).append(next(tokens, ""))
                    break
    if not {"INPUT", "FORWARD", "OUTPUT"} <= policies.keys():
        raise ValueError("無法解析 iptables 預設政策")
    pending = list(policies)
    seen = set()
    while pending:
        chain = pending.pop()
        if chain not in seen:
            seen.add(chain)
            pending.extend(targets.get(chain, []))
    blocks = bool(seen & {"DROP", "REJECT"})
    policy_detail = ", ".join(f"{name}={policy}" for name, policy in policies.items())
    detail = f"{policy_detail}；有 DROP／REJECT 規則：{'是' if blocks else '否'}"
    return ("是" if "DROP" in policies.values() or blocks else "否"), detail


def get_firewall_status() -> list[dict]:
    rows = []
    ufw = _command(["ufw", "status", "verbose"], timeout=10)
    if not ufw.missing:
        match = re.search(r"^Status:[ \t]*(active|inactive)[ \t]*$", ufw.stdout, re.M | re.I)
        enabled = {"active": "是", "inactive": "否"}[match[1].lower()] if ufw.returncode == 0 and match else "未知"
        rows.append(_firewall_row("ufw", "all", enabled, ufw.stdout or ufw.stderr))

    firewalld = _command(["firewall-cmd", "--state"], timeout=10)
    if not firewalld.missing:
        state = (firewalld.stdout or firewalld.stderr).strip().lower()
        if firewalld.returncode == 0 and state == "running":
            detail = _command(["firewall-cmd", "--list-all-zones"], timeout=10)
            enabled = "是" if detail.returncode == 0 and detail.stdout.strip() else "未知"
            rows.append(_firewall_row("firewalld", "all", enabled, detail.stdout or detail.stderr or "無法取得區域設定"))
        else:
            stopped = firewalld.returncode == 252 and state == "not running"
            rows.append(_firewall_row("firewalld", "all", "否" if stopped else "未知", state))

    for backend, profile, cmd, parse in (
        ("nftables", "ruleset", ["nft", "-j", "-n", "list", "ruleset"], _nft_status),
        ("iptables", "IPv4 filter", ["iptables", "-t", "filter", "-S"], _iptables_status),
        ("ip6tables", "IPv6 filter", ["ip6tables", "-t", "filter", "-S"], _iptables_status),
    ):
        probe = _command(cmd, timeout=10)
        if probe.missing:
            continue
        enabled, detail = "未知", probe.stderr or "無法讀取規則"
        if probe.returncode == 0:
            try:
                enabled, detail = parse(probe.stdout)
            except (ValueError, KeyError, TypeError, AttributeError):
                detail = "無法解析規則"
        rows.append(_firewall_row(backend, profile, enabled, detail))

    return rows or [_firewall_row("未取得防火牆資料", "", "未知", "找不到可用的防火牆檢查指令")]


def _firewall_assessment(rows: list[dict]) -> str:
    states = {row.get("啟用") for row in rows}
    if "未知" in states or None in states:
        return "UNKNOWN"
    if "是" in states:
        return "PASS"
    if states and states <= {"否", "否（無規則）"}:
        return "FAIL"
    return "UNKNOWN"


def get_smb_status() -> list[dict]:
    result: list[dict] = []

    # Samba 版本
    ver_out = _run(["smbd", "--version"], timeout=5)
    if not ver_out.strip():
        ver_out = _run(["smbd", "-V"], timeout=5)
    if not ver_out.strip():
        result.append({"設定": "Samba", "值": "未安裝（smbd 不存在）"})
        return result

    result.append({"設定": "Samba 版本", "值": ver_out.strip().splitlines()[0]})

    # 服務狀態
    svc_out = _run(["systemctl", "is-active", "smbd"], timeout=5, ok_codes=(0, 3, 4)).strip() or "未知"
    result.append({"設定": "Samba 服務狀態", "值": svc_out})

    # 優先使用 testparm -sv 取得實際生效設定（含 include / 預設值）。
    effective = _run(["testparm", "-sv"], timeout=10, stdin_input="\n")
    if effective:
        for key in ("server min protocol", "client min protocol", "server max protocol"):
            m = re.search(rf"^\s*{re.escape(key)}\s*=\s*(.+)$", effective, re.M | re.I)
            if m:
                result.append({"設定": key, "值": m.group(1).strip()})

    # 讀取 smb.conf 作為備援與人工檢視
    for conf in ["/etc/samba/smb.conf", "/usr/local/samba/etc/smb.conf"]:
        if not os.path.isfile(conf):
            continue
        try:
            content = open(conf).read()
            m = re.search(r"^\s*(server\s+min\s+protocol|min\s+protocol)\s*=\s*(.+)$", content, re.M | re.I)
            if m:
                proto = m.group(2).strip().upper()
                result.append({"設定": "smb.conf min protocol", "值": proto})
            else:
                result.append({"設定": "smb.conf min protocol", "值": "未設定"})
        except Exception as e:
            result.append({"設定": f"無法讀取 {conf}", "值": str(e)})
        break

    return result



def get_shared_folders() -> list[dict]:
    result = []
    try:
        with open("/etc/samba/smb.conf", encoding="utf-8", errors="replace") as conf:
            current_share = None
            for line in conf:
                line = line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                heading = re.fullmatch(r"\[(.+)\]", line)
                if heading:
                    name = heading[1]
                    current_share = None
                    if name.lower() not in ("global", "printers", "print$", "homes"):
                        current_share = {"共用名稱": name, "路徑": "", "說明": "", "類型": "Samba"}
                        result.append(current_share)
                elif current_share is not None and "=" in line:
                    key, value = line.split("=", 1)
                    label = {"path": "路徑", "comment": "說明"}.get(key.strip().lower())
                    if label:
                        current_share[label] = value.strip()
    except FileNotFoundError:
        pass

    try:
        with open("/etc/exports", encoding="utf-8", errors="replace") as conf:
            for line in conf:
                fields = line.partition("#")[0].split(None, 1)
                if fields:
                    result.append({
                        "共用名稱": os.path.basename(fields[0]) or fields[0], "路徑": fields[0],
                        "說明": fields[1].strip() if len(fields) > 1 else "", "類型": "NFS",
                    })
    except FileNotFoundError:
        pass
    return result


def get_audit_policy() -> list[dict]:
    result: list[dict] = []

    # auditd 服務狀態
    svc = _run(["systemctl", "is-active", "auditd"], timeout=5, ok_codes=(0, 3, 4)).strip()
    result.append({"稽核類別": "auditd 服務狀態", "稽核設定": svc if svc else "未知（systemctl 不可用）"})

    # auditctl -l（列出規則）
    rules = _command(["auditctl", "-l"], timeout=10)
    if rules.returncode == 0:
        lines = rules.stdout.strip().splitlines()
        if not lines or lines[0].strip() in ("-a never,task", "No rules"):
            result.append({"稽核類別": "稽核規則", "稽核設定": "無規則（No auditing）"})
        else:
            for line in lines:
                result.append({"稽核類別": "稽核規則", "稽核設定": line.strip()})
    else:
        result.append({"稽核類別": "auditctl", "稽核設定": "未安裝或無法執行（需 root）"})

    # 規則檔存在狀態
    for path in ["/etc/audit/audit.rules", "/etc/audit/rules.d"]:
        if os.path.isfile(path):
            result.append({"稽核類別": "稽核規則檔", "稽核設定": path})
        elif os.path.isdir(path):
            try:
                n = len(os.listdir(path))
                result.append({"稽核類別": "稽核規則目錄", "稽核設定": f"{path} （{n} 個檔案）"})
            except Exception:
                pass

    return result


def get_hosts_file() -> list[dict]:
    hosts_path = "/etc/hosts"
    result: list[dict] = []
    _STD_IPS  = {"127.0.0.1", "::1", "0.0.0.0", "127.0.1.1", "127.0.53.53",
                 "255.255.255.255", "ff02::1", "ff02::2"}
    _STD_HOST = {"localhost", "localhost.localdomain", "localhost6", "localhost6.localdomain6",
                 "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters",
                 "broadcasthost"}
    try:
        with open(hosts_path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                parts = stripped.split()
                if len(parts) >= 2:
                    ip, hostname = parts[0], parts[1]
                    is_std = ip in _STD_IPS and hostname in _STD_HOST
                    result.append({
                        "行號":    lineno,
                        "IP":      ip,
                        "主機名稱": hostname,
                        "完整內容": stripped,
                        "是否標準": "是" if is_std else "否",
                    })
    except Exception as e:
        result.append({"行號": 0, "IP": "", "主機名稱": "", "完整內容": f"無法讀取: {e}", "是否標準": "否"})
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Findings 分析層
# ─────────────────────────────────────────────────────────────────────────────
def _finding(category: str, severity: int, title: str, detail: str, raw_data: dict | None = None) -> dict:
    return {
        "category": category,
        "severity": severity,
        "title":    title,
        "detail":   detail,
        "raw_data": raw_data or {},
        "status":   "open",
    }


def _analyze_processes(processes: list[dict], process_hashes: list[dict]) -> list[dict]:
    findings: list[dict] = []
    pid_map = {p["PID"]: (p.get("程序名稱") or "").lower() for p in processes if p.get("PID")}

    for proc in processes:
        name    = (proc.get("程序名稱") or "").lower()
        path    = (proc.get("執行路徑") or "").lower()
        cmdline = (proc.get("命令列")   or "").lower()
        pid     = proc.get("PID")
        ppid    = proc.get("父PID")
        ctx     = f"PID：{pid}　父PID：{ppid}"

        # 可疑路徑
        if path and _SUSPICIOUS_PATHS.search(path):
            findings.append(_finding(
                "suspicious_process", 3,
                f"程序執行於可疑路徑: {proc['程序名稱']}",
                f"{ctx}\n執行路徑: {proc['執行路徑']}",
                proc,
            ))

        # 可疑命令列
        for pattern, sev in _SUSPICIOUS_CMDLINE:
            if re.search(pattern, cmdline, re.I):
                findings.append(_finding(
                    "suspicious_process", sev,
                    f"程序命令列含可疑特徵: {proc['程序名稱']}",
                    f"{ctx}\n命令列符合規則 '{pattern}'\n{proc['命令列'][:300]}",
                    proc,
                ))
                break

    return findings


def _analyze_netstat(netstat: list[dict]) -> list[dict]:
    findings: list[dict] = []
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

        local_ip_part  = local.rsplit(":", 1)[0] if ":" in local else ""
        local_port_str = local.rsplit(":", 1)[1] if ":" in local else "0"
        try:
            local_port = int(local_port_str)
        except Exception:
            local_port = 0

        if state == "ESTABLISHED" and foreign_ip and not _is_private_ip(foreign_ip):
            proc_name = conn.get("程序名稱", "")
            if foreign_port in _MALICIOUS_PORTS:
                findings.append(_finding(
                    "suspicious_connection", 3,
                    f"連線至已知惡意 Port {foreign_port}",
                    f"程序 {proc_name} 連線到 {foreign}",
                    conn,
                ))
            elif foreign_port not in (80, 443):
                findings.append(_finding(
                    "suspicious_connection", 2,
                    f"對外非標準 Port 連線：{proc_name} → {foreign}",
                    f"程序 {proc_name} 使用非標準 port {foreign_port} 連線至公網",
                    conn,
                ))

        _is_wildcard = local_ip_part in ("0.0.0.0", "::", "[::]", "*", "")
        if state in ("LISTEN", "LISTENING") and _is_wildcard and local_port in _SENSITIVE_LISTEN:
            port_names = {
                23: "Telnet（明文，危險）", 445: "SMB",
                512: "rexec", 513: "rlogin", 514: "rsh",
                3306: "MySQL", 5432: "PostgreSQL",
                6379: "Redis（可能無認證）", 27017: "MongoDB（可能無認證）",
            }
            findings.append(_finding(
                "open_port", 2 if local_port not in (23, 512, 513, 514) else 3,
                f"敏感服務對外監聽: {port_names.get(local_port, str(local_port))}",
                f"Port {local_port} 在 {local_ip_part or '*'} 對外監聽",
                conn,
            ))
    return findings


def _analyze_accounts(user_accounts: list[dict]) -> list[dict]:
    findings: list[dict] = []
    now = datetime.datetime.now()

    # 找所有 UID 0 帳號（root 之外）
    uid0_non_root = [a for a in user_accounts if a.get("UID") == 0 and a.get("帳號名稱") != "root"]
    for acc in uid0_non_root:
        findings.append(_finding(
            "account_anomaly", 4,
            f"非 root 帳號具有 UID 0：{acc['帳號名稱']}",
            f"帳號 {acc['帳號名稱']} 的 UID=0，擁有等同 root 的完整權限，極度危險。",
            acc,
        ))

    for acc in user_accounts:
        name    = acc.get("帳號名稱", "")
        enabled = acc.get("是否啟用") == "啟用"
        shell   = acc.get("Shell", "")
        uid     = acc.get("UID")
        account_type = acc.get("帳號類型", "")
        if not enabled:
            continue

        pw_exp = acc.get("密碼到期", "")
        last   = acc.get("上次登入", "")

        is_interactive = (
            name == "root"
            or account_type == "一般使用者"
            or (isinstance(uid, int) and uid >= 1000)
        )
        if is_interactive and shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin"):
            if pw_exp in ("永不到期", "never", "Never", ""):
                findings.append(_finding(
                    "account_anomaly", 1,
                    f"可互動帳號密碼永不到期: {name}",
                    f"帳號 {name} 可互動登入且密碼設定為永不到期，請確認是否符合帳號管理政策。",
                    acc,
                ))

        if account_type == "一般使用者" and name not in ("nobody",):
            findings.append(_finding(
                "account_inventory", 0,
                f"非系統帳號：{name}",
                f"UID={uid}，Shell={shell}。此類帳號應列入人員帳號盤點。",
                acc,
            ))

        # 長期未登入（> 180 天）
        if last and last not in ("", "從未登入"):
            for fmt in ("%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %z %Y", "%a %b %d %H:%M:%S %Y"):
                try:
                    dt = datetime.datetime.strptime(last.strip(), fmt)
                    if dt.tzinfo:
                        dt = dt.replace(tzinfo=None)
                    days = (now - dt).days
                    if days > 180:
                        findings.append(_finding(
                            "account_anomaly", 1,
                            f"帳號長期未登入: {name}",
                            f"最後登入 {last}（{days} 天前）",
                            acc,
                        ))
                    break
                except Exception:
                    continue

    return findings


def _analyze_password_policy(password_policy: list[dict]) -> list[dict]:
    findings: list[dict] = []
    policy = {item["設定"]: item["值"] for item in password_policy}

    def _int(key: str) -> int | None:
        v = str(policy.get(key, "")).strip()
        if v.upper() in ("UNLIMITED", "NEVER", "-1", "0", ""):
            return 0 if v not in ("", "UNLIMITED") else None
        try:
            return int(v)
        except Exception:
            return None

    # PASS_MIN_LEN
    min_len = _int("PASS_MIN_LEN")
    if min_len is not None and min_len < 8:
        findings.append(_finding(
            "password_policy", 2,
            "密碼最短長度不足（/etc/login.defs）",
            f"PASS_MIN_LEN = {min_len}，建議至少 8 字元",
            {"PASS_MIN_LEN": min_len},
        ))

    # PASS_MAX_DAYS
    max_days_str = policy.get("PASS_MAX_DAYS", "")
    try:
        max_days = int(max_days_str)
        if max_days == 99999 or max_days <= 0:
            findings.append(_finding(
                "password_policy", 2,
                "密碼永不過期（/etc/login.defs）",
                f"PASS_MAX_DAYS = {max_days}，密碼最長使用期限實際上為永不過期",
                {"PASS_MAX_DAYS": max_days},
            ))
    except Exception:
        pass

    return findings


def _analyze_antivirus(av_status: list[dict]) -> list[dict]:
    findings: list[dict] = []
    if not av_status:
        return findings
    if av_status[0].get("狀態") == "未安裝":
        findings.append(_finding(
            "endpoint_protection", 3,
            "未偵測到任何防毒 / 端點保護工具",
            "未找到 ClamAV、rkhunter、chkrootkit 等工具，建議安裝端點保護軟體。",
            {},
        ))
        return findings
    for av in av_status:
        if av.get("即時保護") and "停用" in av.get("即時保護", ""):
            findings.append(_finding(
                "endpoint_protection", 2,
                f"{av['工具']} 已安裝但即時保護停用",
                f"{av['工具']} daemon 未在執行中，即時保護未啟用。",
                av,
            ))
    return findings


def _analyze_startup_items(startup_items: list[dict]) -> list[dict]:
    findings: list[dict] = []
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
        for pattern, sev in _SUSPICIOUS_CMDLINE:
            if re.search(pattern, cmd, re.I):
                findings.append(_finding(
                    "suspicious_startup", sev,
                    f"啟動項目命令含可疑特徵: {name}",
                    f"來源: {source}\n命令: {item.get('命令/路徑','')[:200]}",
                    item,
                ))
                break
    return findings



def _analyze_firewall(firewall_data: list[dict]) -> list[dict]:
    if _firewall_assessment(firewall_data) != "FAIL":
        return []
    return [_finding(
        "firewall", 3, "未偵測到啟用的主機防火牆",
        "已查得的防火牆均未啟用或未偵測到封包阻擋政策；請確認主機防護設定。",
        {"防火牆": firewall_data},
    )]


def _analyze_smb(smb_data: list[dict]) -> list[dict]:
    findings: list[dict] = []
    cfg = {item.get("設定", ""): str(item.get("值", "")) for item in smb_data}
    svc = cfg.get("Samba 服務狀態", "")
    if not smb_data or cfg.get("Samba", "").startswith("未安裝"):
        return findings

    if "active" not in svc.lower() and "running" not in svc.lower():
        findings.append(_finding(
            "network_share", 0,
            "Samba 已安裝但服務未啟用",
            f"smbd 狀態：{svc}。目前未對外提供 SMB 分享，僅列資訊。",
            {"Samba 服務狀態": svc},
        ))
        return findings

    proto = (
        cfg.get("server min protocol")
        or cfg.get("smb.conf min protocol")
        or cfg.get("min protocol")
        or ""
    ).upper()
    if proto in ("NT1", "LANMAN1", "CORE", "COREPLUS"):
        findings.append(_finding(
            "smb_risk", 4,
            "Samba SMBv1 已啟用",
            "SMBv1 存在 EternalBlue 等嚴重漏洞，建議在 smb.conf 加入：\nmin protocol = SMB2",
            {"server min protocol": proto},
        ))
    elif not proto or proto in ("未設定", "DEFAULT"):
        findings.append(_finding(
            "smb_risk", 2,
            "Samba 未明確限制最低 SMB 協定",
            "smbd 正在執行，但未明確設定 server min protocol，建議設定為 SMB2 或以上。",
            cfg,
        ))
    return findings


def _analyze_updates(update_status: list[dict]) -> list[dict]:
    findings: list[dict] = []
    data = {item.get("項目", ""): item.get("內容", "") for item in update_status}
    try:
        count = int(data.get("可更新套件數", "0"))
        if count >= 50:
            findings.append(_finding(
                "patch_management", 3,
                f"可更新套件過多：{count} 個",
                "系統存在大量尚未更新套件，建議安排弱點修補與版本更新。",
                {"可更新套件數": count},
            ))
        elif count > 0:
            findings.append(_finding(
                "patch_management", 2,
                f"存在可更新套件：{count} 個",
                "系統有尚未套用的套件更新，請確認是否包含安全性修補。",
                {"可更新套件數": count},
            ))
    except Exception:
        pass
    return findings


def _analyze_privileged_accounts(priv_accounts: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for acc in priv_accounts:
        name = acc.get("帳號", "")
        source = acc.get("權限來源", "")
        if not source:
            continue
        if source == "UID 0" and name != "root":
            findings.append(_finding(
                "privileged_account", 4,
                f"非 root 帳號具有 UID 0：{name}",
                f"{name} 擁有等同 root 的完整權限，應立即確認必要性。",
                acc,
            ))
        elif source in ("sudo", "wheel", "admin"):
            findings.append(_finding(
                "privileged_account", 1,
                f"管理權限帳號：{name}",
                f"{name} 屬於 {source} 群組，應列入特權帳號盤點。",
                acc,
            ))
    return findings


def _analyze_ssh_security(ssh_rows: list[dict]) -> list[dict]:
    findings: list[dict] = []
    cfg = {item.get("設定", ""): str(item.get("值", "")).lower() for item in ssh_rows}
    if cfg.get("openssh server", "").startswith("未安裝"):
        return findings

    root_login = cfg.get("允許 root 登入", "")
    if root_login in ("yes", "without-password", "prohibit-password"):
        findings.append(_finding(
            "ssh_security", 3 if root_login == "yes" else 2,
            "SSH 允許 root 登入",
            f"PermitRootLogin = {root_login}，建議停用 root 直接登入，改用一般帳號加 sudo。",
            {"PermitRootLogin": root_login},
        ))

    pass_auth = cfg.get("允許密碼登入", "")
    if pass_auth == "yes":
        findings.append(_finding(
            "ssh_security", 2,
            "SSH 允許密碼登入",
            "PasswordAuthentication = yes，建議改用金鑰登入並搭配 MFA / VPN / IP 限制。",
            {"PasswordAuthentication": pass_auth},
        ))

    empty_pw = cfg.get("允許空密碼", "")
    if empty_pw == "yes":
        findings.append(_finding(
            "ssh_security", 4,
            "SSH 允許空密碼登入",
            "PermitEmptyPasswords = yes，這是高風險設定，應立即關閉。",
            {"PermitEmptyPasswords": empty_pw},
        ))
    return findings


def _analyze_kernel_hardening(rows: list[dict]) -> list[dict]:
    findings: list[dict] = []
    vals = {item.get("sysctl", ""): item.get("值", "") for item in rows}
    expected = {
        "kernel.randomize_va_space": ("2", 2, "ASLR 未完整啟用"),
        "net.ipv4.ip_forward": ("0", 2, "IPv4 轉送已啟用"),
        "net.ipv4.conf.all.accept_redirects": ("0", 2, "允許 ICMP Redirect"),
        "net.ipv4.conf.all.send_redirects": ("0", 2, "允許送出 ICMP Redirect"),
        "net.ipv4.tcp_syncookies": ("1", 2, "SYN Cookies 未啟用"),
        "kernel.kptr_restrict": ("1", 1, "kernel pointer 保護不足"),
        "kernel.dmesg_restrict": ("1", 1, "dmesg 未限制讀取"),
    }
    for key, (want, sev, title) in expected.items():
        val = str(vals.get(key, ""))
        if val and val != want:
            findings.append(_finding(
                "kernel_hardening", sev,
                title,
                f"{key} = {val}，建議值為 {want}。",
                {"sysctl": key, "值": val, "建議值": want},
            ))
    return findings


def _analyze_mac_status(rows: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for row in rows:
        mechanism = row.get("機制", "")
        status = row.get("狀態", "")
        status_l = status.lower()
        if mechanism == "AppArmor" and ("not" in status_l or "未偵測" in status):
            findings.append(_finding(
                "mandatory_access_control", 1,
                "AppArmor 未啟用或未偵測",
                "建議依發行版支援狀況啟用 AppArmor 或 SELinux，提高程序隔離能力。",
                row,
            ))
        if mechanism == "SELinux" and status in ("Disabled", "Permissive"):
            findings.append(_finding(
                "mandatory_access_control", 1,
                f"SELinux 狀態：{status}",
                "建議評估是否可設為 Enforcing，或確認已由 AppArmor 提供等效保護。",
                row,
            ))
    return findings


def _analyze_file_permission_risks(rows: list[dict]) -> list[dict]:
    findings: list[dict] = []
    risky = [r for r in rows if r.get("路徑")]
    suid = [r for r in risky if r.get("類型") == "SUID 檔案"]
    ww = [r for r in risky if r.get("類型") == "全域可寫目錄"]
    if len(suid) > 30:
        findings.append(_finding(
            "file_permission", 2,
            f"SUID 檔案數量偏多：{len(suid)}",
            "SUID 檔案應定期盤點，避免被利用進行權限提升。",
            {"SUID 檔案數": len(suid), "前幾筆": suid[:10]},
        ))
    if ww:
        findings.append(_finding(
            "file_permission", 2,
            f"發現全域可寫目錄：{len(ww)} 個",
            "全域可寫目錄需確認 sticky bit 與用途，避免被植入或覆寫檔案。",
            {"全域可寫目錄": ww[:20]},
        ))
    return findings


def _analyze_shared_folders(shared_data: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for share in shared_data:
        findings.append(_finding(
            "shared_folder", 2,
            f"偵測到共用資料夾：{share.get('共用名稱', '')}（{share.get('類型','')}）",
            f"路徑：{share.get('路徑','')}　請確認存取權限是否符合最小權限原則。",
            share,
        ))
    return findings


def _analyze_audit_policy(audit_data: list[dict]) -> list[dict]:
    findings: list[dict] = []
    audit_map = {item.get("稽核類別", ""): item.get("稽核設定", "") for item in audit_data}

    svc_status = audit_map.get("auditd 服務狀態", "")
    auditctl_missing = audit_map.get("auditctl") == "未安裝或無法執行（需 root）"
    if auditctl_missing:
        findings.append(_finding(
            "audit_policy", 2,
            "auditd 未安裝或無法執行",
            "未偵測到 auditd / auditctl，或未以 root 執行導致無法讀取稽核規則。",
            {},
        ))
        return findings

    if svc_status and svc_status not in ("active", "running"):
        findings.append(_finding(
            "audit_policy", 2,
            "auditd 服務未運行",
            f"auditd 狀態：{svc_status}。無法記錄系統稽核事件，出事時難以追查。",
            {"auditd": svc_status},
        ))

    rule_entries = [v for k, v in audit_map.items() if k == "稽核規則"]
    if any("無規則" in v or "No auditing" in v for v in rule_entries):
        findings.append(_finding(
            "audit_policy", 2,
            "auditd 無稽核規則",
            "auditd 已安裝但無設定任何稽核規則，等同未啟用稽核。\n"
            "建議安裝 auditd 規則集，例如：apt install auditd audispd-plugins",
            {},
        ))

    return findings


def _analyze_hosts_file(hosts_data: list[dict]) -> list[dict]:
    findings: list[dict] = []
    non_std = []
    local_hostname = platform.node()
    for h in hosts_data:
        if h.get("是否標準") != "否" or not h.get("IP"):
            continue
        # Debian / Ubuntu / Kali 常見：127.0.1.1 hostname，屬正常主機名解析。
        if h.get("IP") == "127.0.1.1" and h.get("主機名稱") == local_hostname:
            continue
        non_std.append(h)
    if non_std:
        lines = [f"  {h['IP']}\t{h['主機名稱']}" for h in non_std[:20]]
        findings.append(_finding(
            "hosts_tampering", 3,
            f"hosts 檔案含 {len(non_std)} 筆非標準記錄",
            "可能為 DNS 劫持或惡意重導向，請確認以下記錄是否合法：\n" + "\n".join(lines),
            {"非標準記錄": non_std},
        ))
    return findings


def analyze_findings(report_data: dict) -> list[dict]:
    findings: list[dict] = []
    findings += _analyze_updates(report_data.get("更新狀態", []))
    findings += _analyze_processes(
        report_data.get("執行中程序", []),
        report_data.get("程序雜湊",   []),
    )
    findings += _analyze_netstat(report_data.get("網路連線", []))
    findings += _analyze_accounts(report_data.get("使用者帳號", []))
    findings += _analyze_privileged_accounts(report_data.get("特權帳號", []))
    findings += _analyze_password_policy(report_data.get("密碼原則", []))
    findings += _analyze_ssh_security(report_data.get("SSH安全設定", []))
    findings += _analyze_antivirus(report_data.get("防毒工具", []))
    findings += _analyze_startup_items(report_data.get("啟動項目", []))
    findings += _analyze_firewall(report_data.get("防火牆狀態", []))
    findings += _analyze_smb(report_data.get("SMB狀態", []))
    findings += _analyze_shared_folders(report_data.get("網路分享", []))
    findings += _analyze_audit_policy(report_data.get("稽核原則", []))
    findings += _analyze_kernel_hardening(report_data.get("KernelHardening", []))
    findings += _analyze_mac_status(report_data.get("MAC保護", []))
    findings += _analyze_file_permission_risks(report_data.get("檔案權限風險", []))
    findings += _analyze_hosts_file(report_data.get("Hosts檔案", []))
    return findings


def calculate_risk(findings: list[dict]) -> tuple[int, str]:
    """主機初步風險（0–100, 等級）——委派共用計分模組 h2c_scoring（scoring v2）。

    與 VANS 同一套公式；VANS 會再加入 CVE / 情資 findings 重算正式分數。
    """
    return host_score(findings)



def build_compliance_summary(report_data: dict, findings: list[dict]) -> list[dict]:
    """彙整已取得的資料並標明未能判定的項目。"""
    collection = report_data.get("meta", {}).get("collection_status", {})
    policy = {item.get("設定"): item.get("值") for item in report_data.get("密碼原則", [])}
    users = report_data.get("使用者帳號", [])
    priv = report_data.get("特權帳號", [])
    av = report_data.get("防毒工具", [])
    fw = report_data.get("防火牆狀態", [])
    ssh = {item.get("設定"): item.get("值", "") for item in report_data.get("SSH安全設定", [])}
    audit = {item.get("稽核類別"): item.get("稽核設定", "") for item in report_data.get("稽核原則", [])}
    updates = {item.get("項目"): item.get("內容") for item in report_data.get("更新狀態", [])}
    shares = report_data.get("網路分享", []) or report_data.get("共用資料夾", [])
    listening = [
        conn for conn in report_data.get("網路連線", [])
        if str(conn.get("狀態", "")).upper() in ("LISTEN", "LISTENING", "UNCONN")
    ]
    summary = []

    def add(section: str, item: str, value: str, status: str, suggestion: str) -> None:
        if collection.get(section) == "failed":
            value, status = "無法取得", "UNKNOWN"
        summary.append({"檢核項目": item, "目前狀態": value, "判定": status, "建議": suggestion})

    for key, name, passes, failure, tip in [
        ("PASS_MIN_LEN", "密碼最短長度", lambda n: n >= 8, "FAIL", "請確認 PAM 與 login.defs 的密碼長度政策。"),
        ("PASS_MAX_DAYS", "密碼最長期限", lambda n: 0 < n <= 180, "WARN", "建議依機關政策設定密碼期限。"),
    ]:
        value = str(policy.get(key, "未取得"))
        try:
            status = "PASS" if passes(int(value)) else failure
        except ValueError:
            status = "UNKNOWN"
        add("密碼原則", name, value, status, tip)

    interactive = [user for user in users if (user.get("帳號類型") == "一般使用者" or user.get("帳號名稱") == "root")
                   and user.get("是否啟用") == "啟用"]
    user_count_known = collection.get("使用者帳號") == "ok" or any(user.get("是否啟用") for user in users)
    add("使用者帳號", "非系統帳號 / 可互動帳號", f"{len(interactive)} 個" if user_count_known else "無資料",
        "INFO" if user_count_known else "UNKNOWN", "請確認帳號用途及人員異動後的停用流程。")

    priv_count = sum(bool(account.get("權限來源")) for account in priv)
    priv_known = bool(priv_count) or collection.get("特權帳號") == "ok"
    add("特權帳號", "特權帳號", f"{priv_count} 個" if priv_known else "無資料",
        ("WARN" if priv_count > 1 else "PASS") if priv_known else "UNKNOWN", "請定期盤點 sudo / wheel / UID 0。")

    av_states = {tool.get("狀態") for tool in av}
    av_status = "UNKNOWN"
    if "無法取得" not in av_states:
        if "已安裝" in av_states:
            av_status = "INFO"
        elif "未安裝" in av_states:
            av_status = "WARN"
    add("防毒工具", "防毒 / 端點防護", "、".join(tool.get("工具", "") for tool in av) or "無資料",
        av_status, "請依主機用途確認端點防護工具及保護狀態。")

    firewall_value = "；".join(f"{item.get('防火牆類型')}={item.get('啟用')}" for item in fw)
    add("防火牆狀態", "主機防火牆", firewall_value or "無資料", _firewall_assessment(fw),
        "請確認 nftables / iptables 的有效政策及管理工具狀態。")

    root_login = ssh.get("允許 root 登入", "")
    pass_auth = ssh.get("允許密碼登入", "")
    empty_passwords = ssh.get("允許空密碼", "")
    ssh_status = "UNKNOWN"
    if empty_passwords == "yes":
        ssh_status = "FAIL"
    elif root_login == "yes" or pass_auth == "yes":
        ssh_status = "WARN"
    elif (root_login in ("no", "prohibit-password", "without-password", "forced-commands-only")
          and pass_auth == empty_passwords == "no"):
        ssh_status = "PASS"
    add("SSH安全設定", "SSH 登入安全",
        f"RootLogin={root_login or '未知'}, PasswordAuth={pass_auth or '未知'}, EmptyPasswords={empty_passwords or '未知'}",
        ssh_status, "請確認有效設定，並依連線條件檢視 Match 規則。")

    audit_state = audit.get("auditd 服務狀態", "")
    audit_rules = audit.get("稽核規則", "")
    audit_status = "UNKNOWN"
    if audit_state in ("inactive", "failed") or audit_rules.startswith("無規則"):
        audit_status = "WARN"
    elif audit_state == "active" and audit_rules:
        audit_status = "PASS"
    add("稽核原則", "稽核記錄 auditd", audit_state or "未知", audit_status,
        "請確認 auditd 服務狀態及已載入的稽核規則。")

    update_count = str(updates.get("可更新套件數", "未知"))
    update_status = ("INFO" if update_count == "0" else "WARN") if update_count.isdecimal() else "UNKNOWN"
    add("更新狀態", "修補 / 更新狀態", update_count, update_status,
        "資料來自本機套件索引，請確認索引更新時間與安全性修補狀態。")

    listeners_known = collection.get("網路連線") == "ok" or bool(listening)
    add("網路連線", "對外監聽服務", f"{len(listening)} 個" if listeners_known else "無資料",
        ("INFO" if listening else "PASS") if listeners_known else "UNKNOWN",
        "請確認監聽服務的業務必要性、來源限制與防火牆規則。")

    shares_known = collection.get("網路分享") == "ok" or bool(shares)
    add("網路分享", "網路分享 / 對外目錄", f"{len(shares)} 筆" if shares_known else "無資料",
        ("WARN" if shares else "PASS") if shares_known else "UNKNOWN",
        "請確認 Samba / NFS 共用的最小權限與存取控制。")

    return summary


# ─────────────────────────────────────────────────────────────────────────────
# HTML 產生（與 Windows 版相同，自含式）
# ─────────────────────────────────────────────────────────────────────────────
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Noto Sans TC', Arial, sans-serif; font-size: 13px;
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
.ns-LISTEN, .ns-LISTENING { background: #cff4fc; }
.status { display:inline-block; min-width:56px; text-align:center; padding:3px 8px; border-radius:10px; color:#fff; font-weight:700; font-size:11px; }
.st-PASS { background:#198754; }
.st-WARN { background:#ffc107; color:#212529; }
.st-FAIL { background:#dc3545; }
.st-INFO { background:#0dcaf0; color:#212529; }
.st-UNKNOWN { background:#6c757d; }
.focus-note { color:#6c757d; font-size:12px; margin-bottom:10px; }
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


def _section_table(data: list, tid: str) -> str:
    if not data:
        return '<p style="color:#6c757d;padding:8px">無資料</p>'
    if not (isinstance(data, list) and data and isinstance(data[0], dict)):
        return "".join(f"<p>{item}</p>" for item in data)
    headers = list(data[0].keys())
    h = [
        f'<div class="search"><input placeholder="搜尋..." oninput="filterT(this,\'{tid}\')"></div>',
        f'<div class="tbl-wrap"><table id="{tid}"><thead><tr>',
    ]
    for i, hdr in enumerate(headers):
        h.append(f'<th onclick="sortT(\'{tid}\',{i})">{hdr} ↕</th>')
    h.append("</tr></thead><tbody>")
    for item in data:
        h.append("<tr>")
        for hdr in headers:
            val = item.get(hdr, "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            h.append(f"<td>{html.escape(str(val))}</td>")
        h.append("</tr>")
    h.append("</tbody></table></div>")
    return "\n".join(h)


def _netstat_table(data: list) -> str:
    if not data:
        return '<p style="color:#6c757d;padding:8px">無資料</p>'
    headers = ["協定", "本地位址", "遠端位址", "狀態", "PID", "程序名稱"]
    h = [
        '<div class="search"><input placeholder="搜尋..." oninput="filterT(this,\'ns_t\')"></div>',
        '<div class="tbl-wrap"><table id="ns_t"><thead><tr>',
    ]
    for i, hdr in enumerate(headers):
        h.append(f'<th onclick="sortT(\'ns_t\',{i})">{hdr} ↕</th>')
    h.append("</tr></thead><tbody>")
    for item in data:
        state = item.get("狀態", "")
        cls   = f"ns-{state}" if state in ("ESTABLISHED", "LISTEN", "LISTENING") else ""
        h.append(f'<tr class="{cls}">')
        for hdr in headers:
            h.append(f"<td>{html.escape(str(item.get(hdr, '')))}</td>")
        h.append("</tr>")
    h.append("</tbody></table></div>")
    return "\n".join(h)


def _focus_table(summary: list[dict]) -> str:
    headers = ["檢核項目", "目前狀態", "判定", "建議"]
    h = ['<p class="focus-note">以下為行政院資安健診常見關注項目，方便先看重點；詳細原始資料仍保留在下方各章節。</p>']
    h.append('<div class="tbl-wrap"><table id="focus_t"><thead><tr>')
    for i, hdr in enumerate(headers):
        h.append(f'<th onclick="sortT(\'focus_t\',{i})">{hdr} ↕</th>')
    h.append("</tr></thead><tbody>")
    for item in summary:
        status = str(item.get("判定", "INFO")).upper()
        h.append("<tr>")
        h.append(f"<td>{html.escape(str(item.get('檢核項目', '')))}</td>")
        h.append(f"<td>{html.escape(str(item.get('目前狀態', '')))}</td>")
        h.append(f'<td><span class="status st-{status}">{status}</span></td>')
        h.append(f"<td>{html.escape(str(item.get('建議', '')))}</td>")
        h.append("</tr>")
    h.append("</tbody></table></div>")
    return "\n".join(h)


def generate_html(computer_name: str, local_ip: str, report_data: dict,
                  findings: list, risk_score: int, risk_level: str) -> str:
    sc = {s: sum(1 for f in findings if f.get("severity") == s) for s in (4, 3, 2, 1, 0)}
    risk_color = RISK_COLORS.get(risk_level, "#6c757d")
    now_str    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    focus_summary = build_compliance_summary(report_data, findings)
    collection = report_data.get("meta", {}).get("collection_status", {})
    failed = [section for section, status in collection.items() if status == "failed"]
    unknown = [row["檢核項目"] for row in focus_summary if row["判定"] == "UNKNOWN"]
    coverage = ""
    if failed or unknown:
        detail = "；".join(filter(None, [
            f"收集失敗：{'、'.join(failed)}" if failed else "",
            f"無法判定：{'、'.join(unknown)}" if unknown else "",
        ]))
        coverage = f'<p class="focus-note"><strong>部分檢查未完成</strong>。{html.escape(detail)}</p>'

    def findings_rows() -> str:
        rows = []
        for f in sorted(findings, key=lambda x: -x.get("severity", 0)):
            sev    = f.get("severity", 0)
            color  = SEVERITY_COLOR.get(sev, "#6c757d")
            badge  = f'<span class="badge" style="background:{color}">{SEVERITY_LABEL.get(sev,"?")}</span>'
            detail = html.escape(f.get("detail") or "").replace("\n", "<br>")
            rows.append(
                f"<tr><td>{badge}</td>"
                f"<td>{html.escape(f.get('category',''))}</td>"
                f"<td>{html.escape(f.get('title',''))}</td>"
                f"<td>{detail}</td></tr>"
            )
        if not rows:
            return '<tr><td colspan="4" style="color:#6c757d;text-align:center">無風險項目</td></tr>'
        return "\n".join(rows)

    sections = [
        ("系統資訊",             "sys_t",       report_data.get("系統資訊",        [])),
        ("修補 / 更新狀態",       "upd_t",       report_data.get("更新狀態",        [])),
        ("帳號與權限",           "usr_t",       report_data.get("使用者帳號",      [])),
        ("特權帳號",             "priv_t",      report_data.get("特權帳號",        [])),
        ("密碼 / PAM 原則",       "pol_t",       report_data.get("密碼原則",        [])),
        ("SSH 安全設定",         "ssh_t",       report_data.get("SSH安全設定",     [])),
        ("防毒 / 端點防護",       "av_t",        report_data.get("防毒工具",        [])),
        ("防火牆狀態",           "fw_t",        report_data.get("防火牆狀態",      [])),
        ("網路設定",             "net_t",       report_data.get("網路設定",        [])),
        ("對外監聽 / 網路連線",   "conn_t",      report_data.get("網路連線",        [])),
        ("啟動服務與排程",       "startup_t",   report_data.get("啟動項目",        [])),
        ("稽核與日誌",           "audit_t",     report_data.get("稽核原則",        [])),
        ("Kernel Hardening",     "kernel_t",    report_data.get("KernelHardening", [])),
        ("SELinux / AppArmor",   "mac_t",       report_data.get("MAC保護",         [])),
        ("檔案權限風險",         "perm_t",      report_data.get("檔案權限風險",    [])),
        ("網路分享 / 對外目錄",   "share_t",     report_data.get("網路分享",        [])),
        ("Samba 設定",           "samba_t",     report_data.get("SMB狀態",         [])),
        ("容器環境",             "container_t", report_data.get("容器環境",        [])),
        ("Hosts 檔案",           "hosts_t",     report_data.get("Hosts檔案",       [])),
        ("已安裝套件",           "pkg_t",       report_data.get("已安裝套件",      [])),
        ("執行中程序",           "proc_t",      report_data.get("執行中程序",      [])),
        ("程序情資素材 / Hash 清單", "hash_t",   report_data.get("程序雜湊",        [])),
    ]
    nav = " ".join(
        f'<a href="#{aid}">{label}</a>'
        for label, aid in [("健診重點", "focus_sec"), ("風險摘要", "findings_sec")]
                          + [(t, f"sec_{i}") for t, i, _ in sections]
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
<title>H2C Linux 健診 — {computer_name} ({local_ip})</title>
<style>{_CSS}</style>
</head>
<body>
<div class="topbar">
  <span class="brand">H2C Linux 健診</span>
  {nav}
</div>
<div class="container">
  <h1>Linux 資安健診報告</h1>
  <p class="meta-line">
    主機：<strong>{computer_name}</strong> &nbsp;|&nbsp;
    IP：<strong>{local_ip}</strong> &nbsp;|&nbsp;
    產生時間：{now_str}
  </p>
  {coverage}
  <div class="card" id="focus_sec">
    <div class="card-header">行政院資安健診重點摘要</div>
    <div class="card-body">{_focus_table(focus_summary)}</div>
  </div>
  <div class="card" id="findings_sec">
    <div class="card-header">
      風險摘要（初步評分：僅本機規則，正式分數以 VANS 為準）
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
            <th>說明</th>
          </tr></thead>
          <tbody>{findings_rows()}</tbody>
        </table>
      </div>
    </div>
  </div>
{cards}
</div>
<script>{_JS}</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# XLSX 產生
# ─────────────────────────────────────────────────────────────────────────────
_XLSX_INVALID_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _safe_cell(val):
    if val is None or isinstance(val, (int, float)):
        return val
    text = _XLSX_INVALID_XML.sub("", str(val))
    if text.startswith(("=", "+", "-", "@", "|", "%")):
        return "'" + text
    return text


def _write_sheet(ws, data: list, field_order: list | None = None) -> None:
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
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            row.append(_safe_cell(val))
        ws.append(row)


def generate_xlsx(report_data: dict, findings: list) -> "Workbook":
    wb = Workbook()
    ws = wb.active
    ws.title = "健診重點"
    focus = build_compliance_summary(report_data, findings)
    _write_sheet(ws, focus, ["檢核項目", "目前狀態", "判定", "建議"])

    ws = wb.create_sheet("風險摘要")
    ws.append(["類別", "嚴重度", "標題", "說明", "狀態"])
    for f in sorted(findings, key=lambda x: -x.get("severity", 0)):
        ws.append([
            _safe_cell(f.get("category", "")),
            SEVERITY_LABEL.get(f.get("severity", 0), ""),
            _safe_cell(f.get("title", "")),
            _safe_cell(f.get("detail", "")),
            _safe_cell(f.get("status", "open")),
        ])

    sheet_cfg = [
        ("系統資訊",         report_data.get("系統資訊",   []),  ["項目", "內容"]),
        ("更新狀態",         report_data.get("更新狀態",   []),  ["項目", "內容"]),
        ("防毒工具",         report_data.get("防毒工具",   []),  ["工具", "版本", "狀態", "即時保護"]),
        ("已安裝套件",       report_data.get("已安裝套件", []),  ["名稱", "版本", "架構", "描述"]),
        ("使用者帳號",       report_data.get("使用者帳號", []),
         ["帳號名稱", "UID", "是否啟用", "帳號類型", "描述", "Shell", "上次登入", "密碼到期", "所屬群組"]),
        ("特權帳號",         report_data.get("特權帳號",   []),  ["帳號", "權限來源", "UID", "Shell"]),
        ("密碼原則",         report_data.get("密碼原則",   []),  ["設定", "值"]),
        ("SSH安全設定",      report_data.get("SSH安全設定", []), ["設定", "值", "狀態"]),
        ("網路設定",         report_data.get("網路設定",   []),  ["介面名稱", "IP位址", "子網前綴", "DNS server"]),
        ("啟動項目",         report_data.get("啟動項目",   []),  ["來源", "名稱", "狀態", "命令/路徑"]),
        ("執行中程序",       report_data.get("執行中程序", []),
         ["程序名稱", "PID", "父PID", "執行路徑", "命令列", "記憶體(KB)"]),
        ("程序情資素材",     report_data.get("程序雜湊",   []),
         ["程序名稱", "PID", "執行路徑", "SHA256", "hash_status", "套件來源",
          "是否已刪除", "vt_status", "threat_source", "first_seen", "last_seen"]),
        ("網路連線",         report_data.get("網路連線",   []),  ["協定", "本地位址", "遠端位址", "狀態", "PID", "程序名稱"]),
        ("防火牆狀態",       report_data.get("防火牆狀態", []),  ["防火牆類型", "設定檔", "啟用", "詳細資訊"]),
        ("SMB狀態",          report_data.get("SMB狀態",    []),  ["設定", "值"]),
        ("網路分享",         report_data.get("網路分享",   []),  ["共用名稱", "路徑", "說明", "類型"]),
        ("稽核原則",         report_data.get("稽核原則",   []),  ["稽核類別", "稽核設定"]),
        ("KernelHardening",  report_data.get("KernelHardening", []), ["項目", "sysctl", "值"]),
        ("MAC保護",          report_data.get("MAC保護", []), ["機制", "狀態", "詳細"]),
        ("容器環境",         report_data.get("容器環境", []), ["Runtime", "名稱", "映像", "狀態", "Port"]),
        ("檔案權限風險",     report_data.get("檔案權限風險", []), ["類型", "路徑", "說明"]),
        ("Hosts檔案",        report_data.get("Hosts檔案",  []),  ["行號", "IP", "主機名稱", "完整內容", "是否標準"]),
    ]
    for sheet_name, data, fields in sheet_cfg:
        _write_sheet(wb.create_sheet(sheet_name), data, fields)

    return wb


# ─────────────────────────────────────────────────────────────────────────────
# 打包 .h2cpc.zip
# ─────────────────────────────────────────────────────────────────────────────
def package_zip(base_name: str, report_data: dict, findings: list,
                risk_score: int, risk_level: str,
                computer_name: str, local_ip: str) -> str:
    now = datetime.datetime.now()
    report_json_bytes   = json.dumps(report_data, ensure_ascii=False, indent=2).encode("utf-8")
    findings_with_id    = [dict(f, id=f"linux:{f['category']}:{i}") for i, f in enumerate(findings)]
    findings_json_bytes = json.dumps(findings_with_id, ensure_ascii=False, indent=2).encode("utf-8")
    html_bytes          = generate_html(computer_name, local_ip, report_data, findings, risk_score, risk_level).encode("utf-8")
    buf = io.BytesIO()
    generate_xlsx(report_data, findings).save(buf)
    xlsx_bytes = buf.getvalue()

    meta = {
        "tool":          "H2C_PcSecCheck_linux",
        "version":       TOOL_VERSION,
        "schema_ver":    SCHEMA_VERSION,
        "scoring_ver":   SCORING_VERSION,
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
        zf.writestr("meta.json",                    meta_json_bytes)
        zf.writestr(f"{base_name}.report.json",     report_json_bytes)
        zf.writestr(f"{base_name}.findings.json",   findings_json_bytes)
        zf.writestr(f"{base_name}.report.html",     html_bytes)
        zf.writestr(f"{base_name}.report.xlsx",     xlsx_bytes)
    return zip_filename


# ─────────────────────────────────────────────────────────────────────────────
# 主程式
# ─────────────────────────────────────────────────────────────────────────────
def _print(msg: str) -> None:
    print(msg, flush=True)


def main() -> None:
    import sys

    if os.geteuid() != 0:
        _print("[警告] 建議以 root（sudo）執行，否則部分資料將無法收集。")
        _print("")

    computer_name = platform.node()
    local_ip      = get_local_ip_address()
    ts            = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    base_name     = f"{computer_name}_{local_ip}_{ts}"

    _print("=" * 56)
    _print("  H2C Linux 資安健診工具  v2.0")
    _print(f"  主機：{computer_name}   IP：{local_ip}")
    _print("=" * 56)
    _print("")

    steps = [
        ("[1/22]  取得系統資訊...",              get_system_info,          "系統資訊"),
        ("[2/22]  取得修補 / 更新狀態...",       get_update_status,        "更新狀態"),
        ("[3/22]  偵測防毒 / 端點防護...",       get_av_status,            "防毒工具"),
        ("[4/22]  取得已安裝套件...",            get_installed_packages,   "已安裝套件"),
        ("[5/22]  取得使用者帳號...",            get_local_user_accounts,  "使用者帳號"),
        ("[6/22]  取得特權帳號...",              get_privileged_accounts,  "特權帳號"),
        ("[7/22]  取得密碼 / PAM 原則...",       get_password_policy,      "密碼原則"),
        ("[8/22]  取得 SSH 安全設定...",         get_ssh_security,         "SSH安全設定"),
        ("[9/22]  取得網路設定...",              get_network_settings,     "網路設定"),
        ("[10/22] 取得啟動服務與排程...",        get_startup_items,        "啟動項目"),
        ("[11/22] 取得執行中程序...",            get_processes,            "執行中程序"),
        ("[12/22] 收集程序情資素材 / SHA256...", get_process_hashes,       "程序雜湊"),
        ("[13/22] 取得對外監聽 / 網路連線...",   get_netstat,              "網路連線"),
        ("[14/22] 取得防火牆狀態...",            get_firewall_status,      "防火牆狀態"),
        ("[15/22] 取得 Samba 設定...",           get_smb_status,           "SMB狀態"),
        ("[16/22] 取得網路分享 / 對外目錄...",   get_shared_folders,       "網路分享"),
        ("[17/22] 取得稽核與日誌設定...",        get_audit_policy,         "稽核原則"),
        ("[18/22] 取得 Kernel hardening...",     get_kernel_hardening,     "KernelHardening"),
        ("[19/22] 取得 SELinux / AppArmor...",   get_mac_status,           "MAC保護"),
        ("[20/22] 取得容器環境...",              get_container_status,     "容器環境"),
        ("[21/22] 取得檔案權限風險...",          get_file_permission_risks,"檔案權限風險"),
        ("[22/22] 讀取 hosts 檔案...",           get_hosts_file,           "Hosts檔案"),
    ]

    report_data: dict = {
        "meta": {
            "tool":          "H2C_PcSecCheck_linux",
            "version":       TOOL_VERSION,
            "schema_ver":    SCHEMA_VERSION,
            "computer_name": computer_name,
            "local_ip":      local_ip,
            "generated_at":  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "collection_status": {},
        }
    }
    collection = report_data["meta"]["collection_status"]
    for label, func, key in steps:
        _print(label)
        try:
            report_data[key] = func()
            collection[key] = "ok"
        except Exception as e:
            _print(f"  [錯誤] {key}: {e}")
            report_data[key] = []
            collection[key] = "failed"

    _print("\n[分析] 執行風險評估...")
    findings               = analyze_findings(report_data)
    risk_score, risk_level = calculate_risk(findings)
    _print(f"[分析] 發現 {len(findings)} 個風險項目，等級: {risk_level.upper()} ({risk_score}/100)")

    _print("[打包] 產生 .h2cpc.zip...")
    zip_file = package_zip(base_name, report_data, findings, risk_score, risk_level, computer_name, local_ip)

    _print("")
    _print("=" * 56)
    _print(f"  完成！輸出：{zip_file}")
    _print(f"  初步風險等級：{risk_level.upper()} ({risk_score}/100)")
    for sev, label in [(4, "Critical"), (3, "High"), (2, "Medium"), (1, "Low"), (0, "Info")]:
        cnt = sum(1 for f in findings if f.get("severity") == sev)
        if cnt:
            _print(f"    {label:8s}: {cnt}")
    _print("=" * 56)
    _print("  請將 .h2cpc.zip 繳交給資安健診人員")
    _print("=" * 56)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[中斷] 使用者取消執行", flush=True)
    except Exception as e:
        print(f"\n[錯誤] {e}", flush=True)
        import traceback
        traceback.print_exc()
    input("\n按 Enter 鍵關閉視窗...")
