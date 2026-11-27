"""Linux 資料收集與報告匯出的回歸測試。"""
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import zipfile

import pytest
from openpyxl import load_workbook

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import H2C_PcSecCheck_linux as linux  # noqa: E402


def mock_commands(monkeypatch, responses):
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return responses.get(cmd[0], linux.CommandResult(missing=True))

    monkeypatch.setattr(linux, "_command", run)
    return calls


def summary(report):
    return {row["檢核項目"]: row["判定"] for row in linux.build_compliance_summary(report, [])}


def test_empty_report_and_failed_collector_cannot_pass():
    assert set(summary({}).values()) == {"UNKNOWN"}
    report = {
        "meta": {"collection_status": {"網路連線": "ok", "網路分享": "ok", "防火牆狀態": "failed"}},
        "網路連線": [],
        "網路分享": [],
        "防火牆狀態": [{"防火牆類型": "ufw", "啟用": "是"}],
    }
    statuses = summary(report)
    assert statuses["對外監聽服務"] == statuses["網路分享 / 對外目錄"] == "PASS"
    assert statuses["主機防火牆"] == "UNKNOWN"
    report_html = linux.generate_html("host", "192.0.2.1", report, [], 0, "info")
    assert "部分檢查未完成" in report_html
    assert "收集失敗：防火牆狀態" in report_html


def test_failed_ssh_command_does_not_use_partial_stdout(monkeypatch):
    mock_commands(monkeypatch, {
        "sshd": linux.CommandResult("permitrootlogin no\npasswordauthentication no\npermitemptypasswords no", returncode=1),
    })
    with pytest.raises(RuntimeError, match="OpenSSH"):
        linux.get_ssh_security()


def test_unreadable_pam_policy_does_not_pass_using_login_defs_only(monkeypatch):
    from io import StringIO

    def open_policy(path):
        if path == "/etc/login.defs":
            return StringIO("PASS_MIN_LEN 12\nPASS_MAX_DAYS 90\n")
        raise PermissionError(path)

    monkeypatch.setattr(linux, "open", open_policy, raising=False)
    with pytest.raises(RuntimeError, match="pwquality"):
        linux.get_password_policy()


@pytest.mark.parametrize(("output", "expected"), [
    ("Status: inactive\n", "否"),
    ("Status: active\n", "是"),
    ("Status: active with warnings\n", "未知"),
])
def test_ufw_matches_complete_status(monkeypatch, output, expected):
    mock_commands(monkeypatch, {"ufw": linux.CommandResult(output, returncode=0)})
    assert linux.get_firewall_status()[0]["啟用"] == expected


@pytest.mark.parametrize(("input_policy", "rules", "expected"), [
    ("DROP", "", "是"),
    ("ACCEPT", '-A INPUT -m comment --comment "refer to DROP" -j ACCEPT\n', "否"),
    ("ACCEPT", "-N custom\n-A INPUT -j custom\n-A custom -j REJECT\n", "是"),
    ("ACCEPT", "-N detached\n-A detached -j DROP\n", "否"),
])
def test_iptables_considers_policy_and_reachable_rules(monkeypatch, input_policy, rules, expected):
    output = f"-P INPUT {input_policy}\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n{rules}"
    mock_commands(monkeypatch, {"iptables": linux.CommandResult(output, returncode=0)})
    row = linux.get_firewall_status()[0]
    assert row["啟用"] == expected
    assert f"INPUT={input_policy}" in row["詳細資訊"]


def nft_rules(*, policy="accept", hook="input", flags=None, expressions=None):
    table = {"family": "inet", "name": "filter", "flags": flags or []}
    chain = {"family": "inet", "table": "filter", "name": "input",
             "type": "filter", "hook": hook, "policy": policy}
    rows = [{"metainfo": {"json_schema_version": 1}}, {"table": table}, {"chain": chain}]
    if expressions is not None:
        rows.append({"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": expressions}})
    return json.dumps({"nftables": rows})


@pytest.mark.parametrize(("output", "status"), [
    (nft_rules(policy="drop"), "是"),
    (nft_rules(expressions=[{"reject": None}]), "是"),
    (nft_rules(expressions=[{"counter": None}, {"accept": None}]), "否"),
    (nft_rules(policy="drop", flags=["dormant"]), "否"),
    (nft_rules(policy="drop", hook=None), "否"),
    (nft_rules(expressions=[{"vmap": {"data": "@verdicts"}}]), "未知"),
    ('{"nftables": []}', "否"),
    ("invalid JSON", "未知"),
])
def test_nftables_reads_ruleset(monkeypatch, output, status):
    calls = mock_commands(monkeypatch, {"nft": linux.CommandResult(output, returncode=0)})
    row = linux.get_firewall_status()[0]
    assert ["nft", "-j", "-n", "list", "ruleset"] in calls
    assert row["防火牆類型"] == "nftables"
    assert row["啟用"] == status


def test_inactive_ufw_does_not_hide_nftables(monkeypatch):
    mock_commands(monkeypatch, {
        "ufw": linux.CommandResult("Status: inactive", returncode=0),
        "nft": linux.CommandResult(nft_rules(policy="drop"), returncode=0),
    })
    rows = linux.get_firewall_status()
    assert summary({"防火牆狀態": rows})["主機防火牆"] == "PASS"
    assert linux._analyze_firewall(rows) == []


def test_firewall_permission_error_is_unknown(monkeypatch):
    mock_commands(monkeypatch, {
        "ufw": linux.CommandResult("Status: inactive", returncode=0),
        "nft": linux.CommandResult(nft_rules(policy="drop"), "Permission denied", returncode=1),
    })
    rows = linux.get_firewall_status()
    assert summary({"防火牆狀態": rows})["主機防火牆"] == "UNKNOWN"
    assert linux._analyze_firewall(rows) == []


def test_no_available_firewall_probe_is_unknown(monkeypatch):
    mock_commands(monkeypatch, {})
    assert summary({"防火牆狀態": linux.get_firewall_status()})["主機防火牆"] == "UNKNOWN"


@pytest.mark.parametrize(("state", "zones", "expected"), [
    (linux.CommandResult("not running", returncode=252), None, "FAIL"),
    (linux.CommandResult("running", returncode=0), linux.CommandResult("public zone", returncode=0), "PASS"),
    (linux.CommandResult("running", returncode=0), linux.CommandResult(stderr="denied", returncode=1), "UNKNOWN"),
])
def test_firewalld_distinguishes_stopped_and_unreadable(monkeypatch, state, zones, expected):
    def run(cmd, **kwargs):
        if cmd[0] != "firewall-cmd":
            return linux.CommandResult(missing=True)
        return state if cmd[1] == "--state" else zones

    monkeypatch.setattr(linux, "_command", run)
    assert summary({"防火牆狀態": linux.get_firewall_status()})["主機防火牆"] == expected


def test_successful_empty_ss_and_failed_ss_are_distinct(monkeypatch):
    mock_commands(monkeypatch, {"ss": linux.CommandResult(returncode=0)})
    assert linux.get_netstat() == []
    mock_commands(monkeypatch, {"ss": linux.CommandResult(stderr="指令逾時")})
    with pytest.raises(RuntimeError, match="ss 或 netstat"):
        linux.get_netstat()


def test_ss_parses_tcp_only_output_without_protocol(monkeypatch):
    def run(cmd):
        if "-tnp" in cmd:
            return linux.CommandResult('ESTAB 0 0 192.0.2.8:42500 192.0.2.9:443 users:(("app",pid=10,fd=4))', returncode=0)
        return linux.CommandResult("udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*", returncode=0)

    monkeypatch.setattr(linux, "_command", run)
    udp, tcp = linux.get_netstat()
    assert udp["狀態"] == "UNCONN"
    assert tcp["狀態"] == "ESTABLISHED"
    assert tcp["遠端位址"] == "192.0.2.9:443"
    assert tcp["PID"] == "10"


def test_missing_ip_uses_only_local_commands(monkeypatch):
    calls = mock_commands(monkeypatch, {})
    assert linux.get_local_ip_address() == "未知"
    assert calls == [
        ["ip", "-4", "route", "show", "default"],
        ["ip", "-4", "-o", "addr", "show", "scope", "global"],
        ["hostname", "-I"],
    ]


@pytest.mark.parametrize("manager", ["dnf", "yum"])
@pytest.mark.parametrize(("returncode", "output", "count"), [
    (0, "", "0"),
    (100, "example.x86_64 1.2 updates\nObsoleting Packages\nold.x86_64 1.0 base\n", "1"),
    (1, "example.x86_64 1.2 updates\n", None),
    (100, "unexpected format", None),
])
def test_rpm_updates_are_cache_only(monkeypatch, manager, returncode, output, count):
    calls = mock_commands(monkeypatch, {manager: linux.CommandResult(output, returncode=returncode)})
    if count is None:
        with pytest.raises(RuntimeError, match=manager):
            linux.get_update_status()
    else:
        updates = linux.get_update_status()
        assert next(row["內容"] for row in updates if row["項目"] == "可更新套件數") == count
        assert summary({"更新狀態": updates})["修補 / 更新狀態"] == ("INFO" if count == "0" else "WARN")
    assert calls[-1][0] == manager
    assert "--cacheonly" in calls[-1]
    assert {"--noplugins", "--setopt=plugins=0"} & set(calls[-1])


def test_apt_lists_cached_updates_without_refresh(monkeypatch):
    calls = mock_commands(monkeypatch, {"apt": linux.CommandResult("Listing...\n", returncode=0)})
    assert summary({"更新狀態": linux.get_update_status()})["修補 / 更新狀態"] == "INFO"
    assert calls == [["apt", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "list", "--upgradable"]]


def test_container_probes_use_only_local_endpoints(monkeypatch):
    monkeypatch.setattr(linux.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(linux.os.path, "exists", lambda path: False)
    calls = mock_commands(monkeypatch, {})
    linux.get_container_status()
    assert calls[0][:4] == ["docker", "--host", "unix:///var/run/docker.sock", "ps"]
    assert calls[1][:3] == ["podman", "--remote=false", "ps"]


def test_command_drops_remote_endpoint_environment_and_preserves_failure(monkeypatch):
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST", "DBUS_SYSTEM_BUS_ADDRESS"):
        monkeypatch.setenv(name, "remote")

    def run(cmd, **kwargs):
        env = kwargs["env"]
        assert not {"DOCKER_HOST", "DOCKER_CONTEXT", "CONTAINER_HOST", "DBUS_SYSTEM_BUS_ADDRESS"} & env.keys()
        return subprocess.CompletedProcess(cmd, 1, "partial output", "denied")

    monkeypatch.setattr(linux.subprocess, "run", run)
    probe = linux._command(["nft"])
    assert (probe.returncode, probe.stderr) == (1, "denied")
    assert linux._run(["nft"]) == ""


def test_package_zip_exports_xlsx_with_control_characters(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    command = "\x00\x1b=argument\twith\nbreak\rhere\x0b\x0c\uffff"
    report = {"執行中程序": [{"PID": 42, "命令列": command}]}
    findings = [linux._finding("process", 1, "\x1fExample", "Line\x01 one")]
    findings[0]["status"] = "op\x02en"

    filename = linux.package_zip("host", report, findings, 0, "info", "host", "192.0.2.1")
    with zipfile.ZipFile(filename) as archive:
        assert archive.testzip() is None
        assert json.loads(archive.read("host.report.json"))["執行中程序"][0]["命令列"] == command
        assert "host.report.html" in archive.namelist()
        with io.BytesIO(archive.read("host.report.xlsx")) as xlsx:
            workbook = load_workbook(xlsx)
    assert workbook["執行中程序"]["B2"].value == 42
    cell = workbook["執行中程序"]["E2"]
    assert cell.value.replace("\r", "\n") == "'=argument\twith\nbreak\nhere"
    assert cell.data_type == "s"
    assert workbook["風險摘要"]["C2"].value == "Example"
    assert workbook["風險摘要"]["D2"].value == "Line one"
    assert workbook["風險摘要"]["E2"].value == "open"


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux procfs")
def test_process_hash_uses_running_executable_after_path_replacement(monkeypatch, tmp_path):
    sleep = shutil.which("sleep")
    if sleep is None:
        pytest.skip("sleep executable is unavailable")
    executable = tmp_path / "h2c-hash-test"
    shutil.copyfile(sleep, executable)
    executable.chmod(0o700)
    original_hash = hashlib.sha256(executable.read_bytes()).hexdigest().upper()
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement contents")
    replacement_hash = hashlib.sha256(replacement.read_bytes()).hexdigest().upper()

    package_queries = []
    monkeypatch.setattr(linux, "_get_package_owner", lambda path, cache: package_queries.append(path) or "test-package")
    with subprocess.Popen([str(executable), "30"]) as child:
        try:
            real_listdir = os.listdir
            monkeypatch.setattr(linux.os, "listdir", lambda path: [str(child.pid)] if path == "/proc" else real_listdir(path))
            normal, = linux.get_process_hashes()
            assert normal["SHA256"] == original_hash
            assert normal["套件來源"] == "test-package"
            os.replace(replacement, executable)
            deleted, = linux.get_process_hashes()
        finally:
            child.terminate()
    assert deleted["PID"] == child.pid
    assert deleted["SHA256"] == original_hash
    assert deleted["SHA256"] != replacement_hash
    assert deleted["hash_status"] == "ok"
    assert deleted["是否已刪除"] == "是"
    assert deleted["套件來源"] == ""
    assert package_queries == [str(executable)]


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux procfs")
def test_process_hash_does_not_fallback_to_path_when_proc_exe_is_denied(monkeypatch):
    pid = os.getpid()
    real_listdir = os.listdir
    real_open = os.open

    def open_file(path, flags, mode=0o777, *, dir_fd=None):
        if path == "exe" and dir_fd is not None:
            raise PermissionError(path)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def unexpected_package_lookup(*args):
        pytest.fail("The executable could not be read")

    monkeypatch.setattr(linux.os, "listdir", lambda path: [str(pid)] if path == "/proc" else real_listdir(path))
    monkeypatch.setattr(linux.os, "open", open_file)
    monkeypatch.setattr(linux, "_get_package_owner", unexpected_package_lookup)
    row, = linux.get_process_hashes()
    assert row["執行路徑"] == os.readlink(f"/proc/{pid}/exe")
    assert row["SHA256"] == ""
    assert row["hash_status"] == "permission_denied"
