# Dev Log — 2026-08-31 #02：對外連線誤報收斂（loopback IPv6 + 標準服務埠分級）

> 背景：netstat 程序歸屬修好後（#01 的 `$procId`），實測報告出現一批
> `對外非標準 Port 連線` 誤報 —— `vmware → [::1]:17402`、`ChatGPT → x.x.x.x:5228`、
> `Ssms → 120.118.220.5:1433`。程序名這次是對的，是**規則邏輯太粗**。

## 三類誤報與根因

| 樣態 | 根因 |
|---|---|
| `vmware → [::1]:…`（4 筆） | `_is_private_ip()` 先做 `ip.split(":")[0]` 再比 IPv4 正則 → `'[::1]'` 變 `'['`、`'fe80::…'` 變 `'fe80'`，IPv6 私網/loopback/link-local 全被判成公網 |
| `ChatGPT → :5228` | 5228–5230 是 Google FCM/GCM 推播埠，Chrome / Electron app 常態使用；規則只放行 80/443 |
| `Ssms → …:1433` | 1433 **就是** MSSQL 標準埠，`Ssms`（SSMS）連 1433 是正常維運；規則一律當「非標準」 |

## 這次做了什麼（保守範圍）

只做 agent 端能安全判斷的部分；「對端是否雲端/自有網段」這種需要情資或組織設定的
分層，留給中央端（VANS `unusual_egress`）。

### 1. `_is_private_ip()` 改用 `ipaddress`

正確涵蓋 IPv4/IPv6 的 private / loopback / link-local / ULA(`fc00::/7`) /
CGNAT(`100.64/10`) / 169.254 / multicast / reserved；無法解析時才退回舊正則。
新增 `_norm_ip()`（去 `[]` 與 `%zone`）、`_split_hostport()`（正確拆 `[ipv6]:port`）。

### 2. 標準服務埠分級 `_LOW_RISK_EXTERNAL_PORTS`

對外 ESTABLISHED 的埠分四級：

| 埠 | 級別 |
|---|---|
| 4444/5555/6666/1337/31337/9001 | High（`_MALICIOUS_PORTS`，不變） |
| 80/443 | Low（不變） |
| **1433/3306/5432、465/587、993/995/143/110、3389、123/853、5228–5230** | **Low（新增，仍保留 finding）** |
| 其他冷門埠 | Medium（維持） |

**刻意不降級**：22(SSH)、25(SMTP 直送)、389/636(LDAP)、5985/5986(WinRM) ——
這些是 reverse tunnel / 橫向移動 / 直接外洩最常被濫用的埠，對外部目的地維持 Medium。
5228–5230 於此僅降級；「對端是否真為 Google IP」由 VANS 再判。

### 3. link-local 不再當「對外」，改記 Low

`fe80::/10`、`169.254/16` 的 ESTABLISHED 連線 → `同網段 link-local 連線` severity 1
（非對外，但屬同網段可達，仍可能是橫向存取，故不完全丟棄）。

## 驗證

`_analyze_netstat` 對合成連線列（比照實測報告樣態）：

```
Ssms → 120.118.220.5:1433      → Low   （原 Medium）
ChatGPT → 64.233.188.188:5228  → Low   （原 Medium）
vmware → [::1]:17402            → 無 finding（原 Medium）
mstsc → <公網>:3389             → Low
brave → <公網>:443              → Low
putty → <公網>:22               → Medium（SSH 不放行）
powershell → <公網>:5985        → Medium（WinRM 不放行）
<proc> → <公網>:6001            → Medium（冷門埠）
<proc> → <公網>:4444            → High （惡意埠）
System → [fe80::9]:139          → Low  （同網段 link-local）
```

`_is_private_ip` / `_is_link_local` / `_split_hostport` 單元檢查全通過（IPv4/IPv6/裸位址/zone id）。

## 限制（交給 VANS）

- 校內公網段（如 TANet `120.118/16`、`140.126/16`）目前仍算「對外」→ `Ssms → 內網 DB`
  只是降到 Low，尚未識別為「自有主機」。需要組織網段（自動推導 + 設定）才能做，屬 VANS。
- 443 上的 C2、外洩量、beacon 週期 —— 埠判斷抓不到，需 VANS 的程序權重 × 對端信譽 ×
  beacon 分析（`unusual_egress` 設計）。
- 版本字串維持 `2.0.0.0`（沿專案慣例，不逐次 bump）。
