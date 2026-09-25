# Work-session site and app blocking — file map and runbook

**Full documentation (architecture, stack, pros/cons, operations):** [`work-session-blocking-full-documentation.md`](./work-session-blocking-full-documentation.md).

This note lists **what was added or changed** for session-gated system-wide blocking, **which packages it uses**, and **what you must do for the feature to actually block**.

Design background: [`system-wide-site-and-app-blocking.md`](./system-wide-site-and-app-blocking.md).  
Implementation prompt: [`prompts/implement-system-wide-blocking.md`](./prompts/implement-system-wide-blocking.md).

**Product rule:** listed sites and apps are considered only while the user is on the clock (Sentinel **Start Tracking**, or Citadel tracking with a working status). They are idle when tracking stops.

**Current Windows engines (helper `fw-4`):** AppLocker is **deny-list** only (Allow Everyone `*` + deny listed apps). A deny-only Enabled collection bricks the device — that is why `fw-3` required a system restore on a test machine.

| Target | While tracking | When tracking stops |
|---|---|---|
| **Sites** | Windows Firewall outbound BLOCK of resolved deny-list IPs | Rules named `VMG Sentinel *` are deleted |
| **Apps** | AppLocker **Allow Everyone `*`** plus **Exe Deny** for listed apps + one-shot close of already-running matches | Sentinel AppLocker rules removed; Exe enforcement set to **NotConfigured** |

This is **not** WDAC CI policy and **not** a `taskkill` poller. WDAC is still detect-only (never deployed from this helper). `VMG_SENTINEL_AUDIT_ONLY=1` skips filters. AppLocker needs the Application Identity service; Windows Home (and some Pro SKUs) may not refuse `CreateProcess` — the banner `last_error` says so.

---

## Architecture (short)

```
Angular UI  →  Electron main (user, unelevated)
                    │  named pipe (typed IPC only)
                    ▼
     vmg-sentinel-helper.exe  (LocalSystem service, build fw-4)
                    │
                    ├─ sites: DNS → INetFw outbound RemoteAddresses
                    ├─ apps:  AppLocker allow-all + listed deny + one-shot close
                    ├─ WDAC:  detect only; never deploy CiTool XML
                    └─ clear on SetSession(false) including Quit, helper exit, --clear-blocks / --uninstall
```

The renderer never talks to the helper. Main sends typed IPC only: `ApplyPolicy`, `GetStatus`, `GetRecentBlocks`, `ReportTamper`, `SetSession`. There is no `RunCommand`. Packaged Sentinel **attaches** to the service; it does not spawn the helper or show UAC.

---

## Files created

### Native helper (`native/policy-helper/`)

| Path | Role |
|---|---|
| `Cargo.toml` / `Cargo.lock` | Helper crate `vmg-sentinel-helper` |
| `.gitignore` | Ignores `target/` and private key files |
| `keys/dev_ed25519.pub` | Dev public key (RFC 8032 test vector 1) |
| `src/lib.rs` | Crate modules |
| `src/main.rs` | Console vs `--service` / `--install` / `--uninstall` / `--clear-blocks` |
| `src/runtime.rs` | Shared listen loop, ProgramData store for the service |
| `src/service.rs` | LocalSystem SCM dispatcher (`windows-service`) |
| `src/privilege.rs` | LocalSystem / admin / user |
| `src/enforce/safety.rs` | Site engine `fw`; app engine `launch` (AppLocker) |
| `src/enforce/mde.rs` | Detect Defender Network Protection |
| `src/enforce/wdac.rs` | Detect App Control; **never** deploy XML |
| `src/enforce/firewall.rs` | INetFw outbound site/app rules; leftover wipe |
| `src/enforce/applocker.rs` | Session-gated AppLocker exe deny XML + clear |
| `src/policy.rs` | Parse, Ed25519 verify, seed allowlist merge |
| `src/policy_store.rs` | `last-good.json` + tamper log |
| `src/seed_allowlist.rs` | SSO / Citadel / OS-update hosts that cannot be denied |
| `src/ttl.rs` | After TTL: keep document, force **audit** |
| `src/auth.rs` | Peer must be authenticated; `RunCommand` is forbidden |
| `src/state.rs` | Session flag, last policy, reconcile, status JSON |
| `src/ipc/protocol.rs` | Length-prefixed JSON; method allowlist |
| `src/ipc/dispatch.rs` | Method handlers |
| `src/ipc/serve.rs` | Frame read/write loop |
| `src/ipc/windows.rs` | Named pipe + token check |
| `src/ipc/macos.rs` | UNIX socket stub (`TODO(platform)` for XPC/code signing) |
| `src/ipc/mod.rs` | Platform listen |
| `src/enforce/mod.rs` | Apply vs clear vs audit |
| `src/enforce/plan.rs` | Session+mode gate, hostname match, DNS resolve |
| `src/enforce/windows.rs` | Apply/clear firewall + AppLocker; one-shot close running deny apps |
| `tests/policy_tests.rs` | Unsigned / expired / audit vs block / TTL restore |
| `tests/ipc_authz.rs` | Unauthenticated `ApplyPolicy` rejected |

Release binary:

Staged binary: `native/policy-helper/bin/vmg-sentinel-helper.exe` (`npm run build:helper`).

### Electron / Angular

| Path | Role |
|---|---|
| `electron/services/policy-document.js` | JS parse + signature verify |
| `electron/services/policy-document.spec.js` | Vitest for policy document |
| `electron/services/policy-seed-allowlist.js` | Same seed hosts as Rust |
| `electron/services/policy-helper-client.js` | Named-pipe client |
| `electron/services/policy-helper-client.spec.js` | Mock pipe protocol tests |
| `electron/services/work-session.js` | When blocking is on/off |
| `electron/services/work-session.spec.js` | Session gate tests |
| `electron/services/dev-block-policy.js` | Signed local deny list until Citadel loads (`VMG_SENTINEL_DEV_POLICY=0` disables) |
| `build/installer.nsh` | Per-machine NSIS: `--install` / `--clear-blocks` / `--uninstall` |
| `electron/services/policy-fetch.js` | GET signed Citadel `/v1/agent/endpoint-policy`; fail-soft |
| `electron/vitest.config.mjs` | Node + globals for these specs |

---

## Files updated

| Path | What changed |
|---|---|
| `electron/main.js` | Attach to service; spawn helper only when unpackaged; Citadel policy fetch |
| `electron/preload.js` | `getPolicyStatus`, `setCitadelWorkSession`, `onPolicyStatus` |
| `src/global.d.ts` | `PolicyStatus` + Electron API types |
| `src/app/electron.service.ts` | Bridges those APIs |
| `src/app/app.ts` | Banner state; forwards Citadel tracker status to main |
| `src/app/app.html` | Policy banner |
| `src/app/app.scss` | Banner styles |
| `package.json` | `test:policy`, `build:helper`, `dist` (electron-builder NSIS `perMachine`) |
| `.gitignore` | `native/*/target/`, helper private keys, `.policy-helper-state/` |

Not changed for this feature: `native/meeting-detector`, hosts file, IFEO, WinDivert, `taskkill` poller.

---

## Packages and dependencies

### npm

Blocking uses Node built-ins (`net`, `crypto`, `child_process`, `fs`). Packaging uses `electron-builder` (NSIS per-machine).

Existing tools used by tests:

| Package | Already in | Used for |
|---|---|---|
| `vitest` | `devDependencies` | `npm run test:policy` |
| `electron` | `devDependencies` | Main process + named pipe |

### Rust (Cargo, not `package.json`)

Installed when you `cargo build` in `native/policy-helper/`:

| Crate | Why |
|---|---|
| `ed25519-dalek` | Sign/verify policy |
| `serde` / `serde_json` | Policy + IPC JSON |
| `tokio` | Async pipe, heartbeat, 45s DNS refresh |
| `time` | RFC3339 `issued_at` / TTL |
| `hex` / `thiserror` | Keys and errors |
| `sha2` | Hash match for app rules |
| `windows` 0.58 | Named pipe, WFP leftovers, INetFw, token/SID |
| `windows-service` 0.7 | LocalSystem service |
| `winreg` 0.52 | Detect MDE / WDAC |

Windows crate features of note: `Win32_NetworkManagement_WindowsFirewall`, `Win32_NetworkManagement_WindowsFilteringPlatform`, `Win32_System_Pipes`, `Win32_System_Diagnostics_ToolHelp`, `Win32_UI_Shell` (`IsUserAnAdmin`).

**Toolchain:** Rust/Cargo on the PATH, plus a Windows SDK. Same `windows` major as `native/meeting-detector`. AppLocker apply/clear uses `powershell.exe` `Set-AppLockerPolicy` / `Get-AppLockerPolicy` from the helper (not from Electron).

---

## Important pointers to make the feature work

### 1. Local helper binary

```bash
npm run build:helper
npm run verify:helper
```

`build:helper` always rebuilds and **refuses** to stage an exe that is not `fw-4` or that lacks the AppLocker allow-all string. `verify:helper` is also run automatically by `npm run dist`. Unpackaged Electron looks in `native/policy-helper/bin/` first.

### 2. LocalSystem service (required for real blocks)

Users never launch the helper. The per-machine NSIS installer (`npm run dist`) ships the exe under `resources/policy-helper/` and runs `--install` / `--uninstall`.

Local testing without a full installer, from an **elevated** prompt:

```bat
npm run build:helper
native\policy-helper\bin\vmg-sentinel-helper.exe --install
```

That creates `VMGSentinelHelper` (LocalSystem, auto-start), stores last-good policy under `%ProgramData%\VMG\Sentinel\policy-helper`, and listens on `\\.\pipe\vmg-sentinel-helper`. Then `npm start` **attaches**. `--clear-blocks` removes leftover firewall + AppLocker rules. `--uninstall` clears those rules and deletes the service. Packaged Sentinel never kills the service, but **Quit** sends `SetSession(false)` so rules lift. Electron expects `helper_build` **`fw-4`**.

### 3. Audit vs block, and when anything is actually blocked

| Turns enforcement **on** | Turns it **off** |
|---|---|
| **Start Tracking** in Sentinel | **Stop Tracking** (and **Quit**, which sends `SetSession(false)`) |
| Citadel `is_tracking` + status `online` / `busy` / `in_a_meeting` / `official_business` | `offline`, `not_working`, lunch/bio/unpaid break, `timetracker:stopped` |

Policy can be loaded while idle. Blocks apply after `SetSession { active: true }` when policy `mode` is `block`. Sites use Windows Firewall outbound rules. Apps use session-gated AppLocker: **Allow Everyone `*`** plus deny listed exes (cannot launch), plus a one-shot close of already-running matches. Stop Tracking / Quit must set Exe enforcement to **NotConfigured** and remove `VMG Sentinel *` rules. Deny-only Enabled AppLocker (helper `fw-3`) bricks the device — do not ship that build. `VMG_SENTINEL_AUDIT_ONLY=1` skips filters.

Unpackaged `npm start` does **not** spawn a Windows helper. It attaches to `VMGSentinelHelper` (or an admin helper already on the pipe).

### 4. Policy source

Packaged and unpackaged builds apply the local signed deny list from `dev-block-policy.js` until a Citadel policy is loaded. A successful Citadel `GET {citadelApiUrl}/v1/agent/endpoint-policy` replaces it. Set `VMG_SENTINEL_DEV_POLICY=0` to disable the local list.

SSO / Microsoft 365 / Citadel / OS-update hosts in `policy-seed-allowlist.js` (and the matching Rust list) are always merged into `sites.allow`.

### 5. What the banner means

- **engine fw**: site firewall rules are in play.
- **app_engine launch**: AppLocker launch deny is the app engine (or `last_error` if AppLocker is unavailable).
- **build fw-4**: current helper (allow-all AppLocker + dirty reconcile). Older builds (`fw-3` and below) are rejected on attach.
- **helper LocalSystem**: service path. `user` means blocking will not stick.
- **needs_service**: install/reinstall `VMGSentinelHelper`.
- **last_error**: firewall or AppLocker apply/clear failed.

There is no custom Chrome block page. True hostname/SNI filtering is not in this helper (no callout driver).

### 6. Tests

```bash
cd native/policy-helper && cargo test
npm run test:policy
npm run verify:helper
```

`test:policy` uses `electron/vitest.config.mjs` (`environment: node`, `globals: true`).

### 7. macOS

IPC UNIX socket exists. OS enforcement is `TODO(platform)` (`NEFilterDataProvider` / `ES_EVENT_TYPE_AUTH_EXEC`). **Process terminate is not implemented and will not be used as a substitute.**

---

## IPC cheat sheet

| Method | Who | Effect |
|---|---|---|
| `ApplyPolicy` | Main, Citadel fetch or unpackaged dev policy | Store signed document |
| `SetSession` | Main, on tracking/Citadel change or **Quit** | Apply or clear firewall + AppLocker |
| `GetStatus` | Main / UI | `engine`, `app_engine`, `helper_build`, `privilege`, `enforcing` |
| `GetRecentBlocks` | Optional | Last audit/would-block events |
| `ReportTamper` | Reserved | Append tamper log |

Pipe name: `\\.\pipe\vmg-sentinel-helper`  
Policy store (service): `%ProgramData%\VMG\Sentinel\policy-helper\last-good.json`  
Policy store (dev spawn): `{userData}/policy-helper/last-good.json`

---

## Still later

- Citadel endpoint that actually serves signed policy (client is wired; API may 404)
- Authenticode-sign the NSIS installer (SmartScreen)
- Intune/MDE WDAC for **all-day** launch deny (never deploy CI XML from this helper)
- Hostname/SNI callout instead of DNS→IP firewall
- macOS system extension + MDM preapproval
- Custom in-browser “Blocked by company policy: {rule_id}” page
- Citadel-authored SHA-256 / publisher values for deny apps (schema and helper XML are ready)
- AppLocker on SKUs where Application Identity is missing (Home) — launch deny will fail open with `last_error`

---

## Lab recovery only (not a customer step)

If an old helper left AppLocker Enabled after Stop Tracking, **do not** give `scripts/unbrick-applocker.ps1` to end users. Production users only Start / Stop Tracking. For a stuck lab machine, elevated:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\unbrick-applocker.ps1
```
