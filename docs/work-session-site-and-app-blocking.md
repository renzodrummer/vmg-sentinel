# Work-session site and app blocking — file map and runbook

This note lists **what was added or changed** for session-gated system-wide blocking, **which packages it uses**, and **what you must do for the feature to actually block**.

Design background: [`system-wide-site-and-app-blocking.md`](./system-wide-site-and-app-blocking.md).  
Implementation prompt: [`prompts/implement-system-wide-blocking.md`](./prompts/implement-system-wide-blocking.md).

**Product rule:** listed sites and apps are considered only while the user is on the clock (Sentinel **Start Tracking**, or Citadel tracking with a working status). They are idle when tracking stops.

**Safety rule:** production does **not** block by resolved IP or by killing processes. Default mode is **audit**. If Microsoft Defender Network Protection or WDAC is already on, Sentinel defers and does not duplicate those engines. IP filters / one-shot terminate stay env opt-in for local demos only.

---

## Architecture (short)

```
Angular UI  →  Electron main (user, unelevated)
                    │  named pipe (typed IPC only)
                    ▼
     vmg-sentinel-helper.exe  (LocalSystem service)
                    │
                    ├─ audit: log hostname / app would-blocks
                    ├─ if MDE Network Protection on → do nothing else
                    ├─ if WDAC present → do not terminate, do not deploy CI policy
                    └─ VMG_SENTINEL_IP_FALLBACK=1 only → DNS→IP WFP (not SNI)
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
| `src/main.rs` | Console vs `--service` / `--install` / `--uninstall` |
| `src/runtime.rs` | Shared listen loop, ProgramData store for the service |
| `src/service.rs` | LocalSystem SCM dispatcher (`windows-service`) |
| `src/privilege.rs` | LocalSystem / admin / user |
| `src/enforce/safety.rs` | MDE-first engine choice; IP/kill opt-in |
| `src/enforce/mde.rs` | Detect Defender Network Protection |
| `src/enforce/wdac.rs` | Detect App Control; **never** deploy XML |
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
| `src/enforce/windows.rs` | Opt-in IP WFP only; terminate gated off by default |
| `tests/policy_tests.rs` | Unsigned / expired / audit vs block / TTL restore |
| `tests/ipc_authz.rs` | Unauthenticated `ApplyPolicy` rejected |

Release binary:

`native/policy-helper/target/release/vmg-sentinel-helper.exe`

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
| `electron/services/dev-block-policy.js` | Unpackaged **audit** deny list (not used when packaged) |
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
| `package.json` | Script `test:policy` |
| `.gitignore` | `native/*/target/`, helper private keys, `.policy-helper-state/` |

Not changed for this feature: `native/meeting-detector`, hosts file, IFEO, WinDivert, `taskkill` poller.

---

## Packages and dependencies

### npm

**No new npm packages** were added for blocking. The client uses Node built-ins (`net`, `crypto`, `child_process`, `fs`).

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
| `windows` 0.58 | Named pipe, WFP, token/SID |
| `windows-service` 0.7 | LocalSystem service |
| `winreg` 0.52 | Detect MDE / WDAC |

Windows crate features of note: `Win32_NetworkManagement_WindowsFilteringPlatform`, `Win32_System_Pipes`, `Win32_System_Diagnostics_ToolHelp`, `Win32_UI_Shell` (`IsUserAnAdmin`).

**Toolchain:** Rust/Cargo on the PATH, plus a Windows SDK (for `fwpuclnt.dll` / WFP). Same `windows` major as `native/meeting-detector`.

---

## Important pointers to make the feature work

### 1. Local helper binary

```bash
npm run build:helper
```

That stages `native/policy-helper/bin/vmg-sentinel-helper.exe`. Unpackaged Electron looks there first.

### 2. LocalSystem service (required for real blocks)

Users never launch the helper. The per-machine NSIS installer (`npm run dist`) ships the exe under `resources/policy-helper/` and runs `--install` / `--uninstall`.

Local testing without a full installer, from an **elevated** prompt:

```bat
npm run build:helper
native\policy-helper\bin\vmg-sentinel-helper.exe --install
```

That creates `VMGSentinelHelper` (LocalSystem, auto-start), stores last-good policy under `%ProgramData%\VMG\Sentinel\policy-helper`, and listens on `\\.\pipe\vmg-sentinel-helper`. Then `npm start` **attaches**. `--uninstall` removes the service. Packaged Sentinel never spawns or kills the service.

### 3. Audit vs block, and when anything is actually blocked

| Turns enforcement **on** | Turns it **off** |
|---|---|
| **Start Tracking** in Sentinel | **Stop Tracking** |
| Citadel `is_tracking` + status `online` / `busy` / `in_a_meeting` / `official_business` | `offline`, `not_working`, lunch/bio/unpaid break, `timetracker:stopped` |

Policy can be loaded while idle. Blocks apply after `SetSession { active: true }` when policy `mode` is `block`. Sites and apps use Windows Firewall outbound rules. Process terminate stays opt-in (`VMG_SENTINEL_TERMINATE=1`). `VMG_SENTINEL_AUDIT_ONLY=1` skips filters.

Unpackaged `npm start` does **not** spawn a Windows helper. It attaches to `VMGSentinelHelper` (or an admin helper already on the pipe).

### 4. Policy source

Packaged builds wait for a **signed** Citadel document from `GET {citadelApiUrl}/v1/agent/endpoint-policy` (cookie from the Electron session). 404 / unsigned / network errors keep last-good and do **not** apply `dev-block-policy.js`.

Packaged and unpackaged builds apply the local signed deny list until a Citadel policy is loaded. Override with `VMG_SENTINEL_DEV_POLICY=0`.

SSO / Microsoft 365 / Citadel / OS-update hosts in `policy-seed-allowlist.js` (and the matching Rust list) are always merged into `sites.allow`.

### 5. What the banner means

- **Audit** while on the clock: “Company policy is in audit — nothing is blocked.”
- **Enforcing**: only if an opt-in engine actually added filters or terminated a process.
- **needs_service**: install the LocalSystem helper; Sentinel will not elevate.
- **mde_present**: Defender is handling web protection; Sentinel is not stacking WFP.

There is no custom Chrome block page. True hostname/SNI filtering is not in this helper (no callout driver).

### 6. Tests

```bash
cd native/policy-helper && cargo test
npm run test:policy
```

`test:policy` uses `electron/vitest.config.mjs` (`environment: node`, `globals: true`).

### 7. macOS

IPC UNIX socket exists. OS enforcement is `TODO(platform)` (`NEFilterDataProvider` / `ES_EVENT_TYPE_AUTH_EXEC`). **Process terminate is not implemented and will not be used as a substitute.**

---

## IPC cheat sheet

| Method | Who | Effect |
|---|---|---|
| `ApplyPolicy` | Main, Citadel fetch or unpackaged dev policy | Store signed document |
| `SetSession` | Main, on tracking/Citadel change | Reconcile audit / optional engines |
| `GetStatus` | Main / UI | `engine`, `mde_present`, `needs_service`, `enforcing` |
| `GetRecentBlocks` | Optional | Last audit/would-block events |
| `ReportTamper` | Reserved | Append tamper log |

Pipe name: `\\.\pipe\vmg-sentinel-helper`  
Policy store (service): `%ProgramData%\VMG\Sentinel\policy-helper\last-good.json`  
Policy store (dev spawn): `{userData}/policy-helper/last-good.json`

---

## Still later

- Citadel endpoint that actually serves signed policy (client is wired; API may 404)
- Intune/MDE WDAC **audit ring**, then deny-list enforce (never from this helper)
- Hostname/SNI callout or Defender indicators instead of IP fallback
- macOS system extension + MDM preapproval
- Custom in-browser “Blocked by company policy: {rule_id}” page
- NSIS `perMachine: true` so the installer registers the service
