# Prompt: Implement system-wide site and app blocking

Copy the block below into a new Agent session. The architecture spec is [`docs/system-wide-site-and-app-blocking.md`](../system-wide-site-and-app-blocking.md). Do not invent a different design.

---

## Prompt (copy from here)

You are implementing **system-wide website and native-app blocking** for the VMG Sentinel Electron desktop agent on **Windows and macOS**.

Read and follow `docs/system-wide-site-and-app-blocking.md` as the source of truth. If this prompt and that doc conflict, the doc wins. Do not “simplify” enforcement into hosts-file edits, a local HTTP proxy, IFEO, or process-kill loops.

### Product goal

A corporate endpoint agent that can deny listed websites (by hostname) and listed native apps (by publisher/hash/path) on the **whole machine**, not only inside Sentinel’s Chromium session.

Sentinel’s Electron UI stays unprivileged. Enforcement lives in a privileged native helper. Policy is server-authored (Citadel), signed, versioned, and has a TTL. Ship **audit mode first**, then **block mode** behind a flag.

### Non-goals (do not implement)

- Editing `/etc/hosts` or `C:\Windows\System32\drivers\etc\hosts`
- Destination-IP firewall rules as the primary site block
- IFEO registry keys
- WinDivert, WinPcap, unsigned kernel drivers
- `sudo-prompt` / one-shot elevation from the renderer
- Polling `taskkill` / `NSWorkspace.terminate` as the product
- TLS MITM / installing a corporate root CA
- An npm package that claims to do system-wide blocking
- Accepting arbitrary shell commands over IPC from Electron

A local Layer-7 proxy is **not** milestone 1. Kill-after-launch is **not** the app-control design. If you need cleanup of an already-running process after a policy change, it is a **one-shot reconcile**, not a timer loop.

### Architecture you must implement

```
Citadel (signed policy JSON: version, TTL, allow/deny, mode)
        → unprivileged Electron UI (show reason, never enforce)
        → authenticated IPC (Windows named pipe with ACL / macOS XPC with code-signing requirement)
        → privileged helper
             Windows: Service as LocalSystem
             macOS: system extension in the .app bundle (+ LaunchDaemon only if needed)
        → OS engines
             Windows sites: WFP (hostname/SNI), not hosts file
             Windows apps:  WDAC (App Control for Business) as primary; AppLocker only if a tenant already has it
             macOS sites:   NEFilterDataProvider (flows, allow/block before data transfer)
             macOS apps:    Endpoint Security ES_EVENT_TYPE_AUTH_EXEC (inline deny before exec)
```

Electron `session.webRequest` / `setProxy` may be used **only** for in-app blocking inside Sentinel. They must not be presented as system-wide enforcement.

### Policy contract

Implement a typed policy document (TypeScript + native structs). Suggested shape:

```json
{
  "version": 1,
  "issued_at": "<ISO-8601>",
  "ttl_seconds": 3600,
  "mode": "audit",
  "signature": "<signature>",
  "sites": {
    "allow": ["login.microsoftonline.com"],
    "deny": ["facebook.com"]
  },
  "apps": {
    "deny": [
      { "kind": "publisher", "value": "..." },
      { "kind": "hash", "alg": "sha256", "value": "..." },
      { "kind": "path", "value": "..." }
    ]
  }
}
```

Rules:

- Helper verifies signature and expiry. Unsigned or stale policy is rejected.
- `mode: "audit"` logs would-be denies and does **not** block.
- `mode: "block"` enforces at the OS engine.
- Always allow SSO, OS update, and this product’s own APIs (seed an allowlist).
- Prefer publisher/hash over process file name.
- On helper crash or Citadel outage: keep last good policy until TTL. Do not permanently lock the user out of traffic/SSO. After TTL, fail in a documented, coded direction (do not leave this as a comment).
- IPC is typed only: `ApplyPolicy`, `GetStatus`, `GetRecentBlocks`, `ReportTamper`. Never `RunCommand`.

### Privilege and install

- Electron main + renderer: logged-on user. Never admin/root.
- Windows: per-machine installer (not per-user). Service DACL and named-pipe ACL must reject unauthenticated local clients.
- macOS: app under `/Applications`, Developer ID + notarization path documented even if local unsigned builds exist for dev. Same Team ID on app and system extension.
- Uninstall requires admin and reports tamper.
- MDM preapproval of the macOS system extension is in-scope as config/docs (Intune/Jamf payload sketches). Manual System Settings clicks are not an acceptable production path.

### Implementation order (do these in order; stop at the end of each milestone unless asked to continue)

**Milestone 0 — Spec lock**

- Confirm you read `docs/system-wide-site-and-app-blocking.md`.
- List files you will add. Do not start with UI chrome.

**Milestone 1 — Policy + IPC skeleton (no enforcement)**

- Policy schema, signing verification stub (dev key OK), helper process that loads, heartbeats, and answers `GetStatus`.
- Electron talks to the helper over authenticated IPC only.
- Unit tests for parse / reject unsigned / reject expired / audit vs block mode flag.

**Milestone 2 — Windows enforcement (audit, then block flag)**

- WFP hostname/SNI deny path for `sites.deny` (document exactly which WFP layer/callout you used and what you can see without TLS inspection).
- WDAC policy apply/remove for `apps.deny`.
- Audit mode must log and not deny.
- Tests: policy apply, allowlist still works, helper restart restores last policy within TTL.

**Milestone 3 — macOS enforcement (audit, then block flag)**

- System extension with `NEFilterDataProvider` for sites.
- `ES_EVENT_TYPE_AUTH_EXEC` for apps (Apple entitlement may be stubbed behind a compile flag if the entitlement is not granted yet; do not fake it with `NSWorkspace.terminate`).
- Same audit/block behavior as Windows.

**Milestone 4 — Agent UX and Citadel wiring**

- Fetch policy from the existing backend/socket patterns in this repo if present; otherwise define a clear `GET policy` client with versioning.
- UI: show “Blocked by company policy: …” with rule id. No silent failures.
- Structured audit events: `policy_version`, `rule_id`, `actor`, `process_path`, `hostname`, `action` (`audit` | `block`).
- Optional one-shot terminate of an already-running denied process **after** launch-deny is in place — once per policy version, not a poller.

**Milestone 5 — Packaging**

- Switch Windows install toward per-machine.
- Document MDM profiles for extension preapproval.
- Do not compete with Microsoft Defender for Endpoint if the tenant already has web content filtering / App Control; prefer reporting compliance over duplicating those engines when that path is available.

### Engineering constraints for this repo

- Match existing style: Electron main in `electron/`, native addons under `native/` if that pattern already exists (this repo has `native/meeting-detector` via napi-rs). Prefer a **separate privileged binary/service**, not stuffing WFP/WDAC into the user-mode meeting-detector addon.
- Keep diffs focused. No drive-by refactors. No new markdown unless a milestone requires a short installer/MDM note.
- Tests required for policy parsing and IPC authz. Native enforcement tests can be unit-level with fakes where OS APIs cannot run in CI.
- If a platform API is unavailable in the current environment, implement the interface + Windows or macOS side you can compile, and leave a clearly marked `TODO(platform)` rather than substituting an anti-pattern.

### Acceptance criteria

- [ ] Electron process is not admin/root.
- [ ] Unauthenticated local process cannot apply policy over IPC.
- [ ] In-app `webRequest` is not used as the system-wide mechanism.
- [ ] Denied site in Chrome/Edge/Firefox is blocked by hostname in block mode (or logged in audit mode).
- [ ] Denied app does not start (launch deny), rather than flashing then dying.
- [ ] Publisher/hash deny still applies if the binary is copied or renamed.
- [ ] Allowlisted SSO and Sentinel endpoints still work.
- [ ] Helper crash does not leave a kill loop; TTL behavior is implemented.
- [ ] No hosts file, IFEO, WinDivert, or `taskkill` poller in the tree.

### First action

Start at Milestone 0. Summarize the file plan, then implement Milestone 1 unless the user already named a later milestone.
