# AuthForge - Cookie & Token Toolkit

A Chromium browser extension for inspecting, modifying, and replaying browser
authentication artifacts. Built for web developers, security engineers,
penetration testers, and anyone who needs to understand or reshape what their
browser is sending to the servers it talks to.

AuthForge unifies under one UI what would otherwise require six or seven
separate tools: DevTools' Application tab, a JWT debugger, a request
re-issuer (Burp's Repeater / Postman), a network sniffer, a JWT attack
generator, a Microsoft Entra audit tool, and a cookie / storage editor.

This document describes every feature, every permission and why it's needed,
the privacy and security posture of the extension, installation,
configuration, and known limitations.

---

## Contents

- [What AuthForge does](#what-authforge-does)
- [Feature tour](#feature-tour)
  - [Cookies](#cookies)
  - [LocalStorage / SessionStorage](#localstorage--sessionstorage)
  - [IndexedDB](#indexeddb)
  - [Tokens (cross-storage detector)](#tokens-cross-storage-detector)
  - [Network capture](#network-capture)
  - [Request Workbench](#request-workbench)
  - [Audit](#audit)
  - [Snapshots and Profiles](#snapshots-and-profiles)
  - [Microsoft Entra recon and FOCI exchange](#microsoft-entra-recon-and-foci-exchange)
  - [JWT toolkit](#jwt-toolkit)
- [Permissions: what each one does and why it's needed](#permissions-what-each-one-does-and-why-its-needed)
- [Privacy and data handling](#privacy-and-data-handling)
- [Installation](#installation)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [Building from source](#building-from-source)
- [License](#license)

---

## What AuthForge does

AuthForge runs entirely inside your browser. It does not communicate with any
remote server operated by the author. Every operation is local: reading the
browser's cookie store, executing scripts in the page to read web storage,
re-firing requests through the page's own fetch context.

The audience is people who already understand what cookies and tokens are
and want a better surface to work with them. If you only need to delete a
single cookie occasionally, the built-in DevTools is fine. AuthForge is for
when you need to:

- See every cookie across every site in one filterable view, group them by
  domain, edit values inline, decode embedded JWTs in place
- Capture authenticated requests as they leave the browser, see decoded
  Authorization headers (Bearer / Basic / Digest), Set-Cookie responses,
  custom auth headers
- Edit a captured request — method, URL, query params, headers, body,
  credentials, redirect mode — and re-fire it from the page's own context,
  see the response inline, and iterate. Repeat-N times for race conditions
- Decode any JWT to its claims, edit them, optionally re-sign with HMAC,
  write the new token back into the cookie or IndexedDB record it came from
- Generate JWT attack variants (alg confusion, kid injection, claim
  tampering) and replay them against the original endpoint
- For Microsoft Entra ID (Azure AD) tokens: identify the audience, scope,
  tenant, whether it's a FOCI client, run authenticated Graph recon queries,
  and perform FOCI refresh-token exchanges to laterally pivot between
  Microsoft services
- Snapshot a tab's entire storage state (cookies + LS + SS + IDB) and
  restore it later, swap between named sessions, transplant cookies between
  domains
- Run an opinionated audit that classifies cookies (auth / csrf / analytics
  / functional) and surfaces role-aware findings (e.g., an analytics cookie
  with SameSite=None gets ignored; an auth cookie with the same flag is a
  high-severity finding)

---

## Feature tour

### Cookies

Inspect, search, edit, and delete cookies for the current tab, a custom URL,
or every cookie the browser holds.

- **Scope picker** at the top of the cookies tab: `📍 Current tab` /
  `🌐 All open tabs (cookies + storage)` / `🔗 Custom URL…`. "All open
  tabs" returns every cookie the browser can see across every store and
  every origin
- **Search** filters by name, value, domain, or path. Searches use a
  case-insensitive substring; no regex
- **Row badges** at a glance: `JWT` (value parses as a JWT), `RT` (key
  matches refresh-token heuristics), `Session` (no expiration), `Secure`,
  `HttpOnly`, `CHIPS` (partitioned, Chrome 119+), `Expired`, `Soon`
  (expiring within an hour)
- **Inline editor** — click a row to expand. Edit name, value, domain,
  path, expiration, SameSite, Secure, HttpOnly. Save creates an undoable
  history entry. The cookie's `partitionKey` (CHIPS) round-trips correctly
  through save and delete
- **Value encoding toolbar** above the value textarea: URL-decode /
  URL-encode / base64 ↔ text / JSON pretty-print / JSON minify. Each
  transcodes the textarea in place
- **JWT detection** — if a cookie value is a JWT, expanding the row also
  shows the decoded header and payload, with editable claims, attack-variant
  generator, and "Replay this request with each variant" if the JWT was
  also captured in a network entry
- **Undo / Redo** — recent edits stack up in the toolbar. ⌘Z / Ctrl+Z
  works. Up to 50 actions remembered

### LocalStorage / SessionStorage

Same row-and-editor format as cookies. Each tab's entries are read by
injecting a small read-only script into the page's main world (cookies are
read through `chrome.cookies` instead — extensions can't see web storage
from outside the page).

- **All-domains aggregation** — in "All open tabs" mode, LS/SS entries
  from every open tab are merged into one list, with the origin shown per
  row
- **Refresh-token detection** — keys matching common refresh-token
  patterns get a badge. Storing refresh tokens in localStorage is widely
  considered an anti-pattern (XSS-readable); the audit will flag it
- **JWT detection** — values that look like JWTs get the same inline
  decoder/editor as cookies

### IndexedDB

The hardest store to inspect through normal browser tools. AuthForge lists
every database, lets you open a database to see its object stores, and
provides per-record CRUD:

- **Add record** button per store. Handles both in-line keyPath stores
  (key derived from value) and out-of-line stores (key entered separately)
- **Expand a row** to edit the value as JSON, with Save / Delete / Copy
  buttons. The key is shown read-only — IDB keys are immutable; to change
  one, delete and re-add
- **Inline JWT editor** — when an IDB record contains an embedded JWT
  (the MSAL cache pattern: `{ secret: "eyJ..." }`), the editor shows a
  collapsible panel that decodes the JWT, lets you edit its header and
  payload, optionally re-sign with an HMAC secret, and patches the
  re-encoded token back into the original record at the correct JSON path
- **Database delete** — drop entire databases when needed

### Tokens (cross-storage detector)

A unified view of every JWT, refresh token, auth-artifact-keyed entry, and
network-detected token across all of:

- Cookies (for the active scope)
- localStorage
- sessionStorage
- Captured network entries (Authorization headers, Set-Cookie responses,
  body findings from DevTools deep capture)
- IndexedDB databases whose name suggests auth/session data

Each detected token is shown with its source, key, and a short preview.
Tokens that look like JWTs get a "decode" button that opens the JWT toolkit.

For Microsoft tokens, a **MS credential extraction matrix** appears at the
top — collapsible by category (Entra access tokens, MSAL refresh tokens,
SharePoint federation tokens, etc.), each category showing how many
artifacts were found and one-click expansion.

### Network capture

A passive, lightweight observer of HTTP(S) traffic via `chrome.webRequest`
(headers only — MV3 doesn't expose response bodies). Three modes:

1. **Headers-only (default)** — always-on once recording is started.
   Captures: `Authorization` header (Bearer / Basic / Digest), `Set-Cookie`
   response headers (with JWT detection on the values), custom auth-style
   headers (`X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`, etc.), and any
   request to a known token endpoint (`/token`, `/oauth/token`,
   `/authorize`, etc.)
2. **DevTools network deep capture** — when AuthForge's DevTools panel is
   open, request and response bodies become available. Bodies are scanned
   for JWT patterns
3. **Debugger deep capture** — opt-in per tab. Uses `chrome.debugger`
   (Chrome DevTools Protocol) to read response bodies *without* requiring
   DevTools to be open. Shows the yellow "AuthForge started debugging this
   browser" banner; click Cancel to detach

The Network tab lists captured entries newest-first. Each row shows the
method, status, URL, and any auth findings as badges. Expanding a row
reveals the [Request Workbench](#request-workbench) and per-finding details
(decoded JWT claims, etc.).

### Request Workbench

Expand any captured network row and you get a complete editable replay UI:

- **Method dropdown** + **URL field**, kept in sync
- **Query parameters editor** — each `?k=v` pair becomes an enable / name
  / value / remove row. The URL re-serializes live as you edit
- **Headers editor** — same row format. Original captured headers are
  pre-populated; add, edit, disable (without losing the value), or remove
- **Body editor** with type strip — `raw / JSON / form-urlencoded /
  multipart (text) / none`. Selecting a type auto-sets the `Content-Type`
  header. `form-urlencoded` opens a structured table editor that
  re-serializes the body on every edit
- **Body encoding toolbar** — JSON pretty/minify, URL encode/decode,
  base64 ↔ text
- **Fetch options row** — credentials, redirect, cache, mode, referrer
  URL, referrer policy, integrity (SRI hash), keepalive, timeout (ms),
  repeat N times, delay between repeats
- **Diff indicator** — pill showing how many fields you changed from the
  original captured request, so you can see at a glance whether the replay
  matches or differs
- **Action bar**: `▶ Send` · `Reset to original` · `Copy as curl` · `Copy
  as fetch` · `Import curl…` · `🔑 Use captured token…`
- **🔑 Use captured token…** opens a modal listing every token AuthForge
  has detected anywhere. Click one and the Authorization header swaps to
  `Bearer <picked>`. Useful for cross-pollinating sessions or testing
  whether a token from one origin works against another
- **`Import curl…`** parses a pasted curl command and populates every field
  from it (supports `-H`, `-d` / `--data-raw` / `--data-binary`, `-X`, `-b`,
  `-u`, `--user-agent`, `--referer`, with proper shell-quote handling).
  Round-trips with Copy as curl
- **Response viewer** — status code colored by class (2xx green, 3xx
  yellow, 4xx orange, 5xx red), duration, size, redirect indicator,
  collapsible response headers grid, full body in a readonly textarea
  (JSON pretty-printed if parseable)
- **Repeat mode** (`Repeat N×` > 1) — runs the request N times with the
  configured delay between attempts. Shows a verdict table: row per
  attempt with status / time / size / outcome, color-coded by status class.
  Final summary line: `3× 2xx · 1× 4xx · 0× err`. Useful for
  race-condition probes, brute-forcing surface checks

Replays execute in the page's own MAIN world via `chrome.scripting`. This
means cookies, CORS, Origin headers, and HSTS all behave exactly as they
did for the original request. Bearer tokens swapped via the picker are
substituted into the Authorization header before the page-world fetch.

### Audit

An opinionated read-only analysis of everything AuthForge can see, with
findings ranked by severity (critical / high / medium / low / info) and
grouped:

- **Cookie audit** — role-aware. Cookies are classified by name and value
  heuristics into `auth`, `csrf`, `analytics`, or `functional` classes.
  Findings are tailored to the class: a session cookie missing `HttpOnly`
  is high severity; an analytics cookie missing `HttpOnly` is informational.
  Reduces noise dramatically on real sites (typical: 100→58 findings on a
  modern M365 / SharePoint tenant)
- **Storage audit** — JWTs and refresh-token-shaped values in localStorage
  / sessionStorage; configurable suppression for known service workers
- **Network audit** — bearer tokens sent over plain HTTP, tokens sent to
  unexpected third-party origins, expired JWTs still being sent, JWTs with
  `alg: none` in production traffic
- **Microsoft Entra audit** — for every detected Entra JWT: token
  lifetime anomalies, FOCI client identification, audience-confusion
  candidates, scope sensitivity, suspicious app IDs
- **Source attribution** — every finding shows which cookie domain, page
  URL, or request URL it came from. Critical for "All open tabs" audits
  where 50+ findings span many hosts. Expand a finding for the full source
- **JSON export** — one click writes every finding (with sources) to a
  JSON file for inclusion in reports

### Snapshots and Profiles

- **Snapshots** — capture the current storage state of a domain (cookies +
  LS + SS + IDB databases listing) as a named snapshot saved in
  `chrome.storage.local`. Restore later to repopulate the same state.
  Useful for "save my logged-in dev session and restore it after I clear
  everything"
- **Profiles** — broader than snapshots: a profile is a named bundle of
  cookies + storage + custom metadata. Export profiles to JSON, import them
  elsewhere, or apply a profile to a different domain with optional
  domain-remapping (transplant a session captured on `dev.example.com` to
  `staging.example.com`)

### Microsoft Entra recon and FOCI exchange

For Microsoft Entra ID (Azure AD) tokens specifically — recognized by
issuer (`https://login.microsoftonline.com/...`) and standard claims:

- **Audience inspection** — what API does this token unlock? Shown as a
  human-readable label (e.g. "Microsoft Graph", "Azure Resource Manager",
  "Outlook Mailbox API") plus the raw `aud` claim
- **Scope and role inspection** — `scp` / `roles` claims rendered with
  highlighting for known high-privilege scopes
- **Tenant info** — tenant ID, app ID, with FOCI client identification
  ("This token is for Microsoft Outlook Web, a known FOCI client")
- **Audience-aware recon** — 26 read-only endpoints across 5 audience
  groups (Graph, Outlook, ARM, Key Vault, SharePoint). Matched-to-token
  endpoints are highlighted; "what else could this token unlock?" endpoints
  are listed below. Click any endpoint to make an authenticated GET via
  the SW (which enforces a Microsoft-host allowlist)
- **FOCI refresh-token exchange** — Microsoft's first-party clients share
  a refresh-token "family". A refresh token issued to one FOCI client can
  be exchanged for an access token belonging to any other FOCI client.
  The exchange UI pre-fills with 13 known FOCI client IDs (Azure CLI, MS
  Edge, Outlook, Teams, Office, OneDrive, etc.). Pick a target, optionally
  override scope and tenant, and click Exchange — the resulting access
  token is decoded, audience-resolved, and ready for use

This is a meaningful capability — it lets you pivot from a refresh token
captured for one Microsoft service to access another without re-auth. Used
defensively, it's a fast way to enumerate what a stolen RT can actually
reach. Used offensively, it's the same workflow GraphSpy and ROADtools
publish.

### JWT toolkit

For any detected JWT:

- **Decoded view** — header, payload, signature segments shown separately
  with syntax highlighting; expiration parsed and shown as a human-readable
  countdown
- **Claim editor** — edit any claim in the payload; AuthForge will
  re-encode and re-sign (or set `alg: none`)
- **Attack variants** — generate categorized variants:
  - **recon** — variants useful only for surfacing server behavior (e.g.
    `alg: none`, empty signature, expired-but-otherwise-valid)
  - **test** — claim tampering (mutate `sub`, `aud`, `iss`, etc.) to
    detect whether the server checks them
  - **attack** — `kid` SQL/path injection, `jku` injection, alg confusion
    (HS256 signed with the RSA public key)
- **Replay variant** — if the JWT was captured in a network entry, each
  variant has a "Replay this request with this variant" button. The
  request fires from the page MAIN world with the variant substituted into
  the Authorization header; the response is shown inline
- **HMAC brute force** — for HS256/384/512 tokens, paste a wordlist (or
  use the default top-1000) and AuthForge tries each as the signing
  secret. Hits are reported with the cracked secret

---

## Permissions: what each one does and why it's needed

The extension declares the following permissions. Each is justified below
with the specific feature it enables. If any of these feel like too much,
the source is fully readable — every permission use is reachable from a
single message dispatcher in `background/service-worker.js`.

### `cookies`

- **Purpose**: Read, create, modify, and delete cookies via
  `chrome.cookies`. Subscribe to `chrome.cookies.onChanged` for the live
  cookie-change feed
- **Used by**: the entire Cookies tab; Snapshots cookie capture / restore;
  Profiles cookie transplant
- **Without it**: AuthForge couldn't read any cookies — the core feature
  wouldn't work

### `storage`

- **Purpose**: Persist user settings, snapshots, and profiles via
  `chrome.storage.local`. Remember network capture state across
  service-worker restarts via `chrome.storage.session`
- **Used by**: Options panel (themes, custom regex patterns, network
  buffer size, etc.), Snapshots, Profiles, network-capture buffer
  persistence
- **Without it**: settings wouldn't survive a popup close; snapshots
  couldn't be saved

### `tabs`

- **Purpose**: Read tab IDs, URLs, and window structure via `chrome.tabs`.
  Used to identify which tab AuthForge is operating on
- **Used by**: Cookies tab (knowing the current tab's URL to scope cookie
  queries), Wide-mode popup (passing the source tab ID through the URL),
  All-open-tabs aggregation, the audit's source-URL attribution
- **Without it**: AuthForge wouldn't know which tab to operate on

### `activeTab`

- **Purpose**: Temporary scripting and host access to the tab the user
  invoked the extension on, granted at click time
- **Used by**: Reading localStorage / sessionStorage from the active tab
  via `chrome.scripting.executeScript` injecting `world: "MAIN"`
- **Without it**: Web storage couldn't be read or modified (those APIs
  aren't reachable from extension contexts; they must be executed in the
  page itself)

### `scripting`

- **Purpose**: Programmatic script injection via `chrome.scripting.execute
  Script` (instead of the deprecated `chrome.tabs.executeScript`)
- **Used by**: All localStorage / sessionStorage / IndexedDB reads and
  writes. The Request Workbench's page-context replay (so cookies and CORS
  behave naturally)
- **Without it**: Same as `activeTab` — no web-storage access

### `sidePanel`

- **Purpose**: Optionally open the same UI as a Chrome side panel rather
  than a toolbar popup. Configured to NOT open automatically on action
  click — the popup is still the default. The side panel is available as
  an alternative surface for users who prefer it
- **Used by**: Users who pin the side panel via Chrome's UI
- **Without it**: One less UI surface; popup and the wide-mode window
  would still work fine

### `webRequest`

- **Purpose**: Observe (not block, not modify) HTTP(S) request and
  response headers via `chrome.webRequest.onBeforeSendHeaders`,
  `onHeadersReceived`, `onCompleted`, and `onErrorOccurred`
- **Used by**: The Network tab's passive headers-only capture (the
  default capture mode). This is HOW AuthForge sees Authorization
  headers, Set-Cookie responses, and custom auth headers leaving / entering
  the browser
- **Without it**: The Network tab would be empty. Note that `webRequest`
  in MV3 is *observation only* — AuthForge has no `webRequestBlocking`
  permission and cannot block, redirect, or modify in-flight traffic. The
  Workbench's replay uses a fresh `fetch()` from the page, not interception

### `debugger`

- **Purpose**: Opt-in deep network capture (response bodies, not just
  headers) via the Chrome DevTools Protocol. Requires explicit per-tab
  user opt-in (the "Deep capture" toggle in the Network tab)
- **Used by**: The optional `chrome.debugger`-based capture path that
  reads response bodies without needing DevTools open. Attaching shows
  Chrome's yellow "AuthForge started debugging this browser" banner so
  the user is always aware
- **Without it**: Response-body inspection only works when AuthForge's own
  DevTools panel is open

### `host_permissions: ["<all_urls>"]`

- **Purpose**: Permission to operate on any URL — read cookies for, inject
  scripts into, and observe network requests for any site the user visits
- **Why broad**: AuthForge is a cross-site analysis tool. Constraining
  hosts at install time would require either listing every domain the
  user might want to inspect (impossible) or asking for permission
  per-domain at every use (terrible UX for a tool whose main job is
  comparing artifacts across many sites)
- **What AuthForge does NOT do with this**: contact any remote endpoint
  (no telemetry, no analytics, no auto-updates beyond Chrome's own).
  Cross-domain operations are user-initiated only

### `incognito: "split"`

- **Purpose**: When the user is in incognito mode, AuthForge runs as a
  separate process with no shared state with the regular profile. Cookies
  and snapshots captured in incognito stay in incognito
- **Without it**: Incognito and regular state could mix, which would be
  surprising and a privacy regression

---

## Privacy and data handling

- **No remote endpoints under the author's control are contacted**, ever
- **No analytics, telemetry, error reporting, or update pings** beyond
  Chrome's own
- **All state is local** — `chrome.storage.local` (snapshots, settings,
  profiles) and `chrome.storage.session` (network capture buffer). Both
  are isolated per extension and never sync without an explicit user
  action (and there is no implemented sync mechanism)
- **Network capture buffer** lives in `chrome.storage.session` so it
  doesn't outlive the browser session. It contains auth headers and
  Set-Cookie values — by design, since the user opted to capture them —
  but never leaves the browser
- **JWT secret-cracking** runs entirely in the service worker; the
  candidate wordlist is local
- **Microsoft Graph recon and FOCI exchange** make outbound HTTPS
  requests, but only to Microsoft-owned endpoints (a static allowlist in
  the service worker). Tokens are not exfiltrated; the response is
  rendered in the popup
- **No content scripts run on page load**. Scripts are only injected when
  the user opens AuthForge or explicitly triggers a read/write through it
- **Request replays** fire from the page's own MAIN world. They are
  indistinguishable from a request the page itself made via `fetch()` —
  no extension-only headers are added

---

## Installation

### From source (developer mode)

1. Download or clone this repository
2. Open `chrome://extensions/` (or `edge://extensions/`)
3. Toggle **Developer mode** on (top right)
4. Click **Load unpacked** and select the repository folder
5. Pin AuthForge to the toolbar via the puzzle icon for quick access

### From the Chrome Web Store

(Pending — to be linked once published.)

### Minimum browser version

Chrome 114 or compatible (Microsoft Edge, Brave, Vivaldi, Arc, etc.). The
`sidePanel` API and several MV3 features require this baseline.

---

## Architecture

```
authforge/
├── manifest.json
├── background/
│   ├── service-worker.js       — message router, chrome.* gateway
│   ├── network-capture.js      — webRequest observer
│   └── debugger-capture.js     — optional CDP-based deep capture
├── popup/
│   ├── popup.html              — UI shell loaded into both popup and side panel
│   ├── popup.js                — entry point; pre-seeds state from URL params
│   ├── popup.css               — popup-specific styles (wide-mode)
├── devtools/
│   ├── devtools.html / .js     — DevTools panel registration
│   ├── panel.html / .js        — the DevTools UI surface (same StorageForgeApp)
│   ├── network-body-scanner.js — DevTools-only request/response body scan
├── options/
│   ├── options.html            — full settings page
│   ├── options.js              — settings load/save via storage API
├── shared/
│   ├── ui.js                   — AuthForgeApp class (the entire UI)
│   ├── api.js                  — chrome.runtime.sendMessage wrappers
│   ├── theme.css               — design tokens and component CSS
│   ├── jwt.js                  — JWT decode / encode / verify / attack-gen
│   ├── audit.js                — cookie + storage + network + entra audit
│   ├── entra.js                — Microsoft Entra analyzer, FOCI clients,
│   │                            recon endpoints, audience mapping
│   ├── token-body-scanner.js   — JWT detection in response bodies
│   ├── storage-injector.js     — page-world functions for LS/SS/IDB
│   ├── formats.js              — import/export between Cookie-Editor /
│   │                            Netscape / EditThisCookie formats
│   ├── profile-formats.js      — profile import/export
│   ├── har.js                  — HAR import for the Network tab
│   └── history.js              — undo/redo store
├── icons/                      — 16/32/48/128 px PNGs
└── README.md                   — this file
```

The service worker is the only context with `chrome.cookies`,
`chrome.webRequest`, `chrome.debugger`, and `chrome.scripting`. The popup,
DevTools panel, and options page talk to it via
`chrome.runtime.sendMessage`. There is one dispatcher (`handleRequest` in
`background/service-worker.js`) — auditing every privileged action is a
matter of reading one switch statement.

UI code is fully module-based — no bundler, no build step required. The
extension loads ES modules directly from disk.

---

## Known limitations

- **Response bodies via webRequest** — not available in MV3 (Chrome
  removed this for performance reasons). Use the AuthForge DevTools panel
  or the opt-in `chrome.debugger` mode to see bodies
- **WebSocket frames** — not captured. `chrome.webRequest` reports the
  upgrade handshake but not individual frames
- **HTTP/3 / QUIC over UDP** — observed via `chrome.webRequest` like any
  other request; the URL and headers are visible
- **Service worker cold-start latency** — first popup open after Chrome
  restart can take 5–10 seconds in some Edge / Chromium fork builds. The
  popup shows a "Loading…" placeholder until the SW wakes; no timeout
  cuts data short
- **CHIPS partitioned cookies in Edge** — some Edge / Chromium fork
  builds do not fire the callback for
  `chrome.cookies.getAll({partitionKey:{}})`. AuthForge wraps that call
  in a 1.5-second timeout race at both the SW and UI layers, so worst case
  the partitioned-cookies subset is empty and the primary cookie list still
  populates correctly
- **Devtools panel** — works, but the popup is the main supported
  surface. DevTools shares the same UI



---

## License

AuthForge is released under the **MIT License**. The full text is in the
[`LICENSE`](LICENSE) file at the root of the repository.

In short: you can use, copy, modify, merge, publish, distribute, sublicense,
and sell copies of the software, provided that the copyright notice and the
permission notice are included in all copies or substantial portions. The
software is provided "as is", without warranty of any kind.

Copyright © 2026 mthcht. Source code: <https://github.com/mthcht/AuthForge>.
