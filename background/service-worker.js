/**
 * AuthForge — Service Worker (background/service-worker.js)
 *
 * Routes messages between the popup/devtools UI and the chrome.* APIs that
 * are only available in extension contexts. Manages:
 *   - chrome.cookies CRUD
 *   - chrome.scripting injection for page-side localStorage / sessionStorage /
 *     IndexedDB (the page APIs aren't reachable from MV3 service workers, so
 *     we forward to the page via executeScript with world:"MAIN").
 *   - Live cookie change broadcasts.
 *   - Snapshot persistence (chrome.storage.local).
 */

import { PAGE_FUNCTIONS } from '../shared/storage-injector.js';
import { networkCapture } from './network-capture.js';
import { debuggerCapture } from './debugger-capture.js';

// Wire debugger detach events into the broadcast channel so the UI can
// reactively show "you got detached" feedback.
debuggerCapture.setDetachListener((tabId, reason) => {
  broadcast({ type: 'debuggerDetached', tabId, reason });
});

const ports = new Set();

// ---------- Boot --------------------------------------------------------------

chrome.runtime.onInstalled.addListener((details) => {
  console.log('[AuthForge] installed:', details.reason);
  // On a fresh install (not update / chrome_update / shared_module_update),
  // open the welcome page in a new tab so the user knows what they just got.
  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('welcome/welcome.html') });
  }
});

// Allow opening the side panel from the toolbar icon as a fallback for users
// who don't want the popup behaviour.
if (chrome.sidePanel?.setPanelBehavior) {
  chrome.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: false })
    .catch((e) => console.warn('[AuthForge] sidePanel setup failed', e));
}

// ---------- Long-lived port connections (devtools panel) ---------------------

chrome.runtime.onConnect.addListener((port) => {
  ports.add(port);
  port.onDisconnect.addListener(() => ports.delete(port));
});

function broadcast(message) {
  for (const port of ports) {
    try {
      port.postMessage(message);
    } catch (e) {
      ports.delete(port);
    }
  }
}

// ---------- Cookie change live feed -------------------------------------------

chrome.cookies.onChanged.addListener((changeInfo) => {
  broadcast({ type: 'cookiesChanged', changeInfo });
});

// ---------- Request/response (popup, options) ---------------------------------

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  handleRequest(req)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => {
      console.error('[AuthForge] handler error', req?.type, err);
      sendResponse({ ok: false, error: err?.message || String(err) });
    });
  return true; // keep the channel open for async sendResponse
});

async function handleRequest(req) {
  switch (req.type) {
    // ---- Tab helpers ----
    case 'getCurrentTab': {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });
      return tab || null;
    }
    case 'getTabById': {
      // The API wrapper sends params as { tabId } under req.params, not at
      // the top level. Reading req.tabId here gave undefined, which caused
      // chrome.tabs.get(undefined) → "No matching signature" — the error
      // you'd see when opening the wide-mode popup with a pinned tab.
      return chrome.tabs.get(req.params.tabId);
    }
    case 'getAllTabs': {
      return chrome.tabs.query({});
    }

    // ---- Cookies ----
    case 'cookies.getAll': {
      const { url, domain, storeId } = req.params || {};
      const params = {};
      if (url) params.url = url;
      if (domain) params.domain = domain;
      if (storeId) params.storeId = storeId;
      return chrome.cookies.getAll(params);
    }
    // Separate handler for CHIPS (Cookies Having Independent Partitioned
    // State) — Chrome 119+. Kept isolated from cookies.getAll because
    // chrome.cookies.getAll({partitionKey:{}}) is known to hang forever
    // (callback never fires) on some Edge / Chromium fork builds. We
    // wrap with Promise.race against a 1.5s timeout so this handler is
    // guaranteed to return within 1.5s no matter what the underlying
    // chrome.* call does. Worst case: caller gets [] and primary cookies
    // are unaffected.
    case 'cookies.getAllPartitioned': {
      const { url, domain, storeId } = req.params || {};
      const params = { partitionKey: {} };
      if (url) params.url = url;
      if (domain) params.domain = domain;
      if (storeId) params.storeId = storeId;
      return Promise.race([
        (async () => {
          try { return await chrome.cookies.getAll(params); }
          catch { return []; }
        })(),
        new Promise((resolve) => setTimeout(() => resolve([]), 1500)),
      ]);
    }
    case 'cookies.set': {
      // Round-trip partitionKey if the UI sent one (CHIPS cookies must be
      // written with partitionKey set or they become unpartitioned)
      return chrome.cookies.set(req.params.cookie);
    }
    case 'cookies.remove': {
      const { name, url, storeId, partitionKey } = req.params;
      const params = { name, url };
      if (storeId) params.storeId = storeId;
      if (partitionKey) params.partitionKey = partitionKey;
      return chrome.cookies.remove(params);
    }
    case 'cookies.getAllStores': {
      return chrome.cookies.getAllCookieStores();
    }

    // ---- Page-side storage (proxied through chrome.scripting) ----
    case 'page.localStorage.getAll':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.localStorageGetAll);
    case 'page.localStorage.set':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.localStorageSet, [
        req.params.key,
        req.params.value,
      ]);
    case 'page.localStorage.remove':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.localStorageRemove, [
        req.params.key,
      ]);
    case 'page.localStorage.clear':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.localStorageClear);

    case 'page.sessionStorage.getAll':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.sessionStorageGetAll);
    case 'page.sessionStorage.set':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.sessionStorageSet, [
        req.params.key,
        req.params.value,
      ]);
    case 'page.sessionStorage.remove':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.sessionStorageRemove, [
        req.params.key,
      ]);
    case 'page.sessionStorage.clear':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.sessionStorageClear);

    case 'page.indexedDB.listDatabases':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.idbListDatabases);
    case 'page.indexedDB.readDatabase':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.idbReadDatabase, [
        req.params.dbName,
      ]);
    case 'page.indexedDB.putRecord':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.idbPutRecord, [
        req.params.dbName,
        req.params.storeName,
        req.params.key,
        req.params.value,
      ]);
    case 'page.indexedDB.deleteRecord':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.idbDeleteRecord, [
        req.params.dbName,
        req.params.storeName,
        req.params.key,
      ]);
    case 'page.indexedDB.deleteDatabase':
      return runInPage(req.params.tabId, PAGE_FUNCTIONS.idbDeleteDatabase, [
        req.params.dbName,
      ]);

    // ---- "All open tabs" aggregations -------------------------------------
    //
    // localStorage, sessionStorage, and IndexedDB are per-origin and require
    // an open tab to inject into. We can't see storage for sites that aren't
    // open. The best we can do is iterate every regular http(s) tab, inject
    // the same page-function into each, and aggregate the results, grouped
    // by origin.
    //
    // The UI uses these when the scope picker is set to "All sites".
    case 'page.localStorage.getAllAcrossTabs':
      return collectAcrossTabs(PAGE_FUNCTIONS.localStorageGetAll);
    case 'page.sessionStorage.getAllAcrossTabs':
      return collectAcrossTabs(PAGE_FUNCTIONS.sessionStorageGetAll);
    case 'page.indexedDB.listAcrossTabs':
      return collectAcrossTabs(PAGE_FUNCTIONS.idbListDatabases);

    // ---- Snapshots (extension storage) ----
    case 'snapshot.list': {
      const { snapshots = {} } = await chrome.storage.local.get('snapshots');
      return snapshots;
    }
    case 'snapshot.save': {
      const { snapshots = {} } = await chrome.storage.local.get('snapshots');
      snapshots[req.params.id] = req.params.snapshot;
      await chrome.storage.local.set({ snapshots });
      return true;
    }
    case 'snapshot.delete': {
      const { snapshots = {} } = await chrome.storage.local.get('snapshots');
      delete snapshots[req.params.id];
      await chrome.storage.local.set({ snapshots });
      return true;
    }

    // ---- Settings ----
    case 'settings.get': {
      const { settings = {} } = await chrome.storage.local.get('settings');
      return settings;
    }
    case 'settings.set': {
      await chrome.storage.local.set({ settings: req.params.settings });
      return true;
    }

    // ---- Bulk: get a full domain snapshot in one round-trip ----
    case 'snapshot.capture': {
      const { tabId, url } = req.params;
      const [cookies, ls, ss, idb] = await Promise.all([
        chrome.cookies.getAll({ url }),
        runInPage(tabId, PAGE_FUNCTIONS.localStorageGetAll).catch(() => []),
        runInPage(tabId, PAGE_FUNCTIONS.sessionStorageGetAll).catch(() => []),
        runInPage(tabId, PAGE_FUNCTIONS.idbListDatabases).catch(() => []),
      ]);
      return {
        url,
        capturedAt: Date.now(),
        cookies,
        localStorage: ls,
        sessionStorage: ss,
        indexedDBDatabases: idb,
      };
    }

    // ---- Profiles: reusable, portable credential bundles -------------------
    //
    // A profile is like a snapshot, but designed to be applied across
    // environments. It carries cookies + LS/SS + auth-header hints, plus
    // optional notes. Apply-time supports domain remapping, so a profile
    // captured on dev.example.com can be re-targeted at staging.example.com.

    case 'profiles.list': {
      const { profiles = {} } = await chrome.storage.local.get('profiles');
      return profiles;
    }
    case 'profiles.save': {
      const { profiles = {} } = await chrome.storage.local.get('profiles');
      const now = Date.now();
      const existing = profiles[req.params.id];
      profiles[req.params.id] = {
        ...req.params.profile,
        id: req.params.id,
        createdAt: existing?.createdAt || now,
        updatedAt: now,
      };
      await chrome.storage.local.set({ profiles });
      return profiles[req.params.id];
    }
    case 'profiles.delete': {
      const { profiles = {} } = await chrome.storage.local.get('profiles');
      delete profiles[req.params.id];
      await chrome.storage.local.set({ profiles });
      return true;
    }
    case 'profiles.capture': {
      // Capture the current state of a tab as a brand-new profile (saved by
      // caller). Same shape as snapshot.capture but excludes IDB databases —
      // profiles are about credentials, not data.
      const { tabId, url } = req.params;
      const [cookies, ls, ss] = await Promise.all([
        chrome.cookies.getAll({ url }),
        runInPage(tabId, PAGE_FUNCTIONS.localStorageGetAll).catch(() => []),
        runInPage(tabId, PAGE_FUNCTIONS.sessionStorageGetAll).catch(() => []),
      ]);
      return {
        sourceUrl: url,
        sourceDomain: safeHostname(url),
        cookies,
        localStorage: ls,
        sessionStorage: ss,
        authHeaders: [],
      };
    }
    case 'profiles.apply': {
      return applyProfile(req.params);
    }

    // ---- Network capture ---------------------------------------------------
    case 'network.status': {
      return {
        available: networkCapture.available(),
        recording: networkCapture.isRecording(),
      };
    }
    case 'network.start': {
      networkCapture.start();
      broadcast({ type: 'networkStatusChanged', recording: true });
      return true;
    }
    case 'network.stop': {
      networkCapture.stop();
      broadcast({ type: 'networkStatusChanged', recording: false });
      return true;
    }
    case 'network.clear': {
      networkCapture.clear();
      broadcast({ type: 'networkBufferCleared' });
      return true;
    }
    case 'network.list': {
      return networkCapture.list(req.params || {});
    }
    case 'network.addBodyFinding': {
      // From the devtools panel — adds a body-scan finding to the buffer
      const e = networkCapture.addBodyFinding(req.params.entry || {});
      broadcast({ type: 'networkEntryAdded', entry: e });
      return e;
    }

    // ---- Debugger-based deep capture (CDP) ---------------------------------
    case 'debugger.status': {
      return {
        available: debuggerCapture.available(),
        attachedTabs: debuggerCapture.attachedTabs(),
      };
    }
    case 'debugger.attach': {
      const r = await debuggerCapture.attach(req.params.tabId);
      broadcast({ type: 'debuggerAttached', tabId: req.params.tabId });
      return r;
    }
    case 'debugger.detach': {
      const r = await debuggerCapture.detach(req.params.tabId);
      broadcast({ type: 'debuggerDetached', tabId: req.params.tabId, reason: 'user_request' });
      return r;
    }
    case 'debugger.detachAll': {
      const r = await debuggerCapture.detachAll();
      broadcast({ type: 'debuggerDetachedAll' });
      return r;
    }

    // ---- JWT Attack Replay -------------------------------------------------
    //
    // Re-fire a captured request from the page's own context, with the
    // Authorization header swapped for a mutated variant. Page-context
    // execution means cookies are sent and CORS plays out naturally — we
    // see exactly what an attacker exploiting an XSS or running against
    // their own session would see. GET-only by default for safety.
    case 'replay.request': {
      const {
        tabId, url, method, headers, body, credentials,
        redirect, cache, mode, referrer, referrerPolicy,
        integrity, keepalive, timeoutMs, fullResponse,
      } = req.params;
      if (typeof tabId !== 'number') throw new Error('tabId is required');
      if (!url || !/^https?:/i.test(url)) throw new Error('Invalid URL');
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        world: 'MAIN',
        func: pageReplay,
        args: [{
          url, method, headers, body, credentials,
          redirect, cache, mode, referrer, referrerPolicy,
          integrity, keepalive, timeoutMs, fullResponse,
        }],
      });
      const r = results?.[0]?.result;
      if (!r) throw new Error('Replay failed (no result)');
      return r;
    }

    // ---- Direct authenticated fetch (used for Microsoft Graph recon) ----
    case 'entra.graphFetch': {
      const { url, token, method = 'GET' } = req.params || {};
      if (!url || !isMicrosoftEndpoint(url)) {
        throw new Error('Refusing to fetch — URL is not a Microsoft endpoint.');
      }
      if (!token) throw new Error('token is required');
      const startedAt = Date.now();
      try {
        const r = await fetch(url, {
          method,
          headers: {
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/json',
          },
        });
        let bodyText = '';
        try { bodyText = await r.text(); } catch {}
        let parsed = null;
        try { parsed = bodyText ? JSON.parse(bodyText) : null; } catch {}
        return {
          ok: r.ok,
          status: r.status,
          statusText: r.statusText,
          durationMs: Date.now() - startedAt,
          body: parsed,
          bodyText: parsed ? null : bodyText.slice(0, 4000),
        };
      } catch (e) {
        return {
          ok: false,
          status: 0,
          error: String(e?.message || e),
          durationMs: Date.now() - startedAt,
        };
      }
    }

    // ---- FOCI (Family of Client IDs) refresh token exchange -------------
    //
    // The big GraphSpy / ROADtools move: Microsoft's first-party clients
    // share a refresh-token "family". A refresh token issued to one FOCI
    // client can be exchanged for an access token belonging to any other
    // FOCI client — meaning a refresh token captured from Outlook Web can
    // be swapped for a Graph, Teams, SharePoint, or Azure CLI access
    // token. This pivots laterally between Microsoft services without
    // needing the user to re-auth.
    //
    // Endpoint: POST {tenant_authority}/oauth2/v2.0/token
    //   client_id={target_foci_client_id}
    //   refresh_token={captured_rt}
    //   grant_type=refresh_token
    //   scope={target_scope}
    case 'entra.refreshFOCI': {
      const { refreshToken, clientId, scope, tenantId } = req.params || {};
      if (!refreshToken) throw new Error('refreshToken is required');
      if (!clientId) throw new Error('clientId is required');
      const tenant = tenantId || 'common';
      const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(tenant)}/oauth2/v2.0/token`;
      const body = new URLSearchParams({
        client_id: clientId,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
        scope: scope || 'https://graph.microsoft.com/.default offline_access',
      });
      const startedAt = Date.now();
      try {
        const r = await fetch(tokenUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
          },
          body: body.toString(),
        });
        const text = await r.text();
        let parsed = null;
        try { parsed = JSON.parse(text); } catch {}
        return {
          ok: r.ok,
          status: r.status,
          durationMs: Date.now() - startedAt,
          body: parsed,
          bodyText: parsed ? null : text.slice(0, 4000),
        };
      } catch (e) {
        return {
          ok: false,
          status: 0,
          error: String(e?.message || e),
          durationMs: Date.now() - startedAt,
        };
      }
    }

    default:
      throw new Error('Unknown request type: ' + req?.type);
  }
}

/**
 * Allowlist for AuthForge's authenticated outbound fetches. Limits the
 * surface so the extension can't be coerced into being a generic credential
 * exfiltration tool — we only let it talk to Microsoft service hosts.
 *
 * The hostname is matched against a fixed list of trusted suffixes covering
 * Entra, Graph, Outlook, Office 365, SharePoint, Azure, Live, Yammer, Power
 * BI, Dynamics 365, Intune, plus US Government / China sovereign clouds.
 */
function isMicrosoftEndpoint(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch { return false; }
  const trustedSuffixes = [
    // Identity / authentication
    'login.microsoftonline.com',
    'login.microsoftonline.us',
    'login.microsoftonline.de',
    'login.partner.microsoftonline.cn',
    'login.windows.net',
    'sts.windows.net',
    'login.live.com',
    'login.microsoft.com',
    'b2clogin.com',
    // Microsoft Graph (current + legacy)
    'graph.microsoft.com',
    'graph.microsoft.us',
    'dod-graph.microsoft.us',
    'microsoftgraph.chinacloudapi.cn',
    'graph.windows.net',
    // Office / Outlook
    'outlook.office.com',
    'outlook.office365.com',
    'outlook.office.us',
    'partner.outlook.cn',
    'office.com',
    'office.net',
    'office365.com',
    'microsoft365.com',
    'protection.outlook.com',
    // SharePoint / OneDrive
    'sharepoint.com',
    'sharepoint.us',
    'sharepoint.cn',
    'sharepoint-df.com',
    'onedrive.com',
    'onedrive.live.com',
    // Azure (management, key vault, storage, etc.)
    'management.azure.com',
    'management.usgovcloudapi.net',
    'management.chinacloudapi.cn',
    'management.core.windows.net',
    'vault.azure.net',
    'vault.azure.cn',
    'vault.usgovcloudapi.net',
    'storage.azure.com',
    'database.windows.net',
    'servicebus.azure.net',
    'eventgrid.azure.net',
    'azureedge.net',
    'azurewebsites.net',
    'azure.com',
    // Teams
    'teams.microsoft.com',
    'teams.microsoft.us',
    'teams.live.com',
    // Power Platform / BI
    'analysis.windows.net',
    'powerbi.com',
    'api.powerbi.com',
    'powerapps.com',
    // Dynamics
    'dynamics.com',
    // Intune / device management
    'manage.microsoft.com',
    'enterpriseregistration.windows.net',
    // Microsoft Account (consumer)
    'live.com',
    'msn.com',
    'xboxlive.com',
    // Sovereign clouds — broad catches
    'microsoftonline.com',
    'microsoftonline.us',
    'microsoftonline.de',
    'microsoft.us',
    'microsoft.cn',
    'partner.microsoftonline.cn',
  ];
  return trustedSuffixes.some((suffix) => host === suffix || host.endsWith('.' + suffix));
}

/**
 * Run a function in the MAIN world of a page tab. Returns the function's
 * return value (which must be JSON-serializable, or a Promise resolving to
 * one).
 */
async function runInPage(tabId, func, args = []) {
  const results = await chrome.scripting.executeScript({
    target: { tabId },
    world: 'MAIN',
    func,
    args,
  });
  if (!results || !results[0]) {
    throw new Error('Script injection failed (no result frame)');
  }
  const result = results[0].result;
  // The injected function may resolve to { error } when it caught something
  // synchronously — surface it as a real exception so the caller can handle.
  if (result && typeof result === 'object' && result.__error) {
    throw new Error(result.__error);
  }
  return result;
}

/**
 * Run the same page-function in every open http(s) tab, in parallel, and
 * return a flat list grouped by origin. Used to power the "All sites" scope
 * for localStorage / sessionStorage / IndexedDB.
 *
 * Returned shape:
 *   [{ tabId, url, origin, entries: <whatever the injected func returns> }, ...]
 *
 * Tabs where injection fails (system pages, restricted origins, etc.) are
 * silently skipped — we don't want one privileged URL aborting the rest.
 */
async function collectAcrossTabs(fn) {
  const tabs = await chrome.tabs.query({});
  const results = await Promise.all(
    tabs.map(async (tab) => {
      if (!tab.url || !/^https?:/i.test(tab.url)) return null;
      try {
        const entries = await runInPage(tab.id, fn);
        if (!entries || (Array.isArray(entries) && entries.length === 0)) {
          return null;
        }
        let origin = '';
        try { origin = new URL(tab.url).origin; } catch {}
        return { tabId: tab.id, url: tab.url, origin, entries };
      } catch {
        return null;
      }
    })
  );
  return results.filter(Boolean);
}

// ============================================================================
// Profile application — apply a saved credential bundle to a tab, with
// optional domain remapping and optional "clear current state first".
// ============================================================================

/**
 * @param {object} params
 * @param {object} params.profile      The profile to apply (raw object).
 * @param {number} params.tabId        Tab to inject LS/SS into.
 * @param {string} params.targetUrl    URL to scope cookies / page access to.
 * @param {boolean} [params.remapDomain]  If true, rewrite cookie domains from
 *   params.sourceHost → host of targetUrl (suffix-replace).
 * @param {string}  [params.sourceHost]   Source host to remap from. Defaults
 *   to profile.sourceDomain.
 * @param {boolean} [params.clearFirst]   Wipe current cookies + LS/SS first.
 * @param {boolean} [params.includeStorage]  Apply LS/SS (default true).
 * @returns {Promise<{cookiesApplied:number, cookiesFailed:Array, lsApplied:number, ssApplied:number, cleared:boolean}>}
 */
async function applyProfile(params) {
  const {
    profile,
    tabId,
    targetUrl,
    remapDomain = false,
    sourceHost,
    clearFirst = false,
    includeStorage = true,
  } = params;

  if (!profile) throw new Error('No profile provided.');
  if (!targetUrl) throw new Error('targetUrl is required.');

  const targetHost = safeHostname(targetUrl);
  if (!targetHost) throw new Error('targetUrl is not a valid URL.');
  const fromHost = (sourceHost || profile.sourceDomain || '').replace(/^\./, '');

  const report = {
    cookiesApplied: 0,
    cookiesFailed: [],
    lsApplied: 0,
    ssApplied: 0,
    cleared: false,
  };

  // ---- Optional clear ------------------------------------------------------
  if (clearFirst) {
    const existing = await chrome.cookies.getAll({ url: targetUrl });
    await Promise.all(
      existing.map((c) =>
        chrome.cookies.remove({
          url: buildCookieUrl(c),
          name: c.name,
          storeId: c.storeId,
        }).catch(() => null)
      )
    );
    if (includeStorage && tabId) {
      await Promise.all([
        runInPage(tabId, PAGE_FUNCTIONS.localStorageClear).catch(() => null),
        runInPage(tabId, PAGE_FUNCTIONS.sessionStorageClear).catch(() => null),
      ]);
    }
    report.cleared = true;
  }

  // ---- Cookies -------------------------------------------------------------
  for (const cookie of profile.cookies || []) {
    if (!cookie.name) continue;
    const rewritten = remapDomain && fromHost
      ? remapCookieDomain(cookie, fromHost, targetHost)
      : cookie;
    const setParams = cookieToSetParams(rewritten, targetUrl);
    try {
      const result = await chrome.cookies.set(setParams);
      if (result) {
        report.cookiesApplied++;
      } else {
        report.cookiesFailed.push({ name: cookie.name, reason: 'set returned null' });
      }
    } catch (e) {
      report.cookiesFailed.push({ name: cookie.name, reason: e.message });
    }
  }

  // ---- Storage -------------------------------------------------------------
  if (includeStorage && tabId) {
    for (const entry of profile.localStorage || []) {
      if (!entry?.key) continue;
      try {
        await runInPage(tabId, PAGE_FUNCTIONS.localStorageSet, [entry.key, entry.value ?? '']);
        report.lsApplied++;
      } catch {
        /* skip */
      }
    }
    for (const entry of profile.sessionStorage || []) {
      if (!entry?.key) continue;
      try {
        await runInPage(tabId, PAGE_FUNCTIONS.sessionStorageSet, [entry.key, entry.value ?? '']);
        report.ssApplied++;
      } catch {
        /* skip */
      }
    }
  }

  return report;
}

/**
 * Build a URL that chrome.cookies.set/remove will accept for this cookie.
 * Cookies need a URL whose origin matches their (secure, domain, path).
 */
function buildCookieUrl(cookie) {
  const scheme = cookie.secure ? 'https' : 'http';
  const host = cookie.domain ? cookie.domain.replace(/^\./, '') : 'localhost';
  return scheme + '://' + host + (cookie.path || '/');
}

/**
 * Translate a chrome.cookies object into the parameter shape required by
 * chrome.cookies.set. Honors the target URL when the cookie's domain has
 * been rewritten and might no longer match a self-built URL.
 */
function cookieToSetParams(cookie, fallbackUrl) {
  const out = {
    url: fallbackUrl || buildCookieUrl(cookie),
    name: cookie.name,
    value: String(cookie.value ?? ''),
    path: cookie.path || '/',
    secure: !!cookie.secure,
    httpOnly: !!cookie.httpOnly,
    sameSite: cookie.sameSite || 'unspecified',
  };
  if (cookie.storeId) out.storeId = cookie.storeId;
  // Domain: hostOnly cookies must NOT have a domain attribute. Domain-scoped
  // cookies should pass through. Leading dot is fine for chrome.cookies.set.
  if (!cookie.hostOnly && cookie.domain) {
    out.domain = cookie.domain;
  }
  if (cookie.expirationDate) {
    out.expirationDate = cookie.expirationDate;
  }
  // Partitioned (CHIPS) cookies — Chrome 119+. The `partitionKey` is an
  // object like { topLevelSite: "https://example.com" }. If the user is
  // editing a partitioned cookie we must round-trip the partitionKey or
  // it will be written as unpartitioned (effectively a different cookie).
  if (cookie.partitionKey) {
    out.partitionKey = cookie.partitionKey;
  }
  return out;
}

/**
 * Suffix-replace a cookie's domain. Used when applying a profile captured on
 * one environment to a different environment.
 *
 *   cookie.domain = ".dev.example.com",  from = "dev.example.com",
 *   to = "staging.example.com"  →  ".staging.example.com"
 *
 *   cookie.domain = "auth.dev.example.com",  from = "dev.example.com",
 *   to = "staging.example.com"  →  "auth.staging.example.com"
 */
function remapCookieDomain(cookie, fromHost, toHost) {
  if (!cookie.domain) return cookie;
  const leadingDot = cookie.domain.startsWith('.');
  const bare = cookie.domain.replace(/^\./, '').toLowerCase();
  const from = fromHost.toLowerCase();
  const to = toHost;

  let newBare;
  if (bare === from) {
    newBare = to;
  } else if (bare.endsWith('.' + from)) {
    newBare = bare.slice(0, -from.length) + to;
  } else {
    // No match — leave the cookie untouched; chrome.cookies.set may reject
    // it, and the caller will see that in cookiesFailed.
    return cookie;
  }
  return {
    ...cookie,
    domain: (leadingDot ? '.' : '') + newBare,
  };
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/**
 * Injected into the page (MAIN world) by replay.request. Re-fires a captured
 * request from the page's own context — so cookies, CORS, and any auth other
 * than the Authorization header behave exactly as they did originally.
 *
 * MUST be self-contained — chrome.scripting won't pass closures.
 */
async function pageReplay(req) {
  const start = performance.now();
  try {
    const controller = new AbortController();
    const timeoutMs = Number(req.timeoutMs) || 15000;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const fetchInit = {
      method: req.method || 'GET',
      headers: req.headers || {},
      credentials: req.credentials || 'include',
      signal: controller.signal,
      // see redirects rather than silently following — gives pentester visibility
      redirect: req.redirect || 'manual',
    };
    // Body — fetch requires no body for GET/HEAD, otherwise pass through
    const noBodyMethods = new Set(['GET', 'HEAD']);
    if (req.body != null && !noBodyMethods.has(fetchInit.method.toUpperCase())) {
      fetchInit.body = req.body;
    }
    // Optional extras
    if (req.cache) fetchInit.cache = req.cache;
    if (req.mode) fetchInit.mode = req.mode;
    if (req.referrer != null) fetchInit.referrer = req.referrer;
    if (req.referrerPolicy) fetchInit.referrerPolicy = req.referrerPolicy;
    if (req.integrity) fetchInit.integrity = req.integrity;
    if (req.keepalive) fetchInit.keepalive = true;

    const response = await fetch(req.url, fetchInit);
    clearTimeout(timeout);
    let text = '';
    try { text = await response.text(); } catch { /* body unreadable, fine */ }
    const headersObj = {};
    response.headers.forEach((v, k) => { headersObj[k] = v; });
    const out = {
      ok: true,
      status: response.status,
      statusText: response.statusText,
      type: response.type,
      redirected: response.redirected,
      url: response.url,
      headers: headersObj,
      bodyPreview: text.slice(0, 800),
      bodySize: text.length,
      durationMs: Math.round(performance.now() - start),
    };
    if (req.fullResponse) {
      // Cap at 5 MB to avoid blowing up the message bus
      out.body = text.length > 5 * 1024 * 1024 ? text.slice(0, 5 * 1024 * 1024) : text;
      out.bodyTruncated = text.length > 5 * 1024 * 1024;
    }
    return out;
  } catch (e) {
    return {
      ok: false,
      error: String((e && e.message) || e),
      durationMs: Math.round(performance.now() - start),
    };
  }
}
