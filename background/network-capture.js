/**
 * AuthForge — Network capture (background/network-capture.js)
 *
 * Passive observation of HTTP(S) traffic via chrome.webRequest. We hook the
 * three header phases (onBeforeSendHeaders, onHeadersReceived, onCompleted)
 * and surface anything that looks like an authentication artifact:
 *
 *   - Authorization request header (Bearer <jwt> | Basic ... | Digest ...)
 *   - Set-Cookie response headers, with JWT detection on the values
 *   - Custom auth-style headers (X-API-Key, X-Auth-Token, etc.)
 *   - Requests to known token-endpoint paths (/token, /oauth/token, /authorize)
 *
 * MV3 caveats: response bodies are NOT readable from webRequest in MV3. The
 * companion code in devtools/panel.js uses chrome.devtools.network for body
 * scans when DevTools is open. This module only sees headers.
 *
 * Listeners are registered synchronously at script load so they're re-installed
 * whenever the service worker wakes. State (ring buffer + recording flag)
 * lives in module scope and is mirrored to chrome.storage.session so it
 * survives worker termination during a session.
 */

import { looksLikeJWT, summarizeJWT } from '../shared/jwt.js';

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

const MAX_BUFFER = 500;
const MAX_PENDING = 200;
const PENDING_GC_MS = 60_000; // discard never-completed requests after a minute

// Request types that can plausibly carry tokens. Skip noisy static assets.
const CAPTURED_TYPES = new Set([
  'main_frame',
  'sub_frame',
  'xmlhttprequest',
  'websocket',
  'other', // covers some fetch() corner cases
]);

// Headers we treat as "auth-relevant" beyond the standard Authorization.
const CUSTOM_AUTH_HEADER_RES = [
  /^x-api-key$/i,
  /^x-auth-token$/i,
  /^x-access-token$/i,
  /^x-csrf-token$/i,
  /^x-xsrf-token$/i,
  /^x-amz-security-token$/i,
  /^x-id-token$/i,
  /^x-refresh-token$/i,
];

// URL paths that suggest a token-issuing endpoint. Requests to these are
// captured even if their headers look mundane (the body — which we can't see
// from webRequest — is where the action is).
const TOKEN_ENDPOINT_RES = [
  /\/oauth\/?2?\/token/i,
  /\/oauth2?\/v\d+\/token/i,
  /\/connect\/token/i,            // IdentityServer / OpenIddict
  /\/auth\/realms\/[^/]+\/protocol\/openid-connect\/token/i, // Keycloak
  /\/oauth2\/aus[^/]+\/v1\/token/i, // Okta
  /\/oauth2\/default\/v1\/token/i, // Okta default AS
  /login\.microsoftonline\.com\/[^/]+\/oauth2\//i,
  /login\.windows\.net\/[^/]+\/oauth2\//i,
  /\/\.auth0\.com\/oauth\/token/i,
  /\/v1\/login/i,
  /\/api\/auth\/(callback|signin|session|token)/i, // NextAuth
  /\/api\/v\d+\/auth\/login/i,
  /\/login\b/i,
  /\/logout\b/i,
  /\/refresh\b/i,
  /\/authorize\b/i,
];

// ----------------------------------------------------------------------------
// State
//
// Recording defaults to ON — AuthForge is meant to surface auth artifacts
// as they happen, and forcing the user to click Start every session defeats
// that. Captures are header-only (no bodies), heavily filtered to auth-
// relevant entries, and live in session storage (wiped at browser close).
// User can pause anytime from the Network tab.
// ----------------------------------------------------------------------------

let recording = true;
let buffer = [];                      // ring buffer of captured entries
const pending = new Map();            // requestId -> entry (in-flight)
let lastPersist = 0;

// Re-hydrate from session storage when the worker wakes. We honor an
// explicit "off" state — if the user paused, we stay paused; otherwise
// (no saved value, or saved value true) we record.
chrome.storage.session?.get?.(['network.recording', 'network.buffer'], (data) => {
  if (data && typeof data === 'object') {
    if (typeof data['network.recording'] === 'boolean') {
      recording = data['network.recording'];
    }
    if (Array.isArray(data['network.buffer'])) {
      buffer = data['network.buffer'].slice(-MAX_BUFFER);
    }
  }
});

function persistSoon() {
  // Debounced — at most every 500ms. We use storage.session because the
  // captures are sensitive (auth headers) and shouldn't outlive the browser.
  const now = Date.now();
  if (now - lastPersist < 500) return;
  lastPersist = now;
  chrome.storage.session?.set?.({
    'network.recording': recording,
    'network.buffer': buffer,
  }).catch(() => null);
}

// ----------------------------------------------------------------------------
// Listener registration (synchronous; survives SW restart)
// ----------------------------------------------------------------------------

function safeRegister() {
  if (!chrome.webRequest) {
    console.warn('[AuthForge] webRequest API unavailable — network capture disabled.');
    return false;
  }
  try {
    // Request-side headers (Authorization etc.)
    chrome.webRequest.onBeforeSendHeaders.addListener(
      handleBeforeSendHeaders,
      { urls: ['<all_urls>'] },
      ['requestHeaders', 'extraHeaders']
    );
    // Response-side headers (Set-Cookie etc.)
    chrome.webRequest.onHeadersReceived.addListener(
      handleHeadersReceived,
      { urls: ['<all_urls>'] },
      ['responseHeaders', 'extraHeaders']
    );
    chrome.webRequest.onCompleted.addListener(
      handleCompleted,
      { urls: ['<all_urls>'] }
    );
    chrome.webRequest.onErrorOccurred.addListener(
      handleError,
      { urls: ['<all_urls>'] }
    );
    return true;
  } catch (e) {
    console.warn('[AuthForge] failed to register webRequest listeners:', e);
    return false;
  }
}

const listenersOk = safeRegister();

// Periodic GC of stale pending entries
setInterval(() => {
  if (pending.size === 0) return;
  const cutoff = Date.now() - PENDING_GC_MS;
  for (const [id, entry] of pending) {
    if (entry.initiatedAt < cutoff) pending.delete(id);
  }
}, PENDING_GC_MS / 2);

// ----------------------------------------------------------------------------
// Listener handlers
// ----------------------------------------------------------------------------

function handleBeforeSendHeaders(details) {
  if (!recording) return;
  if (!CAPTURED_TYPES.has(details.type)) return;
  if (!details.url || !/^https?:/i.test(details.url)) return;

  const entry = {
    id: details.requestId + '-' + details.timeStamp,
    requestId: details.requestId,
    url: details.url,
    method: details.method,
    type: details.type,
    tabId: details.tabId,
    initiatedAt: details.timeStamp || Date.now(),
    status: 'open',
    statusCode: null,
    authHeader: null,
    customAuthHeaders: [],
    setCookies: [],
    tokenEndpoint: TOKEN_ENDPOINT_RES.some((re) => re.test(details.url)),
    jwtFindings: [],
    interesting: false,
  };

  for (const h of details.requestHeaders || []) {
    if (!h.name) continue;
    if (h.name.toLowerCase() === 'authorization') {
      entry.authHeader = { name: h.name, value: h.value || '' };
      extractJwtFromAuthorization(entry);
    } else if (CUSTOM_AUTH_HEADER_RES.some((re) => re.test(h.name))) {
      entry.customAuthHeaders.push({ name: h.name, value: h.value || '' });
    }
  }

  entry.interesting =
    !!entry.authHeader ||
    entry.customAuthHeaders.length > 0 ||
    entry.tokenEndpoint;

  pending.set(details.requestId, entry);
  if (entry.interesting) {
    pushToBuffer(entry);
  }
  // Cap pending to avoid leaks if a site fires many never-completing requests
  if (pending.size > MAX_PENDING) {
    const oldest = pending.keys().next().value;
    pending.delete(oldest);
  }
}

function handleHeadersReceived(details) {
  if (!recording) return;
  const entry = pending.get(details.requestId);
  if (!entry) return;
  entry.statusCode = details.statusCode;

  for (const h of details.responseHeaders || []) {
    if (!h.name) continue;
    if (h.name.toLowerCase() === 'set-cookie') {
      const parsed = parseSetCookie(h.value || '');
      if (parsed) {
        entry.setCookies.push(parsed);
        if (looksLikeJWT(parsed.value)) {
          entry.jwtFindings.push({
            where: 'Set-Cookie:' + parsed.name,
            name: parsed.name,
            summary: summarizeJWT(parsed.value),
            token: parsed.value,
            tokenPreview: previewToken(parsed.value),
          });
        }
      }
    }
  }
  if (entry.setCookies.length && !entry.interesting) {
    entry.interesting = true;
    pushToBuffer(entry);
  }
  // Update existing buffer position (entry object is the same reference)
  persistSoon();
}

function handleCompleted(details) {
  const entry = pending.get(details.requestId);
  if (entry) {
    entry.status = 'completed';
    entry.statusCode = details.statusCode;
    pending.delete(details.requestId);
    persistSoon();
  }
}

function handleError(details) {
  const entry = pending.get(details.requestId);
  if (entry) {
    entry.status = 'error';
    entry.errorText = details.error;
    pending.delete(details.requestId);
    persistSoon();
  }
}

// ----------------------------------------------------------------------------
// Buffer ops
// ----------------------------------------------------------------------------

function pushToBuffer(entry) {
  buffer.push(entry);
  if (buffer.length > MAX_BUFFER) buffer.splice(0, buffer.length - MAX_BUFFER);
  persistSoon();
}

function extractJwtFromAuthorization(entry) {
  if (!entry.authHeader) return;
  const v = entry.authHeader.value || '';
  const m = v.match(/^Bearer\s+(.+)$/i);
  if (!m) return;
  const token = m[1].trim();
  if (looksLikeJWT(token)) {
    entry.jwtFindings.push({
      where: 'Authorization: Bearer',
      name: 'authorization',
      summary: summarizeJWT(token),
      token,                          // keep the full token for copy/decode
      tokenPreview: previewToken(token),
    });
  }
}

function parseSetCookie(raw) {
  // Set-Cookie syntax: name=value; Attr1=...; Attr2; ...
  const semi = raw.indexOf(';');
  const head = semi === -1 ? raw : raw.slice(0, semi);
  const eq = head.indexOf('=');
  if (eq === -1) return null;
  const name = head.slice(0, eq).trim();
  const value = head.slice(eq + 1).trim();
  const attrs = semi === -1 ? '' : raw.slice(semi + 1).trim();
  return { name, value, attrs };
}

function previewToken(token) {
  if (!token) return '';
  if (token.length <= 80) return token;
  return token.slice(0, 40) + '…' + token.slice(-20);
}

// ----------------------------------------------------------------------------
// Public surface (called from the message router)
// ----------------------------------------------------------------------------

export const networkCapture = {
  available: () => listenersOk,
  isRecording: () => recording,
  start() {
    recording = true;
    persistSoon();
  },
  stop() {
    recording = false;
    persistSoon();
  },
  clear() {
    buffer = [];
    pending.clear();
    persistSoon();
  },
  list({ tabId, hostFilter, authOnly = true, limit = 200 } = {}) {
    let entries = buffer;
    if (typeof tabId === 'number') {
      entries = entries.filter((e) => e.tabId === tabId);
    }
    if (hostFilter) {
      const needle = hostFilter.toLowerCase();
      entries = entries.filter((e) => e.url.toLowerCase().includes(needle));
    }
    if (authOnly) {
      entries = entries.filter((e) => e.interesting);
    }
    if (limit) entries = entries.slice(-limit);
    // Return newest first
    return entries.slice().reverse();
  },
  /**
   * Used by the DevTools panel to add response-body findings — body content
   * isn't visible to webRequest in MV3, but the devtools network API can read
   * it. The DevTools panel posts findings back via the message router.
   */
  addBodyFinding(entry) {
    const e = {
      id: 'devtools-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8),
      requestId: entry.requestId || null,
      url: entry.url,
      method: entry.method || 'GET',
      type: 'xmlhttprequest',
      tabId: entry.tabId ?? -1,
      initiatedAt: entry.timeStamp || Date.now(),
      status: 'completed',
      statusCode: entry.statusCode || 200,
      authHeader: null,
      customAuthHeaders: [],
      setCookies: [],
      tokenEndpoint: true,
      jwtFindings: entry.jwtFindings || [],
      bodyFindings: entry.bodyFindings || [],
      interesting: true,
      source: 'devtools-body',
    };
    pushToBuffer(e);
    return e;
  },
};
