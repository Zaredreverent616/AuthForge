/**
 * AuthForge — Debugger-based deep capture (background/debugger-capture.js)
 *
 * Optional third layer of network capture. Uses chrome.debugger (Chrome
 * DevTools Protocol) to read response *bodies* without needing the DevTools
 * window to be open. Triggers the yellow "AuthForge started debugging
 * this browser" banner that the user can dismiss to detach.
 *
 * Two-layer relationship recap:
 *
 *   1. webRequest (network-capture.js)   — headers only, always available
 *   2. devtools.network (devtools/network-body-scanner.js) — bodies, but
 *      only while DevTools is open
 *   3. chrome.debugger (THIS module)     — bodies, no DevTools required,
 *      shows banner. Opt-in per tab.
 *
 * Bodies are scanned with the same shared/token-body-scanner module, then
 * routed into the same network-capture ring buffer so the UI doesn't have
 * to know which source produced a finding.
 *
 * Lifecycle:
 *   - User clicks "Deep capture" toggle in the Network tab → attach({tabId})
 *   - Chrome shows the banner. Network.enable starts streaming events.
 *   - We listen to Network.requestWillBeSent / responseReceived /
 *     loadingFinished and call Network.getResponseBody for matches.
 *   - User toggles off, closes the tab, navigates away from the tab,
 *     or clicks "Cancel" on the banner → detach + cleanup.
 *   - Service-worker restart will also implicitly detach.
 */

import { networkCapture } from './network-capture.js';
import {
  scanForTokens,
  looksLikeTokenEndpoint,
  looksLikeJsonContentType,
  MAX_SCAN_BYTES,
} from '../shared/token-body-scanner.js';

const CDP_VERSION = '1.3';

// Per-tab state. attached.get(tabId) = { requests: Map<requestId, {url, method, timestamp, statusCode, contentType}> }
const attached = new Map();

let detachListenerCallback = null; // set by service worker

// ----------------------------------------------------------------------------
// Public surface
// ----------------------------------------------------------------------------

export const debuggerCapture = {
  available: () => !!chrome.debugger,

  isAttached: (tabId) => attached.has(tabId),

  attachedTabs: () => Array.from(attached.keys()),

  /** Set a callback for detach events so the service worker can broadcast. */
  setDetachListener(fn) {
    detachListenerCallback = fn;
  },

  async attach(tabId) {
    if (!chrome.debugger) {
      throw new Error('chrome.debugger API unavailable in this build.');
    }
    if (typeof tabId !== 'number' || tabId < 0) {
      throw new Error('Invalid tabId for debugger attach.');
    }
    if (attached.has(tabId)) return { alreadyAttached: true };

    try {
      await chrome.debugger.attach({ tabId }, CDP_VERSION);
    } catch (e) {
      // Common cause: another tool (DevTools, another extension) already debugging
      throw new Error(
        'Could not attach debugger: ' +
          (e?.message || e) +
          '. Close any other debugger session on this tab and try again.'
      );
    }
    try {
      await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {});
    } catch (e) {
      // If enabling fails, detach and surface the error
      try { await chrome.debugger.detach({ tabId }); } catch {}
      throw new Error('Network.enable failed: ' + (e?.message || e));
    }
    attached.set(tabId, { requests: new Map() });
    return { alreadyAttached: false };
  },

  async detach(tabId) {
    if (!attached.has(tabId)) return { wasAttached: false };
    try {
      await chrome.debugger.detach({ tabId });
    } catch {
      // Already detached or tab gone — fall through to local cleanup
    }
    attached.delete(tabId);
    return { wasAttached: true };
  },

  async detachAll() {
    const tabs = Array.from(attached.keys());
    await Promise.all(tabs.map((tid) => this.detach(tid).catch(() => null)));
    return { detached: tabs.length };
  },
};

// ----------------------------------------------------------------------------
// CDP event handling
// ----------------------------------------------------------------------------

if (chrome.debugger?.onEvent) {
  chrome.debugger.onEvent.addListener((source, method, params) => {
    const tabId = source?.tabId;
    if (typeof tabId !== 'number') return;
    const state = attached.get(tabId);
    if (!state) return;

    try {
      switch (method) {
        case 'Network.requestWillBeSent':
          state.requests.set(params.requestId, {
            url: params.request?.url || '',
            method: params.request?.method || 'GET',
            timestamp: Date.now(),
          });
          break;
        case 'Network.responseReceived': {
          const r = state.requests.get(params.requestId);
          if (!r) return;
          r.statusCode = params.response?.status;
          // CDP gives headers as a flat object — find content-type case-insensitively
          const headers = params.response?.headers || {};
          r.contentType =
            headers['content-type'] ||
            headers['Content-Type'] ||
            headers['CONTENT-TYPE'] ||
            findHeaderCaseInsensitive(headers, 'content-type') ||
            '';
          break;
        }
        case 'Network.loadingFinished': {
          const r = state.requests.get(params.requestId);
          if (!r) return;
          // Decide whether to fetch the body
          const interesting =
            looksLikeTokenEndpoint(r.url) ||
            looksLikeJsonContentType(r.contentType || '');
          const tooLarge =
            (params.encodedDataLength || 0) > MAX_SCAN_BYTES;
          if (!interesting || tooLarge) {
            state.requests.delete(params.requestId);
            return;
          }
          // Fetch + scan asynchronously, don't block CDP event loop
          fetchAndScan(tabId, params.requestId, r).finally(() => {
            state.requests.delete(params.requestId);
          });
          break;
        }
        case 'Network.loadingFailed':
          state.requests.delete(params.requestId);
          break;
      }
    } catch (e) {
      console.warn('[AuthForge] debugger CDP handler error:', e);
    }
  });
}

async function fetchAndScan(tabId, requestId, requestInfo) {
  let result;
  try {
    result = await chrome.debugger.sendCommand(
      { tabId },
      'Network.getResponseBody',
      { requestId }
    );
  } catch (e) {
    // Body may have been discarded already, or the request had no body
    return;
  }
  if (!result || typeof result.body !== 'string') return;
  let text = result.body;
  if (result.base64Encoded) {
    try { text = atob(text); } catch { return; }
  }
  const findings = scanForTokens(text);
  if (!findings.length) return;

  networkCapture.addBodyFinding({
    url: requestInfo.url,
    method: requestInfo.method,
    timeStamp: requestInfo.timestamp,
    statusCode: requestInfo.statusCode,
    tabId,
    bodyFindings: findings,
    jwtFindings: findings
      .filter((f) => f.isJwt)
      .map((f) => ({
        where: 'response.body.' + f.field,
        name: f.field,
        summary: f.summary,
        token: f.value, tokenPreview: f.preview,
      })),
    source: 'debugger-deep-capture',
  });
}

function findHeaderCaseInsensitive(headers, want) {
  const lower = want.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lower) return headers[k];
  }
  return '';
}

// ----------------------------------------------------------------------------
// Detach handling — user clicks "Cancel" on banner, tab closes, etc.
// ----------------------------------------------------------------------------

if (chrome.debugger?.onDetach) {
  chrome.debugger.onDetach.addListener((source, reason) => {
    const tabId = source?.tabId;
    if (typeof tabId !== 'number') return;
    if (attached.has(tabId)) {
      attached.delete(tabId);
      if (detachListenerCallback) {
        try { detachListenerCallback(tabId, reason); } catch {}
      }
    }
  });
}

// When the tab itself is closed, clean up our local state (Chrome detaches
// automatically but doesn't always fire onDetach)
if (chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    if (attached.has(tabId)) {
      attached.delete(tabId);
      if (detachListenerCallback) {
        try { detachListenerCallback(tabId, 'tab_closed'); } catch {}
      }
    }
  });
}
