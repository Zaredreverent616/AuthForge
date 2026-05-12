/**
 * AuthForge — Token body scanner (shared/token-body-scanner.js)
 *
 * Pure JavaScript — no chrome.* APIs — that recognises plaintext credential
 * values in HTTP response bodies. Used by both:
 *
 *   - devtools/network-body-scanner.js  (runs when DevTools is open)
 *   - background/debugger-capture.js    (runs via chrome.debugger / CDP)
 *
 * Recognises the OAuth2 RFC 6749 field names (snake_case) plus the camelCase
 * variants emitted by Microsoft Identity Platform, Auth0, and SPA SDKs.
 * Walks nested objects so non-standard auth APIs (`data.auth.accessToken`)
 * are still caught.
 */

import { looksLikeJWT, summarizeJWT } from './jwt.js';

export const TOKEN_FIELD_NAMES = [
  'access_token',
  'refresh_token',
  'id_token',
  'idToken',
  'accessToken',
  'refreshToken',
  'token',
  'bearer',
  'jwt',
  'auth_token',
  'authToken',
  'sessionToken',
  'session_token',
];

export const TOKEN_ENDPOINT_RES = [
  /\/oauth\/?2?\/token/i,
  /\/connect\/token/i,
  /\/oauth2?\/v\d+\/token/i,
  /\/v\d+\/token/i,
  /\/auth\/realms\/[^/]+\/protocol\/openid-connect\/token/i,
  /login\.microsoftonline\.com\/[^/]+\/oauth2\//i,
  /login\.windows\.net\/[^/]+\/oauth2\//i,
  /\.auth0\.com\/oauth\/token/i,
  /\/api\/auth\/(callback|signin|session|token|refresh)/i,
  /\/refresh\b/i,
  /\/authorize\b/i,
  /\/sso\/login/i,
  /\/login\b/i,
];

export const MAX_SCAN_BYTES = 500_000; // skip absurdly large bodies

export function looksLikeTokenEndpoint(url) {
  if (!url) return false;
  return TOKEN_ENDPOINT_RES.some((re) => re.test(url));
}

export function looksLikeJsonContentType(contentType) {
  if (!contentType) return false;
  return /^application\/(json|jose|jwt|x-www-form-urlencoded)/i.test(contentType);
}

/**
 * Scan an arbitrary response body string for token-shaped values. Returns
 * `[{ field, value, preview, isJwt, summary? }]`, possibly empty.
 *
 * Order of attempts:
 *   1. JSON.parse → walk the object tree
 *   2. URL-encoded form (key=value&key=value) → parse and check known field names
 *   3. Regex fallback over plain text
 */
export function scanForTokens(text) {
  if (typeof text !== 'string' || !text) return [];
  if (text.length > MAX_SCAN_BYTES) return [];

  // 1) JSON
  try {
    const obj = JSON.parse(text);
    const out = [];
    walkJson(obj, '', out);
    if (out.length) return out;
  } catch {
    /* not JSON, fall through */
  }

  // 2) URL-encoded form
  if (text.includes('=') && !text.startsWith('{') && !text.startsWith('[')) {
    const out = [];
    try {
      const params = new URLSearchParams(text);
      for (const [k, v] of params) {
        if (isTokenFieldName(k) && v && v.length >= 8) {
          const f = makeFinding(k, v);
          out.push(f);
        }
      }
    } catch {
      /* not parseable */
    }
    if (out.length) return out;
  }

  // 3) Regex fallback over raw text
  return regexScan(text);
}

function walkJson(node, path, out) {
  if (node == null) return;
  if (typeof node === 'object' && !Array.isArray(node)) {
    for (const [k, v] of Object.entries(node)) {
      const childPath = path ? path + '.' + k : k;
      if (typeof v === 'string' && isTokenFieldName(k) && v.length >= 8) {
        out.push(makeFinding(childPath, v));
      } else if (typeof v === 'object') {
        walkJson(v, childPath, out);
      }
    }
  } else if (Array.isArray(node)) {
    node.forEach((v, i) => walkJson(v, path + '[' + i + ']', out));
  }
}

function regexScan(text) {
  const out = [];
  for (const field of TOKEN_FIELD_NAMES) {
    const re = new RegExp(
      '["\']' + escapeRe(field) + '["\']\\s*[:=]\\s*["\']([^"\']{8,})["\']',
      'gi'
    );
    let m;
    while ((m = re.exec(text)) !== null) {
      out.push(makeFinding(field, m[1]));
    }
  }
  return out;
}

function makeFinding(field, value) {
  const finding = {
    field,
    value,
    preview: value.length > 200 ? value.slice(0, 200) + '…' : value,
    isJwt: looksLikeJWT(value),
  };
  if (finding.isJwt) {
    try { finding.summary = summarizeJWT(value); } catch { /* leave undefined */ }
  }
  return finding;
}

function isTokenFieldName(name) {
  if (!name || typeof name !== 'string') return false;
  const lower = name.toLowerCase();
  return TOKEN_FIELD_NAMES.some((t) => t.toLowerCase() === lower);
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
