/**
 * AuthForge — HAR file parser (shared/har.js)
 *
 * Parses an HTTP Archive (HAR) export and extracts a credentials profile:
 *   - Cookies (request + response, deduplicated, latest wins)
 *   - Authorization headers (Bearer tokens, etc.)
 *   - X-API-Key / X-Auth-Token style custom headers
 *   - The originating domain/url (so the profile knows where it came from)
 *
 * HAR is the canonical format every DevTools panel and many test/recording
 * tools export. Pulling credentials from a HAR is a routine DevOps step:
 * a teammate captures their broken session, you import it, you reproduce.
 *
 * Spec reference: https://w3c.github.io/web-performance/specs/HAR/Overview.html
 */

const AUTH_HEADER_PATTERNS = [
  /^authorization$/i,
  /^x-api-key$/i,
  /^x-auth-token$/i,
  /^x-access-token$/i,
  /^x-csrf-token$/i,
  /^x-xsrf-token$/i,
];

/**
 * Parse a HAR string (or already-parsed object) into a credentials profile.
 *
 * The returned object can be saved directly via profilesApi.save() after the
 * caller fills in `name` / `description`.
 *
 * @param {string | object} input  HAR JSON string or parsed object
 * @param {object} [opts]
 * @param {string} [opts.filterHost]  If set, only entries whose URL host
 *   matches (substring) are considered. Use this when a HAR contains traffic
 *   from many origins and you only want credentials for one of them.
 * @returns {{
 *   sourceUrl: string,
 *   sourceDomain: string,
 *   cookies: Array,
 *   localStorage: Array,
 *   sessionStorage: Array,
 *   authHeaders: Array,
 *   stats: { entries: number, hosts: string[] }
 * }}
 */
export function parseHar(input, opts = {}) {
  const har = typeof input === 'string' ? JSON.parse(input) : input;
  if (!har || !har.log || !Array.isArray(har.log.entries)) {
    throw new Error('Not a valid HAR file (missing log.entries).');
  }

  const filterHost = (opts.filterHost || '').toLowerCase();
  const cookieMap = new Map(); // key = name|domain|path → latest cookie object
  const authHeaderMap = new Map(); // key = name|host → header
  const hostsSeen = new Set();
  let consideredEntries = 0;
  let firstUrl = null;

  for (const entry of har.log.entries) {
    const url = entry.request?.url;
    if (!url) continue;
    let host;
    try {
      host = new URL(url).hostname;
    } catch {
      continue;
    }
    hostsSeen.add(host);
    if (filterHost && !host.toLowerCase().includes(filterHost)) continue;
    consideredEntries++;
    if (!firstUrl) firstUrl = url;

    // Request cookies — the browser is sending these, so they exist in the
    // browser's jar at request time.
    for (const c of entry.request.cookies || []) {
      addCookie(cookieMap, c, host, /* fromResponse */ false);
    }

    // Response cookies — Set-Cookie directives. These are what we'd be
    // installing if we replayed.
    for (const c of entry.response?.cookies || []) {
      addCookie(cookieMap, c, host, /* fromResponse */ true);
    }

    // Authorization-style headers from the request side
    for (const header of entry.request.headers || []) {
      if (!header.name || !header.value) continue;
      if (AUTH_HEADER_PATTERNS.some((re) => re.test(header.name))) {
        const key = header.name.toLowerCase() + '|' + host;
        authHeaderMap.set(key, {
          name: header.name,
          value: header.value,
          host,
        });
      }
    }
  }

  if (filterHost && consideredEntries === 0) {
    throw new Error(
      `No entries matched host filter "${filterHost}". Hosts in this HAR: ` +
        Array.from(hostsSeen).join(', ')
    );
  }

  const sourceUrl = firstUrl || har.log.entries[0]?.request?.url || '';
  const sourceDomain = sourceUrl ? safeHostname(sourceUrl) : '';

  return {
    sourceUrl,
    sourceDomain,
    cookies: Array.from(cookieMap.values()),
    localStorage: [], // HAR doesn't capture LS/SS — left empty for the caller
    sessionStorage: [],
    authHeaders: Array.from(authHeaderMap.values()),
    stats: {
      entries: consideredEntries,
      hosts: Array.from(hostsSeen).sort(),
    },
  };
}

function addCookie(map, harCookie, fallbackHost, fromResponse) {
  if (!harCookie.name) return;
  // HAR cookie shape: { name, value, path, domain, expires, httpOnly, secure }
  const domain = (harCookie.domain || fallbackHost || '').replace(/^\./, '');
  const path = harCookie.path || '/';
  const key = harCookie.name + '|' + domain + '|' + path;

  // Convert ISO expires → unix seconds for chrome.cookies compatibility
  let expirationDate;
  if (harCookie.expires) {
    const t = Date.parse(harCookie.expires);
    if (!Number.isNaN(t)) expirationDate = Math.floor(t / 1000);
  }

  const cookie = {
    name: harCookie.name,
    value: harCookie.value || '',
    domain: harCookie.domain || ('.' + fallbackHost),
    path,
    secure: !!harCookie.secure,
    httpOnly: !!harCookie.httpOnly,
    sameSite: normalizeSameSite(harCookie.sameSite),
    hostOnly: !harCookie.domain || !harCookie.domain.startsWith('.'),
    session: !expirationDate,
  };
  if (expirationDate) cookie.expirationDate = expirationDate;

  // Response cookies win over request cookies when both are present, since
  // a Set-Cookie observed during the capture is the more recent state.
  const existing = map.get(key);
  if (!existing || fromResponse) {
    map.set(key, cookie);
  }
}

function normalizeSameSite(raw) {
  if (!raw) return 'unspecified';
  const s = String(raw).toLowerCase();
  if (s === 'strict') return 'strict';
  if (s === 'lax') return 'lax';
  if (s === 'none' || s === 'no_restriction') return 'no_restriction';
  return 'unspecified';
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}
