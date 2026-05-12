/**
 * AuthForge — Profile exporters (shared/profile-formats.js)
 *
 * Converts a Profile object into formats DevOps and QA tools consume:
 *
 *   - postman-env      Postman Environment JSON (variables for each cookie /
 *                      auth header — drop straight into Postman collections)
 *   - httpie-session   HTTPie session JSON (cookies + headers; replay with
 *                      `http --session=file ...`)
 *   - dotenv           .env file mapping each cookie / header to UPPER_SNAKE
 *                      variable names — good for CI/test runners
 *   - curl             A `curl` command with Cookie + Authorization headers
 *                      preset for one URL (delegates to shared/formats.js
 *                      where appropriate, but folds in auth headers too)
 *   - json             The full profile (round-trip-safe)
 */

export const PROFILE_FORMATS = [
  { id: 'json', label: 'AuthForge JSON', ext: 'json', mime: 'application/json' },
  { id: 'curl', label: 'cURL command', ext: 'sh', mime: 'text/x-shellscript' },
  { id: 'postman-env', label: 'Postman environment', ext: 'json', mime: 'application/json' },
  { id: 'httpie-session', label: 'HTTPie session', ext: 'json', mime: 'application/json' },
  { id: 'dotenv', label: '.env file', ext: 'env', mime: 'text/plain' },
];

/**
 * @param {object} profile
 * @param {string} formatId  one of PROFILE_FORMATS[].id
 * @param {object} [opts]
 * @param {string} [opts.targetUrl]  the URL to embed in formats that need one
 *   (curl, httpie). Defaults to profile.sourceUrl.
 * @returns {string}
 */
export function exportProfile(profile, formatId, opts = {}) {
  const targetUrl = opts.targetUrl || profile.sourceUrl || '';
  switch (formatId) {
    case 'json':
      return JSON.stringify(profile, null, 2);
    case 'curl':
      return toCurl(profile, targetUrl);
    case 'postman-env':
      return toPostmanEnv(profile);
    case 'httpie-session':
      return toHttpieSession(profile);
    case 'dotenv':
      return toDotenv(profile);
    default:
      throw new Error('Unknown profile export format: ' + formatId);
  }
}

// ----------------------------------------------------------------------------
// cURL — Cookie header + every auth header on a single GET line. The user
// can swap the method/URL trivially.
// ----------------------------------------------------------------------------

function toCurl(profile, targetUrl) {
  const lines = [];
  const url = targetUrl || profile.sourceUrl || 'https://example.com';
  lines.push('curl ' + shellQuote(url) + ' \\');
  // Cookie header
  const cookiePairs = (profile.cookies || [])
    .filter((c) => c.name)
    .map((c) => `${c.name}=${c.value ?? ''}`);
  if (cookiePairs.length) {
    lines.push(
      '  -H ' + shellQuote('Cookie: ' + cookiePairs.join('; ')) + ' \\'
    );
  }
  // Authorization & co.
  for (const h of profile.authHeaders || []) {
    if (!h.name || !h.value) continue;
    lines.push('  -H ' + shellQuote(`${h.name}: ${h.value}`) + ' \\');
  }
  // Trim trailing backslash
  if (lines.length) {
    lines[lines.length - 1] = lines[lines.length - 1].replace(/\s*\\$/, '');
  }
  return lines.join('\n');
}

// ----------------------------------------------------------------------------
// Postman environment — variables a user can reference as {{var_name}} in
// requests. We expose:
//   - cookie_<NAME>       for each cookie value
//   - header_<NAME>       for each auth header value (sanitized)
//   - base_url            for profile.sourceUrl
// ----------------------------------------------------------------------------

function toPostmanEnv(profile) {
  const env = {
    id: cryptoRandomId(),
    name: profile.name ? `AuthForge — ${profile.name}` : 'AuthForge profile',
    values: [],
    _postman_variable_scope: 'environment',
    _postman_exported_at: new Date().toISOString(),
    _postman_exported_using: 'AuthForge',
  };

  if (profile.sourceUrl) {
    env.values.push({
      key: 'base_url',
      value: profile.sourceUrl,
      type: 'default',
      enabled: true,
    });
  }

  for (const c of profile.cookies || []) {
    if (!c.name) continue;
    env.values.push({
      key: 'cookie_' + sanitizeVarName(c.name),
      value: c.value ?? '',
      type: looksSecret(c.name) ? 'secret' : 'default',
      enabled: true,
    });
  }

  for (const h of profile.authHeaders || []) {
    if (!h.name) continue;
    env.values.push({
      key: 'header_' + sanitizeVarName(h.name),
      value: h.value ?? '',
      type: 'secret',
      enabled: true,
    });
  }

  return JSON.stringify(env, null, 2);
}

// ----------------------------------------------------------------------------
// HTTPie session — JSON file you point `http --session=path.json` at. Carries
// cookies (with full attributes) and default headers.
// ----------------------------------------------------------------------------

function toHttpieSession(profile) {
  const session = {
    __meta__: {
      about: 'HTTPie session file',
      help: 'https://httpie.io/docs/cli/sessions',
      generated_by: 'AuthForge',
      profile_name: profile.name || null,
    },
    auth: { type: null, raw_auth: null },
    cookies: {},
    headers: {},
  };

  for (const c of profile.cookies || []) {
    if (!c.name) continue;
    session.cookies[c.name] = {
      value: c.value ?? '',
      ...(c.expirationDate ? { expires: Math.floor(c.expirationDate) } : {}),
      ...(c.path ? { path: c.path } : {}),
      ...(c.domain ? { domain: c.domain.replace(/^\./, '') } : {}),
      ...(c.secure ? { secure: true } : {}),
    };
  }

  for (const h of profile.authHeaders || []) {
    if (!h.name) continue;
    session.headers[h.name] = h.value ?? '';
  }

  return JSON.stringify(session, null, 2);
}

// ----------------------------------------------------------------------------
// .env file — UPPER_SNAKE_CASE variables. Easy to source in CI / test runners.
// Values are double-quoted with embedded quotes escaped.
// ----------------------------------------------------------------------------

function toDotenv(profile) {
  const lines = [];
  lines.push('# AuthForge profile: ' + (profile.name || '(unnamed)'));
  if (profile.sourceUrl) lines.push('# Source: ' + profile.sourceUrl);
  lines.push('# Generated: ' + new Date().toISOString());
  lines.push('');

  if (profile.sourceUrl) {
    lines.push('BASE_URL=' + dotenvQuote(profile.sourceUrl));
  }

  if ((profile.cookies || []).length) {
    lines.push('');
    lines.push('# --- Cookies ---');
    for (const c of profile.cookies) {
      if (!c.name) continue;
      const key = 'COOKIE_' + envSnake(c.name);
      lines.push(key + '=' + dotenvQuote(c.value ?? ''));
    }
    // Composite header — drop straight into curl -H "Cookie: $COOKIE_HEADER"
    const composite = profile.cookies
      .filter((c) => c.name)
      .map((c) => `${c.name}=${c.value ?? ''}`)
      .join('; ');
    if (composite) {
      lines.push('COOKIE_HEADER=' + dotenvQuote(composite));
    }
  }

  if ((profile.authHeaders || []).length) {
    lines.push('');
    lines.push('# --- Auth headers ---');
    for (const h of profile.authHeaders) {
      if (!h.name) continue;
      const key = envSnake(h.name);
      lines.push(key + '=' + dotenvQuote(h.value ?? ''));
    }
  }

  return lines.join('\n') + '\n';
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function shellQuote(s) {
  // Single-quote everything, escape embedded single quotes the POSIX way.
  return "'" + String(s).replace(/'/g, `'\\''`) + "'";
}

function dotenvQuote(s) {
  // Wrap in double quotes, escape \ and " and embedded newlines.
  const escaped = String(s)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
  return '"' + escaped + '"';
}

function envSnake(name) {
  return String(name)
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}

function sanitizeVarName(name) {
  return String(name).replace(/[^A-Za-z0-9_]/g, '_');
}

function looksSecret(name) {
  return /token|secret|key|session|auth|jwt|password|refresh/i.test(name);
}

function cryptoRandomId() {
  // RFC4122-ish — good enough for an export identifier
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
