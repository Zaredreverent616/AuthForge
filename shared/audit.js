/**
 * AuthForge — Security audit (shared/audit.js)
 *
 * Static analysis of cookies and storage values. Surfaces the kinds of issues
 * a pentester or security-conscious developer wants to spot at a glance:
 *
 *   - Missing Secure / HttpOnly / SameSite on session-class cookies
 *   - SameSite=None without Secure (browser-rejected anyway, but worth flagging)
 *   - Overly broad Domain scope (parent-domain cookies that needn't be)
 *   - Long-lived auth cookies
 *   - JWTs sitting in cookie values without HttpOnly (XSS-readable bearer tokens)
 *   - Expired tokens still being sent
 *   - Refresh tokens visible to page script
 *   - Likely-sensitive values stored in localStorage / sessionStorage
 *
 * No heuristic is perfect — the audit aims for high-signal findings. Each
 * finding includes a severity and a recommendation. The caller renders.
 */

import { looksLikeJWT, summarizeJWT, looksLikeRefreshTokenKey } from './jwt.js';

/**
 * Classify a cookie by role. The previous flat "session-pattern" regex list
 * lumped auth tokens, CSRF tokens, and analytics under the same umbrella and
 * generated identical findings for all of them — producing high-severity
 * false positives like "csrftoken is JS-readable" (which is the whole POINT
 * of a CSRF token in the double-submit-cookie pattern).
 *
 * Roles:
 *   'auth'        — carries authentication / authorization state
 *   'csrf'        — anti-CSRF token; deliberately JS-readable in many frameworks
 *   'analytics'   — tracking / telemetry / WAF challenge; not security-relevant
 *   'functional'  — UI state, preferences; not security-relevant
 *   'unknown'     — name doesn't tell us anything; classify by value only
 *
 * Returns an object so we can carry confidence and a short rationale.
 */
function classifyCookieRole(name, value) {
  const lower = (name || '').toLowerCase();

  // ---- Definitely CSRF (highest precedence — naming is unambiguous) -----
  // CSRF tokens MUST be readable from JS to support the double-submit cookie
  // pattern. Flagging them for missing HttpOnly is wrong.
  if (/^(csrf|xsrf|x[-_]?csrf|x[-_]?xsrf)([-_]token)?$/i.test(name) ||
      /^csrf[-_]?token$/i.test(name) ||
      /^xsrf[-_]?token$/i.test(name) ||
      /^__requestverificationtoken/i.test(name) ||  // .NET MVC anti-forgery
      /^anti[-_]?forgery[-_]?token$/i.test(name) ||
      /(^|[_-])csrf[_-]/i.test(name) ||  // foo_csrf_token, splunkweb_csrf_token_8443
      /(^|[_-])xsrf[_-]/i.test(name) ||
      /^validation[-_]?token$/i.test(name)) {
    return { role: 'csrf', confidence: 'high' };
  }

  // ---- Definitely analytics / tracking / WAF -----------------------------
  // These have "session" in the name but aren't carrying auth.
  if (
    /^_ga(_|$)/i.test(name) || lower === '_ga' || lower === '_gid' ||
    /^_gcl[_-]/i.test(name) ||
    /^_fbp$/i.test(name) || /^_fbc$/i.test(name) ||
    /^_hj[a-z]/i.test(name) ||      // Hotjar
    /^ajs_/i.test(name) ||           // Segment.io
    /^mp_/i.test(name) ||            // Mixpanel
    /^amplitude/i.test(name) || /^amp_/i.test(name) ||
    /^intercom-/i.test(name) ||      // Intercom widget
    /^drift_/i.test(name) ||
    /^optimizely/i.test(name) || lower.includes('optimizely') ||
    lower === 'activitysessionid' ||  // GA-like activity tracking
    /(^|[-_])utm[-_]/i.test(name) ||
    /^aws-waf-token$/i.test(name) || // AWS WAF bot challenge
    /^awsalb/i.test(name) ||         // ALB sticky session (load balancer, not auth)
    /^visitor[-_]?id$/i.test(name) ||
    /enwikimwuser-sessionId/i.test(name) || // Wikipedia anon tracking
    /^bcookie$/i.test(name) ||       // LinkedIn cookie
    /^lidc$/i.test(name) ||          // LinkedIn tracking
    /^muid$/i.test(name) ||          // Microsoft tracking (NOT auth — distinct from MSPAuth etc.)
    /^anon$/i.test(name)             // Microsoft anonymous tracking
  ) {
    return { role: 'analytics', confidence: 'high' };
  }

  // ---- Definitely functional (UI state) ----------------------------------
  if (
    /^(theme|color[-_]?mode|locale|lang|timezone|tz)$/i.test(name) ||
    /^(consent|cookies?[-_]?accept|gdpr|ccpa)/i.test(name) ||
    /^(pref|prefs|preference)/i.test(name)
  ) {
    return { role: 'functional', confidence: 'high' };
  }

  // ---- Likely auth — only after CSRF / analytics filtering --------------
  // We loosened these from word-boundary matches to substring matches so
  // cookies like "dekisession", "mtwebsession", "flight-msaoauth2",
  // "pps_token", "authng_user" still classify as auth. CSRF/analytics ran
  // first above so we won't mis-tag a CSRF token.
  if (
    // Microsoft Entra / Account family
    /^(ESTSAUTH|ESTSAUTHPERSISTENT|ESTSAUTHLIGHT|ESTS|ESCTX|BUID|FPC|FedAuth|RTFA)/i.test(name) ||
    /^(MSPAuth|MSPProf|MSPRequ|MSPCID|RPSAuth|RPSSecAuth|WLSSC)$/i.test(name) ||
    /^x-ms-(refreshtokencredential|prt|deviceauthkey)/i.test(name) ||
    // Common session names (still anchored — they need to be exact matches)
    /^(JSESSIONID|PHPSESSID|ASP\.NET_SessionId)$/i.test(name) ||
    /^connect\.sid$/i.test(name) ||
    /^laravel_session$/i.test(name) ||
    /^_rails_session$/i.test(name) ||
    /^sid$/i.test(name) || /^SID$/.test(name) ||
    // Anywhere-substring keywords (CSRF/XSRF already excluded above)
    /session/i.test(name) ||
    /auth/i.test(name) ||
    /login/i.test(name) ||
    /credential/i.test(name) ||
    /bearer/i.test(name) ||
    /(^|[^a-z])jwt([^a-z]|$)/i.test(name) ||
    /oauth/i.test(name) ||
    /token/i.test(name) ||                  // catches pps_token, application_token, etc.
    /^remember[_-]?me?$/i.test(name)
  ) {
    return { role: 'auth', confidence: 'high' };
  }

  // ---- Value-based fallback ----------------------------------------------
  // If the value LOOKS like a JWT, it's almost certainly auth regardless of
  // name. This catches `_C_Auth`-style cookies whose names don't match the
  // patterns above.
  if (value && looksLikeJWT(value)) {
    return { role: 'auth', confidence: 'medium', reason: 'value is a JWT' };
  }
  if (looksLikeRefreshTokenKey(name)) {
    return { role: 'auth', confidence: 'medium', reason: 'name matches refresh-token pattern' };
  }

  return { role: 'unknown', confidence: 'low' };
}

const LIKELY_SECRET_KEY_PATTERNS = [
  /api[_-]?key/i,
  /secret/i,
  /password/i,
  /token/i,
  /credential/i,
  /private[_-]?key/i,
];

/**
 * Audit an array of cookies (chrome.cookies shape).
 *
 * Returns a list of findings, each shaped:
 *   { severity, category, target, targetKind, issue, detail, recommendation,
 *     cookieClass, context? }
 *
 * Severity scale:
 *   critical  exploitable now without further work
 *   high      enables exploitation given a small additional condition
 *   medium    fragile defence / weak best-practice violation
 *   low       hygiene / blast-radius
 *   info      observation only
 *
 * @param {Array} cookies
 * @param {object} [opts]
 * @param {string} [opts.pageUrl]  the URL the cookies were captured for
 */
export function auditCookies(cookies, opts = {}) {
  const findings = [];
  const pageHost = opts.pageUrl ? safeHost(opts.pageUrl) : '';
  const pageIsHttps = opts.pageUrl ? /^https:/i.test(opts.pageUrl) : true;
  const now = Math.floor(Date.now() / 1000);

  for (const c of cookies || []) {
    if (!c?.name) continue;
    const classification = classifyCookieRole(c.name, c.value);
    const role = classification.role;

    // Analytics and functional cookies aren't part of the security boundary
    // — skip cookie hygiene checks entirely. (We still scan their values for
    // JWTs etc. just in case, below.)
    if (role !== 'analytics' && role !== 'functional') {
      addRoleSpecificFindings(findings, c, classification, {
        pageHost,
        pageIsHttps,
        now,
      });
    }

    // Value-based checks apply to ALL cookies regardless of role — a JWT in
    // a "preference" cookie is just as worth knowing about.
    addValueBasedFindings(findings, c, classification);
  }

  return findings;
}

/**
 * Per-role attribute checks. Different roles have different expectations:
 *   - auth: must have Secure, HttpOnly, sane SameSite; lifetime matters
 *   - csrf: must have Secure (on HTTPS), MUST have SameSite=Lax|Strict (None
 *           defeats the protection); HttpOnly is NOT required and is often
 *           wrong (double-submit needs JS access)
 *   - unknown: only the most generic checks
 */
function addRoleSpecificFindings(findings, c, classification, ctx) {
  const role = classification.role;
  const isCsrf = role === 'csrf';
  const isAuth = role === 'auth';

  // ---- Secure flag (HTTPS-only) -----------------------------------------
  // Only matters if the site also has HTTP endpoints, OR if SameSite=None
  // (browsers reject SameSite=None without Secure). On an HTTPS-only origin
  // it's still a best-practice violation but not actively exploitable.
  if (!c.secure) {
    if (isAuth) {
      findings.push(finding({
        target: c.name,
        targetKind: 'cookie',

        origin: c.domain,
        cookieClass: 'auth',
        issue: ctx.pageIsHttps
          ? 'Auth cookie missing Secure flag (HTTPS-only site)'
          : 'Auth cookie sent over HTTP',
        detail: ctx.pageIsHttps
          ? `"${c.name}" is an auth cookie without the Secure attribute. ` +
            'On a strictly HTTPS site this is best-practice only — but if any ' +
            'subdomain ever serves HTTP, an active-network attacker can steal it.'
          : `"${c.name}" is an auth cookie and the Secure flag is unset, so ` +
            'it will be transmitted in cleartext over HTTP. Active-network ' +
            'attackers can steal it.',
        recommendation: 'Set the Secure attribute. Serve auth-bearing endpoints over HTTPS only.',
        severity: ctx.pageIsHttps ? 'medium' : 'high',
        category: 'attribute',
      }));
    } else if (isCsrf) {
      findings.push(finding({
        target: c.name,
        targetKind: 'cookie',

        origin: c.domain,
        cookieClass: 'csrf',
        issue: 'CSRF token missing Secure flag',
        detail: `"${c.name}" is a CSRF token without Secure. An attacker on ` +
          'a coffee-shop network can read it during an HTTP request and then ' +
          'craft cross-site requests that bypass the double-submit-cookie check.',
        recommendation: 'Set Secure. Serve all token-bearing pages over HTTPS only.',
        severity: 'medium',
        category: 'attribute',
      }));
    }
  }

  // ---- HttpOnly flag ----------------------------------------------------
  // CSRF tokens are EXPECTED to be readable from JS in the double-submit
  // pattern. Don't flag this for CSRF. Only flag for auth cookies.
  if (!c.httpOnly && isAuth) {
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: 'auth',
      issue: 'Auth cookie readable from JavaScript',
      detail: `"${c.name}" is an auth cookie without HttpOnly, so any XSS ` +
        'payload (or third-party script) can read and exfiltrate it. Combined ' +
        'with any reflected/stored XSS this is a session-takeover.',
      recommendation: 'Set HttpOnly unless the application has a concrete need to read the cookie from page script.',
      severity: 'high',
      category: 'attribute',
    }));
  }

  // ---- SameSite ---------------------------------------------------------
  const sameSite = (c.sameSite || '').toLowerCase();
  const sameSiteNone = sameSite === 'no_restriction' || sameSite === 'none';
  const sameSiteLaxOrStrict = sameSite === 'lax' || sameSite === 'strict';

  if (!c.secure && sameSiteNone) {
    // Cross-cutting: SameSite=None without Secure is rejected by every
    // modern browser. Still worth flagging because it means the cookie
    // is silently being dropped — auth WILL break in cross-site contexts.
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: role,
      issue: 'SameSite=None without Secure',
      detail: 'Browsers reject this combination — the cookie is silently ' +
        'discarded in cross-site contexts and auth will partially fail.',
      recommendation: 'Either add Secure (and ensure HTTPS-only delivery) or change SameSite to Lax/Strict.',
      severity: 'high',
      category: 'attribute',
    }));
  }

  if (isCsrf && sameSiteNone) {
    // For CSRF tokens, SameSite=None means cross-site requests include the
    // token, which defeats double-submit-cookie protection entirely.
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: 'csrf',
      issue: 'CSRF token has SameSite=None — protection defeated',
      detail: `"${c.name}" is sent on every cross-site request, which means ` +
        'an attacker page can trigger an authenticated cross-origin POST and ' +
        'the browser will forward the token automatically. The double-submit ' +
        'CSRF defence relies on the token NOT being sent cross-site.',
      recommendation: 'Set SameSite=Lax or Strict. CSRF tokens must not flow across origins.',
      severity: 'high',
      category: 'attribute',
    }));
  }

  if (isAuth && !sameSite && !c.session) {
    // For auth cookies, missing SameSite is medium — relies on browser
    // defaults which vary. Less concerning than for CSRF tokens.
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: 'auth',
      issue: 'Auth cookie has no explicit SameSite',
      detail: `"${c.name}" inherits the browser default for SameSite. ` +
        'Default behaviour differs across browsers and versions; relying on it ' +
        'for CSRF protection is fragile.',
      recommendation: 'Set SameSite=Lax explicitly (or Strict if no cross-origin top-level navigation is expected).',
      severity: 'low',
      category: 'attribute',
    }));
  }

  if (isAuth && sameSiteNone) {
    // Auth cookie with SameSite=None is fine for some legitimate cross-org
    // SSO flows but worth a low-severity reminder.
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: 'auth',
      issue: 'Auth cookie has SameSite=None',
      detail: `"${c.name}" is sent on every cross-site request. CSRF defence ` +
        'relies entirely on additional measures (anti-CSRF tokens, custom headers, Origin checks).',
      recommendation: 'Audit the application\'s CSRF defence in depth. If cross-site flow isn\'t required, switch to SameSite=Lax.',
      severity: 'low',
      category: 'attribute',
    }));
  }

  // ---- Domain scope -----------------------------------------------------
  // Auth cookies scoped to a parent domain spread the attack surface to
  // every subdomain (any compromised sub.example.com can read example.com's
  // auth cookies). Worth flagging at medium.
  if (isAuth && c.domain && ctx.pageHost) {
    const cookieDomain = (c.domain || '').replace(/^\./, '').toLowerCase();
    const pageHost = ctx.pageHost.toLowerCase();
    if (cookieDomain && cookieDomain !== pageHost && pageHost.endsWith('.' + cookieDomain)) {
      findings.push(finding({
        target: c.name,
        targetKind: 'cookie',

        origin: c.domain,
        cookieClass: 'auth',
        issue: 'Auth cookie scoped to a parent domain',
        detail: `"${c.name}" is scoped to .${cookieDomain} but the page is ` +
          `on ${pageHost}. Every subdomain of ${cookieDomain} can read this ` +
          'cookie — a single XSS or subdomain takeover on a less-protected ' +
          'host (e.g. a marketing site) becomes session theft.',
        recommendation: `Scope the cookie to ${pageHost} (no leading dot) unless cross-subdomain delivery is required.`,
        severity: 'medium',
        category: 'scope',
      }));
    }
  }

  // ---- Lifetime ---------------------------------------------------------
  // Browsers now cap cookie lifetimes at ~400 days regardless. Worth
  // flagging at low when the declared expiry exceeds 1 year, since it
  // signals an intent that's no longer enforceable and a long blast radius
  // if the cookie ever leaks.
  if (isAuth && c.expirationDate && (c.expirationDate - ctx.now) > 365 * 24 * 3600) {
    const days = Math.round((c.expirationDate - ctx.now) / 86400);
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: 'auth',
      issue: `Auth cookie lifetime: ${days} days`,
      detail: `"${c.name}" is valid for over a year (Chrome will cap at ~400 ` +
        'days). Long-lived auth credentials expand the blast radius of any ' +
        'future leak — refresh-token rotation is usually safer.',
      recommendation: 'Consider shorter cookie lifetimes paired with a refresh-token rotation flow.',
      severity: 'low',
      category: 'expiry',
    }));
  }
}

/**
 * Value-based findings — apply regardless of role. The really pentester-
 * interesting things live here: JWTs in cookie values, refresh tokens
 * accessible to JS, expired tokens still being sent.
 */
function addValueBasedFindings(findings, c, classification) {
  if (!c.value) return;
  const isJwt = looksLikeJWT(c.value);

  // JWT in cookie value, NOT HttpOnly — readable bearer credential.
  if (isJwt && !c.httpOnly) {
    const summary = summarizeJWT(c.value);
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: classification.role,
      issue: 'JWT in cookie value is readable from JavaScript',
      detail: `"${c.name}" carries a JWT (alg=${summary?.alg || '?'}, ` +
        `aud=${truncate(String(summary?.aud || '—'), 60)}) and is not HttpOnly. ` +
        'Any XSS payload extracts this as a usable bearer credential — game over ' +
        'for the user\'s session against whatever this token addresses.',
      recommendation: 'Move JWTs to HttpOnly cookies or short-lived in-memory storage. Don\'t expose long-lived bearer credentials to page script.',
      severity: 'high',
      category: 'value',
      context: summary,
    }));
  }

  // Expired JWT still being sent. Either the server isn't enforcing exp
  // (vulnerability) or the cookie is dead weight (info disclosure of stale
  // user/tenant data).
  if (isJwt) {
    const summary = summarizeJWT(c.value);
    if (summary?.exp && summary.exp * 1000 < Date.now()) {
      findings.push(finding({
        target: c.name,
        targetKind: 'cookie',

        origin: c.domain,
        cookieClass: classification.role,
        issue: 'Expired JWT still set as cookie',
        detail: `"${c.name}" contains a JWT that expired ${
          formatRelativeTime(summary.exp * 1000)
        }. If the server still accepts it, that's weak expiry enforcement; ` +
          'if not, this is stale cleanup that still leaks the original claims (user, tenant, scopes).',
        recommendation: 'Verify server-side exp enforcement, and clear stale cookies on logout / refresh.',
        severity: 'medium',
        category: 'value',
        context: summary,
      }));
    }
  }

  // Refresh-token-shaped cookie readable from JS — different class of risk
  // from a session cookie since refresh tokens unlock new access tokens.
  if (looksLikeRefreshTokenKey(c.name) && !c.httpOnly) {
    findings.push(finding({
      target: c.name,
      targetKind: 'cookie',

      origin: c.domain,
      cookieClass: classification.role,
      issue: 'Refresh-token-shaped cookie readable from JS',
      detail: `"${c.name}" looks like a refresh token, and is JS-readable. ` +
        'XSS extraction here doesn\'t just steal one session — it lets the ' +
        'attacker mint new access tokens until the refresh chain is revoked.',
      recommendation: 'Move refresh tokens to HttpOnly cookies, and rotate on every use (refresh-token rotation).',
      severity: 'high',
      category: 'value',
    }));
  }
}

function formatRelativeTime(ts) {
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return Math.round(diff / 60_000) + ' minutes ago';
  if (diff < 86_400_000) return Math.round(diff / 3_600_000) + ' hours ago';
  return Math.round(diff / 86_400_000) + ' days ago';
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/**
 * Audit localStorage / sessionStorage entries (array of {key, value}).
 *
 * Even more heuristic than the cookie audit: any flag here is a hint, not a
 * verdict. The big one is "JWT/refresh-token sitting in localStorage" —
 * widely considered an XSS-friendly anti-pattern.
 */
export function auditStorage(entries, opts = {}) {
  const storeName = opts.storeName || 'storage';
  // Origin: where these LS/SS entries were captured from. Caller (the
  // popup) passes the page URL or hostname so findings carry source.
  const originHost = opts.pageUrl ? safeHost(opts.pageUrl) : (opts.origin || '');
  const findings = [];

  for (const e of entries || []) {
    if (!e?.key) continue;
    // Per-entry origin: in cross-tab aggregated audits the entry itself
    // can carry .origin (its source tab's host). Otherwise fall back to
    // the call-level origin.
    const entryOrigin = e.origin || originHost;
    if (looksLikeJWT(e.value)) {
      const summary = summarizeJWT(e.value);
      findings.push(finding({
        severity: storeName === 'localStorage' ? 'medium' : 'low',
        category: 'token',
        target: e.key,
        targetKind: storeName,
        origin: entryOrigin,
        issue: `JWT in ${storeName}`,
        detail:
          `"${e.key}" contains a JWT. Storing bearer tokens in ${storeName} ` +
          'means any XSS or third-party script can read them. HttpOnly cookies ' +
          'are the standard hardened alternative.',
        recommendation:
          'Move bearer tokens out of web storage; use HttpOnly+Secure cookies ' +
          'and let the browser attach them automatically.',
      }));
      if (summary.alg === 'none') {
        findings.push(finding({
          severity: 'high',
          category: 'token',
          target: e.key,
          targetKind: storeName,
          origin: entryOrigin,
          issue: `JWT with alg=none in ${storeName}`,
          detail:
            `"${e.key}" contains an unsigned JWT (alg=none). If the server ` +
            'accepts it, forging tokens is trivial.',
          recommendation:
            'Verify the server rejects alg=none tokens via a tampered-claim test.',
        }));
      }
    } else if (looksLikeRefreshTokenKey(e.key)) {
      findings.push(finding({
        severity: storeName === 'localStorage' ? 'high' : 'medium',
        category: 'token',
        target: e.key,
        targetKind: storeName,
        origin: entryOrigin,
        issue: `Refresh-token-shaped key in ${storeName}`,
        detail:
          `"${e.key}" matches refresh-token naming heuristics and lives in ` +
          `${storeName}, which is fully accessible to page script.`,
        recommendation:
          'Refresh tokens should be HttpOnly cookies if at all possible.',
      }));
    } else if (LIKELY_SECRET_KEY_PATTERNS.some((re) => re.test(e.key))) {
      findings.push(finding({
        severity: 'low',
        category: 'token',
        target: e.key,
        targetKind: storeName,
        origin: entryOrigin,
        issue: `Likely-sensitive value in ${storeName}`,
        detail:
          `Key name "${e.key}" suggests this entry holds a credential. ` +
          `${storeName} is accessible to all script on the origin.`,
        recommendation:
          'Confirm whether this value is sensitive; if so, move it to a more ' +
          'protected channel.',
      }));
    }
  }

  return findings.sort(bySeverity);
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function bySeverity(a, b) {
  const sa = SEVERITY_ORDER[a.severity] ?? 99;
  const sb = SEVERITY_ORDER[b.severity] ?? 99;
  if (sa !== sb) return sa - sb;
  return (a.target || '').localeCompare(b.target || '');
}

function finding(f) {
  const out = {
    severity: f.severity,
    category: f.category,
    target: f.target,
    targetKind: f.targetKind,
    issue: f.issue,
    detail: f.detail,
    recommendation: f.recommendation,
  };
  if (f.cookieClass) out.cookieClass = f.cookieClass;
  if (f.context) out.context = f.context;
  // Origin tells the UI / export consumer where this finding came from.
  // For cookies: the cookie's domain (with leading-dot preserved). For
  // network entries: the request URL's host. For LS/SS/IDB: the page URL's
  // host. Without this the audit table can't tell you which site to blame.
  if (f.origin) out.origin = f.origin;
  return out;
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function countLabels(host) {
  return host ? host.split('.').filter(Boolean).length : 0;
}

// ===========================================================================
// Network-capture audit
//
// Once we have captured requests, there's a whole second tier of findings:
// JWTs flying past in plaintext over HTTP, tokens being sent to third-party
// hosts, refresh tokens hardcoded into URLs. These complement the static
// cookie/storage checks.
// ===========================================================================

/**
 * Audit a list of captured network entries (shape from network-capture.js).
 * Pair findings with the entry's id so the UI can deep-link.
 */
export function auditNetwork(entries = []) {
  const findings = [];
  const seenAuthHosts = new Set();
  const seenJwtsByHost = new Map(); // host → Set<token-prefix>

  for (const entry of entries) {
    const host = safeHost(entry.url);
    const isHttps = entry.url?.startsWith('https://');

    // ---- Plain HTTP carrying auth ----
    if (entry.authHeader && !isHttps) {
      findings.push({
        id: 'net-auth-over-http:' + entry.id,
        severity: 'critical',
        title: 'Bearer token sent over plaintext HTTP',
        description:
          `Request to ${entry.url} carried an Authorization header without TLS. ` +
          'Anyone on the network path captured this token in clear text.',
        recommendation:
          'Enforce HTTPS for every endpoint that accepts bearer tokens. Add HSTS. ' +
          'Treat the captured token as compromised — rotate immediately.',
        entity: { kind: 'network', name: entry.url, id: entry.id },
        references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
      });
    }

    // ---- Token sent to third-party / unexpected origin ----
    if (entry.authHeader && host && entry.tabUrl) {
      const tabHost = safeHost(entry.tabUrl);
      if (tabHost && host !== tabHost && !sameSiteHosts(tabHost, host)) {
        seenAuthHosts.add(host);
      }
    }

    // ---- JWT findings on this entry ----
    for (const f of entry.jwtFindings || []) {
      const summary = f.summary;
      if (!summary || !summary.ok) continue;

      // Expired token still being sent
      if (summary.status === 'expired') {
        findings.push({
          id: 'net-expired-jwt:' + entry.id + ':' + f.name,
          severity: 'medium',
          title: 'Expired JWT still being sent',
          description:
            `Request to ${host} carried a JWT that expired at ${new Date(summary.expiresAt * 1000).toISOString()}. ` +
            `Look at how the server responds — accepting an expired token would be a critical vulnerability.`,
          recommendation:
            'Replay this exact request with curl/Burp — if the server returns 200 instead of 401, the ' +
            'JWT verification doesn\'t check the exp claim. That\'s a real bypass.',
          entity: { kind: 'network', name: entry.url, id: entry.id },
        });
      }

      // alg=none in production
      if (summary.alg && /^none$/i.test(summary.alg)) {
        findings.push({
          id: 'net-alg-none:' + entry.id + ':' + f.name,
          severity: 'critical',
          title: 'JWT with alg:none in production traffic',
          description: 'A real request used an unsigned JWT. The server may be accepting them.',
          recommendation:
            'Verify the server is not configured to accept alg:none tokens. This is the classic ' +
            'JWT bypass — any attacker can mint a token with arbitrary claims.',
          entity: { kind: 'network', name: entry.url, id: entry.id },
        });
      }

      // Weak HMAC algorithm
      if (summary.alg && /^HS(256|384|512)$/i.test(summary.alg)) {
        findings.push({
          id: 'net-hmac:' + entry.id + ':' + f.name,
          severity: 'low',
          title: 'HMAC-signed JWT in production',
          description:
            `Token uses ${summary.alg}. HMAC tokens are only as strong as the shared secret. ` +
            'Try the "Brute-force HMAC secret" tool in the JWT toolkit — many apps still ship weak defaults.',
          recommendation:
            'Prefer RS256/ES256 where the public key can be published; reserve HMAC for ' +
            'symmetric-server scenarios. Rotate HMAC secrets regularly and source them from a vault.',
          entity: { kind: 'network', name: entry.url, id: entry.id },
        });
      }

      // Long-lived access tokens
      if (summary.expiresAt && summary.iat) {
        const lifetimeHours = (summary.expiresAt - summary.iat) / 3600;
        if (lifetimeHours > 24) {
          findings.push({
            id: 'net-long-jwt:' + entry.id + ':' + f.name,
            severity: 'low',
            title: 'Long-lived JWT (' + Math.round(lifetimeHours) + 'h)',
            description:
              'JWTs are not revocable on the server without extra machinery. Tokens that live ' +
              'this long present a large window if leaked or stolen.',
            recommendation:
              'Shrink access-token lifetime to <1h. Use refresh tokens (revocable) for longer sessions. ' +
              'If the app already does this, lower the access-token TTL.',
            entity: { kind: 'network', name: entry.url, id: entry.id },
          });
        }
      }

      // Same token shape seen at many hosts (token leakage / over-broad audience)
      if (f.token || f.tokenPreview) {
        const prefix = (f.token || f.tokenPreview || '').slice(0, 32);
        if (!seenJwtsByHost.has(prefix)) seenJwtsByHost.set(prefix, new Set());
        seenJwtsByHost.get(prefix).add(host);
      }
    }
  }

  for (const [prefix, hosts] of seenJwtsByHost) {
    if (hosts.size > 1) {
      findings.push({
        id: 'net-cross-host-jwt:' + prefix,
        severity: 'medium',
        title: 'Same JWT sent to ' + hosts.size + ' different hosts',
        description:
          'Hosts: ' + [...hosts].join(', ') + '. The same access token is being presented at ' +
          'multiple endpoints — if the audience claim covers all of them this is intended; if not, ' +
          'one of those services should not be accepting it.',
        recommendation:
          'Decode the token (Tokens tab) and check the `aud` claim. If it lists only one resource, ' +
          'the others may be silently accepting tokens for a different audience — a real bypass.',
      });
    }
  }

  return findings;
}

function sameSiteHosts(a, b) {
  const aParts = a.split('.');
  const bParts = b.split('.');
  if (aParts.length < 2 || bParts.length < 2) return a === b;
  return (
    aParts[aParts.length - 1] === bParts[bParts.length - 1] &&
    aParts[aParts.length - 2] === bParts[bParts.length - 2]
  );
}

// ===========================================================================
// Microsoft Entra-specific audit
//
// When a decoded JWT is an Entra token, the analysis reveals issues that
// generic cookie/storage rules can't catch: privileged role memberships,
// over-broad audiences, multi-tenant exposure, app-only credentials. The
// caller is expected to pass in the result of analyzeEntraToken() and the
// source entry (cookie/storage/network) for attribution.
// ===========================================================================

export function auditEntraToken(analysis, sourceLabel) {
  const findings = [];
  if (!analysis?.isEntra) return findings;

  // Global Admin → critical, immediately
  const ga = analysis.directoryRoles.find((w) => w.info?.name === 'Global Administrator');
  if (ga) {
    findings.push({
      id: 'entra-ga:' + sourceLabel,
      severity: 'critical',
      title: 'Global Administrator token observed',
      description:
        'The captured token belongs to a Global Administrator. Theft of this token gives an ' +
        'attacker complete control of the tenant — bypassing MFA, conditional access, and PIM ' +
        'until the token expires.',
      recommendation:
        'Global Admin sessions should use Phishing-resistant MFA (FIDO2/WHfB), be excluded from ' +
        'token-replay scenarios via Conditional Access, and never appear in long-lived browser ' +
        'storage. Investigate why this token was reachable from script.',
      entity: { kind: 'entra', name: 'Global Administrator', id: sourceLabel },
    });
  }

  // App-only (client credentials) tokens — these act with app permissions directly
  if (analysis.app?.idtyp === 'app') {
    findings.push({
      id: 'entra-app-only:' + sourceLabel,
      severity: 'high',
      title: 'App-only access token (client credentials)',
      description:
        'This token was issued via the OAuth2 client credentials flow — no user context. The app ' +
        `(${analysis.app.id || 'unknown app'}) is acting with whatever application permissions it ` +
        'has been granted. Compromise of this token = full compromise of those permissions.',
      recommendation:
        'App-only tokens should never appear in browser storage. They\'re meant for service-to-' +
        'service flows. If you found this in a browser, the app secret or certificate is also ' +
        'reachable from the browser — that\'s the real bug.',
      entity: { kind: 'entra', name: analysis.app?.id, id: sourceLabel },
    });
  }

  // Multi-tenant token (common/organizations)
  if (analysis.multiTenant) {
    findings.push({
      id: 'entra-multi-tenant:' + sourceLabel,
      severity: 'medium',
      title: 'Multi-tenant audience',
      description:
        `Token was issued via the /${analysis.tenantId}/ endpoint. Any AAD tenant\'s users can ` +
        'authenticate to this app. If the app trusts claims like `email` or `unique_name` for ' +
        'authorization instead of `oid` + `tid`, attacker-controlled tenants can spoof identities.',
      recommendation:
        'Authorization decisions must use `tid` + `oid` (immutable per-tenant object id) — never ' +
        '`email`, `upn`, or `name`. Reject tokens where `tid` is not on an explicit allowlist.',
      entity: { kind: 'entra', name: 'multi-tenant', id: sourceLabel },
    });
  }

  // .default scope — token carries every consented permission
  if (analysis.scopes?.includes('.default')) {
    findings.push({
      id: 'entra-default-scope:' + sourceLabel,
      severity: 'medium',
      title: 'Token uses the .default scope',
      description:
        'The .default scope grants every permission previously consented to for this app — ' +
        'not the subset the caller actually needs. If consent has accumulated over time, this ' +
        'token may carry broader permissions than current code needs.',
      recommendation:
        'Audit consented permissions for the app in Azure portal → App registrations → API ' +
        'permissions. Remove unused grants. Prefer explicit scopes per request when possible.',
      entity: { kind: 'entra', name: '.default', id: sourceLabel },
    });
  }

  // High-privilege scopes
  for (const s of analysis.scopes || []) {
    if (/(Directory|RoleManagement|Application)\.ReadWrite\.All/.test(s)) {
      findings.push({
        id: 'entra-write-all:' + sourceLabel + ':' + s,
        severity: 'high',
        title: 'High-privilege scope: ' + s,
        description:
          'This scope confers write access to tenant-wide directory objects. With this token an ' +
          'attacker can create users, assign roles, register applications.',
        recommendation:
          'Use least-privilege scopes — prefer .Read.All over .ReadWrite.All. If write is needed, ' +
          'gate the operation behind Privileged Identity Management and require approval.',
        entity: { kind: 'entra', name: s, id: sourceLabel },
      });
    }
  }

  // Long-lived Entra tokens (default is 1h but custom lifetime policies exist)
  if (analysis.issuedAt && analysis.expiresAt) {
    const hours = (analysis.expiresAt - analysis.issuedAt) / 3600000;
    if (hours > 8) {
      findings.push({
        id: 'entra-long:' + sourceLabel,
        severity: 'low',
        title: 'Entra token lifetime is ' + Math.round(hours) + ' hours',
        description:
          'Microsoft\'s default access-token lifetime is 1 hour. A token issued with a much longer ' +
          'lifetime suggests a Token Lifetime Policy is in effect.',
        recommendation:
          'Audit Conditional Access → Sign-in frequency and token lifetime policies. Long-lived ' +
          'access tokens widen the window for replay if the token is stolen.',
        entity: { kind: 'entra', name: 'long-lifetime', id: sourceLabel },
      });
    }
  }

  return findings;
}
