/**
 * AuthForge — Format codecs (shared/formats.js)
 *
 * Parsers and formatters for the cookie/storage exchange formats users
 * actually need:
 *
 *   - JSON: round-trip preserving every Chrome cookie attribute.
 *   - Netscape (cookies.txt): the format curl, yt-dlp, and friends speak.
 *   - cURL: produces `curl -H 'Cookie: ...'` style snippets.
 *   - Header: a raw `Cookie: name=value; name2=value2` line, also accepted
 *     as input (we parse it back to a list of name/value pairs).
 */

// ---------- JSON --------------------------------------------------------------

export const Json = {
  format(cookies) {
    const out = cookies.map((c) => {
      // Strip storeId so the dump is portable between Chrome profiles.
      const { storeId, ...rest } = c;
      if (rest.sameSite === 'unspecified') rest.sameSite = null;
      return rest;
    });
    return JSON.stringify(out, null, 2);
  },
  parse(text) {
    const data = JSON.parse(text);
    if (!Array.isArray(data)) {
      throw new Error('JSON: expected an array of cookies at the top level');
    }
    return data;
  },
};

// ---------- Netscape cookies.txt ---------------------------------------------

const HTTPONLY_PREFIX = '#HttpOnly_';

export const Netscape = {
  format(cookies) {
    const lines = [
      '# Netscape HTTP Cookie File',
      '# https://curl.se/docs/http-cookies.html',
      '# Exported by AuthForge',
    ];
    for (const c of cookies) {
      const includeSubdomain = c.hostOnly ? 'FALSE' : 'TRUE';
      const secure = c.secure ? 'TRUE' : 'FALSE';
      let expiration = 0;
      if (c.session) {
        // Session cookies don't survive the format; we give them a 24h
        // expiry so they at least re-import as live cookies.
        expiration = Math.trunc((Date.now() + 86400 * 1000) / 1000);
      } else if (c.expirationDate) {
        expiration = Math.trunc(c.expirationDate);
      }
      const prefix = c.httpOnly ? HTTPONLY_PREFIX : '';
      lines.push(
        `${prefix}${c.domain}\t${includeSubdomain}\t${c.path}\t${secure}\t${expiration}\t${c.name}\t${c.value}`
      );
    }
    return lines.join('\n');
  },
  parse(text) {
    const cookies = [];
    for (let line of text.split(/\r?\n/)) {
      line = line.trim();
      if (!line) continue;
      const httpOnly = line.startsWith(HTTPONLY_PREFIX);
      if (httpOnly) line = line.substring(HTTPONLY_PREFIX.length);
      // Skip pure comments
      if (line.startsWith('#')) continue;
      const parts = line.split('\t');
      if (parts.length !== 7) {
        throw new Error(
          'Netscape: expected 7 tab-separated columns, got ' + parts.length
        );
      }
      const [domain, includeSub, path, secureStr, expStr, name, value] = parts;
      cookies.push({
        domain,
        hostOnly: includeSub.toUpperCase() === 'FALSE',
        path,
        secure: secureStr.toUpperCase() === 'TRUE',
        expirationDate: Number(expStr) || undefined,
        session: !Number(expStr),
        name,
        value,
        httpOnly,
      });
    }
    return cookies;
  },
};

// ---------- Header line -------------------------------------------------------

export const HeaderLine = {
  /**
   * Build a single `Cookie:` header value (the actual line you'd send to a
   * server). Filters out HttpOnly cookies? No — HttpOnly is a *response*
   * attribute; the browser still sends those in the Cookie header. We
   * include everything.
   */
  format(cookies) {
    return cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  },
  /**
   * Parse `name=value; name2=value2` back into a partial cookie list. We
   * don't get domain/path/expiry from this format, so the caller has to
   * fill those in when importing.
   */
  parse(text) {
    const out = [];
    for (const pair of text.split(/;\s*/)) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      if (eq === -1) {
        out.push({ name: pair.trim(), value: '' });
      } else {
        out.push({
          name: pair.slice(0, eq).trim(),
          value: pair.slice(eq + 1).trim(),
        });
      }
    }
    return out;
  },
};

// ---------- cURL --------------------------------------------------------------

export const Curl = {
  /**
   * `curl 'https://example.com' -H 'Cookie: a=1; b=2'`
   * If a URL is passed, it gets quoted as the first positional argument;
   * otherwise we only emit the `-H` flag and the user pastes it where
   * needed.
   */
  format(cookies, url = null) {
    const header = HeaderLine.format(cookies);
    if (url) {
      return `curl '${url.replace(/'/g, "'\\''")}' -H 'Cookie: ${header.replace(
        /'/g,
        "'\\''"
      )}'`;
    }
    return `-H 'Cookie: ${header.replace(/'/g, "'\\''")}'`;
  },
};

// ---------- Storage (LS / SS) -------------------------------------------------
//
// LocalStorage / SessionStorage are simple key/value strings, so a JSON
// dictionary is the right format. We don't include a Netscape equivalent
// because no such thing exists.

export const StorageJson = {
  format(entries) {
    const obj = Object.fromEntries(entries.map((e) => [e.key, e.value]));
    return JSON.stringify(obj, null, 2);
  },
  parse(text) {
    const data = JSON.parse(text);
    if (data == null || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('Storage JSON: expected an object of key→value pairs');
    }
    return Object.entries(data).map(([key, value]) => ({
      key,
      value: typeof value === 'string' ? value : JSON.stringify(value),
    }));
  },
};
