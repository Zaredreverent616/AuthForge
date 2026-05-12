/* ============================================================================
   AuthForge — Options page logic.
   Handles settings persistence, JWT playground, snapshot management, and
   simple section navigation. Imports shared modules for parity with the
   popup / devtools surfaces.
   ============================================================================ */

import { settingsApi, snapshotsApi, profilesApi, tabs, cookies as cookiesApi, localStorageApi, sessionStorageApi } from '../shared/api.js';
import {
  decodeJWT,
  encodeJWT,
  verifyJWT,
  summarizeJWT,
  looksLikeJWT,
  generateAttackVariants,
  tryHmacSecrets,
  DEFAULT_HMAC_SECRETS,
} from '../shared/jwt.js';
import { parseHar } from '../shared/har.js';
import { PROFILE_FORMATS, exportProfile } from '../shared/profile-formats.js';
import { auditCookies, auditStorage } from '../shared/audit.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const DEFAULT_SETTINGS = {
  theme: 'auto',
  showExpired: true,
  defaultExportFormat: 'json',
  confirmDelete: true,
  // Advanced — UI
  hideEmptyStorageTabs: true,
  compactMode: false,
  // Advanced — detection
  customRefreshTokenPatterns: [],
  customAuthHeaderNames: [],
  customTokenEndpointPatterns: [],
  customTokenFieldNames: [],
  // Advanced — network capture
  autoStartNetworkCapture: true,
  networkBufferSize: 500,
  persistNetworkCaptures: false,
  // Advanced — security testing
  customHmacWordlist: '',
  jwtBruteMaxAttempts: 1000,
};

let currentSettings = { ...DEFAULT_SETTINGS };

// ============================================================================
// Bootstrap
// ============================================================================

async function init() {
  await loadSettings();
  applyTheme();
  bindSectionNav();
  bindSettingsForm();
  bindAdvancedTab();
  bindSnapshotsTab();
  bindProfilesTab();
  bindResetButton();
  populateAbout();
  await refreshSnapshots();
  await refreshProfiles();
}

document.addEventListener('DOMContentLoaded', init);

// ============================================================================
// Settings
// ============================================================================

async function loadSettings() {
  try {
    const saved = await settingsApi.get();
    currentSettings = { ...DEFAULT_SETTINGS, ...(saved || {}) };
  } catch (err) {
    console.warn('Failed to load settings:', err);
    currentSettings = { ...DEFAULT_SETTINGS };
  }
  // Reflect into the form
  $('#opt-theme').value = currentSettings.theme;
  $('#opt-show-expired').checked = currentSettings.showExpired !== false;
  $('#opt-default-export').value = currentSettings.defaultExportFormat || 'json';
  $('#opt-confirm-delete').checked = currentSettings.confirmDelete !== false;
}

async function saveSettings(partial) {
  currentSettings = { ...currentSettings, ...partial };
  try {
    await settingsApi.set(currentSettings);
    toast('Saved');
  } catch (err) {
    toast('Save failed: ' + err.message, 'error');
  }
}

function applyTheme() {
  const desired =
    currentSettings.theme === 'auto'
      ? matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : currentSettings.theme;
  document.documentElement.dataset.theme = desired;
}

function bindSettingsForm() {
  $('#opt-theme').addEventListener('change', (e) => {
    saveSettings({ theme: e.target.value });
    applyTheme();
  });
  $('#opt-show-expired').addEventListener('change', (e) => {
    saveSettings({ showExpired: e.target.checked });
  });
  $('#opt-default-export').addEventListener('change', (e) => {
    saveSettings({ defaultExportFormat: e.target.value });
  });
  $('#opt-confirm-delete').addEventListener('change', (e) => {
    saveSettings({ confirmDelete: e.target.checked });
  });

  // React to OS theme changes when in auto mode
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (currentSettings.theme === 'auto') applyTheme();
  });
}

function bindResetButton() {
  $('#btn-reset-settings').addEventListener('click', async () => {
    if (!confirm('Reset all settings to their defaults?')) return;
    currentSettings = { ...DEFAULT_SETTINGS };
    try {
      await settingsApi.set(currentSettings);
      await loadSettings();
      applyTheme();
      toast('Settings reset');
    } catch (err) {
      toast('Reset failed: ' + err.message, 'error');
    }
  });
}

// ============================================================================
// Section navigation (simple in-page tabs)
// ============================================================================

function bindSectionNav() {
  const links = $$('.nav-link');
  const sections = $$('.panel');

  const show = (target) => {
    sections.forEach((s) => {
      s.classList.toggle('hidden', s.id !== target);
    });
    links.forEach((l) => {
      l.classList.toggle('active', l.dataset.target === target);
    });
    history.replaceState(null, '', '#' + target);
  };

  links.forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      show(link.dataset.target);
    });
  });

  // Honor hash on load
  const initial = (location.hash || '').replace(/^#/, '');
  if (initial && sections.some((s) => s.id === initial)) {
    show(initial);
  }

  // "Show welcome page" button in the About panel — opens the same
  // onboarding tour that runs on first install.
  document.getElementById('open-welcome')?.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('welcome/welcome.html') });
  });
}

// ============================================================================
// JWT playground
// ============================================================================

// Module-level so the Attack Lab can read whatever the playground last decoded.
let lastDecodedJWT = null;
let lastDecodedRawToken = '';

function bindJwtPlayground() {
  const input = $('#jwt-input');
  const headerEl = $('#jwt-header');
  const payloadEl = $('#jwt-payload');
  const secretEl = $('#jwt-secret');
  const statusEl = $('#jwt-status');
  const outputEl = $('#jwt-output');

  let lastDecoded = null;

  // Mirror local state into module-level so the Attack Lab can use it.
  function setDecoded(decoded, raw) {
    lastDecoded = decoded;
    lastDecodedJWT = decoded;
    lastDecodedRawToken = raw || '';
    updateAttackLabReadiness();
  }

  const setStatus = (msg, tone = '') => {
    statusEl.textContent = msg;
    statusEl.classList.remove('error', 'ok');
    if (tone) statusEl.classList.add(tone);
  };

  const tryDecode = () => {
    const raw = input.value.trim();
    if (!raw) {
      headerEl.value = '';
      payloadEl.value = '';
      outputEl.textContent = '';
      setDecoded(null, '');
      setStatus('Paste a token to decode.');
      return;
    }
    if (!looksLikeJWT(raw)) {
      setStatus('That does not look like a JWT (expected three base64url segments).', 'error');
      return;
    }
    try {
      const decoded = decodeJWT(raw);
      setDecoded(decoded, raw);
      headerEl.value = JSON.stringify(decoded.header, null, 2);
      payloadEl.value = JSON.stringify(decoded.payload, null, 2);

      const summary = summarizeJWT(raw);
      const bits = [];
      if (summary.alg) bits.push('alg=' + summary.alg);
      if (summary.issuer) bits.push('iss=' + summary.issuer);
      if (summary.subject) bits.push('sub=' + summary.subject);
      if (summary.audience) {
        const aud = Array.isArray(summary.audience)
          ? summary.audience.join(',')
          : summary.audience;
        bits.push('aud=' + aud);
      }
      if (summary.expiresAt) {
        const expDate = new Date(summary.expiresAt * 1000).toISOString();
        bits.push('exp=' + expDate);
      }
      if (summary.status === 'expired') {
        setStatus('Decoded · expired · ' + bits.join(' · '), 'error');
      } else if (summary.status === 'expiring-soon') {
        setStatus('Decoded · expiring soon · ' + bits.join(' · '), 'ok');
      } else {
        setStatus('Decoded · ' + bits.join(' · '), 'ok');
      }
    } catch (err) {
      setStatus('Decode failed: ' + err.message, 'error');
    }
  };

  input.addEventListener('input', tryDecode);

  $('#btn-jwt-clear').addEventListener('click', () => {
    input.value = '';
    headerEl.value = '';
    payloadEl.value = '';
    secretEl.value = '';
    outputEl.textContent = '';
    setDecoded(null, '');
    setStatus('Cleared.');
  });

  $('#btn-jwt-resign').addEventListener('click', async () => {
    let header, payload;
    try {
      header = JSON.parse(headerEl.value);
    } catch {
      setStatus('Header is not valid JSON.', 'error');
      return;
    }
    try {
      payload = JSON.parse(payloadEl.value);
    } catch {
      setStatus('Payload is not valid JSON.', 'error');
      return;
    }
    const alg = header.alg;
    if (!alg || !/^HS(256|384|512)$/.test(alg)) {
      setStatus(
        'Re-signing only supports HS256, HS384, HS512. Set header.alg accordingly.',
        'error'
      );
      return;
    }
    const secret = secretEl.value;
    if (!secret) {
      setStatus('Provide an HMAC secret to sign with.', 'error');
      return;
    }
    try {
      const token = await encodeJWT(header, payload, secret);
      outputEl.textContent = token;
      try {
        await navigator.clipboard.writeText(token);
        setStatus('Signed and copied to clipboard.', 'ok');
      } catch {
        setStatus('Signed. Clipboard blocked — copy the token below.', 'ok');
      }
    } catch (err) {
      setStatus('Sign failed: ' + err.message, 'error');
    }
  });

  $('#btn-jwt-verify').addEventListener('click', async () => {
    if (!lastDecoded) {
      setStatus('Decode a token first.', 'error');
      return;
    }
    const secret = secretEl.value;
    if (!secret) {
      setStatus('Provide the HMAC secret to verify against.', 'error');
      return;
    }
    try {
      const ok = await verifyJWT(input.value.trim(), secret);
      if (ok) {
        outputEl.textContent = '✓ Signature is valid for this secret.';
        setStatus('Signature verified.', 'ok');
      } else {
        outputEl.textContent = '✗ Signature does not match this secret.';
        setStatus('Signature mismatch.', 'error');
      }
    } catch (err) {
      setStatus('Verify failed: ' + err.message, 'error');
    }
  });
}

// ============================================================================
// JWT Attack Lab — preset payloads for security testing
// ============================================================================

function updateAttackLabReadiness() {
  const btn = $('#btn-attack-generate');
  const state = $('#attack-state');
  if (!btn || !state) return;
  if (lastDecodedJWT) {
    btn.disabled = false;
    state.textContent =
      `Ready — token decoded (alg=${lastDecodedJWT.header.alg ?? '?'})`;
    state.className = 'attack-state ok';
  } else {
    btn.disabled = true;
    state.textContent = 'Decode a token first.';
    state.className = 'attack-state';
  }
}

function bindAttackLab() {
  updateAttackLabReadiness();

  $('#btn-attack-generate').addEventListener('click', async () => {
    if (!lastDecodedJWT) return;
    try {
      const variants = await generateAttackVariants(lastDecodedJWT);
      renderAttackVariants(variants);
    } catch (err) {
      toast('Failed to generate variants: ' + err.message, 'error');
    }
  });

  $('#btn-attack-brute').addEventListener('click', performBruteForce);
}

function renderAttackVariants(variants) {
  const host = $('#attack-variants');
  host.innerHTML = '';
  for (const v of variants) {
    const card = document.createElement('div');
    card.className = 'variant-card';
    card.dataset.severity = v.severity || 'medium';

    const head = document.createElement('div');
    head.className = 'variant-head';
    const name = document.createElement('div');
    name.className = 'variant-name';
    name.textContent = v.name;
    head.appendChild(name);
    const sev = document.createElement('div');
    sev.className = 'variant-severity';
    sev.dataset.severity = v.severity || 'medium';
    sev.textContent = v.severity || 'medium';
    head.appendChild(sev);
    card.appendChild(head);

    const desc = document.createElement('div');
    desc.className = 'variant-desc';
    desc.textContent = v.description;
    card.appendChild(desc);

    if (v.note) {
      const note = document.createElement('div');
      note.className = 'variant-note';
      note.textContent = '⓵  ' + v.note;
      card.appendChild(note);
    }

    const token = document.createElement('div');
    token.className = 'variant-token';
    token.textContent = v.token;
    card.appendChild(token);

    const actions = document.createElement('div');
    actions.className = 'variant-actions';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn primary';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(v.token);
        toast('Variant copied', 'success');
      } catch {
        toast('Clipboard blocked — select manually', 'error');
      }
    });
    actions.appendChild(copyBtn);

    const useBtn = document.createElement('button');
    useBtn.className = 'btn ghost';
    useBtn.textContent = 'Load into playground';
    useBtn.addEventListener('click', () => {
      $('#jwt-input').value = v.token;
      $('#jwt-input').dispatchEvent(new Event('input'));
      $('#jwt-input').scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
    actions.appendChild(useBtn);

    card.appendChild(actions);
    host.appendChild(card);
  }
}

async function performBruteForce() {
  if (!lastDecodedRawToken) {
    setBruteResult('Decode a token first.', 'err');
    return;
  }
  if (!/^HS(256|384|512)$/.test(lastDecodedJWT?.header?.alg || '')) {
    setBruteResult(
      'Only HS256 / HS384 / HS512 tokens can be brute-forced this way.',
      'err'
    );
    return;
  }

  const extra = ($('#attack-brute-list').value || '')
    .split('\n')
    .map((s) => s.replace(/\r$/, ''))
    .filter((s) => s.length || s === '');
  // Dedupe but preserve order: defaults first, extras after
  const seen = new Set();
  const list = [];
  for (const s of [...DEFAULT_HMAC_SECRETS, ...extra]) {
    if (seen.has(s)) continue;
    seen.add(s);
    list.push(s);
  }

  setBruteResult(`Trying ${list.length} candidates…`, '');
  $('#btn-attack-brute').disabled = true;

  try {
    const result = await tryHmacSecrets(
      lastDecodedRawToken,
      list,
      (n, total) => setBruteResult(`Trying ${n}/${total}…`, '')
    );
    if (!result.applicable) {
      setBruteResult('Token alg is not HMAC — nothing to try.', 'err');
    } else if (result.found !== null) {
      setBruteResult(
        `Match! Secret = ${JSON.stringify(result.found)} (after ${result.attempted} tries)`,
        'ok'
      );
      // Auto-fill into the secret field so the user can re-sign mutated payloads
      $('#jwt-secret').value = result.found;
      toast('Weak HMAC secret found', 'success');
    } else {
      setBruteResult(`No match in ${result.attempted} candidates.`, 'err');
    }
  } catch (err) {
    setBruteResult('Error: ' + err.message, 'err');
  } finally {
    $('#btn-attack-brute').disabled = false;
  }
}

function setBruteResult(text, tone) {
  const el = $('#attack-brute-result');
  el.textContent = text;
  el.className = 'attack-brute-result' + (tone ? ' ' + tone : '');
}

// ============================================================================
// Security Audit — heuristic analysis of cookies + storage on a target URL
// ============================================================================

function bindAuditTab() {
  $('#btn-audit-current').addEventListener('click', async () => {
    try {
      const tab = await tabs.current();
      if (!tab?.url) {
        toast('No active tab.', 'error');
        return;
      }
      $('#audit-target-url').value = tab.url;
      await runAudit(tab.url, tab.id);
    } catch (err) {
      toast('Audit failed: ' + err.message, 'error');
    }
  });

  $('#btn-audit-url').addEventListener('click', async () => {
    const url = $('#audit-target-url').value.trim();
    if (!url) {
      toast('Enter a URL to audit.', 'error');
      return;
    }
    // No tab → cookies only (no LS/SS access without a tab to inject into)
    await runAudit(url, null);
  });
}

async function runAudit(url, tabId) {
  const summary = $('#audit-summary');
  const findingsEl = $('#audit-findings');
  summary.innerHTML = '';
  findingsEl.innerHTML = '';

  const status = document.createElement('div');
  status.className = 'audit-summary-row';
  status.innerHTML = '<span class="audit-summary-label">Auditing…</span>';
  summary.appendChild(status);

  try {
    const cookieList = await cookiesApi.getAll({ url });
    let lsEntries = [];
    let ssEntries = [];
    if (tabId) {
      try {
        lsEntries = (await localStorageApi.getAll(tabId)) || [];
      } catch {
        /* page may not have any */
      }
      try {
        ssEntries = (await sessionStorageApi.getAll(tabId)) || [];
      } catch {
        /* page may not have any */
      }
    }

    const cookieFindings = auditCookies(cookieList, { pageUrl: url });
    const lsFindings = auditStorage(lsEntries, { storeName: 'localStorage' });
    const ssFindings = auditStorage(ssEntries, { storeName: 'sessionStorage' });
    const all = [...cookieFindings, ...lsFindings, ...ssFindings];

    renderAuditSummary(summary, url, all, {
      cookies: cookieList.length,
      ls: lsEntries.length,
      ss: ssEntries.length,
      tabAvailable: !!tabId,
    });
    renderAuditFindings(findingsEl, all);
  } catch (err) {
    summary.innerHTML = '';
    const errEl = document.createElement('div');
    errEl.className = 'audit-summary-row';
    errEl.innerHTML =
      '<span class="audit-summary-label">Audit failed:</span> <span>' +
      escapeHtml(err.message) +
      '</span>';
    summary.appendChild(errEl);
  }
}

function renderAuditSummary(host, url, findings, stats) {
  host.innerHTML = '';
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const row = document.createElement('div');
  row.className = 'audit-summary-row';
  row.innerHTML =
    '<span class="audit-summary-label">Target:</span> ' +
    '<span style="font-family:var(--font-mono);font-size:12px">' + escapeHtml(url) + '</span>' +
    '<span class="audit-summary-label">·</span>' +
    `<span>${stats.cookies} cookies` +
    (stats.tabAvailable
      ? `, ${stats.ls} LS / ${stats.ss} SS`
      : ', LS/SS skipped (no tab)') +
    '</span>' +
    '<span class="audit-summary-label">·</span>' +
    `<span class="audit-summary-count ${counts.high ? 'high' : 'zero'}">${counts.high} high</span>` +
    `<span class="audit-summary-count ${counts.medium ? 'medium' : 'zero'}">${counts.medium} medium</span>` +
    `<span class="audit-summary-count ${counts.low ? 'low' : 'zero'}">${counts.low} low</span>`;
  host.appendChild(row);
}

function renderAuditFindings(host, findings) {
  host.innerHTML = '';
  if (!findings.length) {
    const empty = document.createElement('div');
    empty.className = 'audit-empty ok';
    empty.innerHTML =
      '<strong>No findings.</strong>' +
      '<p>Cookies and storage on this page passed the heuristic checks. ' +
      'This isn\'t a full security review — it covers the common misconfigurations.</p>';
    host.appendChild(empty);
    return;
  }
  for (const f of findings) {
    const card = document.createElement('div');
    card.className = 'audit-finding';
    card.dataset.severity = f.severity;

    const head = document.createElement('div');
    head.className = 'audit-finding-head';
    const issue = document.createElement('div');
    issue.className = 'audit-finding-issue';
    issue.textContent = f.issue;
    head.appendChild(issue);
    const target = document.createElement('div');
    target.className = 'audit-finding-target';
    target.textContent = f.targetKind + ': ' + f.target;
    head.appendChild(target);
    card.appendChild(head);

    if (f.detail) {
      const d = document.createElement('div');
      d.className = 'audit-finding-detail';
      d.textContent = f.detail;
      card.appendChild(d);
    }

    if (f.recommendation) {
      const r = document.createElement('div');
      r.className = 'audit-finding-rec';
      const strong = document.createElement('strong');
      strong.textContent = 'Recommendation: ';
      r.appendChild(strong);
      r.appendChild(document.createTextNode(f.recommendation));
      card.appendChild(r);
    }

    host.appendChild(card);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

// ============================================================================
// Snapshots manager
// ============================================================================

let snapshotsCache = {};

async function refreshSnapshots() {
  try {
    snapshotsCache = (await snapshotsApi.list()) || {};
  } catch (err) {
    snapshotsCache = {};
    console.warn('Failed to list snapshots:', err);
  }
  renderSnapshots();
}

function bindSnapshotsTab() {
  $('#snap-search').addEventListener('input', renderSnapshots);

  $('#btn-snap-export-all').addEventListener('click', () => {
    const entries = Object.entries(snapshotsCache);
    if (!entries.length) {
      toast('No snapshots to export', 'error');
      return;
    }
    const blob = new Blob([JSON.stringify(snapshotsCache, null, 2)], {
      type: 'application/json',
    });
    downloadBlob(blob, 'authforge-snapshots-' + new Date().toISOString().slice(0, 10) + '.json');
    toast('Exported ' + entries.length + ' snapshot' + (entries.length === 1 ? '' : 's'));
  });

  $('#snap-import-file').addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      if (!data || typeof data !== 'object') throw new Error('Not a snapshot file');
      let imported = 0;
      // Two accepted shapes: { id: snapshot } map, or a single snapshot object
      if (data.cookies || data.localStorage) {
        const id = 'imported-' + Date.now();
        await snapshotsApi.save(id, data);
        imported = 1;
      } else {
        for (const [id, snap] of Object.entries(data)) {
          if (snap && typeof snap === 'object') {
            await snapshotsApi.save(id, snap);
            imported++;
          }
        }
      }
      await refreshSnapshots();
      toast('Imported ' + imported + ' snapshot' + (imported === 1 ? '' : 's'));
    } catch (err) {
      toast('Import failed: ' + err.message, 'error');
    } finally {
      e.target.value = '';
    }
  });
}

function renderSnapshots() {
  const list = $('#snap-list');
  const search = ($('#snap-search').value || '').toLowerCase().trim();
  list.innerHTML = '';

  const entries = Object.entries(snapshotsCache)
    .filter(([id, snap]) => {
      if (!search) return true;
      const hay = (id + ' ' + (snap.url || '') + ' ' + (snap.name || '')).toLowerCase();
      return hay.includes(search);
    })
    .sort((a, b) => (b[1].capturedAt || 0) - (a[1].capturedAt || 0));

  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'snap-empty';
    if (Object.keys(snapshotsCache).length === 0) {
      empty.innerHTML =
        '<strong>No snapshots yet.</strong>Capture one from the popup or DevTools panel to save a domain\'s full state.';
    } else {
      empty.innerHTML = '<strong>No matches.</strong>Try a different search term.';
    }
    list.appendChild(empty);
    return;
  }

  for (const [id, snap] of entries) {
    list.appendChild(renderSnapshotCard(id, snap));
  }
}

function renderSnapshotCard(id, snap) {
  const card = document.createElement('div');
  card.className = 'snap-card';

  const main = document.createElement('div');
  main.className = 'snap-card-main';

  const name = document.createElement('div');
  name.className = 'snap-card-name';
  name.textContent = snap.name || id;
  main.appendChild(name);

  const meta = document.createElement('div');
  meta.className = 'snap-card-meta';
  const url = snap.url || '(no url)';
  const captured = snap.capturedAt
    ? new Date(snap.capturedAt).toLocaleString()
    : 'unknown time';
  meta.textContent = url + ' · ' + captured;
  main.appendChild(meta);

  const stats = document.createElement('div');
  stats.className = 'snap-card-stats';
  const cookieCount = (snap.cookies || []).length;
  const lsCount = (snap.localStorage || []).length;
  const ssCount = (snap.sessionStorage || []).length;
  const idbCount = (snap.indexedDBDatabases || []).length;
  stats.innerHTML =
    '<span><strong>' + cookieCount + '</strong> cookies</span>' +
    '<span><strong>' + lsCount + '</strong> localStorage</span>' +
    '<span><strong>' + ssCount + '</strong> sessionStorage</span>' +
    '<span><strong>' + idbCount + '</strong> IDB</span>';
  main.appendChild(stats);

  const actions = document.createElement('div');
  actions.className = 'snap-card-actions';

  const exportBtn = document.createElement('button');
  exportBtn.className = 'btn ghost';
  exportBtn.textContent = 'Export';
  exportBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(snap, null, 2)], { type: 'application/json' });
    const safeId = id.replace(/[^a-z0-9_.-]/gi, '_');
    downloadBlob(blob, 'snapshot-' + safeId + '.json');
    toast('Exported');
  });
  actions.appendChild(exportBtn);

  const delBtn = document.createElement('button');
  delBtn.className = 'btn danger';
  delBtn.textContent = 'Delete';
  delBtn.addEventListener('click', async () => {
    if (!confirm('Delete snapshot "' + (snap.name || id) + '"?')) return;
    try {
      await snapshotsApi.delete(id);
      await refreshSnapshots();
      toast('Deleted');
    } catch (err) {
      toast('Delete failed: ' + err.message, 'error');
    }
  });
  actions.appendChild(delBtn);

  card.appendChild(main);
  card.appendChild(actions);
  return card;
}

// ============================================================================
// About
// ============================================================================

function populateAbout() {
  try {
    const mf = chrome.runtime.getManifest();
    $('#about-version').textContent = 'v' + mf.version;
  } catch {
    $('#about-version').textContent = 'unknown';
  }
}

// ============================================================================
// Profiles — reusable credential bundles
// ============================================================================

let profilesCache = {};
let activeProfile = null;
let activeModalTab = 'apply';

async function refreshProfiles() {
  try {
    profilesCache = (await profilesApi.list()) || {};
  } catch (err) {
    profilesCache = {};
    console.warn('Failed to list profiles:', err);
  }
  renderProfiles();
}

function bindProfilesTab() {
  $('#prof-search').addEventListener('input', renderProfiles);

  $('#btn-prof-capture').addEventListener('click', captureCurrentTabAsProfile);

  $('#prof-import-har').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = parseHar(text);
      const name = prompt(
        `Imported ${parsed.cookies.length} cookies and ${parsed.authHeaders.length} auth headers ` +
          `from ${parsed.stats.hosts.length} host(s).\n\n` +
          `Name this profile:`,
        guessProfileNameFromUrl(parsed.sourceUrl) || file.name.replace(/\.har$/i, '')
      );
      if (!name) return;
      const profile = {
        name,
        description: `Imported from HAR · ${parsed.stats.entries} entries · ${parsed.stats.hosts.join(', ')}`,
        sourceUrl: parsed.sourceUrl,
        sourceDomain: parsed.sourceDomain,
        cookies: parsed.cookies,
        localStorage: parsed.localStorage,
        sessionStorage: parsed.sessionStorage,
        authHeaders: parsed.authHeaders,
        notes: '',
      };
      const id = 'profile-' + Date.now();
      await profilesApi.save(id, profile);
      await refreshProfiles();
      toast(`Imported profile "${name}"`, 'success');
    } catch (err) {
      toast('HAR import failed: ' + err.message, 'error');
    } finally {
      e.target.value = '';
    }
  });

  $('#prof-import-json').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      let imported = 0;
      // Accept either a single profile or a { id: profile } map
      if (data && typeof data === 'object' && (data.cookies || data.authHeaders || data.name)) {
        const id = data.id || 'profile-' + Date.now();
        await profilesApi.save(id, stripIdMeta(data));
        imported = 1;
      } else if (data && typeof data === 'object') {
        for (const [id, p] of Object.entries(data)) {
          if (p && typeof p === 'object') {
            await profilesApi.save(id, stripIdMeta(p));
            imported++;
          }
        }
      }
      await refreshProfiles();
      toast(
        imported
          ? `Imported ${imported} profile${imported === 1 ? '' : 's'}`
          : 'Nothing to import',
        imported ? 'success' : 'error'
      );
    } catch (err) {
      toast('JSON import failed: ' + err.message, 'error');
    } finally {
      e.target.value = '';
    }
  });

  // Modal mechanics
  $('#prof-modal-close').addEventListener('click', closeProfileModal);
  $$('#prof-modal [data-close-modal]').forEach((el) =>
    el.addEventListener('click', closeProfileModal)
  );
  $$('#prof-modal .modal-tab').forEach((tab) =>
    tab.addEventListener('click', () => switchModalTab(tab.dataset.modalTab))
  );
  $('#prof-modal').addEventListener('click', (e) => {
    if (e.target.id === 'prof-modal') closeProfileModal();
  });

  // Apply panel
  $('#btn-apply').addEventListener('click', performApply);
  $('#apply-target-url').addEventListener('input', () => {
    const host = safeHost($('#apply-target-url').value);
    $('#apply-target-host').value = host;
    // If user changes target, auto-enable remap when hosts differ
    const src = $('#apply-source-host').value;
    if (host && src && host !== src) {
      $('#apply-remap').checked = true;
    }
  });

  // Edit panel
  $('#btn-save-edits').addEventListener('click', saveProfileEdits);

  // Export panel
  const fmtSel = $('#export-format');
  for (const f of PROFILE_FORMATS) {
    const opt = document.createElement('option');
    opt.value = f.id;
    opt.textContent = f.label;
    fmtSel.appendChild(opt);
  }
  fmtSel.addEventListener('change', refreshExportPreview);
  $('#export-target-url').addEventListener('input', refreshExportPreview);
  $('#btn-export-copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('#export-preview').value);
      toast('Copied to clipboard', 'success');
    } catch {
      toast('Clipboard blocked — select and copy manually', 'error');
    }
  });
  $('#btn-export-download').addEventListener('click', () => {
    const fmt = PROFILE_FORMATS.find((f) => f.id === fmtSel.value);
    if (!fmt || !activeProfile) return;
    const safeName = (activeProfile.name || activeProfile.id || 'profile')
      .replace(/[^a-z0-9_.-]/gi, '_')
      .slice(0, 64);
    const blob = new Blob([$('#export-preview').value], { type: fmt.mime });
    downloadBlob(blob, `${safeName}.${fmt.ext}`);
    toast('Downloaded', 'success');
  });
}

async function captureCurrentTabAsProfile() {
  try {
    const tab = await tabs.current();
    if (!tab || !tab.url) {
      toast('No active tab to capture.', 'error');
      return;
    }
    const captured = await profilesApi.capture(tab.id, tab.url);
    if (!captured.cookies.length && !captured.localStorage.length && !captured.sessionStorage.length) {
      if (!confirm('Nothing found to capture on this page. Save an empty profile anyway?')) {
        return;
      }
    }
    const name = prompt(
      'Name this profile:',
      guessProfileNameFromUrl(tab.url) || 'Profile'
    );
    if (!name) return;
    const id = 'profile-' + Date.now();
    await profilesApi.save(id, {
      ...captured,
      name,
      description: `Captured from ${tab.url}`,
      notes: '',
    });
    await refreshProfiles();
    toast(`Saved "${name}"`, 'success');
  } catch (err) {
    toast('Capture failed: ' + err.message, 'error');
  }
}

function renderProfiles() {
  const list = $('#prof-list');
  const search = ($('#prof-search').value || '').toLowerCase().trim();
  list.innerHTML = '';

  const entries = Object.entries(profilesCache)
    .filter(([id, p]) => {
      if (!search) return true;
      const hay = (
        id + ' ' + (p.name || '') + ' ' + (p.description || '') + ' ' + (p.sourceUrl || '')
      ).toLowerCase();
      return hay.includes(search);
    })
    .sort((a, b) => (b[1].updatedAt || 0) - (a[1].updatedAt || 0));

  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'prof-empty';
    if (Object.keys(profilesCache).length === 0) {
      empty.innerHTML =
        '<strong>No profiles yet.</strong>' +
        '<p>Capture the current tab to save its cookies + storage as a reusable profile, ' +
        'or import a HAR file from your DevTools / API client to bootstrap one. ' +
        'Apply a profile to any URL with optional cross-environment domain remapping.</p>';
    } else {
      empty.innerHTML = '<strong>No matches.</strong>';
    }
    list.appendChild(empty);
    return;
  }

  for (const [id, profile] of entries) {
    list.appendChild(renderProfileCard(id, profile));
  }
}

function renderProfileCard(id, profile) {
  const card = document.createElement('div');
  card.className = 'prof-card';

  const main = document.createElement('div');
  main.className = 'prof-card-main';

  const name = document.createElement('div');
  name.className = 'prof-card-name';
  const nameText = document.createElement('span');
  nameText.textContent = profile.name || id;
  name.appendChild(nameText);

  if (profile.sourceDomain) {
    const badge = document.createElement('span');
    badge.className = 'prof-card-source-badge';
    badge.textContent = profile.sourceDomain;
    name.appendChild(badge);
  }
  main.appendChild(name);

  if (profile.description) {
    const desc = document.createElement('div');
    desc.className = 'prof-card-desc';
    desc.textContent = profile.description;
    desc.title = profile.description;
    main.appendChild(desc);
  }

  const stats = document.createElement('div');
  stats.className = 'prof-card-stats';
  stats.innerHTML =
    '<span><strong>' + (profile.cookies || []).length + '</strong> cookies</span>' +
    '<span><strong>' + (profile.localStorage || []).length + '</strong> LS</span>' +
    '<span><strong>' + (profile.sessionStorage || []).length + '</strong> SS</span>' +
    '<span><strong>' + (profile.authHeaders || []).length + '</strong> headers</span>';
  main.appendChild(stats);

  if (profile.updatedAt) {
    const meta = document.createElement('div');
    meta.className = 'prof-card-meta';
    meta.textContent = 'Updated ' + new Date(profile.updatedAt).toLocaleString();
    main.appendChild(meta);
  }

  const actions = document.createElement('div');
  actions.className = 'prof-card-actions';

  const applyBtn = document.createElement('button');
  applyBtn.className = 'btn primary';
  applyBtn.textContent = 'Apply…';
  applyBtn.addEventListener('click', () => openProfileModal(id, 'apply'));
  actions.appendChild(applyBtn);

  const editBtn = document.createElement('button');
  editBtn.className = 'btn ghost';
  editBtn.textContent = 'Edit';
  editBtn.addEventListener('click', () => openProfileModal(id, 'edit'));
  actions.appendChild(editBtn);

  const exportBtn = document.createElement('button');
  exportBtn.className = 'btn ghost';
  exportBtn.textContent = 'Export';
  exportBtn.addEventListener('click', () => openProfileModal(id, 'export'));
  actions.appendChild(exportBtn);

  const delBtn = document.createElement('button');
  delBtn.className = 'btn danger';
  delBtn.textContent = 'Delete';
  delBtn.addEventListener('click', async () => {
    if (!confirm(`Delete profile "${profile.name || id}"?`)) return;
    try {
      await profilesApi.delete(id);
      await refreshProfiles();
      toast('Deleted', 'success');
    } catch (err) {
      toast('Delete failed: ' + err.message, 'error');
    }
  });
  actions.appendChild(delBtn);

  card.appendChild(main);
  card.appendChild(actions);
  return card;
}

async function openProfileModal(id, initialTab = 'apply') {
  activeProfile = { id, ...profilesCache[id] };
  $('#prof-modal-title').textContent = activeProfile.name || id;
  switchModalTab(initialTab);

  // Pre-fill Apply panel with the current active tab
  try {
    const tab = await tabs.current();
    if (tab?.url) {
      $('#apply-target-url').value = tab.url;
      $('#apply-target-host').value = safeHost(tab.url);
    }
  } catch {
    /* ignore */
  }
  $('#apply-source-host').value = activeProfile.sourceDomain || '';
  const targetHost = $('#apply-target-host').value;
  $('#apply-remap').checked = !!(
    targetHost &&
    activeProfile.sourceDomain &&
    targetHost !== activeProfile.sourceDomain
  );
  $('#apply-clear-first').checked = false;
  $('#apply-include-storage').checked = true;
  $('#apply-result').textContent = '';
  $('#apply-result').className = 'apply-result';

  // Pre-fill Edit panel
  $('#edit-name').value = activeProfile.name || '';
  $('#edit-description').value = activeProfile.description || '';
  $('#edit-source-url').value = activeProfile.sourceUrl || '';
  $('#edit-notes').value = activeProfile.notes || '';
  $('#edit-raw').value = JSON.stringify(activeProfile, null, 2);

  // Pre-fill Export panel
  $('#export-target-url').value = activeProfile.sourceUrl || '';
  $('#export-format').value = 'curl';
  refreshExportPreview();

  $('#prof-modal').classList.remove('hidden');
}

function closeProfileModal() {
  $('#prof-modal').classList.add('hidden');
  activeProfile = null;
}

function switchModalTab(name) {
  activeModalTab = name;
  $$('#prof-modal .modal-tab').forEach((t) =>
    t.classList.toggle('active', t.dataset.modalTab === name)
  );
  $$('#prof-modal .modal-panel').forEach((p) =>
    p.classList.toggle('hidden', p.dataset.modalPanel !== name)
  );
  if (name === 'export') refreshExportPreview();
}

async function performApply() {
  if (!activeProfile) return;
  const targetUrl = $('#apply-target-url').value.trim();
  if (!targetUrl) {
    showApplyResult('Target URL is required.', 'err');
    return;
  }
  let targetTab;
  try {
    targetTab = await tabs.current();
  } catch {
    /* may be undefined */
  }

  showApplyResult('Applying…', '');

  try {
    const report = await profilesApi.apply({
      profile: activeProfile,
      tabId: targetTab?.id,
      targetUrl,
      remapDomain: $('#apply-remap').checked,
      sourceHost: $('#apply-source-host').value.trim() || undefined,
      clearFirst: $('#apply-clear-first').checked,
      includeStorage: $('#apply-include-storage').checked,
    });

    const lines = [];
    if (report.cleared) lines.push('• Cleared previous state');
    lines.push(`• Cookies applied: ${report.cookiesApplied}`);
    if (report.cookiesFailed.length) {
      lines.push(`• Cookies failed: ${report.cookiesFailed.length}`);
      for (const f of report.cookiesFailed.slice(0, 5)) {
        lines.push(`    - ${f.name}: ${f.reason}`);
      }
      if (report.cookiesFailed.length > 5) {
        lines.push(`    … and ${report.cookiesFailed.length - 5} more`);
      }
    }
    lines.push(`• localStorage entries: ${report.lsApplied}`);
    lines.push(`• sessionStorage entries: ${report.ssApplied}`);

    const ok = report.cookiesFailed.length === 0;
    showApplyResult(lines.join('\n'), ok ? 'ok' : 'err');
    toast(
      ok
        ? `Applied to ${safeHost(targetUrl)}`
        : `Applied with ${report.cookiesFailed.length} cookie failure(s)`,
      ok ? 'success' : 'error'
    );
  } catch (err) {
    showApplyResult('Apply failed: ' + err.message, 'err');
    toast('Apply failed: ' + err.message, 'error');
  }
}

function showApplyResult(text, tone) {
  const el = $('#apply-result');
  el.textContent = text;
  el.className = 'apply-result' + (tone ? ' ' + tone : '');
}

async function saveProfileEdits() {
  if (!activeProfile) return;
  // Prefer the raw JSON if the user actually edited it; otherwise rebuild
  // from the named fields and reuse the rest of the profile.
  let next;
  const rawText = $('#edit-raw').value;
  let rawParsed = null;
  try {
    rawParsed = JSON.parse(rawText);
  } catch {
    /* fall through */
  }

  if (rawParsed && typeof rawParsed === 'object') {
    next = stripIdMeta({
      ...rawParsed,
      name: $('#edit-name').value || rawParsed.name,
      description: $('#edit-description').value,
      sourceUrl: $('#edit-source-url').value,
      sourceDomain: safeHost($('#edit-source-url').value) || rawParsed.sourceDomain,
      notes: $('#edit-notes').value,
    });
  } else {
    next = {
      ...activeProfile,
      name: $('#edit-name').value,
      description: $('#edit-description').value,
      sourceUrl: $('#edit-source-url').value,
      sourceDomain: safeHost($('#edit-source-url').value) || activeProfile.sourceDomain,
      notes: $('#edit-notes').value,
    };
    delete next.id;
    delete next.createdAt;
    delete next.updatedAt;
  }

  try {
    await profilesApi.save(activeProfile.id, next);
    await refreshProfiles();
    toast('Saved', 'success');
    closeProfileModal();
  } catch (err) {
    toast('Save failed: ' + err.message, 'error');
  }
}

function refreshExportPreview() {
  if (!activeProfile) return;
  const fmtId = $('#export-format').value;
  const targetUrl = $('#export-target-url').value.trim() || activeProfile.sourceUrl;
  const help = {
    'json':
      'Round-trip-safe. Re-importable here.',
    'curl':
      'A curl command with Cookie + auth headers preset. Edit the method/URL as needed.',
    'postman-env':
      'Postman environment JSON. Import via Postman → Environments → Import.',
    'httpie-session':
      'HTTPie session file. Replay with: http --session=path.json …',
    'dotenv':
      'A .env file. Source it in CI or test runners (e.g. dotenv-cli).',
  };
  $('#export-format-help').textContent = help[fmtId] || '';
  try {
    $('#export-preview').value = exportProfile(activeProfile, fmtId, { targetUrl });
  } catch (err) {
    $('#export-preview').value = '# Export failed: ' + err.message;
  }
}

// ---------- Profile utilities ------------------------------------------------

function guessProfileNameFromUrl(url) {
  const host = safeHost(url);
  if (!host) return '';
  // strip common www., return host
  return host.replace(/^www\./, '');
}

function safeHost(url) {
  if (!url) return '';
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function stripIdMeta(obj) {
  const { id, createdAt, updatedAt, ...rest } = obj || {};
  return rest;
}

// ============================================================================
// Advanced settings — power-user knobs
// ============================================================================

function arrToText(arr) { return Array.isArray(arr) ? arr.join('\n') : ''; }
function textToArr(s) {
  return String(s || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

function bindAdvancedTab() {
  // Reflect current settings into the controls
  populateAdvancedFields();

  // UI
  bindAdvSwitch('opt-hide-empty-tabs', 'hideEmptyStorageTabs');
  bindAdvSwitch('opt-compact', 'compactMode');

  // Detection — arrays of strings (one per line)
  bindAdvTextarea('opt-refresh-patterns', 'customRefreshTokenPatterns', true);
  bindAdvTextarea('opt-auth-headers', 'customAuthHeaderNames', true);
  bindAdvTextarea('opt-endpoint-patterns', 'customTokenEndpointPatterns', true);
  bindAdvTextarea('opt-field-names', 'customTokenFieldNames', true);

  // Network
  bindAdvSwitch('opt-auto-record', 'autoStartNetworkCapture');
  bindAdvNumber('opt-buffer-size', 'networkBufferSize', { min: 50, max: 5000 });
  bindAdvSwitch('opt-persist-captures', 'persistNetworkCaptures');

  // Security
  bindAdvTextarea('opt-jwt-wordlist', 'customHmacWordlist', false);
  bindAdvNumber('opt-brute-max', 'jwtBruteMaxAttempts', { min: 50, max: 50000 });

  // Data management
  $('#btn-clear-network').addEventListener('click', clearNetworkCaptures);
  $('#btn-clear-snapshots').addEventListener('click', clearAllSnapshots);
  $('#btn-clear-profiles').addEventListener('click', clearAllProfiles);
  $('#btn-export-all').addEventListener('click', exportEverything);
  $('#opt-import-all').addEventListener('change', importEverything);
}

function populateAdvancedFields() {
  $('#opt-hide-empty-tabs').checked = currentSettings.hideEmptyStorageTabs !== false;
  $('#opt-compact').checked = !!currentSettings.compactMode;
  $('#opt-refresh-patterns').value = arrToText(currentSettings.customRefreshTokenPatterns);
  $('#opt-auth-headers').value = arrToText(currentSettings.customAuthHeaderNames);
  $('#opt-endpoint-patterns').value = arrToText(currentSettings.customTokenEndpointPatterns);
  $('#opt-field-names').value = arrToText(currentSettings.customTokenFieldNames);
  $('#opt-auto-record').checked = currentSettings.autoStartNetworkCapture !== false;
  $('#opt-buffer-size').value = currentSettings.networkBufferSize || 500;
  $('#opt-persist-captures').checked = !!currentSettings.persistNetworkCaptures;
  $('#opt-jwt-wordlist').value = currentSettings.customHmacWordlist || '';
  $('#opt-brute-max').value = currentSettings.jwtBruteMaxAttempts || 1000;
}

function bindAdvSwitch(elementId, settingKey) {
  $('#' + elementId).addEventListener('change', (e) => {
    saveSettings({ [settingKey]: e.target.checked });
    showAdvStatus('Saved');
  });
}

function bindAdvNumber(elementId, settingKey, { min, max }) {
  $('#' + elementId).addEventListener('change', (e) => {
    let v = parseInt(e.target.value, 10);
    if (isNaN(v)) v = currentSettings[settingKey];
    v = Math.max(min, Math.min(max, v));
    e.target.value = v;
    saveSettings({ [settingKey]: v });
    showAdvStatus('Saved');
  });
}

function bindAdvTextarea(elementId, settingKey, asArray) {
  let timer = null;
  $('#' + elementId).addEventListener('input', (e) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      const value = asArray ? textToArr(e.target.value) : e.target.value;
      saveSettings({ [settingKey]: value });
      showAdvStatus('Saved');
    }, 500);
  });
}

function showAdvStatus(text, tone = 'ok') {
  const el = $('#advanced-save-status');
  el.textContent = text;
  el.className = 'advanced-save-status shown ' + tone;
  clearTimeout(showAdvStatus._t);
  showAdvStatus._t = setTimeout(() => {
    el.className = 'advanced-save-status';
  }, 1500);
}

async function clearNetworkCaptures() {
  if (!confirm('Clear every captured network entry? This cannot be undone.')) return;
  try {
    // Use the networkApi indirectly via the registered SW handler
    await chrome.runtime.sendMessage({ type: 'network.clear' });
    toast('Network captures cleared', 'success');
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
}

async function clearAllSnapshots() {
  if (!confirm('Delete EVERY saved snapshot? This cannot be undone.')) return;
  try {
    snapshotsCache = (await snapshotsApi.list()) || {};
    for (const id of Object.keys(snapshotsCache)) {
      await snapshotsApi.delete(id);
    }
    await refreshSnapshots();
    toast('All snapshots deleted', 'success');
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
}

async function clearAllProfiles() {
  if (!confirm('Delete EVERY saved profile? This cannot be undone.')) return;
  try {
    const profiles = (await profilesApi.list()) || {};
    for (const id of Object.keys(profiles)) {
      await profilesApi.delete(id);
    }
    await refreshProfiles();
    toast('All profiles deleted', 'success');
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
}

async function exportEverything() {
  try {
    const [settings, profiles, snapshots] = await Promise.all([
      settingsApi.get(),
      profilesApi.list(),
      snapshotsApi.list(),
    ]);
    const bundle = {
      __format__: 'authforge-export',
      __version__: 1,
      exportedAt: new Date().toISOString(),
      settings: settings || {},
      profiles: profiles || {},
      snapshots: snapshots || {},
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    downloadBlob(blob, 'authforge-export-' + new Date().toISOString().slice(0, 10) + '.json');
    toast('Export downloaded', 'success');
  } catch (err) {
    toast('Export failed: ' + err.message, 'error');
  }
}

async function importEverything(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const bundle = JSON.parse(text);
    if (bundle.__format__ !== 'authforge-export') {
      throw new Error('Not a AuthForge export file');
    }
    if (!confirm(
      `Import this bundle?\n\n` +
      `• Settings: ${bundle.settings ? 'yes' : 'no'}\n` +
      `• Profiles: ${Object.keys(bundle.profiles || {}).length}\n` +
      `• Snapshots: ${Object.keys(bundle.snapshots || {}).length}\n\n` +
      `Existing items with the same id will be overwritten.`
    )) return;

    if (bundle.settings) {
      await settingsApi.set({ ...DEFAULT_SETTINGS, ...bundle.settings });
    }
    if (bundle.profiles) {
      for (const [id, p] of Object.entries(bundle.profiles)) {
        await profilesApi.save(id, p);
      }
    }
    if (bundle.snapshots) {
      for (const [id, s] of Object.entries(bundle.snapshots)) {
        await snapshotsApi.save(id, s);
      }
    }
    await loadSettings();
    populateAdvancedFields();
    await refreshSnapshots();
    await refreshProfiles();
    applyTheme();
    toast('Import complete', 'success');
  } catch (err) {
    toast('Import failed: ' + err.message, 'error');
  } finally {
    e.target.value = '';
  }
}

// ============================================================================
// Utilities
// ============================================================================

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function toast(message, tone = '') {
  const stack = $('#toast-stack');
  const el = document.createElement('div');
  // Theme uses .toast.err / .toast.ok / .toast.warn
  const toneClass =
    tone === 'error' ? 'err' : tone === 'success' ? 'ok' : tone;
  el.className = 'toast' + (toneClass ? ' ' + toneClass : '');
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => {
    el.style.transition = 'opacity 0.22s ease, transform 0.22s ease';
    el.style.opacity = '0';
    el.style.transform = 'translateY(-4px)';
    setTimeout(() => el.remove(), 240);
  }, 2400);
}
