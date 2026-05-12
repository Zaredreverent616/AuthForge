/**
 * AuthForge — Main UI module (shared/ui.js)
 *
 * This is the editor itself: a tabbed interface over cookies, localStorage,
 * sessionStorage, IndexedDB, and the JWT decoder. It's loaded by both the
 * popup and the devtools panel — the only thing those surfaces do is
 * mount this and pass us a config object.
 *
 * Style of code: explicit, imperative DOM construction (no framework). The
 * UI is small enough that a framework would be more weight than value, and
 * staying framework-free means zero build step.
 */

import {
  tabs as tabsApi,
  cookies as cookiesApi,
  localStorageApi,
  sessionStorageApi,
  indexedDBApi,
  snapshotsApi,
  settingsApi,
  networkApi,
  debuggerApi,
  replayApi,
  entraApi,
  subscribe,
} from './api.js';
import {
  looksLikeJWT,
  decodeJWT,
  encodeJWT,
  summarizeJWT,
  looksLikeRefreshTokenKey,
  looksLikeAuthArtifactKey,
  classifyAuthArtifact,
  generateAttackVariants,
  tryHmacSecrets,
  DEFAULT_HMAC_SECRETS,
} from './jwt.js';
import { auditCookies, auditStorage, auditNetwork, auditEntraToken } from './audit.js';
import {
  isEntraToken,
  analyzeEntraToken,
  RECON_ENDPOINTS,
  reconEndpointsForToken,
  AUDIENCE_CONFUSION_TARGETS,
  FOCI_CLIENTS,
  isLikelyFOCIClient,
} from './entra.js';
import { Json, Netscape, HeaderLine, Curl, StorageJson } from './formats.js';
import { HistoryStore } from './history.js';
import { t } from './i18n.js';

// ---------- Constants ---------------------------------------------------------

// Tab definitions. The `label` field is the English fallback; `i18nKey`
// points at the messages.json key so the renderer can resolve the
// localised label at call time via t(key, fallback).
const TABS = [
  { id: 'cookies', i18nKey: 'tabCookies', label: 'Cookies' },
  { id: 'localStorage', i18nKey: 'tabLocalStorage', label: 'Local' },
  { id: 'sessionStorage', i18nKey: 'tabSessionStorage', label: 'Session' },
  { id: 'indexedDB', i18nKey: 'tabIndexedDB', label: 'IDB' },
  { id: 'tokens', i18nKey: 'tabTokens', label: 'Tokens' },
  { id: 'network', i18nKey: 'tabNetwork', label: 'Network' },
  { id: 'audit', i18nKey: 'tabAudit', label: 'Audit' },
  { id: 'snapshots', i18nKey: 'tabSnapshots', label: 'Snapshots' },
];

// ---------- Tiny DOM helpers (zero-dep) --------------------------------------

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') {
      el.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (k === 'dataset') {
      Object.assign(el.dataset, v);
    } else if (k in el) {
      el[k] = v;
    } else {
      el.setAttribute(k, v);
    }
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
}

// ---------- Toast notifications ----------------------------------------------

function truncate(s, n = 80) {
  if (typeof s !== 'string') return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function safeHostFromOrigin(origin) {
  if (!origin) return '';
  try {
    return new URL(origin).hostname;
  } catch {
    // Origin might already be just a hostname or a malformed string
    return String(origin).replace(/^https?:\/\//, '').split('/')[0];
  }
}

function groupBy(arr, key) {
  const out = {};
  for (const item of arr || []) {
    const k = item[key] || '(unknown)';
    if (!out[k]) out[k] = [];
    out[k].push(item);
  }
  return out;
}

/**
 * Recursively scan a value (object / array / string) for an embedded JWT.
 * Returns { token, path } or null. Path is a JSONPath-ish string like
 * "$.secret" or "$.items[2].access_token". Used by the IDB record editor
 * to surface MSAL-cache-style entries where the token sits at a known key.
 */
function scanValueForJwt(value, path = '$') {
  if (value == null) return null;
  if (typeof value === 'string') {
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(value) && value.length > 20) {
      try {
        const header = JSON.parse(atob(value.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')));
        if (header && (header.alg || header.typ)) {
          return { token: value, path };
        }
      } catch {}
    }
    return null;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const r = scanValueForJwt(value[i], `${path}[${i}]`);
      if (r) return r;
    }
    return null;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      const r = scanValueForJwt(v, `${path}.${k}`);
      if (r) return r;
    }
    return null;
  }
  return null;
}

/**
 * Set a value at a JSONPath-ish path produced by scanValueForJwt. Returns
 * a deep clone with the patch applied (original is not mutated).
 */
function patchAtPath(root, path, newValue) {
  let copy;
  try { copy = structuredClone(root); }
  catch { copy = JSON.parse(JSON.stringify(root)); }

  const segments = parsePath(path);
  if (segments.length === 0) return newValue;
  let cur = copy;
  for (let i = 0; i < segments.length - 1; i++) {
    cur = cur[segments[i]];
  }
  cur[segments[segments.length - 1]] = newValue;
  return copy;
}

function parsePath(path) {
  if (!path || path === '$') return [];
  const cleaned = path.replace(/^\$\.?/, '');
  const parts = [];
  for (const seg of cleaned.split(/(?=\[)|\./).filter(Boolean)) {
    const m = seg.match(/^\[(\d+)\]$/);
    if (m) parts.push(Number(m[1]));
    else parts.push(seg);
  }
  return parts;
}

/**
 * Parse a curl command into { method, url, headers, body }. Tolerant —
 * handles continuations, -H / --header, -d / --data, -X / --request, -b
 * cookies, --data-raw, --data-binary. Used by the request-workbench
 * "Import curl…" feature so users can paste from Chrome DevTools' "Copy
 * as cURL" and re-fire after editing.
 */
function parseCurl(text) {
  // Strip backslash-newline line continuations and normalise whitespace
  let s = text.replace(/\\\s*\n\s*/g, ' ').trim();
  // Strip leading 'curl '
  s = s.replace(/^curl\s+/i, '');

  const tokens = [];
  let i = 0;
  while (i < s.length) {
    // Skip whitespace
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    const ch = s[i];
    if (ch === "'" || ch === '"') {
      const quote = ch;
      i++;
      let v = '';
      while (i < s.length && s[i] !== quote) {
        if (s[i] === '\\' && i + 1 < s.length) {
          v += s[i + 1]; i += 2;
        } else {
          v += s[i]; i++;
        }
      }
      i++; // skip closing quote
      tokens.push(v);
    } else {
      let j = i;
      while (j < s.length && !/\s/.test(s[j])) j++;
      tokens.push(s.slice(i, j));
      i = j;
    }
  }

  const out = { method: 'GET', url: '', headers: [], body: '' };
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (t === '-X' || t === '--request') {
      out.method = (tokens[++k] || 'GET').toUpperCase();
    } else if (t === '-H' || t === '--header') {
      const h2 = tokens[++k] || '';
      const idx = h2.indexOf(':');
      if (idx > 0) {
        out.headers.push([h2.slice(0, idx).trim(), h2.slice(idx + 1).trim()]);
      }
    } else if (t === '-d' || t === '--data' || t === '--data-raw' || t === '--data-binary' || t === '--data-urlencode') {
      out.body = tokens[++k] || '';
      if (out.method === 'GET') out.method = 'POST';
    } else if (t === '-b' || t === '--cookie') {
      out.headers.push(['Cookie', tokens[++k] || '']);
    } else if (t === '-u' || t === '--user') {
      const cred = tokens[++k] || '';
      out.headers.push(['Authorization', 'Basic ' + btoa(cred)]);
    } else if (t === '-A' || t === '--user-agent') {
      out.headers.push(['User-Agent', tokens[++k] || '']);
    } else if (t === '-e' || t === '--referer' || t === '--referrer') {
      out.headers.push(['Referer', tokens[++k] || '']);
    } else if (t.startsWith('--')) {
      // unknown long option — skip its arg if present
      if (k + 1 < tokens.length && !tokens[k + 1].startsWith('-')) k++;
    } else if (t.startsWith('-')) {
      // unknown short option — skip its arg
      if (k + 1 < tokens.length && !tokens[k + 1].startsWith('-')) k++;
    } else if (!out.url) {
      out.url = t;
    }
  }
  if (!out.url) throw new Error('Could not find URL in curl command');
  return out;
}

function toast(message, kind = 'ok', timeout = 2500) {
  let stack = document.querySelector('.toast-stack');
  if (!stack) {
    stack = h('div', { class: 'toast-stack' });
    document.body.appendChild(stack);
  }
  const node = h('div', { class: 'toast ' + kind }, message);
  stack.appendChild(node);
  setTimeout(() => {
    node.style.opacity = '0';
    node.style.transition = 'opacity 0.15s';
    setTimeout(() => node.remove(), 200);
  }, timeout);
}

// ---------- Confirm modal ----------------------------------------------------

function confirmModal(title, body, { okLabel = 'OK', danger = false } = {}) {
  return new Promise((resolve) => {
    const close = (result) => {
      backdrop.remove();
      document.removeEventListener('keydown', onKey);
      resolve(result);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') close(false);
      if (e.key === 'Enter') close(true);
    };
    const backdrop = h(
      'div',
      { class: 'modal-backdrop', onClick: (e) => e.target === backdrop && close(false) },
      h(
        'div',
        { class: 'modal' },
        h(
          'header',
          {},
          h('h2', {}, title),
          h('button', { class: 'btn ghost icon', onClick: () => close(false) }, '✕')
        ),
        h('div', { class: 'body' }, body),
        h(
          'footer',
          {},
          h('button', { class: 'btn', onClick: () => close(false) }, 'Cancel'),
          h(
            'button',
            { class: 'btn ' + (danger ? 'danger' : 'primary'), onClick: () => close(true) },
            okLabel
          )
        )
      )
    );
    document.body.appendChild(backdrop);
    document.addEventListener('keydown', onKey);
  });
}

// ---------- Main app class ---------------------------------------------------

export class AuthForgeApp {
  /**
   * @param {HTMLElement} root  The container element to mount into.
   * @param {object} [opts]
   * @param {string} [opts.surface]  "popup" | "devtools" — adjusts layout.
   * @param {number} [opts.tabId]   Override target tab (devtools knows its inspected tab).
   */
  constructor(root, opts = {}) {
    this.root = root;
    this.surface = opts.surface || 'popup';
    this.forcedTabId = opts.tabId || null;

    // Mutable state
    this.currentTab = null;       // chrome.tabs.Tab for the page we operate on
    this.activeStorageTab = 'cookies';
    this.searchTerm = '';
    this.cookies = [];
    this.localStorage = [];
    this.sessionStorage = [];
    this.indexedDB = { databases: [], openDb: null }; // openDb: {name, stores}
    this.snapshots = {};
    this.expandedRowId = null;
    this.history = new HistoryStore(50);
    this.settings = {
      theme: 'auto',
      showExpired: true,
      // Advanced — UI
      hideEmptyStorageTabs: true,
      compactMode: false,
      // Advanced — detection (regex patterns user-supplied; merged with defaults)
      customRefreshTokenPatterns: [],
      customAuthHeaderNames: [],
      customTokenEndpointPatterns: [],
      customTokenFieldNames: [],
      // Advanced — network capture
      networkBufferSize: 500,
      autoStartNetworkCapture: true,
      persistNetworkCaptures: false,
      // Advanced — security testing
      customHmacWordlist: '',
      jwtBruteMaxAttempts: 1000,
    };

    // Cookie scope: which set of cookies the user is browsing.
    //   'currentTab'  — cookies for the active tab's URL (default)
    //   'allDomains'  — every cookie in the browser, grouped by domain
    //   'customUrl'   — cookies scoped to a user-pasted URL
    this.cookieScope = { mode: 'currentTab', customUrl: '' };

    // Network capture state
    this.networkEntries = [];
    this.networkRecording = false;
    this.networkAuthOnly = true;
    this.networkScopeToTab = false;
    this.networkHostFilter = '';
    this.debuggerAttachedTabs = []; // tabIds currently under CDP deep capture

    // DOM refs
    this.refs = {};
  }

  async mount() {
    await this.loadSettings();
    this.applyTheme();
    this.buildShell();
    this.bindKeyboard();
    this.bindLiveUpdates();
    await this.refreshCurrentTab();
    // The undo state changes -> re-render the toolbar buttons.
    this.history.onChange(() => this.renderToolbar());
  }

  // ---------- Settings & theme ------------------------------------------------

  async loadSettings() {
    try {
      this.settings = { ...this.settings, ...(await settingsApi.get()) };
    } catch (e) {
      console.warn('settings.get failed', e);
    }
  }

  applyTheme() {
    const desired =
      this.settings.theme === 'auto'
        ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
        : this.settings.theme;
    document.documentElement.dataset.theme = desired;
  }

  // ---------- Shell -----------------------------------------------------------

  buildShell() {
    clear(this.root);

    const searchBar = h(
      'div',
      { class: 'search-bar' },
      h('input', {
        class: 'input',
        placeholder: 'Search keys & values…  (⌘/Ctrl+F)',
        oninput: (e) => {
          this.searchTerm = e.target.value.trim().toLowerCase();
          this.renderActiveTab();
        },
      }),
      this.buildScopePicker()
    );

    const tabBar = h(
      'div',
      { class: 'tabs', role: 'tablist' },
      ...TABS.map((tab) =>
        h(
          'button',
          {
            class: 'tab',
            role: 'tab',
            'aria-selected': String(this.activeStorageTab === tab.id),
            dataset: { tab: tab.id },
            onClick: () => {
              this.activeStorageTab = tab.id;
              this.renderTabBar();
              this.renderActiveTab();
            },
          },
          t(tab.i18nKey, tab.label),
          h('span', { class: 'count', dataset: { count: tab.id } }, '0')
        )
      )
    );
    this.refs.tabBar = tabBar;

    const toolbar = h('div', { class: 'toolbar' });
    this.refs.toolbar = toolbar;

    const body = h('div', { class: 'tab-body' });
    this.refs.body = body;

    this.refs.searchInput = searchBar.querySelector('input');

    this.root.appendChild(searchBar);
    this.root.appendChild(tabBar);
    this.root.appendChild(toolbar);
    this.root.appendChild(body);

    this.renderToolbar();
  }

  /**
   * Build the scope picker that sits in the top bar. Lets the user choose
   * between "current tab", "all cookies" (the whole browser), or a custom
   * URL — so cookies for any site can be inspected without navigating.
   *
   * LS / sessionStorage / IndexedDB remain tab-scoped (browser security
   * requires page injection) — those tabs show a friendly hint when the
   * scope isn't "current tab".
   */
  buildScopePicker() {
    const wrap = h('div', { class: 'scope-picker' });

    const select = h('select', {
      class: 'scope-select',
      title:
        'Choose the browsing scope. Applies to every storage tab — Cookies, ' +
        'Local, Session, and IndexedDB.',
      onChange: async (e) => {
        const v = e.target.value;
        if (v === 'allDomains') {
          this.cookieScope = { mode: 'allDomains', customUrl: '' };
        } else if (v === 'customUrl') {
          this.cookieScope = { mode: 'customUrl', customUrl: this.cookieScope.customUrl };
        } else {
          this.cookieScope = { mode: 'currentTab', customUrl: '' };
        }
        this.updateScopePicker();
        if (this.cookieScope.mode === 'customUrl' && !this.cookieScope.customUrl) {
          this.refs.scopeUrlInput?.focus();
          return;
        }
        // Reload EVERY store appropriate to the new scope. Previously we only
        // reloaded cookies on scope change, which made LS/SS/IDB tabs look
        // stale or empty when the user switched to "All sites".
        await this.reloadForScope();
        this.updateTabCounts();
        this.renderActiveTab();
      },
    });
    select.appendChild(h('option', { value: 'currentTab' }, t('scopeCurrentTab', '📍 Current tab')));
    select.appendChild(
      h('option', { value: 'allDomains' }, t('scopeAllDomains', '🌐 All open tabs (cookies + storage)'))
    );
    select.appendChild(h('option', { value: 'customUrl' }, t('scopeCustomUrl', '🔗 Custom URL…')));
    this.refs.scopeSelect = select;
    wrap.appendChild(select);

    // Inline URL entry — shown when mode === 'customUrl'
    const urlInput = h('input', {
      class: 'input scope-url-input hidden',
      type: 'url',
      placeholder: 'https://example.com',
      onChange: async (e) => {
        this.cookieScope.customUrl = e.target.value.trim();
        await this.reloadForScope();
        this.updateTabCounts();
        this.renderActiveTab();
      },
      onKeydown: (e) => {
        if (e.key === 'Enter') e.target.blur();
      },
    });
    this.refs.scopeUrlInput = urlInput;
    wrap.appendChild(urlInput);

    // Label that summarises the current scope at a glance
    const label = h('div', { class: 'scope-label' }, '');
    this.refs.scopeLabel = label;
    wrap.appendChild(label);

    return wrap;
  }

  /** Refresh visible scope-picker controls to reflect current state. */
  updateScopePicker() {
    if (!this.refs.scopeSelect) return;
    this.refs.scopeSelect.value = this.cookieScope.mode;
    if (this.refs.scopeUrlInput) {
      this.refs.scopeUrlInput.classList.toggle(
        'hidden',
        this.cookieScope.mode !== 'customUrl'
      );
      if (this.cookieScope.mode === 'customUrl') {
        this.refs.scopeUrlInput.value = this.cookieScope.customUrl;
      }
    }
    if (this.refs.scopeLabel) {
      this.refs.scopeLabel.textContent = this.describeScope();
      this.refs.scopeLabel.dataset.mode = this.cookieScope.mode;
    }
  }

  describeScope() {
    if (this.cookieScope.mode === 'allDomains') {
      return 'browser-wide';
    }
    if (this.cookieScope.mode === 'customUrl') {
      try {
        return this.cookieScope.customUrl
          ? new URL(this.cookieScope.customUrl).hostname
          : '(enter url)';
      } catch {
        return '(invalid url)';
      }
    }
    if (this.currentTab?.url) {
      try {
        return new URL(this.currentTab.url).hostname;
      } catch {
        return this.currentTab.url;
      }
    }
    return '(no tab)';
  }

  /**
   * Reload every store appropriate for the *current* scope. Called whenever
   * the user changes the scope picker — we used to only reload cookies here,
   * which made it look like "All sites" didn't apply to Local Storage / IDB.
   */
  async reloadForScope() {
    if (this.cookieScope.mode === 'allDomains') {
      await Promise.all([
        this.loadCookies(),
        this.loadLocalStorage(),
        this.loadSessionStorage(),
        this.loadIndexedDBList(),
      ]);
    } else if (this.cookieScope.mode === 'customUrl') {
      await this.loadCookies(); // LS/SS/IDB need an actual tab — not loadable
    } else {
      await Promise.all([
        this.loadCookies(),
        this.loadLocalStorage(),
        this.loadSessionStorage(),
        this.loadIndexedDBList(),
      ]);
    }
  }


  renderTabBar() {
    for (const tab of this.refs.tabBar.querySelectorAll('.tab')) {
      tab.setAttribute(
        'aria-selected',
        String(tab.dataset.tab === this.activeStorageTab)
      );
    }
  }

  renderToolbar() {
    clear(this.refs.toolbar);
    const t = this.refs.toolbar;
    const isStorageTab =
      this.activeStorageTab === 'cookies' ||
      this.activeStorageTab === 'localStorage' ||
      this.activeStorageTab === 'sessionStorage';

    if (isStorageTab) {
      const inBrowseAll = this.cookieScope.mode === 'allDomains';
      t.appendChild(
        h(
          'button',
          {
            class: 'btn primary',
            disabled: inBrowseAll,
            title: inBrowseAll
              ? 'Switch to a single tab/domain to add new entries'
              : 'Create a new entry',
            onClick: () => this.openNewItemEditor(),
          },
          '+ New'
        )
      );
      t.appendChild(
        h(
          'button',
          {
            class: 'btn danger',
            disabled: inBrowseAll,
            title: inBrowseAll
              ? 'Switch to a single tab/domain to bulk-delete'
              : 'Delete every entry on this tab',
            onClick: () => this.deleteAllInActiveTab(),
          },
          'Delete all'
        )
      );
      t.appendChild(
        h(
          'button',
          { class: 'btn', onClick: () => this.openImportModal() },
          'Import'
        )
      );
      t.appendChild(
        h(
          'button',
          { class: 'btn', onClick: () => this.openExportModal() },
          'Export'
        )
      );
    }
    if (this.activeStorageTab === 'cookies') {
      t.appendChild(
        h(
          'button',
          { class: 'btn', onClick: () => this.copyCurrentAsHeader() },
          'Copy as header'
        )
      );
    }

    t.appendChild(h('div', { class: 'spacer' }));

    if (isStorageTab) {
      t.appendChild(
        h(
          'button',
          {
            class: 'btn',
            disabled: !this.history.canUndo(),
            title: 'Undo (⌘/Ctrl+Z)',
            onClick: () => this.undo(),
          },
          '↶ Undo'
        )
      );
      t.appendChild(
        h(
          'button',
          {
            class: 'btn',
            disabled: !this.history.canRedo(),
            title: 'Redo (⌘/Ctrl+⇧+Z)',
            onClick: () => this.redo(),
          },
          '↷ Redo'
        )
      );
    }
    t.appendChild(
      h(
        'button',
        {
          class: 'btn ghost icon',
          title: 'Refresh (R)',
          onClick: () => this.refreshActiveTab(),
        },
        '↻'
      )
    );
    t.appendChild(
      h(
        'button',
        {
          class: 'btn ghost icon',
          title: 'Toggle theme',
          onClick: () => this.toggleTheme(),
        },
        '◐'
      )
    );
  }

  bindKeyboard() {
    document.addEventListener('keydown', (e) => {
      const cmd = e.metaKey || e.ctrlKey;
      if (cmd && e.key === 'f') {
        e.preventDefault();
        this.refs.searchInput.focus();
        this.refs.searchInput.select();
      } else if (cmd && e.key.toLowerCase() === 'z' && !e.shiftKey) {
        e.preventDefault();
        this.undo();
      } else if (cmd && e.key.toLowerCase() === 'z' && e.shiftKey) {
        e.preventDefault();
        this.redo();
      } else if (e.key === 'r' && !cmd && document.activeElement === document.body) {
        this.refreshActiveTab();
      }
    });
  }

  bindLiveUpdates() {
    this.unsubscribe = subscribe((msg) => {
      if (msg.type === 'cookiesChanged' && this.activeStorageTab === 'cookies') {
        // Throttled refresh — multiple changes in one tick collapse into one.
        if (this._cookieRefreshScheduled) return;
        this._cookieRefreshScheduled = true;
        setTimeout(() => {
          this._cookieRefreshScheduled = false;
          this.loadCookies().then(() => this.renderActiveTab());
        }, 100);
      }
      if (msg.type === 'networkEntryAdded' || msg.type === 'networkBufferCleared'
          || msg.type === 'networkStatusChanged') {
        // Same throttle pattern — webRequest events can flood
        if (this._networkRefreshScheduled) return;
        this._networkRefreshScheduled = true;
        setTimeout(() => {
          this._networkRefreshScheduled = false;
          this.loadNetwork().then(() => {
            this.updateTabCounts();
            if (this.activeStorageTab === 'network') this.renderActiveTab();
          });
        }, 300);
      }
      if (msg.type === 'debuggerAttached' || msg.type === 'debuggerDetached'
          || msg.type === 'debuggerDetachedAll') {
        // Re-fetch status promptly so the toggle reflects reality
        this.loadNetwork().then(() => {
          if (this.activeStorageTab === 'network') this.renderActiveTab();
        });
        if (msg.type === 'debuggerDetached' && msg.reason && msg.reason !== 'user_request') {
          toast('Deep capture detached: ' + msg.reason, 'warn');
        }
      }
    });
  }

  // ---------- Tab/data refresh ------------------------------------------------

  async refreshCurrentTab() {
    this.currentTab = this.forcedTabId
      ? await tabsApi.get(this.forcedTabId)
      : await tabsApi.current();

    this.updateScopePicker();

    // In non-currentTab scope, we don't need an active page — but in
    // allDomains scope we DO load LS/SS/IDB across every open tab.
    if (this.cookieScope.mode === 'allDomains') {
      await Promise.all([
        this.loadCookies(),
        this.loadLocalStorage(),
        this.loadSessionStorage(),
        this.loadIndexedDBList(),
        this.loadSnapshots(),
        this.loadNetwork(),
      ]);
      this.updateTabCounts();
      this.renderActiveTab();
      return;
    }
    if (this.cookieScope.mode === 'customUrl') {
      await Promise.all([this.loadCookies(), this.loadNetwork()]);
      this.updateTabCounts();
      this.renderActiveTab();
      return;
    }

    if (!this.currentTab || !this.currentTab.url) {
      this.refs.body.innerHTML = '';
      this.refs.body.appendChild(
        emptyState(
          'No active tab',
          'Open AuthForge on a regular website to begin — or switch the scope ' +
          'picker above to "All cookies" to browse cookies for every site in your ' +
          'browser without needing a tab open.'
        )
      );
      return;
    }

    if (
      this.currentTab.url.startsWith('chrome://') ||
      this.currentTab.url.startsWith('chrome-extension://') ||
      this.currentTab.url.startsWith('edge://') ||
      this.currentTab.url.startsWith('about:')
    ) {
      this.refs.body.innerHTML = '';
      this.refs.body.appendChild(
        emptyState(
          'Browser-internal page',
          'Cookies and storage can only be edited on regular http(s) pages. ' +
          'Switch the scope above to "All cookies" to keep browsing.'
        )
      );
      return;
    }

    await Promise.all([
      this.loadCookies(),
      this.loadLocalStorage(),
      this.loadSessionStorage(),
      this.loadIndexedDBList(),
      this.loadSnapshots(),
      this.loadNetwork(),
    ]);
    this.updateTabCounts();
    this.renderActiveTab();
  }

  async refreshActiveTab() {
    switch (this.activeStorageTab) {
      case 'cookies':
        await this.loadCookies();
        break;
      case 'localStorage':
        await this.loadLocalStorage();
        break;
      case 'sessionStorage':
        await this.loadSessionStorage();
        break;
      case 'indexedDB':
        await this.loadIndexedDBList();
        break;
      case 'snapshots':
        await this.loadSnapshots();
        break;
      case 'tokens':
        await Promise.all([this.loadCookies(), this.loadLocalStorage(), this.loadSessionStorage()]);
        break;
      case 'network':
        await this.loadNetwork();
        break;
    }
    this.updateTabCounts();
    this.renderActiveTab();
  }

  async loadNetwork() {
    try {
      const status = await networkApi.status();
      this.networkRecording = !!status.recording;
      this.networkAvailable = !!status.available;
      this.networkEntries = await networkApi.list({
        tabId: this.networkScopeToTab && this.currentTab?.id ? this.currentTab.id : undefined,
        hostFilter: this.networkHostFilter || undefined,
        authOnly: this.networkAuthOnly,
        limit: 300,
      });
      // Debugger status — separate API call, tolerant of failure (e.g. if
      // the permission was denied at install time).
      try {
        const dbg = await debuggerApi.status();
        this.debuggerAvailable = !!dbg.available;
        this.debuggerAttachedTabs = dbg.attachedTabs || [];
      } catch {
        this.debuggerAvailable = false;
        this.debuggerAttachedTabs = [];
      }
    } catch (e) {
      this.networkEntries = [];
    }
  }

  async loadCookies() {
    try {
      let baseParams;
      if (this.cookieScope.mode === 'allDomains') {
        // chrome.cookies.getAll({}) returns every cookie the extension can
        // see, across every store and every origin — exactly what we want
        // for a "browse the whole browser" view.
        baseParams = {};
      } else if (this.cookieScope.mode === 'customUrl') {
        if (!this.cookieScope.customUrl) {
          this.cookies = [];
          return;
        }
        baseParams = { url: this.cookieScope.customUrl };
      } else {
        if (!this.currentTab?.url) {
          this.cookies = [];
          return;
        }
        baseParams = { url: this.currentTab.url };
      }

      // Primary cookies — this is the call that MUST succeed.
      this.cookies = await cookiesApi.getAll(baseParams);

      // Optional follow-up: CHIPS partitioned cookies. The SW handler
      // already has a 1.5s timeout race, but we add a second timeout
      // here as belt-and-braces. The primary list above is already
      // populated, so any failure in this block just means partitioned
      // cookies don't appear — never breaks the cookies tab.
      try {
        const partitioned = await Promise.race([
          cookiesApi.getAllPartitioned(baseParams),
          new Promise((resolve) => setTimeout(() => resolve([]), 1500)),
        ]);
        if (Array.isArray(partitioned) && partitioned.length > 0) {
          const seen = new Set(
            this.cookies.map((c) => `${c.name}|${c.domain}|${c.path}|`)
          );
          for (const c of partitioned) {
            const k = `${c.name}|${c.domain}|${c.path}|${JSON.stringify(c.partitionKey || {})}`;
            if (!seen.has(k)) {
              seen.add(k);
              this.cookies.push(c);
            }
          }
        }
      } catch {
        // Partitioned cookies are bonus — silently swallow failures.
      }

      // Sort: by domain first (when grouping matters), then by name.
      this.cookies.sort((a, b) => {
        const d = (a.domain || '').localeCompare(b.domain || '');
        return d !== 0 ? d : a.name.localeCompare(b.name);
      });
    } catch (e) {
      toast('Failed to load cookies: ' + e.message, 'err');
      this.cookies = [];
    }
  }

  async loadLocalStorage() {
    // In "All sites" mode we aggregate from every open tab. The flat list
    // stays compatible with the existing renderer when groups aren't needed.
    if (this.cookieScope.mode === 'allDomains') {
      try {
        const groups = await localStorageApi.getAllAcrossTabs();
        this.localStorageGroups = Array.isArray(groups) ? groups : [];
        // Flat list with origin tagged on each entry — used for the Tokens
        // scan and the search-term test
        this.localStorage = [];
        for (const g of this.localStorageGroups) {
          for (const e of g.entries || []) {
            this.localStorage.push({ ...e, _origin: g.origin, _tabId: g.tabId });
          }
        }
      } catch {
        this.localStorageGroups = [];
        this.localStorage = [];
      }
      return;
    }
    this.localStorageGroups = null;
    if (!this.currentTab?.id) {
      this.localStorage = [];
      return;
    }
    try {
      this.localStorage = await localStorageApi.getAll(this.currentTab.id);
      if (!Array.isArray(this.localStorage)) this.localStorage = [];
    } catch (e) {
      this.localStorage = [];
    }
  }

  async loadSessionStorage() {
    if (this.cookieScope.mode === 'allDomains') {
      try {
        const groups = await sessionStorageApi.getAllAcrossTabs();
        this.sessionStorageGroups = Array.isArray(groups) ? groups : [];
        this.sessionStorage = [];
        for (const g of this.sessionStorageGroups) {
          for (const e of g.entries || []) {
            this.sessionStorage.push({ ...e, _origin: g.origin, _tabId: g.tabId });
          }
        }
      } catch {
        this.sessionStorageGroups = [];
        this.sessionStorage = [];
      }
      return;
    }
    this.sessionStorageGroups = null;
    if (!this.currentTab?.id) {
      this.sessionStorage = [];
      return;
    }
    try {
      this.sessionStorage = await sessionStorageApi.getAll(this.currentTab.id);
      if (!Array.isArray(this.sessionStorage)) this.sessionStorage = [];
    } catch (e) {
      this.sessionStorage = [];
    }
  }

  async loadIndexedDBList() {
    if (this.cookieScope.mode === 'allDomains') {
      try {
        const groups = await indexedDBApi.listAcrossTabs();
        this.indexedDBGroups = Array.isArray(groups) ? groups : [];
        // Flatten databases list, with origin tagged for the group renderer
        this.indexedDB.databases = [];
        for (const g of this.indexedDBGroups) {
          for (const db of g.entries || []) {
            this.indexedDB.databases.push({
              ...db,
              _origin: g.origin,
              _tabId: g.tabId,
            });
          }
        }
      } catch {
        this.indexedDBGroups = [];
        this.indexedDB.databases = [];
      }
      return;
    }
    this.indexedDBGroups = null;
    if (!this.currentTab?.id) {
      this.indexedDB.databases = [];
      return;
    }
    try {
      const list = await indexedDBApi.list(this.currentTab.id);
      this.indexedDB.databases = Array.isArray(list) ? list : [];
    } catch (e) {
      this.indexedDB.databases = [];
    }
  }

  async loadSnapshots() {
    try {
      const snaps = await snapshotsApi.list();
      // Defensive: handler may return null/undefined for empty storage in
      // some scenarios. Coerce to {} so downstream Object.keys() etc. work
      // without throwing "Cannot convert undefined or null to object".
      this.snapshots = snaps && typeof snaps === 'object' ? snaps : {};
    } catch (e) {
      this.snapshots = {};
    }
  }

  updateTabCounts() {
    const auditFindings = this.runAudit();
    const counts = {
      cookies: this.cookies.length,
      localStorage: this.localStorage.length,
      sessionStorage: this.sessionStorage.length,
      indexedDB: this.indexedDB.databases.length,
      tokens: this.detectTokens().length,
      network: this.networkEntries?.length || 0,
      audit: auditFindings.length,
      // Belt and braces — even if loadSnapshots somehow left this.snapshots
      // as null, this row won't crash the whole popup.
      snapshots: this.snapshots ? Object.keys(this.snapshots).length : 0,
    };
    // Honor the "Hide empty storage tabs" setting. Defaults to true since
    // LS / SS / IDB are empty on most sites and clutter the bar otherwise.
    // Toggle off in Options → Advanced → UI to always show all tabs.
    const hideEmpty = this.settings.hideEmptyStorageTabs !== false;
    const hidable = new Set(['localStorage', 'sessionStorage', 'indexedDB']);
    for (const tab of this.refs.tabBar.querySelectorAll('.tab')) {
      const id = tab.dataset.tab;
      const countSpan = tab.querySelector('.count');
      if (countSpan) countSpan.textContent = counts[id] ?? 0;
      // Tab visibility: hide LS/SS/IDB when empty unless setting overrides,
      // OR when the tab is currently active (don't yank the rug out).
      if (hideEmpty && hidable.has(id) && counts[id] === 0 && this.activeStorageTab !== id) {
        tab.style.display = 'none';
      } else {
        tab.style.display = '';
      }
    }
  }

  // ---------- Active tab dispatch ---------------------------------------------

  renderActiveTab() {
    this.renderToolbar();
    clear(this.refs.body);

    // In customUrl scope, only Cookies make sense — LS/SS/IDB need a real
    // tab to inject into. In allDomains scope we aggregate from every open
    // tab, so all storage views work.
    if (
      this.cookieScope.mode === 'customUrl' &&
      (this.activeStorageTab === 'localStorage' ||
        this.activeStorageTab === 'sessionStorage' ||
        this.activeStorageTab === 'indexedDB' ||
        this.activeStorageTab === 'snapshots')
    ) {
      this.refs.body.appendChild(
        emptyState(
          'Switch to a real tab',
          'Pick "All sites" to aggregate this view across every open tab, or ' +
            '"Current tab" to scope to the active page.'
        )
      );
      return;
    }

    switch (this.activeStorageTab) {
      case 'cookies':
        return this.renderCookies();
      case 'localStorage':
        return this.renderKeyValueList(this.localStorage, 'localStorage');
      case 'sessionStorage':
        return this.renderKeyValueList(this.sessionStorage, 'sessionStorage');
      case 'indexedDB':
        return this.renderIndexedDB();
      case 'tokens':
        return this.renderTokens();
      case 'network':
        return this.renderNetwork();
      case 'audit':
        return this.renderAudit();
      case 'snapshots':
        return this.renderSnapshots();
    }
  }

  // ---------- Cookies UI ------------------------------------------------------

  renderCookies() {
    const now = Math.floor(Date.now() / 1000);
    const showExpired = this.settings.showExpired !== false;
    const inBrowseAll = this.cookieScope.mode === 'allDomains';

    const filtered = this.cookies.filter((c) => {
      // In all-domains mode the search term can also match the cookie's domain.
      const haystack = inBrowseAll ? c.name + ' ' + c.value + ' ' + (c.domain || '') : null;
      if (haystack !== null) {
        if (this.searchTerm && !haystack.toLowerCase().includes(this.searchTerm)) {
          return false;
        }
      } else if (!this.matchesSearch(c.name, c.value)) {
        return false;
      }
      if (!showExpired && c.expirationDate && c.expirationDate < now) return false;
      return true;
    });

    if (!filtered.length) {
      this.refs.body.appendChild(
        emptyState(
          this.cookies.length === 0 ? 'No cookies' : 'No matches',
          this.cookies.length === 0
            ? (inBrowseAll
                ? 'No cookies in the browser. (Or extension permissions are restricted.)'
                : 'This page hasn’t set any cookies yet.')
            : 'Try a different search term.'
        )
      );
      return;
    }

    if (inBrowseAll) {
      // Group by cookie.domain — collapsible per-domain sections.
      const groups = new Map();
      for (const c of filtered) {
        const key = (c.domain || '(no domain)').replace(/^\./, '');
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(c);
      }
      // Sort domain keys alphabetically
      const sortedKeys = Array.from(groups.keys()).sort();
      const wrap = h('div', { class: 'list domain-groups' });
      for (const domain of sortedKeys) {
        wrap.appendChild(this.renderDomainGroup(domain, groups.get(domain)));
      }
      this.refs.body.appendChild(wrap);
      return;
    }

    const list = h('div', { class: 'list' });
    for (const cookie of filtered) {
      list.appendChild(this.renderCookieRow(cookie));
    }
    this.refs.body.appendChild(list);
  }

  /**
   * Render a collapsible domain section. Expanded by default if the domain
   * has been previously opened in this session, or if there are only a few
   * domains shown.
   */
  renderDomainGroup(domain, cookies) {
    this._expandedDomains = this._expandedDomains || new Set();
    const isOpen = this._expandedDomains.has(domain);

    const head = h(
      'div',
      {
        class: 'domain-group-head',
        onClick: () => {
          if (this._expandedDomains.has(domain)) {
            this._expandedDomains.delete(domain);
          } else {
            this._expandedDomains.add(domain);
          }
          this.renderActiveTab();
        },
      },
      h('span', { class: 'caret' }, isOpen ? '▾' : '▸'),
      h('span', { class: 'domain-group-name' }, domain),
      h('span', { class: 'domain-group-count' }, String(cookies.length))
    );

    const group = h('div', { class: 'domain-group' }, head);

    if (isOpen) {
      const inner = h('div', { class: 'domain-group-cookies' });
      for (const cookie of cookies) {
        inner.appendChild(this.renderCookieRow(cookie));
      }
      group.appendChild(inner);
    }
    return group;
  }

  renderCookieRow(cookie) {
    const rowId = 'cookie:' + cookie.name + '@' + cookie.domain + cookie.path;
    const isExpanded = this.expandedRowId === rowId;
    const isJWT = looksLikeJWT(cookie.value);
    const isRefresh = looksLikeRefreshTokenKey(cookie.name);
    const session = !cookie.expirationDate;

    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: (e) => {
          if (e.target.closest('button, input, select, textarea, .editor')) return;
          this.expandedRowId = isExpanded ? null : rowId;
          this.renderActiveTab();
        },
      },
      h(
        'div',
        { class: 'row-name', title: cookie.name },
        cookie.name,
        // In "All open tabs" mode, surface the cookie's domain as a sub-label
        // so the row stays informative without a separate column.
        this.cookieScope.mode === 'allDomains' && cookie.domain
          ? h(
              'div',
              {
                style: {
                  fontSize: '10px',
                  color: 'var(--text-faint)',
                  fontWeight: '400',
                  marginTop: '2px',
                },
                title: cookie.domain,
              },
              cookie.domain
            )
          : null
      ),
      h('div', { class: 'row-value', title: cookie.value }, cookie.value),
      h(
        'div',
        { class: 'row-badges' },
        isJWT && h('span', { class: 'badge jwt' }, 'JWT'),
        isRefresh && h('span', { class: 'badge refresh' }, 'RT'),
        session && h('span', { class: 'badge session' }, 'Session'),
        cookie.secure && h('span', { class: 'badge secure' }, 'Secure'),
        cookie.httpOnly && h('span', { class: 'badge' }, 'HttpOnly'),
        // CHIPS — Partitioned cookies (Chrome 119+). Hover for the
        // top-level site this cookie is scoped to.
        cookie.partitionKey
          ? h(
              'span',
              {
                class: 'badge partitioned',
                title:
                  'Partitioned (CHIPS) — top-level site: ' +
                  (cookie.partitionKey.topLevelSite || '?'),
              },
              'CHIPS'
            )
          : null,
        cookie.expirationDate && this.expiryBadge(cookie.expirationDate)
      )
    );

    const wrap = h('div', {}, row);
    if (isExpanded) wrap.appendChild(this.buildCookieEditor(cookie));
    return wrap;
  }

  expiryBadge(expirationDate) {
    const now = Date.now() / 1000;
    const dt = expirationDate - now;
    if (dt < 0) return h('span', { class: 'badge expired' }, 'Expired');
    if (dt < 3600) return h('span', { class: 'badge expiring' }, 'Soon');
    return null;
  }

  buildCookieEditor(cookie) {
    const draft = { ...cookie };

    const inputName = h('input', {
      class: 'input mono',
      value: draft.name,
      oninput: (e) => (draft.name = e.target.value),
    });
    const inputDomain = h('input', {
      class: 'input mono',
      value: draft.domain,
      oninput: (e) => (draft.domain = e.target.value),
    });
    const inputPath = h('input', {
      class: 'input mono',
      value: draft.path,
      oninput: (e) => (draft.path = e.target.value),
    });
    const expirationISO = draft.expirationDate
      ? new Date(draft.expirationDate * 1000).toISOString().slice(0, 16)
      : '';
    const inputExpiration = h('input', {
      class: 'input mono',
      type: 'datetime-local',
      value: expirationISO,
      oninput: (e) => {
        const v = e.target.value;
        draft.expirationDate = v ? Math.floor(new Date(v).getTime() / 1000) : null;
      },
    });
    const selectSameSite = h(
      'select',
      {
        class: 'input',
        onchange: (e) => (draft.sameSite = e.target.value),
      },
      ...['unspecified', 'no_restriction', 'lax', 'strict'].map((s) =>
        h('option', { value: s, selected: draft.sameSite === s }, s)
      )
    );
    const valueTextarea = h('textarea', {
      class: 'textarea',
      oninput: (e) => (draft.value = e.target.value),
    });
    valueTextarea.value = draft.value;

    // ---- Value encoding toolbar -----------------------------------------
    // Cookie values are often URL-encoded, base64-encoded, or JSON. Editing
    // the raw form blindly is error-prone. These buttons transcode the
    // current textarea content in place.
    const transcodeButton = (label, transform, title) => h(
      'button',
      {
        class: 'btn ghost',
        type: 'button',
        title,
        style: { fontSize: '10.5px', padding: '3px 8px' },
        onClick: (e) => {
          e.stopPropagation();
          try {
            const newVal = transform(valueTextarea.value);
            if (newVal == null) {
              toast('No-op (not encoded that way)', 'warn');
              return;
            }
            valueTextarea.value = newVal;
            draft.value = newVal;
          } catch (err) {
            toast(label + ' failed: ' + err.message, 'err');
          }
        },
      },
      label
    );
    const encodingToolbar = h(
      'div',
      { class: 'encoding-toolbar', style: { display: 'flex', gap: '4px', flexWrap: 'wrap', margin: '4px 0' } },
      transcodeButton('URL-decode', (v) => {
        const decoded = decodeURIComponent(v);
        return decoded === v ? null : decoded;
      }, 'Replace %XX escapes with their character'),
      transcodeButton('URL-encode', (v) => encodeURIComponent(v), 'Re-encode special characters'),
      transcodeButton('base64 → text', (v) => {
        try { return atob(v); }
        catch {
          try { return atob(v.replace(/-/g, '+').replace(/_/g, '/')); }
          catch { return null; }
        }
      }, 'Decode if base64 / base64url'),
      transcodeButton('text → base64', (v) => btoa(v), 'Encode as base64'),
      transcodeButton('JSON pretty', (v) => {
        const parsed = JSON.parse(v);
        return JSON.stringify(parsed, null, 2);
      }, 'Pretty-print as JSON'),
      transcodeButton('JSON minify', (v) => {
        const parsed = JSON.parse(v);
        return JSON.stringify(parsed);
      }, 'Minify JSON'),
    );

    const flag = (label, prop) => {
      const input = h('input', { type: 'checkbox', checked: draft[prop] });
      input.addEventListener('change', () => (draft[prop] = input.checked));
      return h('label', { class: 'toggle-label' },
        h('span', { class: 'switch' }, input, h('span', { class: 'slider' })),
        label
      );
    };

    const onSave = async () => {
      try {
        const url = buildCookieUrl(cookie); // use ORIGINAL location for delete
        const newUrl = buildCookieUrl(draft);
        const before = { ...cookie };
        const after = {
          name: draft.name,
          value: draft.value,
          domain: draft.hostOnly ? undefined : draft.domain,
          path: draft.path,
          secure: !!draft.secure,
          httpOnly: !!draft.httpOnly,
          sameSite: draft.sameSite === 'unspecified' ? undefined : draft.sameSite,
          expirationDate: draft.expirationDate || undefined,
          url: newUrl,
        };

        await this.history.push({
          description: `Edit cookie ${before.name}`,
          redo: async () => {
            // If name/domain/path changed, the old cookie must be removed.
            if (
              before.name !== after.name ||
              before.domain !== (after.domain || before.domain) ||
              before.path !== after.path
            ) {
              await cookiesApi.remove({ name: before.name, url, partitionKey: before.partitionKey });
            }
            await cookiesApi.set(after);
          },
          undo: async () => {
            await cookiesApi.remove({ name: after.name, url: newUrl, partitionKey: after.partitionKey });
            const { storeId, ...rest } = before;
            await cookiesApi.set({ ...rest, url });
          },
        });
        toast(`Saved “${after.name}”`);
        this.expandedRowId = null;
        await this.loadCookies();
        this.updateTabCounts();
        this.renderActiveTab();
      } catch (e) {
        toast(`Save failed: ${e.message}`, 'err');
      }
    };

    const onDelete = async () => {
      const url = buildCookieUrl(cookie);
      const snapshot = { ...cookie };
      try {
        await this.history.push({
          description: `Delete cookie ${cookie.name}`,
          redo: async () => {
            await cookiesApi.remove({ name: cookie.name, url, partitionKey: cookie.partitionKey });
          },
          undo: async () => {
            const { storeId, ...rest } = snapshot;
            await cookiesApi.set({ ...rest, url });
          },
        });
        toast(`Deleted “${cookie.name}”`);
        this.expandedRowId = null;
        await this.loadCookies();
        this.updateTabCounts();
        this.renderActiveTab();
      } catch (e) {
        toast(`Delete failed: ${e.message}`, 'err');
      }
    };

    const editor = h(
      'div',
      { class: 'editor' },
      h(
        'div',
        { class: 'field-row' },
        h('div', {}, h('label', {}, 'Name'), inputName),
        h('div', {}, h('label', {}, 'Domain'), inputDomain)
      ),
      h(
        'div',
        { class: 'field-row' },
        h('div', {}, h('label', {}, 'Path'), inputPath),
        h('div', {}, h('label', {}, 'Expires'), inputExpiration)
      ),
      h(
        'div',
        { class: 'field-row' },
        h('div', {}, h('label', {}, 'SameSite'), selectSameSite),
        h('div', {})
      ),
      h(
        'div',
        { class: 'field-row full' },
        h('div', {}, h('label', {}, 'Value'), encodingToolbar, valueTextarea)
      ),
      h(
        'div',
        { class: 'toggles' },
        flag('Secure', 'secure'),
        flag('HttpOnly', 'httpOnly'),
        flag('Host-only', 'hostOnly')
      ),
      looksLikeJWT(cookie.value) ? this.renderJWTBlock(cookie.value) : null,
      h(
        'div',
        { class: 'actions' },
        h('button', { class: 'btn danger', onClick: onDelete }, 'Delete'),
        h('button', { class: 'btn primary', onClick: onSave }, 'Save')
      )
    );
    return editor;
  }

  renderJWTBlock(value) {
    try {
      const s = summarizeJWT(value);
      if (!s.ok) return null;
      const decoded = decodeJWT(value);
      return h(
        'div',
        {},
        h('label', {}, 'JWT preview'),
        h(
          'div',
          { class: 'jwt-meta' },
          ...[
            ['alg', s.alg],
            ['typ', s.typ],
            ['iss', s.issuer],
            ['sub', s.subject],
            ['aud', Array.isArray(s.audience) ? s.audience.join(', ') : s.audience],
            ['iat', s.issuedAt ? new Date(s.issuedAt * 1000).toLocaleString() : null],
            [
              'exp',
              s.expiresAt
                ? new Date(s.expiresAt * 1000).toLocaleString() +
                  ' (' +
                  (s.ttlSeconds > 0 ? '+' : '') +
                  formatDuration(Math.abs(s.ttlSeconds)) +
                  ')'
                : null,
            ],
            ['status', s.status],
          ]
            .filter(([, v]) => v != null)
            .map(([k, v]) =>
              h(
                'div',
                { class: 'item' },
                h('div', { class: 'label' }, k),
                h('div', { class: 'value' }, v)
              )
            )
        ),
        h(
          'div',
          { class: 'jwt-panel' },
          h(
            'div',
            { class: 'jwt-section' },
            h('h4', {}, 'Header'),
            h('pre', {}, JSON.stringify(decoded.header, null, 2))
          ),
          h(
            'div',
            { class: 'jwt-section' },
            h('h4', {}, 'Payload'),
            h('pre', {}, JSON.stringify(decoded.payload, null, 2))
          )
        )
      );
    } catch {
      return null;
    }
  }

  // ---------- LocalStorage / SessionStorage UI -------------------------------

  renderKeyValueList(items, kind) {
    // "All sites" mode — group by origin
    const groups =
      this.cookieScope.mode === 'allDomains'
        ? (kind === 'localStorage' ? this.localStorageGroups : this.sessionStorageGroups)
        : null;

    if (groups) {
      // Filter each group's entries by search term
      const filteredGroups = groups
        .map((g) => ({
          ...g,
          filteredEntries: (g.entries || []).filter((e) =>
            this.matchesSearch(e.key, e.value)
          ),
        }))
        .filter((g) => g.filteredEntries.length > 0);

      const totalEntries = filteredGroups.reduce(
        (n, g) => n + g.filteredEntries.length,
        0
      );

      if (totalEntries === 0) {
        this.refs.body.appendChild(
          emptyState(
            items.length === 0 ? `No ${kind} entries across open tabs` : 'No matches',
            items.length === 0
              ? 'Open the sites you want to inspect in tabs, then refresh. ' +
                  'Browser security requires page injection for localStorage / ' +
                  'sessionStorage / IndexedDB.'
              : 'Try a different search term.'
          )
        );
        return;
      }

      this._expandedOrigins = this._expandedOrigins || new Set();
      const wrap = h('div', { class: 'list domain-groups' });
      const sorted = filteredGroups
        .slice()
        .sort((a, b) => (a.origin || '').localeCompare(b.origin || ''));
      for (const g of sorted) {
        wrap.appendChild(this.renderOriginGroup(g, kind));
      }
      this.refs.body.appendChild(wrap);
      return;
    }

    // Single-origin (current tab) flat view — original behaviour
    const filtered = items.filter((e) => this.matchesSearch(e.key, e.value));
    if (!filtered.length) {
      const hint =
        items.length === 0
          ? 'Nothing has been stored on this page yet. ' +
            'Switch the scope above to "All open tabs" to see ' + kind +
            ' from every other tab you have open.'
          : 'Try a different search term.';
      this.refs.body.appendChild(
        emptyState(
          items.length === 0 ? `No ${kind} entries on this tab` : 'No matches',
          hint
        )
      );
      return;
    }
    // Top-of-list hint when scoped to current tab — surfaces the option to
    // browse all tabs without forcing the user to discover the scope picker.
    if (this.cookieScope.mode === 'currentTab') {
      this.refs.body.appendChild(this.renderScopeHint(kind));
    }
    const list = h('div', { class: 'list' });
    for (const entry of filtered) {
      list.appendChild(this.renderKeyValueRow(entry, kind));
    }
    this.refs.body.appendChild(list);
  }

  /**
   * Inline "Switch to all open tabs?" affordance that appears at the top of
   * the LS / SS / IDB lists when in current-tab scope. Clicking it switches
   * the scope picker for the user.
   */
  renderScopeHint(kind) {
    const labels = {
      localStorage: 'localStorage',
      sessionStorage: 'sessionStorage',
      indexedDB: 'IndexedDB databases',
    };
    const label = labels[kind] || 'storage';
    return h(
      'div',
      { class: 'scope-hint' },
      h(
        'span',
        { class: 'scope-hint-text' },
        `Browsing this tab only. `
      ),
      h(
        'button',
        {
          class: 'scope-hint-link',
          onClick: async () => {
            this.cookieScope = { mode: 'allDomains', customUrl: '' };
            this.updateScopePicker();
            await this.reloadForScope();
            this.updateTabCounts();
            this.renderActiveTab();
          },
        },
        `Show ${label} from every open tab →`
      )
    );
  }

  /**
   * Collapsible origin section used in "All sites" mode. `group.entries` is
   * the array filtered for the current search term.
   */
  renderOriginGroup(group, kind) {
    const key = group.origin || '(no origin)';
    const isOpen = this._expandedOrigins.has(key);

    const head = h(
      'div',
      {
        class: 'domain-group-head',
        onClick: () => {
          if (this._expandedOrigins.has(key)) this._expandedOrigins.delete(key);
          else this._expandedOrigins.add(key);
          this.renderActiveTab();
        },
      },
      h('span', { class: 'caret' }, isOpen ? '▾' : '▸'),
      h('span', { class: 'domain-group-name' }, key),
      h('span', { class: 'domain-group-count' }, String(group.filteredEntries.length))
    );

    const wrap = h('div', { class: 'domain-group' }, head);
    if (isOpen) {
      const inner = h('div', { class: 'domain-group-cookies' });
      for (const entry of group.filteredEntries) {
        // Pass the tabId on the entry so the editor knows which tab to mutate
        inner.appendChild(
          this.renderKeyValueRow(
            { ...entry, _tabId: group.tabId, _origin: group.origin },
            kind
          )
        );
      }
      wrap.appendChild(inner);
    }
    return wrap;
  }

  renderKeyValueRow(entry, kind) {
    const rowId = kind + ':' + entry.key;
    const isExpanded = this.expandedRowId === rowId;
    const isJWT = looksLikeJWT(entry.value);
    const isRefresh = looksLikeRefreshTokenKey(entry.key);
    const isJSON = looksLikeJson(entry.value);
    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: (e) => {
          if (e.target.closest('button, input, select, textarea, .editor')) return;
          this.expandedRowId = isExpanded ? null : rowId;
          this.renderActiveTab();
        },
      },
      h(
        'div',
        { class: 'row-name', title: entry.key },
        entry.key,
        entry._origin
          ? h(
              'div',
              {
                style: {
                  fontSize: '10px',
                  color: 'var(--text-faint)',
                  fontWeight: '400',
                  marginTop: '2px',
                },
                title: entry._origin,
              },
              entry._origin
            )
          : null
      ),
      h(
        'div',
        { class: 'row-value', title: String(entry.value ?? '') },
        entry.value
      ),
      h(
        'div',
        { class: 'row-badges' },
        isJWT && h('span', { class: 'badge jwt' }, 'JWT'),
        isRefresh && h('span', { class: 'badge refresh' }, 'RT'),
        isJSON && !isJWT && h('span', { class: 'badge' }, 'JSON')
      )
    );
    const wrap = h('div', {}, row);
    if (isExpanded) wrap.appendChild(this.buildKeyValueEditor(entry, kind));
    return wrap;
  }

  buildKeyValueEditor(entry, kind) {
    const api = kind === 'localStorage' ? localStorageApi : sessionStorageApi;
    const draft = { key: entry.key, value: entry.value };

    // If the value parses as JSON, offer a "pretty" toggle.
    const parsedJson = (() => {
      try {
        return JSON.parse(entry.value);
      } catch {
        return undefined;
      }
    })();
    let prettyMode = parsedJson !== undefined;

    const keyInput = h('input', {
      class: 'input mono',
      value: draft.key,
      oninput: (e) => (draft.key = e.target.value),
    });
    const valueTextarea = h('textarea', {
      class: 'textarea',
      oninput: (e) => (draft.value = e.target.value),
    });
    valueTextarea.value = prettyMode
      ? JSON.stringify(parsedJson, null, 2)
      : draft.value;

    if (prettyMode) {
      // Track raw value vs pretty
      draft.value = entry.value;
      valueTextarea.addEventListener('input', () => {
        // user is now editing pretty version; on save we'll minify
      });
    }

    const onSave = async () => {
      const before = { key: entry.key, value: entry.value };
      let newValue = valueTextarea.value;
      if (prettyMode) {
        try {
          newValue = JSON.stringify(JSON.parse(newValue));
        } catch (e) {
          toast('Pretty-mode JSON is invalid: ' + e.message, 'err');
          return;
        }
      }
      const after = { key: draft.key, value: newValue };
      // In "All sites" mode each entry carries its own _tabId. Fall back to
      // the active tab otherwise.
      const tabIdForOp = entry._tabId ?? this.currentTab?.id;
      try {
        await this.history.push({
          description: `Edit ${kind} ${before.key}`,
          redo: async () => {
            if (before.key !== after.key) {
              await api.remove(tabIdForOp, before.key);
            }
            await api.set(tabIdForOp, after.key, after.value);
          },
          undo: async () => {
            await api.remove(tabIdForOp, after.key);
            await api.set(tabIdForOp, before.key, before.value);
          },
        });
        toast(`Saved “${after.key}”`);
        this.expandedRowId = null;
        await (kind === 'localStorage'
          ? this.loadLocalStorage()
          : this.loadSessionStorage());
        this.updateTabCounts();
        this.renderActiveTab();
      } catch (e) {
        toast(`Save failed: ${e.message}`, 'err');
      }
    };

    const onDelete = async () => {
      const snapshot = { key: entry.key, value: entry.value };
      const tabIdForOp = entry._tabId ?? this.currentTab?.id;
      try {
        await this.history.push({
          description: `Delete ${kind} ${entry.key}`,
          redo: async () => api.remove(tabIdForOp, snapshot.key),
          undo: async () => api.set(tabIdForOp, snapshot.key, snapshot.value),
        });
        toast(`Deleted “${entry.key}”`);
        this.expandedRowId = null;
        await (kind === 'localStorage'
          ? this.loadLocalStorage()
          : this.loadSessionStorage());
        this.updateTabCounts();
        this.renderActiveTab();
      } catch (e) {
        toast(`Delete failed: ${e.message}`, 'err');
      }
    };

    const togglePretty = parsedJson !== undefined
      ? h(
          'button',
          {
            class: 'btn ghost',
            onClick: () => {
              if (prettyMode) {
                // Switch to raw: minify what's on screen
                try {
                  valueTextarea.value = JSON.stringify(
                    JSON.parse(valueTextarea.value)
                  );
                } catch {
                  // leave as-is; user edited into invalid JSON
                }
              } else {
                try {
                  valueTextarea.value = JSON.stringify(
                    JSON.parse(valueTextarea.value),
                    null,
                    2
                  );
                } catch {
                  toast('Not valid JSON — cannot pretty-print', 'warn');
                  return;
                }
              }
              prettyMode = !prettyMode;
            },
          },
          'Pretty JSON'
        )
      : null;

    return h(
      'div',
      { class: 'editor' },
      h(
        'div',
        { class: 'field-row' },
        h('div', {}, h('label', {}, 'Key'), keyInput),
        h(
          'div',
          {},
          h(
            'label',
            { style: { display: 'flex', justifyContent: 'space-between' } },
            'Value',
            togglePretty
          ),
          valueTextarea
        )
      ),
      looksLikeJWT(entry.value) ? this.renderJWTBlock(entry.value) : null,
      h(
        'div',
        { class: 'actions' },
        h('button', { class: 'btn danger', onClick: onDelete }, 'Delete'),
        h('button', { class: 'btn primary', onClick: onSave }, 'Save')
      )
    );
  }

  // ---------- IndexedDB UI ----------------------------------------------------

  renderIndexedDB() {
    // Origin-grouped view when in "All sites" mode
    if (this.cookieScope.mode === 'allDomains' && this.indexedDBGroups) {
      this._expandedOrigins = this._expandedOrigins || new Set();
      const filtered = this.indexedDBGroups
        .map((g) => ({
          ...g,
          filteredEntries: (g.entries || []).filter((db) =>
            this.matchesSearch(db.name || '', String(db.version ?? ''))
          ),
        }))
        .filter((g) => g.filteredEntries.length > 0);

      const total = filtered.reduce((n, g) => n + g.filteredEntries.length, 0);
      if (!total) {
        this.refs.body.appendChild(
          emptyState(
            this.indexedDB.databases.length === 0 ? 'No IndexedDB across open tabs' : 'No matches',
            this.indexedDB.databases.length === 0
              ? 'No open http(s) tab has reported any IndexedDB databases. Open ' +
                  'the sites you want to inspect and refresh.'
              : 'Try a different search term.'
          )
        );
        return;
      }

      const wrap = h('div', { class: 'list domain-groups' });
      const sorted = filtered
        .slice()
        .sort((a, b) => (a.origin || '').localeCompare(b.origin || ''));
      for (const g of sorted) {
        const key = g.origin || '(no origin)';
        const isOpen = this._expandedOrigins.has(key);
        const head = h(
          'div',
          {
            class: 'domain-group-head',
            onClick: () => {
              if (this._expandedOrigins.has(key)) this._expandedOrigins.delete(key);
              else this._expandedOrigins.add(key);
              this.renderActiveTab();
            },
          },
          h('span', { class: 'caret' }, isOpen ? '▾' : '▸'),
          h('span', { class: 'domain-group-name' }, key),
          h('span', { class: 'domain-group-count' }, String(g.filteredEntries.length))
        );
        const groupEl = h('div', { class: 'domain-group' }, head);
        if (isOpen) {
          const inner = h('div', { class: 'domain-group-cookies' });
          for (const db of g.filteredEntries) {
            inner.appendChild(this.renderIDBRow({ ...db, _tabId: g.tabId, _origin: g.origin }));
          }
          groupEl.appendChild(inner);
        }
        wrap.appendChild(groupEl);
      }
      this.refs.body.appendChild(wrap);
      return;
    }

    // Single-origin (current tab) view
    if (!this.indexedDB.databases.length) {
      this.refs.body.appendChild(
        emptyState(
          'No IndexedDB databases on this tab',
          'This page hasn’t opened any IndexedDB databases that the browser ' +
            'will report. Switch the scope above to "All open tabs" to see ' +
            'IndexedDB databases from every other tab you have open.'
        )
      );
      return;
    }
    if (this.cookieScope.mode === 'currentTab') {
      this.refs.body.appendChild(this.renderScopeHint('indexedDB'));
    }
    const list = h('div', { class: 'list' });
    for (const db of this.indexedDB.databases) {
      list.appendChild(this.renderIDBRow(db));
    }
    this.refs.body.appendChild(list);
  }

  renderIDBRow(db) {
    const rowId = 'idb:' + db.name;
    const isExpanded = this.expandedRowId === rowId;
    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: async (e) => {
          if (e.target.closest('button, input, select, textarea, .editor')) return;
          if (!isExpanded) {
            this.expandedRowId = rowId;
            this.idbReading = db.name;
            this.renderActiveTab();
            try {
              const tabIdForOp = db._tabId ?? this.currentTab?.id;
              const stores = await indexedDBApi.read(tabIdForOp, db.name);
              this.indexedDB.openDb = { name: db.name, stores, _tabId: tabIdForOp };
              this.renderActiveTab();
            } catch (e) {
              toast('Failed to read IndexedDB: ' + e.message, 'err');
            }
          } else {
            this.expandedRowId = null;
            this.indexedDB.openDb = null;
            this.renderActiveTab();
          }
        },
      },
      h('div', { class: 'row-name' }, db.name,
        db._origin
          ? h('div', { style: { fontSize: '10px', color: 'var(--text-faint)', fontWeight: '400', marginTop: '2px' } }, db._origin)
          : null
      ),
      h('div', { class: 'row-value' }, `version ${db.version}`),
      h(
        'div',
        { class: 'row-badges' },
        h(
          'button',
          {
            class: 'btn danger',
            onClick: async (e) => {
              e.stopPropagation();
              if (
                !(await confirmModal(
                  'Delete IndexedDB database?',
                  `“${db.name}” will be erased completely.`,
                  { okLabel: 'Delete', danger: true }
                ))
              )
                return;
              try {
                const tabIdForOp = db._tabId ?? this.currentTab?.id;
                await indexedDBApi.deleteDatabase(tabIdForOp, db.name);
                toast(`Deleted database “${db.name}”`);
                await this.loadIndexedDBList();
                this.updateTabCounts();
                this.renderActiveTab();
              } catch (err) {
                toast('Delete failed: ' + err.message, 'err');
              }
            },
          },
          'Delete DB'
        )
      )
    );
    const wrap = h('div', {}, row);
    if (isExpanded) {
      const open = this.indexedDB.openDb;
      if (!open || open.name !== db.name) {
        wrap.appendChild(h('div', { class: 'editor' }, 'Loading…'));
      } else {
        wrap.appendChild(this.renderIDBStores(open));
      }
    }
    return wrap;
  }

  renderIDBStores(open) {
    const container = h('div', { class: 'editor' });
    if (!open.stores.length) {
      container.appendChild(
        h('div', { class: 'empty' }, 'No object stores in this database.')
      );
      return container;
    }
    for (const store of open.stores) {
      container.appendChild(
        h(
          'div',
          {
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              margin: '0 0 6px',
            },
          },
          h(
            'h4',
            { style: { margin: '0', fontSize: '12px', flex: '1 1 auto' } },
            `${store.storeName} `,
            h(
              'span',
              { style: { color: 'var(--text-faint)', fontWeight: '400' } },
              `${store.records.length} record${store.records.length === 1 ? '' : 's'}` +
                (store.keyPath ? ` • keyPath: ${JSON.stringify(store.keyPath)}` : '')
            )
          ),
          h(
            'button',
            {
              class: 'btn ghost',
              style: { fontSize: '10.5px', padding: '3px 8px' },
              onClick: () => this.openIDBAddDialog(open.name, store),
            },
            '+ Add record'
          )
        )
      );
      if (!store.records.length) {
        container.appendChild(
          h('div', { class: 'empty', style: { padding: '12px' } }, 'Empty')
        );
        continue;
      }
      for (const record of store.records) {
        container.appendChild(this.renderIDBRecord(open.name, store, record));
      }
    }
    return container;
  }

  /**
   * Open a modal to add a new record to an object store. Handles both
   * in-line keyPath stores (key derived from value) and out-of-line stores
   * (key entered separately).
   */
  async openIDBAddDialog(dbName, store) {
    const inLine = store.keyPath != null;
    const tabIdForOp = this.indexedDB.openDb?._tabId ?? this.currentTab?.id;

    const keyInput = h('input', {
      class: 'input mono',
      placeholder: inLine ? '(key derived from value via keyPath)' : 'Key (string or number)',
      style: { width: '100%', marginBottom: '8px' },
    });
    if (inLine) keyInput.disabled = true;
    const valueTextarea = h('textarea', {
      class: 'textarea code',
      placeholder: inLine
        ? `JSON value (must contain ${JSON.stringify(store.keyPath)} property)`
        : 'JSON value',
      style: { minHeight: '120px' },
    });

    const formBody = h(
      'div',
      {},
      inLine
        ? h(
            'div',
            { style: { fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px' } },
            'This store uses an in-line keyPath of ',
            h('code', {}, JSON.stringify(store.keyPath)),
            ' — the key is derived from the value object automatically.'
          )
        : null,
      keyInput,
      valueTextarea
    );

    const ok = await confirmModal(`Add record to ${store.storeName}`, formBody, { okLabel: 'Add' });
    if (!ok) return;

    let value, key;
    try {
      value = JSON.parse(valueTextarea.value);
    } catch (e) {
      toast('Invalid JSON: ' + e.message, 'err');
      return;
    }
    if (!inLine) {
      const rawKey = keyInput.value.trim();
      if (!rawKey) { toast('Key required', 'err'); return; }
      key = /^-?\d+(\.\d+)?$/.test(rawKey) ? Number(rawKey) : rawKey;
    }

    try {
      await indexedDBApi.putRecord(tabIdForOp, dbName, store.storeName, key, value);
      toast('Record added');
      const stores = await indexedDBApi.read(tabIdForOp, dbName);
      this.indexedDB.openDb = { name: dbName, stores, _tabId: tabIdForOp };
      this.renderActiveTab();
    } catch (e) {
      toast('Add failed: ' + e.message, 'err');
    }
  }

  renderIDBRecord(dbName, store, record) {
    const rowId = `idb:${dbName}:${store.storeName}:${JSON.stringify(record.key)}`;
    const isExpanded = this.expandedRowId === rowId;
    const valuePreview = typeof record.value === 'object'
      ? JSON.stringify(record.value)
      : String(record.value);

    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: () => {
          this.expandedRowId = isExpanded ? null : rowId;
          this.renderActiveTab();
        },
      },
      h('div', { class: 'row-name', title: String(record.key) }, String(record.key)),
      h('div', { class: 'row-value', title: valuePreview }, valuePreview.slice(0, 200))
    );

    const wrap = h('div', {}, row);
    if (isExpanded) {
      wrap.appendChild(this.buildIDBRecordEditor(dbName, store, record));
    }
    return wrap;
  }

  buildIDBRecordEditor(dbName, store, record) {
    const tabIdForOp = this.indexedDB.openDb?._tabId ?? this.currentTab?.id;
    const inLine = store.keyPath != null;
    const initial = typeof record.value === 'object'
      ? JSON.stringify(record.value, null, 2)
      : String(record.value);

    const keyInput = h('input', {
      class: 'input mono',
      value: String(record.key),
      disabled: true,
      title: 'IDB keys are immutable. Delete and re-add to change.',
      style: { width: '100%', marginBottom: '8px' },
    });
    const valueTextarea = h('textarea', {
      class: 'textarea code',
      style: { minHeight: '160px' },
    });
    valueTextarea.value = initial;

    // Detect embedded JWT in the value (e.g. MSAL cache: { secret: 'eyJ...' })
    const jwtScan = scanValueForJwt(record.value);
    let jwtPanel = null;
    if (jwtScan) {
      jwtPanel = h(
        'details',
        { class: 'idb-jwt-panel', style: { margin: '8px 0' } },
        h(
          'summary',
          { style: { cursor: 'pointer', fontSize: '11px', fontWeight: '600' } },
          `🔑 Embedded JWT detected at ${jwtScan.path} — click to decode and edit in place`
        )
      );
      jwtPanel.appendChild(this.buildInlineJwtEditor(jwtScan, (newToken) => {
        const newValue = patchAtPath(record.value, jwtScan.path, newToken);
        valueTextarea.value = JSON.stringify(newValue, null, 2);
        toast('JWT updated — review and click Save to write back', 'ok');
      }));
    }

    const editor = h('div', { class: 'editor' });
    editor.appendChild(h('label', { class: 'field-label' }, 'Key (immutable):'));
    editor.appendChild(keyInput);
    if (jwtPanel) editor.appendChild(jwtPanel);
    editor.appendChild(h('label', { class: 'field-label' }, 'Value (JSON):'));
    editor.appendChild(valueTextarea);

    const buttons = h('div', { class: 'editor-actions' });
    buttons.appendChild(
      h(
        'button',
        {
          class: 'btn primary',
          onClick: async (e) => {
            e.stopPropagation();
            let parsedValue;
            try {
              parsedValue = JSON.parse(valueTextarea.value);
            } catch {
              parsedValue = valueTextarea.value;
            }
            const explicitKey = inLine ? undefined : record.key;
            try {
              await indexedDBApi.putRecord(
                tabIdForOp, dbName, store.storeName, explicitKey, parsedValue
              );
              toast('Record saved');
              this.expandedRowId = null;
              const stores = await indexedDBApi.read(tabIdForOp, dbName);
              this.indexedDB.openDb = { name: dbName, stores, _tabId: tabIdForOp };
              this.renderActiveTab();
            } catch (err) {
              toast('Save failed: ' + err.message, 'err');
            }
          },
        },
        'Save'
      )
    );
    buttons.appendChild(
      h(
        'button',
        {
          class: 'btn danger ghost',
          onClick: async (e) => {
            e.stopPropagation();
            if (
              !(await confirmModal(
                'Delete record?',
                `Key: ${JSON.stringify(record.key)}`,
                { okLabel: 'Delete', danger: true }
              ))
            ) return;
            try {
              await indexedDBApi.deleteRecord(
                tabIdForOp, dbName, store.storeName, record.key
              );
              toast('Record deleted');
              this.expandedRowId = null;
              const stores = await indexedDBApi.read(tabIdForOp, dbName);
              this.indexedDB.openDb = { name: dbName, stores, _tabId: tabIdForOp };
              this.renderActiveTab();
            } catch (err) {
              toast('Delete failed: ' + err.message, 'err');
            }
          },
        },
        'Delete'
      )
    );
    buttons.appendChild(
      h(
        'button',
        {
          class: 'btn ghost',
          onClick: async (e) => {
            e.stopPropagation();
            try {
              await navigator.clipboard.writeText(valueTextarea.value);
              toast('Value copied');
            } catch {
              toast('Clipboard blocked', 'err');
            }
          },
        },
        'Copy value'
      )
    );
    editor.appendChild(buttons);
    return editor;
  }

  /**
   * Inline JWT editor for embedded tokens (e.g. inside an IDB record value).
   * Decodes header + payload, lets the user tweak claims, optionally re-sign
   * with HMAC, then calls back with the new token string for writeback.
   */
  buildInlineJwtEditor(jwtScan, onApply) {
    let decoded;
    try { decoded = decodeJWT(jwtScan.token); }
    catch { return h('div', { class: 'empty' }, 'Could not decode JWT'); }
    const editor = h('div', { class: 'inline-jwt-editor' });
    editor.appendChild(
      h(
        'div',
        { style: { fontSize: '11px', color: 'var(--text-muted)', margin: '8px 0' } },
        'Edit the decoded claims, optionally provide an HMAC secret to re-sign, ' +
          'then Apply to write back. No secret → alg=none (unsigned).'
      )
    );
    const headerTa = h('textarea', { class: 'textarea code', style: { minHeight: '70px', fontSize: '10.5px' } });
    headerTa.value = JSON.stringify(decoded.header, null, 2);
    const payloadTa = h('textarea', { class: 'textarea code', style: { minHeight: '120px', fontSize: '10.5px' } });
    payloadTa.value = JSON.stringify(decoded.payload, null, 2);
    const secretInput = h('input', {
      class: 'input mono',
      placeholder: 'HMAC secret (leave empty for alg=none)',
      style: { width: '100%' },
    });
    editor.appendChild(h('label', { class: 'field-label' }, 'Header:'));
    editor.appendChild(headerTa);
    editor.appendChild(h('label', { class: 'field-label' }, 'Payload:'));
    editor.appendChild(payloadTa);
    editor.appendChild(h('label', { class: 'field-label' }, 'HMAC secret (optional):'));
    editor.appendChild(secretInput);
    editor.appendChild(
      h(
        'button',
        {
          class: 'btn primary',
          style: { marginTop: '6px' },
          onClick: async (e) => {
            e.stopPropagation();
            let header, payload;
            try {
              header = JSON.parse(headerTa.value);
              payload = JSON.parse(payloadTa.value);
            } catch (err) {
              toast('Invalid JSON: ' + err.message, 'err');
              return;
            }
            const secret = secretInput.value;
            try {
              let token;
              if (secret) {
                const alg = header.alg || 'HS256';
                token = await encodeJWT(header, payload, secret, alg);
              } else {
                const noneHeader = { ...header, alg: 'none' };
                const b64 = (obj) => btoa(JSON.stringify(obj))
                  .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
                token = b64(noneHeader) + '.' + b64(payload) + '.';
              }
              onApply(token);
            } catch (err) {
              toast('Re-sign failed: ' + err.message, 'err');
            }
          },
        },
        'Apply (re-sign + write back)'
      )
    );
    return editor;
  }

  // ---------- Tokens (cross-storage detector) --------------------------------

  /**
   * Scan everywhere we know about for things a tester would want to see in
   * the Tokens tab. The rule is: any JWT-shaped value, anything whose key
   * matches the broader auth-artifact heuristic, and any IndexedDB database
   * whose name suggests it carries auth/session data (we don't decrypt — we
   * point at it so the user knows where to look).
   *
   * Each entry carries `kind`:
   *   - 'jwt'       — value parses as a JWT, decode-and-edit available
   *   - 'opaque'    — looks like a credential by name, but not a JWT
   *   - 'idb-hint'  — IDB database whose name suggests auth storage; the
   *                   value is the database name + a note
   */
  detectTokens() {
    const out = [];
    const seen = new Set();

    // Origin labels — the host (or full URL fragment) we attribute each
    // finding to. Critical for "All open tabs" mode where the same key shape
    // can appear across many sites — without this, the Tokens tab is a soup.
    const currentTabHost = (() => {
      if (!this.currentTab?.url) return '';
      try { return new URL(this.currentTab.url).hostname; } catch { return ''; }
    })();

    const push = (entry) => {
      const k = entry.source + '|' + entry.name + '|' + (entry.value || '').slice(0, 40) + '|' + (entry.originLabel || '');
      if (seen.has(k)) return;
      seen.add(k);
      out.push(entry);
    };

    for (const c of this.cookies) {
      const isJwt = looksLikeJWT(c.value);
      const cls = classifyAuthArtifact(c.name);
      const originLabel = (c.domain || '').replace(/^\./, '') || currentTabHost;
      if (isJwt) {
        push({
          source: 'cookie',
          kind: 'jwt',
          name: c.name,
          value: c.value,
          container: c,
          classification: cls,
          originLabel,
        });
      } else if (looksLikeAuthArtifactKey(c.name)) {
        push({
          source: 'cookie',
          kind: 'opaque',
          name: c.name,
          value: c.value,
          container: c,
          classification: cls,
          originLabel,
        });
      }
    }
    for (const e of this.localStorage) {
      const isJwt = looksLikeJWT(e.value);
      const cls = classifyAuthArtifact(e.key);
      const originLabel = e._origin
        ? safeHostFromOrigin(e._origin)
        : currentTabHost;
      if (isJwt) {
        push({
          source: 'localStorage',
          kind: 'jwt',
          name: e.key,
          value: e.value,
          container: e,
          classification: cls,
          originLabel,
        });
      } else if (looksLikeAuthArtifactKey(e.key) || cls) {
        push({
          source: 'localStorage',
          kind: 'opaque',
          name: e.key,
          value: e.value,
          container: e,
          classification: cls,
          originLabel,
        });
      }
    }
    for (const e of this.sessionStorage) {
      const isJwt = looksLikeJWT(e.value);
      const cls = classifyAuthArtifact(e.key);
      const originLabel = e._origin
        ? safeHostFromOrigin(e._origin)
        : currentTabHost;
      if (isJwt) {
        push({
          source: 'sessionStorage',
          kind: 'jwt',
          name: e.key,
          value: e.value,
          container: e,
          classification: cls,
          originLabel,
        });
      } else if (looksLikeAuthArtifactKey(e.key) || cls) {
        push({
          source: 'sessionStorage',
          kind: 'opaque',
          name: e.key,
          value: e.value,
          container: e,
          classification: cls,
          originLabel,
        });
      }
    }
    for (const db of this.indexedDB.databases || []) {
      const n = (db.name || '').toLowerCase();
      const cls = classifyAuthArtifact(db.name || '');
      if (
        cls ||
        n.includes('msal') ||
        n.includes('auth') ||
        n.includes('oidc') ||
        n.includes('keycloak') ||
        n.includes('firebase') ||
        n.includes('amplify') ||
        n.includes('cache')
      ) {
        push({
          source: 'indexedDB',
          kind: 'idb-hint',
          name: db.name,
          value: 'IndexedDB database (v' + (db.version ?? '?') + ')',
          container: db,
          classification: cls || { framework: 'Unknown', type: 'cache' },
          originLabel: db._origin
            ? safeHostFromOrigin(db._origin)
            : currentTabHost,
          note:
            cls && cls.framework === 'MSAL'
              ? 'MSAL stores its token cache in IndexedDB, encrypted with an ' +
                'AES key referenced by the cookie msal.cache.encryption. The ' +
                'refresh token is in there, but AuthForge cannot decrypt ' +
                'it — open this database from the IndexedDB tab to inspect.'
              : 'Open this database from the IndexedDB tab to inspect records.',
        });
      }
    }
    for (const entry of this.networkEntries || []) {
      for (const f of entry.jwtFindings || []) {
        // Try every available source for the full token. Older captures
        // (pre full-token-retention) stored only `tokenPreview`; the full
        // token lives on the entry's authHeader / setCookies for findings
        // sourced from those. Falling back through these means the Tokens
        // tab can show network JWTs even from previously-captured entries.
        let tokenValue = f.token;
        if (!tokenValue && f.where && /^Authorization/i.test(f.where)) {
          const m = entry.authHeader?.value?.match(/^Bearer\s+(.+)$/i);
          if (m) tokenValue = m[1].trim();
        }
        if (!tokenValue && f.where && /^Set-Cookie/i.test(f.where)) {
          const sc = entry.setCookies?.find((s) => s.name === f.name);
          if (sc) tokenValue = sc.value;
        }
        if (!tokenValue && f.tokenPreview) {
          tokenValue = f.tokenPreview; // truncated, still useful
        }
        if (!tokenValue) continue;

        let host = '';
        try { host = new URL(entry.url).hostname; } catch {}
        push({
          source: 'network',
          kind: 'jwt',
          name: f.name,
          value: tokenValue,
          container: { entry, finding: f },
          classification: null,
          where: f.where,
          requestUrl: entry.url,
          originLabel: host,
        });
      }
    }

    return out;
  }

  // ---------- Security Audit -------------------------------------------------
  //
  // Surfaces cookie + storage hygiene problems inline in the popup.
  // The same checks were previously only available on the Options page
  // ("Security audit" tab) — now they're one click away, and findings
  // power the tab badge so issues are visible at a glance.

  runAudit() {
    const cookieFindings = auditCookies(this.cookies || [], {
      pageUrl: this.currentTab?.url,
    });
    const storageFindings = [
      ...auditStorage(this.localStorage || [], {
        kind: 'localStorage',
        pageUrl: this.currentTab?.url,
      }),
      ...auditStorage(this.sessionStorage || [], {
        kind: 'sessionStorage',
        pageUrl: this.currentTab?.url,
      }),
    ];
    // Network-tier findings — tokens-over-HTTP, expired JWTs replayed, etc.
    const networkFindings = auditNetwork(this.networkEntries || []);

    // Entra-tier findings: run Microsoft Entra analysis on every JWT.
    const entraFindings = [];
    const tokens = this.detectTokens();
    for (const t of tokens) {
      if (t.kind !== 'jwt' || !t.value) continue;
      let decoded;
      try { decoded = decodeJWT(t.value); } catch { continue; }
      if (!decoded || !isEntraToken(decoded)) continue;
      const analysis = analyzeEntraToken(decoded);
      const label = t.source + ':' + t.name + (t.originLabel ? '@' + t.originLabel : '');
      entraFindings.push(...auditEntraToken(analysis, label));
    }

    // Normalize: different audit modules use different field names. The
    // renderer expects {issue, detail, target, targetKind}. Older modules
    // emit {title, description, entity:{kind,name}}. Coalesce here so the
    // UI only deals with one shape.
    const normalize = (f, idx) => {
      const issue = f.issue || f.title || '(unnamed finding)';
      const detail = f.detail || f.description || '';
      const target = f.target || f.entity?.name || '';
      const targetKind = f.targetKind || f.entity?.kind || 'audit';
      const id = f.id ||
        `${targetKind}:${(target || 'global').replace(/[^a-z0-9_-]/gi, '_').slice(0, 60)}:${issue.toString().slice(0, 40).replace(/\s+/g, '_')}:${idx}`;
      return {
        ...f,
        issue,
        detail,
        target,
        targetKind,
        id,
      };
    };

    return [
      ...cookieFindings,
      ...storageFindings,
      ...networkFindings,
      ...entraFindings,
    ].map(normalize);
  }

  renderAudit() {
    const findings = this.runAudit();
    const filtered = this.searchTerm
      ? findings.filter((f) =>
          ((f.issue || '') + ' ' +
           (f.detail || '') + ' ' +
           (f.target || '') + ' ' +
           (f.recommendation || ''))
            .toLowerCase()
            .includes(this.searchTerm)
        )
      : findings;

    // Severity grouping
    const bySeverity = { critical: [], high: [], medium: [], low: [], info: [] };
    for (const f of filtered) (bySeverity[f.severity] || bySeverity.info).push(f);

    if (!filtered.length) {
      this.refs.body.appendChild(
        emptyState(
          findings.length === 0 ? 'No issues found' : 'No matches',
          findings.length === 0
            ? 'AuthForge audited cookies, storage, network captures, and ' +
              'detected JWTs (including Microsoft Entra-specific checks) and ' +
              'found nothing concerning. Switch the scope to "All open tabs" ' +
              'to audit every site at once, or capture more network traffic.'
            : 'Try a different search term.'
        )
      );
      return;
    }

    // Summary banner with counts and export
    const summary = h(
      'div',
      { class: 'audit-summary' },
      h(
        'div',
        { class: 'audit-summary-counts' },
        ['critical', 'high', 'medium', 'low', 'info']
          .filter((s) => bySeverity[s].length)
          .map((s) =>
            h(
              'span',
              { class: 'audit-summary-count audit-sev-' + s },
              h('span', { class: 'audit-summary-dot' }, ''),
              bySeverity[s].length + ' ' + s
            )
          )
      ),
      h(
        'button',
        {
          class: 'btn',
          onClick: () => this.exportAudit(filtered),
        },
        'Export findings (JSON)'
      )
    );
    this.refs.body.appendChild(summary);

    // Findings list — ordered by severity weight
    const list = h('div', { class: 'list' });
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      for (const f of bySeverity[sev]) {
        list.appendChild(this.renderAuditRow(f));
      }
    }
    this.refs.body.appendChild(list);
  }

  renderAuditRow(finding) {
    const rowId = 'audit:' + finding.id;
    const isExpanded = this.expandedRowId === rowId;
    const sev = finding.severity || 'info';

    // Real field names from audit.js:
    //   issue          short headline ("Session-class cookie sent over HTTP")
    //   detail         longer explanation of the risk
    //   target         the cookie name / storage key / token label
    //   targetKind     'cookie' | 'localStorage' | 'sessionStorage' | 'network' | 'entra-token'
    //   recommendation what to do about it
    //   category       'attribute' | 'value' | 'scope' | 'lifetime' | 'entra-recon' | …
    const headline = finding.issue || '(unnamed finding)';
    // Extract a source-host hint. For cookies: the cookie domain (audit
    // attaches it as origin). For network findings: target is the request
    // URL — pull the host out. For storage: page URL host from auditStorage.
    let originLabel = finding.origin || '';
    if (!originLabel && finding.targetKind === 'network' && finding.target) {
      try { originLabel = new URL(finding.target).host; } catch {}
    }
    const sublabel = (finding.targetKind || 'audit') +
      (finding.target ? ' · ' + finding.target : '') +
      (originLabel ? '  @ ' + originLabel : '');

    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: () => {
          this.expandedRowId = isExpanded ? null : rowId;
          this.renderActiveTab();
        },
      },
      h(
        'div',
        { class: 'row-name', title: headline },
        headline,
        h(
          'div',
          {
            style: {
              fontSize: '10px',
              color: 'var(--text-faint)',
              fontWeight: '400',
              marginTop: '2px',
            },
            title: sublabel,
          },
          sublabel
        )
      ),
      h(
        'div',
        { class: 'row-value', title: finding.detail || '' },
        finding.detail || ''
      ),
      h(
        'div',
        { class: 'row-badges' },
        h('span', { class: 'badge audit-sev-' + sev }, sev.toUpperCase()),
        finding.cookieClass
          ? h(
              'span',
              {
                class: 'badge audit-class-' + finding.cookieClass,
                title: 'Cookie classification: ' + finding.cookieClass,
              },
              finding.cookieClass
            )
          : null,
        finding.category
          ? h('span', { class: 'badge' }, finding.category)
          : null
      )
    );

    const wrap = h('div', {}, row);
    if (isExpanded) {
      const detail = h(
        'div',
        { class: 'editor', style: { fontSize: '12px' } },
        h(
          'div',
          { style: { marginBottom: '8px' } },
          h('strong', {}, headline)
        )
      );
      if (finding.detail) {
        detail.appendChild(
          h(
            'div',
            { style: { marginBottom: '8px', color: 'var(--text-muted)' } },
            finding.detail
          )
        );
      }
      // Source — show explicitly which site / URL the finding came from.
      // Critical for "allDomains" audits where 50+ findings span many hosts.
      if (originLabel) {
        detail.appendChild(
          h(
            'div',
            {
              style: {
                marginBottom: '8px',
                fontSize: '11.5px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--accent)',
                wordBreak: 'break-all',
              },
            },
            h('strong', { style: { color: 'var(--text-muted)', marginRight: '6px' } }, 'Source:'),
            originLabel
          )
        );
      }
      if (finding.recommendation) {
        detail.appendChild(
          h(
            'div',
            { class: 'audit-recommendation' },
            h('strong', {}, '💡 Recommendation: '),
            finding.recommendation
          )
        );
      }
      // Extra context the audit engine may have stamped — useful for Entra
      // findings (resourceLabel, scopeList, etc.)
      if (finding.context) {
        const ctxBlock = h(
          'div',
          { class: 'audit-context' },
          h('strong', {}, 'Context: '),
          h(
            'pre',
            {
              style: {
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                margin: '4px 0 0',
                fontSize: '11px',
              },
            },
            typeof finding.context === 'string'
              ? finding.context
              : JSON.stringify(finding.context, null, 2)
          )
        );
        detail.appendChild(ctxBlock);
      }
      if (finding.references && finding.references.length) {
        const refs = h(
          'div',
          { style: { marginTop: '8px', fontSize: '11px' } },
          h('strong', {}, 'References: ')
        );
        for (const r of finding.references) {
          refs.appendChild(
            h(
              'a',
              {
                href: r,
                target: '_blank',
                rel: 'noopener',
                style: { marginRight: '8px', color: 'var(--accent)' },
              },
              r
            )
          );
        }
        detail.appendChild(refs);
      }
      wrap.appendChild(detail);
    }
    return wrap;
  }

  exportAudit(findings) {
    const blob = new Blob(
      [JSON.stringify({
        exportedAt: new Date().toISOString(),
        scope: this.cookieScope.mode,
        origin: this.currentTab?.url,
        findings,
      }, null, 2)],
      { type: 'application/json' }
    );
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'authforge-audit-' + Date.now() + '.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast('Audit findings exported', 'ok');
  }

  renderTokens() {
    const tokens = this.detectTokens().filter((t) =>
      this.matchesSearch(t.name, t.value)
    );

    // ---- Microsoft credential extraction matrix --------------------------
    //
    // When any Microsoft / Entra credential artifact is detected (or when
    // browsing a Microsoft property), surface an honest matrix of what the
    // browser CAN extract vs what requires OS-level tooling. This addresses
    // the common "I saw a tool that extracts PRT — can AuthForge do
    // that?" question without overclaiming what's possible from MV3.
    const microsoftPanel = this.buildMicrosoftCredentialMatrix(tokens);
    if (microsoftPanel) {
      this.refs.body.appendChild(microsoftPanel);
    }

    // ---- JWT Toolkit (paste-and-test) -------------------------------------
    this.refs.body.appendChild(this.renderJwtToolkit());

    if (!tokens.length) {
      this.refs.body.appendChild(
        emptyState(
          'No tokens detected',
          'AuthForge scans cookies, storage, and live network captures ' +
            'for JWTs and auth artifacts automatically. ' +
            (this.cookieScope.mode === 'currentTab'
              ? 'Try switching the scope above to "All open tabs" to widen the search.'
              : 'Trigger a login or API call on a captured tab to populate this view.')
        )
      );
      return;
    }

    // Heading for the detected list
    this.refs.body.appendChild(
      h(
        'h3',
        { class: 'section-heading' },
        'Detected (' + tokens.length + ')'
      )
    );

    for (const token of tokens) {
      this.refs.body.appendChild(this.renderTokenRow(token));
    }
  }

  /**
   * The JWT toolkit lives at the top of the Tokens tab. It lets the user
   * paste any JWT (e.g. one they copied from somewhere outside Storage
   * Forge), auto-decode it, and run the full attack suite — exactly what
   * the Options page's "JWT playground" used to do, but in-context.
   */
  /**
   * The Microsoft credential extraction matrix. Honest, opinionated view of
   * what a browser extension CAN and CANNOT extract from a Windows host
   * authenticated to Entra ID. Compares to common offline tooling (ROADtools,
   * AADInternals, Mimikatz) to make the boundary clear.
   *
   * Categories of Microsoft credentials a pentester might want:
   *   1. Access tokens           — JWTs, browser-visible ✅
   *   2. Refresh tokens          — opaque or JWT, browser-visible ✅
   *   3. ESTSAUTH session cookies — browser-visible ✅ (re-playable for SSO)
   *   4. x-ms-RefreshTokenCredential cookie — browser-visible when present ✅
   *   5. MSAL/WAM IDB cache      — visible-but-encrypted ⚠️ (need OS key)
   *   6. Primary Refresh Token (raw) — LSASS/TPM ❌ requires ROADtoken / similar
   *   7. Device certificates     — Windows cert store / TPM ❌
   *   8. WinHello keys           — TPM-bound ❌
   *
   * Only renders when there's at least one Microsoft credential artifact
   * to show OR the user is currently on a Microsoft property.
   */
  buildMicrosoftCredentialMatrix(detectedTokens) {
    const microsoftHosts = [
      'login.microsoftonline.com',
      'login.microsoftonline.us',
      'login.microsoftonline.de',
      'login.partner.microsoftonline.cn',
      'login.live.com',
      'login.windows.net',
      'sts.windows.net',
      'graph.microsoft.com',
      'graph.windows.net',
      'outlook.office.com',
      'outlook.office365.com',
      'b2clogin.com',
    ];
    const currentHost = (() => {
      if (!this.currentTab?.url) return '';
      try { return new URL(this.currentTab.url).hostname.toLowerCase(); } catch { return ''; }
    })();
    const onMicrosoftSite = microsoftHosts.some((h) =>
      currentHost === h || currentHost.endsWith('.' + h)
    );

    // What did we actually find in scope?
    const found = {
      accessTokens: [],      // entra-classified JWTs
      refreshTokens: [],     // refresh-token-shaped artifacts
      sessionCookies: [],    // ESTSAUTH, EsCtx, BuID
      prtDerived: [],        // x-ms-RefreshTokenCredential
      msalCache: [],         // MSAL IDB hints
      mAccount: [],          // MSPAuth/RPSAuth (consumer Microsoft Account)
    };

    for (const t of detectedTokens) {
      const cls = t.classification;
      if (!cls) {
        // Plain JWT — still classify if it decodes as Entra
        if (t.kind === 'jwt' && t.value) {
          try {
            const d = decodeJWT(t.value);
            if (isEntraToken(d)) {
              // Distinguish access vs refresh by lifetime / kind / where
              if (looksLikeRefreshTokenKey(t.name)) {
                found.refreshTokens.push(t);
              } else {
                found.accessTokens.push(t);
              }
            }
          } catch {}
        }
        continue;
      }
      if (cls.framework === 'Entra') {
        if (cls.type === 'sso-session-cookie' || cls.type === 'sso-state-cookie') {
          found.sessionCookies.push(t);
        } else if (cls.type === 'prt-derived-cookie') {
          found.prtDerived.push(t);
        }
      } else if (cls.framework === 'MSAL') {
        if (cls.type === 'refresh-token-cache') found.refreshTokens.push(t);
        else if (cls.type === 'access-token-cache') found.accessTokens.push(t);
        else found.msalCache.push(t);
      } else if (cls.framework === 'Microsoft Account') {
        found.mAccount.push(t);
      }
    }

    const totalFound =
      found.accessTokens.length +
      found.refreshTokens.length +
      found.sessionCookies.length +
      found.prtDerived.length +
      found.msalCache.length +
      found.mAccount.length;

    // Show the matrix when ANY Microsoft signal is present OR we're on
    // a Microsoft property (so the user gets context proactively).
    if (totalFound === 0 && !onMicrosoftSite) return null;

    const wrap = h('details', {
      class: 'ms-matrix',
      // Collapsed by default — open only when the user clicks. The matrix is
      // a reference panel, not a primary surface. Auto-opening on detection
      // made the Tokens tab visually noisy.
    });
    wrap.appendChild(
      h(
        'summary',
        { class: 'ms-matrix-summary' },
        h('span', { class: 'ms-matrix-icon' }, '🟦'),
        h('span', {}, 'Microsoft / Entra credentials extracted'),
        h('span', { class: 'ms-matrix-count' },
          totalFound > 0
            ? totalFound + ' artefact' + (totalFound === 1 ? '' : 's') + ' found'
            : 'reference'
        )
      )
    );

    const body = h('div', { class: 'ms-matrix-body' });
    wrap.appendChild(body);

    body.appendChild(
      h(
        'p',
        { class: 'ms-matrix-intro' },
        'Browser-accessible Microsoft credentials. From an extension we see ' +
          'everything the page sees, plus network traffic. Anything stored in ' +
          'LSASS memory, TPM keys, or the Windows certificate store ',
        h('strong', {}, 'cannot'),
        ' be extracted here — those need an OS-level tool.'
      )
    );

    // Only the rows that ARE possible from a browser. The OS-only categories
    // (raw PRT, device certificates, WinHello keys) are mentioned briefly in
    // the footer rather than rendered as full rows — they're never extractable
    // from a Chrome extension, so listing them as ❌ next to the real rows
    // creates noise.
    const rows = [
      {
        status: 'yes',
        name: 'Access tokens',
        detail:
          'JWTs in Authorization headers, response bodies, and storage. ' +
          'Captured automatically; fully decoded and replayable.',
        count: found.accessTokens.length,
        items: found.accessTokens,
      },
      {
        status: 'yes',
        name: 'Refresh tokens',
        detail:
          'Visible in response bodies (deep capture), cookies, and MSAL ' +
          'IDB cache hints. Full token retained for copy / replay.',
        count: found.refreshTokens.length,
        items: found.refreshTokens,
      },
      {
        status: 'yes',
        name: 'Entra SSO cookies (ESTSAUTH*)',
        detail:
          'Browser session cookies issued by login.microsoftonline.com. Not ' +
          'PRTs but replayable for SSO hijacking against any *.microsoft.com ' +
          'property the user has access to.',
        count: found.sessionCookies.length,
        items: found.sessionCookies,
      },
      {
        status: 'yes',
        name: 'x-ms-RefreshTokenCredential (PRT-derived)',
        detail:
          'The PRT cookie value injected during SSO by Edge\'s account ' +
          'broker or the Windows-Accounts Chrome extension. The closest ' +
          'browser-accessible equivalent to a PRT — what "browser PRT theft" ' +
          'research (ROADtoken) actually targets. Visible in flight during ' +
          'network capture.',
        count: found.prtDerived.length,
        items: found.prtDerived,
      },
      {
        status: 'partial',
        name: 'MSAL / WAM IndexedDB cache',
        detail:
          'We can enumerate the IndexedDB databases (msal.token.cache, ' +
          'microsoft.authentication.broker, …) but contents are AES-encrypted ' +
          'at rest by MSAL — AuthForge can\'t decrypt from the SW context. ' +
          'Workaround: deep-capture catches tokens as they\'re decrypted into ' +
          'fetch requests.',
        count: found.msalCache.length,
        items: found.msalCache,
      },
      {
        status: 'yes',
        name: 'Microsoft Account cookies (MSPAuth, RPSAuth, …)',
        detail:
          'Consumer-side equivalent of ESTSAUTH for live.com / outlook.com / ' +
          'xbox.com accounts. Replayable session credentials.',
        count: found.mAccount.length,
        items: found.mAccount,
      },
    ];

    const grid = h('div', { class: 'ms-matrix-grid' });
    for (const r of rows) {
      // Each row collapses by default; clicking "N found" expands to list
      // the actual items with copy buttons. Rows with no findings render
      // as plain divs (nothing to expand).
      const hasItems = r.items && r.items.length > 0;
      const rowEl = h(
        hasItems ? 'details' : 'div',
        { class: 'ms-matrix-row ms-status-' + r.status }
      );

      const head = h(
        hasItems ? 'summary' : 'div',
        { class: 'ms-matrix-row-head' },
        h(
          'div',
          { class: 'ms-matrix-status' },
          r.status === 'yes' ? '✅' : r.status === 'partial' ? '⚠️' : '❌'
        ),
        h(
          'div',
          { class: 'ms-matrix-content' },
          h(
            'div',
            { class: 'ms-matrix-name' },
            r.name,
            r.count > 0
              ? h('span', { class: 'ms-matrix-found-pill' }, r.count + ' found · click to view')
              : null
          ),
          h('div', { class: 'ms-matrix-detail' }, r.detail)
        )
      );
      rowEl.appendChild(head);

      if (hasItems) {
        const itemList = h('div', { class: 'ms-matrix-items' });
        for (const item of r.items) {
          itemList.appendChild(this.renderMatrixItem(item));
        }
        rowEl.appendChild(itemList);
      }

      grid.appendChild(rowEl);
    }
    body.appendChild(grid);

    if (!totalFound && onMicrosoftSite) {
      body.appendChild(
        h(
          'div',
          { class: 'ms-matrix-tip' },
          '💡 You\'re on a Microsoft property but nothing browser-visible has ' +
            'been captured yet. Switch the scope to "All open tabs" to see ' +
            'whether Entra cookies have been issued elsewhere, or trigger a ' +
            'sign-in / API call so the network capture can grab tokens in flight.'
        )
      );
    }

    // One-line footnote covering the categories that are NOT browser-
    // accessible. Mentioned briefly so the user knows the boundary, but
    // not listed as full rows since they're never extractable here.
    body.appendChild(
      h(
        'div',
        { class: 'ms-matrix-footnote' },
        'Out of scope for browser extensions: ',
        h('strong', {}, 'raw Primary Refresh Tokens'),
        ' (LSASS / TPM), ',
        h('strong', {}, 'device certificates'),
        ' (Windows cert store), ',
        h('strong', {}, 'Windows Hello keys'),
        ' (TPM-bound). Extract these with ROADtools / AADInternals / Mimikatz ' +
          'from an OS-level shell.'
      )
    );

    return wrap;
  }

  /**
   * One item inside an expanded matrix row. Shows the token's name + origin,
   * a truncated value, and a Copy button. Clicking the row jumps focus to
   * the corresponding row in the Detected list below (so the user can dig
   * into the full decoded view with attack/recon actions).
   */
  renderMatrixItem(item) {
    const previewValue = item.kind === 'jwt'
      ? (item.value || '').slice(0, 60) + '…'
      : truncate(item.value || '', 60);

    return h(
      'div',
      { class: 'ms-matrix-item' },
      h(
        'div',
        { class: 'ms-matrix-item-head' },
        h(
          'span',
          { class: 'ms-matrix-item-name', title: item.name },
          item.name
        ),
        item.originLabel
          ? h('span', { class: 'ms-matrix-item-origin' }, '@ ' + item.originLabel)
          : null,
        h('span', { class: 'ms-matrix-item-source' }, item.source)
      ),
      h(
        'div',
        { class: 'ms-matrix-item-value' },
        h('code', {}, previewValue)
      ),
      h(
        'div',
        { class: 'ms-matrix-item-actions' },
        h(
          'button',
          {
            class: 'btn ghost',
            style: { fontSize: '10.5px', padding: '3px 8px' },
            onClick: async (e) => {
              e.stopPropagation();
              e.preventDefault();
              try {
                await navigator.clipboard.writeText(item.value || '');
                toast('Token copied', 'ok');
              } catch {
                toast('Clipboard blocked', 'err');
              }
            },
          },
          'Copy'
        ),
        h(
          'button',
          {
            class: 'btn',
            style: { fontSize: '10.5px', padding: '3px 8px' },
            onClick: (e) => {
              e.stopPropagation();
              e.preventDefault();
              // Open the corresponding token row in the Detected list
              // (renderTokenRow uses this exact rowId scheme).
              this.expandedRowId = `token:${item.source}:${item.name}:${item.originLabel || ''}`;
              this.renderActiveTab();
              // Scroll to the row after render
              requestAnimationFrame(() => {
                const expanded = this.refs.body.querySelector('.row[aria-expanded="true"]');
                if (expanded) expanded.scrollIntoView({ behavior: 'smooth', block: 'center' });
              });
            },
          },
          'Open in detail ↓'
        )
      )
    );
  }

  renderJwtToolkit() {
    // Persistent state across renders
    this._jwtToolkit = this._jwtToolkit || {
      token: '',
      bruteResult: null,
      attackResults: null,
      open: false,
    };

    const wrap = h('details', {
      class: 'jwt-toolkit',
      open: this._jwtToolkit.open,
      onToggle: (e) => {
        this._jwtToolkit.open = e.target.open;
      },
    });
    wrap.appendChild(
      h(
        'summary',
        { class: 'jwt-toolkit-summary' },
        h('span', { class: 'jwt-toolkit-icon' }, '🔧'),
        h('span', {}, 'JWT toolkit — paste a token to decode, run attacks, brute-force the secret')
      )
    );

    const body = h('div', { class: 'jwt-toolkit-body' });
    wrap.appendChild(body);

    const previewBox = h('div', { class: 'jwt-toolkit-preview' });

    const ta = h('textarea', {
      class: 'textarea code',
      placeholder: 'Paste a JWT here (3 dot-separated base64url segments)…',
      style: { minHeight: '60px', fontSize: '11px' },
      oninput: () => {
        const v = ta.value.trim();
        this._jwtToolkit.token = v;
        previewBox.innerHTML = '';
        if (!v) return;
        if (looksLikeJWT(v)) {
          previewBox.appendChild(this.renderJwtFinding({
            where: 'pasted token',
            name: 'manual',
            token: v,
            summary: summarizeJWT(v),
          }));
        } else {
          previewBox.appendChild(
            h(
              'div',
              { style: { padding: '8px', fontSize: '11.5px', color: 'var(--warn)' } },
              "Doesn't look like a JWT (expected three dot-separated base64url segments)."
            )
          );
        }
      },
    });
    if (this._jwtToolkit.token) {
      ta.value = this._jwtToolkit.token;
    }
    body.appendChild(ta);

    // Toolkit actions
    const actions = h('div', { class: 'jwt-toolkit-actions' });

    actions.appendChild(
      h(
        'button',
        {
          class: 'btn',
          onClick: () => this.runManualAttackPreview(previewBox),
        },
        '⚔ Generate attack variants'
      )
    );
    actions.appendChild(
      h(
        'button',
        {
          class: 'btn',
          onClick: () => this.runManualBruteForce(previewBox),
        },
        '🔓 Brute-force HMAC secret'
      )
    );
    actions.appendChild(
      h(
        'button',
        {
          class: 'btn ghost',
          onClick: () => {
            ta.value = '';
            this._jwtToolkit.token = '';
            previewBox.innerHTML = '';
          },
        },
        'Clear'
      )
    );
    body.appendChild(actions);
    body.appendChild(previewBox);

    // If user had content from a previous render, re-trigger preview
    if (this._jwtToolkit.token && looksLikeJWT(this._jwtToolkit.token)) {
      previewBox.appendChild(this.renderJwtFinding({
        where: 'pasted token',
        name: 'manual',
        token: this._jwtToolkit.token,
        summary: summarizeJWT(this._jwtToolkit.token),
      }));
    }

    return wrap;
  }

  async runManualAttackPreview(host) {
    const token = this._jwtToolkit?.token?.trim();
    if (!token || !looksLikeJWT(token)) {
      toast('Paste a valid JWT first', 'warn');
      return;
    }
    host.querySelectorAll('.attack-variants').forEach((el) => el.remove());

    let decoded;
    try {
      decoded = decodeJWT(token);
    } catch (e) {
      toast('Failed to decode JWT: ' + e.message, 'err');
      return;
    }
    if (!decoded || !decoded.header) {
      toast('Token decode produced no header — is this a valid JWT?', 'err');
      return;
    }

    let variants;
    try {
      // generateAttackVariants is async — alg-confusion path uses
      // WebCrypto. Forgetting to await produces a Promise that for…of
      // can't iterate, which looks like "the button does nothing".
      variants = await generateAttackVariants(decoded);
    } catch (e) {
      toast('Variant generation failed: ' + e.message, 'err');
      return;
    }
    if (!variants || variants.length === 0) {
      toast('No variants produced (token may be malformed)', 'warn');
      return;
    }

    const wrap = h('div', { class: 'attack-variants' });
    wrap.appendChild(
      h(
        'div',
        { class: 'replay-head' },
        'Attack variants generated (' + variants.length + ')'
      )
    );
    wrap.appendChild(
      h(
        'div',
        { style: { fontSize: '11px', color: 'var(--text-muted)', marginBottom: '8px' } },
        'These are tokens you can manually send to a server. To replay them ' +
          'automatically against a captured endpoint, find the request on the ' +
          'Network tab and click "Replay this request with attack variants" instead.'
      )
    );
    for (const v of variants) {
      const item = h('div', { class: 'variant-card' });
      item.appendChild(
        h(
          'div',
          { class: 'variant-card-head' },
          h(
            'span',
            { class: 'badge variant-cat variant-cat-' + (v.category || 'attack'), style: { fontSize: '9.5px' } },
            v.category || 'attack'
          ),
          h('span', { class: 'badge', style: { fontSize: '9.5px' } }, v.severity),
          h('span', { class: 'variant-card-name' }, v.name)
        )
      );
      item.appendChild(
        h('div', { class: 'variant-card-desc' }, v.description)
      );
      const tokenLine = h('div', { class: 'variant-card-token' });
      const tokenInput = h(
        'textarea',
        {
          class: 'textarea code',
          readonly: true,
          style: { minHeight: '40px', fontSize: '10.5px' },
        },
        v.token
      );
      tokenLine.appendChild(tokenInput);
      tokenLine.appendChild(
        h(
          'button',
          {
            class: 'btn',
            onClick: async () => {
              try {
                await navigator.clipboard.writeText(v.token);
                toast('Variant copied', 'ok');
              } catch {
                toast('Clipboard blocked', 'err');
              }
            },
          },
          'Copy'
        )
      );
      item.appendChild(tokenLine);
      if (v.note) {
        item.appendChild(
          h(
            'div',
            { class: 'variant-card-note' },
            '💡 ' + v.note
          )
        );
      }
      wrap.appendChild(item);
    }
    host.appendChild(wrap);
  }

  async runManualBruteForce(host) {
    const token = this._jwtToolkit?.token?.trim();
    if (!token || !looksLikeJWT(token)) {
      toast('Paste a valid JWT first', 'warn');
      return;
    }
    const decoded = decodeJWT(token);
    const alg = decoded?.header?.alg;
    if (!alg || !/^HS(256|384|512)$/i.test(alg)) {
      toast('Brute force only works on HS256/384/512 tokens (alg=' + alg + ')', 'warn');
      return;
    }

    host.querySelectorAll('.brute-result').forEach((el) => el.remove());
    const block = h('div', { class: 'brute-result' });
    block.appendChild(h('div', { class: 'replay-head' }, 'Brute-force in progress…'));
    const status = h('div', { class: 'brute-status' }, 'Trying known weak secrets…');
    block.appendChild(status);
    host.appendChild(block);

    // Compose wordlist: built-in + user-added
    const customList = (this.settings.customHmacWordlist || '')
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    const wordlist = [...new Set([...DEFAULT_HMAC_SECRETS, ...customList])];
    const max = Math.min(this.settings.jwtBruteMaxAttempts || 1000, wordlist.length);

    try {
      const result = await tryHmacSecrets(token, wordlist.slice(0, max));
      if (result.found) {
        block.innerHTML = '';
        block.appendChild(h('div', { class: 'replay-head' }, 'Brute-force complete'));
        const found = h(
          'div',
          { class: 'replay-summary err' },
          h('strong', {}, '⚠ Secret recovered: '),
          h(
            'code',
            { style: { background: 'var(--bg)', padding: '2px 6px', borderRadius: '3px' } },
            result.secret
          )
        );
        block.appendChild(found);
        block.appendChild(
          h(
            'div',
            { style: { fontSize: '11.5px', marginTop: '8px' } },
            'This server is signing JWTs with a weak/well-known secret. An ' +
              'attacker can forge tokens for any user. Report immediately.'
          )
        );
      } else {
        block.innerHTML = '';
        block.appendChild(h('div', { class: 'replay-head' }, 'Brute-force complete'));
        block.appendChild(
          h(
            'div',
            { class: 'replay-summary ok' },
            '✓ No match in ' + max + ' candidates. ' +
              'HMAC secret appears strong (or not in our wordlist). ' +
              'Add custom candidates in Settings → Advanced → Security testing.'
          )
        );
      }
    } catch (e) {
      block.innerHTML = '';
      block.appendChild(
        h('div', { class: 'replay-summary err' }, 'Brute-force failed: ' + e.message)
      );
    }
  }

  renderTokenRow(token) {
    const rowId = `token:${token.source}:${token.name}:${token.originLabel || ''}`;
    const isExpanded = this.expandedRowId === rowId;
    const isJwt = token.kind === 'jwt';
    const isIdbHint = token.kind === 'idb-hint';
    const s = isJwt ? summarizeJWT(token.value) : { ok: false };

    // Sub-label: source + framework classification + ORIGIN
    // Critical for "All open tabs" mode where the same token shape can appear
    // across multiple sites — without origin display, the user can't tell
    // which site each one came from.
    const subParts = [token.source];
    if (token.classification) {
      subParts.push(token.classification.framework + ' · ' + token.classification.type);
    }
    if (token.originLabel) {
      subParts.push(token.originLabel);
    }
    const subLabel = subParts.join(' · ');

    const valueLabel = isJwt
      ? (s.ok ? (s.issuer || s.subject || s.audience || s.alg) : '(unreadable)')
      : (isIdbHint ? token.value : truncate(token.value, 80));

    const badges = [];
    if (isJwt && s.ok) {
      if (s.status === 'expired') badges.push(h('span', { class: 'badge expired' }, 'Expired'));
      else if (s.status === 'expiring-soon') badges.push(h('span', { class: 'badge expiring' }, 'Soon'));
      else if (s.status === 'valid') badges.push(h('span', { class: 'badge valid' }, 'Valid'));
      if (s.alg) badges.push(h('span', { class: 'badge' }, s.alg));
    } else if (token.kind === 'opaque') {
      if (looksLikeRefreshTokenKey(token.name)) {
        badges.push(h('span', { class: 'badge refresh' }, 'Refresh'));
      } else {
        badges.push(h('span', { class: 'badge' }, 'Opaque'));
      }
    } else if (isIdbHint) {
      badges.push(h('span', { class: 'badge' }, 'IDB cache'));
    }

    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: () => {
          this.expandedRowId = isExpanded ? null : rowId;
          this.renderActiveTab();
        },
      },
      h(
        'div',
        { class: 'row-name' },
        token.name,
        h(
          'div',
          {
            style: {
              fontSize: '10px',
              color: 'var(--text-faint)',
              fontWeight: '400',
              marginTop: '2px',
            },
          },
          subLabel
        )
      ),
      h('div', { class: 'row-value' }, valueLabel),
      h('div', { class: 'row-badges' }, ...badges)
    );

    const wrap = h('div', {}, row);
    if (isExpanded) {
      const editor = h('div', { class: 'editor' });
      if (isJwt) {
        // Use the full rich JWT finding renderer — same one used in the
        // Network tab. Carries Entra inspector + attack variant generator
        // + (when the token came from a network capture) attack replay.
        //
        // For network-sourced tokens we DO have the captured request, so
        // we stamp a replayCtx onto the finding. The renderer will then
        // offer "Replay this request with attack variants".
        //
        // For cookie/LS/SS/IDB-sourced tokens we don't have an endpoint —
        // the user can still generate variants and brute-force the secret
        // via the JWT toolkit at the top of the tab, then manually replay.
        let replayCtx = null;
        if (token.source === 'network' && token.container?.entry) {
          const entry = token.container.entry;
          replayCtx = {
            tabId: entry.tabId,
            url: entry.url,
            method: entry.method,
            headers: this.captureToHeaderMap(entry, { excludeAuth: true }),
            body: null,
          };
        }
        editor.appendChild(this.renderJwtFinding({
          where: token.source + (token.originLabel ? ' @ ' + token.originLabel : ''),
          name: token.name,
          token: token.value,
          summary: summarizeJWT(token.value),
          replayCtx,
        }));
      } else if (isIdbHint) {
        editor.appendChild(
          h(
            'div',
            { style: { padding: '8px 0', fontSize: '12.5px', lineHeight: '1.5' } },
            token.note || 'IndexedDB database.',
            h(
              'div',
              { style: { marginTop: '10px' } },
              h(
                'button',
                {
                  class: 'btn primary',
                  onClick: () => {
                    this.activeStorageTab = 'indexedDB';
                    this.expandedRowId = null;
                    this.renderTabBar();
                    this.renderActiveTab();
                  },
                },
                'Open in IndexedDB tab →'
              )
            )
          )
        );
      } else {
        // 'opaque' — show the raw value with a copy button and a note about
        // what we think it is.
        editor.appendChild(
          h(
            'div',
            { style: { padding: '4px 0' } },
            h(
              'div',
              {
                style: {
                  fontSize: '11.5px',
                  color: 'var(--text-muted)',
                  marginBottom: '6px',
                },
              },
              'Opaque value — flagged because the key name suggests a credential. ' +
                'Not a JWT, so there\'s nothing to decode; treat it as a bearer secret.'
            ),
            h(
              'textarea',
              {
                class: 'textarea code',
                readonly: true,
                style: { minHeight: '80px', width: '100%' },
              },
              token.value
            ),
            h(
              'div',
              { style: { marginTop: '8px', display: 'flex', gap: '6px' } },
              h(
                'button',
                {
                  class: 'btn',
                  onClick: async () => {
                    try {
                      await navigator.clipboard.writeText(token.value);
                      toast('Copied value', 'ok');
                    } catch {
                      toast('Clipboard blocked', 'err');
                    }
                  },
                },
                'Copy value'
              )
            )
          )
        );
      }
      wrap.appendChild(editor);
    }
    return wrap;
  }

  // ---------- Network capture UI ----------------------------------------------

  renderNetwork() {
    // Toolbar specific to the Network tab — sits inside the body, before the
    // list, so it can stay close to the entries it controls.
    const ctl = h('div', { class: 'network-controls' });

    const recordBtn = h(
      'button',
      {
        class: 'btn ' + (this.networkRecording ? 'danger' : 'primary'),
        onClick: async () => {
          try {
            if (this.networkRecording) {
              await networkApi.stop();
            } else {
              await networkApi.start();
            }
            await this.loadNetwork();
            this.updateTabCounts();
            this.renderActiveTab();
          } catch (e) {
            toast('Failed: ' + e.message, 'err');
          }
        },
      },
      this.networkRecording ? '⏹ Stop recording' : '● Start recording'
    );
    ctl.appendChild(recordBtn);

    ctl.appendChild(
      h(
        'button',
        {
          class: 'btn',
          onClick: async () => {
            if (!(await confirmModal(
              'Clear capture buffer?',
              'All captured network entries will be discarded. This does not affect cookies or storage.',
              { okLabel: 'Clear', danger: true }
            ))) return;
            await networkApi.clear();
            await this.loadNetwork();
            this.updateTabCounts();
            this.renderActiveTab();
          },
        },
        'Clear'
      )
    );

    // Filter input
    const filterInput = h('input', {
      class: 'input',
      placeholder: 'Filter by host or URL substring…',
      value: this.networkHostFilter,
      style: { maxWidth: '260px' },
      oninput: async (e) => {
        this.networkHostFilter = e.target.value;
        await this.loadNetwork();
        this.renderActiveTab();
      },
    });
    ctl.appendChild(filterInput);

    ctl.appendChild(h('div', { class: 'spacer' }));

    // Auth-only toggle
    const authOnly = h('label', { class: 'inline-toggle', style: { fontSize: '12px' } });
    const authCb = h('input', {
      type: 'checkbox',
      checked: this.networkAuthOnly,
      onChange: async (e) => {
        this.networkAuthOnly = e.target.checked;
        await this.loadNetwork();
        this.renderActiveTab();
      },
    });
    authOnly.appendChild(authCb);
    authOnly.appendChild(document.createTextNode(' Auth-relevant only'));
    ctl.appendChild(authOnly);

    // Scope-to-current-tab toggle
    const scopeOnly = h('label', { class: 'inline-toggle', style: { fontSize: '12px' } });
    const scopeCb = h('input', {
      type: 'checkbox',
      checked: this.networkScopeToTab,
      onChange: async (e) => {
        this.networkScopeToTab = e.target.checked;
        await this.loadNetwork();
        this.renderActiveTab();
      },
    });
    scopeOnly.appendChild(scopeCb);
    scopeOnly.appendChild(document.createTextNode(' This tab only'));
    ctl.appendChild(scopeOnly);

    this.refs.body.appendChild(ctl);

    // Deep-capture sub-toolbar — separate row, visually distinct, because
    // it triggers the "is being debugged" banner and warrants opt-in clarity.
    this.refs.body.appendChild(this.renderDeepCaptureBar());

    // Status banner
    if (!this.networkAvailable) {
      this.refs.body.appendChild(
        emptyState(
          'webRequest unavailable',
          'The browser denied the webRequest permission. Reinstall the extension ' +
          'and accept network permissions if you want this feature.'
        )
      );
      return;
    }

    if (!this.networkRecording && this.networkEntries.length === 0) {
      this.refs.body.appendChild(
        emptyState(
          'Capture paused',
          'You stopped network capture earlier this session. Click "Start ' +
          'recording" above to resume — captures default to on in fresh ' +
          'sessions.'
        )
      );
      return;
    }

    if (this.networkEntries.length === 0) {
      this.refs.body.appendChild(
        emptyState(
          'No auth artifacts captured yet',
          'Capture is active. Trigger a login or API request on any tab to ' +
          'populate this view. Toggle "Auth-relevant only" off to see all ' +
          'observed requests instead.'
        )
      );
      return;
    }

    const list = h('div', { class: 'list net-list' });
    for (const entry of this.networkEntries) {
      list.appendChild(this.renderNetworkEntry(entry));
    }
    this.refs.body.appendChild(list);
  }

  /**
   * Sub-toolbar for the optional debugger / CDP "deep capture" layer.
   *
   * This is the only place in the UI that visibly attaches chrome.debugger
   * to a tab. Behaviour:
   *
   *   - Disabled if chrome.debugger isn't available, with explanation.
   *   - When inactive on the current tab, button = "Attach deep capture".
   *   - When active on the current tab, button = "Detach". A warning strip
   *     reminds the user about the browser banner.
   *   - When attached on *other* tabs but not the current one, we list them
   *     so the user can detach from anywhere.
   */
  renderDeepCaptureBar() {
    const tabId = this.currentTab?.id;
    const attachedHere = tabId != null && this.debuggerAttachedTabs.includes(tabId);
    const attachedElsewhere = this.debuggerAttachedTabs.filter((t) => t !== tabId);

    const wrap = h('div', { class: 'deep-capture-bar' });

    const head = h(
      'div',
      { class: 'deep-capture-head' },
      h('span', { class: 'deep-capture-label' }, '🔬 Deep capture (response bodies)'),
      h(
        'span',
        { class: 'deep-capture-help' },
        ' — uses Chrome\'s debugger API; shows a banner on the inspected tab.'
      )
    );
    wrap.appendChild(head);

    if (!this.debuggerAvailable) {
      wrap.appendChild(
        h(
          'div',
          { class: 'deep-capture-unavailable' },
          'chrome.debugger API unavailable. Re-install the extension and accept ' +
          'the debugger permission to enable this layer.'
        )
      );
      return wrap;
    }

    const row = h('div', { class: 'deep-capture-row' });

    if (this.cookieScope.mode !== 'currentTab' || !tabId) {
      row.appendChild(
        h(
          'span',
          { class: 'deep-capture-hint' },
          'Switch the scope picker to "Current tab" on a regular page to attach.'
        )
      );
    } else if (attachedHere) {
      row.appendChild(
        h(
          'button',
          {
            class: 'btn danger',
            onClick: async () => {
              try {
                await debuggerApi.detach(tabId);
                toast('Deep capture detached', 'ok');
                await this.loadNetwork();
                this.renderActiveTab();
              } catch (e) {
                toast('Detach failed: ' + e.message, 'err');
              }
            },
          },
          'Detach from this tab'
        )
      );
      row.appendChild(
        h(
          'span',
          { class: 'deep-capture-active' },
          '● Active on this tab. Click "Cancel" on the browser banner or this ' +
          'button to stop.'
        )
      );
    } else {
      row.appendChild(
        h(
          'button',
          {
            class: 'btn primary',
            onClick: async () => {
              const ok = await confirmModal(
                'Attach deep capture?',
                'Chrome will show a yellow "AuthForge started debugging this browser" ' +
                  'banner on this tab. While attached, AuthForge can read response ' +
                  'bodies and extract tokens — including refresh tokens from MSAL / OAuth2 ' +
                  'flows. Click "Cancel" on the banner at any time to stop.',
                { okLabel: 'Attach', danger: false }
              );
              if (!ok) return;
              try {
                await debuggerApi.attach(tabId);
                toast('Deep capture attached', 'ok');
                await this.loadNetwork();
                this.renderActiveTab();
              } catch (e) {
                toast('Attach failed: ' + e.message, 'err');
              }
            },
          },
          'Attach deep capture to this tab'
        )
      );
    }

    if (attachedElsewhere.length) {
      const list = h(
        'div',
        { class: 'deep-capture-elsewhere' },
        'Also attached on tab' + (attachedElsewhere.length === 1 ? '' : 's') + ' '
      );
      attachedElsewhere.forEach((t, i) => {
        list.appendChild(
          h(
            'button',
            {
              class: 'btn ghost',
              style: { padding: '2px 6px', fontSize: '11px', marginLeft: '4px' },
              onClick: async () => {
                try {
                  await debuggerApi.detach(t);
                  toast('Detached from tab ' + t, 'ok');
                  await this.loadNetwork();
                  this.renderActiveTab();
                } catch (e) {
                  toast('Detach failed: ' + e.message, 'err');
                }
              },
            },
            '#' + t + ' ✕'
          )
        );
        if (i < attachedElsewhere.length - 1) list.appendChild(document.createTextNode(' '));
      });
      list.appendChild(
        h(
          'button',
          {
            class: 'btn ghost',
            style: { padding: '2px 6px', fontSize: '11px', marginLeft: '8px' },
            onClick: async () => {
              try {
                await debuggerApi.detachAll();
                toast('Detached from all tabs', 'ok');
                await this.loadNetwork();
                this.renderActiveTab();
              } catch (e) {
                toast('Detach failed: ' + e.message, 'err');
              }
            },
          },
          'Detach all'
        )
      );
      wrap.appendChild(list);
    }

    wrap.appendChild(row);
    return wrap;
  }

  renderNetworkEntry(entry) {
    const rowId = 'net:' + entry.id;
    const isExpanded = this.expandedRowId === rowId;

    // Compose badges
    const badges = [];
    if (entry.tokenEndpoint) badges.push(h('span', { class: 'badge' }, 'Token endpoint'));
    if (entry.authHeader) badges.push(h('span', { class: 'badge valid' }, 'Authorization'));
    if (entry.setCookies?.length)
      badges.push(h('span', { class: 'badge' }, 'Set-Cookie ×' + entry.setCookies.length));
    if (entry.customAuthHeaders?.length)
      badges.push(h('span', { class: 'badge' }, entry.customAuthHeaders.length + ' auth-hdr'));
    if (entry.jwtFindings?.length)
      badges.push(h('span', { class: 'badge refresh' }, 'JWT ×' + entry.jwtFindings.length));
    if (entry.bodyFindings?.length)
      badges.push(h('span', { class: 'badge refresh' }, 'Body ×' + entry.bodyFindings.length));
    if (entry.statusCode && entry.statusCode >= 400)
      badges.push(h('span', { class: 'badge expired' }, entry.statusCode));
    else if (entry.statusCode)
      badges.push(h('span', { class: 'badge' }, entry.statusCode));

    let host = '';
    try { host = new URL(entry.url).hostname; } catch {}
    const pathPart = entry.url.replace(/^https?:\/\/[^/]+/, '');

    const row = h(
      'div',
      {
        class: 'row',
        'aria-expanded': String(isExpanded),
        onClick: () => {
          this.expandedRowId = isExpanded ? null : rowId;
          this.renderActiveTab();
        },
      },
      h(
        'div',
        { class: 'row-name', style: { minWidth: '0' } },
        h('span', { style: { fontWeight: '600' } }, entry.method + ' '),
        host,
        h(
          'div',
          {
            style: {
              fontSize: '10.5px',
              color: 'var(--text-faint)',
              fontWeight: '400',
              marginTop: '2px',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              maxWidth: '100%',
            },
            title: pathPart,
          },
          pathPart || '/'
        )
      ),
      h(
        'div',
        { class: 'row-value', style: { fontFamily: 'var(--font-mono)', fontSize: '10.5px', color: 'var(--text-muted)' } },
        new Date(entry.initiatedAt).toLocaleTimeString()
      ),
      h('div', { class: 'row-badges' }, ...badges)
    );

    const wrap = h('div', {}, row);
    if (isExpanded) wrap.appendChild(this.renderNetworkEntryDetail(entry));
    return wrap;
  }

  renderNetworkEntryDetail(entry) {
    const body = h('div', { class: 'editor', style: { fontSize: '12px' } });

    body.appendChild(
      h(
        'div',
        { style: { marginBottom: '8px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' } },
        h('strong', {}, entry.method + ' '),
        entry.url
      )
    );

    // ---- Request Workbench (open by default) ---------------------------
    // Full editable replay surface — change method, URL, query params,
    // headers, body, credentials, redirect mode, repeat count. Send and
    // see the response inline.
    body.appendChild(this.buildRequestWorkbench(entry));

    if (entry.authHeader) {
      body.appendChild(this.renderHeaderBlock('Request: Authorization', entry.authHeader.value));
    }
    for (const h2 of entry.customAuthHeaders || []) {
      body.appendChild(this.renderHeaderBlock('Request: ' + h2.name, h2.value));
    }
    for (const sc of entry.setCookies || []) {
      body.appendChild(
        this.renderHeaderBlock(
          'Response: Set-Cookie · ' + sc.name,
          sc.value + (sc.attrs ? '   ; ' + sc.attrs : '')
        )
      );
    }

    // Decoded JWTs found in any header
    for (const f of entry.jwtFindings || []) {
      // Stamp the replay context onto each finding so the rich JWT renderer
      // can offer "Replay this request with attack variants"
      const enriched = {
        ...f,
        replayCtx: {
          tabId: entry.tabId,
          url: entry.url,
          method: entry.method,
          // Build headers from what we captured. Don't include Authorization
          // — that's what the replay mutates.
          headers: this.captureToHeaderMap(entry, { excludeAuth: true }),
          body: null, // webRequest doesn't expose bodies in MV3
        },
      };
      body.appendChild(this.renderJwtFinding(enriched));
    }

    // Body-scan findings (from devtools panel)
    for (const f of entry.bodyFindings || []) {
      const sec = h(
        'div',
        { style: { borderTop: '1px solid var(--border)', paddingTop: '8px', marginTop: '8px' } },
        h('div', { style: { fontSize: '11.5px', color: 'var(--text-muted)', marginBottom: '4px' } },
          'Response body · ' + f.field)
      );
      const ta = h(
        'textarea',
        { class: 'textarea code', readonly: true, style: { minHeight: '60px' } },
        f.preview || ''
      );
      sec.appendChild(ta);
      const btn = h(
        'button',
        {
          class: 'btn',
          style: { marginTop: '6px' },
          onClick: async () => {
            try {
              await navigator.clipboard.writeText(f.value || f.preview || '');
              toast('Copied', 'ok');
            } catch {
              toast('Clipboard blocked', 'err');
            }
          },
        },
        'Copy full value'
      );
      sec.appendChild(btn);
      body.appendChild(sec);
    }

    return body;
  }

  /**
   * Rich JWT presentation for the network-entry expansion. Auto-decodes the
   * header and payload as pretty-printed JSON, shows a status badge, and
   * provides one-click copy buttons for the raw token + the payload.
   *
   * Fallbacks gracefully if `token` is missing on older buffer entries — uses
   * the truncated preview instead.
   */
  renderJwtFinding(f) {
    const rawToken = f.token || f.tokenPreview || '';
    const summary = f.summary || (rawToken ? summarizeJWT(rawToken) : null);

    // Decode header + payload if we have a full token
    let decoded = null;
    if (f.token) {
      try { decoded = decodeJWT(f.token); } catch { /* malformed */ }
    }

    const section = h('div', {
      class: 'jwt-finding',
    });

    // Header line: source + status pill
    const head = h('div', { class: 'jwt-finding-head' });
    head.appendChild(h('span', { class: 'jwt-finding-where' }, '🔑 ' + (f.where || 'JWT')));
    if (summary?.alg) head.appendChild(h('span', { class: 'badge' }, summary.alg));
    if (summary?.status === 'expired') head.appendChild(h('span', { class: 'badge expired' }, 'Expired'));
    else if (summary?.status === 'expiring-soon') head.appendChild(h('span', { class: 'badge expiring' }, 'Expiring soon'));
    else if (summary?.status === 'valid') head.appendChild(h('span', { class: 'badge valid' }, 'Valid'));
    section.appendChild(head);

    // Compact summary line — alg / iss / sub / exp
    if (summary?.ok) {
      const meta = [];
      if (summary.issuer) meta.push('iss=' + summary.issuer);
      if (summary.subject) meta.push('sub=' + summary.subject);
      if (summary.audience) {
        const aud = Array.isArray(summary.audience) ? summary.audience.join(',') : summary.audience;
        meta.push('aud=' + aud);
      }
      if (summary.expiresAt) {
        meta.push('exp=' + new Date(summary.expiresAt * 1000).toISOString());
      }
      if (meta.length) {
        section.appendChild(
          h('div', { class: 'jwt-finding-summary' }, meta.join(' · '))
        );
      }
    }

    // Decoded header (pretty JSON)
    if (decoded?.header) {
      section.appendChild(
        h('div', { class: 'jwt-finding-block-label' }, 'Header')
      );
      section.appendChild(
        h(
          'pre',
          { class: 'jwt-finding-json' },
          JSON.stringify(decoded.header, null, 2)
        )
      );
    }

    // Decoded payload (pretty JSON, with copy button)
    if (decoded?.payload) {
      section.appendChild(
        h('div', { class: 'jwt-finding-block-label' },
          'Payload',
          h(
            'button',
            {
              class: 'jwt-finding-copy',
              onClick: async (e) => {
                e.stopPropagation();
                try {
                  await navigator.clipboard.writeText(
                    JSON.stringify(decoded.payload, null, 2)
                  );
                  toast('Payload JSON copied', 'ok');
                } catch {
                  toast('Clipboard blocked', 'err');
                }
              },
            },
            'Copy JSON'
          )
        )
      );
      section.appendChild(
        h(
          'pre',
          { class: 'jwt-finding-json' },
          JSON.stringify(decoded.payload, null, 2)
        )
      );
    }

    // ---- Entra Inspector --------------------------------------------------
    //
    // If this looks like a Microsoft Entra / Azure AD token, surface a rich
    // analysis block: who/what the principal is, what privileges the token
    // confers, and one-click recon against Microsoft Graph. The actions are
    // all read-only — they enumerate what the token unlocks, they don't
    // mutate the tenant.
    if (decoded && isEntraToken(decoded)) {
      section.appendChild(this.renderEntraInspector(decoded, rawToken));
    }

    // Raw token with prominent copy button
    if (rawToken) {
      section.appendChild(
        h(
          'div',
          { class: 'jwt-finding-block-label' },
          'Raw token',
          h(
            'button',
            {
              class: 'jwt-finding-copy',
              onClick: async (e) => {
                e.stopPropagation();
                try {
                  await navigator.clipboard.writeText(rawToken);
                  toast('Token copied', 'ok');
                } catch {
                  toast('Clipboard blocked', 'err');
                }
              },
            },
            'Copy token'
          )
        )
      );
      const ta = h(
        'textarea',
        {
          class: 'textarea code',
          readonly: true,
          style: { minHeight: '60px', fontSize: '11px' },
        },
        rawToken
      );
      section.appendChild(ta);
      if (!f.token && f.tokenPreview) {
        section.appendChild(
          h(
            'div',
            { class: 'jwt-finding-note' },
            'Note: this entry was captured before full-token retention was enabled. ' +
            'Only the truncated preview is available — re-trigger the request to get a copyable token.'
          )
        );
      }
    }

    // ---- Attack Replay -----------------------------------------------------
    //
    // Available only when we have:
    //   - the full token (need to compute variants)
    //   - the captured request context (URL, method, etc.) — the surrounding
    //     network entry. f.replayCtx is set in renderNetworkEntryDetail.
    //
    // Only auto-replays SAFE methods (GET/HEAD/OPTIONS). Destructive methods
    // require a per-variant confirmation to avoid accidentally writing to
    // the target system.
    if (f.token && decoded && f.replayCtx) {
      const replayBtn = h(
        'button',
        {
          class: 'btn primary',
          style: { marginTop: '10px', fontSize: '11.5px' },
          onClick: (e) => {
            e.stopPropagation();
            this.runAttackReplay(section, f, decoded);
          },
        },
        '▶ Replay this request with attack variants'
      );
      section.appendChild(replayBtn);
      section.appendChild(
        h(
          'div',
          { class: 'jwt-finding-hint' },
          'Re-fires the captured request against ' +
            (f.replayCtx.url ? safeHostFromOrigin(new URL(f.replayCtx.url).origin) : 'the origin') +
            ' with each attack variant. Watch for 2xx responses on tampered tokens — those are likely vulnerabilities.'
        )
      );
    }

    return section;
  }

  /**
   * Run every attack variant against the captured endpoint and render the
   * results table inline. This is the headline pentester feature — manual
   * variant-by-variant testing previously took 10+ minutes and lots of
   * paste-and-pray; here it's one click and 5 seconds.
   */
  async runAttackReplay(host, finding, decoded) {
    // Replace any prior results section
    host.querySelectorAll('.replay-results').forEach((el) => el.remove());

    const results = h('div', { class: 'replay-results' });
    results.appendChild(
      h('div', { class: 'replay-head' }, 'Replay results')
    );
    results.appendChild(
      h(
        'div',
        { class: 'replay-categories' },
        'Variants are grouped into ',
        h('span', { class: 'badge variant-cat variant-cat-baseline' }, 'baseline'),
        ' — your captured token, ',
        h('span', { class: 'badge variant-cat variant-cat-test' }, 'test'),
        ' — boundary checks (expiry, audience, nbf) that should be rejected, and ',
        h('span', { class: 'badge variant-cat variant-cat-attack' }, 'attack'),
        ' — outright bypass attempts. A 2xx on anything other than the baseline is a likely vulnerability.'
      )
    );

    const ctx = finding.replayCtx;
    const isSafe = /^(GET|HEAD|OPTIONS)$/i.test(ctx.method || 'GET');
    if (!isSafe) {
      const warn = h(
        'div',
        { class: 'replay-warn' },
        `⚠ The captured method is ${ctx.method.toUpperCase()} — replaying could ` +
          'modify or delete data on the server. Each variant will ask for ' +
          'explicit confirmation.'
      );
      results.appendChild(warn);
    }
    host.appendChild(results);

    // Compose the variants — control + every attack
    let variants;
    try {
      variants = await generateAttackVariants(decoded);
    } catch (e) {
      results.appendChild(h('div', { class: 'replay-row err' }, 'Failed to generate variants: ' + e.message));
      return;
    }
    const lineup = [
      { id: 'control', name: 'Original (control)', token: finding.token, severity: 'info', category: 'baseline' },
      ...variants.map((v) => ({
        id: v.id,
        name: v.name,
        token: v.token,
        severity: v.severity,
        category: v.category || 'attack',
      })),
    ];

    // Table header
    const table = h('div', { class: 'replay-table' });
    table.appendChild(
      h(
        'div',
        { class: 'replay-row replay-row-head' },
        h('div', { class: 'rr-name' }, 'Variant'),
        h('div', { class: 'rr-status' }, 'Status'),
        h('div', { class: 'rr-verdict' }, 'Verdict')
      )
    );
    results.appendChild(table);

    // Run sequentially — many auth servers rate-limit; parallel makes a
    // noisier signal and can hit lockouts.
    for (const v of lineup) {
      const row = h(
        'div',
        { class: 'replay-row' },
        h('div', { class: 'rr-name' },
          h(
            'span',
            { class: 'badge variant-cat variant-cat-' + v.category, style: { fontSize: '9.5px' } },
            v.category
          ),
          h('span', { class: 'badge', style: { fontSize: '9.5px', marginLeft: '4px' } }, v.severity),
          h('span', { style: { marginLeft: '6px' } }, v.name)
        ),
        h('div', { class: 'rr-status' }, '…'),
        h('div', { class: 'rr-verdict' }, 'running')
      );
      table.appendChild(row);

      if (!isSafe && v.id !== 'control') {
        const ok = await confirmModal(
          'Replay ' + ctx.method.toUpperCase() + ' with “' + v.name + '”?',
          'This will hit ' + ctx.url + ' on the server with the mutated token. ' +
            'Only continue if you have permission to test this endpoint.',
          { okLabel: 'Replay', danger: true }
        );
        if (!ok) {
          row.querySelector('.rr-status').textContent = 'skipped';
          row.querySelector('.rr-verdict').textContent = '—';
          continue;
        }
      }

      // Build the request — start from the captured request, swap the
      // Authorization header for the variant.
      const headers = { ...(ctx.headers || {}) };
      headers['Authorization'] = 'Bearer ' + v.token;

      let r;
      try {
        r = await replayApi.request({
          tabId: ctx.tabId,
          url: ctx.url,
          method: ctx.method,
          headers,
          body: ctx.body,
          credentials: 'include',
        });
      } catch (e) {
        r = { ok: false, error: e.message };
      }

      const statusEl = row.querySelector('.rr-status');
      const verdictEl = row.querySelector('.rr-verdict');

      if (!r.ok) {
        statusEl.textContent = 'error';
        statusEl.className = 'rr-status err';
        verdictEl.textContent = r.error || 'inconclusive';
        verdictEl.className = 'rr-verdict warn';
        continue;
      }

      statusEl.textContent = String(r.status) + (r.durationMs ? ' (' + r.durationMs + 'ms)' : '');
      const accepted = r.status >= 200 && r.status < 300;
      const rejected = r.status === 401 || r.status === 403;

      if (v.id === 'control') {
        statusEl.className = accepted ? 'rr-status ok' : 'rr-status err';
        verdictEl.textContent = accepted ? 'baseline OK' : 'baseline FAILED — control rejected';
        verdictEl.className = accepted ? 'rr-verdict ok' : 'rr-verdict err';
      } else if (accepted) {
        // Server accepted a tampered token — almost certainly a vulnerability
        statusEl.className = 'rr-status err';
        verdictEl.innerHTML = '⚠ <strong>ACCEPTED</strong> — likely vulnerable to ' + v.name;
        verdictEl.className = 'rr-verdict err';
      } else if (rejected) {
        statusEl.className = 'rr-status ok';
        verdictEl.textContent = 'rejected (good)';
        verdictEl.className = 'rr-verdict ok';
      } else {
        statusEl.className = 'rr-status warn';
        verdictEl.textContent = 'inconclusive (' + r.status + ')';
        verdictEl.className = 'rr-verdict warn';
      }
    }

    // Summary footer
    const accepted = Array.from(table.querySelectorAll('.replay-row'))
      .filter((row, idx) => idx > 1)
      .filter((row) => row.querySelector('.rr-verdict.err')?.textContent?.includes('ACCEPTED'))
      .length;
    if (accepted > 0) {
      results.appendChild(
        h(
          'div',
          { class: 'replay-summary err' },
          '⚠ ' + accepted + ' variant' + (accepted === 1 ? '' : 's') +
            ' accepted by the server. This looks like one or more real vulnerabilities — verify with manual testing before reporting.'
        )
      );
    } else {
      results.appendChild(
        h(
          'div',
          { class: 'replay-summary ok' },
          '✓ No tampered tokens were accepted. Server-side JWT validation looks robust on this endpoint.'
        )
      );
    }
  }

  /**
   * Build the editable Request Workbench for a captured network entry.
   * Surfaces every fetch option a pentester or developer would want to
   * tweak before replaying: method, URL, query parameters, headers, body,
   * credentials, redirect mode, cache, mode, referrer, integrity,
   * keepalive, timeout, repeat-N×. Body type strip auto-syncs Content-Type
   * and offers structured form-urlencoded editing.
   */
  buildRequestWorkbench(entry) {
    const wb = h('details', {
      class: 'request-workbench',
      open: true, // open by default — discoverability
    });
    wb.appendChild(
      h(
        'summary',
        { class: 'workbench-summary' },
        h('span', {}, '⚒️ '),
        h('span', { class: 'workbench-title' }, 'Edit and replay this request'),
        h(
          'span',
          { class: 'workbench-hint' },
          'method · URL · query · headers · body · fetch options'
        )
      )
    );

    const originalUrl = entry.url || '';
    const originalMethod = entry.method || 'GET';
    const originalHeaders = this.captureToHeaderMap(entry) || {};

    const draft = {
      method: originalMethod,
      url: originalUrl,
      headers: [],
      body: '',
      bodyType: 'raw',
      credentials: 'include',
      redirect: 'manual',
      cache: 'no-store',
      mode: 'cors',
      referrer: '',
      referrerPolicy: 'no-referrer-when-downgrade',
      integrity: '',
      keepalive: false,
      timeoutMs: 15000,
      repeat: 1,
      repeatDelayMs: 0,
    };

    const bodyEl = h('div', { class: 'workbench-body' });
    wb.appendChild(bodyEl);

    // ---- Method + URL row ----------------------------------------------
    const methodSelect = h(
      'select',
      {
        class: 'input wb-method',
        onchange: (e) => { draft.method = e.target.value; updateDiffIndicator(); },
      },
      ...['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((m) =>
        h('option', { value: m, selected: m === draft.method }, m)
      )
    );
    const urlInput = h('input', {
      class: 'input mono wb-url',
      value: draft.url,
      oninput: (e) => {
        draft.url = e.target.value;
        rebuildQueryParams();
        updateDiffIndicator();
      },
    });
    bodyEl.appendChild(h('div', { class: 'wb-row wb-row-url' }, methodSelect, urlInput));

    // ---- Query params editor -------------------------------------------
    const queryEditor = h('div', { class: 'wb-section' });
    queryEditor.appendChild(
      h(
        'div',
        { class: 'wb-section-head' },
        h('strong', {}, 'Query parameters'),
        h(
          'button',
          {
            class: 'btn ghost wb-add',
            onClick: () => addQueryParam('', '', true),
          },
          '+ Add'
        )
      )
    );
    const queryRows = h('div', { class: 'wb-rows' });
    queryEditor.appendChild(queryRows);
    bodyEl.appendChild(queryEditor);

    const queryParams = [];
    const rebuildQueryParams = () => {
      queryRows.innerHTML = '';
      queryParams.length = 0;
      let u;
      try { u = new URL(draft.url); } catch { return; }
      for (const [k, v] of u.searchParams.entries()) {
        addQueryParam(k, v, true, { skipRebuild: true });
      }
    };
    const reserializeUrl = () => {
      let u;
      try { u = new URL(draft.url); } catch { return; }
      u.search = '';
      for (const p of queryParams) {
        if (!p.enabled || !p.name) continue;
        u.searchParams.append(p.name, p.value);
      }
      const newUrl = u.toString();
      if (newUrl !== draft.url) {
        draft.url = newUrl;
        urlInput.value = newUrl;
      }
      updateDiffIndicator();
    };
    const addQueryParam = (name, value, enabled, opts = {}) => {
      const entry = { name, value, enabled };
      queryParams.push(entry);
      const enableCheckbox = h('input', { type: 'checkbox', checked: enabled });
      enableCheckbox.addEventListener('change', () => {
        entry.enabled = enableCheckbox.checked;
        reserializeUrl();
      });
      const nameInput = h('input', {
        class: 'input mono wb-key', value: name,
        oninput: (e) => { entry.name = e.target.value; reserializeUrl(); },
      });
      const valueInput = h('input', {
        class: 'input mono wb-val', value: value,
        oninput: (e) => { entry.value = e.target.value; reserializeUrl(); },
      });
      const removeBtn = h('button', {
        class: 'btn ghost wb-remove',
        onClick: () => {
          const idx = queryParams.indexOf(entry);
          if (idx >= 0) queryParams.splice(idx, 1);
          row.remove();
          reserializeUrl();
        },
      }, '×');
      const row = h('div', { class: 'wb-kv-row' }, enableCheckbox, nameInput, valueInput, removeBtn);
      queryRows.appendChild(row);
      if (!opts.skipRebuild) reserializeUrl();
    };
    rebuildQueryParams();

    // ---- Headers editor ------------------------------------------------
    const headersEditor = h('div', { class: 'wb-section' });
    headersEditor.appendChild(
      h(
        'div',
        { class: 'wb-section-head' },
        h('strong', {}, 'Headers'),
        h(
          'button',
          { class: 'btn ghost wb-add', onClick: () => addHeaderRow('', '', true) },
          '+ Add'
        )
      )
    );
    const headerRows = h('div', { class: 'wb-rows' });
    headersEditor.appendChild(headerRows);
    bodyEl.appendChild(headersEditor);

    const addHeaderRow = (name, value, enabled) => {
      const entry = { name, value, enabled };
      draft.headers.push(entry);
      const enableCheckbox = h('input', { type: 'checkbox', checked: enabled });
      enableCheckbox.addEventListener('change', () => {
        entry.enabled = enableCheckbox.checked;
        updateDiffIndicator();
      });
      const nameInput = h('input', {
        class: 'input mono wb-key', value: name,
        oninput: (e) => { entry.name = e.target.value; updateDiffIndicator(); },
      });
      const valueInput = h('input', {
        class: 'input mono wb-val', value: value,
        oninput: (e) => { entry.value = e.target.value; updateDiffIndicator(); },
      });
      const removeBtn = h('button', {
        class: 'btn ghost wb-remove',
        onClick: () => {
          const idx = draft.headers.indexOf(entry);
          if (idx >= 0) draft.headers.splice(idx, 1);
          row.remove();
          updateDiffIndicator();
        },
      }, '×');
      const row = h('div', { class: 'wb-kv-row' }, enableCheckbox, nameInput, valueInput, removeBtn);
      headerRows.appendChild(row);
    };
    for (const [name, value] of Object.entries(originalHeaders)) {
      addHeaderRow(name, value, true);
    }

    // ---- Body editor ---------------------------------------------------
    const bodyEditor = h('div', { class: 'wb-section' });
    bodyEditor.appendChild(
      h(
        'div',
        { class: 'wb-section-head' },
        h('strong', {}, 'Body'),
        h(
          'span',
          { class: 'wb-section-hint' },
          'webRequest can\'t see captured bodies in MV3 — paste or type. Body type controls Content-Type.'
        )
      )
    );

    const ctEntry = draft.headers.find((hd) => hd.name.toLowerCase() === 'content-type');
    const ct = (ctEntry?.value || '').toLowerCase();
    if (ct.includes('application/json')) draft.bodyType = 'json';
    else if (ct.includes('application/x-www-form-urlencoded')) draft.bodyType = 'form-urlencoded';
    else if (ct.includes('multipart/form-data')) draft.bodyType = 'multipart';

    const bodyTypeStrip = h('div', { class: 'wb-bodytype-strip' });
    const bodyTypeOptions = [
      { id: 'raw', label: 'raw' },
      { id: 'json', label: 'JSON', contentType: 'application/json' },
      { id: 'form-urlencoded', label: 'form-urlencoded', contentType: 'application/x-www-form-urlencoded' },
      { id: 'multipart', label: 'multipart (text)', contentType: 'multipart/form-data' },
      { id: 'none', label: 'none' },
    ];
    let formRowsEditor;
    const setBodyType = (newType) => {
      draft.bodyType = newType;
      bodyTypeStrip.querySelectorAll('.wb-bodytype-btn').forEach((b) => {
        b.classList.toggle('active', b.dataset.id === newType);
      });
      const wanted = bodyTypeOptions.find((o) => o.id === newType)?.contentType;
      const ctHeader = draft.headers.find((hd) => hd.name.toLowerCase() === 'content-type');
      if (wanted) {
        if (ctHeader) ctHeader.value = wanted;
        else draft.headers.push({ name: 'Content-Type', value: wanted, enabled: true });
        headerRows.innerHTML = '';
        const snapshot = [...draft.headers];
        draft.headers.length = 0;
        for (const hd of snapshot) addHeaderRow(hd.name, hd.value, hd.enabled);
      }
      formRowsEditor.style.display = newType === 'form-urlencoded' ? '' : 'none';
      if (newType === 'form-urlencoded') syncFormToBody();
      updateDiffIndicator();
    };
    for (const opt of bodyTypeOptions) {
      const btn = h(
        'button',
        {
          class: 'btn ghost wb-bodytype-btn' + (opt.id === draft.bodyType ? ' active' : ''),
          type: 'button',
          'data-id': opt.id,
          onClick: (e) => { e.stopPropagation(); setBodyType(opt.id); },
        },
        opt.label
      );
      bodyTypeStrip.appendChild(btn);
    }
    bodyEditor.appendChild(bodyTypeStrip);

    formRowsEditor = h('div', { class: 'wb-form-rows', style: { display: draft.bodyType === 'form-urlencoded' ? '' : 'none', marginBottom: '6px' } });
    const formFields = [];
    const syncFormToBody = () => {
      const sp = new URLSearchParams();
      for (const f of formFields) {
        if (!f.enabled || !f.name) continue;
        sp.append(f.name, f.value);
      }
      const out = sp.toString();
      bodyTextarea.value = out;
      draft.body = out;
      updateDiffIndicator();
    };
    const addFormRow = (name, value, enabled = true) => {
      const entry = { name, value, enabled };
      formFields.push(entry);
      const enableCheckbox = h('input', { type: 'checkbox', checked: enabled });
      enableCheckbox.addEventListener('change', () => { entry.enabled = enableCheckbox.checked; syncFormToBody(); });
      const nameInput = h('input', {
        class: 'input mono wb-key', value: name,
        oninput: (e) => { entry.name = e.target.value; syncFormToBody(); },
      });
      const valueInput = h('input', {
        class: 'input mono wb-val', value: value,
        oninput: (e) => { entry.value = e.target.value; syncFormToBody(); },
      });
      const removeBtn = h('button', {
        class: 'btn ghost wb-remove',
        onClick: () => {
          const i = formFields.indexOf(entry);
          if (i >= 0) formFields.splice(i, 1);
          row.remove();
          syncFormToBody();
        },
      }, '×');
      const row = h('div', { class: 'wb-kv-row' }, enableCheckbox, nameInput, valueInput, removeBtn);
      formRowsEditor.appendChild(row);
    };
    formRowsEditor.appendChild(
      h('button', {
        class: 'btn ghost wb-add',
        type: 'button',
        onClick: (e) => { e.stopPropagation(); addFormRow('', '', true); },
      }, '+ Add field')
    );
    bodyEditor.appendChild(formRowsEditor);

    const bodyTextarea = h('textarea', {
      class: 'textarea code wb-body',
      placeholder: 'Request body (JSON, form-encoded, raw, …). Leave empty for none.',
      oninput: (e) => { draft.body = e.target.value; updateDiffIndicator(); },
    });
    // Encoding toolbar for the body
    const bodyToolbar = h('div', { class: 'encoding-toolbar' });
    const bodyTranscode = (label, transform, title) => h(
      'button',
      {
        class: 'btn ghost', type: 'button', title,
        style: { fontSize: '10.5px', padding: '3px 8px' },
        onClick: (e) => {
          e.stopPropagation();
          try {
            const out = transform(bodyTextarea.value);
            if (out == null) { toast('No-op', 'warn'); return; }
            bodyTextarea.value = out;
            draft.body = out;
          } catch (err) { toast(label + ' failed: ' + err.message, 'err'); }
        },
      },
      label
    );
    bodyToolbar.appendChild(bodyTranscode('JSON pretty', (v) => JSON.stringify(JSON.parse(v), null, 2), 'Pretty-print as JSON'));
    bodyToolbar.appendChild(bodyTranscode('JSON minify', (v) => JSON.stringify(JSON.parse(v)), 'Minify JSON'));
    bodyToolbar.appendChild(bodyTranscode('URL-decode', (v) => { const d = decodeURIComponent(v); return d === v ? null : d; }, 'URL-decode'));
    bodyToolbar.appendChild(bodyTranscode('URL-encode', (v) => encodeURIComponent(v), 'URL-encode'));
    bodyToolbar.appendChild(bodyTranscode('base64 → text', (v) => { try { return atob(v); } catch { try { return atob(v.replace(/-/g, '+').replace(/_/g, '/')); } catch { return null; } } }, 'Decode base64'));
    bodyToolbar.appendChild(bodyTranscode('text → base64', (v) => btoa(v), 'Encode as base64'));
    bodyEditor.appendChild(bodyToolbar);
    bodyEditor.appendChild(bodyTextarea);
    bodyEl.appendChild(bodyEditor);

    // ---- Fetch options --------------------------------------------------
    const optsEditor = h('div', { class: 'wb-section' });
    optsEditor.appendChild(h('div', { class: 'wb-section-head' }, h('strong', {}, 'Fetch options')));
    const optRow = h('div', { class: 'wb-opts' });
    const optSelect = (label, prop, options) => {
      const sel = h('select', {
        class: 'input',
        onchange: (e) => { draft[prop] = e.target.value; },
      }, ...options.map((v) => h('option', { value: v, selected: v === draft[prop] }, v)));
      return h('label', { class: 'wb-opt' }, label, sel);
    };
    optRow.appendChild(optSelect('Credentials', 'credentials', ['include', 'same-origin', 'omit']));
    optRow.appendChild(optSelect('Redirect', 'redirect', ['manual', 'follow', 'error']));
    optRow.appendChild(optSelect('Cache', 'cache', ['no-store', 'no-cache', 'default', 'reload', 'force-cache', 'only-if-cached']));
    optRow.appendChild(optSelect('Mode', 'mode', ['cors', 'no-cors', 'same-origin']));
    optRow.appendChild(optSelect('Referrer policy', 'referrerPolicy', [
      'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
      'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
    ]));
    const referrerInput = h('input', {
      class: 'input mono wb-num', type: 'text', value: draft.referrer,
      placeholder: 'about:client',
      style: { width: '180px' },
      oninput: (e) => { draft.referrer = e.target.value; updateDiffIndicator(); },
    });
    optRow.appendChild(h('label', { class: 'wb-opt' }, 'Referrer URL', referrerInput));
    const integrityInput = h('input', {
      class: 'input mono wb-num', type: 'text', value: draft.integrity,
      placeholder: 'sha384-…',
      style: { width: '180px' },
      oninput: (e) => { draft.integrity = e.target.value; updateDiffIndicator(); },
    });
    optRow.appendChild(h('label', { class: 'wb-opt' }, 'Integrity', integrityInput));
    const keepaliveInput = h('input', { type: 'checkbox', checked: draft.keepalive, style: { width: '16px', height: '16px' } });
    keepaliveInput.addEventListener('change', () => { draft.keepalive = keepaliveInput.checked; updateDiffIndicator(); });
    optRow.appendChild(h('label', { class: 'wb-opt' }, 'Keepalive', keepaliveInput));
    const timeoutInput = h('input', {
      class: 'input wb-num', type: 'number',
      value: draft.timeoutMs, min: 100, max: 120000, step: 100,
      oninput: (e) => { draft.timeoutMs = Number(e.target.value) || 15000; },
    });
    optRow.appendChild(h('label', { class: 'wb-opt' }, 'Timeout (ms)', timeoutInput));
    const repeatInput = h('input', {
      class: 'input wb-num', type: 'number',
      value: draft.repeat, min: 1, max: 1000, step: 1,
      oninput: (e) => { draft.repeat = Math.max(1, Math.min(1000, Number(e.target.value) || 1)); },
    });
    optRow.appendChild(h('label', { class: 'wb-opt' }, 'Repeat N×', repeatInput));
    const delayInput = h('input', {
      class: 'input wb-num', type: 'number',
      value: draft.repeatDelayMs, min: 0, max: 60000, step: 10,
      oninput: (e) => { draft.repeatDelayMs = Math.max(0, Number(e.target.value) || 0); },
    });
    optRow.appendChild(h('label', { class: 'wb-opt' }, 'Delay (ms)', delayInput));
    optsEditor.appendChild(optRow);
    bodyEl.appendChild(optsEditor);

    // ---- Action bar ---------------------------------------------------
    const diffIndicator = h('span', { class: 'wb-diff', title: 'Changes vs original captured request' }, '');
    const updateDiffIndicator = () => {
      let changes = 0;
      if (draft.method !== originalMethod) changes++;
      if (draft.url !== originalUrl) changes++;
      const origPairs = new Set(Object.entries(originalHeaders).map(([k, v]) => k.toLowerCase() + '=' + v));
      const livePairs = new Set(draft.headers.filter((h2) => h2.enabled && h2.name).map((h2) => h2.name.toLowerCase() + '=' + h2.value));
      let headerChanges = 0;
      for (const p of livePairs) if (!origPairs.has(p)) headerChanges++;
      for (const p of origPairs) if (!livePairs.has(p)) headerChanges++;
      if (headerChanges > 0) changes += headerChanges;
      if (draft.body) changes++;
      diffIndicator.textContent = changes > 0
        ? `${changes} change${changes === 1 ? '' : 's'} from original`
        : 'unmodified';
      diffIndicator.classList.toggle('wb-diff-changed', changes > 0);
    };

    const responseHost = h('div', { class: 'wb-response-host' });

    const sendBtn = h('button', {
      class: 'btn primary',
      onClick: async () => this.runWorkbenchSend(draft, originalUrl, responseHost, entry.tabId),
    }, '▶ Send');
    const resetBtn = h('button', {
      class: 'btn ghost',
      onClick: () => {
        this.expandedRowId = null;
        this.renderActiveTab();
        this.expandedRowId = 'net:' + entry.id;
        this.renderActiveTab();
      },
    }, 'Reset to original');
    const copyCurlBtn = h('button', {
      class: 'btn ghost', title: 'Copy this request as a curl command',
      onClick: async () => {
        const cmd = this.draftToCurl(draft);
        try { await navigator.clipboard.writeText(cmd); toast('curl command copied', 'ok'); }
        catch { toast('Clipboard blocked', 'err'); }
      },
    }, 'Copy as curl');
    const copyFetchBtn = h('button', {
      class: 'btn ghost', title: 'Copy as a JavaScript fetch() call',
      onClick: async () => {
        const code = this.draftToFetch(draft);
        try { await navigator.clipboard.writeText(code); toast('fetch() copied', 'ok'); }
        catch { toast('Clipboard blocked', 'err'); }
      },
    }, 'Copy as fetch');
    const importCurlBtn = h('button', {
      class: 'btn ghost', title: 'Paste a curl command — fields populate from it',
      onClick: async () => {
        const text = await this.promptCurl();
        if (!text) return;
        try {
          const parsed = parseCurl(text);
          draft.method = parsed.method;
          draft.url = parsed.url;
          urlInput.value = parsed.url;
          methodSelect.value = parsed.method;
          draft.headers.length = 0;
          headerRows.innerHTML = '';
          for (const [k, v] of parsed.headers) addHeaderRow(k, v, true);
          draft.body = parsed.body || '';
          bodyTextarea.value = parsed.body || '';
          rebuildQueryParams();
          updateDiffIndicator();
          toast('Imported from curl', 'ok');
        } catch (e) { toast('curl parse failed: ' + e.message, 'err'); }
      },
    }, 'Import curl…');
    const tokenPickerBtn = h('button', {
      class: 'btn ghost',
      title: 'Replace Authorization with a detected token from anywhere',
      onClick: async (e) => {
        e.stopPropagation();
        const tokens = this.detectTokens().filter((t) => t.kind === 'jwt' || t.kind === 'string' || t.kind === 'opaque');
        if (tokens.length === 0) { toast('No tokens detected yet', 'warn'); return; }
        const choice = await this.pickTokenModal(tokens);
        if (!choice) return;
        const existing = draft.headers.find((h2) => h2.name.toLowerCase() === 'authorization');
        const newValue = 'Bearer ' + choice.value;
        if (existing) { existing.value = newValue; existing.enabled = true; }
        else draft.headers.push({ name: 'Authorization', value: newValue, enabled: true });
        headerRows.innerHTML = '';
        const snapshot = [...draft.headers];
        draft.headers.length = 0;
        for (const h2 of snapshot) addHeaderRow(h2.name, h2.value, h2.enabled);
        updateDiffIndicator();
        toast('Authorization swapped', 'ok');
      },
    }, '🔑 Use captured token…');

    const actions = h(
      'div', { class: 'wb-actions' },
      sendBtn, resetBtn, copyCurlBtn, copyFetchBtn, importCurlBtn, tokenPickerBtn,
      h('span', { style: { marginLeft: 'auto' } }, diffIndicator)
    );
    bodyEl.appendChild(actions);
    bodyEl.appendChild(responseHost);

    updateDiffIndicator();
    return wb;
  }

  async runWorkbenchSend(draft, originalUrl, host, tabId) {
    host.innerHTML = '';
    const headers = {};
    for (const h2 of draft.headers) {
      if (!h2.enabled || !h2.name) continue;
      headers[h2.name] = h2.value;
    }

    if (draft.repeat > 1) {
      const table = h('div', { class: 'wb-results-table' });
      table.appendChild(
        h('div', { class: 'wb-result-row wb-result-head' },
          h('div', { style: { flex: '0 0 40px' } }, '#'),
          h('div', { style: { flex: '0 0 80px' } }, 'Status'),
          h('div', { style: { flex: '0 0 80px' } }, 'Time'),
          h('div', { style: { flex: '0 0 100px' } }, 'Size'),
          h('div', { style: { flex: '1 1 auto' } }, 'URL / verdict')
        )
      );
      host.appendChild(table);
      const statusCounts = {};
      for (let i = 1; i <= draft.repeat; i++) {
        const row = h('div', { class: 'wb-result-row' },
          h('div', { style: { flex: '0 0 40px' } }, '#' + i),
          h('div', { class: 'wb-r-status', style: { flex: '0 0 80px' } }, '…'),
          h('div', { class: 'wb-r-time', style: { flex: '0 0 80px' } }, '…'),
          h('div', { class: 'wb-r-size', style: { flex: '0 0 100px' } }, '…'),
          h('div', { class: 'wb-r-note', style: { flex: '1 1 auto' } }, '')
        );
        table.appendChild(row);
        try {
          const r = await replayApi.request({
            tabId, url: draft.url, method: draft.method, headers,
            body: draft.body || null,
            credentials: draft.credentials, redirect: draft.redirect,
            cache: draft.cache, mode: draft.mode,
            referrer: draft.referrer || undefined,
            referrerPolicy: draft.referrerPolicy,
            integrity: draft.integrity || undefined,
            keepalive: !!draft.keepalive,
            timeoutMs: draft.timeoutMs,
          });
          if (!r.ok) {
            row.querySelector('.wb-r-status').textContent = 'err';
            row.querySelector('.wb-r-note').textContent = r.error || '?';
            row.classList.add('wb-result-err');
          } else {
            row.querySelector('.wb-r-status').textContent = String(r.status);
            row.querySelector('.wb-r-time').textContent = r.durationMs + 'ms';
            row.querySelector('.wb-r-size').textContent = (r.bodySize ?? 0) + ' B';
            row.querySelector('.wb-r-note').textContent = r.statusText || '';
            const bucket = r.status >= 200 && r.status < 300 ? '2xx'
              : r.status >= 300 && r.status < 400 ? '3xx'
              : r.status >= 400 && r.status < 500 ? '4xx' : '5xx';
            statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
            row.classList.add('wb-result-' + bucket);
          }
        } catch (e) {
          row.querySelector('.wb-r-status').textContent = 'err';
          row.querySelector('.wb-r-note').textContent = e.message;
          row.classList.add('wb-result-err');
        }
        if (draft.repeatDelayMs > 0 && i < draft.repeat) {
          await new Promise((r) => setTimeout(r, draft.repeatDelayMs));
        }
      }
      const summary = h('div', { class: 'wb-results-summary' },
        'Done. ' + Object.entries(statusCounts).map(([k, v]) => v + ' ' + k).join(' · ')
      );
      host.appendChild(summary);
      return;
    }

    // Single shot
    const placeholder = h('div', { class: 'wb-response wb-response-loading' }, 'Sending…');
    host.appendChild(placeholder);
    let r;
    try {
      r = await replayApi.request({
        tabId, url: draft.url, method: draft.method, headers,
        body: draft.body || null,
        credentials: draft.credentials, redirect: draft.redirect,
        cache: draft.cache, mode: draft.mode,
        referrer: draft.referrer || undefined,
        referrerPolicy: draft.referrerPolicy,
        integrity: draft.integrity || undefined,
        keepalive: !!draft.keepalive,
        timeoutMs: draft.timeoutMs,
        fullResponse: true,
      });
    } catch (e) {
      placeholder.textContent = 'Error: ' + e.message;
      placeholder.classList.add('wb-response-err');
      return;
    }
    placeholder.remove();
    host.appendChild(this.renderWorkbenchResponse(r));
  }

  renderWorkbenchResponse(r) {
    if (!r.ok) {
      return h('div', { class: 'wb-response wb-response-err' },
        h('div', { class: 'wb-response-head' }, '✗ Request failed'),
        h('div', { class: 'wb-response-body' }, r.error || 'unknown error')
      );
    }
    const statusClass =
      r.status >= 200 && r.status < 300 ? 'ok'
      : r.status >= 300 && r.status < 400 ? 'redirect'
      : r.status >= 400 && r.status < 500 ? 'clienterr' : 'servererr';

    const head = h('div', { class: 'wb-response-head wb-status-' + statusClass },
      h('strong', {}, r.status + ' ' + (r.statusText || '')),
      h('span', { class: 'wb-response-meta' },
        ' · ' + r.durationMs + 'ms · ' + (r.bodySize ?? 0) + ' B · ' +
        (r.redirected ? 'redirected → ' + r.url : r.type)
      )
    );
    const headerRows = Object.entries(r.headers || {}).sort((a, b) => a[0].localeCompare(b[0]));
    const headersBlock = h('details', { class: 'wb-response-headers' },
      h('summary', {}, 'Response headers (' + headerRows.length + ')'),
      h('div', { class: 'wb-headers-list' },
        ...headerRows.map(([k, v]) =>
          h('div', { class: 'wb-header-pair' },
            h('span', { class: 'wb-header-key' }, k),
            h('span', { class: 'wb-header-val' }, v)
          )
        )
      )
    );
    const bodyContent = r.body ?? r.bodyPreview ?? '';
    let prettyJson = null;
    try { prettyJson = JSON.stringify(JSON.parse(bodyContent), null, 2); } catch {}
    const bodyTa = h('textarea', { class: 'textarea code wb-response-body', readonly: true });
    bodyTa.value = prettyJson || bodyContent;

    return h('div', { class: 'wb-response' }, head, headersBlock, bodyTa);
  }

  draftToCurl(draft) {
    const escapeShell = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
    let cmd = 'curl';
    if (draft.method && draft.method !== 'GET') cmd += ' -X ' + draft.method;
    for (const h2 of draft.headers) {
      if (!h2.enabled || !h2.name) continue;
      cmd += ' \\\n  -H ' + escapeShell(h2.name + ': ' + h2.value);
    }
    if (draft.body) cmd += ' \\\n  --data-raw ' + escapeShell(draft.body);
    cmd += ' \\\n  ' + escapeShell(draft.url);
    return cmd;
  }

  draftToFetch(draft) {
    const headers = {};
    for (const h2 of draft.headers) {
      if (!h2.enabled || !h2.name) continue;
      headers[h2.name] = h2.value;
    }
    const init = {
      method: draft.method,
      headers,
      credentials: draft.credentials,
    };
    if (draft.body) init.body = draft.body;
    return 'await fetch(' + JSON.stringify(draft.url) + ', ' + JSON.stringify(init, null, 2) + ');';
  }

  async promptCurl() {
    const ta = h('textarea', {
      class: 'textarea code',
      placeholder: 'Paste curl command here…',
      style: { minHeight: '160px', width: '100%' },
    });
    const ok = await confirmModal('Import curl command', ta, { okLabel: 'Parse' });
    return ok ? ta.value : null;
  }

  /**
   * Modal picker for one of the tokens AuthForge has detected. Used by
   * the request workbench to one-click swap the Authorization header.
   */
  async pickTokenModal(tokens) {
    return new Promise((resolve) => {
      const list = h('div', { style: { maxHeight: '320px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '4px' } });
      let picked = null;
      for (const t of tokens) {
        const preview = (t.value || '').slice(0, 50) + ((t.value || '').length > 50 ? '…' : '');
        const item = h('button', {
          class: 'btn ghost',
          style: { display: 'block', width: '100%', textAlign: 'left', padding: '8px 10px', fontSize: '11px' },
          onClick: () => {
            picked = {
              value: t.value,
              name: t.name,
              label: (t.originLabel ? '@ ' + t.originLabel + ' / ' : '') + t.name,
            };
            dlg.close();
          },
        },
          h('div', { style: { fontWeight: '600', display: 'flex', alignItems: 'center', gap: '6px' } },
            h('span', { class: 'badge', style: { fontSize: '9.5px' } }, t.source),
            h('span', { style: { fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, t.name),
            t.originLabel ? h('span', { style: { color: 'var(--accent)', fontSize: '10.5px', marginLeft: 'auto' } }, '@ ' + t.originLabel) : null
          ),
          h('div', { style: { fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontSize: '10.5px', marginTop: '2px' } }, preview)
        );
        list.appendChild(item);
      }
      const dlg = h('dialog', { class: 'modal' });
      dlg.appendChild(
        h('form', { method: 'dialog' },
          h('div', { class: 'modal-head' }, 'Pick a token (' + tokens.length + ' detected)'),
          h('div', { class: 'modal-body' },
            h('p', { style: { fontSize: '11px', color: 'var(--text-muted)', margin: '0 0 8px' } },
              'Click a token to replace the Authorization header with `Bearer <value>`.'
            ),
            list
          ),
          h('div', { class: 'modal-actions' },
            h('button', { class: 'btn ghost', value: 'cancel' }, 'Cancel')
          )
        )
      );
      document.body.appendChild(dlg);
      dlg.addEventListener('close', () => { dlg.remove(); resolve(picked); });
      dlg.showModal();
    });
  }

  /**
   * Convert a captured network entry's headers into a plain {name: value}
   * map suitable for re-issuing via fetch(). When excludeAuth=true, drops
   * the Authorization header so the caller can substitute its own.
   */
  captureToHeaderMap(entry, { excludeAuth = false } = {}) {
    const out = {};
    // webRequest gives us only the auth-relevant headers in the entry. For
    // proper replay we'd want the full header set, but the minimal set we
    // have (Authorization + custom auth headers) is sufficient for attack
    // replay since cookies are carried by `credentials: 'include'`.
    if (entry.authHeader && !excludeAuth) {
      out[entry.authHeader.name] = entry.authHeader.value;
    }
    for (const h2 of entry.customAuthHeaders || []) {
      if (h2.name && h2.value) out[h2.name] = h2.value;
    }
    return out;
  }

  /**
   * The Microsoft Entra (Azure AD) inspector: a focused dashboard that
   * appears whenever a decoded JWT looks like an Entra token. Shows
   * structured identity / privilege analysis and offers one-click recon
   * actions against Microsoft Graph.
   *
   * Everything here is READ-ONLY — these enumerate what the token can do.
   * Mutating attacks live in the regular attack-variant replay.
   */
  renderEntraInspector(decoded, rawToken) {
    const a = analyzeEntraToken(decoded);

    const wrap = h('div', { class: 'entra-inspector' });
    wrap.appendChild(
      h(
        'div',
        { class: 'entra-head' },
        h('span', { class: 'entra-logo' }, '🟦'),
        h('span', { class: 'entra-title' }, 'Microsoft Entra inspector'),
        h(
          'span',
          { class: 'entra-tag' },
          a.tokenType,
          ' · v',
          a.version
        )
      )
    );

    // Risk pills (most important first)
    if (a.risks.length) {
      const riskBox = h('div', { class: 'entra-risks' });
      for (const r of a.risks) {
        riskBox.appendChild(
          h(
            'div',
            { class: 'entra-risk audit-sev-' + r.severity },
            h('span', { class: 'audit-summary-dot' }, ''),
            h('strong', {}, r.severity.toUpperCase() + ': '),
            r.text
          )
        );
      }
      wrap.appendChild(riskBox);
    }

    // Identity panel (user/app)
    const identity = h('div', { class: 'entra-grid' });
    const isApp = a.app?.idtyp === 'app';
    identity.appendChild(this.entraField(isApp ? 'App ID (appid/azp)' : 'User UPN', a.user?.upn || a.app?.id));
    if (a.user?.name) identity.appendChild(this.entraField('Display name', a.user.name));
    if (a.user?.oid) identity.appendChild(this.entraField('Object ID (oid)', a.user.oid));
    if (a.app?.id) identity.appendChild(this.entraField('App ID (appid/azp)', a.app.id));
    identity.appendChild(this.entraField('Tenant ID (tid)', a.tenantLabel || a.tenantId || '(missing)'));
    if (a.user?.ipaddr) identity.appendChild(this.entraField('Source IP (ipaddr)', a.user.ipaddr));
    if (a.expiresAt) {
      const now = Date.now();
      const exp = a.expiresAt.getTime();
      const mins = Math.round((exp - now) / 60000);
      identity.appendChild(this.entraField(
        'Expires',
        a.expiresAt.toISOString() + (mins >= 0 ? ` (in ${mins} min)` : ` (expired ${-mins} min ago)`)
      ));
    }
    if (a.auth?.methods?.length) {
      identity.appendChild(this.entraField('Auth methods (amr)', a.auth.methods.join(', ')));
    }
    wrap.appendChild(identity);

    // Resources
    if (a.resources.length) {
      wrap.appendChild(h('div', { class: 'entra-sub' }, 'Audience / target resource'));
      const resBox = h('div', { class: 'entra-chips' });
      for (const r of a.resources) {
        resBox.appendChild(
          h(
            'span',
            {
              class: 'entra-chip',
              title: r.raw + (r.friendly !== r.raw ? '\n→ ' + r.friendly : ''),
            },
            r.friendly
          )
        );
      }
      wrap.appendChild(resBox);
    }

    // Directory roles (wids)
    if (a.directoryRoles.length) {
      wrap.appendChild(h('div', { class: 'entra-sub' }, 'Directory roles (wids)'));
      const widBox = h('div', { class: 'entra-chips' });
      for (const wid of a.directoryRoles) {
        widBox.appendChild(
          h(
            'span',
            {
              class: 'entra-chip entra-chip-risk-' + wid.info.risk,
              title: wid.id,
            },
            wid.info.name
          )
        );
      }
      wrap.appendChild(widBox);
    }

    // App roles
    if (a.appRoles.length) {
      wrap.appendChild(h('div', { class: 'entra-sub' }, 'App roles'));
      const rolesBox = h('div', { class: 'entra-chips' });
      for (const r of a.appRoles) {
        rolesBox.appendChild(h('span', { class: 'entra-chip' }, r));
      }
      wrap.appendChild(rolesBox);
    }

    // Scopes — flag privileged
    if (a.scopes.length) {
      wrap.appendChild(h('div', { class: 'entra-sub' }, 'Granted scopes (scp)'));
      const scopeBox = h('div', { class: 'entra-chips' });
      for (const s of a.scopes) {
        const isHighPriv = /\.(ReadWrite|FullControl|Manage)\.|\.default$/i.test(s);
        scopeBox.appendChild(
          h(
            'span',
            { class: 'entra-chip ' + (isHighPriv ? 'entra-chip-risk-high' : '') },
            s
          )
        );
      }
      wrap.appendChild(scopeBox);
    }

    // ---- Audience-aware recon ---------------------------------------------
    //
    // Entra access tokens are bound to a specific resource (the `aud` claim).
    // A token issued for Outlook can't call Graph, and vice versa — the
    // server returns 401 with "token rejected" no matter how legitimate the
    // token is. We split the endpoint list into "callable with THIS token"
    // and "needs a different audience", then render the callable ones as
    // primary actions and the rest as greyed-out reminders.
    const { matched, unmatched } = reconEndpointsForToken(decoded);
    const matchedByGroup = groupBy(matched, 'audienceGroup');
    const unmatchedByGroup = groupBy(unmatched, 'audienceGroup');

    wrap.appendChild(h('div', { class: 'entra-sub' }, 'Recon — what this token unlocks'));
    if (matched.length === 0) {
      wrap.appendChild(
        h(
          'div',
          { class: 'entra-help', style: { color: 'var(--warn)' } },
          '⚠ This token\'s audience doesn\'t match any of AuthForge\'s known ' +
            'recon endpoints. The token can probably still be used with ' +
            'its target service — pull the API docs for the audience shown ' +
            'above and craft a request manually.'
        )
      );
    } else {
      wrap.appendChild(
        h(
          'div',
          { class: 'entra-help' },
          'These are read-only queries against the audience your token is ' +
            'bound to. They enumerate what this token actually unlocks ' +
            '(identity, mailbox / files / calendar, group memberships, role ' +
            'assignments). Run only on systems you have authorisation to test.'
        )
      );
    }

    const reconResults = h('div', { class: 'entra-recon-results' });

    // 1) Buttons for groups the token CAN reach — primary, grouped under
    //    section headings so the resource binding is explicit.
    for (const [group, endpoints] of Object.entries(matchedByGroup)) {
      wrap.appendChild(
        h(
          'div',
          { class: 'entra-recon-group-head' },
          h('span', { class: 'entra-recon-group-dot ok' }, '●'),
          h('span', {}, group),
          h('span', { class: 'entra-recon-group-note' }, '— token audience matches')
        )
      );
      const buttons = h('div', { class: 'entra-recon-buttons' });
      for (const ep of endpoints) {
        if (ep.isTemplate) {
          // Template URLs (need a tenant hostname substitution) get a
          // distinct ghost-style button + a tooltip explaining.
          buttons.appendChild(
            h(
              'button',
              {
                class: 'btn ghost',
                title: ep.description + '\n\nTemplate URL: ' + ep.url +
                  '\nrequires: ' + ep.requires +
                  '\n\nClicking copies the URL for you to edit.',
                onClick: async () => {
                  try {
                    await navigator.clipboard.writeText(ep.url);
                    toast('Template URL copied — substitute the tenant hostname', 'ok');
                  } catch {
                    toast('Clipboard blocked', 'err');
                  }
                },
              },
              ep.name
            )
          );
        } else {
          buttons.appendChild(
            h(
              'button',
              {
                class: 'btn',
                title: ep.description + '\n\nGET ' + ep.url + '\nrequires: ' + ep.requires,
                onClick: () => this.runEntraRecon(reconResults, ep, rawToken),
              },
              ep.name
            )
          );
        }
      }
      wrap.appendChild(buttons);
    }

    // 2) Audience-confusion test — always available, doesn't care which
    //    audience the token claims since that's the whole point of the test.
    wrap.appendChild(
      h(
        'div',
        { class: 'entra-recon-group-head' },
        h('span', { class: 'entra-recon-group-dot warn' }, '●'),
        h('span', {}, 'Cross-audience test'),
        h('span', { class: 'entra-recon-group-note' }, '— probes for missing audience binding')
      )
    );
    wrap.appendChild(
      h(
        'div',
        { class: 'entra-recon-buttons' },
        h(
          'button',
          {
            class: 'btn',
            style: { borderColor: 'var(--warn)' },
            title: 'Fire the captured token against several Microsoft endpoints to test for audience confusion. ' +
              'Servers should reject — but some do not. A 2xx is a vulnerability finding.',
            onClick: () => this.runEntraAudienceConfusion(reconResults, rawToken),
          },
          '⚔ Test audience confusion'
        )
      )
    );

    // 3) Endpoints that the token CANNOT reach — collapsed by default,
    //    shown so the user knows what they're missing and what audience
    //    they'd need to capture.
    if (unmatched.length > 0) {
      const details = h('details', { class: 'entra-recon-unavailable' });
      details.appendChild(
        h(
          'summary',
          {},
          'Other recon endpoints (need a different audience) — ' + unmatched.length + ' available'
        )
      );
      for (const [group, endpoints] of Object.entries(unmatchedByGroup)) {
        details.appendChild(
          h(
            'div',
            { class: 'entra-recon-group-head dimmed' },
            h('span', { class: 'entra-recon-group-dot err' }, '●'),
            h('span', {}, group),
            h(
              'span',
              { class: 'entra-recon-group-note' },
              '— need token with aud=' +
                (endpoints[0].audiences[0].length > 50
                  ? endpoints[0].audiences[0].slice(0, 50) + '…'
                  : endpoints[0].audiences[0])
            )
          )
        );
        const buttons = h('div', { class: 'entra-recon-buttons' });
        for (const ep of endpoints) {
          buttons.appendChild(
            h(
              'button',
              {
                class: 'btn ghost',
                disabled: true,
                title:
                  ep.description +
                  '\n\nDisabled — your token\'s audience doesn\'t match. Capture a ' +
                  'token for ' + group + ' to enable this query.\n\nGET ' + ep.url,
              },
              ep.name
            )
          );
        }
        details.appendChild(buttons);
      }
      wrap.appendChild(details);
    }

    wrap.appendChild(reconResults);

    // ---- FOCI refresh-token exchange ------------------------------------
    //
    // The big GraphSpy / ROADtools move. Microsoft first-party clients
    // share a refresh-token "family" — a refresh token issued to one FOCI
    // client can be redeemed for an access token belonging to any other
    // FOCI client. So a refresh token captured from Outlook can be swapped
    // for a Graph token, an Azure CLI token, a SharePoint token, etc.
    //
    // We always show the panel (user might want to paste any refresh
    // token, not just the one matching this access token), but highlight
    // when the current access token's appid IS a known FOCI client.
    wrap.appendChild(this.renderFOCIPanel(decoded));

    return wrap;
  }

  renderFOCIPanel(decoded) {
    const issuerClient = decoded?.payload?.appid || decoded?.payload?.azp || '';
    const knownFoci = isLikelyFOCIClient(issuerClient);
    const tenantId = decoded?.payload?.tid || '';

    const panel = h('div', { class: 'foci-panel' });
    panel.appendChild(
      h(
        'div',
        { class: 'foci-panel-head' },
        h('span', {}, '🔁 FOCI refresh-token exchange'),
        knownFoci
          ? h(
              'span',
              { class: 'badge valid', style: { marginLeft: 'auto' } },
              'FOCI family detected'
            )
          : null
      )
    );
    panel.appendChild(
      h(
        'div',
        { class: 'foci-panel-desc' },
        knownFoci
          ? "This token's issuing client (" + issuerClient + ') is a known ' +
            'Family-of-Client-IDs (FOCI) member. If you have its refresh ' +
            'token, you can exchange it for access tokens to any other FOCI ' +
            'client — Graph, Outlook, Teams, Azure CLI, SharePoint, etc.'
          : 'Microsoft first-party clients share a refresh-token family. ' +
            'Paste any FOCI refresh token below and exchange it for an ' +
            'access token to a different Microsoft service. The captured ' +
            'access token doesn\'t tell us if its companion refresh token ' +
            'is FOCI — but most Microsoft tokens are. Try it and see.'
      )
    );

    // Refresh token input (user pastes; we don't auto-fill because the
    // access token doesn't contain the refresh token)
    const rtInput = h('textarea', {
      class: 'textarea code',
      placeholder: 'Paste the refresh token here (look for it in Tokens tab → Refresh tokens)',
      style: { minHeight: '50px', fontSize: '10.5px', marginBottom: '8px' },
    });
    panel.appendChild(rtInput);

    // Target client + tenant inputs
    const targetSelect = h('select', { class: 'foci-client-select' });
    targetSelect.appendChild(h('option', { value: '' }, '— pick a target service —'));
    for (const c of FOCI_CLIENTS) {
      targetSelect.appendChild(
        h(
          'option',
          { value: c.id, title: c.notes || '' },
          c.name + ' → ' + c.targetService
        )
      );
    }
    // Default pick: pivot away from the current audience
    const auds = []
      .concat(decoded?.payload?.aud || [])
      .map((a) => String(a || '').toLowerCase());
    if (auds.some((a) => a.includes('outlook.office'))) {
      targetSelect.value = FOCI_CLIENTS[0].id; // Office → Graph
    } else if (auds.some((a) => a.includes('graph.microsoft'))) {
      targetSelect.value = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; // Azure CLI
    }

    const tenantInput = h('input', {
      class: 'foci-tenant-input',
      placeholder: 'Tenant ID (or "common")',
      value: tenantId || 'common',
      style: { width: '160px' },
    });

    panel.appendChild(
      h(
        'div',
        { class: 'foci-panel-controls' },
        targetSelect,
        tenantInput
      )
    );

    const results = h('div', { class: 'foci-results' });

    panel.appendChild(
      h(
        'button',
        {
          class: 'btn primary',
          style: { width: '100%', fontSize: '11.5px' },
          onClick: async () => {
            const rt = rtInput.value.trim();
            const clientId = targetSelect.value;
            const tenant = tenantInput.value.trim() || 'common';
            if (!rt) {
              toast('Paste a refresh token first', 'warn');
              return;
            }
            if (!clientId) {
              toast('Pick a target service', 'warn');
              return;
            }
            const target = FOCI_CLIENTS.find((c) => c.id === clientId);
            await this.runFOCIExchange(results, rt, target, tenant);
          },
        },
        'Exchange refresh token →'
      )
    );

    panel.appendChild(results);

    return panel;
  }

  async runFOCIExchange(host, refreshToken, target, tenantId) {
    const card = h('div', { class: 'foci-result-row' });
    card.appendChild(
      h(
        'div',
        { class: 'foci-result-head' },
        '… exchanging for ' + target.name + ' (' + target.targetService + ')'
      )
    );
    host.appendChild(card);

    const r = await entraApi.refreshFOCI({
      refreshToken,
      clientId: target.id,
      scope: target.suggestedScope,
      tenantId,
    });

    card.innerHTML = '';

    if (!r.ok) {
      card.className = 'foci-result-row err';
      const errBody = r.body || {};
      const errMsg = errBody.error_description || errBody.error || r.error || ('HTTP ' + r.status);
      card.appendChild(
        h(
          'div',
          { class: 'foci-result-head' },
          '✗ ' + target.name + ' — failed'
        )
      );
      card.appendChild(
        h('div', { class: 'foci-result-token' }, errMsg)
      );
      // Common error: AADSTS54005 (no FOCI relationship)
      if (/AADSTS50173|AADSTS54005|AADSTS70011|invalid_grant/.test(errMsg)) {
        card.appendChild(
          h(
            'div',
            {
              class: 'foci-result-token',
              style: { color: 'var(--warn)', marginTop: '6px' },
            },
            '💡 This usually means the refresh token isn\'t FOCI-eligible ' +
              'for this target (no family relationship), the token is expired, ' +
              'or the tenant\'s Conditional Access blocked the swap. Try ' +
              'a different target client.'
          )
        );
      }
      return;
    }

    const body = r.body || {};
    if (body.access_token) {
      card.appendChild(
        h(
          'div',
          { class: 'foci-result-head' },
          '✓ ' + target.name + ' — new access token (' + (body.expires_in || '?') + 's)'
        )
      );
      let decoded = null;
      try { decoded = decodeJWT(body.access_token); } catch {}
      if (decoded?.payload) {
        const claims = [];
        if (decoded.payload.aud) claims.push('aud=' + (Array.isArray(decoded.payload.aud) ? decoded.payload.aud.join(',') : decoded.payload.aud));
        if (decoded.payload.scp) claims.push('scp=' + decoded.payload.scp);
        if (decoded.payload.roles) claims.push('roles=' + (Array.isArray(decoded.payload.roles) ? decoded.payload.roles.join(',') : decoded.payload.roles));
        if (claims.length) {
          card.appendChild(
            h(
              'div',
              { style: { fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '4px' } },
              claims.join(' · ')
            )
          );
        }
      }
      card.appendChild(
        h(
          'div',
          { class: 'foci-result-token' },
          body.access_token
        )
      );
      const actions = h(
        'div',
        { style: { display: 'flex', gap: '6px', marginTop: '8px' } },
        h(
          'button',
          {
            class: 'btn',
            style: { fontSize: '10.5px', padding: '3px 8px' },
            onClick: async () => {
              try {
                await navigator.clipboard.writeText(body.access_token);
                toast('Access token copied', 'ok');
              } catch {
                toast('Clipboard blocked', 'err');
              }
            },
          },
          'Copy access token'
        )
      );
      if (body.refresh_token) {
        actions.appendChild(
          h(
            'button',
            {
              class: 'btn ghost',
              style: { fontSize: '10.5px', padding: '3px 8px' },
              onClick: async () => {
                try {
                  await navigator.clipboard.writeText(body.refresh_token);
                  toast('New refresh token copied (chain pivots)', 'ok');
                } catch {
                  toast('Clipboard blocked', 'err');
                }
              },
            },
            'Copy new refresh token'
          )
        );
      }
      card.appendChild(actions);
    } else {
      card.className = 'foci-result-row err';
      card.appendChild(h('div', { class: 'foci-result-head' }, 'Unexpected response'));
      card.appendChild(
        h('div', { class: 'foci-result-token' }, JSON.stringify(body).slice(0, 500))
      );
    }
  }

  entraField(label, value) {
    return h(
      'div',
      { class: 'entra-field' },
      h('div', { class: 'entra-field-label' }, label),
      h('div', { class: 'entra-field-value', title: String(value || '') }, value || '—')
    );
  }

  async runEntraRecon(host, endpoint, token) {
    const card = h('div', { class: 'entra-recon-card' });
    card.appendChild(
      h(
        'div',
        { class: 'entra-recon-card-head' },
        h('strong', {}, endpoint.name),
        h('span', { class: 'entra-recon-card-url' }, endpoint.url)
      )
    );
    const body = h('div', { class: 'entra-recon-card-body' }, 'running…');
    card.appendChild(body);
    host.prepend(card); // newest first

    try {
      const r = await entraApi.graphFetch({ url: endpoint.url, token });
      body.innerHTML = '';
      if (!r.ok) {
        const note = h('div', {});
        if (r.status === 401) {
          note.appendChild(h('div', { class: 'entra-recon-status err' }, '401 Unauthorized — token rejected'));
          note.appendChild(h('div', { class: 'entra-recon-help' },
            'The token isn\'t valid for this resource. Likely the audience (aud) is for a different ' +
            'Microsoft service, or the token has expired.'));
        } else if (r.status === 403) {
          note.appendChild(h('div', { class: 'entra-recon-status warn' }, '403 Forbidden — token valid, scope insufficient'));
          note.appendChild(h('div', { class: 'entra-recon-help' },
            'The token is authentic but lacks the required scope: ' + endpoint.requires + '. ' +
            'This is the boundary of the principal\'s privilege for this operation.'));
        } else if (r.status === 0) {
          note.appendChild(h('div', { class: 'entra-recon-status err' }, 'Network error: ' + (r.error || 'unknown')));
        } else {
          note.appendChild(h('div', { class: 'entra-recon-status warn' }, r.status + ' ' + (r.statusText || '')));
          if (r.bodyText) note.appendChild(h('pre', { class: 'entra-recon-body' }, r.bodyText.slice(0, 600)));
        }
        body.appendChild(note);
      } else {
        body.appendChild(h('div', { class: 'entra-recon-status ok' }, r.status + ' OK · ' + r.durationMs + 'ms'));
        // Inline summary of common Graph response shapes
        const summary = this.summarizeGraphResponse(endpoint.id, r.body);
        if (summary) body.appendChild(summary);
        body.appendChild(
          h('details', {},
            h('summary', { style: { fontSize: '11px', cursor: 'pointer', color: 'var(--text-muted)' } }, 'Raw JSON'),
            h('pre', { class: 'entra-recon-body' }, JSON.stringify(r.body, null, 2))
          )
        );
      }
    } catch (e) {
      body.innerHTML = '';
      body.appendChild(h('div', { class: 'entra-recon-status err' }, 'Fetch failed: ' + e.message));
    }
  }

  /** Pull the most interesting field(s) from each Graph response shape. */
  summarizeGraphResponse(endpointId, json) {
    if (!json || typeof json !== 'object') return null;
    const lines = [];
    if (endpointId === 'me') {
      if (json.displayName) lines.push('Name: ' + json.displayName);
      if (json.userPrincipalName) lines.push('UPN: ' + json.userPrincipalName);
      if (json.jobTitle) lines.push('Title: ' + json.jobTitle);
      if (json.officeLocation) lines.push('Office: ' + json.officeLocation);
      if (json.id) lines.push('Object id: ' + json.id);
    } else if (endpointId === 'me-memberof' || endpointId === 'me-transitive') {
      const groups = (json.value || []).filter((x) => x['@odata.type'] === '#microsoft.graph.group');
      const roles = (json.value || []).filter((x) => x['@odata.type'] === '#microsoft.graph.directoryRole');
      lines.push(`${groups.length} groups, ${roles.length} directory roles`);
      for (const r of roles) lines.push('  ROLE: ' + r.displayName);
      for (const g of groups.slice(0, 10)) lines.push('  group: ' + g.displayName);
      if (groups.length > 10) lines.push(`  …and ${groups.length - 10} more`);
    } else if (endpointId === 'users-list') {
      const users = json.value || [];
      lines.push(`Listed ${users.length} users — strong privilege signal.`);
      for (const u of users.slice(0, 5)) lines.push('  ' + u.userPrincipalName + ' — ' + u.displayName);
    } else if (endpointId === 'apps-list') {
      const apps = json.value || [];
      lines.push(`Listed ${apps.length} app registrations — strong privilege signal.`);
      for (const a of apps.slice(0, 5)) lines.push('  ' + a.appId + ' — ' + a.displayName);
    } else if (endpointId === 'role-assignments') {
      const assigns = json.value || [];
      lines.push(`${assigns.length} role assignments visible — critical privilege signal.`);
    } else if (endpointId === 'conditional-access') {
      const policies = json.value || [];
      lines.push(`${policies.length} Conditional Access policies visible — admin-tier signal.`);
      for (const p of policies.slice(0, 5)) lines.push('  ' + (p.displayName || '(unnamed)') + ' — ' + p.state);
    } else if (endpointId === 'me-mfa') {
      const methods = json.value || [];
      lines.push(`${methods.length} authentication methods registered.`);
      for (const m of methods) lines.push('  ' + m['@odata.type']);
    } else if (endpointId === 'me-drive') {
      const files = json.value || [];
      lines.push(`${files.length} items at OneDrive root.`);
      for (const f of files.slice(0, 10)) lines.push('  ' + f.name + (f.folder ? ' /' : ''));
    } else if (endpointId === 'me-messages') {
      const msgs = json.value || [];
      lines.push(`${msgs.length} recent messages.`);
      for (const m of msgs) lines.push('  [' + (m.receivedDateTime || '').slice(0, 16) + '] ' + (m.from?.emailAddress?.address || '?') + ' → ' + m.subject);
    } else if (endpointId === 'directory-roles') {
      const roles = json.value || [];
      lines.push(`${roles.length} activated directory roles.`);
      for (const r of roles.slice(0, 10)) lines.push('  ' + r.displayName);
    }
    if (!lines.length) return null;
    return h('pre', { class: 'entra-recon-summary' }, lines.join('\n'));
  }

  /**
   * Audience-confusion test: fire the captured token at several Microsoft
   * endpoints to see if any unintended resource accepts it. Classic AAD
   * misconfiguration where one app accepts tokens issued for another.
   */
  async runEntraAudienceConfusion(host, token) {
    const card = h('div', { class: 'entra-recon-card' });
    card.appendChild(
      h(
        'div',
        { class: 'entra-recon-card-head' },
        h('strong', {}, '⚔ Audience confusion sweep'),
        h('span', { class: 'entra-recon-card-url' }, AUDIENCE_CONFUSION_TARGETS.length + ' targets')
      )
    );
    const body = h('div', { class: 'entra-recon-card-body' });
    card.appendChild(body);
    host.prepend(card);

    const table = h('div', { class: 'replay-table' });
    table.appendChild(
      h(
        'div',
        { class: 'replay-row replay-row-head' },
        h('div', { class: 'rr-name' }, 'Target resource'),
        h('div', { class: 'rr-status' }, 'Status'),
        h('div', { class: 'rr-verdict' }, 'Verdict')
      )
    );
    body.appendChild(table);

    for (const target of AUDIENCE_CONFUSION_TARGETS) {
      const row = h(
        'div',
        { class: 'replay-row' },
        h('div', { class: 'rr-name' }, target.name,
          h('div', { style: { fontSize: '10px', color: 'var(--text-faint)' } }, target.url)),
        h('div', { class: 'rr-status' }, '…'),
        h('div', { class: 'rr-verdict' }, 'running')
      );
      table.appendChild(row);

      let r;
      try {
        r = await entraApi.graphFetch({ url: target.url, token });
      } catch (e) {
        r = { ok: false, status: 0, error: e.message };
      }
      const statusEl = row.querySelector('.rr-status');
      const verdictEl = row.querySelector('.rr-verdict');
      statusEl.textContent = (r.status || 0) + (r.durationMs ? ` (${r.durationMs}ms)` : '');
      if (r.status === 401) {
        statusEl.className = 'rr-status ok';
        verdictEl.textContent = 'token rejected for this audience (good)';
        verdictEl.className = 'rr-verdict ok';
      } else if (r.status === 403) {
        statusEl.className = 'rr-status warn';
        verdictEl.textContent = 'accepted but scope insufficient — audience IS accepted';
        verdictEl.className = 'rr-verdict warn';
      } else if (r.ok) {
        statusEl.className = 'rr-status err';
        verdictEl.innerHTML = '⚠ <strong>ACCEPTED</strong> — token usable against ' + target.name;
        verdictEl.className = 'rr-verdict err';
      } else {
        statusEl.className = 'rr-status warn';
        verdictEl.textContent = 'inconclusive: ' + (r.error || r.status);
        verdictEl.className = 'rr-verdict warn';
      }
    }
  }

  renderHeaderBlock(label, value) {
    const wrap = h('div', { style: { marginBottom: '6px' } });
    wrap.appendChild(
      h('div', { style: { fontSize: '11.5px', color: 'var(--text-muted)', marginBottom: '2px' } }, label)
    );
    const ta = h(
      'textarea',
      {
        class: 'textarea code',
        readonly: true,
        style: { minHeight: '40px', fontSize: '11px' },
      },
      value
    );
    wrap.appendChild(ta);
    return wrap;
  }

  // ---------- Snapshots UI ----------------------------------------------------

  renderSnapshots() {
    const ids = Object.keys(this.snapshots).filter((id) =>
      this.matchesSearch(id, JSON.stringify(this.snapshots[id]).slice(0, 1000))
    );
    this.refs.body.appendChild(
      h(
        'div',
        { class: 'toolbar', style: { borderTop: 'none' } },
        h(
          'button',
          { class: 'btn primary', onClick: () => this.captureSnapshot() },
          '📸 Capture current state'
        ),
        h('div', { class: 'spacer' })
      )
    );
    if (!ids.length) {
      this.refs.body.appendChild(
        emptyState(
          'No snapshots',
          'Capture the current cookies + storage so you can restore the page state later.'
        )
      );
      return;
    }
    const list = h('div', { class: 'list', style: { padding: '0 12px 12px' } });
    for (const id of ids) {
      list.appendChild(this.renderSnapshotRow(id, this.snapshots[id]));
    }
    this.refs.body.appendChild(list);
  }

  renderSnapshotRow(id, snap) {
    const date = new Date(snap.capturedAt);
    return h(
      'div',
      { class: 'row', style: { cursor: 'default' } },
      h(
        'div',
        { class: 'row-name' },
        id,
        h(
          'div',
          {
            style: {
              fontSize: '10px',
              color: 'var(--text-faint)',
              fontWeight: '400',
            },
          },
          date.toLocaleString()
        )
      ),
      h(
        'div',
        { class: 'row-value' },
        `${snap.cookies?.length || 0} cookies, ` +
          `${snap.localStorage?.length || 0} LS, ` +
          `${snap.sessionStorage?.length || 0} SS`
      ),
      h(
        'div',
        { class: 'row-badges' },
        h(
          'button',
          { class: 'btn primary', onClick: () => this.restoreSnapshot(id, snap) },
          'Restore'
        ),
        h(
          'button',
          {
            class: 'btn danger ghost',
            onClick: async () => {
              if (
                !(await confirmModal(
                  'Delete snapshot?',
                  `“${id}” will be erased.`,
                  { okLabel: 'Delete', danger: true }
                ))
              )
                return;
              await snapshotsApi.delete(id);
              await this.loadSnapshots();
              this.updateTabCounts();
              this.renderActiveTab();
              toast('Snapshot deleted');
            },
          },
          '✕'
        )
      )
    );
  }

  async captureSnapshot() {
    const name = prompt(
      'Snapshot name:',
      `${new URL(this.currentTab.url).hostname} · ${new Date().toLocaleTimeString()}`
    );
    if (!name) return;
    try {
      const snap = await snapshotsApi.capture(this.currentTab.id, this.currentTab.url);
      await snapshotsApi.save(name, snap);
      await this.loadSnapshots();
      this.updateTabCounts();
      this.renderActiveTab();
      toast(`Snapshot “${name}” saved`);
    } catch (e) {
      toast('Capture failed: ' + e.message, 'err');
    }
  }

  async restoreSnapshot(id, snap) {
    if (
      !(await confirmModal(
        'Restore snapshot?',
        h(
          'div',
          {},
          h(
            'p',
            { style: { margin: '0 0 8px' } },
            `“${id}” will overwrite the current page's cookies and storage:`
          ),
          h(
            'ul',
            { style: { margin: 0, paddingLeft: '20px' } },
            h('li', {}, `${snap.cookies?.length || 0} cookies`),
            h('li', {}, `${snap.localStorage?.length || 0} localStorage entries`),
            h('li', {}, `${snap.sessionStorage?.length || 0} sessionStorage entries`)
          )
        ),
        { okLabel: 'Restore' }
      ))
    )
      return;
    try {
      // Cookies
      // First, wipe existing cookies for this URL to mirror the captured state.
      for (const c of this.cookies) {
        await cookiesApi.remove({ name: c.name, url: buildCookieUrl(c) });
      }
      for (const c of snap.cookies || []) {
        const { storeId, ...rest } = c;
        await cookiesApi.set({ ...rest, url: buildCookieUrl(c) });
      }
      // LocalStorage / SessionStorage: clear then write
      await localStorageApi.clear(this.currentTab.id);
      for (const e of snap.localStorage || []) {
        await localStorageApi.set(this.currentTab.id, e.key, e.value);
      }
      await sessionStorageApi.clear(this.currentTab.id);
      for (const e of snap.sessionStorage || []) {
        await sessionStorageApi.set(this.currentTab.id, e.key, e.value);
      }
      await this.refreshCurrentTab();
      toast(`Restored “${id}”`);
    } catch (e) {
      toast('Restore failed: ' + e.message, 'err');
    }
  }

  // ---------- New / bulk operations -------------------------------------------

  openNewItemEditor() {
    switch (this.activeStorageTab) {
      case 'cookies': {
        // Create a stub cookie at the current URL, then expand its editor.
        const url = new URL(this.currentTab.url);
        const stub = {
          name: 'new_cookie',
          value: '',
          domain: url.hostname,
          path: '/',
          secure: url.protocol === 'https:',
          httpOnly: false,
          sameSite: 'lax',
          hostOnly: false,
        };
        this.cookies.unshift(stub);
        this.expandedRowId =
          'cookie:' + stub.name + '@' + stub.domain + stub.path;
        this.renderActiveTab();
        break;
      }
      case 'localStorage':
      case 'sessionStorage': {
        const list =
          this.activeStorageTab === 'localStorage' ? this.localStorage : this.sessionStorage;
        const stub = { key: 'new_key', value: '' };
        list.unshift(stub);
        this.expandedRowId = this.activeStorageTab + ':' + stub.key;
        this.renderActiveTab();
        break;
      }
    }
  }

  async deleteAllInActiveTab() {
    const kind = this.activeStorageTab;
    let label = kind;
    if (kind === 'cookies') label = 'cookies';
    if (kind === 'localStorage') label = 'localStorage entries';
    if (kind === 'sessionStorage') label = 'sessionStorage entries';
    if (
      !(await confirmModal(
        `Delete all ${label}?`,
        'This cannot be undone (history will be cleared).',
        { okLabel: 'Delete all', danger: true }
      ))
    )
      return;
    try {
      if (kind === 'cookies') {
        for (const c of this.cookies) {
          await cookiesApi.remove({ name: c.name, url: buildCookieUrl(c) });
        }
        await this.loadCookies();
      } else if (kind === 'localStorage') {
        await localStorageApi.clear(this.currentTab.id);
        await this.loadLocalStorage();
      } else if (kind === 'sessionStorage') {
        await sessionStorageApi.clear(this.currentTab.id);
        await this.loadSessionStorage();
      }
      this.history.clear();
      this.updateTabCounts();
      this.renderActiveTab();
      toast(`All ${label} deleted`);
    } catch (e) {
      toast('Delete failed: ' + e.message, 'err');
    }
  }

  copyCurrentAsHeader() {
    const text = HeaderLine.format(this.cookies);
    navigator.clipboard.writeText(text).then(
      () => toast('Cookie header copied'),
      () => toast('Clipboard write failed', 'err')
    );
  }

  // ---------- Import / Export -------------------------------------------------

  openExportModal() {
    const kind = this.activeStorageTab;
    let text = '';
    let format = 'JSON';
    if (kind === 'cookies') {
      text = Json.format(this.cookies);
    } else if (kind === 'localStorage') {
      text = StorageJson.format(this.localStorage);
    } else if (kind === 'sessionStorage') {
      text = StorageJson.format(this.sessionStorage);
    }
    const ta = h('textarea', { class: 'textarea', readOnly: true });
    ta.value = text;
    ta.style.minHeight = '300px';

    const selector =
      kind === 'cookies'
        ? h(
            'select',
            {
              class: 'input',
              style: { marginBottom: '8px' },
              onchange: (e) => {
                format = e.target.value;
                if (format === 'JSON') ta.value = Json.format(this.cookies);
                else if (format === 'Netscape')
                  ta.value = Netscape.format(this.cookies);
                else if (format === 'Header')
                  ta.value = HeaderLine.format(this.cookies);
                else if (format === 'cURL')
                  ta.value = Curl.format(this.cookies, this.currentTab.url);
              },
            },
            ...['JSON', 'Netscape', 'Header', 'cURL'].map((f) =>
              h('option', { value: f }, f)
            )
          )
        : null;

    const body = h(
      'div',
      {},
      h('label', {}, 'Format'),
      selector || h('div', { class: 'mono' }, 'JSON'),
      h('label', { style: { marginTop: '8px' } }, 'Export'),
      ta
    );
    confirmModalWithCustom('Export ' + kind, body, [
      {
        label: 'Copy',
        primary: true,
        action: () =>
          navigator.clipboard.writeText(ta.value).then(() => toast('Copied')),
      },
      {
        label: 'Download',
        action: () => downloadAsFile(ta.value, exportFilename(kind, format)),
      },
      { label: 'Close', dismiss: true },
    ]);
  }

  openImportModal() {
    const kind = this.activeStorageTab;
    const ta = h('textarea', {
      class: 'textarea',
      placeholder:
        kind === 'cookies'
          ? 'Paste JSON, Netscape (cookies.txt), or a "Cookie: …" header line'
          : 'Paste a JSON object: { "key": "value", … }',
      style: { minHeight: '240px' },
    });

    let pendingFormat = 'auto';
    const help = h(
      'div',
      { class: 'mono', style: { fontSize: '11px', color: 'var(--text-faint)', marginTop: '4px' } },
      kind === 'cookies' ? 'Format auto-detected' : 'Format: JSON object'
    );

    confirmModalWithCustom(
      'Import ' + kind,
      h('div', {}, h('label', {}, 'Paste data'), ta, help),
      [
        {
          label: 'Import',
          primary: true,
          action: async () => {
            try {
              if (kind === 'cookies') {
                const parsed = detectAndParseCookieFormat(ta.value);
                for (const c of parsed) {
                  const url =
                    c.url ||
                    (this.currentTab && this.currentTab.url) ||
                    `https://${c.domain.replace(/^\./, '')}${c.path || '/'}`;
                  const { storeId, ...rest } = c;
                  await cookiesApi.set({ ...rest, url });
                }
                await this.loadCookies();
              } else {
                const list = StorageJson.parse(ta.value);
                const api = kind === 'localStorage' ? localStorageApi : sessionStorageApi;
                for (const e of list) {
                  await api.set(this.currentTab.id, e.key, e.value);
                }
                if (kind === 'localStorage') await this.loadLocalStorage();
                else await this.loadSessionStorage();
              }
              this.updateTabCounts();
              this.renderActiveTab();
              toast('Imported successfully');
              document.querySelector('.modal-backdrop')?.remove();
            } catch (e) {
              toast('Import failed: ' + e.message, 'err');
            }
          },
        },
        { label: 'Cancel', dismiss: true },
      ]
    );
  }

  // ---------- Misc -------------------------------------------------------------

  matchesSearch(...fields) {
    if (!this.searchTerm) return true;
    return fields.some((f) =>
      String(f || '')
        .toLowerCase()
        .includes(this.searchTerm)
    );
  }

  async undo() {
    try {
      const entry = await this.history.undo();
      if (entry) {
        toast(`Undid: ${entry.description}`);
        await this.refreshActiveTab();
      }
    } catch (e) {
      toast('Undo failed: ' + e.message, 'err');
    }
  }

  async redo() {
    try {
      const entry = await this.history.redo();
      if (entry) {
        toast(`Redid: ${entry.description}`);
        await this.refreshActiveTab();
      }
    } catch (e) {
      toast('Redo failed: ' + e.message, 'err');
    }
  }

  toggleTheme() {
    const cur = document.documentElement.dataset.theme || 'light';
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    this.settings.theme = next;
    settingsApi.set(this.settings).catch(() => {});
  }
}

// ---------- Helpers exported only for tests / clarity -----------------------

function buildCookieUrl(cookie) {
  const protocol = cookie.secure ? 'https://' : 'http://';
  const domain = (cookie.domain || '').replace(/^\./, '');
  const path = cookie.path || '/';
  return protocol + domain + path;
}

function looksLikeJson(v) {
  if (typeof v !== 'string') return false;
  const t = v.trim();
  if (!t.startsWith('{') && !t.startsWith('[')) return false;
  try {
    JSON.parse(t);
    return true;
  } catch {
    return false;
  }
}

function formatDuration(seconds) {
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) return Math.round(seconds / 60) + 'm';
  if (seconds < 86400) return Math.round(seconds / 3600) + 'h';
  return Math.round(seconds / 86400) + 'd';
}

function emptyState(title, body) {
  return h('div', { class: 'empty' }, h('h3', {}, title), body);
}

function detectAndParseCookieFormat(text) {
  const t = text.trim();
  if (!t) throw new Error('Empty input');
  if (t.startsWith('[') || t.startsWith('{')) {
    return Json.parse(t);
  }
  if (t.startsWith('#') || /\n.*\t.*\t/.test(t)) {
    return Netscape.parse(t);
  }
  // Fall back to a header line "Cookie: a=1; b=2" or just "a=1; b=2"
  const stripped = t.replace(/^Cookie:\s*/i, '');
  const parts = HeaderLine.parse(stripped);
  // Header lines lack domain/path; caller will fill in the current URL.
  return parts.map((p) => ({ ...p, path: '/', secure: false }));
}

function downloadAsFile(text, filename) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function exportFilename(kind, format) {
  const ext =
    format === 'Netscape' ? 'txt' : format === 'cURL' ? 'sh' : 'json';
  return `${kind}-${Date.now()}.${ext}`;
}

/**
 * Like confirmModal but lets the caller define an arbitrary set of footer
 * buttons. Used for the import/export workflows that have more than 2
 * actions.
 */
function confirmModalWithCustom(title, body, buttons) {
  const close = () => {
    backdrop.remove();
    document.removeEventListener('keydown', onKey);
  };
  const onKey = (e) => e.key === 'Escape' && close();
  const footerButtons = buttons.map((btn) =>
    h(
      'button',
      {
        class: 'btn ' + (btn.primary ? 'primary' : ''),
        onClick: async () => {
          if (btn.action) await btn.action();
          if (btn.dismiss) close();
        },
      },
      btn.label
    )
  );
  const backdrop = h(
    'div',
    { class: 'modal-backdrop', onClick: (e) => e.target === backdrop && close() },
    h(
      'div',
      { class: 'modal' },
      h(
        'header',
        {},
        h('h2', {}, title),
        h('button', { class: 'btn ghost icon', onClick: close }, '✕')
      ),
      h('div', { class: 'body' }, body),
      h('footer', {}, ...footerButtons)
    )
  );
  document.body.appendChild(backdrop);
  document.addEventListener('keydown', onKey);
}
