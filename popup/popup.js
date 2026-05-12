/**
 * AuthForge — popup entry point.
 *
 * Shared with the "Open in full window" mode, distinguished by the
 * ?wide=1 query parameter. When set, popup.css's .wide-mode kicks in and
 * the content flexes to fill the window instead of staying at 720px.
 *
 * Wide-mode also accepts state in the URL so opening the wider window
 * preserves the user's place — same tab being inspected, same scope,
 * same active storage tab, same search term. Previously the wide window
 * opened "empty" (i.e., to its own popup chrome-extension:// URL as the
 * current tab, which showed the "Browser-internal page" empty state).
 */

import { AuthForgeApp } from '../shared/ui.js';
import { applyI18nAttrs } from '../shared/i18n.js';

// Apply data-i18n attributes (title + header tooltips). Run before mount
// so the popup chrome is in the user's locale from the first frame.
applyI18nAttrs(document);
try {
  const uiLang = chrome?.i18n?.getUILanguage?.();
  if (uiLang) document.documentElement.lang = uiLang;
} catch {}

const params = new URLSearchParams(location.search);
const isWide = params.get('wide') === '1';
if (isWide) {
  document.documentElement.classList.add('wide-mode');
}

// Build constructor options from URL params.
//   ?tabId=<n>           pin the inspected tab (otherwise wide window would
//                        detect itself as the current tab)
const opts = { surface: isWide ? 'wide' : 'popup' };
const tabIdParam = params.get('tabId');
if (tabIdParam && /^\d+$/.test(tabIdParam)) {
  opts.tabId = Number(tabIdParam);
}

const app = new AuthForgeApp(document.getElementById('app'), opts);

// Pre-seed state from URL params BEFORE mount() runs, so the first render
// already reflects what the user was looking at.
const scope = params.get('scope');
if (scope === 'allDomains') {
  app.cookieScope = { mode: 'allDomains', customUrl: '' };
} else if (scope === 'customUrl') {
  app.cookieScope = { mode: 'customUrl', customUrl: params.get('customUrl') || '' };
}
const activeTabParam = params.get('tab');
if (activeTabParam) {
  app.activeStorageTab = activeTabParam;
}
const searchParam = params.get('q');
if (searchParam) {
  app.searchTerm = searchParam;
}

app.mount().catch((e) => {
  console.error('Mount failed:', e);
  document.getElementById('app').innerHTML =
    '<div class="empty"><h3>Failed to start</h3>' +
    (e.message || String(e)).replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c])) +
    '</div>';
});

document.getElementById('open-options').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

document.getElementById('open-devtools-hint').addEventListener('click', () => {
  // Open the same UI in a wider window. Pass the current state so the wider
  // window opens to the same view instead of opening empty.
  const wideParams = new URLSearchParams({ wide: '1' });
  if (app.currentTab?.id != null) {
    wideParams.set('tabId', String(app.currentTab.id));
  }
  if (app.cookieScope?.mode && app.cookieScope.mode !== 'currentTab') {
    wideParams.set('scope', app.cookieScope.mode);
    if (app.cookieScope.mode === 'customUrl' && app.cookieScope.customUrl) {
      wideParams.set('customUrl', app.cookieScope.customUrl);
    }
  }
  if (app.activeStorageTab && app.activeStorageTab !== 'cookies') {
    wideParams.set('tab', app.activeStorageTab);
  }
  if (app.searchTerm) {
    wideParams.set('q', app.searchTerm);
  }
  chrome.windows.create({
    url: chrome.runtime.getURL('popup/popup.html?' + wideParams.toString()),
    type: 'popup',
    width: 1400,
    height: 900,
  });
});
