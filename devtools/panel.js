/**
 * AuthForge — DevTools panel entry point.
 *
 * Unlike the popup, the panel's "current tab" is the tab being inspected,
 * which DevTools makes available as `chrome.devtools.inspectedWindow.tabId`.
 * We pass that explicitly so the UI doesn't fall back to the (incorrect)
 * "active tab in current window".
 */

import { AuthForgeApp } from '../shared/ui.js';
import './network-body-scanner.js';

const tabId = chrome.devtools.inspectedWindow.tabId;

const app = new AuthForgeApp(document.getElementById('app'), {
  surface: 'devtools',
  tabId,
});
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

// When the user navigates the inspected tab, the page identity changes
// and our data is stale. Refresh.
chrome.devtools.network.onNavigated.addListener(() => {
  app.refreshCurrentTab();
});
