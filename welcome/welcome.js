/**
 * Welcome / onboarding page — runs in a regular browser tab on first install
 * (opened by service-worker.js via chrome.runtime.onInstalled). Has no
 * privileged operations; just CTA wiring and i18n.
 */

import { applyI18nAttrs } from '../shared/i18n.js';

// Set the <html lang="..."> attribute to the browser's UI locale so screen
// readers and CSS :lang() rules pick up the actual rendered language.
try {
  const uiLang = chrome?.i18n?.getUILanguage?.();
  if (uiLang) document.documentElement.lang = uiLang;
} catch {}

// Apply data-i18n attributes — replaces text content with the user's locale
// translation, or leaves the English fallback if the key is missing.
applyI18nAttrs(document);

document.getElementById('open-popup')?.addEventListener('click', openPopup);
document.getElementById('open-popup-2')?.addEventListener('click', openPopup);
document.getElementById('close-tab')?.addEventListener('click', () => {
  chrome.tabs.getCurrent((tab) => {
    if (tab?.id != null) chrome.tabs.remove(tab.id);
  });
});
document.getElementById('open-readme')?.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('README.md') });
});

function openPopup() {
  chrome.windows.create({
    url: chrome.runtime.getURL('popup/popup.html?wide=1'),
    type: 'popup',
    width: 1400,
    height: 900,
  });
}
