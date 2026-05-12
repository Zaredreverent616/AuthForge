/**
 * DevTools registration script. Runs in the devtools_page context (no
 * module loader available; that's why this is a plain non-module script).
 *
 * All we do here is register the panel; the panel itself loads `panel.html`,
 * which then imports our normal ES modules.
 */

chrome.devtools.panels.create(
  'AuthForge',
  '/icons/icon-32.png',
  '/devtools/panel.html',
  (panel) => {
    // Reserved for future use — could refresh on panel.onShown, etc.
  }
);
