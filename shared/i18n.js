/**
 * AuthForge i18n helper.
 *
 * Wraps chrome.i18n.getMessage with a safe fallback: if the key isn't
 * defined or chrome.i18n isn't available (e.g. when running unit tests
 * outside an extension context), returns the supplied default text.
 *
 * The user's locale is picked from Chrome's UI language automatically —
 * there is no in-app language switcher because Chrome already exposes one
 * (chrome://settings/languages).
 *
 * Usage:
 *   import { t } from './i18n.js';
 *   button.textContent = t('btnSave', 'Save');
 *
 * For HTML templates, use data-i18n="msgKey" attributes and call
 * applyI18nAttrs(document) on page load. See welcome.js for an example.
 */

export function t(key, fallback) {
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n?.getMessage) {
      const msg = chrome.i18n.getMessage(key);
      if (msg) return msg;
    }
  } catch {
    /* falls through to fallback */
  }
  // Return the supplied fallback (almost always the original English string)
  // or the key itself if no fallback was given.
  return fallback != null ? fallback : key;
}

/**
 * Apply translations to every element in `root` carrying a data-i18n
 * attribute. The attribute value is the messages.json key. Existing text
 * content is treated as the English fallback if the key is missing.
 *
 * Also handles data-i18n-attr="placeholder,title" — comma-separated list
 * of attributes that should also be translated using the same key.
 */
export function applyI18nAttrs(root = document) {
  root.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.dataset.i18n;
    if (!key) return;
    const attrs = el.dataset.i18nAttr;
    // If data-i18n-attr is set, ONLY translate those attributes — leave
    // textContent alone. Used for icon-only buttons where the visible
    // text is an emoji/glyph and the translatable label lives in
    // title / aria-label / placeholder.
    if (attrs) {
      for (const a of attrs.split(',').map((s) => s.trim()).filter(Boolean)) {
        const fallbackAttr = el.getAttribute(a) || '';
        const translated = t(key, fallbackAttr);
        if (translated) el.setAttribute(a, translated);
      }
      return;
    }
    // Default behaviour: translate textContent
    const fallback = el.textContent;
    const translated = t(key, fallback);
    if (translated && translated !== fallback) {
      el.textContent = translated;
    }
  });
}
