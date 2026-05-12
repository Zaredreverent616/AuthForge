/**
 * AuthForge — DevTools-side network body scanner.
 *
 * Hooks chrome.devtools.network.onRequestFinished — only available while
 * DevTools is open. For responses that look auth-relevant (token endpoint or
 * JSON content), we read the body and delegate the actual scanning to the
 * shared token-body-scanner module. Findings get reported back to the
 * service worker's network buffer so they appear on the Network tab.
 *
 * Companion: background/debugger-capture.js does the same job via the
 * chrome.debugger / CDP path when the user explicitly opts into deep
 * capture (with the yellow "is being debugged" banner).
 */

import { networkApi } from '../shared/api.js';
import {
  scanForTokens,
  looksLikeTokenEndpoint,
  looksLikeJsonContentType,
  MAX_SCAN_BYTES,
} from '../shared/token-body-scanner.js';

if (chrome.devtools?.network?.onRequestFinished) {
  chrome.devtools.network.onRequestFinished.addListener(handleRequestFinished);
}

function handleRequestFinished(req) {
  const url = req.request?.url || '';
  if (!url || !/^https?:/i.test(url)) return;

  const contentType = headerValue(req.response?.headers || [], 'content-type') || '';
  const isJsonish = looksLikeJsonContentType(contentType);
  const isTokenEp = looksLikeTokenEndpoint(url);
  if (!isJsonish && !isTokenEp) return;

  const bodySize = req.response?.content?.size || 0;
  if (bodySize > MAX_SCAN_BYTES) return;

  req.getContent((content, encoding) => {
    if (!content) return;
    let text = content;
    if (encoding === 'base64') {
      try { text = atob(content); } catch { return; }
    }
    const findings = scanForTokens(text);
    if (!findings.length) return;

    networkApi
      .addBodyFinding({
        url,
        method: req.request?.method || 'GET',
        timeStamp: Date.now(),
        statusCode: req.response?.status,
        tabId: chrome.devtools.inspectedWindow.tabId,
        bodyFindings: findings,
        jwtFindings: findings
          .filter((f) => f.isJwt)
          .map((f) => ({
            where: 'response.body.' + f.field,
            name: f.field,
            summary: f.summary,
            token: f.value, tokenPreview: f.preview,
          })),
        source: 'devtools-scanner',
      })
      .catch(() => null);
  });
}

function headerValue(headers, name) {
  const want = name.toLowerCase();
  for (const h of headers) {
    if ((h.name || '').toLowerCase() === want) return h.value || '';
  }
  return '';
}
