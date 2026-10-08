/**
 * SafeNotice Content Script
 */

(function () {
  // Prevent execution on unsupported browser tabs or duplicate execution
  if (window.hasSafeNoticeInitialized) return;
  window.hasSafeNoticeInitialized = true;

  let officialDomains = [];
  let scanningEnabled = true;
  let aiEnabled = false;
  let lmEndpoint = '';
  let lmModel = '';

  const scannedUrls = new Set();
  const summaryCounts = { verified: 0, unknown: 0, suspicious: 0 };

  // Load configuration from local storage
  async function loadConfig() {
    const data = await chrome.storage.local.get([
      'officialDomains', 'scanningEnabled', 'aiEnabled', 'lmEndpoint', 'lmModel'
    ]);
    officialDomains = data.officialDomains || [];
    scanningEnabled = data.scanningEnabled !== false;
    aiEnabled = !!data.aiEnabled;
    lmEndpoint = data.lmEndpoint || 'http://localhost:1234/v1/chat/completions';
    lmModel = data.lmModel || 'local-model';
  }

  // Safe HTML Escaping Helper to eliminate DOM XSS risks
  function escapeHTML(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Create or return the advisory modal element
  function getOrCreateModal() {
    let modal = document.getElementById('safenotice-advisory-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'safenotice-advisory-modal';
      modal.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        width: 380px;
        max-width: 90vw;
        background: #ffffff;
        border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15), 0 1px 3px rgba(0,0,0,0.1);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        z-index: 2147483647;
        padding: 18px;
        border: 1px solid #e2e8f0;
        display: none;
        box-sizing: border-box;
        color: #1e293b;
      `;
      document.body.appendChild(modal);
    }
    return modal;
  }

  // Display detail popup modal when a student clicks on a warning badge
  async function showAdvisoryModal(analysis, linkText = '') {
    const modal = getOrCreateModal();
    let currentAnalysis = { ...analysis };

    // Initial render with deterministic rule findings
    renderModalContent(modal, currentAnalysis, false);
    modal.style.display = 'block';

    // Optional local AI explanation query
    if (aiEnabled && currentAnalysis.status === 'suspicious') {
      renderModalContent(modal, currentAnalysis, true); // show AI loading indicator
      try {
        const payload = {
          url: currentAnalysis.url,
          linkText: linkText,
          reasons: currentAnalysis.reasons,
          pageTitle: document.title
        };
        const aiResult = await requestAIExplanation(payload, { lmEndpoint, lmModel });
        if (aiResult) {
          if (aiResult.explanation) currentAnalysis.aiExplanation = aiResult.explanation;
          if (Array.isArray(aiResult.warning_signs) && aiResult.warning_signs.length) {
            currentAnalysis.reasons = aiResult.warning_signs;
          }
          if (aiResult.recommended_action) currentAnalysis.recommendedAction = aiResult.recommended_action;
        }
      } catch (err) {
        console.warn('[SafeNotice] AI query skipped:', err);
      }
      renderModalContent(modal, currentAnalysis, false);
    }
  }

  function renderModalContent(modal, analysis, isAiLoading) {
    const statusColor = analysis.status === 'verified' ? '#10b981' : analysis.status === 'suspicious' ? '#ef4444' : '#f59e0b';
    const statusLabel = analysis.status === 'verified' ? 'Verified Official' : analysis.status === 'suspicious' ? 'Suspicious Notice' : 'Unknown External';

    modal.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:${statusColor};"></span>
          <strong style="font-size: 15px; font-weight: 700; color: #0f172a;">SafeNotice Advisory</strong>
        </div>
        <button id="safenotice-modal-close" style="background:none; border:none; font-size:18px; cursor:pointer; color:#64748b; line-height:1;">&times;</button>
      </div>

      <div style="margin-bottom: 10px;">
        <span style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; color: ${statusColor}; background: ${statusColor}15; padding: 3px 8px; border-radius: 4px;">
          ${escapeHTML(statusLabel)}
        </span>
        <span style="font-size: 12px; color: #64748b; margin-left: 6px;">Risk: <strong>${escapeHTML(analysis.riskLevel.toUpperCase())}</strong></span>
      </div>

      <div style="font-size: 12px; margin-bottom: 8px; word-break: break-all; background: #f8fafc; padding: 6px 8px; border-radius: 6px; border: 1px solid #e2e8f0;">
        <span style="color:#64748b;">Target Host:</span> <strong style="color:#1e293b;">${escapeHTML(analysis.domain || 'N/A')}</strong>
      </div>

      <div style="font-size: 13px; line-height: 1.4; color: #334155; margin-bottom: 12px;">
        <div style="font-weight: 600; margin-bottom: 4px; color: #1e293b;">Notice Analysis:</div>
        <ul style="margin: 0 0 8px 0; padding-left: 18px; color: #475569; font-size: 12px;">
          ${analysis.reasons.map(r => `<li style="margin-bottom: 2px;">${escapeHTML(r)}</li>`).join('')}
        </ul>
        ${isAiLoading ? '<div style="font-size: 11px; color: #3b82f6; font-style: italic;">Asking local LM Studio assistant...</div>' : ''}
        ${analysis.aiExplanation ? `<div style="background: #eff6ff; padding: 8px; border-radius: 6px; font-size: 12px; color: #1e40af; border: 1px solid #dbeafe; margin-top: 6px;"><strong>AI Summary:</strong> ${escapeHTML(analysis.aiExplanation)}</div>` : ''}
      </div>

      <div style="background: #fffbeb; border: 1px solid #fef3c7; padding: 8px 10px; border-radius: 6px; font-size: 12px; color: #92400e; margin-bottom: 12px;">
        <strong>Advisory:</strong> ${escapeHTML(analysis.recommendedAction)}
      </div>

      <div style="display: flex; gap: 8px;">
        <a href="https://cybercrime.gov.in/" target="_blank" rel="noopener noreferrer" style="flex:1; text-align:center; background: #f1f5f9; color: #334155; text-decoration:none; font-size:12px; font-weight:600; padding: 6px 10px; border-radius: 6px;">Report Scam</a>
        <button id="safenotice-modal-dismiss" style="flex:1; background: #2563eb; color: #ffffff; border:none; font-size:12px; font-weight:600; padding: 6px 10px; border-radius: 6px; cursor:pointer;">Acknowledge</button>
      </div>
    `;

    modal.querySelector('#safenotice-modal-close').onclick = () => modal.style.display = 'none';
    modal.querySelector('#safenotice-modal-dismiss').onclick = () => modal.style.display = 'none';
  }

  // Inject a lightweight badge beside inspected hyperlinks
  function attachBadge(linkElement, analysis) {
    if (linkElement.dataset.safenoticeAttached === 'true') return;
    linkElement.dataset.safenoticeAttached = 'true';

    const badge = document.createElement('span');
    badge.className = 'safenotice-badge';

    const color = analysis.status === 'verified' ? '#10b981' : analysis.status === 'suspicious' ? '#ef4444' : '#f59e0b';
    const symbol = analysis.status === 'verified' ? '✓' : analysis.status === 'suspicious' ? '!' : '?';

    badge.style.cssText = `
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 15px;
      height: 15px;
      margin-left: 4px;
      font-size: 10px;
      font-weight: bold;
      color: #ffffff;
      background-color: ${color};
      border-radius: 50%;
      cursor: pointer;
      vertical-align: middle;
      box-shadow: 0 1px 2px rgba(0,0,0,0.15);
      user-select: none;
      text-decoration: none;
      line-height: 1;
    `;
    badge.title = `SafeNotice: ${analysis.status.toUpperCase()} - Click for details`;
    badge.innerText = symbol;

    badge.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showAdvisoryModal(analysis, linkElement.innerText);
    });

    // Insert directly after the link tag to prevent breaking layout
    if (linkElement.nextSibling) {
      linkElement.parentNode.insertBefore(badge, linkElement.nextSibling);
    } else {
      linkElement.parentNode.appendChild(badge);
    }
  }

  // Scan all visible links across the document
  function scanPageLinks() {
    if (!scanningEnabled) return;

    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
      const rawHref = link.getAttribute('href');
      if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:')) return;

      let absoluteUrl;
      try {
        absoluteUrl = new URL(rawHref, window.location.href).href;
      } catch (e) {
        return;
      }

      const text = link.innerText || link.getAttribute('title') || '';
      const analysis = analyzeLink(absoluteUrl, text, officialDomains);

      if (!scannedUrls.has(absoluteUrl)) {
        scannedUrls.add(absoluteUrl);
        if (analysis.status === 'verified') summaryCounts.verified++;
        else if (analysis.status === 'suspicious') summaryCounts.suspicious++;
        else summaryCounts.unknown++;
      }

      attachBadge(link, analysis);
    });

    // Notify extension popup of scan counters
    try {
      chrome.runtime.sendMessage({
        action: 'UPDATE_SUMMARY_COUNTS',
        counts: summaryCounts,
        hostname: window.location.hostname
      });
    } catch (ignore) {}
  }

  // Observe dynamically loaded links (Single Page Applications)
  function initObserver() {
    const observer = new MutationObserver(mutations => {
      let shouldRescan = false;
      for (const m of mutations) {
        if (m.addedNodes.length > 0) {
          shouldRescan = true;
          break;
        }
      }
      if (shouldRescan) {
        scanPageLinks();
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  // Listen for trigger events from popup or context menu
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'TRIGGER_PAGE_SCAN') {
      scanPageLinks();
      sendResponse({ status: 'completed', counts: summaryCounts });
    } else if (msg.action === 'SHOW_INSPECT_MODAL') {
      showAdvisoryModal(msg.analysis);
    }
  });

  // Initialization lifecycle
  loadConfig().then(() => {
    scanPageLinks();
    initObserver();
  });
})();
