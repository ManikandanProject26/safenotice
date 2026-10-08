/**
 * SafeNotice Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const toggleScan = document.getElementById('toggle-scan');
  const currentHostEl = document.getElementById('current-host');
  const cntVerified = document.getElementById('cnt-verified');
  const cntUnknown = document.getElementById('cnt-unknown');
  const cntSuspicious = document.getElementById('cnt-suspicious');
  const btnScanNow = document.getElementById('btn-scan-now');
  const inputDomain = document.getElementById('input-domain');
  const btnAddDomain = document.getElementById('btn-add-domain');
  const domainList = document.getElementById('domain-list');
  const linkOptions = document.getElementById('link-options');

  let officialDomains = [];

  // Read active tab information
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    try {
      const parsed = new URL(tab.url);
      currentHostEl.innerText = parsed.hostname || 'Local page';
    } catch {
      currentHostEl.innerText = 'Restricted page';
    }
  }

  // Load stored options
  const config = await chrome.storage.local.get(['officialDomains', 'scanningEnabled']);
  officialDomains = config.officialDomains || [];
  toggleScan.checked = config.scanningEnabled !== false;

  renderDomains();

  // Open full options tab
  linkOptions.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  // Toggle Scanning Switch
  toggleScan.addEventListener('change', async () => {
    await chrome.storage.local.set({ scanningEnabled: toggleScan.checked });
  });

  // Scan current page manually
  btnScanNow.addEventListener('click', () => {
    btnScanNow.innerText = 'Scanning...';
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, { action: 'TRIGGER_PAGE_SCAN' }, (response) => {
        btnScanNow.innerText = 'Scan Current Page';
        if (response?.counts) {
          cntVerified.innerText = response.counts.verified;
          cntUnknown.innerText = response.counts.unknown;
          cntSuspicious.innerText = response.counts.suspicious;
        }
      });
    }
  });

  // Add Domain to Whitelist
  btnAddDomain.addEventListener('click', async () => {
    const val = inputDomain.value.trim().toLowerCase();
    if (val && !officialDomains.includes(val)) {
      officialDomains.push(val);
      await chrome.storage.local.set({ officialDomains });
      inputDomain.value = '';
      renderDomains();
    }
  });

  function renderDomains() {
    domainList.innerHTML = '';
    officialDomains.slice(0, 8).forEach(domain => {
      const li = document.createElement('li');
      li.innerHTML = `${domain} <span class="remove-domain-btn" data-domain="${domain}">&times;</span>`;
      domainList.appendChild(li);
    });

    domainList.querySelectorAll('.remove-domain-btn').forEach(btn => {
      btn.onclick = async (e) => {
        const toRemove = e.target.getAttribute('data-domain');
        officialDomains = officialDomains.filter(d => d !== toRemove);
        await chrome.storage.local.set({ officialDomains });
        renderDomains();
      };
    });
  }

  // Listen for real-time counts relayed from content script
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === 'UPDATE_SUMMARY_COUNTS' && msg.counts) {
      cntVerified.innerText = msg.counts.verified;
      cntUnknown.innerText = msg.counts.unknown;
      cntSuspicious.innerText = msg.counts.suspicious;
    }
  });
});
