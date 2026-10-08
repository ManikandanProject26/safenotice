/**
 * SafeNotice Options Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const newDomainInput = document.getElementById('new-domain-input');
  const addDomainBtn = document.getElementById('add-domain-btn');
  const domainsContainer = document.getElementById('domains-container');
  const aiToggle = document.getElementById('ai-toggle');
  const lmEndpoint = document.getElementById('lm-endpoint');
  const lmModel = document.getElementById('lm-model');
  const testLmBtn = document.getElementById('test-lm-btn');
  const testStatus = document.getElementById('test-status');
  const saveSettingsBtn = document.getElementById('save-settings-btn');
  const saveConfirm = document.getElementById('save-confirm');

  let officialDomains = [];

  const data = await chrome.storage.local.get([
    'officialDomains', 'aiEnabled', 'lmEndpoint', 'lmModel'
  ]);

  officialDomains = data.officialDomains || [];
  aiToggle.checked = !!data.aiEnabled;
  if (data.lmEndpoint) lmEndpoint.value = data.lmEndpoint;
  if (data.lmModel) lmModel.value = data.lmModel;

  renderDomains();

  addDomainBtn.addEventListener('click', () => {
    const val = newDomainInput.value.trim().toLowerCase();
    if (val && !officialDomains.includes(val)) {
      officialDomains.push(val);
      newDomainInput.value = '';
      renderDomains();
    }
  });

  function renderDomains() {
    domainsContainer.innerHTML = '';
    officialDomains.forEach((d, idx) => {
      const li = document.createElement('li');
      li.innerHTML = `
        <span>${d}</span>
        <button data-index="${idx}">Remove</button>
      `;
      domainsContainer.appendChild(li);
    });

    domainsContainer.querySelectorAll('button').forEach(btn => {
      btn.onclick = (e) => {
        const index = parseInt(e.target.getAttribute('data-index'), 10);
        officialDomains.splice(index, 1);
        renderDomains();
      };
    });
  }

  // Test local LM Studio connection
  testLmBtn.addEventListener('click', async () => {
    testStatus.style.color = '#2563eb';
    testStatus.innerText = 'Testing connection...';
    try {
      const res = await fetch(lmEndpoint.value.trim(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: lmModel.value.trim() || 'local-model',
          messages: [{ role: 'user', content: 'Respond with OK' }],
          max_tokens: 5
        })
      });
      if (res.ok) {
        testStatus.style.color = '#16a34a';
        testStatus.innerText = 'Connected successfully to LM Studio!';
      } else {
        testStatus.style.color = '#ef4444';
        testStatus.innerText = `Connected, but server returned HTTP ${res.status}.`;
      }
    } catch (err) {
      testStatus.style.color = '#ef4444';
      testStatus.innerText = 'Failed: LM Studio not running at this address.';
    }
  });

  // Save Settings
  saveSettingsBtn.addEventListener('click', async () => {
    await chrome.storage.local.set({
      officialDomains,
      aiEnabled: aiToggle.checked,
      lmEndpoint: lmEndpoint.value.trim(),
      lmModel: lmModel.value.trim()
    });

    saveConfirm.innerText = 'Preferences saved successfully!';
    setTimeout(() => { saveConfirm.innerText = ''; }, 3000);
  });
});
