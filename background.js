/**
 * SafeNotice Service Worker
 */

import { analyzeLink } from './analyzer.js';

const DEFAULT_OFFICIAL_DOMAINS = [
  'annauniv.edu',
  'iitm.ac.in',
  'mitindia.edu',
  'tndte.gov.in',
  'ugc.ac.in',
  'aicte-india.org'
];

// Seed default settings on initial install
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(['officialDomains', 'scanningEnabled', 'aiEnabled', 'lmEndpoint', 'lmModel']);
  
  if (!current.officialDomains) {
    await chrome.storage.local.set({
      officialDomains: DEFAULT_OFFICIAL_DOMAINS,
      scanningEnabled: true,
      aiEnabled: false,
      lmEndpoint: 'http://localhost:1234/v1/chat/completions',
      lmModel: 'local-model'
    });
  }

  // Create Right-Click Context Menu
  chrome.contextMenus.create({
    id: 'safenotice-check-link',
    title: 'Check link with SafeNotice',
    contexts: ['link']
  });
});

// Handle Context Menu click
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'safenotice-check-link' && info.linkUrl && tab?.id) {
    const data = await chrome.storage.local.get(['officialDomains']);
    const analysis = analyzeLink(info.linkUrl, info.selectionText || '', data.officialDomains || []);
    
    // Relay analysis directly to content script to display the advisory modal
    chrome.tabs.sendMessage(tab.id, {
      action: 'SHOW_INSPECT_MODAL',
      analysis: analysis
    });
  }
});

// Handle inter-script messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GET_OFFICIAL_DOMAINS') {
    chrome.storage.local.get(['officialDomains', 'scanningEnabled', 'aiEnabled', 'lmEndpoint', 'lmModel']).then(sendResponse);
    return true; // Keep asynchronous message channel open
  }
});
