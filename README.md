# SafeNotice - Privacy-First Student CyberSafe Extension

SafeNotice is a lightweight, privacy-focused Chrome Extension (Manifest V3) engineered for college students. It automatically scans visible hyperlinks on web pages, college notice boards, and campus portals to flag suspicious fee-payment traps, fraudulent internships, phishing credential harvesters, and lookalike domains.

---

## 1. Problem Statement
College students are frequent targets of malicious cyber campaigns:
- **Fake Exam & Arrear Fee Scams:** Malicious actors circulate urgent notices demanding immediate UPI/card payment under threat of debarment.
- **Internship & Scholarship Scams:** Unverified offers demanding upfront registration fees.
- **Lookalike Domains:** Phishing portals mimicking university domains (e.g., `annauniv-exam-fee.com` vs `annauniv.edu`).
- **Cognitive Overload & Panic:** Pressure tactics ("Final Warning", "Account Blocked") cause students to click without checking.

---

## 2. Core Architecture
- **Non-Destructive In-Page Inspection:** `content.js` inspects visible `<a>` anchor tags without disrupting page layout.
- **Heuristic Rule-Based Engine (`analyzer.js`):** Runs locally in microseconds. Checks domain whitelist, homographs, raw IPs, payment keywords, and urgency indicators.
- **Optional Local AI Advisor (`ai-client.js`):** Communicates with an on-device LM Studio instance via `http://localhost:1234/v1/chat/completions`. If offline, SafeNotice falls back to rule-based heuristics.
- **Zero Cloud Leakage:** No browsing history or form inputs leave your machine.

---

## 3. Chrome Extension Permissions Explained

| Permission | Justification |
|---|---|
| `storage` | Stores user-configured official college domains and local LM Studio configuration. |
| `activeTab` | Inspects visible links on the tab currently focused by the student. |
| `contextMenus` | Adds the right-click option: *"Check link with SafeNotice"*. |
| `scripting` | Enables dynamic rescanning and modal injection on active documents. |
| `host_permissions` (`http://*/*`, `https://*/*`) | Allows the extension content script to label links across campus portals and demo pages. |

---

## 4. How to Load the Extension in Google Chrome

1. Clone or download this directory:
   ```bash
   git clone https://github.com/your-team/safenotice.git
