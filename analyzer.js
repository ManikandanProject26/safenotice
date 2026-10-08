/**
 * SafeNotice Rule-Based Link Analyzer
 * Analyzes link URLs, hostnames, and anchor text for security risks.
 */

const KNOWN_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly',
  'rb.gy', 'shorte.st', 'rebrand.ly', 'ow.ly', 'bl.ink'
];

const LOOKALIKE_KEYWORDS = [
  'verify', 'payment', 'exam', 'update', 'login', 'support',
  'scholarship', 'internship', 'result', 'fee', 'admit', 'portal'
];

const SUSPICIOUS_TEXT_PATTERNS = [
  'pay now', 'registration fee', 'exam fee', 'internship fee',
  'scholarship fee', 'verify account', 'submit otp', 'enter otp',
  'enter password', 'limited time', 'final warning', 'account blocked',
  'urgent action', 'immediate payment', 'claim prize', 'click here to pay'
];

const PAYMENT_KEYWORDS = [
  'upi', 'pay', 'payment', 'fee', 'fees', 'qr', 'bank', 'wallet',
  'registration charge', 'gpay', 'phonepe', 'paytm', 'bhim'
];

const EXECUTABLE_EXTENSIONS = [
  '.exe', '.apk', '.bat', '.cmd', '.scr', '.vbs', '.msi', '.sh'
];

/**
 * Validates whether an IP address is raw v4
 */
function isRawIP(hostname) {
  const ipPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipPattern.test(hostname);
}

/**
 * Checks if a domain matches or is a subdomain of an official domain
 */
function isOfficialDomain(hostname, officialDomains = []) {
  const cleanHost = hostname.toLowerCase().trim();
  return officialDomains.some(official => {
    const cleanOfficial = official.toLowerCase().trim();
    return cleanHost === cleanOfficial || cleanHost.endsWith('.' + cleanOfficial);
  });
}

/**
 * Performs heuristic evaluation on a link
 * @param {string} rawUrl - Target URL
 * @param {string} linkText - Visible anchor text
 * @param {Array<string>} officialDomains - Stored official domain whitelist
 * @returns {object} Analysis result
 */
function analyzeLink(rawUrl, linkText = '', officialDomains = []) {
  const result = {
    url: rawUrl,
    domain: '',
    status: 'unknown', // 'verified' | 'unknown' | 'suspicious'
    riskLevel: 'low',  // 'low' | 'medium' | 'high'
    category: 'unknown',
    reasons: [],
    recommendedAction: 'Check before you click.',
    isOfficial: false
  };

  if (!rawUrl || typeof rawUrl !== 'string') {
    result.status = 'suspicious';
    result.riskLevel = 'medium';
    result.category = 'other';
    result.reasons.push('Empty or invalid URL reference.');
    result.recommendedAction = 'Do not interact with malformed links.';
    return result;
  }

  // Handle javascript: or data: pseudo-protocols
  if (rawUrl.trim().toLowerCase().startsWith('javascript:') || rawUrl.trim().toLowerCase().startsWith('data:')) {
    result.status = 'suspicious';
    result.riskLevel = 'high';
    result.category = 'phishing';
    result.reasons.push('Executes in-page script directly from link protocol.');
    result.recommendedAction = 'Do not click this link.';
    return result;
  }

  let parsed;
  try {
    parsed = new URL(rawUrl, window?.location?.href || 'https://unknown.local');
  } catch (err) {
    result.status = 'suspicious';
    result.riskLevel = 'medium';
    result.category = 'other';
    result.reasons.push('Malformed URL structure.');
    result.recommendedAction = 'Verify this address with your college administration.';
    return result;
  }

  result.domain = parsed.hostname.toLowerCase();
  const lowerUrl = parsed.href.toLowerCase();
  const cleanText = (linkText || '').toLowerCase().trim();

  // 1. Official domain check
  if (isOfficialDomain(parsed.hostname, officialDomains)) {
    result.status = 'verified';
    result.riskLevel = 'low';
    result.isOfficial = true;
    result.category = 'verified';
    result.reasons.push('Domain matches recognized official institution whitelist.');
    result.recommendedAction = 'Safe to navigate.';
    return result;
  }

  // 2. Suspicious protocol (plain HTTP)
  if (parsed.protocol === 'http:') {
    result.reasons.push('Connection uses unencrypted HTTP.');
    result.riskLevel = 'medium';
  }

  // 3. Raw IP check
  if (isRawIP(parsed.hostname)) {
    result.reasons.push('Uses raw numerical IP address instead of registered domain name.');
    result.riskLevel = 'high';
  }

  // 4. Punycode check (homograph attacks)
  if (parsed.hostname.startsWith('xn--')) {
    result.reasons.push('Contains Punycode characters (potential lookalike domain spoofing).');
    result.riskLevel = 'high';
  }

  // 5. Shortened URLs
  if (KNOWN_SHORTENERS.includes(parsed.hostname)) {
    result.reasons.push('URL shortener masks the real destination domain.');
    result.riskLevel = 'medium';
    result.category = 'phishing';
  }

  // 6. Lookalike checks against official domains
  for (const official of officialDomains) {
    const baseName = official.split('.')[0].toLowerCase();
    if (baseName.length > 3 && parsed.hostname.includes(baseName) && !parsed.hostname.endsWith('.' + official)) {
      result.reasons.push(`Lookalike domain mimics official institution name "${official}".`);
      result.riskLevel = 'high';
      result.category = 'fake_notice';
      break;
    }
  }

  // 7. Lookalike domain keywords with hyphens (e.g. college-exam-fee.com)
  const containsLookalikeWord = LOOKALIKE_KEYWORDS.some(kw => parsed.hostname.includes(kw));
  if (containsLookalikeWord && parsed.hostname.includes('-')) {
    result.reasons.push('Suspicious domain structure containing hyphens and administrative keywords.');
    result.riskLevel = 'high';
  }

  // 8. Executable file downloads
  if (EXECUTABLE_EXTENSIONS.some(ext => parsed.pathname.toLowerCase().endsWith(ext))) {
    result.reasons.push('Points directly to an executable binary file download (.exe, .apk, etc.).');
    result.riskLevel = 'high';
    result.category = 'phishing';
  }

  // 9. Payment & Fee traps
  const hasPaymentKeywordInText = PAYMENT_KEYWORDS.some(term => cleanText.includes(term));
  const hasPaymentKeywordInUrl = PAYMENT_KEYWORDS.some(term => lowerUrl.includes(term));
  if (hasPaymentKeywordInText || hasPaymentKeywordInUrl) {
    if (cleanText.includes('exam fee') || lowerUrl.includes('exam-fee')) {
      result.reasons.push('Solicits examination fees outside official college payment gateways.');
      result.category = 'payment_scam';
      result.riskLevel = 'high';
    } else if (cleanText.includes('internship') || cleanText.includes('scholarship')) {
      result.reasons.push('Requests upfront payment/fees for internship or scholarship enrollment.');
      result.category = 'internship_scam';
      result.riskLevel = 'high';
    } else {
      result.reasons.push('Contains unverified payment or transaction prompts.');
      if (result.riskLevel !== 'high') result.riskLevel = 'medium';
    }
  }

  // 10. Urgent or threatening text
  const hasUrgency = SUSPICIOUS_TEXT_PATTERNS.some(pat => cleanText.includes(pat));
  if (hasUrgency) {
    result.reasons.push('Employs coercive, urgent, or high-pressure language ("Pay now", "OTP required", "Immediate").');
    if (result.riskLevel !== 'high') result.riskLevel = 'medium';
  }

  // 11. Suspicious credential or login harvesting
  if (cleanText.includes('otp') || cleanText.includes('password') || lowerUrl.includes('login') || lowerUrl.includes('signin')) {
    if (!result.isOfficial) {
      result.reasons.push('Prompts for login credentials or OTP on an external, unverified domain.');
      result.category = 'suspicious_login';
      result.riskLevel = 'high';
    }
  }

  // Status classification
  if (result.riskLevel === 'high' || result.reasons.length >= 2) {
    result.status = 'suspicious';
    if (!result.category || result.category === 'unknown') {
      result.category = 'phishing';
    }
    result.recommendedAction = 'Check before you click. Confirm this notice directly on your college notice board.';
  } else {
    result.status = 'unknown';
    result.riskLevel = 'low';
    result.category = 'unknown';
    if (result.reasons.length === 0) {
      result.reasons.push('External third-party link. Not listed in your official college directory.');
    }
    result.recommendedAction = 'Proceed with routine caution if you recognize this domain.';
  }

  return result;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeLink, isOfficialDomain };
}
