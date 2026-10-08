/**
 * SafeNotice Local AI Explanation Client (LM Studio)
 * Privacy Rule: Sends only link text, destination URL, page title, and rule findings.
 * Never transmits passwords, cookies, session data, or entire page DOM.
 */

async function requestAIExplanation(payload, config = {}) {
  const endpoint = config.lmEndpoint || 'http://localhost:1234/v1/chat/completions';
  const modelName = config.lmModel || 'local-model';

  const prompt = `You are an advisory assistant for college students called SafeNotice.
A student encountered a link on their campus portal or educational webpage:
- Page Title: "${payload.pageTitle || 'Untitled'}"
- Link Text: "${payload.linkText || 'None'}"
- Link URL: "${payload.url}"
- Detected Rule Findings: ${JSON.stringify(payload.reasons || [])}

Analyze the safety risk for a student. Return strictly valid JSON conforming to this schema with no markdown or additional dialogue:
{
  "category": "verified | unknown | phishing | fake_notice | payment_scam | internship_scam | suspicious_login | other",
  "risk_level": "low | medium | high",
  "explanation": "Short 1-2 sentence explanation in student-friendly tone",
  "warning_signs": ["Reason 1", "Reason 2"],
  "recommended_action": "Safe advisory action for student"
}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000); // 4-second timeout failover

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        model: modelName,
        messages: [
          { role: 'system', content: 'You are a cybersecurity safety advisor. You only output valid JSON.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.1
      })
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`LM Studio HTTP ${response.status}`);
    }

    const data = await response.json();
    const rawContent = data.choices?.[0]?.message?.content?.trim();

    // Clean potential markdown blocks
    const cleaned = rawContent.replace(/^```json/i, '').replace(/```$/i, '').trim();
    return JSON.parse(cleaned);
  } catch (error) {
    clearTimeout(timeoutId);
    // Graceful fallback to rule-based analysis
    return null;
  }
}
