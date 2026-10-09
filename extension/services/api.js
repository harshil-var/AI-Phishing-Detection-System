const BACKEND_URL = "http://localhost:8000/api/v1";

async function scanCurrentUrl(url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("edge://")) {
    return {
      classification: "SAFE",
      risk_score: 0,
      confidence: 100,
      reasons: ["Internal browser system page"],
      security_checks: {}
    };
  }

  try {
    const response = await fetch(`${BACKEND_URL}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`API returned HTTP ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error("[PhishGuard Ext API Error]:", error);
    return {
      classification: "SUSPICIOUS",
      risk_score: 50,
      confidence: 60,
      reasons: ["Backend server unreachable. Treat unverified links with caution."],
      security_checks: {}
    };
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanCurrentUrl };
}
