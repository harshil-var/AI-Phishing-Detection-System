(function () {
  const BACKEND_URL = "http://localhost:8000/api/v1";
  const DASHBOARD_URL = "http://localhost:5173/scan";

  function renderWarningOverlay(scanData) {
    if (document.getElementById("phishguard-warning-overlay")) return;

    const isPhishing = scanData.classification === "PHISHING";
    const overlay = document.createElement("div");
    overlay.id = "phishguard-warning-overlay";

    const encodedUrl = encodeURIComponent(window.location.href);
    const fullAnalysisUrl = `${DASHBOARD_URL}?url=${encodedUrl}`;

    const reasonsListHtml = (scanData.reasons || []).slice(0, 3).map(r => `<li>⚠ ${r}</li>`).join("");

    overlay.innerHTML = `
      <div class="pg-modal ${isPhishing ? 'phishing' : 'suspicious'}">
        <span class="pg-badge ${isPhishing ? 'phishing' : 'suspicious'}">
          ${isPhishing ? '🚨 PHISHING WEBSITE DETECTED' : '⚠ SUSPICIOUS WEBSITE'}
        </span>
        <h2 class="pg-title">${isPhishing ? 'Warning: High Security Risk' : 'Caution Advised'}</h2>
        <p class="pg-description">
          ${isPhishing 
            ? 'PhishGuard AI detected that this website may be attempting to steal your credentials or personal information.' 
            : 'This website contains structural and domain characteristics commonly associated with suspicious sites.'}
        </p>

        <div class="pg-stats">
          <div>
            <div class="pg-stat-val">${scanData.risk_score}/100</div>
            <div class="pg-stat-lbl">Risk Score</div>
          </div>
          <div>
            <div class="pg-stat-val">${scanData.confidence}%</div>
            <div class="pg-stat-lbl">AI Confidence</div>
          </div>
          <div>
            <div class="pg-stat-val">${scanData.severity}</div>
            <div class="pg-stat-lbl">Severity</div>
          </div>
        </div>

        <div class="pg-reasons">
          <ul>${reasonsListHtml}</ul>
        </div>

        <div class="pg-actions">
          ${isPhishing ? `<button id="pg-btn-back" class="pg-btn pg-btn-primary">⬅ Go Back (Recommended)</button>` : ''}
          <button id="pg-btn-analysis" class="pg-btn pg-btn-secondary">🔍 View Full Analysis</button>
          <button id="pg-btn-continue" class="pg-btn pg-btn-outline">Continue Anyway</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    if (document.getElementById("pg-btn-back")) {
      document.getElementById("pg-btn-back").addEventListener("click", () => {
        window.history.back();
      });
    }

    document.getElementById("pg-btn-analysis").addEventListener("click", () => {
      window.open(fullAnalysisUrl, "_blank");
    });

    document.getElementById("pg-btn-continue").addEventListener("click", () => {
      overlay.remove();
    });
  }

  // Check current page automatically
  const currentUrl = window.location.href;
  if (!currentUrl.startsWith("http://localhost:5173") && !currentUrl.startsWith("chrome-extension://")) {
    fetch(`${BACKEND_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    })
    .then(res => res.json())
    .then(scanData => {
      if (scanData.classification === "PHISHING" || scanData.classification === "SUSPICIOUS") {
        renderWarningOverlay(scanData);
      }
    })
    .catch(() => {});
  }

  // Listen for messages from service worker
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "PHISHGUARD_WARN" && msg.scanData) {
      renderWarningOverlay(msg.scanData);
    }
  });
})();
