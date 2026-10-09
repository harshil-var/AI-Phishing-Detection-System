document.addEventListener("DOMContentLoaded", () => {
  const statusBadge = document.getElementById("status-badge");
  const siteDomain = document.getElementById("site-domain");
  const riskScore = document.getElementById("risk-score");
  const confidenceScore = document.getElementById("confidence-score");
  const reasonsList = document.getElementById("reasons-list");
  const btnFullAnalysis = document.getElementById("btn-full-analysis");
  const btnSecurityChatbot = document.getElementById("btn-security-chatbot");

  let currentTabUrl = "";

  // Get active tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url) {
      currentTabUrl = tabs[0].url;
      try {
        const parsed = new URL(currentTabUrl);
        siteDomain.textContent = parsed.hostname;
      } catch (e) {
        siteDomain.textContent = currentTabUrl;
      }

      // Query background script for current scan
      chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN" }, (response) => {
        if (response) {
          updateUI(response);
        } else {
          // Direct API fallback
          fetch("http://localhost:8000/api/v1/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: currentTabUrl })
          })
          .then(res => res.json())
          .then(data => updateUI(data))
          .catch(err => {
            statusBadge.textContent = "OFFLINE";
            statusBadge.className = "badge suspicious";
            reasonsList.innerHTML = "<li>Backend server unreachable (http://localhost:8000).</li>";
          });
        }
      });
    }
  });

  function updateUI(data) {
    const cls = data.classification || "SAFE";
    statusBadge.textContent = cls === "PHISHING" ? "🔴 PHISHING DETECTED" : cls;
    statusBadge.className = `badge ${cls.toLowerCase()}`;

    riskScore.textContent = `${data.risk_score}/100`;
    confidenceScore.textContent = `${data.confidence}%`;

    if (data.reasons && data.reasons.length > 0) {
      reasonsList.innerHTML = data.reasons.slice(0, 3).map(r => `<li>${r}</li>`).join("");
    } else {
      reasonsList.innerHTML = "<li>No significant risk factors detected.</li>";
    }
  }

  btnFullAnalysis.addEventListener("click", () => {
    if (currentTabUrl) {
      const encoded = encodeURIComponent(currentTabUrl);
      chrome.tabs.create({ url: `http://localhost:5173/scan?url=${encoded}` });
    } else {
      chrome.tabs.create({ url: "http://localhost:5173/" });
    }
  });

  btnSecurityChatbot.addEventListener("click", () => {
    chrome.tabs.create({ url: "http://localhost:5173/?chat=open" });
  });
});
