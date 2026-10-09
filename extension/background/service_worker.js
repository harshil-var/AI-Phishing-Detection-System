const BACKEND_URL = "http://localhost:8000/api/v1";

async function analyzeTabUrl(tabId, url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:") || url.startsWith("edge://")) {
    return;
  }

  try {
    const response = await fetch(`${BACKEND_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) return;
    const scanData = await response.json();

    // Cache scan data for popup and content script
    chrome.storage.local.set({ [url]: scanData, currentTabScan: scanData });

    // Send result message to content script
    if (scanData.classification === "SUSPICIOUS" || scanData.classification === "PHISHING") {
      chrome.tabs.sendMessage(tabId, {
        type: "PHISHGUARD_WARN",
        scanData: scanData
      }).catch(() => {
        // Content script might not be initialized yet
      });
    }
  } catch (err) {
    console.warn("PhishGuard background scan error:", err);
  }
}

// Listen for tab URL updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeTabUrl(tabId, tab.url);
  }
});

// Listen for messages from popup or content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_CURRENT_SCAN") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs.length > 0 && tabs[0].url) {
        const url = tabs[0].url;
        chrome.storage.local.get([url], async (result) => {
          if (result[url]) {
            sendResponse(result[url]);
          } else {
            try {
              const res = await fetch(`${BACKEND_URL}/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
              });
              const scanData = await res.json();
              chrome.storage.local.set({ [url]: scanData });
              sendResponse(scanData);
            } catch (err) {
              sendResponse(null);
            }
          }
        });
      } else {
        sendResponse(null);
      }
    });
    return true; // Keep response channel open for async
  }
});
