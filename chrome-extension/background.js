const DEFAULT_BACKEND = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";

function getBackendUrl() {
  return Promise.resolve(DEFAULT_BACKEND);
}

function fetchWithTimeout(url, options, timeoutMs = 60000) {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Request timed out")), timeoutMs)
    ),
  ]);
}

async function handleAnalyzeText(data) {
  const backendUrl = await getBackendUrl();
  const response = await fetchWithTimeout(`${backendUrl}/analyze/text`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: data.text, language: data.language || "en" }),
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Backend error ${response.status}: ${err}`);
  }
  return response.json();
}

async function handleGetTranslations(data) {
  const backendUrl = await getBackendUrl();
  const lang = data.language || "en";
  const response = await fetchWithTimeout(`${backendUrl}/translations/${lang}`);
  if (!response.ok) {
    throw new Error(`Failed to load translations for "${lang}"`);
  }
  return response.json();
}

async function handleHealthCheck() {
  const backendUrl = await getBackendUrl();
  const response = await fetchWithTimeout(`${backendUrl}/health`, {}, 5000);
  if (!response.ok) {
    throw new Error(`Health check failed: ${response.status}`);
  }
  return response.json();
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handlers = {
    analyzeText: () => handleAnalyzeText(message),
    getTranslations: () => handleGetTranslations(message),
    healthCheck: () => handleHealthCheck(),
  };

  const handler = handlers[message.action];
  if (!handler) {
    sendResponse({ error: `Unknown action: ${message.action}` });
    return false;
  }

  handler()
    .then((result) => sendResponse({ success: true, data: result }))
    .catch((err) => sendResponse({ success: false, error: err.message }));

  return true; // keep channel open for async response
});
