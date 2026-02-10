const BACKEND_URL = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";
const FIREBASE_API_KEY = "BPv2EQEu5V3kNyElzcRDuTTh4WABeLjhOcdigoqZ4aABXh64b95f15pwiRusc5kzMaCRgXHqCjTZypos4qB5tFY";

function fetchWithTimeout(url, options, timeoutMs = 60000) {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Request timed out")), timeoutMs)
    ),
  ]);
}

// ── Auth token management ────────────────────────────────

async function getAuthToken() {
  const { authToken, refreshToken, tokenExpiry } = await chrome.storage.local.get([
    "authToken", "refreshToken", "tokenExpiry",
  ]);
  if (!authToken) throw new Error("Not logged in");

  // Refresh if expired or about to expire (5 min buffer)
  if (tokenExpiry && Date.now() > tokenExpiry - 300000) {
    return await refreshAuthToken(refreshToken);
  }
  return authToken;
}

async function refreshAuthToken(refreshToken) {
  if (!refreshToken) throw new Error("Not logged in");

  const resp = await fetch(
    `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: refreshToken }),
    }
  );
  if (!resp.ok) throw new Error("Session expired, please log in again");

  const data = await resp.json();
  await chrome.storage.local.set({
    authToken: data.id_token,
    refreshToken: data.refresh_token,
    tokenExpiry: Date.now() + parseInt(data.expires_in) * 1000,
  });
  return data.id_token;
}

async function getAuthHeaders() {
  const token = await getAuthToken();
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${token}`,
  };
}

// ── API handlers ─────────────────────────────────────────

async function handleAnalyzeText(data) {
  const headers = await getAuthHeaders();
  const response = await fetchWithTimeout(`${BACKEND_URL}/analyze/text`, {
    method: "POST",
    headers,
    body: JSON.stringify({ text: data.text, language: data.language || "en" }),
  });
  if (response.status === 401) throw new Error("Session expired, please log in again");
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Backend error ${response.status}: ${err}`);
  }
  return response.json();
}

async function handleGetTranslations(data) {
  const lang = data.language || "en";
  const response = await fetchWithTimeout(`${BACKEND_URL}/translations/${lang}`);
  if (!response.ok) throw new Error(`Failed to load translations for "${lang}"`);
  return response.json();
}

async function handleHealthCheck() {
  const response = await fetchWithTimeout(`${BACKEND_URL}/health`, {}, 60000);
  if (!response.ok) throw new Error(`Health check failed: ${response.status}`);
  return response.json();
}

async function handleSignIn(data) {
  const resp = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        returnSecureToken: true,
      }),
    }
  );
  const result = await resp.json();
  if (result.error) throw new Error(result.error.message);

  await chrome.storage.local.set({
    authToken: result.idToken,
    refreshToken: result.refreshToken,
    tokenExpiry: Date.now() + parseInt(result.expiresIn) * 1000,
    userEmail: result.email,
  });
  return { email: result.email };
}

async function handleSignUp(data) {
  const resp = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        returnSecureToken: true,
      }),
    }
  );
  const result = await resp.json();
  if (result.error) throw new Error(result.error.message);

  await chrome.storage.local.set({
    authToken: result.idToken,
    refreshToken: result.refreshToken,
    tokenExpiry: Date.now() + parseInt(result.expiresIn) * 1000,
    userEmail: result.email,
  });
  return { email: result.email };
}

async function handleSignOut() {
  await chrome.storage.local.remove(["authToken", "refreshToken", "tokenExpiry", "userEmail"]);
  return { success: true };
}

async function handleGetUser() {
  const { userEmail, authToken } = await chrome.storage.local.get(["userEmail", "authToken"]);
  if (userEmail && authToken) {
    return { loggedIn: true, email: userEmail };
  }
  return { loggedIn: false };
}

// ── Message router ───────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handlers = {
    analyzeText: () => handleAnalyzeText(message),
    getTranslations: () => handleGetTranslations(message),
    healthCheck: () => handleHealthCheck(),
    signIn: () => handleSignIn(message),
    signUp: () => handleSignUp(message),
    signOut: () => handleSignOut(),
    getUser: () => handleGetUser(),
  };

  const handler = handlers[message.action];
  if (!handler) {
    sendResponse({ error: `Unknown action: ${message.action}` });
    return false;
  }

  handler()
    .then((result) => sendResponse({ success: true, data: result }))
    .catch((err) => sendResponse({ success: false, error: err.message }));

  return true;
});
