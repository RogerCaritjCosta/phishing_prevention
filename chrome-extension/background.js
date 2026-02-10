const BACKEND_URL = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";
const FIREBASE_API_KEY = "AIzaSyA4viSI5AUH7Mpp02k0uj_mUiIk9SuBzEA";
const FIREBASE_PROJECT_ID = "phishbuster-5d57b";
const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents`;

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

// ── Firestore helpers ───────────────────────────────────

async function firestoreGet(path, token) {
  const resp = await fetch(`${FIRESTORE_BASE}/${path}`, {
    headers: { "Authorization": `Bearer ${token}` },
  });
  if (resp.status === 404) return null;
  if (!resp.ok) throw new Error(`Firestore read failed: ${resp.status}`);
  return resp.json();
}

async function firestoreSet(path, fields, token) {
  const body = { fields };
  const resp = await fetch(`${FIRESTORE_BASE}/${path}`, {
    method: "PATCH",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`Firestore write failed: ${resp.status}`);
  return resp.json();
}

async function fetchUserBaseLimit() {
  try {
    const token = await getAuthToken();
    const { userUid } = await chrome.storage.local.get("userUid");
    if (!userUid) return 10;
    const doc = await firestoreGet(`users/${userUid}`, token);
    if (doc && doc.fields && doc.fields.dailyLimit) {
      return parseInt(doc.fields.dailyLimit.integerValue) || 10;
    }
    return 10;
  } catch {
    // Fallback to cached value or default
    const { userBaseLimit = 10 } = await chrome.storage.sync.get("userBaseLimit");
    return userBaseLimit;
  }
}

async function createUserDoc(uid, token) {
  await firestoreSet(`users/${uid}`, {
    dailyLimit: { integerValue: "10" },
  }, token);
}

// ── Daily limit ─────────────────────────────────────────

const ADD_MORE_AMOUNT = 15;

function getTodayStr() {
  return new Date().toISOString().slice(0, 10);
}

async function getDailyUsage() {
  const { dailyCount = 0, dailyDate = "", dailyExtra = 0, userBaseLimit = 10 } =
    await chrome.storage.sync.get(["dailyCount", "dailyDate", "dailyExtra", "userBaseLimit"]);
  const today = getTodayStr();
  if (dailyDate !== today) {
    // New day: reset count and extra, refresh base limit from Firestore
    let baseLimit = userBaseLimit;
    try { baseLimit = await fetchUserBaseLimit(); } catch {}
    await chrome.storage.sync.set({
      dailyCount: 0, dailyDate: today, dailyExtra: 0, userBaseLimit: baseLimit,
    });
    updateBadge(0, baseLimit);
    return { count: 0, limit: baseLimit, base: baseLimit };
  }
  const effectiveLimit = userBaseLimit + dailyExtra;
  return { count: dailyCount, limit: effectiveLimit, base: userBaseLimit };
}

async function incrementDailyCount() {
  const usage = await getDailyUsage();
  const newCount = usage.count + 1;
  await chrome.storage.sync.set({ dailyCount: newCount });
  updateBadge(newCount, usage.limit);
  return { count: newCount, limit: usage.limit };
}

async function handleAddMoreAnalyses() {
  const usage = await getDailyUsage();
  const { dailyExtra = 0 } = await chrome.storage.sync.get("dailyExtra");
  const newExtra = dailyExtra + ADD_MORE_AMOUNT;
  const newLimit = usage.base + newExtra;
  await chrome.storage.sync.set({ dailyExtra: newExtra });
  updateBadge(usage.count, newLimit);
  return { count: usage.count, limit: newLimit };
}

function updateBadge(count, limit) {
  const text = String(count);
  const color = count >= limit ? "#ef4444" : "#3b82f6";
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// Update badge on startup
getDailyUsage().then(({ count, limit }) => updateBadge(count, limit));

// ── API handlers ─────────────────────────────────────────

async function handleAnalyzeText(data) {
  // Check daily limit
  const usage = await getDailyUsage();
  if (usage.count >= usage.limit) {
    throw new Error("DAILY_LIMIT_REACHED");
  }

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

  // Increment daily count after successful analysis
  await incrementDailyCount();

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
    userUid: result.localId,
  });

  // Fetch and cache user's base limit from Firestore
  try {
    const doc = await firestoreGet(`users/${result.localId}`, result.idToken);
    if (doc && doc.fields && doc.fields.dailyLimit) {
      const baseLimit = parseInt(doc.fields.dailyLimit.integerValue) || 10;
      await chrome.storage.sync.set({ userBaseLimit: baseLimit });
    }
  } catch {}

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
    userUid: result.localId,
  });

  // Create user document in Firestore with default daily limit
  try {
    await createUserDoc(result.localId, result.idToken);
    await chrome.storage.sync.set({ userBaseLimit: 10 });
  } catch {}

  return { email: result.email };
}

async function handleSignOut() {
  await chrome.storage.local.remove(["authToken", "refreshToken", "tokenExpiry", "userEmail", "userUid"]);
  await chrome.storage.sync.remove(["userBaseLimit", "dailyCount", "dailyDate", "dailyExtra"]);
  chrome.action.setBadgeText({ text: "" });
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
    getDailyUsage: () => getDailyUsage(),
    addMoreAnalyses: () => handleAddMoreAnalyses(),
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
