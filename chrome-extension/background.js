const BACKEND_URL = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";
const FIREBASE_API_KEY = "AIzaSyBrXR9gC0Iw66XuItJmQYzU8e0yNgVgmLM";
const FIREBASE_PROJECT_ID = "universal-login-hub";
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

const PLAN_LIMITS = { free: 10, basic: 50, pro: 250 };

async function fetchUserPlan() {
  try {
    const token = await getAuthToken();
    const { userUid } = await chrome.storage.local.get("userUid");
    if (!userUid) return { planType: "free", dailyLimit: 10, planExpiresAt: null, role: "user" };

    const doc = await firestoreGet(`users/${userUid}/apps/phishbuster`, token);
    if (!doc || !doc.fields) return { planType: "free", dailyLimit: 10, planExpiresAt: null, role: "user" };

    const f = doc.fields;
    const role = f.role?.stringValue || "user";
    let planType = f.planType?.stringValue || "free";
    let planExpiresAt = f.planExpiresAt?.stringValue || null;
    let dailyLimit = parseInt(f.dailyLimit?.integerValue) || PLAN_LIMITS[planType] || 10;

    // Check expiry
    if (planType !== "free" && planExpiresAt) {
      if (new Date(planExpiresAt) < new Date()) {
        planType = "free";
        dailyLimit = PLAN_LIMITS.free;
        planExpiresAt = null;
      }
    }

    // Role override
    if (role === "unlimited") {
      dailyLimit = Infinity;
    }

    const plan = { planType, dailyLimit, planExpiresAt, role };
    await chrome.storage.local.set({ cachedPlan: plan });
    return plan;
  } catch {
    const { cachedPlan } = await chrome.storage.local.get("cachedPlan");
    return cachedPlan || { planType: "free", dailyLimit: 10, planExpiresAt: null, role: "user" };
  }
}

async function createUserDoc(uid, email, token) {
  await firestoreSet(`users/${uid}`, {
    email: { stringValue: email },
  }, token);
  await firestoreSet(`users/${uid}/apps/phishbuster`, {
    enabled: { booleanValue: true },
    role: { stringValue: "user" },
    dailyLimit: { integerValue: "10" },
    planType: { stringValue: "free" },
    planExpiresAt: { stringValue: "" },
    stripeCustomerId: { stringValue: "" },
    lastPaymentId: { stringValue: "" },
  }, token);
}

async function checkAppAccess(uid, token) {
  const doc = await firestoreGet(`users/${uid}/apps/phishbuster`, token);
  if (!doc || !doc.fields || !doc.fields.enabled || !doc.fields.enabled.booleanValue) {
    throw new Error("You don't have access to PhishBuster. Contact the administrator.");
  }
  return doc.fields.role?.stringValue || "user";
}

// ── Daily usage (persisted in Firestore) ────────────────

function getTodayStr() {
  return new Date().toISOString().slice(0, 10);
}

async function fetchDailyCount() {
  try {
    const token = await getAuthToken();
    const { userUid } = await chrome.storage.local.get("userUid");
    if (!userUid) return 0;
    const today = getTodayStr();
    const doc = await firestoreGet(`users/${userUid}/apps/phishbuster/usage/${today}`, token);
    if (doc && doc.fields && doc.fields.count) {
      return parseInt(doc.fields.count.integerValue) || 0;
    }
    return 0;
  } catch {
    return 0;
  }
}

async function saveDailyCount(count) {
  try {
    const token = await getAuthToken();
    const { userUid } = await chrome.storage.local.get("userUid");
    if (!userUid) return;
    const today = getTodayStr();
    await firestoreSet(`users/${userUid}/apps/phishbuster/usage/${today}`, {
      count: { integerValue: String(count) },
    }, token);
  } catch {}
}

async function getDailyUsage() {
  const plan = await fetchUserPlan();
  const count = await fetchDailyCount();
  updateBadge(count, plan.dailyLimit);
  return {
    count,
    limit: plan.dailyLimit,
    planType: plan.planType,
    planExpiresAt: plan.planExpiresAt,
    role: plan.role,
  };
}

async function incrementDailyCount() {
  const usage = await getDailyUsage();
  const newCount = usage.count + 1;
  await saveDailyCount(newCount);
  updateBadge(newCount, usage.limit);
  return { count: newCount, limit: usage.limit };
}

function updateBadge(count, limit) {
  const text = String(count);
  const color = (limit !== Infinity && count >= limit) ? "#ef4444" : "#3b82f6";
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

// Update badge on startup
getDailyUsage().then(({ count, limit }) => updateBadge(count, limit));

// ── API handlers ─────────────────────────────────────────

async function handleCreateCheckout(data) {
  const headers = await getAuthHeaders();
  const response = await fetchWithTimeout(`${BACKEND_URL}/checkout`, {
    method: "POST",
    headers,
    body: JSON.stringify({ plan: data.plan }),
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Checkout failed: ${err}`);
  }
  const result = await response.json();
  chrome.tabs.create({ url: result.url });
  return { opened: true };
}

async function handleAnalyzeText(data) {
  // Check daily limit (Infinity for unlimited users)
  const usage = await getDailyUsage();
  if (usage.limit !== Infinity && usage.count >= usage.limit) {
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

  // Check email verification
  const verified = await lookupEmailVerified(result.idToken);
  if (!verified) {
    throw new Error("EMAIL_NOT_VERIFIED");
  }

  // Check app access before completing sign-in
  await checkAppAccess(result.localId, result.idToken);

  await chrome.storage.local.set({
    authToken: result.idToken,
    refreshToken: result.refreshToken,
    tokenExpiry: Date.now() + parseInt(result.expiresIn) * 1000,
    userEmail: result.email,
    userUid: result.localId,
  });

  return { email: result.email };
}

async function sendVerificationEmail(idToken) {
  const resp = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requestType: "VERIFY_EMAIL", idToken }),
    }
  );
  if (!resp.ok) {
    const err = await resp.json();
    throw new Error(err.error?.message || "Failed to send verification email");
  }
}

async function lookupEmailVerified(idToken) {
  const resp = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken }),
    }
  );
  if (!resp.ok) throw new Error("Failed to check email verification status");
  const data = await resp.json();
  return data.users?.[0]?.emailVerified === true;
}

async function handleSignUp(data) {
  if (data.email && data.email.includes("+")) {
    throw new Error("INVALID_EMAIL");
  }

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

  // Create user document in Firestore
  try {
    await createUserDoc(result.localId, result.email, result.idToken);
  } catch {}

  // Send verification email
  await sendVerificationEmail(result.idToken);

  // Do NOT auto-login — user must verify email first
  return { email: result.email, verificationSent: true };
}

async function handleResendVerification(data) {
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

  await sendVerificationEmail(result.idToken);
  return { sent: true };
}

async function handleSignOut() {
  await chrome.storage.local.remove(["authToken", "refreshToken", "tokenExpiry", "userEmail", "userUid", "cachedPlan"]);
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
    resendVerification: () => handleResendVerification(message),
    signOut: () => handleSignOut(),
    getUser: () => handleGetUser(),
    getDailyUsage: () => getDailyUsage(),
    createCheckout: () => handleCreateCheckout(message),
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
