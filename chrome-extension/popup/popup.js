const BACKEND_URL = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";

const $ = (id) => document.getElementById(id);

// ── Auth elements ────────────────────────────────────────
const authSection  = $("authSection");
const appSection   = $("appSection");
const tabLogin     = $("tabLogin");
const tabRegister  = $("tabRegister");
const authEmail    = $("authEmail");
const authPassword = $("authPassword");
const authBtn      = $("authBtn");
const authMsg      = $("authMsg");
const userEmailEl  = $("userEmail");
const logoutBtn    = $("logoutBtn");

// ── App elements ─────────────────────────────────────────
const langSelect    = $("language");
const saveBtn       = $("saveBtn");
const saveMsg       = $("saveMsg");
const statusDot     = $("statusDot");
const statusText    = $("statusText");
const trustedList   = $("trustedList");
const trustedInput  = $("trustedInput");
const addTrustedBtn = $("addTrustedBtn");
const csvBtn        = $("csvBtn");
const csvFile       = $("csvFile");
const csvMsg        = $("csvMsg");
const domainList    = $("domainList");
const domainInput   = $("domainInput");
const addDomainBtn  = $("addDomainBtn");
const quotaCount    = $("quotaCount");
const quotaLimit    = $("quotaLimit");
const quotaFill     = $("quotaFill");
const addMoreBtn    = $("addMoreBtn");

// ── Auth state ───────────────────────────────────────────
let authMode = "login"; // "login" or "register"

function sendMsg(action, data = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ action, ...data }, (resp) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!resp || !resp.success) return reject(new Error(resp?.error || "Unknown error"));
      resolve(resp.data);
    });
  });
}

// Check if user is logged in on popup open
chrome.storage.local.get(["userEmail", "authToken"], (items) => {
  if (items.userEmail && items.authToken) {
    showApp(items.userEmail);
  } else {
    showAuth();
  }
});

function showAuth() {
  authSection.style.display = "";
  appSection.style.display = "none";
}

function showApp(email) {
  authSection.style.display = "none";
  appSection.style.display = "";
  userEmailEl.textContent = email;

  chrome.storage.sync.get(
    { language: "en", trustedSenders: [], trustedDomains: [] },
    (items) => {
      langSelect.value = items.language;
      checkHealth();
      loadDailyUsage();
      renderTrustedList(items.trustedSenders);
      renderDomainList(items.trustedDomains);
    }
  );
}

// ── Auth tabs ────────────────────────────────────────────
tabLogin.addEventListener("click", () => {
  authMode = "login";
  tabLogin.classList.add("phd-popup__auth-tab--active");
  tabRegister.classList.remove("phd-popup__auth-tab--active");
  authBtn.textContent = "Log in";
  authMsg.textContent = "";
});

tabRegister.addEventListener("click", () => {
  authMode = "register";
  tabRegister.classList.add("phd-popup__auth-tab--active");
  tabLogin.classList.remove("phd-popup__auth-tab--active");
  authBtn.textContent = "Register";
  authMsg.textContent = "";
});

// ── Auth action ──────────────────────────────────────────
authBtn.addEventListener("click", async () => {
  const email = authEmail.value.trim();
  const password = authPassword.value;
  if (!email || !password) {
    authMsg.textContent = "Please fill in all fields";
    authMsg.className = "phd-popup__msg phd-popup__msg--err";
    return;
  }
  if (password.length < 6) {
    authMsg.textContent = "Password must be at least 6 characters";
    authMsg.className = "phd-popup__msg phd-popup__msg--err";
    return;
  }

  authBtn.disabled = true;
  authBtn.textContent = "Loading...";
  authMsg.textContent = "";

  try {
    const action = authMode === "login" ? "signIn" : "signUp";
    const result = await sendMsg(action, { email, password });
    showApp(result.email);
  } catch (err) {
    const msg = err.message
      .replace("EMAIL_NOT_FOUND", "Email not found")
      .replace("INVALID_PASSWORD", "Wrong password")
      .replace("INVALID_LOGIN_CREDENTIALS", "Invalid email or password")
      .replace("EMAIL_EXISTS", "Email already registered")
      .replace("WEAK_PASSWORD", "Password too weak (min 6 chars)")
      .replace("INVALID_EMAIL", "Invalid email address");
    authMsg.textContent = msg;
    authMsg.className = "phd-popup__msg phd-popup__msg--err";
  } finally {
    authBtn.disabled = false;
    authBtn.textContent = authMode === "login" ? "Log in" : "Register";
  }
});

authPassword.addEventListener("keydown", (e) => {
  if (e.key === "Enter") authBtn.click();
});

// ── Toggle password visibility ──────────────────────────
$("togglePassword").addEventListener("click", () => {
  const isHidden = authPassword.type === "password";
  authPassword.type = isHidden ? "text" : "password";
  $("togglePassword").textContent = isHidden ? "\u25CF" : "\u{1F441}";
});

// ── Logout ───────────────────────────────────────────────
logoutBtn.addEventListener("click", async () => {
  await sendMsg("signOut");
  showAuth();
});

// ── Save settings ────────────────────────────────────────
saveBtn.addEventListener("click", () => {
  const language = langSelect.value;
  chrome.storage.sync.set({ language }, () => {
    flash("Settings saved", "ok");
    chrome.tabs.query({ url: "https://mail.google.com/*" }, (tabs) => {
      for (const tab of tabs) {
        chrome.tabs.sendMessage(tab.id, { action: "settingsUpdated", language }).catch(() => {});
      }
    });
  });
});

// ── Health check ─────────────────────────────────────────
async function checkHealth() {
  statusDot.className = "phd-popup__dot";
  statusText.textContent = "Checking...";
  try {
    const resp = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(60000) });
    if (!resp.ok) throw new Error();
    statusDot.classList.add("phd-popup__dot--ok");
    statusText.textContent = "Connected";
  } catch {
    statusDot.classList.add("phd-popup__dot--error");
    statusText.textContent = "Backend unreachable";
  }
}

// ── Flash message ────────────────────────────────────────
function flash(text, type) {
  saveMsg.textContent = text;
  saveMsg.className = `phd-popup__msg phd-popup__msg--${type}`;
  setTimeout(() => { saveMsg.textContent = ""; saveMsg.className = "phd-popup__msg"; }, 2500);
}

// ── Trusted senders ──────────────────────────────────────
function renderTrustedList(senders) {
  if (!senders || senders.length === 0) {
    trustedList.innerHTML = '<div class="phd-popup__trusted-empty">No trusted senders yet</div>';
    return;
  }
  trustedList.innerHTML = senders.map((s) => `
    <div class="phd-popup__trusted-item">
      <span class="phd-popup__trusted-email" title="${s}">${s}</span>
      <button class="phd-popup__trusted-remove" data-sender="${s}" title="Remove">&times;</button>
    </div>
  `).join("");
  trustedList.querySelectorAll(".phd-popup__trusted-remove").forEach((btn) => {
    btn.addEventListener("click", () => removeTrusted(btn.dataset.sender));
  });
}

function notifyGmailTabs() {
  chrome.storage.sync.get({ trustedSenders: [], trustedDomains: [] }, (items) => {
    chrome.tabs.query({ url: "https://mail.google.com/*" }, (tabs) => {
      for (const tab of tabs) {
        chrome.tabs.sendMessage(tab.id, {
          action: "trustedSendersUpdated",
          trustedSenders: items.trustedSenders,
          trustedDomains: items.trustedDomains,
        }).catch(() => {});
      }
    });
  });
}

addTrustedBtn.addEventListener("click", () => {
  const email = trustedInput.value.trim().toLowerCase();
  if (!email) return;
  chrome.storage.sync.get({ trustedSenders: [] }, (items) => {
    const list = items.trustedSenders;
    if (list.includes(email)) { flash("Already trusted", "err"); return; }
    list.push(email);
    chrome.storage.sync.set({ trustedSenders: list }, () => {
      trustedInput.value = "";
      renderTrustedList(list);
      notifyGmailTabs();
    });
  });
});

trustedInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addTrustedBtn.click(); });

function removeTrusted(sender) {
  chrome.storage.sync.get({ trustedSenders: [] }, (items) => {
    const list = items.trustedSenders.filter((s) => s !== sender);
    chrome.storage.sync.set({ trustedSenders: list }, () => {
      renderTrustedList(list);
      notifyGmailTabs();
    });
  });
}

// ── CSV import ───────────────────────────────────────────
csvBtn.addEventListener("click", () => csvFile.click());
csvFile.addEventListener("change", () => {
  const file = csvFile.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    const emails = e.target.result
      .split(/[\r\n,;]+/)
      .map((s) => s.trim().toLowerCase().replace(/^["']+|["']+$/g, ""))
      .filter((s) => s && s.includes("@"));
    if (emails.length === 0) {
      csvMsg.textContent = "No valid emails found";
      csvMsg.style.color = "#dc2626";
      return;
    }
    chrome.storage.sync.get({ trustedSenders: [] }, (items) => {
      const existing = new Set(items.trustedSenders);
      let added = 0;
      for (const em of emails) { if (!existing.has(em)) { existing.add(em); added++; } }
      const list = [...existing];
      chrome.storage.sync.set({ trustedSenders: list }, () => {
        renderTrustedList(list);
        notifyGmailTabs();
        csvMsg.textContent = `+${added} emails imported`;
        csvMsg.style.color = "#16a34a";
        setTimeout(() => { csvMsg.textContent = ""; }, 3000);
      });
    });
    csvFile.value = "";
  };
  reader.readAsText(file);
});

// ── Trusted domains ──────────────────────────────────────
function renderDomainList(domains) {
  if (!domains || domains.length === 0) {
    domainList.innerHTML = '<div class="phd-popup__trusted-empty">No trusted domains yet</div>';
    return;
  }
  domainList.innerHTML = domains.map((d) => `
    <div class="phd-popup__trusted-item">
      <span class="phd-popup__trusted-email" title="@${d}">@${d}</span>
      <button class="phd-popup__trusted-remove" data-domain="${d}" title="Remove">&times;</button>
    </div>
  `).join("");
  domainList.querySelectorAll(".phd-popup__trusted-remove").forEach((btn) => {
    btn.addEventListener("click", () => removeDomain(btn.dataset.domain));
  });
}

addDomainBtn.addEventListener("click", () => {
  let domain = domainInput.value.trim().toLowerCase().replace(/^@/, "");
  if (!domain) return;
  chrome.storage.sync.get({ trustedDomains: [] }, (items) => {
    const list = items.trustedDomains;
    if (list.includes(domain)) { flash("Already trusted", "err"); return; }
    list.push(domain);
    chrome.storage.sync.set({ trustedDomains: list }, () => {
      domainInput.value = "";
      renderDomainList(list);
      notifyGmailTabs();
    });
  });
});

domainInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addDomainBtn.click(); });

// ── Daily usage / quota ─────────────────────────────────
async function loadDailyUsage() {
  try {
    const usage = await sendMsg("getDailyUsage");
    renderQuota(usage.count, usage.limit);
  } catch {
    renderQuota(0, 15);
  }
}

function renderQuota(count, limit) {
  quotaCount.textContent = count;
  quotaLimit.textContent = limit;
  const pct = Math.min((count / limit) * 100, 100);
  quotaFill.style.width = `${pct}%`;
  quotaFill.className = "phd-popup__quota-fill";
  if (pct >= 100) {
    quotaFill.classList.add("phd-popup__quota-fill--full");
    quotaCount.style.color = "#ef4444";
  } else if (pct >= 70) {
    quotaFill.classList.add("phd-popup__quota-fill--warn");
    quotaCount.style.color = "#f59e0b";
  } else {
    quotaCount.style.color = "#3b82f6";
  }
}

addMoreBtn.addEventListener("click", async () => {
  addMoreBtn.disabled = true;
  addMoreBtn.textContent = "Adding...";
  try {
    const usage = await sendMsg("addMoreAnalyses");
    renderQuota(usage.count, usage.limit);
    flash("+15 analyses added", "ok");
  } catch (err) {
    flash(err.message, "err");
  } finally {
    addMoreBtn.disabled = false;
    addMoreBtn.textContent = "+ 15 more";
  }
});

function removeDomain(domain) {
  chrome.storage.sync.get({ trustedDomains: [] }, (items) => {
    const list = items.trustedDomains.filter((d) => d !== domain);
    chrome.storage.sync.set({ trustedDomains: list }, () => {
      renderDomainList(list);
      notifyGmailTabs();
    });
  });
}
