const BACKEND_URL = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";

const $ = (id) => document.getElementById(id);

// ── Popup translations ──────────────────────────────────
const POPUP_I18N = {
  en: {
    login: "Log in",
    register: "Register",
    email_placeholder: "Email",
    password_placeholder: "Password",
    loading: "Loading...",
    fill_all_fields: "Please fill in all fields",
    no_plus_email: "Email addresses with '+' are not allowed",
    password_too_short: "Password must be at least 6 characters",
    email_not_found: "Email not found",
    wrong_password: "Wrong password",
    invalid_credentials: "Invalid email or password",
    email_exists: "Email already registered",
    weak_password: "Password too weak (min 6 chars)",
    invalid_email: "Invalid email address",
    verify_title: "Check your email",
    verify_text_before: "We sent a verification link to",
    verify_text_after: "Click the link to activate your account.",
    verify_hint: "Can't find it? Check your spam/junk folder.",
    resend: "Resend verification email",
    resend_sending: "Sending...",
    resend_ok: "Verification email sent! Check your spam folder too.",
    resend_rate_limit: "Too many attempts. Please wait 15-60 minutes before trying again, and check your spam folder.",
    resend_go_back: "Please go back and log in again",
    back_to_login: "Back to login",
    logout: "Log out",
    checking: "Checking...",
    connected: "Connected",
    backend_unreachable: "Backend unreachable",
    analyses_today: "analyses today",
    add_more: "+ 15 more",
    adding: "Adding...",
    added_more: "+15 analyses added",
    language: "Language",
    save: "Save",
    settings_saved: "Settings saved",
    trusted_senders: "Trusted senders",
    no_trusted_senders: "No trusted senders yet",
    already_trusted: "Already trusted",
    import_csv: "Import CSV",
    no_valid_emails: "No valid emails found",
    trusted_domains: "Trusted domains",
    no_trusted_domains: "No trusted domains yet",
  },
  es: {
    login: "Iniciar sesión",
    register: "Registrarse",
    email_placeholder: "Email",
    password_placeholder: "Contraseña",
    loading: "Cargando...",
    fill_all_fields: "Rellena todos los campos",
    no_plus_email: "No se permiten emails con '+'",
    password_too_short: "La contraseña debe tener al menos 6 caracteres",
    email_not_found: "Email no encontrado",
    wrong_password: "Contraseña incorrecta",
    invalid_credentials: "Email o contraseña incorrectos",
    email_exists: "Email ya registrado",
    weak_password: "Contraseña demasiado débil (mín. 6 caracteres)",
    invalid_email: "Email no válido",
    verify_title: "Revisa tu email",
    verify_text_before: "Hemos enviado un enlace de verificación a",
    verify_text_after: "Haz clic en el enlace para activar tu cuenta.",
    verify_hint: "¿No lo encuentras? Revisa la carpeta de spam.",
    resend: "Reenviar email de verificación",
    resend_sending: "Enviando...",
    resend_ok: "¡Email de verificación enviado! Revisa también la carpeta de spam.",
    resend_rate_limit: "Demasiados intentos. Espera 15-60 minutos e inténtalo de nuevo. Revisa tu carpeta de spam.",
    resend_go_back: "Vuelve atrás e inicia sesión de nuevo",
    back_to_login: "Volver al inicio de sesión",
    logout: "Cerrar sesión",
    checking: "Comprobando...",
    connected: "Conectado",
    backend_unreachable: "Backend no disponible",
    analyses_today: "análisis hoy",
    add_more: "+ 15 más",
    adding: "Añadiendo...",
    added_more: "+15 análisis añadidos",
    language: "Idioma",
    save: "Guardar",
    settings_saved: "Ajustes guardados",
    trusted_senders: "Remitentes de confianza",
    no_trusted_senders: "Sin remitentes de confianza",
    already_trusted: "Ya está en la lista",
    import_csv: "Importar CSV",
    no_valid_emails: "No se encontraron emails válidos",
    trusted_domains: "Dominios de confianza",
    no_trusted_domains: "Sin dominios de confianza",
  },
  ca: {
    login: "Iniciar sessió",
    register: "Registrar-se",
    email_placeholder: "Email",
    password_placeholder: "Contrasenya",
    loading: "Carregant...",
    fill_all_fields: "Omple tots els camps",
    no_plus_email: "No es permeten emails amb '+'",
    password_too_short: "La contrasenya ha de tenir almenys 6 caràcters",
    email_not_found: "Email no trobat",
    wrong_password: "Contrasenya incorrecta",
    invalid_credentials: "Email o contrasenya incorrectes",
    email_exists: "Email ja registrat",
    weak_password: "Contrasenya massa feble (mínim 6 caràcters)",
    invalid_email: "Email no vàlid",
    verify_title: "Revisa el teu email",
    verify_text_before: "Hem enviat un enllaç de verificació a",
    verify_text_after: "Fes clic a l'enllaç per activar el teu compte.",
    verify_hint: "No el trobes? Revisa la carpeta de spam.",
    resend: "Reenviar email de verificació",
    resend_sending: "Enviant...",
    resend_ok: "Email de verificació enviat! Revisa també la carpeta de spam.",
    resend_rate_limit: "Massa intents. Espera 15-60 minuts i torna-ho a provar. Revisa la carpeta de spam.",
    resend_go_back: "Torna enrere i inicia sessió de nou",
    back_to_login: "Tornar a l'inici de sessió",
    logout: "Tancar sessió",
    checking: "Comprovant...",
    connected: "Connectat",
    backend_unreachable: "Backend no disponible",
    analyses_today: "anàlisis avui",
    add_more: "+ 15 més",
    adding: "Afegint...",
    added_more: "+15 anàlisis afegides",
    language: "Idioma",
    save: "Desar",
    settings_saved: "Ajustos desats",
    trusted_senders: "Remitents de confiança",
    no_trusted_senders: "Sense remitents de confiança",
    already_trusted: "Ja està a la llista",
    import_csv: "Importar CSV",
    no_valid_emails: "No s'han trobat emails vàlids",
    trusted_domains: "Dominis de confiança",
    no_trusted_domains: "Sense dominis de confiança",
  },
};

let currentLang = "en";

function t(key) {
  return POPUP_I18N[currentLang]?.[key] || POPUP_I18N.en[key] || key;
}

function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
}

// ── Auth elements ────────────────────────────────────────
const authSection    = $("authSection");
const appSection     = $("appSection");
const verifySection  = $("verifySection");
const tabLogin       = $("tabLogin");
const tabRegister    = $("tabRegister");
const authEmail      = $("authEmail");
const authPassword   = $("authPassword");
const authBtn        = $("authBtn");
const authMsg        = $("authMsg");
const userEmailEl    = $("userEmail");
const logoutBtn      = $("logoutBtn");
const verifyEmailEl  = $("verifyEmail");
const resendBtn      = $("resendBtn");
const verifyMsg      = $("verifyMsg");
const backToLoginBtn = $("backToLoginBtn");

// ── App elements ─────────────────────────────────────────
const langGroup     = $("langGroup");
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
chrome.storage.sync.get({ language: "en" }, (items) => {
  currentLang = items.language;
  applyI18n();

  chrome.storage.local.get(["userEmail", "authToken"], (local) => {
    if (local.userEmail && local.authToken) {
      showApp(local.userEmail);
    } else {
      showAuth();
    }
  });
});

// ── Pending verification state ──────────────────────────
let pendingVerifyEmail = "";
let pendingVerifyPassword = "";

function showAuth() {
  authSection.style.display = "";
  appSection.style.display = "none";
  verifySection.style.display = "none";
}

function showVerify(email) {
  authSection.style.display = "none";
  appSection.style.display = "none";
  verifySection.style.display = "";
  verifyEmailEl.textContent = email;
  verifyMsg.textContent = "";
}

function showApp(email) {
  authSection.style.display = "none";
  appSection.style.display = "";
  verifySection.style.display = "none";
  userEmailEl.textContent = email;

  chrome.storage.sync.get(
    { language: "en", trustedSenders: [], trustedDomains: [] },
    (items) => {
      currentLang = items.language;
      setActiveLang(items.language);
      applyI18n();
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
  authBtn.textContent = t("login");
  authMsg.textContent = "";
});

tabRegister.addEventListener("click", () => {
  authMode = "register";
  tabRegister.classList.add("phd-popup__auth-tab--active");
  tabLogin.classList.remove("phd-popup__auth-tab--active");
  authBtn.textContent = t("register");
  authMsg.textContent = "";
});

// ── Auth action ──────────────────────────────────────────
authBtn.addEventListener("click", async () => {
  const email = authEmail.value.trim();
  const password = authPassword.value;
  if (!email || !password) {
    authMsg.textContent = t("fill_all_fields");
    authMsg.className = "phd-popup__msg phd-popup__msg--err";
    return;
  }
  if (authMode === "register" && email.includes("+")) {
    authMsg.textContent = t("no_plus_email");
    authMsg.className = "phd-popup__msg phd-popup__msg--err";
    return;
  }
  if (password.length < 6) {
    authMsg.textContent = t("password_too_short");
    authMsg.className = "phd-popup__msg phd-popup__msg--err";
    return;
  }

  authBtn.disabled = true;
  authBtn.textContent = t("loading");
  authMsg.textContent = "";

  try {
    const action = authMode === "login" ? "signIn" : "signUp";
    const result = await sendMsg(action, { email, password });

    if (result.verificationSent) {
      pendingVerifyEmail = email;
      pendingVerifyPassword = password;
      showVerify(email);
    } else {
      showApp(result.email);
    }
  } catch (err) {
    if (err.message.includes("EMAIL_NOT_VERIFIED")) {
      pendingVerifyEmail = email;
      pendingVerifyPassword = password;
      showVerify(email);
    } else {
      const msg = err.message
        .replace("EMAIL_NOT_FOUND", t("email_not_found"))
        .replace("INVALID_PASSWORD", t("wrong_password"))
        .replace("INVALID_LOGIN_CREDENTIALS", t("invalid_credentials"))
        .replace("EMAIL_EXISTS", t("email_exists"))
        .replace("WEAK_PASSWORD", t("weak_password"))
        .replace("INVALID_EMAIL", t("invalid_email"));
      authMsg.textContent = msg;
      authMsg.className = "phd-popup__msg phd-popup__msg--err";
    }
  } finally {
    authBtn.disabled = false;
    authBtn.textContent = authMode === "login" ? t("login") : t("register");
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

// ── Language selector ────────────────────────────────────
function getActiveLang() {
  const active = langGroup.querySelector(".phd-popup__lang-btn--active");
  return active ? active.dataset.lang : "en";
}

function setActiveLang(lang) {
  langGroup.querySelectorAll(".phd-popup__lang-btn").forEach((btn) => {
    btn.classList.toggle("phd-popup__lang-btn--active", btn.dataset.lang === lang);
  });
}

langGroup.addEventListener("click", (e) => {
  const btn = e.target.closest(".phd-popup__lang-btn");
  if (!btn) return;
  setActiveLang(btn.dataset.lang);
});

// ── Save settings ────────────────────────────────────────
saveBtn.addEventListener("click", () => {
  const language = getActiveLang();
  currentLang = language;
  applyI18n();
  chrome.storage.sync.set({ language }, () => {
    flash(t("settings_saved"), "ok");
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
  statusText.textContent = t("checking");
  try {
    const resp = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(60000) });
    if (!resp.ok) throw new Error();
    statusDot.classList.add("phd-popup__dot--ok");
    statusText.textContent = t("connected");
  } catch {
    statusDot.classList.add("phd-popup__dot--error");
    statusText.textContent = t("backend_unreachable");
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
    trustedList.innerHTML = `<div class="phd-popup__trusted-empty">${t("no_trusted_senders")}</div>`;
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
    if (list.includes(email)) { flash(t("already_trusted"), "err"); return; }
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
      csvMsg.textContent = t("no_valid_emails");
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
    domainList.innerHTML = `<div class="phd-popup__trusted-empty">${t("no_trusted_domains")}</div>`;
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
    if (list.includes(domain)) { flash(t("already_trusted"), "err"); return; }
    list.push(domain);
    chrome.storage.sync.set({ trustedDomains: list }, () => {
      domainInput.value = "";
      renderDomainList(list);
      notifyGmailTabs();
    });
  });
});

domainInput.addEventListener("keydown", (e) => { if (e.key === "Enter") addDomainBtn.click(); });

// ── Email verification ──────────────────────────────────
resendBtn.addEventListener("click", async () => {
  if (!pendingVerifyEmail || !pendingVerifyPassword) {
    verifyMsg.textContent = t("resend_go_back");
    verifyMsg.className = "phd-popup__msg phd-popup__msg--err";
    return;
  }
  resendBtn.disabled = true;
  resendBtn.textContent = t("resend_sending");
  verifyMsg.textContent = "";
  try {
    await sendMsg("resendVerification", {
      email: pendingVerifyEmail,
      password: pendingVerifyPassword,
    });
    verifyMsg.textContent = t("resend_ok");
    verifyMsg.className = "phd-popup__msg phd-popup__msg--ok";
  } catch (err) {
    let msg = err.message;
    if (msg.includes("TOO_MANY_ATTEMPTS_TRY_LATER")) {
      msg = t("resend_rate_limit");
    }
    verifyMsg.textContent = msg;
    verifyMsg.className = "phd-popup__msg phd-popup__msg--err";
  } finally {
    resendBtn.disabled = false;
    resendBtn.textContent = t("resend");
  }
});

backToLoginBtn.addEventListener("click", () => {
  pendingVerifyEmail = "";
  pendingVerifyPassword = "";
  authMode = "login";
  tabLogin.classList.add("phd-popup__auth-tab--active");
  tabRegister.classList.remove("phd-popup__auth-tab--active");
  authBtn.textContent = t("login");
  authMsg.textContent = "";
  showAuth();
});

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
  addMoreBtn.textContent = t("adding");
  try {
    const usage = await sendMsg("addMoreAnalyses");
    renderQuota(usage.count, usage.limit);
    flash(t("added_more"), "ok");
  } catch (err) {
    flash(err.message, "err");
  } finally {
    addMoreBtn.disabled = false;
    addMoreBtn.textContent = t("add_more");
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
