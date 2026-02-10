const BACKEND_URL = "https://phishing-prevention-1-vqvj.onrender.com/api/v1";

const $ = (id) => document.getElementById(id);

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
const counterNumber = $("counterNumber");

// ── Load saved settings ──────────────────────────────────
chrome.storage.sync.get(
  { language: "en", trustedSenders: [], trustedDomains: [], analyzedCount: 0 },
  (items) => {
    langSelect.value = items.language;
    counterNumber.textContent = items.analyzedCount;
    checkHealth();
    renderTrustedList(items.trustedSenders);
    renderDomainList(items.trustedDomains);
  }
);

// ── Save ─────────────────────────────────────────────────
saveBtn.addEventListener("click", () => {
  const language = langSelect.value;

  chrome.storage.sync.set({ language }, () => {
    flash("Settings saved", "ok");

    // Notify open Gmail tabs
    chrome.tabs.query({ url: "https://mail.google.com/*" }, (tabs) => {
      for (const tab of tabs) {
        chrome.tabs.sendMessage(tab.id, {
          action: "settingsUpdated",
          language,
        }).catch(() => {});
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
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    statusDot.classList.add("phd-popup__dot--ok");
    const apis = data.apis_configured || {};
    const active = Object.entries(apis).filter(([, v]) => v).map(([k]) => k);
    statusText.textContent = active.length
      ? `Connected — APIs: ${active.join(", ")}`
      : "Connected";
  } catch {
    statusDot.classList.add("phd-popup__dot--error");
    statusText.textContent = "Backend unreachable";
  }
}

// ── Flash message ────────────────────────────────────────
function flash(text, type) {
  saveMsg.textContent = text;
  saveMsg.className = `phd-popup__msg phd-popup__msg--${type}`;
  setTimeout(() => {
    saveMsg.textContent = "";
    saveMsg.className = "phd-popup__msg";
  }, 2500);
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

// ── Trusted senders: add / remove ────────────────────────
addTrustedBtn.addEventListener("click", () => {
  const email = trustedInput.value.trim().toLowerCase();
  if (!email) return;
  chrome.storage.sync.get({ trustedSenders: [] }, (items) => {
    const list = items.trustedSenders;
    if (list.includes(email)) {
      flash("Already trusted", "err");
      return;
    }
    list.push(email);
    chrome.storage.sync.set({ trustedSenders: list }, () => {
      trustedInput.value = "";
      renderTrustedList(list);
      notifyGmailTabs();
    });
  });
});

trustedInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addTrustedBtn.click();
});

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
    const text = e.target.result;
    // Parse CSV: one email per line, or comma/semicolon separated
    const emails = text
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
      for (const email of emails) {
        if (!existing.has(email)) {
          existing.add(email);
          added++;
        }
      }
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
    if (list.includes(domain)) {
      flash("Already trusted", "err");
      return;
    }
    list.push(domain);
    chrome.storage.sync.set({ trustedDomains: list }, () => {
      domainInput.value = "";
      renderDomainList(list);
      notifyGmailTabs();
    });
  });
});

domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addDomainBtn.click();
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
