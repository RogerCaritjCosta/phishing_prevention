/* Gmail Phishing Detector — Content Script */

(function () {
  "use strict";

  const BANNER_ID = "phd-banner";
  const POLL_INTERVAL = 300;
  const POLL_TIMEOUT = 5000;
  const DEBOUNCE_MS = 200;

  // ── State ───────────────────────────────────────────────
  const cache = {};          // emailId → analysis result
  let translations = {};
  let currentLang = "en";
  let currentEmailId = null; // tracks which email is currently displayed
  let currentSender = null;  // sender of the currently displayed email
  let trustedSenders = [];   // list of trusted sender addresses
  let trustedDomains = [];   // list of trusted domains
  let debounceTimer = null;
  let observer = null;

  // ── Selectors (multi-tier) ──────────────────────────────
  const SELECTORS = {
    emailBody: [
      'div.a3s.aiL',
      'div.a3s',
      'div.ii.gt',
    ],
    sender: [
      'span.gD[email]',
    ],
    subject: [
      'h2.hP',
    ],
    injectionPoint: [
      'div[role="listitem"]',
      '.nH.aHU',
    ],
  };

  // ── Helpers ─────────────────────────────────────────────

  function queryFirst(selectors, root = document) {
    for (const sel of selectors) {
      const el = root.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  function getEmailIdFromHash() {
    const hash = location.hash; // e.g. #inbox/FMfcgz…
    const parts = hash.split("/");
    // The email ID is the last segment that looks like a Gmail message ID
    const id = parts[parts.length - 1];
    if (id && id.length > 6 && id !== "inbox" && id !== "sent" && id !== "drafts") {
      return id;
    }
    return null;
  }

  function waitForEmailBody() {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const check = () => {
        const body = queryFirst(SELECTORS.emailBody);
        if (body && body.innerText.trim().length > 0) {
          resolve(body);
          return;
        }
        if (Date.now() - start > POLL_TIMEOUT) {
          reject(new Error("Timeout waiting for email body"));
          return;
        }
        setTimeout(check, POLL_INTERVAL);
      };
      check();
    });
  }

  // ── Extraction ──────────────────────────────────────────

  function extractSender() {
    const el = queryFirst(SELECTORS.sender);
    if (el) return el.getAttribute("email") || el.textContent.trim();
    // Fallback: look for email-like text in header area
    const headerArea = document.querySelector('.gE.iv.gt');
    if (headerArea) {
      const match = headerArea.textContent.match(/[\w.+-]+@[\w.-]+\.\w{2,}/);
      if (match) return match[0];
    }
    return null;
  }

  function extractSubject() {
    const el = queryFirst(SELECTORS.subject);
    if (el) return el.textContent.trim();
    // Fallback: document title without " - Gmail" suffix
    const title = document.title.replace(/\s*-\s*Gmail\s*$/, "").trim();
    return title || null;
  }

  function composeAnalysisText(sender, subject, bodyEl) {
    const parts = [];
    if (sender) parts.push(`From: ${sender}`);
    if (subject) parts.push(`Subject: ${subject}`);

    // Include both plain text and raw HTML so the backend can detect
    // link mismatches via its HTML parser
    const plainText = bodyEl.innerText.trim();
    const rawHtml = bodyEl.innerHTML;
    parts.push("", plainText, "", rawHtml);

    return parts.join("\n");
  }

  // ── Injection point ─────────────────────────────────────

  function getInjectionPoint() {
    // Strategy 1: find the email container via role="listitem"
    const listItem = document.querySelector('div[role="listitem"]');
    if (listItem) return { parent: listItem, position: "prepend" };

    // Strategy 2: Gmail's main email view container
    const container = document.querySelector('.nH.aHU');
    if (container) return { parent: container, position: "prepend" };

    // Strategy 3: inject right before the first email body
    const body = queryFirst(SELECTORS.emailBody);
    if (body && body.parentElement) {
      return { parent: body.parentElement, position: "before", ref: body };
    }

    return null;
  }

  // ── Banner rendering ───────────────────────────────────

  function removeBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) existing.remove();
  }

  function injectBanner(bannerEl) {
    removeBanner();
    bannerEl.id = BANNER_ID;
    const point = getInjectionPoint();
    if (!point) return;

    if (point.position === "before" && point.ref) {
      point.parent.insertBefore(bannerEl, point.ref);
    } else {
      point.parent.prepend(bannerEl);
    }
  }

  function t(key, fallback) {
    return translations[key] || fallback || key;
  }

  function renderLoadingBanner() {
    const el = document.createElement("div");
    el.className = "phd-banner phd-banner--loading";
    el.innerHTML = `
      <div class="phd-header">
        <div class="phd-spinner"></div>
        <span class="phd-loading-text">${t("analyzing", "Analyzing email for phishing indicators...")}</span>
      </div>`;
    injectBanner(el);
  }

  function renderErrorBanner(message, onRetry) {
    const el = document.createElement("div");
    el.className = "phd-banner phd-banner--error";
    el.innerHTML = `
      <div class="phd-header">
        <span class="phd-shield">&#x26A0;</span>
        <span class="phd-error-text">${escapeHtml(message)}</span>
        <button class="phd-retry">${t("retry", "Retry")}</button>
        <button class="phd-close" title="Close">&times;</button>
      </div>`;
    el.querySelector(".phd-retry").addEventListener("click", onRetry);
    el.querySelector(".phd-close").addEventListener("click", removeBanner);
    injectBanner(el);
  }

  function renderBanner(result) {
    const risk = result.risk_level || "low";
    const riskLabel = result.risk_level_label || risk;
    const alarms = result.alarms || [];

    const el = document.createElement("div");
    el.className = `phd-banner phd-banner--${risk}`;

    const isTrusted = risk === "trusted";
    const shieldIcon = (risk === "low" || isTrusted) ? "&#x1F6E1;" : "&#x26A0;";
    const hasAlarms = alarms.length > 0;

    const trustBtn = (currentSender && !isTrusted)
      ? `<button class="phd-trust" title="${escapeHtml(currentSender)}">&#x2714; ${t("trust_sender", "Trust sender")}</button>`
      : "";

    el.innerHTML = `
      <div class="phd-header">
        <span class="phd-shield">${shieldIcon}</span>
        <span class="phd-title">${t("results_title", "Phishing Analysis")}</span>
        <span class="phd-risk-badge phd-risk-badge--${risk}">${escapeHtml(riskLabel)}</span>
        ${hasAlarms ? `<button class="phd-toggle" title="Toggle details">&#x25BC;</button>` : ""}
        ${trustBtn}
        <button class="phd-close" title="Close">&times;</button>
      </div>
      <div class="phd-details ${hasAlarms ? "phd-details--hidden" : ""}">
        ${renderMeta(result)}
        ${hasAlarms ? renderAlarms(alarms) : renderNoAlarms()}
      </div>`;

    // Toggle details
    const toggle = el.querySelector(".phd-toggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const details = el.querySelector(".phd-details");
        const isHidden = details.classList.toggle("phd-details--hidden");
        toggle.innerHTML = isHidden ? "&#x25BC;" : "&#x25B2;";
      });
    }

    // Trust sender
    const trustEl = el.querySelector(".phd-trust");
    if (trustEl) {
      trustEl.addEventListener("click", async () => {
        await addTrustedSender(currentSender);
        // Update cached result and re-render immediately
        const emailId = getEmailIdFromHash();
        if (emailId && cache[emailId]) {
          cache[emailId].risk_level = "trusted";
          cache[emailId].risk_level_label = t("risk_trusted", "Trusted sender");
          currentEmailId = null; // allow re-render
          renderBanner(cache[emailId]);
        }
      });
    }

    el.querySelector(".phd-close").addEventListener("click", removeBanner);
    injectBanner(el);
  }

  function renderMeta(result) {
    const meta = result.metadata || {};
    const time = meta.analysis_time_ms;
    const analyzers = meta.analyzers_run;
    const parts = [];
    if (analyzers) parts.push(`${analyzers.length} analyzers`);
    if (time != null) parts.push(`${time}ms`);
    if (parts.length === 0) return "";
    return `<div class="phd-meta">${escapeHtml(parts.join(" · "))}</div>`;
  }

  function renderAlarms(alarms) {
    const cards = alarms.map((a) => {
      const sev = a.severity || "info";
      const sevLabel = t(`severity_${sev}`, sev);
      return `
        <div class="phd-alarm phd-alarm--${sev}">
          <span class="phd-alarm__severity phd-alarm__severity--${sev}">${escapeHtml(sevLabel)}</span>
          <div class="phd-alarm__title">${escapeHtml(a.title || a.alarm_type)}</div>
          <div class="phd-alarm__desc">${escapeHtml(a.description || "")}</div>
        </div>`;
    }).join("");
    return `<div class="phd-alarms">${cards}</div>`;
  }

  function renderNoAlarms() {
    return `<div class="phd-no-alarms">${t("no_alarms", "No phishing indicators detected.")}</div>`;
  }

  function escapeHtml(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  // ── Trusted senders ───────────────────────────────────

  function loadTrustedSenders() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ trustedSenders: [], trustedDomains: [] }, (items) => {
        trustedSenders = items.trustedSenders;
        trustedDomains = items.trustedDomains;
        resolve();
      });
    });
  }

  function isTrustedSender(sender) {
    if (!sender) return false;
    const s = sender.toLowerCase();
    // Check exact email match
    if (trustedSenders.some((ts) => ts.toLowerCase() === s)) return true;
    // Check domain match
    const domainMatch = s.match(/@([\w.-]+)$/);
    if (domainMatch) {
      const senderDomain = domainMatch[1];
      return trustedDomains.some((td) => td.toLowerCase() === senderDomain);
    }
    return false;
  }

  function addTrustedSender(sender) {
    if (!sender || isTrustedSender(sender)) return Promise.resolve();
    trustedSenders.push(sender.toLowerCase());
    return new Promise((resolve) => {
      chrome.storage.sync.set({ trustedSenders }, resolve);
    });
  }

  // ── Analysis orchestration ──────────────────────────────

  async function analyzeEmail() {
    const emailId = getEmailIdFromHash();
    if (!emailId) return;

    // Check cache
    if (cache[emailId]) {
      renderBanner(cache[emailId]);
      return;
    }

    // Check if user is logged in
    try {
      const user = await PhishingAPI.getUser();
      if (!user.loggedIn) {
        renderErrorBanner("Please log in to PhishBuster to analyze emails.", () => analyzeEmail());
        return;
      }
    } catch {
      renderErrorBanner("Please log in to PhishBuster to analyze emails.", () => analyzeEmail());
      return;
    }

    renderLoadingBanner();

    try {
      const bodyEl = await waitForEmailBody();
      const sender = extractSender();
      currentSender = sender;
      const subject = extractSubject();

      const text = composeAnalysisText(sender, subject, bodyEl);

      const result = await PhishingAPI.analyzeText(text, currentLang);

      // Trusted sender: keep alarms visible but override risk to "trusted"
      if (isTrustedSender(sender)) {
        result.risk_level = "trusted";
        result.risk_level_label = t("risk_trusted", "Trusted sender");
      }

      cache[emailId] = result;
      renderBanner(result);

    } catch (err) {
      console.error("[PHD] Analysis failed:", err);
      let errorMsg;
      if (err.message.includes("DAILY_LIMIT_REACHED")) {
        errorMsg = t("daily_limit", "Daily analysis limit reached. Open PhishBuster to get more analyses.");
      } else if (err.message.includes("timed out") || err.message.includes("Failed to fetch")) {
        errorMsg = t("backend_unreachable", "Backend unreachable — is the server running?");
      } else if (err.message.includes("Session expired") || err.message.includes("Not logged in")) {
        errorMsg = t("auth_required", "Please log in to PhishBuster to analyze emails.");
      } else {
        errorMsg = err.message || t("error_generic", "An error occurred during analysis.");
      }
      renderErrorBanner(errorMsg, () => analyzeEmail());
    }
  }

  // ── Navigation handling ─────────────────────────────────

  function handleNavigation() {
    const emailId = getEmailIdFromHash();
    if (!emailId) {
      currentEmailId = null;
      removeBanner();
      return;
    }

    // Same email and banner already visible — nothing to do
    if (emailId === currentEmailId && document.getElementById(BANNER_ID)) {
      return;
    }

    currentEmailId = emailId;

    // Check cache first for instant display
    if (cache[emailId]) {
      renderBanner(cache[emailId]);
      return;
    }

    analyzeEmail();
  }

  function debouncedNavigation() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(handleNavigation, DEBOUNCE_MS);
  }

  // ── Settings & translations ─────────────────────────────

  async function loadSettings() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ language: "en", trustedSenders: [], trustedDomains: [] }, (items) => {
        currentLang = items.language;
        trustedSenders = items.trustedSenders;
        trustedDomains = items.trustedDomains;
        resolve();
      });
    });
  }

  async function loadTranslations() {
    try {
      translations = await PhishingAPI.getTranslations(currentLang);
    } catch (err) {
      console.warn("[PHD] Could not load translations:", err.message);
      translations = {};
    }
  }

  // ── Initialization ─────────────────────────────────────

  async function init() {
    await loadSettings();
    await loadTranslations();

    // Listen for URL hash changes (email navigation)
    window.addEventListener("hashchange", debouncedNavigation);

    // MutationObserver for Gmail's SPA transitions
    // Ignore mutations inside our own banner to prevent toggle/close
    // from triggering a re-render loop.
    observer = new MutationObserver((mutations) => {
      const banner = document.getElementById(BANNER_ID);
      if (banner) {
        const allInsideBanner = mutations.every((m) => banner.contains(m.target));
        if (allInsideBanner) return;
      }
      debouncedNavigation();
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    // Listen for settings changes from popup
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.action === "settingsUpdated") {
        currentLang = msg.language || currentLang;
        loadTranslations().then(() => {
          const emailId = getEmailIdFromHash();
          if (emailId && cache[emailId]) {
            renderBanner(cache[emailId]);
          }
        });
      }
      if (msg.action === "trustedSendersUpdated") {
        trustedSenders = msg.trustedSenders ?? trustedSenders;
        trustedDomains = msg.trustedDomains ?? trustedDomains;
        const emailId = getEmailIdFromHash();
        if (emailId) {
          delete cache[emailId];
          currentEmailId = null;
          handleNavigation();
        }
      }
    });

    // Initial check (in case user opened Gmail directly to an email)
    handleNavigation();
  }

  // Wait for Gmail to be ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
