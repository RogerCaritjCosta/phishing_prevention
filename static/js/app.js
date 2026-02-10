document.addEventListener("DOMContentLoaded", () => {
    // Tabs
    document.querySelectorAll(".tab").forEach(tab => {
        tab.addEventListener("click", () => {
            document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            tab.classList.add("active");
            document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
        });
    });

    // Language selector
    const langSelect = document.getElementById("lang-select");
    langSelect.addEventListener("change", () => I18n.load(langSelect.value));

    // Analyze text
    document.getElementById("analyze-text-btn").addEventListener("click", async () => {
        const text = document.getElementById("email-text").value.trim();
        if (!text) return;
        await runAnalysis(() => API.analyzeText(text, I18n.current));
    });

    // Drop zone
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("eml-file");
    const fileNameEl = document.getElementById("file-name");
    const emlBtn = document.getElementById("analyze-eml-btn");

    dropZone.addEventListener("click", () => fileInput.click());

    dropZone.addEventListener("dragover", e => {
        e.preventDefault();
        dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", () => {
        dropZone.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", e => {
        e.preventDefault();
        dropZone.classList.remove("dragover");
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            onFileSelected();
        }
    });

    fileInput.addEventListener("change", onFileSelected);

    function onFileSelected() {
        if (fileInput.files.length) {
            fileNameEl.textContent = fileInput.files[0].name;
            emlBtn.disabled = false;
        }
    }

    emlBtn.addEventListener("click", async () => {
        if (!fileInput.files.length) return;
        await runAnalysis(() => API.analyzeEml(fileInput.files[0], I18n.current));
    });

    // Analysis runner
    async function runAnalysis(apiFn) {
        const loading = document.getElementById("loading");
        const results = document.getElementById("results");
        const errorMsg = document.getElementById("error-msg");

        results.classList.add("hidden");
        errorMsg.classList.add("hidden");
        loading.classList.remove("hidden");

        try {
            const data = await apiFn();
            loading.classList.add("hidden");

            if (!data.success) {
                errorMsg.textContent = data.error || I18n.t("error_generic");
                errorMsg.classList.remove("hidden");
                return;
            }

            renderResults(data);
        } catch (err) {
            loading.classList.add("hidden");
            errorMsg.textContent = I18n.t("error_generic");
            errorMsg.classList.remove("hidden");
        }
    }

    function renderResults(data) {
        const results = document.getElementById("results");
        const badge = document.getElementById("risk-badge");
        const alarmsList = document.getElementById("alarms-list");

        badge.textContent = data.risk_level_label;
        badge.className = `risk-badge risk-${data.risk_level}`;

        alarmsList.innerHTML = "";
        if (data.alarms.length === 0) {
            alarmsList.innerHTML = `<p class="no-alarms">${I18n.t("no_alarms")}</p>`;
        } else {
            data.alarms.forEach(alarm => {
                const card = document.createElement("div");
                card.className = `alarm-card severity-${alarm.severity}`;

                let detailsHtml = "";
                if (alarm.details && Object.keys(alarm.details).length > 0) {
                    const entries = Object.entries(alarm.details)
                        .map(([k, v]) => `<strong>${k}:</strong> ${escapeHtml(String(v))}`)
                        .join("<br>");
                    detailsHtml = `<div class="alarm-details">${entries}</div>`;
                }

                card.innerHTML = `
                    <div class="alarm-header">
                        <span class="alarm-title">${escapeHtml(alarm.title)}</span>
                        <span class="alarm-severity severity-${alarm.severity}">
                            ${I18n.t("severity_" + alarm.severity)}
                        </span>
                    </div>
                    <div class="alarm-desc">${escapeHtml(alarm.description)}</div>
                    ${detailsHtml}
                `;
                alarmsList.appendChild(card);
            });
        }

        results.classList.remove("hidden");
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // Init i18n
    I18n.load("en");
});
