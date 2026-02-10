const I18n = {
    current: "en",
    translations: {},

    async load(lang) {
        if (this.translations[lang]) {
            this.current = lang;
            this.apply();
            return;
        }
        const data = await API.getTranslations(lang);
        if (data) {
            this.translations[lang] = data;
            this.current = lang;
            this.apply();
        }
    },

    t(key) {
        return (this.translations[this.current] || {})[key] || key;
    },

    apply() {
        document.querySelectorAll("[data-i18n]").forEach(el => {
            el.textContent = this.t(el.dataset.i18n);
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
            el.placeholder = this.t(el.dataset.i18nPlaceholder);
        });
        document.title = this.t("app_title");
    }
};
