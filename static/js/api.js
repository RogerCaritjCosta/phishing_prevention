const API = {
    base: "/api/v1",

    async analyzeText(text, language) {
        const res = await fetch(`${this.base}/analyze/text`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text, language }),
        });
        return res.json();
    },

    async analyzeEml(file, language) {
        const form = new FormData();
        form.append("file", file);
        form.append("language", language);
        const res = await fetch(`${this.base}/analyze/eml`, {
            method: "POST",
            body: form,
        });
        return res.json();
    },

    async getTranslations(lang) {
        const res = await fetch(`${this.base}/translations/${lang}`);
        if (!res.ok) return null;
        return res.json();
    },

    async health() {
        const res = await fetch(`${this.base}/health`);
        return res.json();
    }
};
