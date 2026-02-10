const PhishingAPI = {
  _send(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response || !response.success) {
          reject(new Error(response?.error || "Unknown error"));
          return;
        }
        resolve(response.data);
      });
    });
  },

  analyzeText(text, language) {
    return this._send({ action: "analyzeText", text, language });
  },

  getTranslations(language) {
    return this._send({ action: "getTranslations", language });
  },

  healthCheck() {
    return this._send({ action: "healthCheck" });
  },

  getUser() {
    return this._send({ action: "getUser" });
  },

  getDailyUsage() {
    return this._send({ action: "getDailyUsage" });
  },

  addMoreAnalyses() {
    return this._send({ action: "addMoreAnalyses" });
  },
};
