import hashlib
import base64
import requests
from flask import current_app
from app.analyzers.base import BaseAnalyzer
from app.models.analysis_result import Alarm, Severity
from app.utils.rate_limiter import RateLimiter

_vt_limiter = RateLimiter(max_requests=4, per_seconds=60)

ALARM_TEXTS = {
    "virustotal": {
        "en": ("VirusTotal: Malicious URL", "The URL was flagged as malicious by multiple security vendors."),
        "es": ("VirusTotal: URL maliciosa", "La URL fue marcada como maliciosa por múltiples proveedores de seguridad."),
        "ca": ("VirusTotal: URL maliciosa", "La URL ha estat marcada com a maliciosa per múltiples proveïdors de seguretat."),
    },
    "safebrowsing": {
        "en": ("Google Safe Browsing: Threat detected", "Google has identified this URL as a threat."),
        "es": ("Google Safe Browsing: Amenaza detectada", "Google ha identificado esta URL como una amenaza."),
        "ca": ("Google Safe Browsing: Amenaça detectada", "Google ha identificat aquesta URL com una amenaça."),
    },
    "phishtank": {
        "en": ("PhishTank: Known phishing URL", "This URL is listed in the PhishTank phishing database."),
        "es": ("PhishTank: URL de phishing conocida", "Esta URL está listada en la base de datos de phishing de PhishTank."),
        "ca": ("PhishTank: URL de phishing coneguda", "Aquesta URL està llistada a la base de dades de phishing de PhishTank."),
    },
}


def _t(key: str, lang: str) -> tuple[str, str]:
    return ALARM_TEXTS.get(key, {}).get(lang, ALARM_TEXTS[key]["en"])


class ExternalAPIAnalyzer(BaseAnalyzer):
    name = "external_api"

    def analyze(self, parsed_data: dict, language: str = "en") -> list[Alarm]:
        alarms: list[Alarm] = []
        urls = parsed_data.get("urls", [])
        if not urls:
            return alarms

        try:
            config = current_app.config
        except RuntimeError:
            return alarms

        vt_key = config.get("VIRUSTOTAL_API_KEY", "")
        gsb_key = config.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
        pt_key = config.get("PHISHTANK_API_KEY", "")

        for url in urls:
            if vt_key:
                alarm = self._check_virustotal(url, vt_key, language)
                if alarm:
                    alarms.append(alarm)

            if gsb_key:
                alarm = self._check_safebrowsing(url, gsb_key, language)
                if alarm:
                    alarms.append(alarm)

            if pt_key:
                alarm = self._check_phishtank(url, pt_key, language)
                if alarm:
                    alarms.append(alarm)

        return alarms

    def _check_virustotal(self, url: str, api_key: str, lang: str) -> Alarm | None:
        if not _vt_limiter.acquire():
            return None

        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious >= 3 or suspicious >= 5:
                title, desc = _t("virustotal", lang)
                severity = Severity.CRITICAL if malicious >= 5 else Severity.HIGH
                return Alarm(
                    analyzer=self.name,
                    alarm_type="virustotal_malicious",
                    severity=severity,
                    title=title,
                    description=desc,
                    details={
                        "url": url,
                        "malicious_detections": malicious,
                        "suspicious_detections": suspicious,
                    },
                )
        except Exception:
            pass
        return None

    def _check_safebrowsing(self, url: str, api_key: str, lang: str) -> Alarm | None:
        try:
            resp = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={
                    "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
                timeout=10,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            if data.get("matches"):
                title, desc = _t("safebrowsing", lang)
                threat_type = data["matches"][0].get("threatType", "UNKNOWN")
                return Alarm(
                    analyzer=self.name,
                    alarm_type="safebrowsing_threat",
                    severity=Severity.CRITICAL,
                    title=title,
                    description=desc,
                    details={"url": url, "threat_type": threat_type},
                )
        except Exception:
            pass
        return None

    def _check_phishtank(self, url: str, api_key: str, lang: str) -> Alarm | None:
        try:
            resp = requests.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={
                    "url": url,
                    "format": "json",
                    "app_key": api_key,
                },
                timeout=10,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            results = data.get("results", {})
            if results.get("in_database") and results.get("verified") and results.get("valid"):
                title, desc = _t("phishtank", lang)
                return Alarm(
                    analyzer=self.name,
                    alarm_type="phishtank_phishing",
                    severity=Severity.CRITICAL,
                    title=title,
                    description=desc,
                    details={"url": url, "phish_id": results.get("phish_id")},
                )
        except Exception:
            pass
        return None
