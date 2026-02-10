from urllib.parse import urlparse
from app.analyzers.base import BaseAnalyzer
from app.models.analysis_result import Alarm, Severity
from app.utils.url_utils import is_ip_url, is_shortened_url, check_typosquatting

ALARM_TEXTS = {
    "url_ip": {
        "en": ("IP address in URL", "The URL uses an IP address instead of a domain name, which is common in phishing."),
        "es": ("IP en URL", "La URL usa una dirección IP en vez de un dominio, algo común en phishing."),
        "ca": ("IP a la URL", "La URL utilitza una adreça IP en lloc d'un domini, cosa habitual en phishing."),
    },
    "url_shortener": {
        "en": ("URL shortener detected", "The link uses a URL shortening service, which can hide the real destination."),
        "es": ("URL acortada detectada", "El enlace usa un servicio de acortamiento que puede ocultar el destino real."),
        "ca": ("URL escurçada detectada", "L'enllaç usa un servei d'escurçament que pot amagar la destinació real."),
    },
    "url_mismatch": {
        "en": ("Link text/URL mismatch", "The visible text shows a different URL than where the link actually goes."),
        "es": ("Texto/URL no coinciden", "El texto visible muestra una URL diferente a donde realmente lleva el enlace."),
        "ca": ("Text/URL no coincideixen", "El text visible mostra una URL diferent d'on realment porta l'enllaç."),
    },
    "typosquatting": {
        "en": ("Typosquatting domain detected", "The domain closely resembles a known brand but is misspelled — a common phishing tactic."),
        "es": ("Dominio typosquatting detectado", "El dominio se parece mucho a una marca conocida pero está mal escrito — táctica común de phishing."),
        "ca": ("Domini typosquatting detectat", "El domini s'assembla molt a una marca coneguda però està mal escrit — tàctica comuna de phishing."),
    },
}


def _t(alarm_type: str, lang: str) -> tuple[str, str]:
    return ALARM_TEXTS.get(alarm_type, {}).get(lang, ALARM_TEXTS[alarm_type]["en"])


class URLAnalyzer(BaseAnalyzer):
    name = "url_analyzer"

    def analyze(self, parsed_data: dict, language: str = "en") -> list[Alarm]:
        alarms: list[Alarm] = []
        urls = parsed_data.get("urls", [])

        for url in urls:
            if is_ip_url(url):
                title, desc = _t("url_ip", language)
                alarms.append(Alarm(
                    analyzer=self.name,
                    alarm_type="url_ip_detected",
                    severity=Severity.HIGH,
                    title=title,
                    description=desc,
                    details={"url": url},
                ))

            if is_shortened_url(url):
                title, desc = _t("url_shortener", language)
                alarms.append(Alarm(
                    analyzer=self.name,
                    alarm_type="url_shortener_detected",
                    severity=Severity.MEDIUM,
                    title=title,
                    description=desc,
                    details={"url": url},
                ))

            brand_match = check_typosquatting(url)
            if brand_match:
                title, desc = _t("typosquatting", language)
                alarms.append(Alarm(
                    analyzer=self.name,
                    alarm_type="typosquatting_detected",
                    severity=Severity.HIGH,
                    title=title,
                    description=desc,
                    details={"url": url, "similar_to": brand_match},
                ))

        for mismatch in parsed_data.get("link_mismatches", []):
            title, desc = _t("url_mismatch", language)
            alarms.append(Alarm(
                analyzer=self.name,
                alarm_type="url_text_mismatch",
                severity=Severity.HIGH,
                title=title,
                description=desc,
                details={
                    "visible_text": mismatch["visible_text"],
                    "actual_href": mismatch["href"],
                },
            ))

        return alarms
