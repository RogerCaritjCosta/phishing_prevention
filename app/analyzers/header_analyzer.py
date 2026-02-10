import re
from app.analyzers.base import BaseAnalyzer
from app.models.analysis_result import Alarm, Severity
from app.utils.dns_utils import check_spf, check_dmarc, check_dkim_header, check_spf_header

ALARM_TEXTS = {
    "spf_fail": {
        "en": ("SPF check failed", "The sender's IP is not authorized by the domain's SPF record."),
        "es": ("Fallo de SPF", "La IP del remitente no está autorizada por el registro SPF del dominio."),
        "ca": ("Fallada de SPF", "La IP del remitent no està autoritzada pel registre SPF del domini."),
    },
    "spf_missing": {
        "en": ("No SPF record found", "The sender's domain has no SPF record, making it easy to spoof."),
        "es": ("Sin registro SPF", "El dominio del remitente no tiene registro SPF, facilitando la suplantación."),
        "ca": ("Sense registre SPF", "El domini del remitent no té registre SPF, facilitant la suplantació."),
    },
    "dkim_fail": {
        "en": ("DKIM signature failed", "The email's DKIM signature did not pass verification."),
        "es": ("Firma DKIM fallida", "La firma DKIM del email no pasó la verificación."),
        "ca": ("Signatura DKIM fallida", "La signatura DKIM del correu no ha passat la verificació."),
    },
    "dmarc_fail": {
        "en": ("DMARC policy not enforced", "The domain's DMARC policy is set to 'none', offering no protection."),
        "es": ("Política DMARC no aplicada", "La política DMARC del dominio está en 'none', sin protección."),
        "ca": ("Política DMARC no aplicada", "La política DMARC del domini està en 'none', sense protecció."),
    },
    "dmarc_missing": {
        "en": ("No DMARC record found", "The sender's domain has no DMARC record."),
        "es": ("Sin registro DMARC", "El dominio del remitente no tiene registro DMARC."),
        "ca": ("Sense registre DMARC", "El domini del remitent no té registre DMARC."),
    },
    "from_mismatch": {
        "en": ("From/Return-Path mismatch", "The From address differs from the Return-Path, which may indicate spoofing."),
        "es": ("From/Return-Path no coinciden", "La dirección From difiere del Return-Path, lo que puede indicar suplantación."),
        "ca": ("From/Return-Path no coincideixen", "L'adreça From difereix del Return-Path, cosa que pot indicar suplantació."),
    },
}


def _t(key: str, lang: str) -> tuple[str, str]:
    return ALARM_TEXTS.get(key, {}).get(lang, ALARM_TEXTS[key]["en"])


def _extract_domain(address: str) -> str | None:
    match = re.search(r'@([\w.-]+)', address)
    return match.group(1).lower() if match else None


class HeaderAnalyzer(BaseAnalyzer):
    name = "header_analyzer"

    def analyze(self, parsed_data: dict, language: str = "en") -> list[Alarm]:
        if parsed_data.get("source") != "eml":
            return []

        headers = parsed_data.get("headers", {})
        if not headers:
            return []

        alarms: list[Alarm] = []
        from_header = headers.get("from", "")
        domain = _extract_domain(from_header)

        if domain:
            alarms.extend(self._check_spf(headers, domain, language))
            alarms.extend(self._check_dkim(headers, language))
            alarms.extend(self._check_dmarc(domain, language))

        alarms.extend(self._check_from_return_path(headers, language))

        return alarms

    def _check_spf(self, headers: dict, domain: str, lang: str) -> list[Alarm]:
        received_spf = headers.get("received-spf")
        auth_results = headers.get("authentication-results")

        spf_result = check_spf_header(received_spf, auth_results)

        if spf_result["present"]:
            if not spf_result["pass"]:
                title, desc = _t("spf_fail", lang)
                return [Alarm(
                    analyzer=self.name,
                    alarm_type="spf_fail",
                    severity=Severity.HIGH,
                    title=title,
                    description=desc,
                    details={"result": spf_result["result"], "domain": domain},
                )]
            return []

        # No SPF header — check DNS
        dns_spf = check_spf(domain)
        if not dns_spf["exists"]:
            title, desc = _t("spf_missing", lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="spf_missing",
                severity=Severity.MEDIUM,
                title=title,
                description=desc,
                details={"domain": domain},
            )]
        return []

    def _check_dkim(self, headers: dict, lang: str) -> list[Alarm]:
        auth_results = headers.get("authentication-results", "")
        dkim = check_dkim_header(auth_results)

        if dkim["present"] and not dkim["pass"]:
            title, desc = _t("dkim_fail", lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="dkim_fail",
                severity=Severity.HIGH,
                title=title,
                description=desc,
                details={"result": dkim["result"]},
            )]
        return []

    def _check_dmarc(self, domain: str, lang: str) -> list[Alarm]:
        dmarc = check_dmarc(domain)
        if not dmarc["exists"]:
            title, desc = _t("dmarc_missing", lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="dmarc_missing",
                severity=Severity.LOW,
                title=title,
                description=desc,
                details={"domain": domain},
            )]
        if dmarc.get("policy") == "none":
            title, desc = _t("dmarc_fail", lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="dmarc_policy_none",
                severity=Severity.MEDIUM,
                title=title,
                description=desc,
                details={"domain": domain, "policy": "none"},
            )]
        return []

    def _check_from_return_path(self, headers: dict, lang: str) -> list[Alarm]:
        from_addr = headers.get("from", "")
        return_path = headers.get("return-path", "")

        if not from_addr or not return_path:
            return []

        from_domain = _extract_domain(from_addr)
        rp_domain = _extract_domain(return_path)

        if from_domain and rp_domain and from_domain != rp_domain:
            title, desc = _t("from_mismatch", lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="from_return_path_mismatch",
                severity=Severity.MEDIUM,
                title=title,
                description=desc,
                details={"from_domain": from_domain, "return_path_domain": rp_domain},
            )]
        return []
