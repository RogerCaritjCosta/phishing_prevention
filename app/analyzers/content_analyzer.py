import re
from urllib.parse import urlparse
from app.analyzers.base import BaseAnalyzer
from app.models.analysis_result import Alarm, Severity
from app.utils.url_utils import extract_urls

# Urgency keywords per language
URGENCY_KEYWORDS = {
    "en": [
        "urgent", "immediately", "account suspended", "account will be closed",
        "verify your account", "confirm your identity", "unauthorized access",
        "suspicious activity", "limited time", "act now", "expire",
        "within 24 hours", "within 48 hours", "your account has been",
    ],
    "es": [
        "urgente", "inmediatamente", "cuenta suspendida", "cuenta será cerrada",
        "verifica tu cuenta", "confirma tu identidad", "acceso no autorizado",
        "actividad sospechosa", "tiempo limitado", "actúa ahora", "expirar",
        "en 24 horas", "en 48 horas", "tu cuenta ha sido",
    ],
    "ca": [
        "urgent", "immediatament", "compte suspès", "compte serà tancat",
        "verifica el teu compte", "confirma la teva identitat", "accés no autoritzat",
        "activitat sospitosa", "temps limitat", "actua ara", "expirar",
        "en 24 hores", "en 48 hores", "el teu compte ha estat",
    ],
}

CREDENTIAL_KEYWORDS = {
    "en": [
        "contraseña", "pin code", "credit card", "card number",
        "social security", "ssn", "bank account", "cvv", "cvc",
        "login credentials", "enter your password", "confirm password",
        "update your payment", "billing information",
    ],
    "es": [
        "contraseña", "clave", "código pin", "tarjeta de crédito", "número de tarjeta",
        "seguro social", "cuenta bancaria", "cvv", "cvc",
        "credenciales", "introduce tu contraseña", "confirma tu contraseña",
        "actualiza tu pago", "información de facturación",
    ],
    "ca": [
        "contrasenya", "clau", "codi pin", "targeta de crèdit", "número de targeta",
        "seguretat social", "compte bancari", "cvv", "cvc",
        "credencials", "introdueix la teva contrasenya", "confirma la contrasenya",
        "actualitza el teu pagament", "informació de facturació",
    ],
}

PRIZE_BAIT_PATTERNS = {
    "en": [
        r"you have (been selected|won|been chosen)",
        r"you'?ve (been selected|won|been chosen)",
        r"congratulations.{0,20}(winner|won|selected|chosen|prize|reward)",
        r"(claim|collect) your (prize|reward|gift|winnings)",
        r"you are (the|a) (lucky )?(winner|selected|chosen)",
        r"(exclusive|special) (offer|reward|prize) for you",
        r"(lottery|raffle|sweepstake|giveaway).{0,30}(winner|won|selected)",
        r"(gift card|voucher|coupon).{0,20}(reserved|waiting|selected)",
        r"free (iphone|ipad|macbook|samsung|laptop|tv|gift)",
        r"(selected|chosen) (to receive|for a|as a winner)",
    ],
    "es": [
        r"has (sido seleccionado|ganado|sido elegido)",
        r"(felicidades|enhorabuena).{0,20}(ganador|ganado|seleccionado|premio|recompensa)",
        r"(reclama|recoge) tu (premio|recompensa|regalo)",
        r"eres (el|un) (afortunado )?(ganador|seleccionado|elegido)",
        r"(oferta|recompensa|premio) (exclusiv[oa]|especial) para ti",
        r"(lotería|sorteo|rifa).{0,30}(ganador|ganado|seleccionado)",
        r"(tarjeta regalo|vale|cupón).{0,20}(reservad[oa]|esperando|seleccionado)",
        r"(iphone|ipad|macbook|samsung|portátil|televisor|regalo) gratis",
        r"(seleccionado|elegido) (para recibir|como ganador)",
        r"has sido el ganador",
    ],
    "ca": [
        r"has (estat seleccionat|guanyat|estat escollit)",
        r"(felicitats|enhorabona).{0,20}(guanyador|guanyat|seleccionat|premi|recompensa)",
        r"(reclama|recull) el teu (premi|recompensa|regal)",
        r"ets (el|un) (afortunat )?(guanyador|seleccionat|escollit)",
        r"(oferta|recompensa|premi) (exclusiu|exclusiva|especial) per a tu",
        r"(loteria|sorteig|rifa).{0,30}(guanyador|guanyat|seleccionat)",
        r"(targeta regal|val|cupó).{0,20}(reservat|esperant|seleccionat)",
        r"(iphone|ipad|macbook|samsung|portàtil|televisor|regal) gratis",
        r"(seleccionat|escollit) (per rebre|com a guanyador)",
        r"has estat el guanyador",
    ],
}

THREAT_PATTERNS = {
    "en": [
        r"in \d+ hours?", r"within \d+ days?", r"will be (closed|suspended|terminated|locked)",
        r"failure to (respond|verify|confirm|act)", r"legal action",
    ],
    "es": [
        r"en \d+ horas?", r"en \d+ días?", r"será (cerrada|suspendida|bloqueada)",
        r"si no (respondes|verificas|confirmas|actúas)", r"acción legal",
    ],
    "ca": [
        r"en \d+ hores?", r"en \d+ dies?", r"serà (tancat|suspès|bloquejat)",
        r"si no (respons|verifiques|confirmes|actues)", r"acció legal",
    ],
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "zoho.com", "yandex.com", "gmx.com",
    "icloud.com", "live.com", "msn.com",
}

WELL_KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "bank", "wells fargo", "chase",
    "citibank", "hsbc", "santander", "bbva", "caixabank", "sabadell",
    "bankia", "ing", "openbank",
]

VOWELS = set("aeiou")


def _is_gibberish(word: str) -> bool:
    """Heuristic: a word with 4+ chars and very low vowel ratio is likely gibberish."""
    if len(word) < 4:
        return False
    alpha = [c for c in word if c.isalpha()]
    if len(alpha) < 4:
        return False
    vowel_ratio = sum(1 for c in alpha if c in VOWELS) / len(alpha)
    return vowel_ratio < 0.15


ALARM_TEXTS = {
    "urgency": {
        "en": ("Urgency language detected", "The message uses urgency tactics to pressure you into acting quickly."),
        "es": ("Lenguaje de urgencia detectado", "El mensaje usa tácticas de urgencia para presionar a actuar rápido."),
        "ca": ("Llenguatge d'urgència detectat", "El missatge utilitza tàctiques d'urgència per pressionar a actuar ràpid."),
    },
    "credentials": {
        "en": ("Credential request detected", "The message asks for sensitive information. Keyword detected: \"{keyword}\"."),
        "es": ("Petición de credenciales detectada", "El mensaje solicita información sensible. Palabra detectada: \"{keyword}\"."),
        "ca": ("Petició de credencials detectada", "El missatge sol·licita informació sensible. Paraula detectada: \"{keyword}\"."),
    },
    "threat": {
        "en": ("Threat or deadline detected", "The message contains threats or artificial deadlines to force action."),
        "es": ("Amenaza o plazo detectado", "El mensaje contiene amenazas o plazos artificiales para forzar una acción."),
        "ca": ("Amenaça o termini detectat", "El missatge conté amenaces o terminis artificials per forçar una acció."),
    },
    "free_provider": {
        "en": ("Free email provider impersonation", "The sender uses a free email provider while impersonating a known brand."),
        "es": ("Suplantación con proveedor gratuito", "El remitente usa un proveedor de email gratuito haciéndose pasar por una marca conocida."),
        "ca": ("Suplantació amb proveïdor gratuït", "El remitent usa un proveïdor d'email gratuït fent-se passar per una marca coneguda."),
    },
    "prize_bait": {
        "en": ("Prize or reward bait", "The message claims you've won a prize or been selected for a reward. Did you actually sign up for this?"),
        "es": ("Cebo de premio o recompensa", "El mensaje afirma que has ganado un premio o has sido seleccionado para una recompensa. \u00bfRealmente te habías apuntado a algo así?"),
        "ca": ("Esquer de premi o recompensa", "El missatge afirma que has guanyat un premi o has estat seleccionat per a una recompensa. Realment t'havies apuntat a alguna cosa així?"),
    },
    "suspicious_sender": {
        "en": ("Suspicious sender address", "The sender address \"{sender}\" looks fake: {reasons}."),
        "es": ("Dirección de remitente sospechosa", "La dirección \"{sender}\" parece falsa: {reasons}."),
        "ca": ("Adreça de remitent sospitosa", "L'adreça \"{sender}\" sembla falsa: {reasons}."),
    },
}


def _t(key: str, lang: str) -> tuple[str, str]:
    return ALARM_TEXTS.get(key, {}).get(lang, ALARM_TEXTS[key]["en"])


class ContentAnalyzer(BaseAnalyzer):
    name = "content_analyzer"

    def analyze(self, parsed_data: dict, language: str = "en") -> list[Alarm]:
        alarms: list[Alarm] = []
        body = parsed_data.get("body", "").lower()

        # Check all languages — phishing can mix languages
        for lang in ("en", "es", "ca"):
            alarms.extend(self._check_urgency(body, lang, language))
            alarms.extend(self._check_credentials(body, lang, language))
            alarms.extend(self._check_threats(body, lang, language))
            alarms.extend(self._check_prize_bait(body, lang, language))

        # Deduplicate by alarm_type
        seen = set()
        unique = []
        for a in alarms:
            if a.alarm_type not in seen:
                seen.add(a.alarm_type)
                unique.append(a)
        alarms = unique

        alarms.extend(self._check_free_provider(parsed_data, body, language))
        alarms.extend(self._check_suspicious_sender(parsed_data, language))

        return alarms

    def _check_urgency(self, body: str, check_lang: str, ui_lang: str) -> list[Alarm]:
        found = [kw for kw in URGENCY_KEYWORDS.get(check_lang, []) if kw in body]
        if found:
            title, desc = _t("urgency", ui_lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="urgency_detected",
                severity=Severity.MEDIUM,
                title=title,
                description=desc,
                details={"keywords_found": found[:5]},
            )]
        return []

    def _check_credentials(self, body: str, check_lang: str, ui_lang: str) -> list[Alarm]:
        found = [kw for kw in CREDENTIAL_KEYWORDS.get(check_lang, [])
                 if re.search(r'(?<!\w)' + re.escape(kw) + r'(?!\w)', body)]
        if found:
            title, desc_tpl = _t("credentials", ui_lang)
            desc = desc_tpl.format(keyword=found[0])
            return [Alarm(
                analyzer=self.name,
                alarm_type="credential_request",
                severity=Severity.HIGH,
                title=title,
                description=desc,
                details={"keywords_found": found[:5]},
            )]
        return []

    def _check_threats(self, body: str, check_lang: str, ui_lang: str) -> list[Alarm]:
        found = []
        for pattern in THREAT_PATTERNS.get(check_lang, []):
            if re.search(pattern, body):
                found.append(pattern)
        if found:
            title, desc = _t("threat", ui_lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="threat_detected",
                severity=Severity.MEDIUM,
                title=title,
                description=desc,
                details={"patterns_matched": len(found)},
            )]
        return []

    def _check_prize_bait(self, body: str, check_lang: str, ui_lang: str) -> list[Alarm]:
        found = []
        for pattern in PRIZE_BAIT_PATTERNS.get(check_lang, []):
            m = re.search(pattern, body)
            if m:
                found.append(m.group(0))
        if found:
            title, desc = _t("prize_bait", ui_lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="prize_bait",
                severity=Severity.MEDIUM,
                title=title,
                description=desc,
                details={"matches": found[:5]},
            )]
        return []

    def _check_free_provider(self, parsed_data: dict, body: str, ui_lang: str) -> list[Alarm]:
        sender = parsed_data.get("sender", "")
        if not sender:
            from_header = parsed_data.get("headers", {}).get("from", "")
            sender = from_header

        if not sender:
            return []

        sender_lower = sender.lower()
        sender_domain = ""
        email_match = re.search(r'[\w.+-]+@([\w.-]+)', sender_lower)
        if email_match:
            sender_domain = email_match.group(1)

        if sender_domain not in FREE_EMAIL_PROVIDERS:
            return []

        # Check if the body or sender name mentions a known brand
        brand_mentioned = None
        for brand in WELL_KNOWN_BRANDS:
            if brand in body or brand in sender_lower:
                brand_mentioned = brand
                break

        if brand_mentioned:
            title, desc = _t("free_provider", ui_lang)
            return [Alarm(
                analyzer=self.name,
                alarm_type="free_provider_impersonation",
                severity=Severity.HIGH,
                title=title,
                description=desc,
                details={"sender_domain": sender_domain, "brand_mentioned": brand_mentioned},
            )]
        return []

    def _check_suspicious_sender(self, parsed_data: dict, ui_lang: str) -> list[Alarm]:
        sender = parsed_data.get("sender", "")
        if not sender:
            sender = parsed_data.get("headers", {}).get("from", "")
        if not sender:
            return []

        email_match = re.search(r'([\w.+-]+)@([\w.-]+)', sender)
        if not email_match:
            return []

        local_part = email_match.group(1)
        domain_full = email_match.group(2).lower()
        full_address = f"{local_part}@{domain_full}"

        reason_labels = {
            "en": {
                "numeric_local": "local part is purely numeric",
                "repeated_subdomains": "domain has repeated subdomains",
                "gibberish_domain": "domain name looks randomly generated",
                "mixed_alphanum_domain": "domain mixes digits and letters unnaturally",
                "random_case_local": "local part has random uppercase letters",
                "gibberish_local": "local part looks randomly generated",
            },
            "es": {
                "numeric_local": "la parte local es puramente numérica",
                "repeated_subdomains": "el dominio tiene subdominios repetidos",
                "gibberish_domain": "el nombre de dominio parece generado aleatoriamente",
                "mixed_alphanum_domain": "el dominio mezcla dígitos y letras de forma sospechosa",
                "random_case_local": "la parte local tiene mayúsculas aleatorias",
                "gibberish_local": "la parte local parece generada aleatoriamente",
            },
            "ca": {
                "numeric_local": "la part local és purament numèrica",
                "repeated_subdomains": "el domini té subdominis repetits",
                "gibberish_domain": "el nom de domini sembla generat aleatòriament",
                "mixed_alphanum_domain": "el domini barreja dígits i lletres de forma sospitosa",
                "random_case_local": "la part local té majúscules aleatòries",
                "gibberish_local": "la part local sembla generada aleatòriament",
            },
        }
        labels = reason_labels.get(ui_lang, reason_labels["en"])

        reasons = []

        # 1. Purely numeric local part (e.g. 4824135658@...)
        if re.fullmatch(r'\d+', local_part):
            reasons.append(labels["numeric_local"])

        # 2. Repeated subdomains (e.g. ggruzsu.ggruzsu.ggruzsu.fr)
        parts = domain_full.split(".")
        non_tld = parts[:-1]  # exclude TLD
        if len(non_tld) >= 2 and len(set(non_tld)) == 1:
            reasons.append(labels["repeated_subdomains"])

        # 3. Gibberish domain name (low vowel ratio)
        for part in non_tld:
            if _is_gibberish(part):
                reasons.append(labels["gibberish_domain"])
                break

        # 4. Domain part mixes digits and letters (e.g. 628iuqeu)
        for part in non_tld:
            has_digit = any(c.isdigit() for c in part)
            has_alpha = any(c.isalpha() for c in part)
            if has_digit and has_alpha and len(part) >= 4:
                reasons.append(labels["mixed_alphanum_domain"])
                break

        # 5. Random uppercase in local part (e.g. norespondarledlNwbb)
        #    Skip first char; count unexpected uppercase in the middle
        if len(local_part) > 3:
            mid = local_part[1:]
            upper_in_mid = sum(1 for c in mid if c.isupper())
            if upper_in_mid >= 1 and not re.fullmatch(r'[a-z]+[A-Z][a-z]+', local_part):
                reasons.append(labels["random_case_local"])

        # 6. Gibberish local part: 4+ consecutive consonants (e.g. rledlNwbb)
        local_lower = local_part.lower()
        if re.search(r'[^aeiou\d_.+-]{4,}', local_lower) and len(local_part) > 6:
            reasons.append(labels["gibberish_local"])

        if not reasons:
            return []

        title, desc_tpl = _t("suspicious_sender", ui_lang)
        desc = desc_tpl.format(sender=full_address, reasons="; ".join(reasons))
        return [Alarm(
            analyzer=self.name,
            alarm_type="suspicious_sender",
            severity=Severity.HIGH,
            title=title,
            description=desc,
            details={"sender": full_address, "reasons": reasons},
        )]
