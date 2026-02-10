import re
import dns.resolver


def check_spf(domain: str) -> dict:
    """Check SPF record for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                return {"exists": True, "record": txt}
        return {"exists": False, "record": None}
    except Exception:
        return {"exists": False, "record": None, "error": "DNS lookup failed"}


def check_dmarc(domain: str) -> dict:
    """Check DMARC record for a domain."""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                policy = "none"
                match = re.search(r'p=(\w+)', txt)
                if match:
                    policy = match.group(1)
                return {"exists": True, "record": txt, "policy": policy}
        return {"exists": False, "record": None}
    except Exception:
        return {"exists": False, "record": None, "error": "DNS lookup failed"}


def check_dkim_header(auth_results: str) -> dict:
    """Parse DKIM result from Authentication-Results header."""
    if not auth_results:
        return {"present": False}

    dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
    if dkim_match:
        result = dkim_match.group(1).lower()
        return {"present": True, "result": result, "pass": result == "pass"}
    return {"present": False}


def check_spf_header(received_spf: str | None, auth_results: str | None) -> dict:
    """Parse SPF result from Received-SPF or Authentication-Results header."""
    if received_spf:
        result_match = re.match(r'(\w+)', received_spf.strip())
        if result_match:
            result = result_match.group(1).lower()
            return {"present": True, "result": result, "pass": result == "pass"}

    if auth_results:
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            result = spf_match.group(1).lower()
            return {"present": True, "result": result, "pass": result == "pass"}

    return {"present": False}
