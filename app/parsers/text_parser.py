import re
from bs4 import BeautifulSoup
from app.utils.url_utils import extract_urls


class TextParser:
    @staticmethod
    def parse(text: str) -> dict:
        urls = extract_urls(text)
        link_mismatches = TextParser._find_html_link_mismatches(text)
        sender = TextParser._detect_sender(text)

        return {
            "source": "text",
            "raw_text": text,
            "body": text,
            "urls": urls,
            "link_mismatches": link_mismatches,
            "headers": {},
            "sender": sender,
        }

    @staticmethod
    def _find_html_link_mismatches(text: str) -> list[dict]:
        """Detect <a href="X">Y</a> where Y looks like a URL different from X."""
        mismatches = []
        if "<a " not in text.lower():
            return mismatches

        soup = BeautifulSoup(text, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            visible = a_tag.get_text().strip()
            if re.match(r'https?://', visible) and visible != href:
                if not href.startswith("mailto:"):
                    mismatches.append({
                        "href": href,
                        "visible_text": visible,
                    })
        return mismatches

    @staticmethod
    def _detect_sender(text: str) -> str | None:
        """Try to extract From: header from pasted text."""
        match = re.search(r'^From:\s*(.+)$', text, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
