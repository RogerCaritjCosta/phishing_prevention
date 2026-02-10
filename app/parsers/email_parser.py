import email
import re
from email import policy
from email.message import EmailMessage
from bs4 import BeautifulSoup
from app.utils.url_utils import extract_urls


class EmailParser:
    @staticmethod
    def parse(raw_bytes: bytes) -> dict:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)

        headers = EmailParser._extract_headers(msg)
        body_text, body_html = EmailParser._extract_body(msg)

        # Prefer HTML for link analysis, plain text for content
        display_body = body_text or ""
        urls = extract_urls(body_text) if body_text else []
        link_mismatches = []

        if body_html:
            html_urls, html_mismatches = EmailParser._analyze_html(body_html)
            urls = list(set(urls + html_urls))
            link_mismatches = html_mismatches
            if not display_body:
                soup = BeautifulSoup(body_html, "html.parser")
                display_body = soup.get_text(separator="\n")

        return {
            "source": "eml",
            "raw_text": display_body,
            "body": display_body,
            "body_html": body_html,
            "urls": urls,
            "link_mismatches": link_mismatches,
            "headers": headers,
            "sender": headers.get("from", ""),
            "raw_eml": raw_bytes,
        }

    @staticmethod
    def _extract_headers(msg: EmailMessage) -> dict:
        header_keys = [
            "from", "to", "subject", "date", "reply-to", "return-path",
            "received", "received-spf", "authentication-results",
            "dkim-signature", "message-id",
        ]
        headers = {}
        for key in header_keys:
            value = msg.get(key)
            if value:
                headers[key] = str(value)
            # For "received" there can be multiple
            if key == "received":
                all_received = msg.get_all("received")
                if all_received:
                    headers["received_all"] = [str(v) for v in all_received]
        return headers

    @staticmethod
    def _extract_body(msg: EmailMessage) -> tuple[str | None, str | None]:
        text_body = None
        html_body = None

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" and text_body is None:
                    text_body = part.get_content()
                elif content_type == "text/html" and html_body is None:
                    html_body = part.get_content()
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                text_body = msg.get_content()
            elif content_type == "text/html":
                html_body = msg.get_content()

        return text_body, html_body

    @staticmethod
    def _analyze_html(html: str) -> tuple[list[str], list[dict]]:
        urls = []
        mismatches = []
        soup = BeautifulSoup(html, "html.parser")

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if href.startswith(("http://", "https://")):
                urls.append(href)

            visible = a_tag.get_text().strip()
            if re.match(r'https?://', visible) and visible != href:
                if not href.startswith("mailto:"):
                    mismatches.append({
                        "href": href,
                        "visible_text": visible,
                    })

        return urls, mismatches
