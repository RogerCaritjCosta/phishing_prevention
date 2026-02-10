from app.parsers.email_parser import EmailParser


def test_parse_plain_text_eml():
    eml = b"""From: sender@example.com
To: recipient@example.com
Subject: Test Email
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello, visit https://example.com for details.
"""
    result = EmailParser.parse(eml)
    assert result["source"] == "eml"
    assert result["sender"] == "sender@example.com"
    assert "https://example.com" in result["urls"]
    assert result["headers"]["subject"] == "Test Email"


def test_parse_html_eml():
    eml = b"""From: sender@example.com
To: recipient@example.com
Subject: HTML Test
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Click <a href="https://evil.com">https://safe.com</a></p>
</body></html>
"""
    result = EmailParser.parse(eml)
    assert len(result["link_mismatches"]) == 1
    assert "https://evil.com" in result["urls"]


def test_parse_headers():
    eml = b"""From: test@domain.com
To: user@example.com
Return-Path: <bounce@otherdomain.com>
Received-SPF: pass
Authentication-Results: dkim=pass; spf=pass
Subject: Header Test
Content-Type: text/plain

Body text
"""
    result = EmailParser.parse(eml)
    assert result["headers"]["from"] == "test@domain.com"
    assert result["headers"]["return-path"] == "<bounce@otherdomain.com>"
    assert "spf=pass" in result["headers"]["authentication-results"]
