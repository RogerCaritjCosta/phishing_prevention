from app.parsers.text_parser import TextParser


def test_parse_extracts_urls():
    text = "Click here: https://example.com/page"
    result = TextParser.parse(text)
    assert "https://example.com/page" in result["urls"]
    assert result["source"] == "text"


def test_parse_detects_sender():
    text = "From: attacker@evil.com\nSubject: Test\n\nBody here"
    result = TextParser.parse(text)
    assert result["sender"] == "attacker@evil.com"


def test_parse_no_sender():
    text = "Just some text with no headers"
    result = TextParser.parse(text)
    assert result["sender"] is None


def test_parse_html_mismatch():
    text = '<a href="https://evil.com/steal">https://www.paypal.com/secure</a>'
    result = TextParser.parse(text)
    assert len(result["link_mismatches"]) == 1
    assert result["link_mismatches"][0]["href"] == "https://evil.com/steal"
    assert result["link_mismatches"][0]["visible_text"] == "https://www.paypal.com/secure"


def test_parse_html_no_mismatch():
    text = '<a href="https://example.com">Click here</a>'
    result = TextParser.parse(text)
    assert len(result["link_mismatches"]) == 0
