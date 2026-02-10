from app.utils.url_utils import extract_urls, is_ip_url, is_shortened_url, check_typosquatting


def test_extract_urls():
    text = "Visit https://example.com and http://test.org/path?q=1 for more info"
    urls = extract_urls(text)
    assert "https://example.com" in urls
    assert "http://test.org/path?q=1" in urls


def test_extract_urls_no_urls():
    assert extract_urls("No URLs here") == []


def test_is_ip_url():
    assert is_ip_url("http://192.168.1.1/login") is True
    assert is_ip_url("http://10.0.0.1:8080/page") is True
    assert is_ip_url("https://example.com/page") is False


def test_is_shortened_url():
    assert is_shortened_url("https://bit.ly/abc123") is True
    assert is_shortened_url("https://t.co/xyz") is True
    assert is_shortened_url("https://tinyurl.com/short") is True
    assert is_shortened_url("https://example.com/page") is False


def test_typosquatting_detected():
    result = check_typosquatting("https://paypa1.com/login")
    assert result == "paypal.com"


def test_typosquatting_legitimate():
    result = check_typosquatting("https://google.com/search")
    assert result is None


def test_typosquatting_unrelated():
    result = check_typosquatting("https://randomsite.com/page")
    assert result is None
