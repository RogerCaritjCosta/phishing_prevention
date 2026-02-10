from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.content_analyzer import ContentAnalyzer
from app.models.analysis_result import compute_risk_level, Alarm, Severity, RiskLevel


class TestURLAnalyzer:
    def setup_method(self):
        self.analyzer = URLAnalyzer()

    def test_ip_url(self):
        data = {"urls": ["http://192.168.1.1/login"], "link_mismatches": []}
        alarms = self.analyzer.analyze(data)
        assert len(alarms) == 1
        assert alarms[0].alarm_type == "url_ip_detected"
        assert alarms[0].severity == Severity.HIGH

    def test_shortener(self):
        data = {"urls": ["https://bit.ly/abc123"], "link_mismatches": []}
        alarms = self.analyzer.analyze(data)
        assert len(alarms) == 1
        assert alarms[0].alarm_type == "url_shortener_detected"

    def test_mismatch(self):
        data = {
            "urls": [],
            "link_mismatches": [{"href": "https://evil.com", "visible_text": "https://paypal.com"}],
        }
        alarms = self.analyzer.analyze(data)
        assert len(alarms) == 1
        assert alarms[0].alarm_type == "url_text_mismatch"

    def test_typosquatting(self):
        data = {"urls": ["https://paypa1.com/verify"], "link_mismatches": []}
        alarms = self.analyzer.analyze(data)
        types = [a.alarm_type for a in alarms]
        assert "typosquatting_detected" in types

    def test_clean_url(self):
        data = {"urls": ["https://google.com/search"], "link_mismatches": []}
        alarms = self.analyzer.analyze(data)
        assert len(alarms) == 0

    def test_localized_text(self):
        data = {"urls": ["http://192.168.1.1/login"], "link_mismatches": []}
        alarms = self.analyzer.analyze(data, language="es")
        assert "IP en URL" in alarms[0].title


class TestContentAnalyzer:
    def setup_method(self):
        self.analyzer = ContentAnalyzer()

    def test_urgency(self):
        data = {"body": "URGENT: Your account has been suspended immediately!", "headers": {}}
        alarms = self.analyzer.analyze(data)
        types = [a.alarm_type for a in alarms]
        assert "urgency_detected" in types

    def test_credentials(self):
        data = {"body": "Please enter your password and credit card number.", "headers": {}}
        alarms = self.analyzer.analyze(data)
        types = [a.alarm_type for a in alarms]
        assert "credential_request" in types

    def test_threats(self):
        data = {"body": "Your account will be closed in 24 hours.", "headers": {}}
        alarms = self.analyzer.analyze(data)
        types = [a.alarm_type for a in alarms]
        assert "threat_detected" in types

    def test_free_provider(self):
        data = {
            "body": "Dear PayPal customer, verify your account.",
            "sender": "security@gmail.com",
            "headers": {},
        }
        alarms = self.analyzer.analyze(data)
        types = [a.alarm_type for a in alarms]
        assert "free_provider_impersonation" in types

    def test_clean_text(self):
        data = {"body": "Hi, here is the meeting agenda for tomorrow.", "headers": {}}
        alarms = self.analyzer.analyze(data)
        assert len(alarms) == 0


class TestRiskScoring:
    def test_no_alarms(self):
        assert compute_risk_level([]) == RiskLevel.LOW

    def test_low_score(self):
        alarms = [Alarm("test", "test", Severity.INFO, "", "")]
        assert compute_risk_level(alarms) == RiskLevel.LOW

    def test_medium_score(self):
        alarms = [Alarm("test", "test", Severity.MEDIUM, "", "")]
        assert compute_risk_level(alarms) == RiskLevel.MEDIUM

    def test_high_from_severity(self):
        alarms = [Alarm("test", "test", Severity.HIGH, "", "")]
        assert compute_risk_level(alarms) == RiskLevel.HIGH

    def test_critical_from_score(self):
        alarms = [Alarm("test", "t", Severity.HIGH, "", "") for _ in range(3)]
        assert compute_risk_level(alarms) == RiskLevel.CRITICAL

    def test_critical_from_severity(self):
        alarms = [Alarm("test", "test", Severity.CRITICAL, "", "")]
        assert compute_risk_level(alarms) == RiskLevel.CRITICAL
