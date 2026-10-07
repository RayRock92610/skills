import unittest
import json
from validate_report import validate_report

class TestValidateReport(unittest.TestCase):
    def test_valid_report(self):
        report = json.dumps([
            {"id": "test_id", "confidence": 1, "deepLink": "https://github.com/owner/repo"}
        ])
        self.assertTrue(validate_report(report))

    def test_invalid_scheme(self):
        report = json.dumps([
            {"id": "test_id", "confidence": 1, "deepLink": "http://github.com/owner/repo"}
        ])
        self.assertFalse(validate_report(report))

    def test_invalid_hostname(self):
        report = json.dumps([
            {"id": "test_id", "confidence": 1, "deepLink": "https://evil.com/owner/repo"}
        ])
        self.assertFalse(validate_report(report))

    def test_credentials_in_url(self):
        report = json.dumps([
            {"id": "test_id", "confidence": 1, "deepLink": "https://user:pass@github.com/owner/repo"}
        ])
        self.assertFalse(validate_report(report))

    def test_invalid_path(self):
        report = json.dumps([
            {"id": "test_id", "confidence": 1, "deepLink": "https://github.com/owner"}
        ])
        self.assertFalse(validate_report(report))

    def test_xss_in_path(self):
        report = json.dumps([
            {"id": "test_id", "confidence": 1, "deepLink": "https://github.com/owner/<script>"}
        ])
        self.assertFalse(validate_report(report))

if __name__ == "__main__":
    unittest.main()
