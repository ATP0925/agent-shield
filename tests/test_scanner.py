import unittest
from agentshield.scanner import ShieldScanner


class TestShieldScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = ShieldScanner()

    def test_detects_aws_key(self):
        diff = "+aws_key = 'AKIAIOSFODNN7EXAMPLE'"
        findings = self.scanner.scan_text(diff)
        self.assertTrue(any(f["type"] == "aws_access_key" for f in findings))

    def test_detects_github_pat(self):
        diff = "+token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'"
        findings = self.scanner.scan_text(diff)
        self.assertTrue(any(f["type"] == "github_pat" for f in findings))

    def test_exempts_github_noreply_email(self):
        diff = "+author = '224713409+ATP0925@users.noreply.github.com'"
        findings = self.scanner.scan_text(diff)
        # Should not flag noreply email
        self.assertFalse(any(f["type"] == "email" for f in findings))

    def test_flags_regular_email(self):
        diff = "+contact = 'personal_email@domain.com'"
        findings = self.scanner.scan_text(diff)
        self.assertTrue(any(f["type"] == "email" for f in findings))

    def test_detects_private_key(self):
        diff = "+-----BEGIN RSA PRIVATE KEY-----"
        findings = self.scanner.scan_text(diff)
        self.assertTrue(any(f["type"] == "private_key" for f in findings))


if __name__ == "__main__":
    unittest.main()
