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

    def test_detects_openai_and_stripe_keys(self):
        fake_openai = "sk-proj-" + "sampleSecretKeyForTestingPurposeOnly1234567890ABCDEF"
        fake_stripe = "sk_live_" + "testMockSecretForUnitTestValidation123"
        diff = f"+openai = '{fake_openai}'\n+stripe = '{fake_stripe}'"
        findings = self.scanner.scan_text(diff)
        self.assertTrue(any(f["type"] == "openai_api_key" for f in findings))
        self.assertTrue(any(f["type"] == "stripe_api_key" for f in findings))

    def test_normal_file_with_plus_and_minus_lines(self):
        normal_text = """# Math notes
+ 5 + 10 = 15
- item: user@example.com
+ api_key = 'AKIAIOSFODNN7EXAMPLE'
"""
        findings = self.scanner.scan_text(normal_text, source_name="notes.txt")
        # In a normal file, lines starting with + or - must still be scanned as full content
        self.assertTrue(any(f["type"] == "email" for f in findings))
        self.assertTrue(any(f["type"] == "aws_access_key" for f in findings))

    def test_diff_format_skips_removed_lines(self):
        diff_text = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
-removed_key = 'AKIAIOSFODNN7EXAMPLE'
+added_clean_code = True
"""
        findings = self.scanner.scan_text(diff_text, source_name="patch.diff")
        # For unified diffs, removed lines starting with '-' should not be flagged
        self.assertFalse(any(f["type"] == "aws_access_key" for f in findings))


if __name__ == "__main__":
    unittest.main()

