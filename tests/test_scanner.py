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
- item: user@company.com
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

    def test_fnmatch_agent_artifacts_matching(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            claude_dir = os.path.join(tmpdir, ".claude")
            os.makedirs(claude_dir, exist_ok=True)
            claude_hist = os.path.join(claude_dir, "history.json")
            with open(claude_hist, "w", encoding="utf-8") as f:
                f.write('{"conversations": []}')

            findings = self.scanner.scan_file(claude_hist)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["type"], "protected_file")
            self.assertEqual(findings[0]["sample"], "history.json")

            cursor_dir = os.path.join(tmpdir, ".cursor")
            os.makedirs(cursor_dir, exist_ok=True)
            cursor_log = os.path.join(cursor_dir, "logs_test.txt")
            with open(cursor_log, "w", encoding="utf-8") as f:
                f.write("agent logs content")

            findings2 = self.scanner.scan_file(cursor_log)
            self.assertEqual(len(findings2), 1)
            self.assertEqual(findings2[0]["type"], "protected_file")
            self.assertEqual(findings2[0]["sample"], "logs_test.txt")

            safe_file = os.path.join(tmpdir, "safe_script.py")
            with open(safe_file, "w", encoding="utf-8") as f:
                f.write("print('hello world')\n")

            findings_safe = self.scanner.scan_file(safe_file)
            self.assertEqual(len(findings_safe), 0)

    def test_exempts_rfc2606_example_emails(self):
        for email in [
            "support@example.com",
            "info@example.org",
            "test@example.net",
            "user@test.com",
            "admin@localhost"
        ]:
            diff = f"+contact = '{email}'"
            findings = self.scanner.scan_text(diff)
            self.assertFalse(any(f["type"] == "email" for f in findings), f"Expected {email} to be exempt")

    def test_generic_secret_entropy_filtering(self):
        # Low entropy secrets (false positives) should be skipped
        low_entropy_diff = '+password = "test1234"\n+api_key: test1234\n+secret_key = "password"'
        findings_low = self.scanner.scan_text(low_entropy_diff)
        self.assertFalse(any(f["type"] == "generic_secret" for f in findings_low))

        # High entropy secret (quoted and unquoted) constructed programmatically
        rand_token = "".join(["k", "X", "9", "_", "m", "Z", "#", "7", "p", "Q", "!", "2", "L", "4"])
        high_entropy_diff = f"+password = '{rand_token}'\n+api_key = {rand_token}"
        findings_high = self.scanner.scan_text(high_entropy_diff)
        self.assertTrue(any(f["type"] == "generic_secret" for f in findings_high))

    def test_binary_file_skipped(self):
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"header\x00data\x01\x02password='secret'")
            temp_path = tf.name
        try:
            findings = self.scanner.scan_file(temp_path)
            self.assertEqual(findings, [])
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_oversized_file_reported(self):
        from unittest.mock import patch
        with patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=12 * 1024 * 1024):
            findings = self.scanner.scan_file("huge_data.csv")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["type"], "oversized_file")

    def test_config_discovery_repo_root(self):
        import tempfile
        import os
        from unittest.mock import patch
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp_root:
            sub_dir = os.path.join(tmp_root, "nested_folder")
            os.makedirs(sub_dir)
            cfg_file = os.path.join(tmp_root, "shield.config.json")
            with open(cfg_file, "w", encoding="utf-8") as f:
                f.write('{"test_key": "repo_root_val"}')
            os.chdir(sub_dir)
            try:
                with patch("subprocess.check_output", return_value=tmp_root):
                    scanner = ShieldScanner()
                    self.assertEqual(scanner.config.get("test_key"), "repo_root_val")
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()

