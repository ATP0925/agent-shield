import unittest
from agentshield.command_interceptor import CommandInterceptor
from agentshield.gate import ConfirmationGate


class TestCommandInterceptor(unittest.TestCase):

    def setUp(self):
        self.interceptor = CommandInterceptor()

    def test_blocks_root_deletion(self):
        allowed, action, rule = self.interceptor.evaluate("rm -rf /")
        self.assertFalse(allowed)
        self.assertEqual(action, "BLOCK")

        # Windows PowerShell recursive deletion test
        allowed_win, action_win, _ = self.interceptor.evaluate("Remove-Item -Recurse -Force C:\\")
        self.assertFalse(allowed_win)
        self.assertEqual(action_win, "BLOCK")

        # Disk formatting test
        allowed_fmt, action_fmt, _ = self.interceptor.evaluate("format C:")
        self.assertFalse(allowed_fmt)
        self.assertEqual(action_fmt, "BLOCK")

    def test_flags_git_force_push(self):
        allowed, action, rule = self.interceptor.evaluate("git push origin main --force")
        self.assertTrue(allowed)
        self.assertEqual(action, "REQUIRE_CONFIRMATION")

    def test_flags_git_hard_reset(self):
        allowed, action, rule = self.interceptor.evaluate("git reset --hard HEAD~1")
        self.assertTrue(allowed)
        self.assertEqual(action, "REQUIRE_CONFIRMATION")

    def test_flags_blanket_staging(self):
        for cmd in ["git add .", "git add -A", "git add -a", "git add .  "]:
            allowed, action, rule = self.interceptor.evaluate(cmd)
            self.assertTrue(allowed)
            self.assertEqual(action, "REQUIRE_CONFIRMATION")
            self.assertEqual(rule.get("name"), "staging_all_files")

    def test_blocks_sensitive_env_staging(self):
        for cmd in ["git add .env", "git add .env.production", "git add -f .env"]:
            allowed, action, rule = self.interceptor.evaluate(cmd)
            self.assertFalse(allowed)
            self.assertEqual(action, "BLOCK")
            self.assertEqual(rule.get("name"), "staging_sensitive_environment")

    def test_allows_safe_commands(self):
        allowed, action, rule = self.interceptor.evaluate("git status")
        self.assertTrue(allowed)
        self.assertEqual(action, "ALLOW")

        allowed2, action2, _ = self.interceptor.evaluate("npm run build")
        self.assertTrue(allowed2)
        self.assertEqual(action2, "ALLOW")


class TestConfirmationGate(unittest.TestCase):

    def test_non_interactive_blocks_with_findings(self):
        gate = ConfirmationGate(non_interactive=True)
        findings = [{"type": "aws_access_key", "file": "test.py", "line": 1, "sample": "AKI***"}]
        self.assertFalse(gate.verify_action("git commit", findings))

    def test_non_interactive_allows_empty_findings(self):
        gate = ConfirmationGate(non_interactive=True)
        self.assertTrue(gate.verify_action("git commit", []))
        self.assertTrue(gate.verify_action("git commit", None))


if __name__ == "__main__":
    unittest.main()

