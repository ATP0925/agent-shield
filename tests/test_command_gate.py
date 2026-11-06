import unittest
from agentshield.command_interceptor import CommandInterceptor


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

    def test_allows_safe_commands(self):
        allowed, action, rule = self.interceptor.evaluate("git status")
        self.assertTrue(allowed)
        self.assertEqual(action, "ALLOW")

        allowed2, action2, _ = self.interceptor.evaluate("npm run build")
        self.assertTrue(allowed2)
        self.assertEqual(action2, "ALLOW")


if __name__ == "__main__":
    unittest.main()

