import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentshield.gate import ConfirmationGate
from agentshield.anonymizer import GitAnonymizer


class TestGate(unittest.TestCase):
    def test_non_interactive_blocks_with_findings(self):
        gate = ConfirmationGate(steps=2, non_interactive=True)
        findings = [{"type": "test", "file": "x.py", "line": 1, "sample": "***"}]
        self.assertFalse(gate.verify_action("test", findings))

    def test_non_interactive_allows_no_findings(self):
        gate = ConfirmationGate(steps=2, non_interactive=True)
        self.assertTrue(gate.verify_action("test", []))
        self.assertTrue(gate.verify_action("test", None))

    def test_non_interactive_allows_empty_findings(self):
        gate = ConfirmationGate(steps=1, non_interactive=True)
        self.assertTrue(gate.verify_action("test", []))


class TestAnonymizer(unittest.TestCase):
    def test_is_anonymized_noreply(self):
        self.assertTrue(GitAnonymizer.is_anonymized("user@users.noreply.github.com"))
        self.assertTrue(GitAnonymizer.is_anonymized("123+user@users.noreply.github.com"))

    def test_is_not_anonymized(self):
        self.assertFalse(GitAnonymizer.is_anonymized("user@gmail.com"))
        self.assertFalse(GitAnonymizer.is_anonymized(""))

    def test_enforce_noreply_empty_username(self):
        ok, msg = GitAnonymizer.enforce_noreply("")
        self.assertFalse(ok)

    def test_enforce_noreply_scope_parameter(self):
        # Test that scope parameter is accepted (don't actually run git config)
        # Just verify the method signature works
        import inspect
        sig = inspect.signature(GitAnonymizer.enforce_noreply)
        self.assertIn("scope", sig.parameters)


class TestCliCommands(unittest.TestCase):
    def test_check_cmd_multi_word_block(self):
        import types
        from agentshield.cli import cmd_check_cmd
        args = types.SimpleNamespace(command=["rm", "-rf", "/"], non_interactive=True)
        with self.assertRaises(SystemExit) as ctx:
            cmd_check_cmd(args)
        self.assertEqual(ctx.exception.code, 1)

    def test_check_cmd_multi_word_allow(self):
        import types
        from agentshield.cli import cmd_check_cmd
        args = types.SimpleNamespace(command=["git", "status"], non_interactive=True)
        with self.assertRaises(SystemExit) as ctx:
            cmd_check_cmd(args)
        self.assertEqual(ctx.exception.code, 0)

    def test_main_subcommand_check_cmd_parsed(self):
        from unittest.mock import patch
        from agentshield.cli import main
        test_args = ["agentshield", "check-cmd", "echo", "hello", "--non-interactive"]
        with patch.object(sys, "argv", test_args):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)

    def test_scan_default_directory_runs(self):
        from unittest.mock import patch
        from agentshield.cli import main
        test_args = ["agentshield", "scan", "--path", "agentshield", "--non-interactive"]
        with patch.object(sys, "argv", test_args):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 0)

    def test_scan_non_existent_path_fails(self):
        from unittest.mock import patch
        from agentshield.cli import main
        test_args = ["agentshield", "scan", "--path", "definitely_non_existent_file_xyz.py", "--non-interactive"]
        with patch.object(sys, "argv", test_args):
            with self.assertRaises(SystemExit) as ctx:
                main()
            self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
