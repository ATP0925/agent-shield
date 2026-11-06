import unittest
from agentshield.anonymizer import GitAnonymizer


class TestGitAnonymizer(unittest.TestCase):

    def test_detects_anonymized_email(self):
        self.assertTrue(GitAnonymizer.is_anonymized("12345+user@users.noreply.github.com"))
        self.assertTrue(GitAnonymizer.is_anonymized("user@users.noreply.github.com"))
        self.assertFalse(GitAnonymizer.is_anonymized("user@gmail.com"))
        self.assertFalse(GitAnonymizer.is_anonymized("user@company.org"))

    def test_enforce_noreply_validation(self):
        # Empty username
        success, msg = GitAnonymizer.enforce_noreply("")
        self.assertFalse(success)
        self.assertIn("Username required", msg)

        # Invalid username (stripped of all invalid characters leaves empty)
        success, msg = GitAnonymizer.enforce_noreply("$$$%%%^^^")
        self.assertFalse(success)
        self.assertIn("Invalid username after sanitization", msg)


if __name__ == "__main__":
    unittest.main()

