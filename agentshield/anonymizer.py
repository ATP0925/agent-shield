"""
Git Anonymizer & Author Identity Validator for AgentShield.
"""

import subprocess
import re
from typing import Dict, Any, Tuple


class GitAnonymizer:
    """Validates and enforces sanitized git author identity."""

    @staticmethod
    def get_git_author() -> Dict[str, str]:
        """Reads current global/local git user configuration."""
        name = ""
        email = ""
        try:
            name = subprocess.check_output(["git", "config", "user.name"], text=True).strip()
        except Exception:
            pass
        try:
            email = subprocess.check_output(["git", "config", "user.email"], text=True).strip()
        except Exception:
            pass
        return {"name": name, "email": email}

    @staticmethod
    def is_anonymized(email: str) -> bool:
        """Verifies if an email address uses GitHub noreply or sanitized domain."""
        if not email:
            return False
        return bool(re.search(r"@users\.noreply\.github\.com$", email, re.I))

    @staticmethod
    def enforce_noreply(username: str, user_id: str = "", scope: str = "local") -> Tuple[bool, str]:
        """Sets the git user.email to GitHub private noreply address."""
        if not username:
            return False, "Username required to configure noreply address."
        
        # Sanitize username to prevent injection
        safe_user = re.sub(r'[^a-zA-Z0-9_\-.]', '', username)
        safe_id = re.sub(r'[^0-9]', '', user_id) if user_id else ""
        
        if not safe_user:
            return False, "Invalid username after sanitization."
        
        prefix = f"{safe_id}+" if safe_id else ""
        noreply_email = f"{prefix}{safe_user}@users.noreply.github.com"
        
        git_scope = f"--{scope}" if scope in ("local", "global", "system") else "--local"
        try:
            subprocess.run(["git", "config", git_scope, "user.email", noreply_email], check=True)
            return True, f"Git email ({scope}) configured to: {noreply_email}"
        except Exception as e:
            return False, str(e)

