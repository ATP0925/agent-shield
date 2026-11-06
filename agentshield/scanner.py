"""
Scanner Engine for AgentShield: Detects secrets, credentials, PII, and agent logs.
"""

import os
import re
import json
import math
from typing import List, Dict, Any, Tuple


DEFAULT_PATTERNS = {
    "private_key": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)?\s*PRIVATE KEY-----",
    "aws_access_key": r"\b(AKIA[0-9A-Z]{16})\b",
    "github_pat": r"\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[0-9a-zA-Z_]{82})\b",
    "google_api_key": r"\b(AIza[0-9A-Za-z\-_]{35})\b",
    "slack_token": r"\b(xox[baprs]-[0-9A-Za-z]{10,48})\b",
    "openai_api_key": r"\b(sk-[a-zA-Z0-9]{48}|sk-proj-[a-zA-Z0-9_\-]{50,})\b",
    "anthropic_api_key": r"\b(sk-ant-[a-zA-Z0-9_\-]{32,})\b",
    "stripe_api_key": r"\b(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b",
    "huggingface_token": r"\b(hf_[a-zA-Z0-9]{34,})\b",
    "jwt_token": r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
    "generic_secret": r"""(?i)\b(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"][A-Za-z0-9_\-!@#$%^&*]{8,128}['\"]""",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone": r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


class ShieldScanner:
    """Core scanner for code diffs, staged git files, and directory paths."""

    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.patterns = dict(DEFAULT_PATTERNS)
        
        # Load user custom PII patterns
        custom_pii = self.config.get("custom_pii_patterns", [])
        for i, pat in enumerate(custom_pii):
            self.patterns[f"custom_pii_{i}"] = pat

    def _load_config(self, path: str = None) -> Dict[str, Any]:
        candidates = [
            path,
            os.path.join(os.getcwd(), "shield.config.json"),
            os.path.expanduser("~/.config/agentshield/shield.config.json"),
            os.path.expanduser("~/.agentshield.json")
        ]
        for c in candidates:
            if c and os.path.exists(c):
                try:
                    with open(c, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
        return {}

    def is_exempt_email(self, email: str) -> bool:
        """Checks if email is a safe GitHub noreply address."""
        if not self.config.get("security", {}).get("exempt_noreply_emails", True):
            return False
        return bool(re.search(r"users\.noreply\.github\.com$", email, re.I))

    def scan_text(self, text: str, source_name: str = "text") -> List[Dict[str, Any]]:
        """Scans arbitrary text (or git diff) for secrets and PII."""
        findings = []
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # For diffs, only check added lines (+)
            if text.startswith("diff ") or line.startswith("+") or line.startswith("-"):
                if not line.startswith("+") or line.startswith("+++"):
                    continue
                check_content = line[1:].strip()
            else:
                check_content = line.strip()

            if not check_content:
                continue

            for category, regex_pat in self.patterns.items():
                for match in re.finditer(regex_pat, check_content):
                    matched_str = match.group(0)

                    # Email exemption check
                    if category == "email" and self.is_exempt_email(matched_str):
                        continue

                    # Mask secret for reporting
                    masked = matched_str[:3] + "*" * (len(matched_str) - 6) + matched_str[-3:] if len(matched_str) > 8 else "***"

                    findings.append({
                        "file": source_name,
                        "line": line_no,
                        "type": category,
                        "sample": masked,
                        "raw_length": len(matched_str)
                    })

        return findings

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scans a file on disk."""
        if not os.path.exists(file_path):
            return []

        # Check protected filename patterns
        protected_globs = self.config.get("protected_patterns", {}).get("files", [])
        base_name = os.path.basename(file_path)
        for glob_pat in protected_globs:
            # Simple wildcards check
            if glob_pat.startswith("*") and base_name.endswith(glob_pat[1:]):
                return [{
                    "file": file_path,
                    "line": 1,
                    "type": "protected_file",
                    "sample": base_name,
                    "raw_length": len(base_name)
                }]
            elif glob_pat.endswith("*") and base_name.startswith(glob_pat[:-1]):
                return [{
                    "file": file_path,
                    "line": 1,
                    "type": "protected_file",
                    "sample": base_name,
                    "raw_length": len(base_name)
                }]

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, source_name=file_path)
        except Exception:
            return []

