"""
Scanner Engine for AgentShield: Detects secrets, credentials, PII, and agent logs.
"""

import os
import re
import json
import math
import fnmatch
import subprocess
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
    "generic_secret": r"""(?i)\b(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*(?:['\"])?[A-Za-z0-9_\-!@#$%^&*]{8,128}(?:['\"])?""",
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
        # Try to find repo root
        repo_root = None
        try:
            repo_root = subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"], 
                text=True, stderr=subprocess.DEVNULL
            ).strip()
        except Exception:
            pass

        candidates = [
            path,
            os.path.join(os.getcwd(), "shield.config.json"),
            os.path.join(repo_root, "shield.config.json") if repo_root else None,
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
        """Checks if email is a safe noreply or test domain address."""
        if not self.config.get("security", {}).get("exempt_noreply_emails", True):
            return False
        # GitHub noreply
        if re.search(r"users\.noreply\.github\.com$", email, re.I):
            return True
        # RFC 2606 test domains
        test_domains = ["example.com", "example.org", "example.net", "test.com", "localhost"]
        domain = email.split("@")[-1].lower() if "@" in email else ""
        if domain in test_domains:
            return True
        return False

    def scan_text(self, text: str, source_name: str = "text") -> List[Dict[str, Any]]:
        """Scans arbitrary text (or git diff) for secrets and PII."""
        findings = []
        lines = text.splitlines()

        # Detect if this is a unified diff format
        is_diff = text.lstrip().startswith("diff ") or text.lstrip().startswith("--- ")

        for line_no, line in enumerate(lines, start=1):
            if is_diff:
                # For diffs, only check added lines (+)
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

                    # Shannon entropy check for generic_secret and jwt_token
                    if category in ("generic_secret", "jwt_token"):
                        token_str = matched_str
                        if category == "generic_secret":
                            parts = re.split(r"[:=]", matched_str, maxsplit=1)
                            if len(parts) > 1:
                                token_str = parts[1].strip(" '\"")
                        if calculate_shannon_entropy(token_str) < 3.0:
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

        # Size guard: skip files > 10MB
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:
                return [{"file": file_path, "line": 0, "type": "oversized_file", 
                         "sample": f"{file_size // (1024*1024)}MB", "raw_length": file_size}]
        except OSError:
            return []

        # Check protected filename patterns (both files and agent_artifacts)
        all_protected = []
        all_protected.extend(self.config.get("protected_patterns", {}).get("files", []))
        all_protected.extend(self.config.get("protected_patterns", {}).get("agent_artifacts", []))

        # Use relative and normalized path for matching
        norm_path = file_path.replace("\\", "/")
        try:
            rel_path = os.path.relpath(file_path).replace("\\", "/")
        except Exception:
            rel_path = norm_path
        base_name = os.path.basename(file_path)

        for glob_pat in all_protected:
            # fnmatch-style matching
            if (
                fnmatch.fnmatch(base_name, glob_pat)
                or fnmatch.fnmatch(rel_path, glob_pat)
                or fnmatch.fnmatch(norm_path, glob_pat)
                or fnmatch.fnmatch(norm_path, f"*/{glob_pat.lstrip('/')}")
            ):
                return [{
                    "file": file_path,
                    "line": 1,
                    "type": "protected_file",
                    "sample": base_name,
                    "raw_length": len(base_name)
                }]

        try:
            with open(file_path, "rb") as f:
                header = f.read(8192)
            # Binary detection: skip files with null bytes
            if b'\x00' in header:
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, source_name=file_path)
        except Exception:
            return []

