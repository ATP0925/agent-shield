"""
Command Interceptor Engine for AgentShield:
Blocks or prompts confirmation for high-risk, destructive terminal commands.
"""

import re
import json
import os
from typing import Dict, Any, Tuple


DEFAULT_DESTRUCTIVE_RULES = [
    {
        "name": "recursive_root_deletion",
        "pattern": r"(?i)(?:rm\s+-rf|rmdir\s+/s\s+/q)\s+(?:[/~]|[A-Za-z]:[\\/])",
        "risk": "CRITICAL",
        "action": "BLOCK",
        "message": "Dangerous recursive deletion of root/home filesystem prohibited."
    },
    {
        "name": "recursive_deletion_variant",
        "pattern": r"(?i)(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|rm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+(?:[/~]|[A-Za-z]:[\\/])",
        "risk": "CRITICAL",
        "action": "BLOCK",
        "message": "Dangerous recursive deletion variant (rm -fr, rm -rfi, etc.) blocked."
    },
    {
        "name": "powershell_recursive_root_deletion",
        "pattern": r"(?i)(?:remove-item|del|rmdir|rd)\s+.*?-recurse\s+.*?(?:[A-Za-z]:[\\/]|/|~)",
        "risk": "CRITICAL",
        "action": "BLOCK",
        "message": "PowerShell recursive root/home deletion prohibited."
    },
    {
        "name": "disk_formatting",
        "pattern": r"(?i)\b(?:format\s+[A-Za-z]:|diskpart)(?:\s|$)",
        "risk": "CRITICAL",
        "action": "BLOCK",
        "message": "Disk formatting and partition destruction blocked."
    },
    {
        "name": "powershell_download_cradle",
        "pattern": r"(?i)(?:iex|invoke-expression)\s*\(.*?(?:downloadstring|webclient|iwr).*?\)",
        "risk": "CRITICAL",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Remote code execution download cradle detected."
    },
    {
        "name": "curl_pipe_execution",
        "pattern": r"(?i)(?:curl|wget)\s+.*?\|\s*(?:bash|sh|zsh|python|powershell)",
        "risk": "CRITICAL",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Remote code download and pipe execution detected."
    },
    {
        "name": "git_force_push",
        "pattern": r"(?i)\bgit\s+push\b.*?\s+(?:--force|-f)\b",
        "risk": "HIGH",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Git force push can overwrite remote branch history."
    },
    {
        "name": "git_force_push_plus",
        "pattern": r"(?i)\bgit\s+push\b.*?\s+\+\w",
        "risk": "HIGH",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Git refspec force push (+branch) can overwrite remote history."
    },
    {
        "name": "git_hard_reset",
        "pattern": r"(?i)\bgit\s+reset\b.*?\s+--hard\b",
        "risk": "HIGH",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Git hard reset discards all uncommitted and staged modifications."
    },
    {
        "name": "database_drop",
        "pattern": r"(?i)\b(?:DROP\s+DATABASE|DROP\s+TABLE|TRUNCATE\s+TABLE)\b",
        "risk": "CRITICAL",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Destructive SQL DDL statement detected."
    },
    {
        "name": "staging_sensitive_environment",
        "pattern": r"(?i)\bgit\s+add\b.*?\s+\.env[^\s]*",
        "risk": "CRITICAL",
        "action": "BLOCK",
        "message": "Direct git staging of environment/secret files (.env*) is blocked."
    },
    {
        "name": "staging_all_files",
        "pattern": r"(?i)\bgit\s+add\s+(?:-[aA]|\.)\s*$",
        "risk": "HIGH",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Blanket staging (git add . / git add -A) may include secret files. Use explicit file paths."
    }
]


class CommandInterceptor:
    """Evaluates shell commands before execution."""

    def __init__(self, config_path: str = None):
        self.rules = list(DEFAULT_DESTRUCTIVE_RULES)
        cfg = self._load_config(config_path)
        custom_cmds = cfg.get("protected_patterns", {}).get("destructive_commands", [])
        for i, pat in enumerate(custom_cmds):
            self.rules.append({
                "name": f"custom_rule_{i}",
                "pattern": pat,
                "risk": "HIGH",
                "action": "REQUIRE_CONFIRMATION",
                "message": f"Matches protected destructive command pattern: {pat}"
            })

    def _load_config(self, path: str = None) -> dict:
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

    def evaluate(self, command_line: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Evaluates a shell command.
        Returns: (is_allowed, action, rule_matched)
        """
        cmd_clean = command_line.strip()
        for rule in self.rules:
            if re.search(rule["pattern"], cmd_clean):
                action = rule["action"]
                allowed = (action != "BLOCK")
                return allowed, action, rule
        return True, "ALLOW", {}
