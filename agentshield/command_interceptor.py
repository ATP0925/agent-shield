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
        "name": "git_force_push",
        "pattern": r"(?i)\bgit\s+push\b.*?\s+(?:--force|-f)\b",
        "risk": "HIGH",
        "action": "REQUIRE_CONFIRMATION",
        "message": "Git force push can overwrite remote branch history."
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
    }
]


class CommandInterceptor:
    """Evaluates shell commands before execution."""

    def __init__(self, config_path: str = None):
        self.rules = list(DEFAULT_DESTRUCTIVE_RULES)
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    custom_cmds = cfg.get("protected_patterns", {}).get("destructive_commands", [])
                    for i, pat in enumerate(custom_cmds):
                        self.rules.append({
                            "name": f"custom_rule_{i}",
                            "pattern": pat,
                            "risk": "HIGH",
                            "action": "REQUIRE_CONFIRMATION",
                            "message": f"Matches protected destructive command pattern: {pat}"
                        })
            except Exception:
                pass

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
