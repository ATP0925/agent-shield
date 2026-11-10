"""
AgentShield: The bulletproof safety harness for autonomous AI coding agents.
Protects against credential leakage, PII exposure, and destructive autonomous commands.
"""

import sys

# Ensure UTF-8 output encoding across cross-platform environments (e.g. Windows consoles)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

__version__ = "1.0.0"
__author__ = "ATP0925"
__license__ = "MIT"


