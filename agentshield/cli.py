"""
CLI Interface for AgentShield.
"""

import sys
import os
import argparse
import subprocess
import json
from .scanner import ShieldScanner
from .command_interceptor import CommandInterceptor
from .gate import ConfirmationGate
from .anonymizer import GitAnonymizer


def cmd_init(args):
    """Initializes AgentShield in current repository."""
    target_dir = os.getcwd()
    git_dir = os.path.join(target_dir, ".git")

    print(f"🛡️  Initializing AgentShield in {target_dir}...")

    # 1. Create shield.config.json if not present
    cfg_path = os.path.join(target_dir, "shield.config.json")
    if not os.path.exists(cfg_path):
        sample_cfg = {
            "version": "1.0.0",
            "security": {
                "block_on_secrets": True,
                "block_on_pii": True,
                "confirmation_steps": 2,
                "exempt_noreply_emails": True
            },
            "protected_patterns": {
                "files": [".env*", "*.pem", "*.key", "id_rsa*", "secrets.*"],
                "agent_artifacts": [".claude/*", ".cursor/*", ".gemini/*"],
                "destructive_commands": ["rm\\s+-rf\\s+[/~]", "git\\s+push\\s+.*--force"]
            },
            "custom_pii_patterns": [],
            "user_settings": {
                "user_alias": "Developer"
            }
        }
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(sample_cfg, f, indent=2)
        print(f"  ✓ Created {cfg_path}")
    else:
        print(f"  ✓ Existing config found at {cfg_path}")

    # 2. Install Git hooks if inside a git repository
    if os.path.exists(git_dir):
        hooks_dir = os.path.join(git_dir, "hooks")
        os.makedirs(hooks_dir, exist_ok=True)

        pre_commit_script = """#!/usr/bin/env sh
# AgentShield Pre-Commit Security Hook
python -m agentshield.cli scan --cached || exit 1
"""
        pre_push_script = """#!/usr/bin/env sh
# AgentShield Pre-Push Security Hook
python -m agentshield.cli scan --diff HEAD~1 || exit 1
"""
        pc_path = os.path.join(hooks_dir, "pre-commit")
        pp_path = os.path.join(hooks_dir, "pre-push")

        with open(pc_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(pre_commit_script)
        with open(pp_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(pre_push_script)

        # Make executable on unix
        try:
            os.chmod(pc_path, 0o755)
            os.chmod(pp_path, 0o755)
        except Exception:
            pass

        print(f"  ✓ Installed Git hooks in {hooks_dir}")
    else:
        print("  ℹ️  No .git folder detected; skipping git hooks installation.")

    print("\n✅ AgentShield initialization complete! Your workspace is protected.")


def cmd_scan(args):
    """Scans git diff, cached index, or specified path."""
    scanner = ShieldScanner()
    findings = []

    if args.cached:
        try:
            diff_text = subprocess.check_output(["git", "diff", "--cached"], text=True, errors="ignore")
            findings = scanner.scan_text(diff_text, source_name="git staged diff")
        except Exception as e:
            print(f"Git diff error: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.diff:
        try:
            diff_text = subprocess.check_output(["git", "diff", args.diff], text=True, errors="ignore")
            findings = scanner.scan_text(diff_text, source_name=f"git diff {args.diff}")
        except Exception as e:
            print(f"Git diff error: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.path:
        if os.path.isdir(args.path):
            for root, _, files in os.walk(args.path):
                for f in files:
                    fp = os.path.join(root, f)
                    findings.extend(scanner.scan_file(fp))
        else:
            findings = scanner.scan_file(args.path)

    if findings:
        print(f"\n🚨 [AgentShield] Security violation detected! Found {len(findings)} issues:")
        for item in findings:
            print(f"   [{item['type'].upper()}] {item['file']}:{item['line']} -> {item['sample']}")
        
        gate = ConfirmationGate(steps=2, non_interactive=args.non_interactive)
        if not gate.verify_action("Commit / Push with detected items", findings):
            print("\n❌ Operation rejected by AgentShield gate.")
            sys.exit(1)
        else:
            print("⚠️  Proceeding under explicit user confirmation.")
            sys.exit(0)
    else:
        print("✅ [AgentShield] Clean! Zero secrets, credentials, or PII detected.")
        sys.exit(0)


def cmd_check_cmd(args):
    """Evaluates an autonomous shell command."""
    interceptor = CommandInterceptor()
    allowed, action, rule = interceptor.evaluate(args.command)
    if not allowed:
        print(f"🚫 [BLOCKED] AgentShield intercepted high-risk command:")
        print(f"   Rule: {rule.get('name')} | Risk: {rule.get('risk')}")
        print(f"   Reason: {rule.get('message')}")
        sys.exit(1)
    elif action == "REQUIRE_CONFIRMATION":
        print(f"⚠️  [CONFIRMATION REQUIRED] Command flagged:")
        print(f"   Rule: {rule.get('name')} | Risk: {rule.get('risk')}")
        print(f"   Reason: {rule.get('message')}")
        gate = ConfirmationGate(steps=1, non_interactive=args.non_interactive)
        if not gate.verify_action(f"Execute flagged command: {args.command}"):
            sys.exit(1)
        sys.exit(0)
    else:
        print("✅ Command authorized by AgentShield.")
        sys.exit(0)


def cmd_doctor(args):
    """Diagnoses environment and security configuration."""
    print("🩺 AgentShield Health Check:")
    author = GitAnonymizer.get_git_author()
    print(f"  • Git Author Name: {author.get('name', 'Not set')}")
    print(f"  • Git Author Email: {author.get('email', 'Not set')}")
    is_anon = GitAnonymizer.is_anonymized(author.get('email', ''))
    status_icon = "✓" if is_anon else "⚠️"
    print(f"  {status_icon} Anonymized Identity: {'Yes (Noreply protected)' if is_anon else 'No (Personal email exposed)'}")

    in_git = os.path.exists(".git")
    print(f"  • Inside Git Repo: {'Yes' if in_git else 'No'}")
    if in_git:
        has_hooks = os.path.exists(".git/hooks/pre-commit")
        print(f"  • Pre-commit Hook: {'Active' if has_hooks else 'Missing (Run: agentshield init)'}")
    print("\nSystem ready.")


def main():
    parser = argparse.ArgumentParser(prog="agentshield", description="Bulletproof security harness for autonomous AI coding agents.")
    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", help="Initialize AgentShield in current repo")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan diff or path for secrets and PII")
    p_scan.add_argument("--cached", action="store_true", help="Scan git staged changes")
    p_scan.add_argument("--diff", type=str, help="Scan git diff against target revision (e.g. HEAD~1)")
    p_scan.add_argument("--path", type=str, help="Scan local file or directory")
    p_scan.add_argument("--non-interactive", action="store_true", help="Fail without interactive prompt in CI")

    # check-cmd
    p_cmd = subparsers.add_parser("check-cmd", help="Evaluate safety of a terminal command")
    p_cmd.add_argument("command", type=str, help="Command line string to evaluate")
    p_cmd.add_argument("--non-interactive", action="store_true", help="Non-interactive evaluation")

    # doctor
    p_doc = subparsers.add_parser("doctor", help="Check security posture and git config")

    args = parser.parse_args()
    command = getattr(args, "command", None)
    if command == "init":
        cmd_init(args)
    elif command == "scan":
        cmd_scan(args)
    elif command == "check-cmd":
        cmd_check_cmd(args)
    elif command == "doctor":
        cmd_doctor(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

