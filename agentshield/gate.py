"""
Interactive Gate for AgentShield: Enforces 2-step verification for sensitive operations.
"""

import sys
from typing import List, Dict, Any


class ConfirmationGate:
    """Manages multi-step confirmations before allowing risky operations."""

    def __init__(self, steps: int = 2, non_interactive: bool = False):
        self.required_steps = max(1, steps)
        self.non_interactive = non_interactive

    def verify_action(self, action_name: str, findings: List[Dict[str, Any]] = None) -> bool:
        """
        Executes a multi-step confirmation gate.
        Returns True if all confirmation steps are satisfied.
        """
        if self.non_interactive:
            # In CI or non-interactive mode, block unless 0 findings
            return findings is None or len(findings) == 0

        print("\n" + "=" * 60)
        print(f"🛡️  AgentShield Confirmation Gate: [{action_name.upper()}]")
        print("=" * 60)

        if findings:
            print(f"⚠️  {len(findings)} potential security/privacy items detected:")
            for item in findings[:5]:
                print(f"  - [{item.get('type')}] in {item.get('file')}:{item.get('line')} -> {item.get('sample')}")
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more items.")

        # Step 1: Payload Inspection
        print(f"\n[Step 1/{self.required_steps}] Payload Verification")
        val1 = input("Have you reviewed the staged changes and confirmed no private keys or secrets exist? (yes/no): ").strip().lower()
        if val1 not in ["y", "yes"]:
            print("❌ Gate Aborted: Step 1 confirmation rejected.")
            return False

        if self.required_steps >= 2:
            # Step 2: Final Authorization
            print(f"\n[Step 2/{self.required_steps}] Final Authorization")
            val2 = input(f"Are you 100% certain you wish to proceed with '{action_name}'? (confirm/cancel): ").strip().lower()
            if val2 not in ["confirm", "yes", "y"]:
                print("❌ Gate Aborted: Step 2 authorization rejected.")
                return False

        print("✅ Gate Passed: Operation authorized.\n")
        return True
