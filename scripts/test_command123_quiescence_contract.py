"""Contract regression for rollback checks that must include paused guests.

Read exact local Python sources as reviewed in CI; no libvirt access.
Concrete unit tests also exercise non-shutoff runtime conditions.
"""
from pathlib import Path
import ast
import unittest


FILES = (
    "command123_deployment_transaction.py",
    "command123_repair_rollback.py",
    "command3_service_owned_rollback.py",
    "command2_portable_network_rollback.py",
    "command2_portable_zero_nic_rollback.py",
)
EXACT_RECOVERY_GATES = {
    "command123_deployment_transaction.py": "no_live_work",
    "command123_repair_rollback.py": "no_live_workloads",
    "command3_service_owned_rollback.py": "no_live_guest",
    "command2_portable_network_rollback.py": "no_guest_using_network",
    "command2_portable_zero_nic_rollback.py": "live_admission",
}


class AllGuestRecoveryContract(unittest.TestCase):
    def test_recovery_never_uses_running_only_libvirt_filter(self):
        for path in FILES:
            with self.subTest(file=path):
                code=(Path(__file__).with_name(path)).read_text()
                module=ast.parse(code)
                literals=[
                    n.value for n in ast.walk(module)
                    if isinstance(n, ast.Constant) and
                    isinstance(n.value, str)
                ]
                self.assertNotIn("--state-running",literals)
                self.assertNotIn("--state-paused",literals)
                functions={n.name for n in module.body if
                           isinstance(n, ast.FunctionDef)}
                self.assertIn(EXACT_RECOVERY_GATES[path],functions)

    def test_quiescence_helper_has_only_query_commands(self):
        src=Path(__file__).with_name("command123_libvirt_quiescence.py")
        module=ast.parse(src.read_text())
        strings=[n.value for n in ast.walk(module)
                 if isinstance(n, ast.Constant) and isinstance(n.value,str)]
        for forbidden in ("destroy","shutdown","start","snapshot-revert",
                          "undefine","net-destroy","net-undefine"):
            self.assertNotIn(forbidden,strings)
        self.assertIn("domstate",strings)
        self.assertIn("--all",strings)


if __name__=="__main__":
    unittest.main()
