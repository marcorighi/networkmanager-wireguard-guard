"""Policy-generation unit tests: AST extraction avoids system-specific config."""
import ast
import ipaddress
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / 'src/wg-guard.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'nft_rules')
        space = {'TABLE': 'nm_wg_guard', 'SSH_PORT': 22}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), space)
        cls.build = staticmethod(space['nft_rules'])

    def test_guard_policy_default_drop_and_vpn_exception(self):
        rules = self.build({'fwmark': '0xc101', 'port': 51820}, 'wg-homeLAN', [])
        self.assertIn('oifname "wg-homeLAN" accept', rules)
        self.assertIn('meta mark 0xc101 udp dport 51820 accept', rules)
        self.assertIn('counter drop', rules)
        self.assertIn('tcp sport 22 ct direction reply accept', rules)
        self.assertTrue(rules.endswith('}\n'))

    def test_configurable_ssh_port(self):
        old = self.build.__globals__['SSH_PORT']
        try:
            self.build.__globals__['SSH_PORT'] = 443  # Standard HTTPS port as synthetic custom SSH example.
            rules = self.build({'fwmark': '0xc101', 'port': 51820}, 'wg-homeLAN', [])
            self.assertIn('tcp sport 443 ct direction reply accept', rules)
            self.assertNotIn('tcp sport 22 ct direction reply accept', rules)
        finally:
            self.build.__globals__['SSH_PORT'] = old

    def test_direct_dns_preceded_local_network_allow(self):
        rules = self.build({'fwmark': '0xc101', 'port': 51820}, 'wg-homeLAN', [])
        self.assertLess(rules.index('udp dport { 53, 853 } drop'), rules.index('counter drop'))
        self.assertIn('ip6 daddr ff02::/16 accept', rules)

if __name__ == '__main__':
    unittest.main()
