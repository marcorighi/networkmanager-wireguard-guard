"""Non-invasive public source release checks; no root or networking changes."""
from pathlib import Path
import ipaddress
import json
import re
import unittest
import ast

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_SUFFIXES = {'.md', '.py', '.sh', '.json', '.cff', '.texi', '.1', ''}
# Ignore transient interpreter bytecode, which is excluded from the Git repository.
# The release archive itself is separately checked for text-only content.
TEXT_FILES = sorted(p for p in ROOT.rglob('*') if p.is_file()
                    and '.git' not in p.parts and '__pycache__' not in p.parts
                    and p.suffix != '.pyc')

class PublicationChecks(unittest.TestCase):
    def test_synthetic_site_labels(self):
        entries = json.loads((ROOT / 'examples/sites.example.json').read_text())['sites']
        self.assertEqual(set(entries), {'homeLAN', 'workLAB'})
        self.assertTrue(all(row['endpoint_host'].endswith('.example.invalid') for row in entries.values()))

    def test_text_only_files(self):
        for path in TEXT_FILES:
            self.assertNotIn('__pycache__', path.parts)
            self.assertNotEqual(path.suffix, '.pyc')
            # No control bytes other than CR, LF, TAB; UTF-8 text must decode.
            raw = path.read_bytes()
            raw.decode('utf-8')
            self.assertTrue(all(c >= 32 or c in (9, 10, 13) for c in raw), path.name)

    def test_no_literal_private_addresses(self):
        literal = re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
        permitted = {'255.255.255.255', '224.0.0.0'}
        for path in TEXT_FILES:
            for address in literal.findall(path.read_text(encoding='utf-8')):
                ip = ipaddress.ip_address(address)
                self.assertTrue(address in permitted or not ip.is_private,
                                f'Private IPv4 address found in {path.relative_to(ROOT)}')

    def test_no_secret_looking_text(self):
        # Conservative scanner; manual review is required for nonmatching secrets.
        forbidden = [r'(?i)privatekey\s*=', r'(?i)password\s*=',
                     r'(?i)api[_-]?token\s*=', r'[a-z0-9_.-]+\.duckdns\.org']
        for path in TEXT_FILES:
            if path == Path(__file__):
                continue
            data = path.read_text(encoding='utf-8')
            for pattern in forbidden:
                self.assertIsNone(re.search(pattern, data), f'Secret/endpoint marker in {path.relative_to(ROOT)}')

    def test_standard_public_port_examples(self):
        obj = json.loads((ROOT / 'examples/sites.example.json').read_text())
        self.assertEqual(obj['ssh_port'], 22)
        self.assertEqual([row['endpoint_port'] for row in obj['sites'].values()], [51820, 51820])
        dns = json.loads((ROOT / 'examples/dns-policy.example.json').read_text())
        for name in ('homeLAN', 'workLAB'):
            self.assertEqual(dns[name]['vpn_dns_ip'], 'VPN_DNS_IP')
            self.assertEqual(dns[name]['local_dns_ip'], 'LOCAL_DNS_IP')
            self.assertEqual(dns[name]['vpn_dns_domain'], 'VPN_DNS_DOMAIN')

    def test_syntax_all_python_sources(self):
        for path in TEXT_FILES:
            if path.suffix == '.py':
                ast.parse(path.read_text(encoding='utf-8'), filename=str(path))

if __name__ == '__main__':
    unittest.main()
