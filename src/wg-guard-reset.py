#!/usr/bin/env python3
"""Emergency NetworkManager WireGuard recovery: disconnect full VPN then clear guard.

--force clears the firewall even if NetworkManager cannot disconnect a full
VPN. This intentionally disables leak protection. Only use at local console.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

STATE = Path('/run/nm_wg_guard_state.json')
CONFIG = Path('/etc/networkmanager-wireguard-guard/sites.json')
TABLES = ('nm_wg_guard',)


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=30)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run as root')
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != '--force'):
        raise RuntimeError('Usage: wg-guard-reset [--force]')
    force = '--force' in sys.argv[1:]
    # Attempt a clean NetworkManager disconnect before disabling the firewall.
    snapshot = run('nmcli', '-t', '-f', 'NAME,TYPE', 'connection', 'show', '--active')
    if snapshot.returncode and not force:
        raise RuntimeError('Cannot read active VPNs; retaining the firewall')
    sites = json.loads(CONFIG.read_text(encoding='utf-8')).get('sites', {})
    profiles = [v['full_profile'] for v in sites.values()]
    for profile in profiles:
        if f'{profile}:wireguard' in snapshot.stdout.splitlines():
            down = run('nmcli', '-w', '20', 'connection', 'down', profile)
            if down.returncode and not force:
                raise RuntimeError('Full tunnel did not disconnect; guard retained. Use --force only if necessary')
    after = run('nmcli', '-t', '-f', 'NAME,TYPE', 'connection', 'show', '--active')
    if not force and (after.returncode or any(
        f'{profile}:wireguard' in after.stdout.splitlines()
        for profile in profiles
    )):
        raise RuntimeError('Cannot confirm full VPN deactivation; retaining the guard')
    try:
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
    except (OSError, ValueError):
        state = {}
    # Firewall removal is intentionally prioritized in an emergency.
    for table in TABLES:
        if run('nft', 'list', 'table', 'inet', table).returncode == 0:
            result = run('nft', 'delete', 'table', 'inet', table)
            if result.returncode:
                raise RuntimeError(f'Could not remove {table}; inspect locally')
            print('Removed firewall table:', table)
    if state.get('version') in (2, 3):
        for rule in state.get('ssh_rules', []):
            family = rule.get('family')
            source = rule.get('source')
            priority = rule.get('priority')
            port = rule.get('port', 22) if state.get('version') == 3 else 22
            if family not in ('-4', '-6') or not isinstance(priority, int) or not 12500 <= priority < 12524:
                continue
            if not isinstance(source, str) or len(source) > 100:
                continue
            if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
                continue
            run('ip', family, 'rule', 'del', 'priority', str(priority),
                'from', source, 'ipproto', 'tcp', 'sport', str(port), 'lookup', 'main')
        print('Managed SSH policy cleanup requested')
    STATE.unlink(missing_ok=True)
    print('Guard recovery complete' + (' (FORCED: leak protection removed)' if force else ''))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print('ERROR:', error, file=sys.stderr)
        sys.exit(1)
