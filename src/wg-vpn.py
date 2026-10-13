#!/usr/bin/env python3
"""Public English CLI for NetworkManager WireGuard profiles."""
import json
import os
from pathlib import Path
import subprocess
import sys

CONFIG = Path('/etc/networkmanager-wireguard-guard/sites.json')
GUARD = '/usr/local/sbin/wg-guard'
GUARD_RESET = '/usr/local/sbin/wg-guard-reset'

HELP = """NetworkManager WireGuard Guard

Usage:
  wg-vpn {homeLAN|workLAB} {full|split|stop|check}
  wg-vpn status
  wg-vpn gui
  wg-vpn --help
  wg-vpn --version

full   Install the kill switch BEFORE activating the full-tunnel profile.
split  Activate a split-tunnel profile; ordinary Internet uses the guest network.
stop   Intentionally disconnect the guarded full VPN, if present; otherwise
       disconnect the selected split profile.  Guard removal follows VPN down.
check  Validate firewall syntax, routing prerequisites and profile settings.
status Display active profiles and firewall state; read-only.
gui    Launch the two-indicator graphical interface.

SECURITY
  Never activate full-tunnel profiles directly from NetworkManager's menu.
  Local networks, DHCP and encrypted WireGuard transport are exceptions.
  LEDs indicate permitted routing paths, not measured packet activity.
  IPv6 Internet, roaming and remote SSH require validation in each environment.
  Emergency recovery from a local console: sudo wg-guard-reset

Documentation: man wg-vpn | info wg-vpn
"""


def call(*args, check=True, timeout=70):
    return subprocess.run(args, check=check, timeout=timeout)


def sites():
    st = CONFIG.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Site configuration must be root-owned and not group/world-writable')
    entries = json.loads(CONFIG.read_text(encoding='utf-8'))['sites']
    if set(entries) != {'homeLAN', 'workLAB'}:
        raise RuntimeError('Expected homeLAN and workLAB configuration entries')
    return entries


def active_wireguard_profiles():
    result = subprocess.run(['nmcli', '-t', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show', '--active'],
                            text=True, capture_output=True, check=True, timeout=10)
    return {fields[0] for line in result.stdout.splitlines()
            if (fields := line.rsplit(':', 2)) and len(fields) == 3 and fields[1] == 'wireguard'}


def full_guard_active():
    return subprocess.run(['sudo', '-n', 'nft', 'list', 'table', 'inet', 'nm_wg_guard'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode == 0


def status(entries):
    print('Active WireGuard profiles:')
    active = active_wireguard_profiles()
    print('\n'.join(sorted(active)) or '(none)')
    print('Kill switch status:')
    try:
        call('sudo', '-n', GUARD, 'status', timeout=7)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print('Guard status unavailable: run sudo wg-guard status')


def main(argv):
    if not argv or argv in (['-h'], ['--help'], ['help']):
        print(HELP)
        return 0
    if argv in (['-V'], ['--version']):
        print('wg-vpn 0.1.2-public-candidate')
        return 0
    if argv == ['gui']:
        os.execv('/usr/local/bin/wg-vpn-gui', ['wg-vpn-gui'])
    entries = sites()
    if argv == ['status']:
        status(entries)
        return 0
    if len(argv) != 2 or argv[0] not in entries or argv[1] not in ('full', 'split', 'stop', 'check'):
        print(HELP, file=sys.stderr)
        return 2
    site, mode = argv
    row = entries[site]
    if mode == 'check':
        call('sudo', '-v')
        call('sudo', GUARD, 'check', site)
    elif mode == 'stop':
        call('sudo', '-v')
        if full_guard_active():
            call('sudo', GUARD, 'stop')
        else:
            active = active_wireguard_profiles()
            if any(entry['full_profile'] in active for entry in entries.values()):
                raise RuntimeError('Unguarded full tunnel active; inspect VPN state before recovery')
            if row['split_profile'] in active:
                call('sudo', 'nmcli', '-w', '25', 'connection', 'down', row['split_profile'])
            else:
                print('Selected split profile is not active; no guard is installed')
    elif mode == 'full':
        call('sudo', '-v')
        call('sudo', GUARD, 'start', site)
    else:
        # Split must not activate when the full guard is present.
        call('sudo', '-v')
        if full_guard_active():
            raise RuntimeError('A full-tunnel guard is active; stop it first')
        active = active_wireguard_profiles()
        if any(entry['full_profile'] in active for entry in entries.values()):
            raise RuntimeError('A full-tunnel profile is active without a guard; inspect locally')
        call('sudo', 'nmcli', '-w', '35', 'connection', 'up', row['split_profile'])
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print('ERROR:', e, file=sys.stderr)
        sys.exit(1)
