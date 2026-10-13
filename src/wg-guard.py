#!/usr/bin/env python3
"""NetworkManager WireGuard fail-closed guard (public reference version).

The firewall is pre-armed before NetworkManager activates a full-tunnel VPN.
A failed activation leaves the firewall enabled (fail closed). Run 'stop'
from the local console to intentionally disconnect and release the guard.

No services or dispatchers are installed by this file. Do not use an
unprotected NetworkManager menu to activate full profiles.
"""

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

TABLE = "nm_wg_guard"
STATE = Path("/run/nm_wg_guard_state.json")
LOCK = Path("/run/nm_wg_guard.lock")
CONFIG = Path("/etc/networkmanager-wireguard-guard/sites.json")
SSH_RULE_PRIORITY = 12500
SSH_RULE_LIMIT = 24


def load_config():
    """Read root-controlled settings; reject unsafe identifiers and values."""
    st = CONFIG.stat()
    if st.st_uid != 0 or (st.st_mode & 0o022):
        raise RuntimeError("Site configuration must be root-owned and not group/world-writable")
    parsed = json.loads(CONFIG.read_text(encoding="utf-8"))
    ssh_port = parsed.get("ssh_port", 22)
    if isinstance(ssh_port, bool) or not isinstance(ssh_port, int) or not (1 <= ssh_port <= 65535):
        raise RuntimeError("Invalid configured local SSH TCP port")
    sites = parsed.get("sites")
    if not isinstance(sites, dict) or set(sites) != {"homeLAN", "workLAB"}:
        raise RuntimeError("Configure precisely homeLAN and workLAB")
    result = {}
    for key, row in sites.items():
        if not isinstance(row, dict):
            raise RuntimeError("Invalid site specification")
        required = ("full_profile", "split_profile", "interface", "fwmark", "endpoint_host", "endpoint_port")
        if not all(isinstance(row.get(field), (str, int)) for field in required):
            raise RuntimeError("Missing or invalid site field")
        for field in ("full_profile", "split_profile", "interface", "endpoint_host"):
            value = row[field]
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", value):
                raise RuntimeError("Unsafe site identifier")
        mark = row["fwmark"]
        if not isinstance(mark, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", mark) or int(mark, 16) == 0:
            raise RuntimeError("Invalid WireGuard fwmark")
        port = row["endpoint_port"]
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise RuntimeError("Invalid UDP port")
        if row["endpoint_host"].endswith(".invalid"):
            raise RuntimeError("Replace the example endpoint placeholders before using the guard")
        result[key] = {"name": row["full_profile"], "split": row["split_profile"],
                       "interface": row["interface"], "fwmark": mark.lower(),
                       "port": port, "hostname": row["endpoint_host"]}
    names = [value[field] for value in result.values() for field in ("name", "split")]
    if len(set(names)) != len(names):
        raise RuntimeError("NetworkManager profile names must be unique")
    return result, ssh_port


PROFILES, SSH_PORT = load_config()
FULL_NAMES = {row["name"] for row in PROFILES.values()}


def command(*args, input_text=None, check=True, timeout=35):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True,
        timeout=timeout, env={**os.environ, "LC_ALL": "C"},
    )
    if check and result.returncode:
        raise RuntimeError(f"Failed: {args[0]} (exit={result.returncode})")
    return result


def capture(*args):
    return command(*args).stdout.strip()


def require_root():
    if os.geteuid() != 0:
        raise RuntimeError("Run as root")


def exists_guard():
    return command("nft", "list", "table", "inet", TABLE, check=False).returncode == 0


def active_vpn():
    result = {}
    for line in capture("nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active").splitlines():
        fields = line.rsplit(":", 2)
        if len(fields) == 3 and fields[1] == "wireguard":
            result[fields[0]] = fields[2]
    return result


def incoming_ssh():
    return bool(capture("ss", "-Htn", "state", "established", "(", "sport", "=", f":{SSH_PORT}", ")"))


def profile_info(label):
    data = PROFILES[label]
    name = data["name"]
    stored_mark = capture("nmcli", "-g", "wireguard.fwmark", "connection", "show", name).lower()
    if stored_mark != data["fwmark"]:
        raise RuntimeError(f"{name}: unexpected WireGuard fwmark")
    device = capture("nmcli", "-g", "connection.interface-name", "connection", "show", name)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", device) or device == "--" or device != data["interface"]:
        raise RuntimeError(f"{name}: unexpected WireGuard interface name")
    autoconnect = capture("nmcli", "-g", "connection.autoconnect", "connection", "show", name)
    if autoconnect.lower() != "no":
        raise RuntimeError(f"{name}: autoconnect must remain disabled")
    return data, device


def physical_and_networks():
    devices = set()
    for line in capture("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status").splitlines():
        fields = line.rsplit(":", 2)
        if len(fields) != 3:
            continue
        name, kind, state = fields
        if kind in ("wifi", "ethernet", "bluetooth") and state.startswith("connected"):
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                raise RuntimeError("Unsafe physical interface name")
            devices.add(name)
    prefixes = set()
    for family in (4, 6):
        routes = json.loads(capture("ip", "-j", f"-{family}", "route", "show", "table", "main"))
        for route in routes:
            interface = route.get("dev")
            if interface not in devices or any(route.get(k) for k in ("gateway", "via", "nexthops")):
                continue
            destination = route.get("dst", "default")
            if destination == "default":
                continue
            net = ipaddress.ip_network(destination, strict=False)
            if net.prefixlen == 0 or net.is_loopback or net.is_multicast or net.is_unspecified:
                continue
            prefixes.add((interface, net))
    return devices, sorted(prefixes, key=lambda x: (x[0], x[1].version, str(x[1])))


def nft_rules(data, vpn_device, prefixes):
    # DHCP, neighbour discovery and strictly link-local multicast must work
    # on a newly connected interface *before* NetworkManager announces it.
    statements = [
        'oifname "lo" accept',
        f'oifname "{vpn_device}" accept',
        f'meta mark {data["fwmark"]} udp dport {data["port"]} accept',
        # Only response-direction traffic from sshd may use the physical route.
        f'tcp sport {SSH_PORT} ct direction reply accept',
        'udp sport 68 udp dport 67 accept',
        'udp sport 546 udp dport 547 accept',
        'icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept',
        'ip daddr 255.255.255.255 accept',
        'ip daddr 224.0.0.0/24 accept',
        'ip6 daddr ff02::/16 accept',
        # No direct DNS/DoT fallback through a physical LAN.
        'udp dport { 53, 853 } drop',
        'tcp dport { 53, 853 } drop',
    ]
    for iface, network in prefixes:
        family = "ip" if network.version == 4 else "ip6"
        statements.append(f'oifname "{iface}" {family} daddr {network} accept')
    statements.append("counter drop")
    return (
        f"table inet {TABLE} {{\n"
        " chain output {\n"
        "  type filter hook output priority 10; policy accept;\n"
        + "\n".join(f"  {line}" for line in statements)
        + "\n }\n}\n"
    )


def syntax_check(rules, replace):
    batch = (f"delete table inet {TABLE}\n" if replace else "") + rules
    result = command("nft", "-c", "-f", "-", input_text=batch, check=False)
    if result.returncode:
        raise RuntimeError("nft syntax check failed: " + result.stderr.strip())
    return batch


def reserved_ssh_priorities_in_use():
    for family in ("-4", "-6"):
        for line in capture("ip", family, "rule", "show").splitlines():
            match = re.match(r"^\s*(\d+):", line)
            if match and SSH_RULE_PRIORITY <= int(match.group(1)) < SSH_RULE_PRIORITY + SSH_RULE_LIMIT:
                return True
    return False


def physical_ssh_rules(devices):
    """Route only sshd replies from actual physical IPs outside the VPN."""
    records = []
    for device in sorted(devices):
        for link in json.loads(capture("ip", "-j", "address", "show", "dev", device)):
            for info in link.get("addr_info", []):
                family = info.get("family")
                if family not in ("inet", "inet6"):
                    continue
                address = ipaddress.ip_address(info.get("local"))
                if address.is_loopback or address.is_multicast or address.is_unspecified:
                    continue
                family_arg = "-4" if family == "inet" else "-6"
                prefix = f"{address}/{address.max_prefixlen}"
                records.append((family_arg, prefix))
    records = sorted(set(records))
    if len(records) > SSH_RULE_LIMIT:
        raise RuntimeError("Too many physical interface addresses for SSH policy")
    # A numeric priority is unique *within* each address family.
    counts = {"-4": 0, "-6": 0}
    result = []
    for family, source in records:
        priority = SSH_RULE_PRIORITY + counts[family]
        counts[family] += 1
        result.append({"family": family, "source": source, "priority": priority, "port": SSH_PORT})
    return result


def add_one_ssh_rule(rule):
    command("ip", rule["family"], "rule", "add", "priority", str(rule["priority"]),
            "from", rule["source"], "ipproto", "tcp", "sport", str(rule["port"]), "lookup", "main")


def del_one_ssh_rule(rule):
    command("ip", rule["family"], "rule", "del", "priority", str(rule["priority"]),
            "from", rule["source"], "ipproto", "tcp", "sport", str(rule["port"]), "lookup", "main",
            check=False)


def add_ssh_rules(rules):
    for rule in rules:
        add_one_ssh_rule(rule)


def delete_ssh_rules(rules):
    for rule in rules:
        del_one_ssh_rule(rule)


def replace_ssh_rules(old, new):
    # Keep unchanged rules, add new rules, then remove old obsolete rules.
    # nftables remains fail-closed throughout.
    old_ids = {(r["family"], r["source"], r["priority"], r["port"]) for r in old}
    new_ids = {(r["family"], r["source"], r["priority"], r["port"]) for r in new}
    for r in new:
        if (r["family"], r["source"], r["priority"], r["port"]) not in old_ids:
            add_one_ssh_rule(r)
    for r in old:
        if (r["family"], r["source"], r["priority"], r["port"]) not in new_ids:
            del_one_ssh_rule(r)


def save_state(label, vpn_device, ssh_rules):
    temp = STATE.with_suffix(".tmp")
    temp.write_text(json.dumps({"profile": label, "device": vpn_device, "version": 3, "ssh_rules": ssh_rules}) + "\n")
    os.chmod(temp, 0o600)
    os.replace(temp, STATE)


def read_state():
    if not STATE.exists():
        raise RuntimeError("Guard state missing; use emergency recovery from local console")
    state = json.loads(STATE.read_text())
    if state.get("version") != 3 or state.get("profile") not in PROFILES:
        raise RuntimeError("Unknown guard state; do not modify firewall")
    rules = state.get("ssh_rules")
    if not isinstance(rules, list):
        raise RuntimeError("Invalid SSH policy state; guard retained")
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("family") not in ("-4", "-6"):
            raise RuntimeError("Invalid SSH policy state; guard retained")
        if (not isinstance(rule.get("source"), str)
            or not isinstance(rule.get("priority"), int)
            or isinstance(rule.get("priority"), bool)
            or not SSH_RULE_PRIORITY <= rule["priority"] < SSH_RULE_PRIORITY + SSH_RULE_LIMIT
            or not isinstance(rule.get("port"), int)
            or isinstance(rule.get("port"), bool)
            or not 1 <= rule["port"] <= 65535):
            raise RuntimeError("Invalid SSH policy state; guard retained")
    return state


def stop():
    # Intentionally disconnect before removing the firewall: no unguarded
    # handoff while the full-tunnel default route is still in effect.
    guard = exists_guard()
    if not guard and not STATE.exists():
        print("Guard absent; no protected full tunnel to stop")
        return
    if not guard:
        raise RuntimeError("Guard table unexpectedly absent; investigate before continuing")
    state = read_state()
    name = PROFILES[state["profile"]]["name"]
    other = {key: value for key, value in active_vpn().items() if key in FULL_NAMES and key != name}
    if other:
        raise RuntimeError("Another full tunnel is active; guard retained")
    if name in active_vpn():
        command("nmcli", "-w", "25", "connection", "down", name, timeout=33)
    if any(key in active_vpn() for key in FULL_NAMES):
        raise RuntimeError("Full VPN remains active; guard retained")
    command("nft", "delete", "table", "inet", TABLE)
    delete_ssh_rules(state.get("ssh_rules", []))
    STATE.unlink(missing_ok=True)
    print("Full VPN disconnected; guard removed; normal routing restored")


def refresh():
    if not exists_guard():
        if STATE.exists():
            raise RuntimeError("Guard state exists but table is missing")
        print("Guard absent: nothing to refresh")
        return
    state = read_state()
    profile = state["profile"]
    data, device = profile_info(profile)
    active = active_vpn()
    if any(key in FULL_NAMES and key != data["name"] for key in active):
        raise RuntimeError("Conflicting full tunnel; old guard retained")
    devices, prefixes = physical_and_networks()
    new_ssh = physical_ssh_rules(devices)
    batch = syntax_check(nft_rules(data, device, prefixes), replace=True)
    old_ssh = state.get("ssh_rules", [])
    replace_ssh_rules(old_ssh, new_ssh)
    # Persist the new SSH rules before replacing nftables.
    save_state(profile, device, new_ssh)
    command("nft", "-f", "-", input_text=batch)
    print("Guard refreshed; local prefixes:", len(prefixes), "physical interfaces:", len(devices))


def preflight(label, dry_run):
    if exists_guard() or STATE.exists():
        raise RuntimeError("Guard/state already present; inspect status or stop first")
    active = active_vpn()
    if active:
        raise RuntimeError("All WireGuard profiles must be inactive before guarded activation")
    if incoming_ssh():
        raise RuntimeError("Incoming SSH session active; perform initial test locally")
    data, device = profile_info(label)
    devices, prefixes = physical_and_networks()
    if not devices:
        raise RuntimeError("No connected physical interface")
    if reserved_ssh_priorities_in_use():
        raise RuntimeError("SSH routing policy priority range already in use")
    ssh_rules = physical_ssh_rules(devices)
    batch = syntax_check(nft_rules(data, device, prefixes), replace=False)
    print("Profile:", data["name"])
    print("WG interface:", device)
    print("Physical interfaces:", len(devices))
    print("Directly connected prefixes:", len(prefixes))
    print("Firewall syntax: PASS")
    if dry_run:
        print("READ-ONLY CHECK: no connection or firewall changes")
    return data, device, batch, ssh_rules


def start(label):
    data, device, batch, ssh_rules = preflight(label, dry_run=False)
    # Warm the DNS cache before the firewall starts blocking physical DNS.
    # Resolving once does not guarantee future re-resolution on roaming.
    try:
        resolved = socket.getaddrinfo(data["hostname"], data["port"],
                                      socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise RuntimeError("Endpoint hostname cannot be resolved before arming") from exc
    if not resolved:
        raise RuntimeError("Endpoint hostname resolution returned no addresses")
    print("Endpoint DNS resolved before guard: YES", flush=True)
    # Order matters: install a fail-closed firewall before an IP-rule change
    # or requesting WireGuard activation.
    command("nft", "-f", "-", input_text=batch)
    save_state(label, device, ssh_rules)
    print("Guard installed BEFORE VPN activation: YES", flush=True)
    # If these steps fail, do not remove the guard automatically.
    add_ssh_rules(ssh_rules)
    result = command("nmcli", "-w", "45", "connection", "up", data["name"],
                     check=False, timeout=52)
    if result.returncode:
        raise RuntimeError("NetworkManager failed to activate VPN; guard remains ACTIVE. "
                           "Use 'stop' locally to restore normal Internet")
    actual = capture("wg", "show", device, "fwmark").lower()
    if actual != data["fwmark"]:
        raise RuntimeError("Runtime fwmark differs; guard remains ACTIVE")
    print("Full VPN activated with guard retained: " + data["name"])
    print("Guard stays enabled if the tunnel later becomes unreachable")


def status():
    guard = exists_guard()
    state = STATE.exists()
    print("Firewall guard:", "ACTIVE" if guard else "ABSENT")
    print("Guard state:", "PRESENT" if state else "ABSENT")
    if guard != state:
        print("WARNING: Firewall and state are inconsistent; inspect locally")
    if guard and state:
        try:
            obj = read_state()
            print("Protected full profile:", PROFILES[obj["profile"]]["name"])
        except (RuntimeError, OSError, ValueError) as exc:
            print("WARNING:", exc)
    count = len(read_state().get("ssh_rules", [])) if guard and state else 0
    print("Configured SSH source rules:", count)


def main():
    require_root()
    args = sys.argv[1:]
    if not args:
        raise RuntimeError("Usage: wg-guard check|start {homeLAN|workLAB}; stop; refresh; status")
    verb = args[0]
    if (verb in ("check", "start") and (len(args) != 2 or args[1] not in PROFILES)) or (verb in ("stop", "refresh", "status") and len(args) != 1):
        raise RuntimeError("Invalid arguments")
    if verb not in ("check", "start", "stop", "refresh", "status"):
        raise RuntimeError("Unknown command")
    with LOCK.open("a", encoding="ascii") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        if verb == "check":
            preflight(args[1], dry_run=True)
        elif verb == "start":
            start(args[1])
        elif verb == "stop":
            stop()
        elif verb == "refresh":
            refresh()
        else:
            status()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print("ERROR:", str(error), file=sys.stderr)
        sys.exit(1)
