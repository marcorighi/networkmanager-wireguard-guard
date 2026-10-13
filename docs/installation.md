# Installation (unverified publication candidate)

**Do not install this candidate on a production host without a local recovery path and independent security review.**

1. Review all files, especially `src/wg-guard.py`, `src/wg-guard-reset.py` and the dispatcher. Check compatibility with your firewall and NetworkManager version.
2. Install dependencies: Python 3, NetworkManager with WireGuard support, wireguard-tools, nftables, `iproute2`, XFCE Terminal, Tkinter, man-db and Texinfo (for GNU Info).
3. Install root-owned scripts in `/usr/local/sbin` and the CLI/GUI in `/usr/local/bin`. Never execute a user-editable copy with elevated privileges.
4. Create `/etc/networkmanager-wireguard-guard/sites.json` from the example. The public example uses `51820/UDP` for both illustrative endpoints and `22/TCP` for local SSH. Set these to the actual LOCAL values only outside the repository. Replace all example values and make the file root-owned; recommended mode 0644 (the local GUI and CLI must read this file; it must not contain secrets).
5. Set DNS policy in NetworkManager separately. The example DNS file in `examples/` is documentary and contains only placeholders (`VPN_DNS_IP`, `LOCAL_DNS_IP`, `VPN_DNS_DOMAIN`). Consult [configuration placeholders](configuration-placeholders.md). Create or import four NetworkManager WireGuard profiles. Full profiles must use distinct nonzero fwmarks, fixed interface names, and `autoconnect=no`. Split profiles should not have an Internet default route.
6. Run `sudo wg-guard check homeLAN` and `sudo wg-guard check workLAB` before any activation. The public example endpoints end in `.invalid`, and the guard intentionally rejects them.
7. Before activating a guard for the first time, arrange a rollback timer and a *local* access method. Test full activation, failure paths, and intentional recovery.
8. Configure GUI status read-only access according to local security policy; without it the LEDs show an **unknown** state rather than guessing.
9. Install the optional NetworkManager refresh dispatcher only after testing it on Wi-Fi/Ethernet and VPN reconnects.

The application does not ship production NetworkManager secrets, active endpoints or ready-to-use credentials.
