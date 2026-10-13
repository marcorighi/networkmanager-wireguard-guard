# NetworkManager WireGuard Guard

**Status: v0.1.2 publication candidate — not yet validated by independent network fault-injection tests.**

Author: Marco Righi (National Research Council of Italy, CNR-IFC).

An anonymized, text-only reference implementation for independently operated Linux WireGuard VPNs through NetworkManager. Example destinations are `homeLAN` and `workLAB`; they do not identify real deployments.

## Components

- `wg-vpn`: CLI to select pre-existing NetworkManager WireGuard profiles in full or split mode.
- `wg-guard`: nftables-based output guard pre-armed **before** activating a full tunnel. Failed activation retains the guard.
- `wg-guard-reset`: emergency recovery for intentional local-console use.
- `wg-vpn-gui`: Tkinter/XFCE interface with route-state indicators (not verified tunnel handshakes).
- Optional NetworkManager dispatcher; manual and Texinfo source; static/unit tests.

## Functional limits

- **Full tunnel:** blocks non-exempt outgoing traffic when the tunnel cannot carry it. Link-local networks, DHCP, encrypted VPN transport and certain management operations have explicit exceptions. Fail-closed does not mean zero physical-network packets.
- **Split tunnel:** uses the routes already defined in the selected NetworkManager profile.
- **Split DNS:** must be separately configured and verified in NetworkManager (for example with `systemd-resolved` routing domains). This application does **not** automatically provision DNS-domain routing.
- **IPv6:** rule generation includes IPv6, but complete leak/roaming behavior has not been validated.
- Never activate protected full profiles directly outside the controller; doing so bypasses pre-arming.

## Requirements and safety

Linux with NetworkManager/WireGuard support, Python 3, nftables, iproute2 and WireGuard tools. For GUI usage, Tkinter and a suitable desktop terminal are needed.

**Do not deploy this publication candidate on a production workstation** before performing isolated fault-injection, connectivity, DNS and dual-stack tests.

Illustrative configuration: `examples/sites.example.json`, using synthetic endpoints under `example.invalid`, WireGuard port `51820/UDP` and SSH port `22/TCP`. DNS placeholders are `VPN_DNS_IP`, `LOCAL_DNS_IP` and `VPN_DNS_DOMAIN`. Configure real values only locally; never commit private keys, private DNS, endpoints, logs or configurations.

Unit and static tests: `python3 -m unittest discover -s tests -v`. Tests must never alter production firewall or routes.

## Publications and DOI

**CNR technical report DOI (pre-reserved): [`10.5281/zenodo.23347452`](https://doi.org/10.5281/zenodo.23347452).** The Zenodo record remains an unpublished draft; this DOI will become registered and resolvable after publication.

The CNR report PDF and LaTeX are prepared for a separate Zenodo technical-report record with the pre-reserved DOI above. The record has not been published yet. These files are intentionally not part of this text-only source repository. A separate Zenodo software DOI, if assigned in future, is a different scholarly object. The report must reference the actual published code revision.

## License

MIT; see `LICENSE`.

See `docs/installation.md`, `docs/security.md`, `docs/dns-policy.md`, `docs/privacy.md` and `RELEASE_STATUS.md` before deployment.