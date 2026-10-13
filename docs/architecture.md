# Architecture

Two named destinations are provided only as examples: `homeLAN` and `workLAB`.

- **Full:** CLI -> root guard preflight -> endpoint pre-resolution -> nftables guard -> policy for SSH replies -> NetworkManager activation -> WireGuard.
- **Split:** CLI -> NetworkManager split profile. Ordinary Internet continues through the physical default route.
- **Intentional stop:** NetworkManager VPN down -> nftables guard removed -> managed SSH policy removed.
- **Unexpected loss:** nftables table persists until an explicit release.
- **GUI:** route permissions are inferred from active NetworkManager profiles and verified guard state; LEDs are not packet counters.

Physical-network prefixes are detected dynamically. Directly connected local destinations may remain accessible; transport UDP packets must carry the expected mark and destination port. The guard is not a general-purpose LAN isolation firewall.
