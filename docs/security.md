# Security considerations

This source is provided as a reviewable reference, **not** a claim of universal leak protection.

- Guard activation must precede full-tunnel NetworkManager activation. The standard NetworkManager GUI does not enforce this sequence.
- A mark-based WireGuard exception allows encrypted tunnel transport to the physical network. Other exceptions include DHCP, IPv6 neighbor discovery, locally connected prefixes, and restricted SSH replies.
- Full-tunnel IPv4 output blocking has to be tested with an explicit physical-interface probe and nftables drop counters.
- **IPv6 Internet support must be independently tested** when a physical IPv6 default route exists. Do not infer safety from absence of an IPv6 default route in a test network.
- Endpoint DNS is pre-resolved once. Future DNS changes, captive portals, endpoint migration, and roaming may require additional design.
- SSH routing rules based on source address and source TCP port are not proof that remote SSH will always stay reachable. Test live sessions.
- Split and full sessions should be mutually exclusive; do not directly activate full profiles outside the wrapper.
- Never put a live VPN private key, public endpoint, QR export, personal hostname, organization name, or internal network inventory into the repository.
- A local root-owned emergency recovery utility is provided; removing the guard intentionally re-enables ordinary physical Internet traffic.
