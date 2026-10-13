# Public example variables and local configuration

The public repository contains **no real DNS addresses, VPN endpoints, LAN prefixes, private hostnames, or credentials**. All published network names are fictitious.

| Deployment setting | Documentation placeholder | Public example / runtime handling |
|---|---|---|
| VPN DNS resolver | `VPN_DNS_IP` | Documentation only; configured in local NetworkManager profile |
| DNS resolver of physical network | `LOCAL_DNS_IP` | Documentation only; configured in local NetworkManager profile |
| VPN conditional routing domain | `VPN_DNS_DOMAIN` | Documentation only; set with NetworkManager DNS routing domains |
| WireGuard VPN endpoint | `WG_ENDPOINT_HOST` | `*.example.invalid` is an intentionally unusable placeholder |
| WireGuard UDP endpoint port | `WG_ENDPOINT_PORT` | `51820/UDP`, change locally if required |
| Local SSH TCP port | `SSH_PORT` | `22/TCP`; adjustable via root-controlled `ssh_port` in `sites.json` |
| Private VPN LAN prefix | `PRIVATE_LAN_CIDR` | Not included; NetworkManager route configuration is local |
| WireGuard tunnel IP | `WG_TUNNEL_ADDRESS` | Not included; NetworkManager profile data is local |
| Device / interface | `PHYSICAL_INTERFACE`, `WG_INTERFACE_NAME` | Physical interface is discovered; VPN interface is a generic name in example |
| Connection profile | `NM_PROFILE_NAME` | Synthetic `wg-homeLAN`, `wg-workLAB` names |
| WireGuard private/preshared keys | Not applicable | **Never** publish or include keys, even as plausible values |

Standard application ports are not evidence of the author's operational port assignments. DNS uses protocol-defined `53` for DNS and `853` for DNS-over-TLS in the firewall policy; HTTPS `443` and HTTP `80` are not required by this software and are not invented as executable defaults.

## What the application uses

The guard and CLI consume only the root-controlled `sites.json` and pre-existing NetworkManager profiles. `endpoint_host`, `endpoint_port`, `ssh_port`, and the profile/interface mappings are operational settings. The `.invalid` endpoints must be replaced *in the local file only*; the guard rejects the example as-is. No public configuration contains operational data.

`examples/dns-policy.example.json` is an explanation of required DNS data, **not executable configuration**. Split DNS is controlled by the local NetworkManager + systemd-resolved setup. The current software neither configures nor audits it automatically.

To prepare a live system, keep `sites.json` under `/etc/networkmanager-wireguard-guard/` owned by root, and store WireGuard keys only in the privileged NetworkManager configuration (not in a Git workspace). The repository `.gitignore` is a last-resort protection, not an alternative to excluding secrets before staging them.
