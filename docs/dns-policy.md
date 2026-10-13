# DNS routing policy: external NetworkManager configuration

The program selects between previously created NetworkManager connection profiles. It **does not provision split DNS or validate DNS leak absence**.

`split tunnel` controls IPv4/IPv6 routing. `split DNS` controls which resolver receives which query. A secondary DNS server is not a domain-routing policy.

For deployments using NetworkManager + systemd-resolved, DNS routing domains can be configured on the appropriate profiles using the documented `ipv4.dns-search` / `ipv6.dns-search` and `~domain` syntax. A routing-only domain such as `~home.example` sends matching lookups to that connection's DNS server; `~.` is a catch-all routing domain. These are examples; never copy nonexistent resolver addresses into a production connection.

Before claiming DNS isolation, test in a disposable VM with separate synthetic resolvers, using `resolvectl status`, `resolvectl query`, and packet-level verification. Repeat with tunnel loss, recovery, interface switching, IPv6 availability, and a downed private resolver. Applications with their own DNS-over-HTTPS stacks may bypass system resolver routing; the policy must account for this separately.

Reference: [NetworkManager DNS settings](https://networkmanager.dev/docs/api/latest/settings-ipv4.html) and [systemd-resolved](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html).

## Placeholder reference

See [`examples/dns-policy.example.json`](../examples/dns-policy.example.json). Its strings `VPN_DNS_IP`, `LOCAL_DNS_IP`, and `VPN_DNS_DOMAIN` are **not real addresses or domains** and are never consumed by the software. No public DNS values describe an actual deployment.
