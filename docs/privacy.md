# Publication privacy checklist

The public tree intentionally contains only generic names `homeLAN` and `workLAB` and example-only domains beneath `example.invalid`. **Neither the public repository nor its Git history should contain**:

- Private or preshared WireGuard keys; QR codes or full connection exports.
- Live endpoint hostnames, dynamic DNS labels, public addresses, private LAN subnets or actual DNS resolvers.
- Private device hostnames, private account names, personal home paths, operational network ownership details, Wi-Fi SSIDs or MAC addresses. Author attribution and the declared CNR affiliation are intentionally public.
- Unredacted command output, logs, backups, archived binaries or screenshots.
- Metadata and Git commit author information that reveal a real identity unless intentionally disclosed.

Run static scanners and manually inspect tracked files **and Git history** before making any repository public. A Git hosting account or commit attribution can still identify the publisher even if the source is anonymized.
