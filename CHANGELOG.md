# Changelog

## 0.1.2 — Text-only configurable-port package (unreleased)
- Standardized both illustrative WireGuard endpoints to `51820/UDP`.
- Added configurable local SSH TCP port, default `22`, to root-owned `sites.json` and persisted policy state.
- Added non-executable DNS placeholder reference for VPN DNS, local DNS and routing domain.
- Documented every environment-specific setting and kept the CNR report outside the code archive.
- Extended unit/publication checks; no production network tests are asserted.

## 0.1.1 — Publication candidate (unreleased)
- Created text-only source and documentation release staging.
- Dropped binary bytecode caches and generated GNU Info output.
- Clarified the status of split DNS and end-to-end security tests.
- Added explicit technical report DOI placeholder and versioned citation metadata.
- Corrected privilege-validation ordering for split activation.
- Expanded non-intrusive publication tests.

## 0.1.0 — Initial anonymized preview
- Generalized illustrative destinations to `homeLAN` and `workLAB`.
- Removed original host checks and operational network constants.
- Added source for CLI, GUI, guard, emergency reset, and dispatcher.
