# Text-only GitHub + Zenodo release process

1. Create a new empty GitHub repository `marcorighi/networkmanager-wireguard-guard`; start **private** for review, without auto-generated files.
2. Add only the text files in this tree. Never push `.pyc`, generated Info output, PDF, archives, keys, configuration exports, packet captures, screenshots, private hostnames or real endpoints.
3. Run `python3 -m unittest discover -s tests -v` and review `docs/security.md`, `docs/privacy.md` and the output of `git status --short`.
4. Run isolated, non-production fault injection for protected full tunnel, loss and re-establishment, IPv4/IPv6, DNS, switchovers and authorization. Document reproducible results; do not claim tests not performed.
5. Review the source and history; when safe, change the repository to public, choose a release tag and pin the exact Git commit in the CNR technical report. An author-approved stable release comes **after** system tests.
6. For the CNR report, upload the compiled report and LaTeX sources as a *separate Zenodo publication record* (resource type Publication/Technical report) and publish after checking metadata. Zenodo can reserve a DOI before publication.
7. Replace `DOI_PENDING_ZENODO` in this text repository with the *report DOI* and create a new commit. If publishing the source code through Zenodo's GitHub-release integration, it receives its **own software DOI**; do not confuse these identifiers.

This staging directory is **not** evidence of a GitHub commit, public release, independent security audit, or Zenodo deposit.
