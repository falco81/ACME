# Releases of acme

`acme-X.Y.Z.tar.gz` - the last ten versions, each signed (`MANIFEST`,
`MANIFEST.sig`, Ed25519, by a key in `deploy/release-keys/`), built by
`tools/release.py`. `index.json` lists them, newest first (name, version,
size, sha256, date, download_url) - what the servers read
(`upgrade_url`: `https://github.com/falco81/ACME/tree/main/release`);
`LATEST` holds the newest version on its first line.

`acme-agent-X.Y.Z.tar.gz` and `acme-agent-X.Y.Z-windows-x64.msi` - the target
agent of each version (Linux, Windows), signed by the same key and carried inside
acme's package too ([docs/target-agent.md](../docs/target-agent.md)); the MSI is
listed in `index.json` as `agent_windows` of its version.

Nothing here is written by hand: see [docs/releasing.md](../docs/releasing.md).
