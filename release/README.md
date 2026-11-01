# Releases of acme

`acme-X.Y.Z.tar.gz` - the last ten versions, each signed (`MANIFEST`,
`MANIFEST.sig`, Ed25519, by a key in `deploy/release-keys/`), built by
`tools/release.py`. `index.json` lists them, newest first (name, version,
size, sha256, date, download_url) - what the servers read
(`upgrade_url`: `https://github.com/falco81/ACME/tree/main/release`);
`LATEST` holds the newest version on its first line.

Nothing here is written by hand: see [docs/releasing.md](../docs/releasing.md).
