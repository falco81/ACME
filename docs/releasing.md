# Making a release

A release is one file, `release/acme-X.Y.Z.tar.gz`, built from this tree by
`tools/release.py` and committed to `main` beside the source. The servers find
it there by themselves (`upgrade_url`, by default
`https://github.com/falco81/ACME/tree/main/release`) and download it from
`raw.githubusercontent.com`.

The repository itself is the unpacked variant: the same tree, without
`MANIFEST`/`MANIFEST.sig` (only the package is signed). `release.py` changes
nothing in it but `release/` - and, only when asked with `--bump`, the one line
of `acmelib/__init__.py` that holds the version.

## The flow

1. **The version.** `acmelib/__init__.py` holds it (`__version__ = 'X.Y.Z'`),
   in one place. Raise it by hand or with

   ```bash
   python3 tools/release.py --bump patch      # or minor, major - and nothing else is built yet
   ```

   (without a key `--bump` only raises the version; with one it goes on and
   builds.) `python3 tools/release.py --version` says which
   version would be built.

   If the new version writes something older ones cannot read, raise
   `DOWNGRADE_FLOOR` in `acmelib/engine/000_start.py` too
   ([upgrades.md](upgrades.md), going back).

2. **CHANGELOG.md**: a section `## X.Y.Z - YYYY-MM-DD` at the top, written for
   the people who run acme - the pages show it before an upgrade, and what
   going back gives up. `release.py` refuses a version without one.

3. **Check it**: `python3 tools/lint-engine.py`, `python3 test/checks.py`,
   `bash -n install.sh`, and an install on a test machine
   (`sudo ./install.sh --dry-run`, then for real).

4. **Build it**:

   ```bash
   ACME_RELEASE_KEY=/path/to/acme-release-1.key python3 tools/release.py
   # or:  python3 tools/release.py --key /path/to/acme-release-1.key
   ```

   It
   - collects the tree: every file but `.git/`, `.github/`, `.claude/`,
     `release/`, `build/`, `dist/`, virtual environments, `__pycache__/`,
     `*.pyc`, editor and test caches, and any `*.key`; a link or anything but a
     plain file stops it;
   - writes `MANIFEST` (`SHA256  path`, one line a file, sorted) and signs it:
     `MANIFEST.sig` is the raw 64-byte **Ed25519** signature of `MANIFEST`
     (`openssl pkeyutl -sign -rawin`), by the private key, whose public half
     must be in `deploy/release-keys/`;
   - packs `acme-X.Y.Z/` into `release/acme-X.Y.Z.tar.gz` - root's, fixed modes
     (0755 for what is executable, 0644 else), one timestamp
     (`SOURCE_DATE_EPOCH` if set), folders only where a file is;
   - checks the package exactly as a server does: `deploy/acme_upgrade.py
     --inspect` against `deploy/release-keys/` (the signature, every file and
     nothing more, the version in `acmelib/__init__.py`). A package that does
     not pass is deleted again;
   - deletes every package in `release/` but the **last ten** versions (git
     keeps the older ones);
   - writes `release/index.json` and `release/LATEST`.

   A version that is in `release/` already is never built again (`--force` if
   it was never pushed); one older than the newest there is refused.

5. **Commit and push** `release/` together with the source, to `main`:

   ```bash
   git add -A release/ acmelib/__init__.py CHANGELOG.md
   git commit -m "acme X.Y.Z"
   git push origin main
   ```

   Every server with `upgrade_check` on sees it within a day (Settings →
   Upgrades → *Look now* at once).

## release/index.json

What the engine's "new versions from the web"
(`acmelib/engine/210_new_versions_from_the.py`) reads first for a GitHub
folder - from `raw.githubusercontent.com/OWNER/REPO/BRANCH/FOLDER/index.json`,
so no API and none of its limit of 60 an hour; only where it is missing is
GitHub's API (and then the folder's page) asked. It is a list, newest first:

```json
[
  {
    "name": "acme-1.0.1.tar.gz",
    "version": "1.0.1",
    "size": 1811459,
    "sha256": "56ed3422…",
    "date": "2026-11-01T09:37:06Z",
    "download_url": "https://raw.githubusercontent.com/falco81/ACME/main/release/acme-1.0.1.tar.gz"
  }
]
```

`upgrade_url` may also be the address of an `index.json` itself (any HTTPS
server: `--base-url` sets the `download_url`s for one). The server holds a
package it downloads to its `sha256` before it even checks the signature. The
`date` of a version is kept from the index before when its package has not
changed.

`release/LATEST` is for scripts: the newest version on its first line, then
its file name, `sha256`, `size`, `date` and `url`, one a line.

## The release key

- The **public** half is `deploy/release-keys/acme-release-1.pub` (PEM,
  Ed25519). install.sh puts exactly the keys of the version it installs into
  `/usr/local/lib/acme/release-keys/` (root's), and an upgrade from the pages is
  refused unless `MANIFEST.sig` verifies with one of them. (The key of otp, the
  product acme was made from, is not trusted.)
- The **private** half is never in the repository (`release.py` refuses one
  inside it, and leaves out every `*.key` when it packs). Keep it offline, with
  a copy; give it to `release.py` by `ACME_RELEASE_KEY` or `--key`.
- A new pair:

  ```bash
  python3 tools/release.py --make-key --name acme-release-2 --key ~/.acme/acme-release-2.key
  ```

  puts `deploy/release-keys/acme-release-2.pub` in the tree. To change keys
  without stranding servers: release once with **both** public keys in
  `deploy/release-keys/` (signed by the old key), then sign the next ones with
  the new key and drop the old `.pub`. A server that missed the overlap is
  upgraded once on the command line (`install.sh --upgrade` trusts the person
  who runs it).
- A key that leaked: remove its `.pub`, make a new pair, release (signed by
  the new key - so this one release goes in on the command line, everywhere).
