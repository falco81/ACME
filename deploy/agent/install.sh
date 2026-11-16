#!/bin/bash
# install.sh - acme-agent on a server that takes its certificates from acme (docs/target-agent.md)
#
#   sudo ./install.sh                 install (or upgrade) the agent; nothing allowed yet
#   sudo ./install.sh --join CODE     ...and join acme with the code made on the target's card
#   sudo ./install.sh --uninstall     the agent taken away (its policy stays: --purge for it too)
#
# What it does: checks the package (MANIFEST and its signature by acme's release key, when
# openssl can), makes the account acme-agent (no shell, no home, no privileges), puts the agent
# into /usr/local/lib/acme-agent and `acme-agent` into /usr/local/sbin, an empty policy into
# /etc/acme-agent/policy (root:root 0644 - nothing is allowed until you allow it), and the two
# systemd units (acme-agent-root: the root side, no network; acme-agent: the network side, as
# acme-agent, hardened). Red Hat Enterprise Linux 8/9/10 and its rebuilds, Debian 11+, Ubuntu 20.04+.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB=/usr/local/lib/acme-agent
BIN=/usr/local/sbin/acme-agent
UNITS=/etc/systemd/system
JOIN=""
UNINSTALL=""
PURGE=""
say()  { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --join)      JOIN="${2:-}"; shift 2;;
        --uninstall) UNINSTALL="yes"; shift;;
        --purge)     PURGE="yes"; shift;;
        -h|--help)   sed -n '2,15p' "$0"; exit 0;;
        *)           fail "what is $1? (--join CODE, --uninstall [--purge])";;
    esac
done
[[ $(id -u) -eq 0 ]] || fail "run it as root (sudo ./install.sh)"

if [[ -n "$UNINSTALL" ]]; then
    systemctl disable --now acme-agent acme-agent-root 2>/dev/null || true
    rm -f "$UNITS/acme-agent.service" "$UNITS/acme-agent-root.service" "$BIN"
    [[ -L /usr/sbin/acme-agent ]] && rm -f /usr/sbin/acme-agent
    rm -rf "$LIB" /var/lib/acme-agent /var/lib/acme-agent-root
    systemctl daemon-reload 2>/dev/null || true
    if [[ -n "$PURGE" ]]; then
        rm -rf /etc/acme-agent
        userdel acme-agent 2>/dev/null || true
        say "acme-agent taken away, its policy and account too"
    else
        say "acme-agent taken away; its policy stays in /etc/acme-agent (--purge takes it too)"
    fi
    exit 0
fi

# Python 3.7 or later (RHEL 8: dnf install python39)
PY=""
for p in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "$p" >/dev/null && "$p" -c 'import sys, ssl; sys.exit(0 if sys.version_info >= (3, 7) and hasattr(ssl, "TLSVersion") else 1)' 2>/dev/null; then
        PY="$(command -v "$p")"; break
    fi
done
[[ -n "$PY" ]] || fail "Python 3.7 or later is needed (RHEL 8: dnf install python39)"
command -v openssl >/dev/null || fail "openssl is needed"
command -v systemctl >/dev/null || fail "systemd is needed"

# The package checked: every file against MANIFEST, MANIFEST against its signature.
if [[ -f "$HERE/MANIFEST" ]]; then
    (cd "$HERE" && sha256sum --quiet -c MANIFEST) || fail "a file of the package is not the one acme shipped (MANIFEST)"
    if [[ -f "$HERE/MANIFEST.sig" ]]; then
        ok=""
        for k in "$HERE"/release-keys/*.pub; do
            [[ -f "$k" ]] || continue
            if openssl pkeyutl -verify -pubin -inkey "$k" -rawin -in "$HERE/MANIFEST" -sigfile "$HERE/MANIFEST.sig" >/dev/null 2>&1; then
                ok="$(basename "$k" .pub)"; break
            fi
        done
        [[ -n "$ok" ]] || fail "the package's signature is not acme's release key"
        say "the package is signed by $ok"
    else
        say "note: the package is not signed (made from a source tree) - compare its sha256 with the one acme shows"
    fi
fi

getent group acme-agent >/dev/null || groupadd --system acme-agent
getent passwd acme-agent >/dev/null || useradd --system --gid acme-agent --no-create-home \
    --home-dir /var/lib/acme-agent --shell /usr/sbin/nologin --comment "acme-agent (network side)" acme-agent

install -d -m 0755 "$LIB"
install -m 0755 "$HERE/acme_agent.py" "$LIB/acme_agent.py"
[[ -f "$HERE/README.md" ]] && install -m 0644 "$HERE/README.md" "$LIB/README.md"
[[ -f "$HERE/release" ]] && install -m 0644 "$HERE/release" "$LIB/release"
# the release keys this package came with: what an update from acme (allow self-update) is
# checked against - pinned here, never taken from the package being installed by acme
if compgen -G "$HERE/release-keys/*.pub" >/dev/null; then
    install -d -m 0755 "$LIB/release-keys"
    install -m 0644 "$HERE"/release-keys/*.pub "$LIB/release-keys/"
fi
cat > "$BIN" <<WRAP
#!/bin/sh
exec $PY -I $LIB/acme_agent.py "\$@"
WRAP
chmod 0755 "$BIN"
# sudo keeps its own PATH (RHEL: secure_path without /usr/local/sbin) - so that
# "sudo acme-agent ..." finds it too (1.0.117)
if [[ ! -e /usr/sbin/acme-agent || -L /usr/sbin/acme-agent ]]; then ln -sfn "$BIN" /usr/sbin/acme-agent; fi
for u in acme-agent.service acme-agent-root.service; do
    sed "s#/usr/bin/python3 #$PY #" "$HERE/$u" > "$UNITS/$u"
    chmod 0644 "$UNITS/$u"
done
"$BIN" init
systemctl daemon-reload
systemctl enable acme-agent-root acme-agent >/dev/null 2>&1
systemctl restart acme-agent-root acme-agent
say "acme-agent $("$BIN" version) is installed. Nothing is allowed yet: acme-agent policy show"

if [[ -n "$JOIN" ]]; then
    exec "$BIN" join "$JOIN"
fi
say "next: acme-agent join CODE (the code is made on the target's card in acme)"
