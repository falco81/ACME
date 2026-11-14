#!/usr/bin/env bash
#
# install.sh — set up acme, the certificate-automation appliance, on AlmaLinux,
# Rocky or RHEL 9 and 10, and (with less of it automatic) Debian and Ubuntu.
#
# acme orders and renews certificates (Let's Encrypt and any ACME CA, its own
# CAs, AD CS, SCEP), answers the CA's validation itself (its own DNS server on
# port 53, HTTP-01 on port 80 through nginx) and puts every new certificate
# where it is used (over SSH, to load balancers, firewalls, appliances).
#
# What this does: packages (Python 3.14, PHP-FPM 8.3, nginx, openssl, the
# OpenSSH client, chrony), a PHP fixed against php2shell, the accounts acme,
# acme-www and the group acme-web, the program tree in /usr/local/lib/acme/
# (put in beside the one running and switched to in one step - an upgrade
# never leaves half a tree, and the tree before is kept for going back), the
# configuration, the systemd units, log rotation, nginx with TLS and a php-fpm
# pool of acme's own, SELinux, the firewall, the first account, the console at
# root's login, and a check that it all works. Run it from inside the unpacked
# folder, as root:
#
#     sudo ./install.sh
#
# Everything it asks can be given on the command line; --help lists it.
# --dry-run prints what would happen and changes nothing. --upgrade replaces
# the program and the pages, brings PHP up to the fixed release and restarts,
# keeping the database, the configuration and the accounts. --uninstall
# removes the service and the pages and keeps everything recorded.
#
set -Eeuo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The version is acmelib/__init__.py's; the floor for going back is the engine's.
VERSION="$(sed -n "s/^__version__ = [\"']\([^\"']*\)[\"'].*/\1/p" "$SOURCE_DIR/acmelib/__init__.py" 2>/dev/null | head -n1)"
VERSION="${VERSION:-unknown}"
SERVICE_USER="acme"
WEB_GROUP="acme-web"
POOL_USER="acme-www"
LIB_DIR="/usr/local/lib/acme"
TREES_DIR="$LIB_DIR/versions"
BIN_LINK="/usr/local/bin/acme"
CONFIG_DIR="/etc/acme"
CONFIG_FILE="$CONFIG_DIR/config.json"
PLUGINS_DIR="$CONFIG_DIR/plugins"
STATE_DIR="/var/lib/acme"
LOG_DIR="/var/log/acme"
WEB_DIR="/var/www/acme"
CERT_DIR="/etc/nginx/certs"
NGINX_CONF="/etc/nginx/conf.d/acme.conf"
UPGRADE_PATH_UNIT="/etc/systemd/system/acme-upgrade.path"
UPGRADE_SERVICE_UNIT="/etc/systemd/system/acme-upgrade.service"
WEB_PATH_UNIT="/etc/systemd/system/acme-web.path"
WEB_SERVICE_UNIT="/etc/systemd/system/acme-web.service"
UNIT_FILE="/etc/systemd/system/acme.service"
LOGROTATE_FILE="/etc/logrotate.d/acme"
# The Python acme is built on: 3.14 or newer (--python PATH decides otherwise).
PY_WANT="3.14"
# PHP-FPM for the pages: 8.3 or newer.
PHP_WANT="8.3"

DRY_RUN=""
ASSUME_YES=""
WITH_WEB="yes"
DO_UPGRADE=""
REWRITE_NGINX=""
DO_UNINSTALL=""
WITH_DB=""
NO_DB_RESTART=""
PY_FORCE=""
ACME_PY=""
DB_RESTART_AGAIN=""
PHP_UPDATE="yes"
PHP_STREAM="8.3"
USE_REMI=""

SERVER_NAME="acme.example.local"
ADMIN_ALLOW=""
PORTAL_ALLOW=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""
CERT_FILE=""
KEY_FILE=""
ISEMON_TARGET=""
ISEMON_HOSTNAME=""
SITE_NAME=""

# ---------------------------------------------------------------------------
# Saying things
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_HEAD=$'\033[1;36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
    C_BAD=$'\033[1;31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
    C_HEAD=""; C_OK=""; C_WARN=""; C_BAD=""; C_DIM=""; C_OFF=""
fi
step()  { printf '\n%s==> %s%s\n' "$C_HEAD" "$1" "$C_OFF"; }
say()   { printf '    %s\n' "$1"; }
note()  { printf '    %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }
good()  { printf '    %s%s%s\n' "$C_OK" "$1" "$C_OFF"; }
warn()  { printf '    %s%s%s\n' "$C_WARN" "$1" "$C_OFF"; }
fail()  { printf '\n%sERROR: %s%s\n' "$C_BAD" "$1" "$C_OFF" >&2; exit 1; }
# Whatever stops this script says what and where - never a silent end.
# shellcheck disable=SC2154
trap 'rc=$?; printf "\n%sERROR: line %s: \"%s\" ended with %s; nothing after it was done.%s\n" "${C_BAD:-}" "$LINENO" "$BASH_COMMAND" "$rc" "${C_OFF:-}" >&2; exit "$rc"' ERR

run() {
    if [[ -n "$DRY_RUN" ]]; then
        note "[would run] $*"
        return 0
    fi
    "$@"
}

write_file() {      # write_file DEST MODE < content
    local dest="$1" mode="${2:-0644}" body
    body="$(cat)"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would write] $dest (${#body} bytes, mode $mode)"
        return 0
    fi
    # Written beside it and renamed over it: a redirect follows a
    # link, and /etc/acme is the acme account's to change - a link put there
    # between the two steps made root write over any file it pointed to. A
    # rename replaces the name itself, whatever it was.
    # ...and written in a folder only root can enter: a file made
    # in /etc/acme itself could be swapped for a link by the acme account
    # between mktemp and the redirect. The folder is made beside the target
    # folder, so the rename stays on one file system.
    local dir tmpd
    dir="$(dirname -- "$dest")"
    # Made only when missing: install -d also set the mode of one
    # that was there - /etc/acme lost the acme group's write on every upgrade.
    [[ -d "$dir" ]] || install -d -m 0755 "$dir" 2>/dev/null || true
    tmpd="$(mktemp -d "$(dirname -- "$dir")/.acme-write.XXXXXX")" || fail "cannot write beside $dir"
    chmod 0700 "$tmpd"
    printf '%s\n' "$body" > "$tmpd/f"
    chmod "$mode" "$tmpd/f"
    mv -fT -- "$tmpd/f" "$dest"
    rmdir -- "$tmpd" 2>/dev/null || true
}

# A folder inside one the acme account owns: made and set by the acme
# account itself, never by root through a path acme could swap for a link -
# install -d as root follows a link and would hand its target to acme.
# The copies of nginx's file, out of conf.d where they piled up.
NGINX_BAK_DIR=/etc/nginx/acme-backups
nginx_backups_tidy() {
    [[ -n "$DRY_RUN" ]] && return 0
    mkdir -p "$NGINX_BAK_DIR"
    chmod 0750 "$NGINX_BAK_DIR"
    local f
    for f in /etc/nginx/conf.d/acme.conf.before-*; do
        [[ -f "$f" ]] && mv -f "$f" "$NGINX_BAK_DIR/"
    done
    # The last ten kept.
    ls -1t "$NGINX_BAK_DIR"/ 2>/dev/null | tail -n +11 | while read -r f; do
        rm -f "$NGINX_BAK_DIR/$f"
    done
    return 0
}

acme_subdir() {
    local d="$1"
    [[ -L "$d" ]] && fail "$d is a symbolic link, which it never should be here; look at it before running this again"
    if [[ -n "$DRY_RUN" ]]; then echo "  would make $d as $SERVICE_USER"; return 0; fi
    if [[ ! -e "$d" ]]; then
        runuser -u "$SERVICE_USER" -- mkdir -m 0750 "$d" \
            || fail "$d could not be made as $SERVICE_USER"
    elif [[ "$(stat -c %U "$d")" != "$SERVICE_USER" ]]; then
        chown -h "$SERVICE_USER:$SERVICE_USER" "$d"      # -h: a link is never followed
    fi
    runuser -u "$SERVICE_USER" -- chmod 0750 "$d" 2>/dev/null || true
}

not_a_link() {
    local one
    for one in "$@"; do
        [[ -L "$one" ]] && fail "$one is a symbolic link, which it never should be here; look at it before running this again"
    done
    return 0
}

cidr_list_ok() {
    python3 - "$1" <<'PY'
import ipaddress, sys
bad = []
for one in sys.argv[1].split(','):
    one = one.strip()
    if not one:
        continue
    try:
        ipaddress.ip_network(one, strict=False)
    except ValueError:
        bad.append(one)
if bad:
    sys.stderr.write('not an address or a network: %s\n' % ', '.join(bad))
    sys.exit(1)
PY
}

ask() {          # ask VAR "prompt" "default"
    local var="$1" prompt="$2" default="${3:-}" answer
    if [[ -n "$ASSUME_YES" ]]; then
        printf -v "$var" '%s' "${!var:-$default}"
        return
    fi
    if [[ -n "${!var:-}" ]]; then default="${!var}"; fi
    if [[ -n "$default" ]]; then
        read -r -p "    $prompt [$default]: " answer
    else
        read -r -p "    $prompt: " answer
    fi
    printf -v "$var" '%s' "${answer:-$default}"
}

ask_secret() {
    local var="$1" prompt="$2" answer again
    [[ -n "$ASSUME_YES" ]] && return
    while true; do
        read -r -s -p "    $prompt: " answer; echo
        [[ -z "$answer" ]] && { printf -v "$var" '%s' ''; return; }
        if (( ${#answer} < 8 )); then
            warn "that is shorter than eight characters"
            continue
        fi
        read -r -s -p "    and again: " again; echo
        [[ "$answer" == "$again" ]] && { printf -v "$var" '%s' "$answer"; return; }
        warn "those two are not the same"
    done
}

confirm() {      # confirm "question" [default y|n]
    local default="${2:-y}" answer
    [[ -n "$ASSUME_YES" ]] && [[ "$default" == "y" ]] && return 0
    [[ -n "$ASSUME_YES" ]] && return 1
    read -r -p "    $1 [$( [[ $default == y ]] && echo Y/n || echo y/N )] " answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

usage() {
    cat <<EOF
acme installer $VERSION — certificates kept, renewed and put in place by themselves

Usage: sudo ./install.sh [options]

  --server-name HOST        the pages' hostname (default $SERVER_NAME)
  --admin-allow CIDR[,..]   who may reach the administration pages (nginx allow)
  --portal-allow CIDR[,..]  who may reach the portal page at / (nginx allow)
                            (both default to the RFC 1918 networks)
  --admin-user NAME         the first account of the administration pages (admin)
  --admin-password PASS     its password (otherwise one is made and printed)
  --cert FILE --key FILE    the TLS certificate and key for nginx (until acme
                            issues its own: Settings -> TLS)
  --isemon HOST[:PORT][/tcp] send the logs to isemon's syslog receiver
  --isemon-hostname NAME    the host name isemon files them under (default: acme)
  --site-name NAME          what to call this installation on the pages
  --with-db ENGINE          the Python driver for mariadb, postgres or both
                            (the file on this machine needs none)

  PHP-FPM $PHP_WANT or newer runs the pages (php2shell, CVE-2026-109618 /
  CVE-2026-109619 - fixed 21 October 2026 in 8.3.36):
  --php-stream X.Y          the AppStream module stream to put PHP on (default 8.3)
  --remi                    take PHP 8.3 from Remi's repository instead
                            (offered by itself when AppStream has no fixed build)
  --no-php-update           leave PHP exactly as it is (it is still checked);
                            a PHP already installed and fixed is left as it is anyway

  --no-web                  the daemon only: no pages, no nginx, no PHP
  --python PATH             run acme on this Python rather than python$PY_WANT
                            (the only way to run it on an older one; at your risk)
  --no-db-restart           the pages may not restart a PostgreSQL on this machine
                            (remembered for every later upgrade)
  --db-restart              they may again, after --no-db-restart
  --upgrade                 replace the program and the pages, bring PHP up to the
                            fixed release, restart; keep everything else
  --rewrite-nginx           write the nginx file afresh even where one is there
                            (it is otherwise kept, and only brought up to date)
  --uninstall               remove the service and the pages; keep the database
                            (with --yes it still asks: removing is never a default)
  --dry-run                 print what would happen and change nothing
  --yes                     never ask; take the defaults
  --help                    this
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-name)     SERVER_NAME="$2"; shift 2;;
        --admin-allow)     ADMIN_ALLOW="$2"; shift 2;;
        --portal-allow)    PORTAL_ALLOW="$2"; shift 2;;
        --admin-user)      ADMIN_USER="$2"; shift 2;;
        --admin-password)  ADMIN_PASSWORD="$2"; shift 2;;
        --cert)            CERT_FILE="$2"; shift 2;;
        --key)             KEY_FILE="$2"; shift 2;;
        --isemon)          ISEMON_TARGET="$2"; shift 2;;
        --isemon-hostname) ISEMON_HOSTNAME="$2"; shift 2;;
        --site-name)       SITE_NAME="$2"; shift 2;;
        --with-db)         WITH_DB="$2"
                           case "$WITH_DB" in mariadb|mysql|postgres|postgresql|both) ;;
                               *) fail "--with-db takes mariadb, postgres or both";; esac
                           shift 2;;
        --php-stream)      PHP_STREAM="$2"; shift 2;;
        --remi)            USE_REMI="yes"; shift;;
        --no-php-update)   PHP_UPDATE=""; shift;;
        --no-web)          WITH_WEB=""; shift;;
        --no-db-restart)   NO_DB_RESTART="yes"; shift;;
        --python)          PY_FORCE="$2"; shift 2;;
        --db-restart)      DB_RESTART_AGAIN="yes"; shift;;
        --upgrade)         DO_UPGRADE="yes"; shift;;
        --rewrite-nginx)   REWRITE_NGINX="yes"; shift;;
        --uninstall)       DO_UNINSTALL="yes"; shift;;
        --dry-run)         DRY_RUN="yes"; shift;;
        -y|--yes)          ASSUME_YES="yes"; shift;;
        -h|--help)         usage; exit 0;;
        --radius-from|--import-legacy|--system-python)
            fail "$1 belonged to otp, the one-time password server acme was made from; acme has no such thing - try --help";;
        *) fail "I do not know the option $1 — try --help";;
    esac
done
if [[ -n "$PY_FORCE" && "$PY_FORCE" != /* ]]; then
    fail "--python takes the full path of a Python, such as /usr/bin/python3.14"
fi
# Checked on every path, the upgrade's too: --admin-allow all went through
# there and opened the administration pages to everybody.
for v in ADMIN_ALLOW PORTAL_ALLOW; do
    [[ -n "${!v}" ]] && { cidr_list_ok "${!v}" || fail "$v takes addresses and networks, comma separated"; }
done

[[ $EUID -eq 0 ]] || fail "run this as root: sudo ./install.sh"
# One of these at a time (1.0.44): a second run's tidying of versions/ took away the first
# one's half-copied tree, or its finished one just before the switch.
if [[ -z "$DRY_RUN" ]] && command -v flock >/dev/null 2>&1; then
    exec 9>/run/acme-install.lock
    flock -n 9 || fail "another install.sh is running (an upgrade from the pages, or one typed in): wait for it, then again"
fi
if [[ -n "$DO_UPGRADE" && -z "${ACME_UPGRADE_FROM_PAGES:-}" && -z "$DRY_RUN" ]] \
        && systemctl is-active --quiet acme-upgrade.service 2>/dev/null; then
    fail "an upgrade from the pages is running (acme-upgrade.service); wait for it, then again"
fi
for need in acme.py acmelib/__init__.py acmelib/engine/__init__.py web/index.php deploy/acme.service; do
    [[ -f "$SOURCE_DIR/$need" ]] || fail "$need is not beside this script; run it from inside the unpacked folder (acme-X.Y.Z/)"
done
DOWNGRADE_FLOOR_NEW="$(sed -n "s/^DOWNGRADE_FLOOR = '\([0-9.]*\)'.*/\1/p" "$SOURCE_DIR"/acmelib/engine/[0-9]*.py 2>/dev/null | head -n 1 || true)"

OS_PRETTY="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}" )"
OS_MAJOR="$( . /etc/os-release 2>/dev/null; v="${VERSION_ID:-}"; printf '%s' "${v%%.*}" )"   # none on Debian testing
OS_ID="$( . /etc/os-release 2>/dev/null; printf '%s' "${ID:-}" )"
case "$( . /etc/os-release 2>/dev/null; printf '%s%s' "${ID:-}" "${ID_LIKE:-}" )" in
    *rhel*|*fedora*|*centos*|*almalinux*|*rocky*) PKG="dnf";;
    *debian*|*ubuntu*) PKG="apt";;
    *) PKG="";;
esac

APT_UPDATED=""
apt_update_once() {
    [[ -n "$APT_UPDATED" ]] && return 0
    APT_UPDATED=yes
    run apt-get update -q >/dev/null 2>&1 || run apt-get update
}
# ---------------------------------------------------------------------------
# Taking it away
# ---------------------------------------------------------------------------
php_fpm_units() {
    # Not a masked one, and the ones switched on before others (1.0.80): every php*-fpm was
    # enabled and started - an old PHP switched off on purpose came back, a masked one warned.
    local found="" off="" unit state listed
    if systemctl cat php-fpm.service >/dev/null 2>&1 && \
            [[ "$(systemctl is-enabled php-fpm.service 2>/dev/null)" != masked* ]]; then
        found="php-fpm"
    fi
    listed="$(systemctl list-unit-files --no-legend 'php*-fpm.service' 2>/dev/null || true)"
    while read -r unit state _rest; do
        unit="${unit%.service}"
        [[ -n "$unit" && "$unit" != "php-fpm" && "$unit" =~ ^php[0-9.]*-fpm$ ]] || continue
        case "$state" in
            masked*) ;;
            enabled*|static*|alias*) found="$found $unit" ;;
            *) off="$off $unit" ;;
        esac
    done <<< "$listed"
    [[ -n "${found// /}" ]] || found="$off"
    # ...and always the one acme's pool goes into (its php-fpm: php-fpm8.3 -> php8.3-fpm),
    # whatever its state - left out, the pool was in a php-fpm never started (502)
    local bin mine
    bin="$(php_fpm_bin)"
    case "$(basename "${bin:-x}")" in
        php-fpm[0-9]*) mine="php$(basename "$bin" | sed 's/^php-fpm//')-fpm" ;;
        php-fpm) mine="php-fpm" ;;
        *) mine="" ;;
    esac
    if [[ -n "$mine" && " $found " != *" $mine "* ]] && \
            systemctl cat "$mine.service" >/dev/null 2>&1; then
        found="$found $mine"
    fi
    echo $found
}

if [[ -n "$DO_UNINSTALL" ]]; then
    step "Removing acme $VERSION"
    say "The database, the sealing key, the certificates it keeps, the configuration,"
    say "your own modules and the accounts are kept:  $STATE_DIR  and  $CONFIG_DIR"
    # Asked even with --yes, as --help says.
    if [[ -n "$ASSUME_YES" && ! -t 0 ]]; then
        fail "removing is never a default: run --uninstall on a terminal, it asks"
    fi
    ASSUME_YES="" confirm "Go ahead?" n || { say "Nothing was changed."; exit 0; }
    # An upgrade going on is not cut off under its own feet - looked at
    # before anything is stopped or taken away.
    if [[ -z "$DRY_RUN" ]] && systemctl is-active --quiet acme-upgrade.service 2>/dev/null; then
        fail "an upgrade from the pages is running (acme-upgrade.service); wait for it, then again"
    fi
    run systemctl disable --now acme.service 2>/dev/null || true
    run systemctl disable --now acme-upgrade.path 2>/dev/null || true
    run systemctl disable --now acme-web.path 2>/dev/null || true
    # keepalived only where the file is acme's own (the web address).
    if head -1 /etc/keepalived/keepalived.conf 2>/dev/null | grep -q '^# written by acme'; then
        run systemctl disable --now keepalived 2>/dev/null || true
        run rm -f /etc/keepalived/keepalived.conf
        say "keepalived stopped: its file was acme's (the web address)"
    fi
    # acme's drop-in for keepalived (started again when it dies), only if it is acme's.
    if head -1 /etc/systemd/system/keepalived.service.d/acme.conf 2>/dev/null | grep -q '^# written by acme'; then
        run rm -f /etc/systemd/system/keepalived.service.d/acme.conf
        run rmdir /etc/systemd/system/keepalived.service.d 2>/dev/null || true
        run systemctl daemon-reload 2>/dev/null || true
    fi
    [[ -e /etc/nginx/conf.d/acme_vip.conf ]] && run rm -f /etc/nginx/conf.d/acme_vip.conf
    [[ -e /usr/libexec/keepalived/acme-vip-check ]] && run rm -f /usr/libexec/keepalived/acme-vip-check
    for one in "$UNIT_FILE" "$LOGROTATE_FILE" "$NGINX_CONF" "$BIN_LINK" \
               "$UPGRADE_PATH_UNIT" "$UPGRADE_SERVICE_UNIT" "$WEB_PATH_UNIT" "$WEB_SERVICE_UNIT" \
               /etc/polkit-1/rules.d/49-acme-database.rules "$CONFIG_DIR/may-restart-database" \
               /etc/php-fpm.d/acme.conf /etc/php/*/fpm/pool.d/acme.conf /etc/profile.d/zz-acme-console.sh /etc/acme-console-login; do
        [[ -e "$one" ]] && run rm -f "$one"
    done
    # sshd's PAM no longer asking an acme that is gone: every password and code
    # over SSH was refused after it - keys alone went on working.
    if [[ -f "$SOURCE_DIR/deploy/acme_web.py" ]]; then
        run python3 -I "$SOURCE_DIR/deploy/acme_web.py" --pam-off || warn "sshd's PAM could not be put back: take acme's block out of /etc/pam.d/sshd by hand"
    fi
    # acme's SELinux module (as otp 1.0.233): its labels and rules gone with it. The mode SELinux is in,
    # its booleans and the ports labelled are the machine's, left as they are.
    if command -v semodule >/dev/null 2>&1 && semodule -l 2>/dev/null | awk '$1=="acme_server"{f=1} END{exit !f}'; then
        run semodule -r acme_server 2>/dev/null || warn "SELinux: semodule -r acme_server did not go"
    fi
    # Every tree, current and previous, and the links to them.
    [[ -e "$LIB_DIR" || -L "$LIB_DIR" ]] && run rm -rf "$LIB_DIR"
    [[ -d "$WEB_DIR" ]] && run rm -rf "$WEB_DIR"
    run systemctl daemon-reload
    for unit in $(php_fpm_units); do run systemctl try-restart "$unit" || true; done
    command -v nginx >/dev/null && run systemctl reload nginx 2>/dev/null || true
    good "Gone. $STATE_DIR and $CONFIG_DIR were left alone."
    say "To remove the rest:  rm -rf $STATE_DIR $CONFIG_DIR $LOG_DIR; userdel $SERVICE_USER; userdel $POOL_USER; groupdel $WEB_GROUP"
    # What it opened and made beside it, said rather than guessed at.
    [[ -e /etc/nginx/certs/acme.pem ]] && say "  its certificate:  rm -f /etc/nginx/certs/acme.pem /etc/nginx/certs/acme.key"
    if command -v firewall-cmd >/dev/null 2>&1; then
        say "  the firewall openings:  firewall-cmd --permanent --remove-service=http --remove-service=https; firewall-cmd --reload"
    fi
    say "  the DNS server's port 53, if Settings -> Firewall opened it: iptables -S | grep -w 53"
    exit 0
fi

# ---------------------------------------------------------------------------
# PHP, fixed against php2shell
# ---------------------------------------------------------------------------
# On 21 October 2026 PHP fixed two remote code execution flaws reached through
# how PHP takes a request apart before any page runs (CVE-2026-109618,
# CVE-2026-109619). Fixed upstream: 8.2.35, 8.3.36, 8.4.27, 8.5.12. The
# distributions rebuilt their streams the same day - AlmaLinux 9's php:8.3 is
# 8.3.36 and php:8.2 is 8.2.35; its default 8.0 has the fix backported and
# keeps its number - so the version alone does not always say it, and the
# package's changelog is read as well.
#
# What this does: puts PHP on the stream asked for (8.3 unless told), brings
# every PHP package up to the newest build, and checks the result by the
# version and by the CVE in the changelog. Where AppStream has no fixed build
# it offers Remi's PHP 8.3 (fixed in 8.3.36). acme's pages need PHP 8.3 or
# newer (EL9: the php:8.3 module stream or Remi; EL10 and Ubuntu 24.04 have
# 8.3 of their own; Debian 12 needs packages.sury.org). Either way the guard goes on:
# upload progress off for every PHP on the machine, acme's own pool taking no
# request body apart, and nginx refusing every multipart body.

php_fpm_bin() {         # the php-fpm that serves the pages: the newest one installed
    local b
    b="$(command -v php-fpm 2>/dev/null || true)"
    [[ -z "$b" && -x /usr/sbin/php-fpm ]] && b=/usr/sbin/php-fpm
    if [[ -z "$b" ]]; then
        b="$(ls -1 /usr/sbin/php-fpm[0-9]* 2>/dev/null | sort -V | tail -n 1 || true)"
    fi
    echo "$b"
}

php_fpm_version() {     # its version, 8.3.36 - from php-fpm itself, not from the
    local b v           # command-line php, which may be another one or missing (1.0.36)
    b="$(php_fpm_bin)"
    [[ -n "$b" ]] || { echo ""; return; }
    v="$("$b" -v 2>/dev/null | head -n 1 | awk '{print $2}')"
    echo "${v%%[-+~]*}"
}

ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]; }

php_fixed() {           # is the PHP that php-fpm runs fixed? 0 yes, 1 no
    local v b f log
    v="$(php_fpm_version)"
    [[ -n "$v" ]] || return 1
    b="$(echo "$v" | cut -d. -f1,2)"
    case "$b" in
        8.2) f=8.2.35 ;; 8.3) f=8.3.36 ;; 8.4) f=8.4.27 ;; 8.5) f=8.5.12 ;;
        *) if ver_ge "$b" 8.6; then return 0; fi; f="" ;;
    esac
    [[ -n "$f" ]] && ver_ge "$v" "$f" && return 0
    # A backport keeps the old number: the changelog says it instead. Read
    # whole first and searched after: `rpm | grep -q` under
    # pipefail failed when grep found it early and rpm died on the pipe.
    if [[ "$PKG" == "dnf" ]]; then
        log="$(rpm -q --changelog php-fpm php-common 2>/dev/null || true)"
        grep -q 'CVE-2026-109618' <<< "$log" && return 0
    elif [[ "$PKG" == "apt" ]]; then
        for log in /usr/share/doc/php*-fpm/changelog.Debian.gz /usr/share/doc/php*-common/changelog.Debian.gz; do
            [[ -f "$log" ]] || continue
            grep -q 'CVE-2026-109618' <<< "$(zcat "$log" 2>/dev/null || true)" && return 0
        done
    fi
    return 1
}

php_says() {
    local v
    v="$(php_fpm_version)"; v="${v:-?}"
    if php_fixed; then
        good "PHP $v has the php2shell fix (CVE-2026-109618, CVE-2026-109619)"
    else
        warn "PHP $v does NOT have the php2shell fix (CVE-2026-109618, CVE-2026-109619)"
    fi
}

php_guard() {           # the second layer, for every PHP on the machine
    local dir
    for dir in /etc/php.d /etc/php/*/fpm/conf.d /etc/php/*/cli/conf.d; do
        [[ -d "$dir" ]] || continue
        if [[ -f "$dir/99-php2shell.ini" ]] && grep -q 'upload_progress.enabled *= *0' "$dir/99-php2shell.ini"; then
            continue
        fi
        run install -m 0644 "$SOURCE_DIR/deploy/99-php2shell.ini" "$dir/99-php2shell.ini"
        PHP_RELOAD=yes
        good "$dir/99-php2shell.ini - session upload progress off, sessions strict"
    done
}

remi_php() {
    [[ "$PKG" == "dnf" ]] || { warn "Remi's repository is for the RHEL family only"; return 1; }
    local major="${OS_MAJOR:-9}"
    say "Remi's repository (rpms.remirepo.net), PHP 8.3"
    if ! rpm -q remi-release >/dev/null 2>&1; then
        run dnf install -y "https://rpms.remirepo.net/enterprise/remi-release-${major}.rpm" \
            || { warn "remi-release could not be installed (is rpms.remirepo.net reachable?)"; return 1; }
    fi
    if dnf module list php 2>/dev/null | grep -q 'remi-8.3'; then
        run dnf module reset -y php
        run dnf module enable -y php:remi-8.3
    else
        run dnf config-manager --set-enabled remi-modular 2>/dev/null || true
        run dnf module reset -y php || true
        run dnf module enable -y php:remi-8.3 || { warn "php:remi-8.3 could not be enabled"; return 1; }
    fi
    run dnf distro-sync -y 'php*'
    run dnf install -y php-fpm php-cli php-common
}

ensure_php() {
    step "PHP, and php2shell"
    if [[ -z "$PHP_UPDATE" ]]; then
        note "--no-php-update: PHP is left as it is"
        php_says
        php_guard
        return 0
    fi
    # PHP that is there and fixed is left exactly as it is: no
    # install, no stream switched, no restart. Updating it further is the
    # system's own business - dnf/apt upgrade - and any newer build or
    # stream is welcome; nothing here pins a version.
    local had_php=""
    if command -v php-fpm >/dev/null 2>&1 || ls /usr/sbin/php-fpm* >/dev/null 2>&1; then had_php=yes; fi
    if [[ -n "$had_php" && -z "$USE_REMI" ]] && php_fixed && ver_ge "$(php_fpm_version)" "$PHP_WANT"; then
        note "PHP is installed and fixed: left as it is (updates come with dnf/apt upgrade)"
        php_says
        php_guard
        return 0
    fi
    if [[ "$PKG" == "dnf" ]]; then
        if [[ -n "$USE_REMI" ]]; then
            remi_php || true
        elif [[ -n "$had_php" ]] && ! ver_ge "$(php_fpm_version)" "$PHP_WANT"; then
            # Older than 8.3: the stream is switched - every PHP site on the
            # machine with it - only when a person says so, never during an
            # upgrade from the pages.
            warn "PHP $(php_fpm_version) is here; acme's pages need $PHP_WANT or newer"
            if [[ -z "${ACME_UPGRADE_FROM_PAGES:-}" ]] && confirm "Switch PHP to the stream php:$PHP_STREAM (every PHP site on this machine moves with it)?" y; then
                run dnf module reset -y php || true
                run dnf module enable -y "php:$PHP_STREAM" || warn "php:$PHP_STREAM could not be enabled (--remi takes Remi's)"
                run dnf distro-sync -y 'php*' || true
                run dnf install -y php-fpm php-cli php-common || true
            fi
        elif [[ -n "$had_php" ]]; then
            # There, but not fixed: only the packages already installed are
            # brought up to date, on whatever stream they are on.
            say "PHP is installed but not fixed: updating the packages that are there"
            run dnf upgrade -y --refresh 'php*' || true
        else
            # Not there at all. A stream is chosen only where none is enabled
            # yet - an enabled one, older or newer, is never switched. On 10
            # PHP is one stream already. dnf exits 1 for "no enabled stream"
            # on a machine that never had PHP, so its output is taken first
            # and read afterwards (set -e, pipefail).
            local streams now
            streams="$(dnf -q module list php 2>/dev/null || true)"
            now="$(dnf -q module list --enabled php 2>/dev/null || true)"
            now="$(awk '/^php /{print $2; exit}' <<< "$now")"
            if [[ -z "$now" ]] && grep -qE "^php +${PHP_STREAM//./\\.}( |$)" <<< "$streams"; then
                say "PHP comes from the stream php:$PHP_STREAM"
                run dnf module enable -y "php:$PHP_STREAM"
            elif [[ -n "$now" ]]; then
                note "the PHP stream php:$now is enabled already: it is kept"
            fi
            run dnf install -y php-fpm php-cli php-common
        fi
    elif [[ "$PKG" == "apt" ]]; then
        if [[ -n "$had_php" ]] && ver_ge "$(php_fpm_version)" "$PHP_WANT"; then
            say "PHP is installed but not fixed: updating the packages that are there"
            apt_update_once
            local have
            have="$(dpkg-query -W -f='${Package} ${Status}\n' 'php*' 2>/dev/null | awk '/ installed$/{print $1}' | tr '\n' ' ' || true)"
            [[ -n "$have" ]] && { run apt-get install -y --only-upgrade $have || true; }
        else
            # php8.3-fpm by its own name where the distribution has it
            # (Ubuntu 24.04), else its default PHP - checked below.
            apt_update_once
            if apt-cache policy "php$PHP_WANT-fpm" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
                run apt-get install -y "php$PHP_WANT-fpm" "php$PHP_WANT-cli"
            else
                run apt-get install -y php-fpm php-cli
            fi
        fi
    else
        warn "this distribution is not one this knows: install php-fpm yourself, fixed against php2shell"
    fi
    [[ -n "$DRY_RUN" ]] && { php_guard; return 0; }
    if ! php_fixed && [[ "$PKG" == "dnf" && -z "$USE_REMI" ]]; then
        warn "the PHP AppStream has here is not fixed yet: $(php_fpm_version)"
        # Never on its own in an upgrade: it moves every PHP site on the
        # machine to Remi's PHP. Asked of a person, or --remi.
        if [[ -n "$DO_UPGRADE" || -n "${ACME_UPGRADE_FROM_PAGES:-}" ]]; then
            note "Remi's PHP 8.3 is not taken during an upgrade by itself: ./install.sh --upgrade --remi"
        elif confirm "Take PHP 8.3 from Remi's repository instead (fixed in 8.3.36)?" y; then
            remi_php || true
        fi
    fi
    php_says
    # PHP 8.3 at least: the pages are written for it.
    local pv
    pv="$(php_fpm_version)"
    if [[ -n "$pv" && -z "$DRY_RUN" ]] && ! ver_ge "$pv" "$PHP_WANT"; then
        fail "php-fpm here is $pv: acme's pages need PHP $PHP_WANT or newer (EL9: --php-stream 8.3 or --remi; Debian 12: packages.sury.org; Ubuntu 22.04: ppa:ondrej/php - or install with --no-web)"
    fi
    if ! php_fixed; then
        warn "Until it is fixed: dnf upgrade --refresh 'php*' (or apt upgrade) as soon as the"
        warn "fixed build is out, and ./install.sh --upgrade. acme's pages are guarded meanwhile:"
        warn "its pool takes no request body apart, upload progress is off everywhere, and nginx"
        warn "refuses every multipart body."
    fi
    php_guard
    # The new build only counts once php-fpm runs it.
    local unit
    for unit in $(php_fpm_units); do
        run systemctl enable "$unit" >/dev/null 2>&1 || true
        run systemctl restart "$unit" || warn "$unit would not restart"
    done
    if grep -lE ' /(usr|lib|acme).*\(deleted\)$' /proc/[0-9]*/maps 2>/dev/null | grep -q .; then
        note "some processes still run files an update replaced; they pick the new ones up when restarted"
    fi
}

# ---------------------------------------------------------------------------
# The pages: the pool, nginx, the certificate
# ---------------------------------------------------------------------------
allow_lines() {         # allow_lines "a,b" -> nginx allow lines, or the defaults
    local list="$1" out="" one
    if [[ -z "$list" ]]; then
        printf '        allow 192.168.0.0/16;\n        allow 172.16.0.0/12;\n        allow 10.0.0.0/8;'
        return
    fi
    IFS=',' read -r -a cidrs <<< "$list"
    for one in "${cidrs[@]}"; do
        one="$(echo "$one" | xargs)"
        [[ -n "$one" ]] && out+="        allow $one;"$'\n'
    done
    printf '%s' "${out%$'\n'}"
}

php_pool_dir() {
    if [[ -d /etc/php-fpm.d ]]; then echo /etc/php-fpm.d; return; fi
    # The pool folder of the php-fpm that is installed: the first
    # folder by name was a 7.4 left behind by a removed package, whose pool
    # nobody ran, and nginx answered 502.
    local b v d
    b="$(php_fpm_bin)"
    v="${b##*/php-fpm}"
    if [[ -n "$v" && -d "/etc/php/$v/fpm/pool.d" ]]; then echo "/etc/php/$v/fpm/pool.d"; return; fi
    for d in $(ls -1d /etc/php/*/fpm/pool.d 2>/dev/null | sort -V -r || true); do
        v="$(echo "$d" | cut -d/ -f4)"
        [[ -x "/usr/sbin/php-fpm$v" ]] && { echo "$d"; return; }
    done
    echo ""
}

install_pages() {
    step "The pages"
    # The tree's web/ whole (acme.php for HTTP-01, metrics.php and all),
    # made beside the one there and put in its place: never the pages of one
    # version beside another's.
    not_a_link "$WEB_DIR"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would copy] $SOURCE_DIR/web -> $WEB_DIR (made beside it, then put in its place)"
    else
        pages_from "$SOURCE_DIR/web"
        PAGES_SWITCHED=yes
    fi
    good "$WEB_DIR"
    install_pages_rest
}

# The pages of a tree put in place of those there (1.0.44: also the old tree's, an upgrade
# that failed after the switch going back).
pages_from() {
        local from="$1" wnew wold=""
        wnew="$(mktemp -d "$(dirname "$WEB_DIR")/.acme-web-new.XXXXXX")"
        tar -C "$from" --exclude='__pycache__' -cf - . | tar -C "$wnew" --no-same-owner -xf -
        chown -R root:root "$wnew"
        find "$wnew" -type d -exec chmod 0755 {} +
        find "$wnew" -type f -exec chmod 0644 {} +
        if [[ -d "$WEB_DIR" ]]; then
            wold="$(dirname "$WEB_DIR")/.acme-web-old.$$"
            mv -T "$WEB_DIR" "$wold"
        fi
        mv -T "$wnew" "$WEB_DIR"
        [[ -n "$wold" ]] && rm -rf "$wold"
        return 0
}

install_pages_rest() {

    # ---- the pool ------------------------------------------------------------
    local pool_dir sock owner
    pool_dir="$(php_pool_dir)"
    if [[ -z "$pool_dir" ]]; then
        warn "no php-fpm pool folder was found; the pages need php-fpm"
    else
        if [[ "$pool_dir" == /etc/php-fpm.d ]]; then
            sock=/run/php-fpm/acme.sock; owner=nginx
        else
            sock="/run/php/acme.sock"; owner=www-data
            id nginx >/dev/null 2>&1 && owner=nginx
        fi
        local pool_new pool_changed=yes
        pool_new="$(sed -e "s|^listen = .*|listen = $sock|" \
                -e "s|^listen.owner = .*|listen.owner = $owner|" \
                -e "s|^listen.group = .*|listen.group = $owner|" \
                "$SOURCE_DIR/deploy/php-fpm-acme.conf")"
        if [[ -f "$pool_dir/acme.conf" ]] && [[ "$(cat "$pool_dir/acme.conf")" == "$pool_new" ]]; then
            pool_changed=""
        fi
        if [[ -n "$DRY_RUN" ]]; then
            note "[would write] $pool_dir/acme.conf ($sock, for $owner)"
        elif [[ -n "$pool_changed" ]]; then
            # What was there kept beside it: a pool tuned by hand
            # (pm.max_children, timeouts) was lost without a trace.
            if [[ -f "$pool_dir/acme.conf" ]]; then
                cp -p "$pool_dir/acme.conf" "$pool_dir/acme.conf.before-$VERSION"
                note "the pool as it was is in $pool_dir/acme.conf.before-$VERSION - carry your own changes over"
            fi
            printf '%s\n' "$pool_new" > "$pool_dir/acme.conf"
            chmod 0644 "$pool_dir/acme.conf"
        fi
        good "$pool_dir/acme.conf - a pool of acme's own, as $POOL_USER, on $sock"
        # Reloaded only when the pool changed or its socket is missing
        #: every install restarted every php-fpm on the machine,
        # other sites' too.
        for unit in $(php_fpm_units); do
            run systemctl enable "$unit" >/dev/null 2>&1 || true
            if [[ -n "$pool_changed" || -n "${PHP_RELOAD:-}" || ! -S "$sock" ]] || ! systemctl is-active --quiet "$unit"; then
                if systemctl is-active --quiet "$unit"; then
                    run systemctl reload "$unit" || run systemctl restart "$unit" \
                        || warn "$unit would not reload - php-fpm -t says why"
                else
                    run systemctl restart "$unit" || warn "$unit would not start - php-fpm -t says why"
                fi
            fi
        done
    fi

    # ---- the certificate -------------------------------------------------------
    run install -d -m 0755 "$CERT_DIR"
    if [[ -n "$CERT_FILE" && -n "$KEY_FILE" ]]; then
        run install -m 0644 "$CERT_FILE" "$CERT_DIR/acme.pem"
        run install -m 0600 "$KEY_FILE" "$CERT_DIR/acme.key"
        good "your certificate is in $CERT_DIR"
    elif [[ -f "$CERT_DIR/acme.pem" && -f "$CERT_DIR/acme.key" ]]; then
        good "$CERT_DIR/acme.pem is already there"
    else
        warn "no certificate given - making one this machine signs itself"
        note "Browsers will complain about it. Replace $CERT_DIR/acme.pem and acme.key with a"
        note "real pair and reload nginx (or let acme issue one: Settings -> TLS): administrators sign in here."
        run openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
            -keyout "$CERT_DIR/acme.key" -out "$CERT_DIR/acme.pem" \
            -subj "/CN=$SERVER_NAME" -addext "subjectAltName=DNS:$SERVER_NAME" 2>/dev/null
        run chmod 0600 "$CERT_DIR/acme.key"
    fi

    # ---- nginx ---------------------------------------------------------------------
    # A file that is there is kept and brought up to date, upgrade or not
    #: installing again wrote it afresh, and its server name, its
    # allow lists and the trusted proxy went back to the defaults.
    if [[ -f "$NGINX_CONF" && -z "$REWRITE_NGINX" ]]; then
        good "$NGINX_CONF is already there and its allow lists are kept (--rewrite-nginx writes it afresh)"
        note "the one this version ships is $LIB_DIR/deploy/nginx-acme.conf, for comparing"
        # What later versions need of it, put in where it is missing - with a
        # copy kept and nginx asked before anything is reloaded: a database
        # put back from the page (1.0.10, the file as the body, up to 4 GB)
        # and the load balancer's health check.
        if [[ -z "$DRY_RUN" ]]; then
            # Copies kept out of conf.d, the last ten; a retry of
            # the same version keeps the first copy.
            nginx_backups_tidy
            NGINX_BAK="$NGINX_BAK_DIR/acme.conf.before-$VERSION"
            [[ -e "$NGINX_BAK" ]] && NGINX_BAK="$NGINX_BAK.$(date +%Y%m%d%H%M%S)"
            cp -a "$NGINX_CONF" "$NGINX_BAK"
            python3 - "$NGINX_CONF" <<'PY'
import re, sys
p = sys.argv[1]
text = open(p).read()
said = []
admin = 'fastcgi_param  SCRIPT_FILENAME $document_root/admin/index.php;'
if admin in text and 'client_max_body_size 4g' not in text:
    text = text.replace(admin, admin + """
        # Putting a copy of the database back: the file itself is the body.
        client_max_body_size 4g;
        client_body_timeout  900s;
        fastcgi_request_buffering off;""", 1)
    text = re.sub(r'(admin/index\.php;[\s\S]*?fastcgi_read_timeout )120s;', r'\g<1>900s;', text, count=1)
    said.append('a database file may be put back from the page')
# Signing in with Windows (1.0.99): a Kerberos ticket with a large PAC is more than 8 kB.
if 'large_client_header_buffers' not in text and 'client_max_body_size 8m;' in text:
    text = text.replace('client_max_body_size 8m;', 'client_max_body_size 8m;\n'
                        '    # A Kerberos ticket of a person in many AD groups is more than 8 kB (1.0.99).\n'
                        '    large_client_header_buffers 4 32k;', 1)
    said.append('room for a Kerberos ticket of a person in many groups (32 kB headers)')
if 'location = /healthz' not in text and 'location /assets/' in text:
    block = """    # The load balancer's question: does this node answer? (acme 1.0.13)
    location = /healthz {
        fastcgi_pass   %s;
        fastcgi_param  SCRIPT_FILENAME $document_root/healthz.php;
        fastcgi_param  HTTPS on;
        include        fastcgi_params;
        fastcgi_read_timeout 10s;
        access_log off;
    }

""" % (re.search(r'fastcgi_pass\s+([^;]+);', text).group(1))
    text = text.replace('    location /assets/', block + '    location /assets/', 1)
    said.append('GET /healthz for a load balancer')
# Prometheus asks /metrics of each node, with its token.
if 'location = /metrics' not in text and 'location /assets/' in text:
    zone = re.search(r'limit_req_zone\s+\$binary_remote_addr\s+zone=([A-Za-z0-9_]+):', text)
    block = """    # Prometheus' scrape of this node, with its token (acme 1.0.173)
    location = /metrics {
%s        fastcgi_pass   %s;
        fastcgi_param  SCRIPT_FILENAME $document_root/metrics.php;
        fastcgi_param  HTTPS on;
        include        fastcgi_params;
        fastcgi_read_timeout 15s;
        access_log off;
    }

""" % (('        limit_req zone=%s burst=10 nodelay;\n        limit_req_status 429;\n' % zone.group(1)) if zone else '',
       re.search(r'fastcgi_pass\s+([^;]+);', text).group(1))
    text = text.replace('    location /assets/', block + '    location /assets/', 1)
    said.append('GET /metrics for Prometheus')
# The CAs' HTTP-01 challenge on port 80, to acme.php: put in
# front of the redirect to HTTPS where it is missing.
if '/.well-known/acme-challenge/' not in text:
    m80 = re.search(r'(?m)^([ \t]*)location / \{\n\s*return 301 https://\$host\$request_uri;', text)
    sockm = re.search(r'fastcgi_pass\s+([^;]+);', text)
    if m80 and sockm:
        pad = m80.group(1)
        block = (pad + 'location ^~ /.well-known/acme-challenge/ {\n' +
                 pad + '    fastcgi_pass  %s;\n' % sockm.group(1) +
                 pad + '    fastcgi_param SCRIPT_FILENAME /var/www/acme/acme.php;\n' +
                 pad + '    include       fastcgi_params;\n' +
                 pad + '    fastcgi_read_timeout 10s;\n' + pad + '}\n')
        text = text[:m80.start()] + block + text[m80.start():]
        said.append('the CAs\' HTTP-01 challenges on port 80 go to acme.php')
# The CRLs and certificates of acme's own authorities at /pki/, on port 80
# (never sent to HTTPS) and 443, for everybody - to pki.php.
if 'location ^~ /pki/' not in text:
    sockm = re.search(r'fastcgi_pass\s+([^;]+);', text)
    zone = re.search(r'limit_req_zone\s+\$binary_remote_addr\s+zone=([A-Za-z0-9_]+):', text)
    def pki_block(pad, tls):
        lines = ['# The CRLs and certificates of acme\'s own authorities (docs/own-ca.md)',
                 '# PKI-BEGIN', 'location = /pki { return 301 /pki/; }', 'location ^~ /pki/ {']
        if zone:
            lines += ['    limit_req zone=%s burst=40 nodelay;' % zone.group(1),
                      '    limit_req_status 429;']
        lines += ['    fastcgi_pass  %s;' % sockm.group(1),
                  '    fastcgi_param SCRIPT_FILENAME /var/www/acme/pki.php;']
        if tls:
            lines.append('    fastcgi_param HTTPS on;')
        lines += ['    include       fastcgi_params;', '    fastcgi_read_timeout 15s;', '}',
                  '# PKI-END']
        return ''.join(pad + ln + '\n' for ln in lines)
    m80 = re.search(r'(?m)^([ \t]*)location / \{\n\s*return 301 https://\$host\$request_uri;', text)
    if m80 and sockm:
        text = text[:m80.start()] + pki_block(m80.group(1), False) + text[m80.start():]
    ma = re.search(r'(?m)^([ \t]*)location /assets/', text)
    if ma and sockm:
        text = text[:ma.start()] + pki_block(ma.group(1), True) + '\n' + text[ma.start():]
    if m80 or ma:
        said.append('/pki/ serves the CRLs of acme\'s own authorities (port 80 and 443)')
# The home screen's manifest of its own type (1.0.52), where mime.types has none for it.
if 'webmanifest' not in text:
    ma = re.search(r'(?m)^([ \t]*)location /assets/', text)
    if ma:
        pad = ma.group(1)
        text = text[:ma.start()] + ''.join(pad + ln + '\n' for ln in [
            'location ~ ^/assets/[a-z-]+\\.webmanifest$ {', '    default_type application/manifest+json;',
            '    expires 1d;', '    access_log off;', '    try_files $uri =404;', '}']) + text[ma.start():]
        said.append('the manifest of the home screen has its type')
# the health check rate-limited like everything else (the zone is
# whichever one the conf keeps for everybody; acme_all, as shipped).
# Looked for in the whole block: the access lists put in front of
# it by the pages (HEALTH-ALLOW) made it look missing, a second limit_req was
# added, nginx refused it - and every other addition of the upgrade with it.
m = re.search(r'(?m)^(\s*)location = /healthz \{\n', text)
hblock = re.search(r'(?ms)^\s*location = /healthz \{.*?^\s*\}', text)
zone = re.search(r'limit_req_zone\s+\$binary_remote_addr\s+zone=([A-Za-z0-9_]+):', text)
if m and zone and not (hblock and 'limit_req ' in hblock.group(0)):
    pad = m.group(1) + '    '
    text = text.replace(m.group(0), m.group(0) + pad + 'limit_req zone=%s burst=10 nodelay;\n' % zone.group(1)
                        + pad + 'limit_req_status 429;\n', 1)
    said.append('/healthz rate-limited')
# sign-in attempts counted on the whole query string, not $arg_api,
# which takes the first of two api= and decodes nothing.
old_map = re.search(r'map \$arg_api \$acme_login_key \{\n\s*"login"\s+\$binary_remote_addr;', text)
if old_map:
    text = text.replace(old_map.group(0),
                        'map $args $acme_login_key {\n    "~(^|&)api=login(&|$)"   $binary_remote_addr;', 1)
    said.append('the sign-in limit sees every spelling of api=login')
# no second Content-Security-Policy from nginx - the pages send their
# own, with a nonce, and a browser given two enforces both.
text, n = re.subn(r'(?m)^\s*add_header\s+Content-Security-Policy\s+"[^"]*"[^\n]*\n', '', text)
if n:
    said.append("the Content-Security-Policy is the pages' own only")
# the body taken whole by nginx before PHP is asked - handed on as it
# came, a few slow requests held every PHP worker, health check and all.
text, n = re.subn(r'(?m)^(\s*)fastcgi_request_buffering\s+off;', r'\1fastcgi_request_buffering on;', text)
if n:
    text = re.sub(r'(?m)^(\s*)client_body_timeout\s+900s;', r'\1client_body_timeout  60s;', text)
    said.append('nginx takes a body whole before PHP sees it')
open(p, 'w').write(text)
print('; '.join(said))
PY
            if nginx -t >/dev/null 2>&1; then
                good "$NGINX_CONF brought up to this version (its copy: $NGINX_BAK)"
            else
                cp -a "$NGINX_BAK" "$NGINX_CONF"
                warn "nginx did not take the additions, so $NGINX_CONF is as it was"
            fi
        fi
        if ! grep -qiE 'content_type[^;]*multipart' "$NGINX_CONF"; then
            warn "$NGINX_CONF does not refuse multipart bodies (php2shell); add inside server { }:"
            warn '  if ($http_content_type ~* "multipart") { return 403; }'
        fi
    elif [[ -n "$DRY_RUN" ]]; then
        note "[would write] $NGINX_CONF for $SERVER_NAME"
    else
        nginx_backups_tidy
        [[ -f "$NGINX_CONF" ]] && cp -a "$NGINX_CONF" "$NGINX_BAK_DIR/acme.conf.before-$VERSION.$(date +%Y%m%d%H%M%S)"
        python3 - "$SOURCE_DIR/deploy/nginx-acme.conf" "$NGINX_CONF" "$SERVER_NAME" \
                  "$(allow_lines "$ADMIN_ALLOW")" "$(allow_lines "$PORTAL_ALLOW")" "${sock:-}" <<'PY'
import re, sys
src, dst, host, admin, portal, sock = sys.argv[1:7]
text = open(src).read().replace('acme.example.local', host)
if sock:
    text = text.replace('unix:/run/php-fpm/acme.sock;', 'unix:%s;' % sock)
for mark, lines in (('ADMIN', admin), ('PORTAL', portal)):
    text, n = re.subn(r'(# %s-ALLOW-BEGIN\n).*?(\n\s*# %s-ALLOW-END)' % (mark, mark),
                      lambda m: m.group(1) + lines + m.group(2), text, flags=re.S)
    if n != 1:
        sys.exit('the %s allow lines were not where they were expected' % mark)
import os
if not os.path.exists('/proc/net/if_inet6'):
    # No IPv6 on this machine (switched off in the kernel): nginx refuses to
    # start on a [::] listen line, so the IPv6 ones are left out.
    text = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', text)
open(dst, 'w').write(text)
PY
        good "$NGINX_CONF for $SERVER_NAME"
    fi
    if command -v nginx >/dev/null; then
        if [[ -z "$DRY_RUN" ]] && ! nginx -t >/dev/null 2>&1; then
            nginx -t || true
            fail "nginx does not read its configuration; sort that out and run this again"
        fi
        run systemctl enable nginx >/dev/null 2>&1 || true
        run systemctl restart nginx
    fi

    nginx_upload_guard

    # ---- SELinux ---------------------------------------------------------------
    selinux_module
    if command -v getenforce >/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        say "SELinux is $(getenforce)"
        run setsebool -P httpd_can_network_connect 1 2>/dev/null || warn "could not set httpd_can_network_connect"
        command -v restorecon >/dev/null && run restorecon -R "$WEB_DIR" 2>/dev/null || true
        good "the pages may talk to the daemon on 127.0.0.1"
        note "If the pages cannot reach the daemon: ausearch -m avc -ts recent | audit2allow -M acme-local"
    fi
}

# acme's SELinux module (as otp 1.0.233): /run/acme as the web server's own run files, so the
# pages may read the API token under enforcing, and two narrow rules (systemd in /run/acme;
# 1.0.59: PostgreSQL reading /etc/pki for the encrypted link between the nodes). Kept beside the
# program always; put into the policy where SELinux is on, and only when it changed (semodule
# takes its time) - on a node without the pages (--no-web) too (1.0.59, as otp 1.0.265): the
# PostgreSQL rule is needed there as well. Where SELinux is disabled nothing is done: "Make it
# ready" on the pages puts it in.
# The tools SELinux is looked after with (as otp 1.0.236), where the system has them in its own
# repositories (RHEL, Rocky, AlmaLinux): put in when missing, at every install and upgrade, with
# SELinux disabled too - "Make it ready" and acme --selinux-check need them; the mode is not
# touched. auditd started where SELinux is on (without it nothing refused is written down).
# Offline: said, not fatal.
selinux_tools() {
    [[ "${PKG:-}" == "dnf" ]] || return 0
    [[ -d /etc/selinux || -x /usr/sbin/getenforce ]] || return 0
    local want=() p
    for p in policycoreutils libselinux-utils policycoreutils-python-utils audit selinux-policy-targeted; do
        rpm -q "$p" >/dev/null 2>&1 || want+=("$p")
    done
    if (( ${#want[@]} )); then
        if run dnf install -y "${want[@]}" >/dev/null 2>&1; then
            good "SELinux: put in ${want[*]}"
        else
            warn "SELinux: ${want[*]} could not be put in (no repository reached?) - dnf install -y ${want[*]}"
        fi
    fi
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]] &&
            command -v auditd >/dev/null 2>&1 && ! systemctl is-active --quiet auditd 2>/dev/null; then
        # auditd refuses to be started by systemctl on some releases: service(8) then.
        { run systemctl enable --now auditd >/dev/null 2>&1 || run service auditd start >/dev/null 2>&1; } &&
            good "SELinux: auditd started - what SELinux refuses is written down" ||
            warn "SELinux: auditd could not be started - systemctl enable --now auditd"
    fi
    return 0
}

selinux_module() {
    selinux_tools
    [[ -f "$SOURCE_DIR/deploy/acme_server.cil" ]] || return 0
    local had=""
    # Compared with the one last put into the policy (as otp 1.0.234), not with the copy beside
    # the program: a semodule that failed once left the copy new and the policy old for good.
    cmp -s "$SOURCE_DIR/deploy/acme_server.cil" "$LIB_DIR/acme_server.cil.in-policy" 2>/dev/null && had=1
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme_server.cil" "$LIB_DIR/acme_server.cil"
    command -v getenforce >/dev/null 2>&1 || return 0
    command -v semodule >/dev/null 2>&1 || return 0
    [[ "$(getenforce)" == "Disabled" ]] && return 0
    if [[ -z "$had" ]] || ! semodule -l 2>/dev/null | awk '$1=="acme_server"{f=1} END{exit !f}'; then
        if run semodule -i "$LIB_DIR/acme_server.cil" 2>/dev/null; then
            run install -m 0644 "$LIB_DIR/acme_server.cil" "$LIB_DIR/acme_server.cil.in-policy"
            good "SELinux: acme's module (acme_server) is in the policy"
        else
            warn "SELinux: acme's module could not be put in: semodule -i $LIB_DIR/acme_server.cil"
        fi
    fi
    [[ -d /run/acme ]] && command -v restorecon >/dev/null 2>&1 && run restorecon -R /run/acme 2>/dev/null || true
    # Upgraded from a version before 1.0.44 (1.0.59, as otp 1.0.249): when acme's needs were last
    # put in is kept in root's folder now, the one in acme's own is not read - said, so that
    # refusals put right long ago, shown again, are not taken for new ones. Once, at the upgrade
    # that lost it - with the machine's start then noted, after which what is counted is new.
    if [[ -f "$STATE_DIR/web/selinux-applied" && ! -f /var/lib/acme-net/selinux-applied &&
          ! -f /var/lib/acme-net/selinux-upgrade-boot && -z "$DRY_RUN" ]]; then
        install -d -m 0700 /var/lib/acme-net 2>/dev/null || true
        cat /proc/sys/kernel/random/boot_id > /var/lib/acme-net/selinux-upgrade-boot 2>/dev/null || true
        chmod 0600 /var/lib/acme-net/selinux-upgrade-boot 2>/dev/null || true
        warn "SELinux: Security check counts again what SELinux refused since the machine started -"
        warn "  also what was put right before this upgrade (when acme's needs were put in is kept in"
        warn "  root's folder now; the old note is not read). Not new refusals: they go at the next"
        warn "  restart of the machine, or when \"Put in what acme needs\" changes something."
    fi
    # Said when the policy does not label it (as otp 1.0.234): the pages could not read the API
    # token under enforcing - Settings - High security - SELinux says what else is missing.
    if command -v matchpathcon >/dev/null 2>&1 && [[ -z "$DRY_RUN" ]]; then
        local want=""
        want="$(matchpathcon /run/acme 2>/dev/null || true)"
        case "$want" in
            *httpd_var_run_t*|*httpd_runtime_t*) ;;
            *) warn "SELinux: the policy does not label /run/acme for the pages (${want:-nothing}) - acme --selinux-check";;
        esac
    fi
}

# ---------------------------------------------------------------------------
# The program: Python, the tree, the account's folders, the units
# ---------------------------------------------------------------------------
# acme is built on Python 3.14 (or newer). From the distribution where it has
# one - python3.14 in AppStream on EL10 (and EL9 where it is there), the
# distribution's own python3 where that is 3.14 already (Debian 14, Ubuntu
# 26.04) - and on Ubuntu from the deadsnakes PPA otherwise. Nothing older is
# taken by itself: without a 3.14 this stops and says how to get one, unless
# --python PATH says which to use. The choice is $LIB_DIR/python, which the
# service and the acme command start; the root helpers (acme_upgrade.py,
# acme_web.py) use only the standard library and stay on the system's python3.
#
# The database drivers (psycopg2, PyMySQL) for that Python: the distribution's
# packages for it where there are any (python3.14-psycopg2 on EL), else a
# virtual environment of acme's own, $LIB_DIR/venv, that sees the system's
# packages and has the driver from PyPI (psycopg2-binary, PyMySQL).
py_mods_wanted() {
    local inuse=""
    inuse="$(python3 -c 'import json,os,stat,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); assert stat.S_ISREG(os.fstat(fd).st_mode); print(json.loads(os.read(fd, 4<<20) or b"{}").get("db_engine") or "")' \
             "$CONFIG_DIR/config.json" 2>/dev/null || true)"
    case "$inuse $WITH_DB" in *postgres*|*both*) echo psycopg2;; esac
    case "$inuse $WITH_DB" in *mariadb*|*mysql*|*both*) echo pymysql;; esac
}
py_new_enough() {        # py_new_enough PYTHON -> 0 when it is 3.14 or newer
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 14) else 1)' 2>/dev/null
}
py_runs_acme() {         # py_runs_acme PYTHON MODULE... -> 0 when it can run acme
    local py="$1"; shift
    [[ -x "$py" ]] || return 1
    "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || return 1
    "$py" -c 'import ssl, sqlite3, hashlib, json, zipfile, venv; hashlib.scrypt' 2>/dev/null \
        || "$py" -c 'import ssl, sqlite3, hashlib, json, zipfile; hashlib.scrypt' 2>/dev/null || return 1
    local m
    for m in "$@"; do "$py" -c "import $m" 2>/dev/null || return 1; done
    ( cd / && "$py" -I "$SOURCE_DIR/acme.py" --version >/dev/null 2>&1 )
}
py_found() {             # the first Python 3.14+ of the distribution's, or nothing
    local py
    for py in /usr/bin/python3.16 /usr/bin/python3.15 /usr/bin/python3.14 /usr/bin/python3; do
        [[ -x "$py" ]] && py_new_enough "$py" && { echo "$py"; return 0; }
    done
    return 0
}
py_install() {           # puts python3.14 on the machine, from where the distribution has it
    if [[ "$PKG" == "dnf" ]]; then
        if [[ -n "$DRY_RUN" ]]; then note "[would run] dnf install -y python$PY_WANT"; return 0; fi
        say "python$PY_WANT from the distribution (AppStream)"
        dnf install -y "python$PY_WANT" >/dev/null 2>&1 || true
    elif [[ "$PKG" == "apt" ]]; then
        apt_update_once
        local cand
        cand="$(apt-cache policy "python$PY_WANT" 2>/dev/null | awk '/Candidate:/{print $2; exit}' || true)"
        if [[ -z "$cand" || "$cand" == "(none)" ]] && [[ "$OS_ID" == "ubuntu" ]]; then
            say "Ubuntu has no python$PY_WANT of its own here: the deadsnakes PPA (ppa:deadsnakes/ppa)"
            if [[ -n "$DRY_RUN" ]]; then
                note "[would run] apt-get install -y software-properties-common; add-apt-repository -y ppa:deadsnakes/ppa"
            else
                command -v add-apt-repository >/dev/null 2>&1 \
                    || apt-get install -y software-properties-common >/dev/null 2>&1 || true
                add-apt-repository -y ppa:deadsnakes/ppa >/dev/null 2>&1 \
                    || warn "the deadsnakes PPA could not be added (is launchpad.net reachable?)"
                APT_UPDATED=""; apt_update_once
            fi
            cand="ppa"
        fi
        if [[ -n "$cand" && "$cand" != "(none)" ]]; then
            if [[ -n "$DRY_RUN" ]]; then note "[would run] apt-get install -y python$PY_WANT python$PY_WANT-venv"; return 0; fi
            apt-get install -y "python$PY_WANT" "python$PY_WANT-venv" >/dev/null 2>&1 \
                || apt-get install -y "python$PY_WANT" >/dev/null 2>&1 || true
        fi
    fi
    return 0
}
py_driver_pkgs() {       # py_driver_pkgs PYTHON MODULE: the distribution's driver for that Python
    local py="$1" mod="$2" v name
    v="$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    case "$mod" in psycopg2) name=psycopg2;; pymysql) name=PyMySQL;; *) return 0;; esac
    if [[ "$PKG" == "dnf" ]]; then
        if [[ "$py" == /usr/bin/python3 ]]; then run dnf install -y "python3-$name" >/dev/null 2>&1 || true
        else run dnf install -y "python$v-$name" >/dev/null 2>&1 || true; fi
    elif [[ "$PKG" == "apt" ]]; then
        # Debian's python3-* packages are for its own python3 only.
        local sys_v
        sys_v="$(/usr/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
        if [[ "$v" == "$sys_v" ]]; then apt_update_once; run apt-get install -y "python3-${name,,}" >/dev/null 2>&1 || true; fi
    fi
    return 0
}
py_venv_drivers() {      # py_venv_drivers PYTHON MODULE...: $LIB_DIR/venv with the drivers from PyPI
    local py="$1"; shift
    local venv="$LIB_DIR/venv" pips=() m
    for m in "$@"; do case "$m" in psycopg2) pips+=(psycopg2-binary);; pymysql) pips+=(PyMySQL);; esac; done
    ((${#pips[@]})) || return 0
    # The one made before, on this Python and with these drivers, is used as it is.
    if [[ -x "$venv/bin/python" && "$(readlink -f "$venv/bin/python")" == "$(readlink -f "$py")" ]]; then
        local all=yes
        for m in "$@"; do "$venv/bin/python" -c "import $m" 2>/dev/null || all=""; done
        [[ -n "$all" ]] && { note "$venv has ${pips[*]} already"; return 0; }
    fi
    if [[ -n "$DRY_RUN" ]]; then note "[would make] $venv on $py, with ${pips[*]} from PyPI"; return 0; fi
    say "the distribution has no ${pips[*]} for $("$py" --version 2>&1): $venv, with them from PyPI"
    if [[ ! -x "$venv/bin/python" ]] || [[ "$(readlink -f "$venv/bin/python")" != "$(readlink -f "$py")" ]]; then
        rm -rf "$venv"
        "$py" -m venv --system-site-packages "$venv" >/dev/null 2>&1 \
            || { [[ "$PKG" == "apt" ]] && apt-get install -y "python$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])')-venv" >/dev/null 2>&1 \
                 && "$py" -m venv --system-site-packages "$venv" >/dev/null 2>&1; } \
            || { warn "$venv could not be made ($py -m venv)"; rm -rf "$venv"; return 1; }
    fi
    "$venv/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade "${pips[@]}" >/dev/null 2>&1 \
        || { warn "pip could not install ${pips[*]} into $venv (is pypi.org reachable?)"; return 1; }
    chown -R root:root "$venv"; chmod -R go-w "$venv"
    return 0
}
runtime_python() {
    step "Python"
    local mods=() cand=() py m kept="$LIB_DIR/python-choice"
    mapfile -t mods < <(py_mods_wanted)
    # The choice of --python kept for the next upgrade: the pages' upgrade and
    # a plain --upgrade took the newest Python again.
    if [[ -n "$PY_FORCE" ]]; then
        [[ -z "$DRY_RUN" ]] && { install -d -m 0755 "$LIB_DIR"; printf '%s\n' "$PY_FORCE" > "$kept"; }
        cand=("$PY_FORCE")
    elif [[ -f "$kept" && ! -L "$kept" ]]; then
        local was=""
        was="$(head -n1 "$kept" 2>/dev/null || true)"
        if [[ "$was" == /* && -x "$was" ]]; then
            PY_FORCE="$was"; cand=("$was")
            note "the Python chosen before with --python is kept: $was (--python PATH to change it)"
        fi
    fi
    if [[ ${#cand[@]} -eq 0 ]]; then
        py="$(py_found)"
        if [[ -z "$py" ]]; then
            note "no Python $PY_WANT or newer here yet"
            py_install
            py="$(py_found)"
        fi
        if [[ -z "$py" && -n "$DRY_RUN" ]]; then
            note "[would use] /usr/bin/python$PY_WANT once it is installed${mods[*]:+ (with ${mods[*]})}"
            ACME_PY="/usr/bin/python$PY_WANT"
            return 0
        fi
        [[ -n "$py" ]] || fail "acme needs Python $PY_WANT or newer, and none was found or could be installed here.
    EL9/EL10:      dnf install python$PY_WANT   (AppStream; on EL9 once Red Hat ships it)
    Ubuntu:        add-apt-repository ppa:deadsnakes/ppa && apt-get install python$PY_WANT python$PY_WANT-venv
    Debian:        a release whose python3 is $PY_WANT or newer
    Or say which Python to run it on (at your own risk if it is older):  --python /path/to/python3"
        cand=("$py")
    fi
    py="${cand[0]}"
    [[ -x "$py" ]] || fail "--python $py: there is no such program"
    if ! py_new_enough "$py"; then
        [[ -n "$PY_FORCE" ]] || fail "$py is $("$py" --version 2>&1), older than $PY_WANT"
        warn "$py is $("$py" --version 2>&1): acme is built and tested on $PY_WANT and newer - taken because --python said so"
    fi
    # The drivers: the distribution's for this Python, else acme's own venv.
    local missing=() use="$py"
    for m in "${mods[@]}"; do
        "$py" -c "import $m" 2>/dev/null && continue
        py_driver_pkgs "$py" "$m"
        "$py" -c "import $m" 2>/dev/null || missing+=("$m")
    done
    if ((${#missing[@]})); then
        if [[ -n "$DRY_RUN" ]]; then
            py_venv_drivers "$py" "${missing[@]}"
        elif py_venv_drivers "$py" "${missing[@]}"; then
            use="$LIB_DIR/venv/bin/python"
        fi
    fi
    if [[ -z "$DRY_RUN" ]] && ! py_runs_acme "$use" "${mods[@]}"; then
        fail "$use ($("$use" --version 2>&1)) cannot run acme here${mods[*]:+ (with ${mods[*]})} - $use -I $SOURCE_DIR/acme.py --version says why"
    fi
    ACME_PY="$use"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would link] $LIB_DIR/python -> $ACME_PY"
    else
        install -d -m 0755 -o root -g root "$LIB_DIR"
        rm -f "$LIB_DIR/.python.$$"
        if [[ "$ACME_PY" == "$LIB_DIR/venv/bin/python" ]]; then
            # A venv is found from the path it is started by: a link to its
            # python from elsewhere would start the bare interpreter.
            printf '#!/bin/sh\n# acme runs on its own venv (install.sh): %s\nexec %s "$@"\n' \
                "$LIB_DIR/venv" "$LIB_DIR/venv/bin/python" > "$LIB_DIR/.python.$$"
            chmod 0755 "$LIB_DIR/.python.$$"
        else
            ln -s "$ACME_PY" "$LIB_DIR/.python.$$"
        fi
        mv -Tf "$LIB_DIR/.python.$$" "$LIB_DIR/python"
    fi
    good "acme runs on $("$ACME_PY" --version 2>&1 || echo "Python $PY_WANT") - $ACME_PY${mods[*]:+ (with ${mods[*]})}"
}

# ---- the tree ----------------------------------------------------------------------
# /usr/local/lib/acme/
#     versions/X.Y.Z-STAMP/   one tree each: acme.py, acmelib/, web/, deploy/, docs/,
#                             install.sh, MANIFEST - root's, compiled
#     current  -> versions/…  the one that runs: switched in one rename(2)
#     previous -> versions/…  the one before, kept for going back
#                             (acme_upgrade.py --previous)
#     acme.py, acme_upgrade.py, acme_web.py, acme-vip-check, deploy, docs,
#     CHANGELOG.md, …         links into current/, so every path that named
#                             them stays right
#     python, python-choice, db-drivers, venv/, release-keys/, downgrade-floor
#                             the machine's own, kept across versions
NEW_TREE=""
tree_copy_excludes=(--exclude=./.git --exclude=./.github --exclude=./.claude --exclude=./release
                    --exclude=./build --exclude=./dist --exclude=./.venv --exclude=./venv
                    --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo'
                    --exclude='.pytest_cache' --exclude='.mypy_cache' --exclude='.ruff_cache')
swap_link() {            # swap_link LINK TARGET: the link made new beside it, renamed over it
    local link="$1" target="$2"
    [[ "$(readlink "$link" 2>/dev/null || true)" == "$target" ]] && return 0
    [[ -e "$link" && ! -L "$link" ]] && fail "$link is there and is not a link - look at it before running this again"
    rm -f "$link.new.$$"
    ln -s "$target" "$link.new.$$"
    mv -Tf "$link.new.$$" "$link"
}
flat_layout_aside() {    # a program put in as files straight into $LIB_DIR: made a tree of its own
    [[ -f "$LIB_DIR/acme.py" && ! -L "$LIB_DIR/acme.py" ]] || return 0
    local was dest one
    was="$(sed -n "s/^__version__ = [\"']\([^\"']*\)[\"'].*/\1/p" "$LIB_DIR/acmelib/__init__.py" "$LIB_DIR/acme.py" 2>/dev/null | head -n1 || true)"
    dest="$TREES_DIR/${was:-0.0.0}-flat"
    mkdir -p "$dest"; chmod 0755 "$dest"
    for one in acme.py acmelib web deploy docs test tools acme_upgrade.py acme_web.py acme-vip-check \
               install.sh INSTALL.md README.md CHANGELOG.md LICENSE.md MANIFEST MANIFEST.sig nginx-acme.conf; do
        [[ -e "$LIB_DIR/$one" && ! -L "$LIB_DIR/$one" ]] && mv "$LIB_DIR/$one" "$dest/"
    done
    swap_link "$LIB_DIR/previous" "versions/$(basename "$dest")"
    note "the program that was in $LIB_DIR itself is now $dest (kept as previous)"
}
install_tree() {
    local stamp src_real trees_real old cur prev one
    stamp="$(date -u +%Y%m%d%H%M%S)"
    src_real="$(readlink -f "$SOURCE_DIR")"
    trees_real="$(readlink -f "$TREES_DIR" 2>/dev/null || echo "$TREES_DIR")"
    if [[ "$(dirname "$src_real")" == "$trees_real" ]]; then
        # Run from one of the trees kept here (going back to previous): that
        # tree itself becomes current again - nothing is copied.
        NEW_TREE="$src_real"
        note "$NEW_TREE is one of the trees kept here: it becomes the current one again"
    else
        NEW_TREE="$TREES_DIR/$VERSION-$stamp"
    fi
    if [[ -n "$DRY_RUN" ]]; then
        note "[would copy] $SOURCE_DIR -> $NEW_TREE (acme.py, acmelib/, web/, deploy/, docs/, install.sh, MANIFEST)"
        note "[would compile] $NEW_TREE with $ACME_PY -m compileall"
        note "[would switch] $LIB_DIR/current -> versions/$(basename "$NEW_TREE"); the tree before becomes previous"
        return 0
    fi
    [[ -L "$LIB_DIR" ]] && fail "$LIB_DIR is a link - look at it before running this again"
    install -d -m 0755 -o root -g root "$LIB_DIR"
    not_a_link "$TREES_DIR"
    install -d -m 0755 -o root -g root "$TREES_DIR"
    flat_layout_aside
    if [[ "$NEW_TREE" != "$src_real" ]]; then
        # Made under a name of its own, and only once whole renamed to the
        # name it keeps: what was cut off half way is a .new- folder, never a tree.
        local tmp="$TREES_DIR/.new-$VERSION-$stamp.$$"
        rm -rf "$tmp"
        mkdir -m 0700 "$tmp"
        tar -C "$SOURCE_DIR" "${tree_copy_excludes[@]}" -cf - . | tar -C "$tmp" --no-same-owner -xf -
        # root's helpers beside acme.py, where the engine and systemd look for them.
        for one in acme_upgrade.py acme_web.py acme-vip-check; do
            [[ -f "$tmp/deploy/$one" ]] && install -m 0755 "$tmp/deploy/$one" "$tmp/$one"
        done
        chown -R root:root "$tmp"
        chmod -R u+rwX,go+rX,go-w "$tmp"
        mv -T "$tmp" "$NEW_TREE"
    fi
    # Compiled where it stays, so tracebacks name the real files; the acme
    # account cannot write here and would compile it on every start.
    "$ACME_PY" -I -m compileall -q -j 0 -x '/(test|tools)/' "$NEW_TREE" >/dev/null 2>&1 \
        || "$ACME_PY" -I -m compileall -q "$NEW_TREE" >/dev/null 2>&1 \
        || warn "$NEW_TREE could not all be compiled: it runs, compiling as it goes"
    chmod -R go-w "$NEW_TREE"
    # The switch: one rename. What ran before is previous.
    cur="$(readlink -e "$LIB_DIR/current" 2>/dev/null || true)"
    # What to go back to, should the new one not run (1.0.44).
    ROLLBACK_TREE="$cur"
    [[ "$cur" == "$NEW_TREE" ]] && ROLLBACK_TREE=""
    rm -f -- "$NEW_TREE/.failed"
    # previous as it was, for a rescue to put back (1.0.52)
    PREV_LINK_BEFORE="$(readlink "$LIB_DIR/previous" 2>/dev/null || true)"
    swap_link "$LIB_DIR/current" "versions/$(basename "$NEW_TREE")"
    TREE_SWITCHED=yes
    # A tree that failed to run is never previous (1.0.44): a second try after a failed
    # one made the failed tree previous, and deleted the last one that ran.
    if [[ -n "$cur" && -d "$cur" && "$cur" != "$NEW_TREE" && ! -e "$cur/.failed" ]]; then
        swap_link "$LIB_DIR/previous" "versions/$(basename "$cur")"
    fi
    for one in acme.py acme_upgrade.py acme_web.py acme-vip-check deploy docs \
               CHANGELOG.md README.md INSTALL.md LICENSE.md; do
        swap_link "$LIB_DIR/$one" "current/$one"
    done
    # Only current and previous are kept - an upgrade's old trees only once it has run
    # (1.0.52): taken away at the switch, a failed upgrade's rescue left previous == current
    # and the version before that gone.
    [[ "${UPGRADE_STAGE:-}" == started ]] || trees_prune
    prev="$(readlink -e "$LIB_DIR/previous" 2>/dev/null || true)"
    good "$LIB_DIR/current -> versions/$(basename "$NEW_TREE")${prev:+ (previous: $(basename "$prev"))}"
}

trees_prune() {
    local cur prev old src_real
    src_real="$(readlink -f "$SOURCE_DIR")"
    cur="$(readlink -e "$LIB_DIR/current" 2>/dev/null || true)"
    [[ -n "$cur" ]] || return 0
    prev="$(readlink -e "$LIB_DIR/previous" 2>/dev/null || true)"
    for old in "$TREES_DIR"/* "$TREES_DIR"/.new-*; do
        [[ -e "$old" ]] || continue
        old="$(readlink -f "$old")"
        [[ "$old" == "$cur" || "$old" == "$prev" || "$old" == "$src_real" ]] && continue
        rm -rf -- "$old"
    done
}

install_program() {
    step "The program"
    # The drivers asked for with --with-db kept for the next upgrade: a later
    # --upgrade - one from the pages too - has none, and took a Python without
    # them; the database could no longer be moved from the pages.
    local drivers="$LIB_DIR/db-drivers"
    if [[ -n "$WITH_DB" && -z "$DRY_RUN" ]]; then
        install -d -m 0755 "$LIB_DIR"
        printf '%s\n' "$WITH_DB" > "$drivers" && chmod 600 "$drivers"
    elif [[ -z "$WITH_DB" && -f "$drivers" && ! -L "$drivers" ]]; then
        WITH_DB="$(head -n1 "$drivers" 2>/dev/null | tr -cd 'a-z')"
        [[ -n "$WITH_DB" ]] && note "the database drivers asked for before are kept: $WITH_DB (--with-db to change)"
    fi
    runtime_python
    step "The tree"
    install_tree
    # The command, on the same Python as the daemon, from the tree that runs
    # when it starts (one switched under it does not mix two versions).
    # Imported, not run as a script: its compiled form is used; -I: nothing
    # from the folder it is run in, nor PYTHON* settings.
    if [[ -z "$DRY_RUN" ]]; then
        rm -f "$BIN_LINK.new.$$"
        cat > "$BIN_LINK.new.$$" <<EOB
#!/bin/sh
# acme, on the Python install.sh chose ($LIB_DIR/python), from $LIB_DIR/current
T="\$(readlink -f $LIB_DIR/current)" || exit 1
exec $LIB_DIR/python -I -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); sys.argv[0] = "acme"; import acme; acme.entry()' "\$T" "\$@"
EOB
        chmod 0755 "$BIN_LINK.new.$$"
        mv -Tf "$BIN_LINK.new.$$" "$BIN_LINK"
    else
        note "[would write] $BIN_LINK"
    fi
    good "$BIN_LINK"
    not_a_link "$STATE_DIR" "$STATE_DIR/backups" "$LOG_DIR" "$CONFIG_DIR"
    run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
    acme_subdir "$STATE_DIR/backups"
    run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR"
    # The daemon writes config.json itself when the database is moved, so the
    # folder is its group's - and nothing else in it is anybody's but root's.
    if [[ -d "$CONFIG_DIR" ]]; then
        run chown root:"$SERVICE_USER" "$CONFIG_DIR"; run chmod 2770 "$CONFIG_DIR"
    else
        run install -d -m 2770 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
    fi
    install_plugin_dirs
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme.service" "$UNIT_FILE"
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme.logrotate" "$LOGROTATE_FILE"
    install_upgrader
    run systemctl daemon-reload
    if [[ -f "$UPGRADE_PATH_UNIT" ]]; then
        run systemctl enable --now acme-upgrade.path >/dev/null 2>&1 \
            || warn "acme-upgrade.path did not start; upgrades from the pages wait for it"
    fi
    if [[ -f "$WEB_PATH_UNIT" ]]; then
        # Restarted, not only enabled: a path unit that is already running
        # keeps watching what its old file named. One left failed by systemd's
        # start limit watches nothing.
        run systemctl reset-failed acme-web.service acme-web.path >/dev/null 2>&1 || true
        { run systemctl enable acme-web.path >/dev/null 2>&1 && run systemctl restart acme-web.path >/dev/null 2>&1; } \
            || warn "acme-web.path did not start; TLS and the web address from the pages wait for it"
    fi
}

# A folder of root's modules made root's again - through its descriptor, never by its name
# (1.0.44): /etc/acme is the acme account's group's, and the acme account could rename root's
# plugins folder away and put its own there (its modules then made root's by the chown), or
# swap the folder for a link between the look and the chown. A folder that is not root's
# already is not taken: it is moved aside, and a new empty one made.
plugin_dir_take() {
    local d="$1" said
    [[ -n "$DRY_RUN" ]] && { note "[would make root's] $d"; return 0; }
    said="$(python3 -I - "$d" <<'PY'
import os, stat, sys, time
d = sys.argv[1]
try:
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError as e:
    print('gone %s' % e)
    sys.exit(0)
try:
    st = os.fstat(fd)
    if st.st_uid != 0:
        aside = '%s.not-roots.%d' % (d, int(time.time()))
        os.rename(d, aside)
        print('aside %s' % aside)
    else:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o755)
        print('ok')
finally:
    os.close(fd)
PY
)"
    case "$said" in
        ok) ;;
        aside*) warn "$d was not root's (made by another account): moved aside as ${said#aside }, and made anew - look at what is in it"
                run install -d -m 0755 -o root -g root "$d" ;;
        *) if [[ -e "$d" || -L "$d" ]]; then
               fail "$d changed while it was looked at (a link put there?) - look at it, then run this again"
           fi
           run install -d -m 0755 -o root -g root "$d" ;;
    esac
}

# Your own modules: /etc/acme/plugins/{issuers,challenges,targets,checks}/*.py, kept
# across upgrades (one with the same kind and version as a shipped one takes its
# place). Root's alone: root's own acme command loads them too, so the acme
# account must not be able to put code there. README and examples/ are acme's:
# written again at every install (1.0.34), your own files are never touched.
install_plugin_dirs() {
    local d f rel
    not_a_link "$PLUGINS_DIR" "$PLUGINS_DIR/issuers" "$PLUGINS_DIR/challenges" "$PLUGINS_DIR/targets" \
        "$PLUGINS_DIR/checks" "$PLUGINS_DIR/examples"
    for d in "$PLUGINS_DIR" "$PLUGINS_DIR/issuers" "$PLUGINS_DIR/challenges" "$PLUGINS_DIR/targets" \
            "$PLUGINS_DIR/checks"; do
        if [[ -d "$d" ]]; then
            plugin_dir_take "$d"
        else
            run install -d -m 0755 -o root -g root "$d"
        fi
    done
    if [[ -f "$SOURCE_DIR/deploy/plugins/README" ]]; then
        run install -m 0644 -o root -g root "$SOURCE_DIR/deploy/plugins/README" "$PLUGINS_DIR/README"
    fi
    if [[ -d "$SOURCE_DIR/deploy/plugins/examples" ]]; then
        # the examples as this release has them: the folder made anew
        [[ -d "$PLUGINS_DIR/examples" ]] && run rm -rf -- "$PLUGINS_DIR/examples"
        run install -d -m 0755 -o root -g root "$PLUGINS_DIR/examples"
        while IFS= read -r -d '' f; do
            rel="${f#"$SOURCE_DIR/deploy/plugins/examples/"}"
            run install -d -m 0755 -o root -g root "$PLUGINS_DIR/examples/$(dirname "$rel")"
            run install -m 0644 -o root -g root "$f" "$PLUGINS_DIR/examples/$rel"
        done < <(find "$SOURCE_DIR/deploy/plugins/examples" -type f -name '*.py.example' -print0)
    fi
    good "$PLUGINS_DIR/{issuers,challenges,targets,checks} - your own modules (root's); README, examples/"
}

# Upgrades from the pages: root's helper, the keys it trusts, and the systemd
# units that start it when the pages ask. The keys are root's alone, in the
# program's folder - never anywhere the acme account may write.
install_upgrader() {
    [[ -f "$SOURCE_DIR/deploy/acme_upgrade.py" ]] || return 0
    run install -d -m 0755 -o root -g root "$LIB_DIR/release-keys"
    local k
    for k in "$SOURCE_DIR"/deploy/release-keys/*.pub; do
        [[ -f "$k" ]] && run install -m 0644 -o root -g root "$k" "$LIB_DIR/release-keys/"
    done
    # Exactly the package's keys: one a release no longer ships is trusted no longer.
    compgen -G "$SOURCE_DIR/deploy/release-keys/*.pub" >/dev/null && for k in "$LIB_DIR"/release-keys/*.pub; do
        [[ -f "$k" ]] || continue
        [[ -f "$SOURCE_DIR/deploy/release-keys/$(basename "$k")" ]] || run rm -f "$k"
    done
    acme_subdir "$STATE_DIR/upgrade"
    # How far back this machine may go: the highest floor of every version put
    # in here - an older version's install.sh leaves it as it is, so going
    # back never lowers it. Root's alone, beside versions/ (not in a tree).
    local floor new="$DOWNGRADE_FLOOR_NEW"
    if [[ -n "$new" ]]; then
        floor=""
        if [[ -L "$LIB_DIR/downgrade-floor" ]]; then run rm -f "$LIB_DIR/downgrade-floor"
        elif [[ -f "$LIB_DIR/downgrade-floor" ]]; then
            floor="$(head -c 32 "$LIB_DIR/downgrade-floor" | tr -cd '0-9.' || true)"
        fi
        if [[ -z "$floor" ]] || ! ver_ge "$floor" "$new"; then floor="$new"; fi
        if [[ -n "$DRY_RUN" ]]; then note "[would write] $LIB_DIR/downgrade-floor: $floor"
        else printf '%s\n' "$floor" > "$LIB_DIR/downgrade-floor"; chown root:root "$LIB_DIR/downgrade-floor"; chmod 0644 "$LIB_DIR/downgrade-floor"; fi
    fi
    # TLS and the cluster's web address from the pages: root's helper (in the
    # tree, linked as $LIB_DIR/acme_web.py), keepalived's check, and the units
    # that start the helper when asked.
    if [[ -f "$SOURCE_DIR/deploy/acme_web.py" ]]; then
        # Where keepalived's scripts belong: SELinux lets keepalived run what is
        # in /usr/libexec/keepalived (keepalived_unconfined_script_exec_t).
        run install -D -m 0755 "$SOURCE_DIR/deploy/acme-vip-check" /usr/libexec/keepalived/acme-vip-check
        command -v restorecon >/dev/null 2>&1 && run restorecon -R /usr/libexec/keepalived >/dev/null 2>&1 || true
        acme_subdir "$STATE_DIR/web"
        run install -D -m 0644 "$SOURCE_DIR/deploy/acme-web.service" "$WEB_SERVICE_UNIT"
        run install -D -m 0644 "$SOURCE_DIR/deploy/acme-web.path" "$WEB_PATH_UNIT"
    fi
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme-upgrade.service" "$UPGRADE_SERVICE_UNIT"
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme-upgrade.path" "$UPGRADE_PATH_UNIT"
    good "upgrades from the pages: acme-upgrade.path, packages signed by $(ls "$SOURCE_DIR/deploy/release-keys" 2>/dev/null | sed 's/\.pub$//' | paste -sd, - || true)"
}

as_acme() {             # a command of acme's, as its own account
    if [[ -n "$DRY_RUN" ]]; then note "[would run as $SERVICE_USER] acme $*"; return 0; fi
    runuser -u "$SERVICE_USER" -- env ACME_CONFIG="$CONFIG_FILE" "$BIN_LINK" "$@"
}

restart_daemon() {
    run systemctl reenable acme.service >/dev/null 2>&1 || run systemctl enable acme.service >/dev/null
    local before after up=0 i
    before="$(systemctl show -p NRestarts --value acme.service 2>/dev/null || echo 0)"
    run systemctl restart acme.service
    [[ -n "$DRY_RUN" ]] && return 0
    # Running, and still the same run 15 s on (1.0.44): Restart=always brings a version that
    # dies at 3 s back every 5 s - after 2 s it was "running", and stayed in a loop.
    for i in $(seq 1 40); do
        sleep 1
        after="$(systemctl show -p NRestarts --value acme.service 2>/dev/null || echo 0)"
        if systemctl is-active --quiet acme.service && [[ "$after" == "$before" ]]; then
            up=$((up + 1))
            [[ $up -ge 15 ]] && break
        else
            up=0
            before="$after"
        fi
    done
    if [[ $up -ge 15 ]]; then
        local here
        here="$(readlink -e "$LIB_DIR/current" 2>/dev/null || true)"
        [[ -n "$here" ]] && touch "$here/.ran-ok" 2>/dev/null || true
        good "acme.service is running"
    else
        warn "it did not start - the last of its log:"
        journalctl -u acme -n 20 --no-pager || true
        fail "sort that out and run this again"
    fi
}

# The database engine's own programs, for the nightly dumps and for putting
# one back (Settings -> The database -> The dumps it keeps). The clients only,
# never a server - and only the client of the engine in use (the config file
# says which; --with-db both is for the drivers, so the pages can move to
# either). Switch engines and run --upgrade again, and the other's comes.
# The Python drivers themselves come with the Python (runtime_python).
install_db_tools() {
    local tools=() inuse=""
    inuse="$(python3 -c 'import json,os,stat,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); assert stat.S_ISREG(os.fstat(fd).st_mode); print(json.loads(os.read(fd, 4<<20) or b"{}").get("db_engine") or "")' \
             "$CONFIG_DIR/config.json" 2>/dev/null || true)"
    case "$inuse" in
        mariadb) tools=("mariadb-dump:mariadb:mariadb-client");;
        postgres) tools=("pg_dump:postgresql:postgresql-client");;
        *) case "$WITH_DB" in
               mariadb|mysql) tools=("mariadb-dump:mariadb:mariadb-client");;
               postgres|postgresql) tools=("pg_dump:postgresql:postgresql-client");;
               both) tools=();;
           esac;;
    esac
    ((${#tools[@]})) || return 0
    step "The database's own tools"
    local one bin rpm deb
    for one in "${tools[@]}"; do
        IFS=: read -r bin rpm deb <<< "$one"
        if command -v "$bin" >/dev/null || { [[ "$bin" == mariadb-dump ]] && command -v mysqldump >/dev/null; }; then
            good "$bin is already here"; continue
        fi
        if [[ "$PKG" == "dnf" ]]; then run dnf install -y "$rpm" || true
        elif [[ "$PKG" == "apt" ]]; then apt_update_once; run apt-get install -y "$deb" || true; fi
        [[ -n "$DRY_RUN" ]] && continue
        command -v "$bin" >/dev/null && good "$bin installed (for the dumps)" \
            || warn "$bin could not be installed: the nightly dump is a portable copy instead"
    done
}

# PostgreSQL's settings that take effect only at its start (shared_buffers
# above all): the pages may restart it - restart, nothing else, and only a
# postgresql*.service - when a full admin asks, as on isemon. Taken away
# with --no-db-restart; the pages then show the command to run instead.
install_db_restart() {
    local rules="/etc/polkit-1/rules.d/49-acme-database.rules"
    local mark="$CONFIG_DIR/may-restart-database"
    # Remembered where only root writes: every later upgrade - the
    # pages' own among them - wrote the rule back.
    local forbid="/etc/polkit-1/rules.d/.acme-no-db-restart"
    if [[ -n "$DB_RESTART_AGAIN" ]]; then
        [[ -e "$forbid" ]] && run rm -f "$forbid"
    elif [[ -e "$forbid" ]]; then
        NO_DB_RESTART="yes"
    fi
    if [[ -n "$NO_DB_RESTART" ]]; then
        [[ -e "$rules" || -e "$mark" ]] && { run rm -f "$rules" "$mark"; good "the pages may no longer restart the database server"; }
        if [[ -d /etc/polkit-1/rules.d && ! -e "$forbid" && -z "$DRY_RUN" ]]; then
            printf 'install.sh --no-db-restart; install.sh --db-restart allows it again\n' > "$forbid"
        fi
        return 0
    fi
    [[ -d /etc/polkit-1/rules.d ]] || { note "no polkit here: the pages show the command to restart PostgreSQL instead"; return 0; }
    write_file "$rules" 0644 <<EOR
// Written by acme's install.sh (1.0.10).
//
// The acme service account may RESTART a PostgreSQL that runs on this
// machine - restart it, and nothing else: not stop it, not start it, not
// touch any other service. Settings -> The database tunes the server for
// its machine, and some of PostgreSQL's settings (shared_buffers, the one
// that matters most) take effect only when it is next started; this is what
// lets the pages finish the job when a full admin asks them to.
//
// Take it away with  install.sh --upgrade --no-db-restart  (or delete this
// file and $mark).
polkit.addRule(function (action, subject) {
    if (action.id === "org.freedesktop.systemd1.manage-units" &&
        subject.user === "$SERVICE_USER") {
        var unit = action.lookup("unit") || "";
        var verb = action.lookup("verb") || "";
        if (verb === "restart" &&
            /^postgresql(-[0-9]+)?(@[A-Za-z0-9_.-]+)?\.service\$/.test(unit)) {
            return polkit.Result.YES;
        }
    }
});
EOR
    printf 'polkit rule %s\n' "$rules" | write_file "$mark" 0644
    good "the pages may restart PostgreSQL on this machine for its tuning (--no-db-restart to forbid)"
}

# The administration's big bodies - a database put back, a new version - go
# to a place of their own where nginx asks the daemon whether a full
# administrator sends them before it reads a byte (1.0.98, auth_request):
# 4 GB was taken on anybody's say-so within the admin networks, and written
# to disk before PHP could refuse it. Everything else on the page is held to
# 32 MB. Put into the file that is there, if nginx has auth_request; nginx
# asked first, and the file put back as it was if it does not take it.
nginx_upload_guard() {
    [[ -f "$NGINX_CONF" && -z "$DRY_RUN" ]] || return 0
    if grep -q 'location = /admin/upload/' "$NGINX_CONF"; then
        # A backup from another machine put back goes this way too:
        # left out, it was refused at 32 MB.
        if grep -q 'api=(db-restore|upgrade-package)(&|\$)' "$NGINX_CONF"; then
            local bak0
            bak0="$NGINX_BAK_DIR/acme.conf.before-rbackup-upload.$(date +%Y%m%d%H%M%S)"
            mkdir -p "$NGINX_BAK_DIR"; cp -a "$NGINX_CONF" "$bak0"
            sed -i 's/api=(db-restore|upgrade-package)(&|\$)/api=(db-restore|upgrade-package|rbackup-upload)(\&|$)/' "$NGINX_CONF"
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx >/dev/null 2>&1 || true
                good "nginx takes a backup from another machine through the guarded upload too"
            else
                cp -a "$bak0" "$NGINX_CONF"
            fi
        fi
        return 0
    fi
    if ! nginx -V 2>&1 | grep -q -- '--with-http_auth_request_module'; then
        # Without the question first, nobody may send 4 GB: nginx
        # wrote whatever anybody on the allow list sent to its disk - the
        # database's disk - before the page could refuse it.
        if grep -q 'client_max_body_size 4g;' "$NGINX_CONF"; then
            local bak1
            bak1="$NGINX_BAK_DIR/acme.conf.before-upload-limit.$(date +%Y%m%d%H%M%S)"
            mkdir -p "$NGINX_BAK_DIR"; cp -a "$NGINX_CONF" "$bak1"
            sed -i 's/client_max_body_size 4g;/client_max_body_size 32m;/' "$NGINX_CONF"
            if nginx -t >/dev/null 2>&1; then
                systemctl reload nginx >/dev/null 2>&1 || true
            else
                cp -a "$bak1" "$NGINX_CONF"
            fi
        fi
        note "nginx has no auth_request here: files over 32 MB (a database put back, a package) are not taken by the pages - put them in with acme --restore / --upgrade on the server"
        return 0
    fi
    local bak
    bak="$NGINX_BAK_DIR/acme.conf.before-upload-guard.$(date +%Y%m%d%H%M%S)"
    mkdir -p "$NGINX_BAK_DIR"; cp -a "$NGINX_CONF" "$bak"
    python3 - "$NGINX_CONF" <<'PY'
import re, sys
p = sys.argv[1]
text = open(p).read()
done = 0
def one(m):
    global done
    pad, body = m.group(1), m.group(2)
    sock = re.search(r'fastcgi_pass\s+([^;]+);', body)
    if not sock or 'client_max_body_size' not in body:
        return m.group(0)
    inner = pad + '    '
    small = re.sub(r'client_max_body_size\s+\S+;', 'client_max_body_size 32m;', body)
    upload = (inner + '# Only these two, and only once nginx has asked whether a full\n' +
              inner + '# administrator signed in sends them (acme 1.0.98).\n' +
              inner + 'if ($args !~ "(^|&)api=(db-restore|upgrade-package|rbackup-upload)(&|$)") { return 404; }\n' +
              body + inner + 'auth_request /admin-upload-who;\n' +
              inner + 'error_page 401 403 = @admin-upload-refused;\n')
    who = (inner + 'internal;\n' + inner + 'fastcgi_pass   %s;\n' % sock.group(1) +
           inner + 'fastcgi_param  SCRIPT_FILENAME $document_root/admin/index.php;\n' +
           inner + 'fastcgi_param  HTTPS on;\n' + inner + 'include        fastcgi_params;\n' +
           inner + 'fastcgi_param  ACME_AUTH_ONLY 1;\n' + inner + 'fastcgi_pass_request_body off;\n' +
           inner + 'fastcgi_param  CONTENT_LENGTH "";\n' + inner + 'fastcgi_read_timeout 15s;\n' +
           inner + '# The question never reads the body: its size is not this one\'s to judge.\n' +
           inner + 'client_max_body_size 0;\n')
    refused = inner + 'default_type application/json;\n' + inner + \
        'return 401 \'{"ok": false, "error": "only a full administrator signed in may send that - sign in again"}\';\n'
    done += 1
    return ('%slocation = /admin/ {\n%s%s}\n\n%slocation = /admin/upload/ {\n%s%s}\n%slocation = /admin-upload-who {\n%s%s}\n'
            '%slocation @admin-upload-refused {\n%s%s}\n' % (pad, small, pad, pad, upload, pad, pad, who, pad,
                                                           pad, refused, pad))
text = re.sub(r'(?ms)^([ \t]*)location = /admin/ \{\n(.*?)^\1\}\n', one, text)
open(p, 'w').write(text)
print(done)
PY
    if nginx -t >/dev/null 2>&1; then
        good "nginx asks who sends a database or a new version before it takes the file (copy: $bak)"
        # Read again now: restarted before the guard was added, nginx
        # answered /admin/upload/ with 404 until something else reloaded it.
        run systemctl reload nginx || warn "nginx could not be reloaded - systemctl reload nginx"
    else
        cp -a "$bak" "$NGINX_CONF"
        warn "nginx did not take the guard for big uploads, so $NGINX_CONF is as it was"
    fi
}

open_firewall() {
    step "The firewall"
    # 443 for the pages; 80 for the ACME CAs' HTTP-01 challenge, answered by
    # acme.php through nginx (everything else on 80 is sent to HTTPS).
    # Port 53 (UDP and TCP) is NOT opened here: acme's own DNS server (for
    # DNS-01) is off until it is switched on (Settings -> DNS server), and the
    # engine's firewall (Settings -> Firewall and access, iptables/ip6tables)
    # opens it then - and only then.
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        if [[ -n "$WITH_WEB" ]]; then
            run firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
            run firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
            run firewall-cmd --reload >/dev/null 2>&1 || true
            good "firewalld: https, and http (the CAs' HTTP-01 challenges; everything else goes to https)"
        fi
    elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        if [[ -n "$WITH_WEB" ]]; then
            run ufw allow 443/tcp >/dev/null 2>&1 || true
            run ufw allow 80/tcp >/dev/null 2>&1 || true
            good "ufw: 443/tcp, and 80/tcp (the CAs' HTTP-01 challenges)"
        fi
    else
        warn "neither firewalld nor ufw is running here, so nothing was opened."
        note "Whatever filters this machine must let through: TCP 443 to the pages and TCP 80"
        note "for the CAs' HTTP-01 challenges, and out: HTTPS to the CAs, SSH to the targets."
    fi
    note "UDP and TCP 53 for acme's own DNS server (DNS-01) is opened by Settings -> Firewall"
    note "and access once the DNS server is switched on - not before, and not by this script."
    [[ -z "$WITH_WEB" ]] && note "--no-web: no nginx, so HTTP-01 cannot be answered on this machine (use DNS-01, or HTTP-01 over SSH)"
    return 0
}

# What acme itself calls: openssl (keys, CSRs, PKCS#12, its own CAs), the
# OpenSSH client (targets and HTTP-01 over SSH, backups over SFTP/SCP),
# runuser, curl (the checks below), tar, and the CA certificates for HTTPS to
# the CAs and the DNS providers' APIs. nginx for the pages.
install_base_packages() {
    local need=() deb=() one
    command -v openssl >/dev/null || need+=("openssl")
    { command -v ssh >/dev/null && command -v ssh-keygen >/dev/null; } || need+=("openssh-clients")
    command -v runuser >/dev/null || need+=("util-linux")
    command -v curl >/dev/null || need+=("curl")
    command -v tar >/dev/null || need+=("tar")
    [[ -f /etc/ssl/certs/ca-certificates.crt || -f /etc/pki/tls/certs/ca-bundle.crt ]] || need+=("ca-certificates")
    if [[ -n "$WITH_WEB" ]]; then
        command -v nginx >/dev/null || need+=("nginx")
    fi
    if ! ((${#need[@]})); then
        good "openssl, the OpenSSH client and the rest are already here"
        return 0
    fi
    say "missing: ${need[*]}"
    if [[ "$PKG" == "dnf" ]]; then
        run dnf install -y "${need[@]}"
    elif [[ "$PKG" == "apt" ]]; then
        for one in "${need[@]}"; do [[ "$one" == openssh-clients ]] && deb+=("openssh-client") || deb+=("$one"); done
        apt_update_once
        run apt-get install -y "${deb[@]}"
    else
        fail "install these by hand and run this again: ${need[*]}"
    fi
    [[ -n "$DRY_RUN" ]] && return 0
    command -v openssl >/dev/null || fail "openssl is needed and could not be installed"
    command -v ssh >/dev/null || warn "the OpenSSH client (ssh) could not be installed: targets over SSH will not work"
    return 0
}

# The programs backups to another machine use: ssh, sftp and scp for SFTP and
# SCP (the OpenSSH client acme needs anyway), smbclient for a Windows or Samba
# share. Best effort: without them those destinations say what is missing.
install_backup_tools() {
    local opt=()
    { command -v ssh >/dev/null && command -v sftp >/dev/null && command -v ssh-keygen >/dev/null; } \
        || opt+=("openssh-clients")
    command -v smbclient >/dev/null || opt+=("samba-client")
    ((${#opt[@]})) || return 0
    [[ -n "$DRY_RUN" ]] && { say "would install, for backups: ${opt[*]}"; return 0; }
    if [[ "$PKG" == "dnf" ]]; then
        dnf install -y "${opt[@]}" >/dev/null 2>&1 \
            && good "for backups to SFTP, SCP and SMB: ${opt[*]}" \
            || warn "for backups to SFTP, SCP and SMB, install by hand: dnf install ${opt[*]}"
    elif [[ "$PKG" == "apt" ]]; then
        local deb=()
        for p in "${opt[@]}"; do [[ "$p" == "openssh-clients" ]] && deb+=("openssh-client") || deb+=("smbclient"); done
        apt_update_once
        apt-get install -y "${deb[@]}" >/dev/null 2>&1 || warn "for backups: apt-get install ${deb[*]}"
    fi
}

# The clock: certificates, the CAs' answers and the cluster's leases are
# all read against it, so chrony
# is put in and started on a fresh install and on every upgrade, wherever it
# is missing or stopped. Its own /etc/chrony.conf (AlmaLinux's pool) is used
# as it is; Settings → Time sets other servers when asked.
install_time_tools() {
    local unit=chronyd
    [[ "$PKG" == "apt" ]] && unit=chrony
    if ! command -v chronyd >/dev/null && ! command -v chronyc >/dev/null; then
        if [[ -n "$DRY_RUN" ]]; then say "would install chrony (the clock)"; return 0; fi
        if [[ "$PKG" == "dnf" ]]; then
            dnf install -y chrony >/dev/null 2>&1 || { warn "chrony could not be installed: dnf install chrony - certificates and the CAs depend on the clock"; return 0; }
        elif [[ "$PKG" == "apt" ]]; then
            apt_update_once; apt-get install -y chrony >/dev/null 2>&1 || { warn "chrony could not be installed: apt-get install chrony"; return 0; }
        else
            warn "install chrony by hand - certificates and the CAs depend on the clock"; return 0
        fi
        good "chrony installed (the clock)"
    fi
    [[ -n "$DRY_RUN" ]] && return 0
    # Another time daemon would fight it.
    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
        note "systemd-timesyncd stopped: chrony keeps the clock"
    fi
    if ! systemctl is-enabled --quiet "$unit" 2>/dev/null || ! systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl enable --now "$unit" >/dev/null 2>&1 \
            && good "chrony started and enabled ($unit)" \
            || warn "chrony could not be started: systemctl enable --now $unit"
    fi
    timedatectl set-ntp true >/dev/null 2>&1 || true
    if ! grep -Eq '^[[:space:]]*(server|pool|peer|sourcedir)[[:space:]]' /etc/chrony.conf /etc/chrony/chrony.conf 2>/dev/null; then
        warn "chrony has no time server: set them in Settings → Time (or in /etc/chrony.conf)"
    fi
}

# The acme console at login: root signing in at the console or over
# SSH lands in `acme --console`; q leaves it for the shell. On unless switched
# off (`acme --console-at-login off`), which an upgrade leaves as it is.
install_console() {
    if [[ -n "$DRY_RUN" ]]; then note "[would write] /etc/profile.d/zz-acme-console.sh"; return 0; fi
    install -m 0644 "$SOURCE_DIR/deploy/acme-console-login.sh" /etc/profile.d/zz-acme-console.sh
    # The choice is kept in /etc itself, where only root writes -
    # in /etc/acme the acme account could have put a link or a pipe there for
    # root to follow. The old file's word is carried over once, read only
    # when it is a plain file, and the old file taken away.
    local flag=/etc/acme-console-login old=/etc/acme/console-login word=""
    if [[ -f "$old" && ! -L "$old" ]]; then
        word="$(head -c 8 "$old" 2>/dev/null | tr -cd 'onf')"
    fi
    [[ -L "$old" || -e "$old" ]] && rm -f "$old"
    if [[ -L "$flag" ]]; then rm -f "$flag"; fi
    if [[ ! -f "$flag" ]]; then
        [[ "$word" == "off" ]] || word="on"
        printf '%s\n' "$word" > "$flag"
        chmod 0644 "$flag"
    fi
    good "the acme console at login: $(head -n 1 "$flag" | head -c 4) (acme --console-at-login on|off)"
}

# ===========================================================================
# An upgrade: the program, the pages, PHP - and nothing else
# ===========================================================================
if [[ -n "$DO_UPGRADE" ]]; then
    step "Upgrading acme to $VERSION"
    id "$SERVICE_USER" >/dev/null 2>&1 || fail "acme is not installed here; run this without --upgrade"
    install_base_packages
    install_backup_tools
    install_time_tools
    install_console
    # This node out of service while it is done: the balancer goes to the
    # other node first, and no renewal or deployment starts here meanwhile.
    # Asked for on the pages, the daemon has done it already.
    MAINT_BY_US=""
    if [[ -z "${ACME_UPGRADE_FROM_PAGES:-}" && -z "$DRY_RUN" ]] && systemctl is-active --quiet acme.service; then
        if as_acme --maintenance status >/dev/null 2>&1; then
            # Never both nodes out at once (1.0.44), as the pages' plan: the other node must be
            # alive and in service, or this one, the last that serves, is not taken out.
            others=""
            others="$(as_acme --ha-status --json 2>/dev/null | python3 -c 'import json,sys
try:
    nodes = [n for n in json.load(sys.stdin).get("nodes", []) if not n.get("me")]
except Exception:
    nodes = []
if not nodes:
    print("alone")
elif any(n.get("alive") and not n.get("maintenance") for n in nodes):
    print("serving")
else:
    print("none")' 2>/dev/null || echo alone)"
            if [[ "$others" == none && -z "${ACME_FORCE_UPGRADE:-}" ]]; then
                fail "the other node is not in service (gone, or in maintenance): this one would be the last out. Bring it back first - or, knowing it: ACME_FORCE_UPGRADE=1 ./install.sh --upgrade"
            fi
            if as_acme --maintenance on --why "install.sh --upgrade to $VERSION" >/dev/null 2>&1; then
                MAINT_BY_US=yes
                good "this node is in maintenance while it is upgraded"
                if [[ "$(as_acme --ha-status --json 2>/dev/null | python3 -c 'import json,sys
try:
    print(sum(1 for n in json.load(sys.stdin).get("nodes", []) if n.get("alive")))
except Exception:
    print(0)' 2>/dev/null)" -gt 1 ]]; then
                    say "waiting 20 s for the load balancer to notice"
                    sleep 20
                fi
            fi
        fi
    fi
    # Whatever stops the upgrade from here on: the daemon is started again
    # and the node comes back into service, rather than staying out with half
    # of it done. The tree is switched in one step, so what runs is always one
    # whole version - the old one until the switch, the new one after it.
    UPGRADE_STAGE=started
    TREE_SWITCHED="" PAGES_SWITCHED="" ROLLBACK_TREE="" PREV_LINK_BEFORE=""
    upgrade_rescue() {
        local rc=$?
        [[ "${UPGRADE_STAGE:-}" == started && $rc -ne 0 && -z "$DRY_RUN" ]] || return 0
        if [[ -n "${TREE_SWITCHED:-}" && -n "${ROLLBACK_TREE:-}" && -d "$ROLLBACK_TREE" ]]; then
            # Back to the version that ran (1.0.44): the new one was switched in and then
            # did not run - restarting it only restarted the same failure.
            warn "the upgrade stopped after the switch (exit $rc): back to $(basename "$ROLLBACK_TREE")"
            touch "$NEW_TREE/.failed" 2>/dev/null || true
            swap_link "$LIB_DIR/current" "versions/$(basename "$ROLLBACK_TREE")" || true
            if [[ -n "${PREV_LINK_BEFORE:-}" ]]; then
                swap_link "$LIB_DIR/previous" "$PREV_LINK_BEFORE" || true    # as it was (1.0.52)
            else
                rm -f -- "$LIB_DIR/previous"     # none before: not the one running again
            fi
            if [[ -n "${PAGES_SWITCHED:-}" && -d "$ROLLBACK_TREE/web" ]]; then
                pages_from "$ROLLBACK_TREE/web" || warn "the pages of $(basename "$ROLLBACK_TREE") could not be put back"
            fi
            systemctl daemon-reload >/dev/null 2>&1 || true
        else
            warn "the upgrade stopped half way (exit $rc); the daemon is started again as it is"
        fi
        systemctl restart acme.service >/dev/null 2>&1 || true
        if [[ -n "$MAINT_BY_US" ]]; then
            sleep 3
            as_acme --maintenance off >/dev/null 2>&1 && warn "this node is back in service - look at what stopped the upgrade"
        fi
    }
    trap upgrade_rescue EXIT
    # Stopped by a signal - Ctrl-C, a hang-up, acme_upgrade.py's TERM at its
    # deadline - the exit status was 0 and the rescue did nothing.
    trap 'exit 130' INT
    trap 'exit 129' HUP
    trap 'exit 143' TERM
    # A machine installed without the pages is upgraded without them:
    # --upgrade from the pages cannot say --no-web.
    if [[ -n "$WITH_WEB" && ! -e "$NGINX_CONF" && ! -d "$WEB_DIR" ]]; then
        WITH_WEB=""
        note "no pages were installed here (no $NGINX_CONF, no $WEB_DIR): the daemon alone is upgraded"
    fi
    install_program
    install_db_tools
    install_db_restart
    if [[ -n "$WITH_WEB" ]]; then
        ensure_php
        install_pages
    fi
    [[ -n "$WITH_WEB" ]] || selinux_module      # SELinux without the pages too (1.0.59)
    restart_daemon
    UPGRADE_STAGE="done"
    [[ -z "$DRY_RUN" ]] && trees_prune
    if [[ -n "$MAINT_BY_US" ]]; then
        sleep 3
        if as_acme --status >/dev/null 2>&1; then
            as_acme --maintenance off >/dev/null 2>&1 && good "this node is back in service"
        else
            warn "this node stays in maintenance: it does not answer as it should. When it does:  acme --maintenance off"
        fi
    fi
    step "Done"
    as_acme --status || true
    note "the version before is kept: $(readlink "$LIB_DIR/previous" 2>/dev/null || echo none) - /usr/bin/python3 -I $LIB_DIR/acme_upgrade.py --previous puts it back"
    exit 0
fi

# ===========================================================================
# A fresh install
# ===========================================================================
step "Looking at this machine"
say "${OS_PRETTY:-unknown}"
[[ -n "$PKG" ]] || warn "I do not recognise this distribution; no packages will be installed."
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed (the installer and root's helpers use the system's python3)"
say "the system's $(python3 --version 2>&1) (for this script and root's helpers; acme itself runs on $PY_WANT)"
# Port 53: acme's own DNS server (DNS-01) needs it once it is switched on.
# systemd-resolved's stub (127.0.0.53, 127.0.0.54) does not stand in its way
# on the machine's own addresses; anything else that holds 53 does.
dns53="$(ss -H -lnup 2>/dev/null | awk '$4 ~ /:53$/ && $4 !~ /^127\.0\.0\.5[34]:/ {print $4" "$6}' | head -n 3 || true)"
if [[ -n "$dns53" ]]; then
    warn "something already listens on port 53 here - acme's own DNS server (DNS-01) will need it when switched on:"
    while read -r line; do note "  $line"; done <<< "$dns53"
fi
web80="$(ss -H -lntp 2>/dev/null | awk '$4 ~ /:80$/ {print $6}' | grep -v nginx | head -n 1 || true)"
if [[ -n "$web80" && -n "$WITH_WEB" ]]; then
    warn "something other than nginx holds TCP 80 ($web80): the CAs' HTTP-01 challenges come there"
fi

step "Packages"
install_base_packages
install_backup_tools
install_time_tools
install_console
install_db_tools
install_db_restart
# In an if, not after &&: a function called after && runs with errexit off,
# and a failure inside it went by unnoticed.
if [[ -n "$WITH_WEB" ]]; then ensure_php; fi

step "The accounts it runs as"
getent group "$WEB_GROUP" >/dev/null || run groupadd --system "$WEB_GROUP"
if id "$SERVICE_USER" >/dev/null 2>&1; then
    good "$SERVICE_USER already exists"
else
    run useradd --system --home-dir "$STATE_DIR" --shell /sbin/nologin --comment "acme daemon" "$SERVICE_USER"
    good "made $SERVICE_USER (the daemon)"
fi
run usermod -a -G "$WEB_GROUP" "$SERVICE_USER"
if [[ -n "$WITH_WEB" ]]; then
    if ! id "$POOL_USER" >/dev/null 2>&1; then
        run useradd --system --no-create-home --home-dir "$WEB_DIR" --shell /sbin/nologin \
            --comment "acme web pages" "$POOL_USER"
        good "made $POOL_USER (the pages' php-fpm pool)"
    fi
    run usermod -a -G "$WEB_GROUP" "$POOL_USER"
    good "$POOL_USER may read the API token, through $WEB_GROUP - and nothing else of acme's"
fi

if [[ -z "$ASSUME_YES" ]]; then
    step "A few questions"
    note "Enter to keep what is in brackets."
    if [[ -n "$WITH_WEB" ]]; then
        ask SERVER_NAME "The pages' hostname"
        ask ADMIN_ALLOW "Who may reach the administration pages (CIDRs, empty = RFC 1918)"
        ask PORTAL_ALLOW "Who may reach the portal page at / (CIDRs, empty = RFC 1918)"
    fi
    ask ISEMON_TARGET "isemon's syslog receiver, host[:port][/tcp] (empty = none for now)"
    if [[ -n "$ISEMON_TARGET" ]]; then
        ask ISEMON_HOSTNAME "The name isemon files this server under" "acme"
    fi
    ask ADMIN_USER "The first account of the administration pages"
    ask_secret ADMIN_PASSWORD "Its password (empty = make one and print it)"
fi
for v in ADMIN_ALLOW PORTAL_ALLOW; do
    [[ -n "${!v}" ]] && { cidr_list_ok "${!v}" || fail "$v takes addresses and networks, comma separated"; }
done

install_program

step "Configuration"
if [[ -L "$CONFIG_FILE" ]]; then
    fail "$CONFIG_FILE is a link - root does not write through one in a folder the acme account may change; put the file itself there (or remove the link) and run this again"
elif [[ -f "$CONFIG_FILE" ]]; then
    good "$CONFIG_FILE is already there and was left alone"
elif [[ -n "$DRY_RUN" ]]; then
    note "[would write] $CONFIG_FILE"
else
    # Made beside it and put in its place: /etc/acme is the acme account's to
    # write, and a link it put there for config.json would be followed by
    # root. Its owner and mode are set on the open file itself, never by name.
    SITE_NAME="${SITE_NAME:-${SERVER_NAME%%.*}}" python3 - "$CONFIG_DIR" "$CONFIG_FILE" "$SERVICE_USER" <<'PY'
import grp, json, os, secrets, sys
folder, final, group = sys.argv[1], sys.argv[2], sys.argv[3]
out = {'db_engine': 'sqlite', 'site_name': os.environ.get('SITE_NAME', '')}
tmp = os.path.join(folder, '.config.json.' + secrets.token_hex(6))
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
try:
    os.fchown(fd, 0, grp.getgrnam(group).gr_gid)
    os.fchmod(fd, 0o660)
    with os.fdopen(fd, 'w') as f:
        fd = None
        json.dump(out, f, indent=2, sort_keys=True)
        f.write('\n')
    os.rename(tmp, final)
except BaseException:
    if fd is not None:
        os.close(fd)
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
PY
    good "$CONFIG_FILE"
fi
note "What is saved on the pages goes into the database. Which database that is lives here."
run install -D -m 0644 "$SOURCE_DIR/deploy/config.json" "$CONFIG_DIR/config.json.example"

step "The first account"
if [[ -z "$DRY_RUN" ]]; then
    exists="$(as_acme --users --json 2>/dev/null | python3 -c 'import json,sys
want = sys.argv[1].strip().lower()
try:
    rows = json.load(sys.stdin).get("users") or []
except ValueError:
    rows = []
print("yes" if any(str(r.get("name","")).lower() == want for r in rows) else "")' "$ADMIN_USER" 2>/dev/null || true)"
    if [[ -n "$exists" ]]; then
        if [[ -n "$ADMIN_PASSWORD" ]]; then
            ACME_PASSWORD="$ADMIN_PASSWORD" as_acme --passwd "$ADMIN_USER" >/dev/null \
                && good "$ADMIN_USER already existed; its password is now the one given here"
        else
            good "$ADMIN_USER already exists and was left alone"
        fi
    else
        if [[ -z "$ADMIN_PASSWORD" ]]; then
            ADMIN_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
            MADE_ONE="yes"
        fi
        [[ ${#ADMIN_PASSWORD} -ge 8 ]] || fail "--admin-password needs at least eight characters"
        ACME_PASSWORD="$ADMIN_PASSWORD" as_acme --add-user "$ADMIN_USER" --role fulladmin \
            --note "made by the installer" >/dev/null || fail "the first account could not be made"
        good "$ADMIN_USER may sign in, as a full administrator"
        if [[ -n "${MADE_ONE:-}" ]]; then
            printf '\n    %sname:     %s%s\n' "$C_OK" "$ADMIN_USER" "$C_OFF"
            printf '    %spassword: %s%s\n\n' "$C_OK" "$ADMIN_PASSWORD" "$C_OFF"
            warn "Write that down now — it is not shown again."
        fi
    fi
else
    note "[would make] $ADMIN_USER, a full administrator"
fi

if [[ -n "$ISEMON_TARGET" ]]; then
    as_acme --set isemon=1 --set "isemon_targets=$ISEMON_TARGET" \
        --set "isemon_hostname=${ISEMON_HOSTNAME:-acme}" >/dev/null && good "the logs go to isemon at $ISEMON_TARGET"
fi

step "The service"
restart_daemon

if [[ -n "$WITH_WEB" ]]; then install_pages; fi
[[ -n "$WITH_WEB" ]] || selinux_module          # SELinux without the pages too (1.0.59)
open_firewall

step "Does it work"
as_acme --status || true
if [[ -n "$WITH_WEB" && -z "$DRY_RUN" ]]; then
    code_admin="$(curl --noproxy '*' -k -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:443:127.0.0.1" "https://$SERVER_NAME/admin/" || true)"
    code_multi="$(curl --noproxy '*' -k -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:443:127.0.0.1" -F a=b "https://$SERVER_NAME/admin/" || true)"
    # HTTP-01: a token nobody asked for is answered 404 by acme.php itself -
    # not 301 to HTTPS, which would mean nginx never sends challenges there.
    code_h01="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:80:127.0.0.1" "http://$SERVER_NAME/.well-known/acme-challenge/install-check-0123456789" || true)"
    [[ "$code_admin" == "200" ]] && good "https://$SERVER_NAME/admin/ answers" || warn "https://$SERVER_NAME/admin/ answered $code_admin"
    [[ "$code_multi" == "403" ]] && good "a multipart body is refused (php2shell)" || warn "a multipart body was answered $code_multi, not 403"
    [[ "$code_h01" == "404" ]] && good "http://$SERVER_NAME/.well-known/acme-challenge/ goes to acme (HTTP-01)" \
        || warn "http://$SERVER_NAME/.well-known/acme-challenge/ answered $code_h01, not 404 from acme.php - HTTP-01 on this machine will not work"
    php_says
fi

step "Done"
say "The administration pages: https://$SERVER_NAME/admin/"
say "Next: Settings -> Issuers (Let's Encrypt: the account and its e-mail), Challenges"
say "      (HTTP-01 here, or DNS-01: acme's own DNS server or your DNS provider's API),"
say "      Targets (where certificates go), then Certificates -> New."
say "      On the command line: acme --help, acme --certs, acme --console."
say "Your own modules go into $PLUGINS_DIR/{issuers,challenges,targets}/."
[[ -n "$ISEMON_TARGET" ]] && say "On the isemon machine: deploy/isemon/11-acme.conf into /etc/rsyslog.d/."
exit 0
