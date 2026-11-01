#!/usr/bin/env bash
#
# install.sh — set up acme on AlmaLinux 9 (and Rocky / RHEL 9 and 10, and,
# with less of it automatic, Debian and Ubuntu).
#
# The same shape as isemon's installer: packages, a fixed PHP (php2shell),
# the service account, the configuration, the systemd unit, log rotation,
# nginx with TLS and a php-fpm pool of acme's own, SELinux, the firewall, the
# first account, a RADIUS client for testing from this machine, and a check
# that it all works. Run it from inside the unpacked folder, as root:
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
VERSION="$(sed -n "s/^__version__ = '\(.*\)'.*/\1/p" "$SOURCE_DIR/acme.py" 2>/dev/null | head -n1)"
VERSION="${VERSION:-unknown}"
SERVICE_USER="acme"
WEB_GROUP="acme-web"
POOL_USER="acme-www"
LIB_DIR="/usr/local/lib/acme"
BIN_LINK="/usr/local/bin/acme"
CONFIG_DIR="/etc/acme"
CONFIG_FILE="$CONFIG_DIR/config.json"
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

DRY_RUN=""
ASSUME_YES=""
WITH_WEB="yes"
DO_UPGRADE=""
REWRITE_NGINX=""
DO_UNINSTALL=""
WITH_DB=""
NO_DB_RESTART=""
PY_FORCE=""
PY_SYSTEM=""
ACME_PY=""
DB_RESTART_AGAIN=""
PHP_UPDATE="yes"
PHP_STREAM="8.3"
USE_REMI=""

SERVER_NAME="acme.example.local"
ADMIN_ALLOW=""
PORTAL_ALLOW=""
RADIUS_FROM=""
ADMIN_USER="admin"
ADMIN_PASSWORD=""
CERT_FILE=""
KEY_FILE=""
LEGACY_ROOT=""
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
    # Written beside it and renamed over it (1.0.94): a redirect follows a
    # link, and /etc/acme is the acme account's to change - a link put there
    # between the two steps made root write over any file it pointed to. A
    # rename replaces the name itself, whatever it was.
    # ...and written in a folder only root can enter (1.0.101): a file made
    # in /etc/acme itself could be swapped for a link by the acme account
    # between mktemp and the redirect. The folder is made beside the target
    # folder, so the rename stays on one file system.
    local dir tmpd
    dir="$(dirname -- "$dest")"
    # Made only when missing (1.0.103): install -d also set the mode of one
    # that was there - /etc/acme lost the acme group's write on every upgrade.
    [[ -d "$dir" ]] || install -d -m 0755 "$dir" 2>/dev/null || true
    tmpd="$(mktemp -d "$(dirname -- "$dir")/.acme-write.XXXXXX")" || fail "cannot write beside $dir"
    chmod 0700 "$tmpd"
    printf '%s\n' "$body" > "$tmpd/f"
    chmod "$mode" "$tmpd/f"
    mv -fT -- "$tmpd/f" "$dest"
    rmdir -- "$tmpd" 2>/dev/null || true
}

# A folder inside one the acme account owns (1.0.44): made and set by the acme
# account itself, never by root through a path acme could swap for a link -
# install -d as root follows a link and would hand its target to acme.
# The copies of nginx's file, out of conf.d where they piled up (1.0.47).
NGINX_BAK_DIR=/etc/nginx/acme-backups
nginx_backups_tidy() {
    [[ -n "$DRY_RUN" ]] && return 0
    mkdir -p "$NGINX_BAK_DIR"
    chmod 0750 "$NGINX_BAK_DIR"
    local f
    for f in /etc/nginx/conf.d/acme.conf.before-* /etc/nginx/conf.d/opt.conf.before-*; do
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
acme installer $VERSION — a one-time password server (RADIUS, TOTP, enrolment, AD)

Usage: sudo ./install.sh [options]

  --server-name HOST        the pages' hostname (default $SERVER_NAME)
  --admin-allow CIDR[,..]   who may reach the administration pages (nginx allow)
  --portal-allow CIDR[,..]  who may reach the enrolment pages (nginx allow)
                            (both default to the RFC 1918 networks)
  --radius-from CIDR[,..]   who may send RADIUS (UDP 1812/1813) through firewalld:
                            the VPN concentrators. Without it, anybody may - and
                            acme answers only its clients either way
  --admin-user NAME         the first account of the administration pages (admin)
  --admin-password PASS     its password (otherwise one is made and printed)
  --cert FILE --key FILE    the TLS certificate and key for nginx
  --import-legacy ROOT      bring an old totpcgi + FreeRADIUS server over: its
                            clients, realms, directory, groups, settings and every
                            token. ROOT holds its etc/raddb and etc/totpcgi
                            (the unpacked acme.zip of the old server)
  --isemon HOST[:PORT][/tcp] send the logs to isemon's syslog receiver
  --isemon-hostname NAME    the host name isemon files them under (default: acme)
  --site-name NAME          what to call this installation on the pages
  --with-db ENGINE          the Python driver for mariadb, postgres or both
                            (the file on this machine needs none)

  PHP (php2shell, CVE-2026-109618 / CVE-2026-109619 - fixed 21 October 2026):
  --php-stream X.Y          the AppStream module stream to put PHP on (default 8.3,
                            fixed in 8.3.36; 8.2 is fixed in 8.2.35)
  --remi                    take PHP 8.4 from Remi's repository instead
                            (offered by itself when AppStream has no fixed build)
  --no-php-update           leave PHP exactly as it is (it is still checked);
                            a PHP already installed and fixed is left as it is anyway

  --no-web                  the daemon only: no pages, no nginx, no PHP
  --python PATH             run acme on this Python (3.8 or newer) rather than the
                            newest one found or installed (3.13, 3.12, 3.11)
  --system-python           run acme on the system's own python3, as before 1.0.97
  --no-db-restart           the pages may not restart a PostgreSQL on this machine
                            (remembered for every later upgrade)
  --db-restart              they may again, after --no-db-restart
                            after tuning it (they show the command instead)
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
        --radius-from)     RADIUS_FROM="$2"; shift 2;;
        --admin-user)      ADMIN_USER="$2"; shift 2;;
        --admin-password)  ADMIN_PASSWORD="$2"; shift 2;;
        --cert)            CERT_FILE="$2"; shift 2;;
        --key)             KEY_FILE="$2"; shift 2;;
        --import-legacy)   LEGACY_ROOT="$2"; shift 2;;
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
        --system-python)   PY_SYSTEM="yes"; shift;;
        --db-restart)      DB_RESTART_AGAIN="yes"; shift;;
        --upgrade)         DO_UPGRADE="yes"; shift;;
        --rewrite-nginx)   REWRITE_NGINX="yes"; shift;;
        --uninstall)       DO_UNINSTALL="yes"; shift;;
        --dry-run)         DRY_RUN="yes"; shift;;
        -y|--yes)          ASSUME_YES="yes"; shift;;
        -h|--help)         usage; exit 0;;
        *) fail "I do not know the option $1 — try --help";;
    esac
done
# Checked on every path (1.0.61), the upgrade's too: --admin-allow all went
# through there and opened the administration pages to everybody.
for v in ADMIN_ALLOW PORTAL_ALLOW RADIUS_FROM; do
    [[ -n "${!v}" ]] && { cidr_list_ok "${!v}" || fail "$v takes addresses and networks, comma separated"; }
done

[[ $EUID -eq 0 ]] || fail "run this as root: sudo ./install.sh"
[[ -f "$SOURCE_DIR/acme.py" ]] || fail "acme.py is not beside this script; run it from inside the unpacked folder"

OS_PRETTY="$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}" )"
OS_MAJOR="$( . /etc/os-release 2>/dev/null; v="${VERSION_ID:-}"; printf '%s' "${v%%.*}" )"   # none on Debian testing (1.0.146)
case "$( . /etc/os-release 2>/dev/null; printf '%s%s' "${ID:-}" "${ID_LIKE:-}" )" in
    *rhel*|*fedora*|*centos*|*almalinux*|*rocky*) PKG="dnf";;
    *debian*|*ubuntu*) PKG="apt";;
    *) PKG="";;
esac

# ---------------------------------------------------------------------------
# Taking it away
# ---------------------------------------------------------------------------
php_fpm_units() {
    local found="" unit listed
    systemctl cat php-fpm.service >/dev/null 2>&1 && found="php-fpm"
    listed="$(systemctl list-unit-files --no-legend 'php*-fpm.service' 2>/dev/null || true)"
    while read -r unit _rest; do
        unit="${unit%.service}"
        [[ -n "$unit" && "$unit" != "php-fpm" && "$unit" =~ ^php[0-9.]*-fpm$ ]] && found="$found $unit"
    done <<< "$listed"
    echo "$found"
}

if [[ -n "$DO_UNINSTALL" ]]; then
    step "Removing acme $VERSION"
    say "The database, the key of the tokens, the configuration and the accounts are kept:"
    say "  $STATE_DIR  and  $CONFIG_DIR"
    # Asked even with --yes, as --help says (1.0.146): it said nothing and
    # changed nothing, and exited 0.
    if [[ -n "$ASSUME_YES" && ! -t 0 ]]; then
        fail "removing is never a default: run --uninstall on a terminal, it asks"
    fi
    ASSUME_YES="" confirm "Go ahead?" n || { say "Nothing was changed."; exit 0; }
    # An upgrade going on is not cut off under its own feet (1.0.44) - looked
    # at before anything is stopped or taken away (1.0.146).
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
    [[ -e /etc/nginx/conf.d/acme_vip.conf ]] && run rm -f /etc/nginx/conf.d/acme_vip.conf
    [[ -e /usr/libexec/keepalived/acme-vip-check ]] && run rm -f /usr/libexec/keepalived/acme-vip-check
    for one in "$UNIT_FILE" "$LOGROTATE_FILE" "$NGINX_CONF" "$BIN_LINK" \
               "$UPGRADE_PATH_UNIT" "$UPGRADE_SERVICE_UNIT" "$WEB_PATH_UNIT" "$WEB_SERVICE_UNIT" \
               /etc/polkit-1/rules.d/49-acme-database.rules "$CONFIG_DIR/may-restart-database" \
               /etc/php-fpm.d/acme.conf /etc/php/*/fpm/pool.d/acme.conf /etc/profile.d/zz-acme-console.sh /etc/acme-console-login; do
        [[ -e "$one" ]] && run rm -f "$one"
    done
    # sshd's PAM no longer asking an acme that is gone (1.0.206): every password
    # and code over SSH was refused after it - keys alone went on working.
    if [[ -f "$SOURCE_DIR/deploy/acme_web.py" ]]; then
        run python3 -I "$SOURCE_DIR/deploy/acme_web.py" --pam-off || warn "sshd's PAM could not be put back: take acme's block out of /etc/pam.d/sshd by hand"
    fi
    [[ -d "$LIB_DIR" ]] && run rm -rf "$LIB_DIR"
    [[ -d "$WEB_DIR" ]] && run rm -rf "$WEB_DIR"
    run systemctl daemon-reload
    for unit in $(php_fpm_units); do run systemctl restart "$unit" || true; done
    command -v nginx >/dev/null && run systemctl reload nginx 2>/dev/null || true
    good "Gone. $STATE_DIR and $CONFIG_DIR were left alone."
    say "To remove the rest:  rm -rf $STATE_DIR $CONFIG_DIR $LOG_DIR; userdel $SERVICE_USER; userdel $POOL_USER; groupdel $WEB_GROUP"
    # What it opened and made beside it, said rather than guessed at (1.0.44).
    [[ -e /etc/nginx/certs/acme.pem ]] && say "  its certificate:  rm -f /etc/nginx/certs/acme.pem /etc/nginx/certs/acme.key"
    if command -v firewall-cmd >/dev/null 2>&1; then
        say "  the firewall openings for RADIUS:  firewall-cmd --permanent --remove-port=1812/udp --remove-port=1813/udp; firewall-cmd --reload"
        say "  (and any rich rules for 1812/1813:  firewall-cmd --list-rich-rules)"
    fi
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
# it offers Remi's PHP 8.4 (fixed in 8.4.27). Either way the guard goes on:
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
    # whole first and searched after (1.0.36): `rpm | grep -q` under
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
    say "Remi's repository (rpms.remirepo.net), PHP 8.4"
    if ! rpm -q remi-release >/dev/null 2>&1; then
        run dnf install -y "https://rpms.remirepo.net/enterprise/remi-release-${major}.rpm" \
            || { warn "remi-release could not be installed (is rpms.remirepo.net reachable?)"; return 1; }
    fi
    if dnf module list php 2>/dev/null | grep -q 'remi-8.4'; then
        run dnf module reset -y php
        run dnf module enable -y php:remi-8.4
    else
        run dnf config-manager --set-enabled remi-modular 2>/dev/null || true
        run dnf module reset -y php || true
        run dnf module enable -y php:remi-8.4 || { warn "php:remi-8.4 could not be enabled"; return 1; }
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
    # PHP that is there and fixed is left exactly as it is (1.0.26): no
    # install, no stream switched, no restart. Updating it further is the
    # system's own business - dnf/apt upgrade - and any newer build or
    # stream is welcome; nothing here pins a version.
    local had_php=""
    if command -v php-fpm >/dev/null 2>&1 || ls /usr/sbin/php-fpm* >/dev/null 2>&1; then had_php=yes; fi
    if [[ -n "$had_php" && -z "$USE_REMI" ]] && php_fixed; then
        note "PHP is installed and fixed: left as it is (updates come with dnf/apt upgrade)"
        php_says
        php_guard
        return 0
    fi
    if [[ "$PKG" == "dnf" ]]; then
        if [[ -n "$USE_REMI" ]]; then
            remi_php || true
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
        if [[ -n "$had_php" ]]; then
            say "PHP is installed but not fixed: updating the packages that are there"
            run apt-get update
            local have
            have="$(dpkg-query -W -f='${Package} ${Status}\n' 'php*' 2>/dev/null | awk '/ installed$/{print $1}' | tr '\n' ' ' || true)"
            [[ -n "$have" ]] && { run apt-get install -y --only-upgrade $have || true; }
        else
            run apt-get update
            run apt-get install -y php-fpm php-cli
        fi
    else
        warn "this distribution is not one this knows: install php-fpm yourself, fixed against php2shell"
    fi
    [[ -n "$DRY_RUN" ]] && { php_guard; return 0; }
    if ! php_fixed && [[ "$PKG" == "dnf" && -z "$USE_REMI" ]]; then
        warn "the PHP AppStream has here is not fixed yet: $(php_fpm_version)"
        # Never on its own in an upgrade (1.0.44): it moves every PHP site on
        # the machine to 8.4. Asked of a person, or --remi.
        if [[ -n "$DO_UPGRADE" || -n "${ACME_UPGRADE_FROM_PAGES:-}" ]]; then
            note "Remi's PHP 8.4 is not taken during an upgrade by itself: ./install.sh --upgrade --remi"
        elif confirm "Take PHP 8.4 from Remi's repository instead (fixed in 8.4.27)?" y; then
            remi_php || true
        fi
    fi
    php_says
    # PHP 8 at least (1.0.94): the pages' relay is written for it, and on a
    # 7.4 every page was a 500 after an install that said it went well.
    local pv
    pv="$(php_fpm_version)"
    if [[ -n "$pv" && -z "$DRY_RUN" ]] && ! ver_ge "$pv" 8.0; then
        fail "php-fpm here is $pv: acme's pages need PHP 8.0 or newer (on Debian 11 / Ubuntu 20.04 add a PHP 8 repository first, or install with --no-web)"
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
    # The pool folder of the php-fpm that is installed (1.0.36): the first
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
    run install -d -m 0755 "$WEB_DIR" "$WEB_DIR/admin" "$WEB_DIR/assets" "$WEB_DIR/lang"
    run install -m 0644 "$SOURCE_DIR/web/index.php" "$SOURCE_DIR/web/acme-api.php" "$SOURCE_DIR/web/healthz.php" \
        "$SOURCE_DIR/web/acme-page.php" "$SOURCE_DIR/web/acme-art.php" "$SOURCE_DIR/web/.user.ini" "$WEB_DIR/"
    run install -m 0644 "$SOURCE_DIR/web/admin/index.php" "$WEB_DIR/admin/"
    run install -m 0644 "$SOURCE_DIR"/web/assets/* "$WEB_DIR/assets/"
    run install -m 0644 "$SOURCE_DIR"/web/lang/*.json "$WEB_DIR/lang/"
    run chown -R root:root "$WEB_DIR"
    good "$WEB_DIR"

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
            # What was there kept beside it (1.0.61): a pool tuned by hand
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
        # (1.0.36): every install restarted every php-fpm on the machine,
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
        note "real pair and reload nginx: people type their directory password on these pages."
        run openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
            -keyout "$CERT_DIR/acme.key" -out "$CERT_DIR/acme.pem" \
            -subj "/CN=$SERVER_NAME" -addext "subjectAltName=DNS:$SERVER_NAME" 2>/dev/null
        run chmod 0600 "$CERT_DIR/acme.key"
    fi

    # ---- nginx ---------------------------------------------------------------------
    # A file that is there is kept and brought up to date, upgrade or not
    # (1.0.36): installing again wrote it afresh, and its server name, its
    # allow lists and the trusted proxy went back to the defaults.
    if [[ -f "$NGINX_CONF" && -z "$REWRITE_NGINX" ]]; then
        good "$NGINX_CONF is already there and its allow lists are kept (--rewrite-nginx writes it afresh)"
        run install -D -m 0644 "$SOURCE_DIR/deploy/nginx-acme.conf" "$LIB_DIR/nginx-acme.conf"
        note "the one this version ships is $LIB_DIR/nginx-acme.conf, for comparing"
        # What later versions need of it, put in where it is missing - with a
        # copy kept and nginx asked before anything is reloaded: a database
        # put back from the page (1.0.10, the file as the body, up to 4 GB)
        # and the load balancer's health check (1.0.13).
        if [[ -z "$DRY_RUN" ]]; then
            # Copies kept out of conf.d, the last ten (1.0.47); a retry of
            # the same version keeps the first copy (1.0.44).
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
# 1.0.173: Prometheus asks /metrics of each node, with its token.
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
# 1.0.15: the health check rate-limited like everything else (the zone is
# whichever one the conf keeps for everybody; acme_all, as shipped).
# Looked for in the whole block (1.0.67): the access lists put in front of
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
# 1.0.15: sign-in attempts counted on the whole query string, not $arg_api,
# which takes the first of two api= and decodes nothing.
old_map = re.search(r'map \$arg_api \$acme_login_key \{\n\s*"login"\s+\$binary_remote_addr;', text)
if old_map:
    text = text.replace(old_map.group(0),
                        'map $args $acme_login_key {\n    "~(^|&)api=login(&|$)"   $binary_remote_addr;', 1)
    said.append('the sign-in limit sees every spelling of api=login')
# 1.0.15: no second Content-Security-Policy from nginx - the pages send their
# own, with a nonce, and a browser given two enforces both.
text, n = re.subn(r'(?m)^\s*add_header\s+Content-Security-Policy\s+"[^"]*"[^\n]*\n', '', text)
if n:
    said.append("the Content-Security-Policy is the pages' own only")
# 1.0.61: the body taken whole by nginx before PHP is asked - handed on as it
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
    if command -v getenforce >/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        say "SELinux is $(getenforce)"
        run setsebool -P httpd_can_network_connect 1 2>/dev/null || warn "could not set httpd_can_network_connect"
        command -v restorecon >/dev/null && run restorecon -R "$WEB_DIR" 2>/dev/null || true
        good "the pages may talk to the daemon on 127.0.0.1"
        note "If the pages say the token is unreadable: ausearch -m avc -ts recent | audit2allow -M acme-local"
    fi
}

# ---------------------------------------------------------------------------
# The program, the account, the folders
# ---------------------------------------------------------------------------
# The Python acme runs on (1.0.97): the newest the distribution offers beside
# its own - python3.14 where AppStream has it (1.0.204), else python3.12 on
# RHEL, Rocky and AlmaLinux 9 (the system's python3 is 3.9) - with the database
# driver for it, and only one that is shown to run acme. From the distribution
# only, never one built or fetched by acme: its security fixes come with the
# system updates. The choice is a link, $LIB_DIR/python, which
# the service and the acme command start; the root helpers stay on the
# system's own python3. --python PATH or --system-python decide instead.
py_mods_wanted() {
    local inuse=""
    inuse="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("db_engine") or "")' \
             "$CONFIG_DIR/config.json" 2>/dev/null || true)"
    case "$inuse $WITH_DB" in *postgres*|*both*) echo psycopg2;; esac
    case "$inuse $WITH_DB" in *mariadb*|*mysql*|*both*) echo pymysql;; esac
}
py_runs_acme() {         # py_runs_acme PYTHON MODULE... -> 0 when it can run acme
    local py="$1"; shift
    [[ -x "$py" ]] || return 1
    "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null || return 1
    "$py" -c 'import ssl, sqlite3, hashlib, json, zipfile; hashlib.scrypt' 2>/dev/null || return 1
    local m
    for m in "$@"; do "$py" -c "import $m" 2>/dev/null || return 1; done
    "$py" "$SOURCE_DIR/acme.py" --version >/dev/null 2>&1
}
runtime_python() {
    step "Python"
    local mods=() cand=() py v m pkg
    mapfile -t mods < <(py_mods_wanted)
    # The choice of --python / --system-python kept for the next upgrade
    # (1.0.147): the pages' upgrade and a plain --upgrade took the newest
    # Python again.
    local kept="$LIB_DIR/python-choice"
    if [[ -n "$PY_FORCE" ]]; then
        [[ -z "$DRY_RUN" ]] && printf '%s\n' "$PY_FORCE" > "$kept"
    elif [[ -n "$PY_SYSTEM" ]]; then
        [[ -z "$DRY_RUN" ]] && printf 'system\n' > "$kept"
    elif [[ -f "$kept" && ! -L "$kept" ]]; then
        local was=""
        was="$(head -n1 "$kept" 2>/dev/null || true)"
        [[ "$was" == "system" ]] && was=/usr/bin/python3
        if [[ "$was" == /* && -x "$was" ]]; then
            # First, and the newest after it should it no longer run acme.
            cand=("$was")
            note "the Python chosen before is tried first: $was (--python PATH or --system-python to change it)"
        fi
    fi
    if [[ ${#cand[@]} -gt 0 ]]; then cand+=(/usr/bin/python3.14 /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3)
    elif [[ -n "$PY_FORCE" ]]; then cand=("$PY_FORCE")
    elif [[ -n "$PY_SYSTEM" ]]; then cand=("/usr/bin/python3")
    else cand=(/usr/bin/python3.14 /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3); fi
    ACME_PY=""
    for py in "${cand[@]}"; do
        v="${py##*/python}"
        if [[ ! -x "$py" && "$v" =~ ^3\.[0-9]+$ && "$PKG" == "dnf" && -z "$DRY_RUN" ]]; then
            dnf install -y "python$v" >/dev/null 2>&1 || true
        fi
        [[ -x "$py" ]] || continue
        for m in "${mods[@]}"; do
            "$py" -c "import $m" 2>/dev/null && continue
            [[ -n "$DRY_RUN" ]] && continue
            case "$m" in psycopg2) pkg=psycopg2;; pymysql) pkg=PyMySQL;; esac
            if [[ "$PKG" == "dnf" ]]; then
                if [[ "$v" =~ ^3\.[0-9]+$ ]]; then dnf install -y "python$v-$pkg" >/dev/null 2>&1 || true
                else dnf install -y "python3-$pkg" >/dev/null 2>&1 || true; fi
            elif [[ "$PKG" == "apt" && ! "$v" =~ ^3\.[0-9]+$ ]]; then
                apt-get install -y "python3-${pkg,,}" >/dev/null 2>&1 || true
            fi
        done
        if [[ -n "$DRY_RUN" ]] || py_runs_acme "$py" "${mods[@]}"; then ACME_PY="$py"; break; fi
        note "$py ($("$py" --version 2>&1)) cannot run acme here (a module missing: ${mods[*]:-none}) - the next one is tried"
    done
    [[ -n "$ACME_PY" ]] || fail "no Python here runs acme${mods[*]:+ with ${mods[*]}} - install python3.14 and python3.14-psycopg2 (or python3.12, python3.12-psycopg2) with dnf, or say which with --python"
    run ln -sfn "$ACME_PY" "$LIB_DIR/python"
    good "acme runs on $("$ACME_PY" --version 2>&1) - $ACME_PY${mods[*]:+ (with ${mods[*]})}"
    if [[ "$ACME_PY" == /usr/bin/python3 && -z "$PY_SYSTEM" && -z "$PY_FORCE" ]] && \
            /usr/bin/python3 -c 'import sys; sys.exit(0 if sys.version_info < (3, 11) else 1)' 2>/dev/null; then
        note "the system's own python3 is used; a newer one (dnf install python3.14 python3.14-psycopg2, or python3.12) is faster, and is taken by the next upgrade"
    fi
}

install_program() {
    step "The daemon"
    run install -D -m 0755 "$SOURCE_DIR/acme.py" "$LIB_DIR/acme.py"
    for extra in INSTALL.md README.md CHANGELOG.md; do
        [[ -f "$SOURCE_DIR/$extra" ]] && run install -D -m 0644 "$SOURCE_DIR/$extra" "$LIB_DIR/$extra"
    done
    for d in docs test deploy; do
        if [[ -d "$SOURCE_DIR/$d" ]]; then
            run rm -rf "$LIB_DIR/$d"
            run cp -r "$SOURCE_DIR/$d" "$LIB_DIR/$d"
        fi
    done
    # The drivers asked for with --with-db kept for the next upgrade (1.0.206): a
    # later --upgrade - one from the pages too - has none, and took a Python
    # without them; the database could no longer be moved from the pages.
    local drivers="$LIB_DIR/db-drivers"
    if [[ -n "$WITH_DB" && -z "$DRY_RUN" ]]; then
        printf '%s\n' "$WITH_DB" > "$drivers" && chmod 600 "$drivers"
    elif [[ -z "$WITH_DB" && -f "$drivers" && ! -L "$drivers" ]]; then
        WITH_DB="$(head -n1 "$drivers" 2>/dev/null | tr -cd 'a-z')"
        [[ -n "$WITH_DB" ]] && note "the database drivers asked for before are kept: $WITH_DB (--with-db to change)"
    fi
    runtime_python
    # The command, on the same Python as the daemon (1.0.97): a link to
    # acme.py ran it on whatever python3 is first in PATH.
    if [[ -z "$DRY_RUN" ]]; then
        rm -f "$BIN_LINK"
        # Imported, not run as a script (1.0.136): its compiled form is kept,
        # so a command no longer spends most of a second compiling acme.py;
        # -I: nothing from the folder it is run in, nor PYTHON* settings.
        printf '#!/bin/sh\n# acme, on the Python install.sh chose (%s/python)\nexec %s/python -I -c '"'"'import sys; sys.path.insert(0, "%s"); sys.argv[0] = "acme"; import acme; acme.entry()'"'"' "$@"\n' \
            "$LIB_DIR" "$LIB_DIR" "$LIB_DIR" > "$BIN_LINK"
        chmod 0755 "$BIN_LINK"
        "$LIB_DIR/python" -I -m py_compile "$LIB_DIR/acme.py" 2>/dev/null || true
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
    run install -d -m 2770 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme.service" "$UNIT_FILE"
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme.logrotate" "$LOGROTATE_FILE"
    install_upgrader
    run systemctl daemon-reload
    if [[ -f "$UPGRADE_PATH_UNIT" ]]; then
        run systemctl enable --now acme-upgrade.path >/dev/null 2>&1 \
            || warn "acme-upgrade.path did not start; upgrades from the pages wait for it"
    fi
    if [[ -f "$WEB_PATH_UNIT" ]]; then
        # Restarted, not only enabled (1.0.52): a path unit that is already
        # running keeps watching what its old file named.
        # One left failed by systemd's start limit (before 1.0.159) watches nothing.
        run systemctl reset-failed acme-web.service acme-web.path >/dev/null 2>&1 || true
        { run systemctl enable acme-web.path >/dev/null 2>&1 && run systemctl restart acme-web.path >/dev/null 2>&1; } \
            || warn "acme-web.path did not start; TLS and the web address from the pages wait for it"
    fi
}

# Upgrades from the pages (1.0.37): root's helper, the keys it trusts, and
# the systemd units that start it when the pages ask. The keys are root's
# alone, in the program's folder - never anywhere the acme account may write.
install_upgrader() {
    [[ -f "$SOURCE_DIR/deploy/acme_upgrade.py" ]] || return 0
    run install -D -m 0755 "$SOURCE_DIR/deploy/acme_upgrade.py" "$LIB_DIR/acme_upgrade.py"
    run install -d -m 0755 -o root -g root "$LIB_DIR/release-keys"
    local k
    for k in "$SOURCE_DIR"/deploy/release-keys/*.pub; do
        [[ -f "$k" ]] && run install -m 0644 -o root -g root "$k" "$LIB_DIR/release-keys/"
    done
    # Exactly the package's keys (1.0.44): one a release no longer ships is
    # trusted no longer.
    compgen -G "$SOURCE_DIR/deploy/release-keys/*.pub" >/dev/null && for k in "$LIB_DIR"/release-keys/*.pub; do
        [[ -f "$k" ]] || continue
        [[ -f "$SOURCE_DIR/deploy/release-keys/$(basename "$k")" ]] || run rm -f "$k"
    done
    acme_subdir "$STATE_DIR/upgrade"
    # How far back this machine may go (1.0.143): the highest floor of every
    # version put in here - an older version's install.sh leaves it as it is,
    # so going back never lowers it. Root's alone.
    local floor new
    new="$(sed -n "s/^DOWNGRADE_FLOOR = '\([0-9.]*\)'.*/\1/p" "$SOURCE_DIR/acme.py" | head -n 1)"
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
    # TLS and the cluster's web address from the pages (1.0.47): root's helper,
    # keepalived's check, and the units that start the helper when asked.
    if [[ -f "$SOURCE_DIR/deploy/acme_web.py" ]]; then
        run install -D -m 0755 "$SOURCE_DIR/deploy/acme_web.py" "$LIB_DIR/acme_web.py"
        run install -D -m 0755 "$SOURCE_DIR/deploy/acme-vip-check" "$LIB_DIR/acme-vip-check"
        # Where keepalived's scripts belong (1.0.47): SELinux lets keepalived
        # run what is in /usr/libexec/keepalived (keepalived_unconfined_script_exec_t),
        # and nothing it would refuse elsewhere.
        run install -D -m 0755 "$SOURCE_DIR/deploy/acme-vip-check" /usr/libexec/keepalived/acme-vip-check
        command -v restorecon >/dev/null 2>&1 && run restorecon -R /usr/libexec/keepalived >/dev/null 2>&1 || true
        acme_subdir "$STATE_DIR/web"
        run install -D -m 0644 "$SOURCE_DIR/deploy/acme-web.service" "$WEB_SERVICE_UNIT"
        run install -D -m 0644 "$SOURCE_DIR/deploy/acme-web.path" "$WEB_PATH_UNIT"
    fi
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme-upgrade.service" "$UPGRADE_SERVICE_UNIT"
    run install -D -m 0644 "$SOURCE_DIR/deploy/acme-upgrade.path" "$UPGRADE_PATH_UNIT"
    good "upgrades from the pages: acme-upgrade.path, packages signed by $(ls "$LIB_DIR/release-keys" 2>/dev/null | sed 's/\.pub$//' | paste -sd, - || true)"
}

as_acme() {             # a command of acme's, as its own account
    if [[ -n "$DRY_RUN" ]]; then note "[would run as $SERVICE_USER] acme $*"; return 0; fi
    runuser -u "$SERVICE_USER" -- env ACME_CONFIG="$CONFIG_FILE" "$BIN_LINK" "$@"
}

restart_daemon() {
    run systemctl reenable acme.service >/dev/null 2>&1 || run systemctl enable acme.service >/dev/null
    run systemctl restart acme.service
    [[ -n "$DRY_RUN" ]] && return 0
    sleep 2
    if systemctl is-active --quiet acme.service; then
        good "acme.service is running"
    else
        warn "it did not start - the last of its log:"
        journalctl -u acme -n 20 --no-pager || true
        fail "sort that out and run this again"
    fi
}

install_colour() {      # colorama: the command line in colour, as isemon's
    # Nothing needs it - without it acme writes the same escape sequences
    # itself - so it is offered and never insisted on.
    if python3 -c 'import colorama' 2>/dev/null; then
        good "python3-colorama is here - the command line is in colour"
        return 0
    fi
    if [[ "$PKG" == "dnf" ]]; then
        run dnf install -y python3-colorama >/dev/null 2>&1 || true
    elif [[ "$PKG" == "apt" ]]; then
        run apt-get install -y python3-colorama >/dev/null 2>&1 || true
    fi
    # Not in the distribution's own repositories (on RHEL 9 it is EPEL's):
    # pip, where there is one, for the system Python.
    if ! python3 -c 'import colorama' 2>/dev/null && python3 -m pip --version >/dev/null 2>&1; then
        run python3 -m pip install --quiet colorama >/dev/null 2>&1 || true
    fi
    if [[ -n "$DRY_RUN" ]] || python3 -c 'import colorama' 2>/dev/null; then
        good "python3-colorama installed - the command line is in colour"
    else
        note "python3-colorama is not available; colour is written by hand instead,"
        note "which works on this terminal and is the only difference."
    fi
}

install_db_drivers() {
    # The engine in use too (1.0.206): moved to PostgreSQL from the pages and
    # upgraded without --with-db, its pg_dump never came - the nightly dumps
    # quietly became the portable copies.
    local inuse0=""
    inuse0="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("db_engine") or "")' \
              "$CONFIG_DIR/config.json" 2>/dev/null || true)"
    [[ -n "$WITH_DB" || "$inuse0" == postgres || "$inuse0" == mariadb ]] || return 0
    step "Database drivers"
    local want=()
    case "$WITH_DB" in
        mariadb|mysql) want=("pymysql:python3-PyMySQL:PyMySQL");;
        postgres|postgresql) want=("psycopg2:python3-psycopg2:psycopg2-binary");;
        both) want=("pymysql:python3-PyMySQL:PyMySQL" "psycopg2:python3-psycopg2:psycopg2-binary");;
    esac
    local one mod pkg pipname
    for one in "${want[@]}"; do
        IFS=: read -r mod pkg pipname <<< "$one"
        if "${ACME_PY:-python3}" -c "import $mod" 2>/dev/null; then good "$mod is already here"; continue; fi
        if [[ "$PKG" == "dnf" ]]; then run dnf install -y "$pkg" || true
        elif [[ "$PKG" == "apt" ]]; then run apt-get install -y "${pkg,,}" || true; fi
        python3 -c "import $mod" 2>/dev/null || run pip3 install $(pip3 install --help 2>/dev/null | grep -q -- --break-system-packages && echo --break-system-packages) "$pipname" || true
        python3 -c "import $mod" 2>/dev/null && good "$mod installed" || warn "$mod could not be installed"
    done
    # The engine's own programs, for the nightly dumps and for putting one
    # back (Settings -> The database -> The dumps it keeps). The clients
    # only, never a server.
    # Only the client of the engine actually in use (the config file says
    # which): --with-db both is for the drivers, so that the pages can move
    # to either - it is not a reason to put the MariaDB client on a machine
    # that runs on PostgreSQL. Switch engines and run --upgrade again, and
    # the other one's client comes. (1.0.11)
    local tools=() inuse=""
    inuse="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("db_engine") or "")' \
             "$CONFIG_DIR/config.json" 2>/dev/null || true)"
    case "$inuse" in
        mariadb) tools=("mariadb-dump:mariadb:mariadb-client");;
        postgres) tools=("pg_dump:postgresql:postgresql-client");;
        *) case "$WITH_DB" in
               mariadb|mysql) tools=("mariadb-dump:mariadb:mariadb-client");;
               postgres|postgresql) tools=("pg_dump:postgresql:postgresql-client");;
           esac;;
    esac
    local bin rpm deb
    for one in "${tools[@]}"; do
        IFS=: read -r bin rpm deb <<< "$one"
        if command -v "$bin" >/dev/null || { [[ "$bin" == mariadb-dump ]] && command -v mysqldump >/dev/null; }; then
            good "$bin is already here"; continue
        fi
        if [[ "$PKG" == "dnf" ]]; then run dnf install -y "$rpm" || true
        elif [[ "$PKG" == "apt" ]]; then run apt-get install -y "$deb" || true; fi
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
    # Remembered where only root writes (1.0.94): every later upgrade - the
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
        # A backup from another machine put back goes this way too (1.0.136):
        # left out, it was refused at 32 MB.
        if grep -q 'api=(db-restore|upgrade-package)(&|\$)' "$NGINX_CONF"; then
            local bak0="$NGINX_BAK_DIR/acme.conf.before-rbackup-upload.$(date +%Y%m%d%H%M%S)"
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
        # Without the question first, nobody may send 4 GB (1.0.149): nginx
        # wrote whatever anybody on the allow list sent to its disk - the
        # database's disk - before the page could refuse it.
        if grep -q 'client_max_body_size 4g;' "$NGINX_CONF"; then
            local bak1="$NGINX_BAK_DIR/acme.conf.before-upload-limit.$(date +%Y%m%d%H%M%S)"
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
    local bak="$NGINX_BAK_DIR/acme.conf.before-upload-guard.$(date +%Y%m%d%H%M%S)"
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
        # Read again now (1.0.103): restarted before the guard was added, nginx
        # answered /admin/upload/ with 404 until something else reloaded it.
        run systemctl reload nginx || warn "nginx could not be reloaded - systemctl reload nginx"
    else
        cp -a "$bak" "$NGINX_CONF"
        warn "nginx did not take the guard for big uploads, so $NGINX_CONF is as it was"
    fi
}

open_firewall() {
    step "The firewall"
    if ! command -v firewall-cmd >/dev/null || ! systemctl is-active --quiet firewalld; then
        warn "firewalld is not running here, so nothing was opened or narrowed."
        note "Whatever filters this machine must let through: TCP 443 (and 80) to the pages,"
        note "UDP 1812 and 1813 from the VPN concentrators${RADIUS_FROM:+ ($RADIUS_FROM)}."
        return 0
    fi
    if [[ -n "$WITH_WEB" ]]; then
        run firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
        run firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
        good "https (and http, which only sends to https) are open"
    fi
    if [[ -n "$RADIUS_FROM" ]]; then
        IFS=',' read -r -a srcs <<< "$RADIUS_FROM"
        for one in "${srcs[@]}"; do
            one="$(echo "$one" | xargs)"; [[ -z "$one" ]] && continue
            # this machine's own packets never meet the firewall
            [[ "$one" == 127.* || "$one" == "::1" || "$one" == "::1/128" ]] && continue
            for port in 1812 1813; do
                run firewall-cmd --permanent --add-rich-rule="rule family=$( [[ "$one" == *:* ]] && echo ipv6 || echo ipv4 ) source address=$one port port=$port protocol=udp accept" >/dev/null 2>&1 || true
            done
        done
        good "RADIUS (UDP 1812, 1813) is open to: $RADIUS_FROM"
    else
        run firewall-cmd --permanent --add-port=1812/udp >/dev/null 2>&1 || true
        run firewall-cmd --permanent --add-port=1813/udp >/dev/null 2>&1 || true
        warn "RADIUS (UDP 1812, 1813) is open to anybody: --radius-from narrows it."
        note "acme answers nothing but its clients either way."
    fi
    run firewall-cmd --reload >/dev/null 2>&1 || true
}

# ===========================================================================
# An upgrade: the program, the pages, PHP - and nothing else
# ===========================================================================

# ---------------------------------------------------------------------------
# From opt to acme (1.0.37). Up to 1.0.36 this program was installed as "opt":
# /usr/local/lib/opt, /var/lib/opt, /etc/opt-acme, opt.service, the accounts
# opt, opt-web and opt-www. All of it is renamed here, once; the databases'
# own names are renamed by  acme --rename-from-opt  further on.
# ---------------------------------------------------------------------------
MIGRATED=""
migrate_from_opt() {
    local old_lib=/usr/local/lib/opt
    [[ -f "$old_lib/opt.py" || -f /etc/systemd/system/opt.service || -d /var/lib/opt || -d /etc/opt-acme ]] || return 0
    step "From opt to acme - the new name, everywhere"
    if [[ -n "$DRY_RUN" ]]; then
        note "[would rename] opt.service, /usr/local/lib/opt, /var/lib/opt, /etc/opt-acme, /var/log/opt, /var/www/opt, the accounts opt, opt-web, opt-www, and the database's names"
        MIGRATED=yes
        return 0
    fi
    [[ -d /var/lib/opt && -d "$STATE_DIR" ]] && fail "both /var/lib/opt and $STATE_DIR are here: look at them and keep one before running this again"
    [[ -d /etc/opt-acme && -d "$CONFIG_DIR" && -n "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]] && fail "both /etc/opt-acme and $CONFIG_DIR are here: keep one before running this again"
    local u
    for u in opt.service opt-upgrade.path opt-upgrade.service; do
        systemctl stop "$u" >/dev/null 2>&1 || true
        systemctl disable "$u" >/dev/null 2>&1 || true
    done
    rm -f /etc/systemd/system/opt.service /etc/systemd/system/opt-upgrade.path /etc/systemd/system/opt-upgrade.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    good "opt.service is stopped and gone; acme.service takes its place"
    # The accounts: renamed, so every file keeps its owner (the numbers stay).
    # Nothing may run as them meanwhile: php-fpm runs the pages as opt-www,
    # and is started again with the new pool further on.
    for u in $(php_fpm_units); do systemctl stop "$u" >/dev/null 2>&1 || true; done
    if id opt >/dev/null 2>&1 && ! id "$SERVICE_USER" >/dev/null 2>&1; then
        usermod -l "$SERVICE_USER" opt || fail "the account opt could not be renamed - is something still running as it?  ps -u opt"
        getent group opt >/dev/null && ! getent group "$SERVICE_USER" >/dev/null && groupmod -n "$SERVICE_USER" opt
        usermod -d "$STATE_DIR" "$SERVICE_USER" >/dev/null 2>&1 || true
        good "the account opt is now $SERVICE_USER"
    fi
    if getent group opt-web >/dev/null && ! getent group "$WEB_GROUP" >/dev/null; then
        groupmod -n "$WEB_GROUP" opt-web
        good "the group opt-web is now $WEB_GROUP"
    fi
    if id opt-www >/dev/null 2>&1 && ! id "$POOL_USER" >/dev/null 2>&1; then
        usermod -l "$POOL_USER" opt-www || fail "the account opt-www could not be renamed - is something still running as it?  ps -u opt-www"
        getent group opt-www >/dev/null && ! getent group "$POOL_USER" >/dev/null && groupmod -n "$POOL_USER" opt-www
        usermod -d "$WEB_DIR" "$POOL_USER" >/dev/null 2>&1 || true
        good "the account opt-www is now $POOL_USER"
    fi
    # The folders.
    if [[ -d /var/lib/opt ]]; then
        mv /var/lib/opt "$STATE_DIR"
        local x
        for x in "" -wal -shm; do
            [[ -f "$STATE_DIR/opt.db$x" ]] && mv "$STATE_DIR/opt.db$x" "$STATE_DIR/acme.db$x"
        done
        rm -f "$STATE_DIR/opt.lock"
        good "/var/lib/opt is now $STATE_DIR"
    fi
    if [[ -d /var/log/opt ]]; then
        if [[ -d "$LOG_DIR" ]]; then cp -a /var/log/opt/. "$LOG_DIR"/ && rm -rf /var/log/opt; else mv /var/log/opt "$LOG_DIR"; fi
        local f
        for f in "$LOG_DIR"/opt.log*; do [[ -e "$f" ]] && mv "$f" "$LOG_DIR/acme.log${f#"$LOG_DIR"/opt.log}"; done
        good "/var/log/opt is now $LOG_DIR"
    fi
    if [[ -d /etc/opt-acme ]]; then
        if [[ -d "$CONFIG_DIR" ]]; then rmdir "$CONFIG_DIR"; fi
        mv /etc/opt-acme "$CONFIG_DIR"
        [[ -f "$CONFIG_DIR/config.json" ]] && sed -i 's#/etc/opt-acme/#/etc/acme/#g' "$CONFIG_DIR/config.json"
        rm -f "$CONFIG_DIR/may-restart-database"
        good "/etc/opt-acme is now $CONFIG_DIR"
    fi
    # The program, the pages and what was around them go; this version's come in.
    rm -f /usr/local/bin/opt
    [[ "$(readlink /usr/local/bin/acme 2>/dev/null || true)" == "$old_lib/opt.py" ]] && rm -f /usr/local/bin/acme
    rm -rf "$old_lib" /var/www/opt
    rm -f /etc/logrotate.d/opt /etc/polkit-1/rules.d/49-opt-database.rules
    rm -f /etc/php-fpm.d/opt.conf /etc/php/*/fpm/pool.d/opt.conf
    if [[ -f /etc/nginx/conf.d/opt.conf ]]; then
        if [[ ! -f "$NGINX_CONF" ]]; then
            # The administrator's file, with its host name and allow lists,
            # under the new name and pointing at the new places.
            sed -e 's#/var/www/opt\b#/var/www/acme#g' -e 's#/run/php-fpm/opt\.sock#/run/php-fpm/acme.sock#g' \
                -e 's#/run/php/opt\.sock#/run/php/acme.sock#g' -e 's#/var/log/nginx/opt-#/var/log/nginx/acme-#g' \
                -e 's#opt_login#acme_login#g' -e 's#opt_all#acme_all#g' -e 's#shared:OPT:#shared:ACME:#g' \
                -e 's#(opt [0-9.]*)#(acme)#g' \
                /etc/nginx/conf.d/opt.conf > "$NGINX_CONF"
        fi
        mv /etc/nginx/conf.d/opt.conf /etc/nginx/opt.conf.before-acme
        # The certificate and its key, under the new names too.
        local ext
        for ext in pem key; do
            if [[ -f "$CERT_DIR/opt.$ext" && ! -f "$CERT_DIR/acme.$ext" ]]; then
                mv "$CERT_DIR/opt.$ext" "$CERT_DIR/acme.$ext"
            fi
        done
        sed -i -e "s#$CERT_DIR/opt\.pem#$CERT_DIR/acme.pem#g" -e "s#$CERT_DIR/opt\.key#$CERT_DIR/acme.key#g" "$NGINX_CONF"
        good "nginx: /etc/nginx/conf.d/opt.conf is now $NGINX_CONF (the old one is /etc/nginx/opt.conf.before-acme)"
    fi
    MIGRATED=yes
    DO_UPGRADE=yes
}

# The programs backups to another machine use (1.0.109): ssh, sftp and scp for
# SFTP and SCP, smbclient for a Windows or Samba share. Best effort: without
# them those destinations say what is missing, everything else works.
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
        apt-get install -y "${deb[@]}" >/dev/null 2>&1 || warn "for backups: apt-get install ${deb[*]}"
    fi
}

# The clock (1.0.122): codes from the app are worked out from it, so chrony
# is put in and started on a fresh install and on every upgrade, wherever it
# is missing or stopped. Its own /etc/chrony.conf (AlmaLinux's pool) is used
# as it is; Settings → Time sets other servers when asked.
install_time_tools() {
    local unit=chronyd
    [[ "$PKG" == "apt" ]] && unit=chrony
    if ! command -v chronyd >/dev/null && ! command -v chronyc >/dev/null; then
        if [[ -n "$DRY_RUN" ]]; then say "would install chrony (the clock)"; return 0; fi
        if [[ "$PKG" == "dnf" ]]; then
            dnf install -y chrony >/dev/null 2>&1 || { warn "chrony could not be installed: dnf install chrony - codes from the app depend on the clock"; return 0; }
        elif [[ "$PKG" == "apt" ]]; then
            apt-get install -y chrony >/dev/null 2>&1 || { warn "chrony could not be installed: apt-get install chrony"; return 0; }
        else
            warn "install chrony by hand - codes from the app depend on the clock"; return 0
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

# The acme console at login (1.0.130): root signing in at the console or over
# SSH lands in `acme --console`; q leaves it for the shell. On unless switched
# off (`acme --console-at-login off`), which an upgrade leaves as it is.
install_console() {
    if [[ -n "$DRY_RUN" ]]; then note "[would write] /etc/profile.d/zz-acme-console.sh"; return 0; fi
    install -m 0644 "$SOURCE_DIR/deploy/acme-console-login.sh" /etc/profile.d/zz-acme-console.sh
    # The choice is kept in /etc itself (1.0.136), where only root writes -
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
    good "the acme console at login: $(head -c 4 "$flag") (acme --console-at-login on|off)"
}

migrate_from_opt

if [[ -n "$DO_UPGRADE" ]]; then
    step "Upgrading acme to $VERSION"
    id "$SERVICE_USER" >/dev/null 2>&1 || fail "acme is not installed here; run this without --upgrade"
    install_backup_tools
    install_time_tools
    install_console
    # This node out of service while it is done (1.0.37): the balancer and
    # the VPN go to the other node first, not after a request has gone
    # unanswered. Asked for on the pages, the daemon has done it already.
    MAINT_BY_US=""
    if [[ -z "${ACME_UPGRADE_FROM_PAGES:-}" && -z "$DRY_RUN" ]] && systemctl is-active --quiet acme.service; then
        if as_acme --maintenance status >/dev/null 2>&1; then
            if as_acme --maintenance on --why "install.sh --upgrade to $VERSION" >/dev/null 2>&1; then
                MAINT_BY_US=yes
                good "this node is in maintenance while it is upgraded"
                if [[ "$(as_acme --ha-status --json 2>/dev/null | python3 -c 'import json,sys
try:
    print(sum(1 for n in json.load(sys.stdin).get("nodes", []) if n.get("alive")))
except Exception:
    print(0)' 2>/dev/null)" -gt 1 ]]; then
                    say "waiting 20 s for the load balancer and the VPN to notice"
                    sleep 20
                fi
            fi
        fi
    fi
    # Whatever stops the upgrade from here on (1.0.44): the daemon is started
    # again and the node comes back into service, rather than staying out
    # with half of it done.
    UPGRADE_STAGE=started
    upgrade_rescue() {
        local rc=$?
        [[ "${UPGRADE_STAGE:-}" == started && $rc -ne 0 && -z "$DRY_RUN" ]] || return 0
        warn "the upgrade stopped half way (exit $rc); the daemon is started again as it is"
        systemctl restart acme.service >/dev/null 2>&1 || true
        if [[ -n "$MAINT_BY_US" ]]; then
            sleep 3
            as_acme --maintenance off >/dev/null 2>&1 && warn "this node is back in service - look at what stopped the upgrade"
        fi
    }
    trap upgrade_rescue EXIT
    # Stopped by a signal (1.0.146) - Ctrl-C, a hang-up, acme_upgrade.py's TERM
    # at its deadline - the exit status was 0 and the rescue did nothing:
    # the node stayed in maintenance.
    trap 'exit 130' INT
    trap 'exit 129' HUP
    trap 'exit 143' TERM
    # A machine installed without the pages is upgraded without them
    # (1.0.44): --upgrade from the pages cannot say --no-web.
    if [[ -n "$WITH_WEB" && ! -e "$NGINX_CONF" && ! -d "$WEB_DIR" ]]; then
        WITH_WEB=""
        note "no pages were installed here (no $NGINX_CONF, no $WEB_DIR): the daemon alone is upgraded"
    fi
    install_program
    install_db_drivers
    if [[ -n "$MIGRATED" ]]; then
        step "The database's names"
        if [[ -n "$DRY_RUN" ]]; then
            note "[would run] acme --rename-from-opt"
        else
            ACME_CONFIG="$CONFIG_FILE" "$LIB_DIR/python" "$LIB_DIR/acme.py" --rename-from-opt \
                || warn "the database's names could not all be changed; it goes on under the old ones"
            # Not through a link (1.0.94): only the file itself, as it is.
            [[ -f "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] && chown -h root:"$SERVICE_USER" "$CONFIG_FILE" 2>/dev/null || true
        fi
    fi
    install_db_restart
    install_colour
    if [[ -n "$WITH_WEB" ]]; then
        ensure_php
        install_pages
    fi
    restart_daemon
    UPGRADE_STAGE=done
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
    exit 0
fi

# ===========================================================================
# A fresh install
# ===========================================================================
step "Looking at this machine"
say "${OS_PRETTY:-unknown}"
[[ -n "$PKG" ]] || warn "I do not recognise this distribution; no packages will be installed."
python3 --version >/dev/null 2>&1 || fail "python3 is not installed"
say "$(python3 --version)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
    || fail "this Python is too old; acme needs 3.8 or newer"
if ss -ulnp 2>/dev/null | grep -qE ':1812\b'; then
    who="$(ss -ulnp 2>/dev/null | sed -n '/:1812\b/s/.*users:(("\([^"]*\)".*/\1/p' | head -1 || true)"
    if [[ "$who" == "radiusd" || "$who" == "freeradius" ]]; then
        warn "FreeRADIUS ($who) holds UDP 1812. acme answers RADIUS itself and needs the port."
        if confirm "Stop and disable $who?" y; then
            run systemctl disable --now radiusd 2>/dev/null || run systemctl disable --now freeradius 2>/dev/null || true
        fi
    elif [[ -n "$who" && "$who" != "python3" ]]; then
        warn "$who holds UDP 1812; acme will not be able to listen there until it lets go"
    fi
fi

step "Packages"
need=()
command -v openssl >/dev/null || need+=("openssl")
command -v runuser >/dev/null || need+=("util-linux")
if [[ -n "$WITH_WEB" ]]; then
    command -v nginx >/dev/null || need+=("nginx")
fi
if ((${#need[@]})); then
    say "missing: ${need[*]}"
    if [[ "$PKG" == "dnf" ]]; then run dnf install -y "${need[@]}"
    elif [[ "$PKG" == "apt" ]]; then run apt-get update && run apt-get install -y "${need[@]}"
    else fail "install these by hand and run this again: ${need[*]}"; fi
else
    good "everything needed is already here"
fi
install_backup_tools
install_time_tools
install_console
install_db_drivers
install_db_restart
install_colour
# In an if, not after && (1.0.146): a function called after && runs with
# errexit off, and a failure inside it went by unnoticed.
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
        ask PORTAL_ALLOW "Who may reach the enrolment pages (CIDRs, empty = RFC 1918)"
    fi
    ask RADIUS_FROM "Who sends RADIUS - the VPN concentrators (CIDRs, empty = anybody)"
    ask ISEMON_TARGET "isemon's syslog receiver, host[:port][/tcp] (empty = none for now)"
    if [[ -n "$ISEMON_TARGET" ]]; then
        ask ISEMON_HOSTNAME "The name isemon files this server under" "acme"
    fi
    ask ADMIN_USER "The first account of the administration pages"
    ask_secret ADMIN_PASSWORD "Its password (empty = make one and print it)"
fi
for v in ADMIN_ALLOW PORTAL_ALLOW RADIUS_FROM; do
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
    # Made beside it and put in its place (1.0.146): /etc/acme is the acme
    # account's to write, and a link it put there for config.json was
    # followed by root - a file of root's anywhere made the acme group's.
    # Made, its owner and mode set on the open file itself, never by name
    # (1.0.147): a link put in place of the name between the steps was
    # followed by chmod and chown.
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
fi

if [[ -n "$LEGACY_ROOT" ]]; then
    step "Bringing the old server over"
    [[ -d "$LEGACY_ROOT" ]] || fail "$LEGACY_ROOT is not a folder"
    # Read as root (the old files are often root's alone), written as acme.
    if [[ -n "$DRY_RUN" ]]; then
        note "[would import] $LEGACY_ROOT"
    else
        tmp="$(mktemp -d)"
        # A copy that broke off is not imported half (1.0.36).
        if cp -a "$LEGACY_ROOT"/. "$tmp/" && chown -R "$SERVICE_USER" "$tmp" && chmod -R u+rX "$tmp"; then
            as_acme --import-legacy "$tmp" || warn "the import said something went wrong; see above"
        else
            warn "$LEGACY_ROOT could not be copied whole, so nothing was imported"
        fi
        rm -rf "$tmp"
    fi
fi

step "A RADIUS client for testing from this machine"
if [[ -z "$DRY_RUN" ]]; then
    if as_acme --clients --json 2>/dev/null | python3 -c 'import json,sys
rows = json.load(sys.stdin)
import ipaddress
sys.exit(0 if any(ipaddress.ip_address("127.0.0.1") in ipaddress.ip_network(r["address"], strict=False) for r in rows) else 1)'; then
        good "there is a client for 127.0.0.1 already"
    else
        TEST_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
        ACME_SECRET="$TEST_SECRET" as_acme --add-client localhost --address 127.0.0.1 --secret - \
            --note "for radtest and the Test page, from this machine" >/dev/null
        good "localhost (127.0.0.1), secret $TEST_SECRET"
        note "radtest NAME CODE 127.0.0.1 0 $TEST_SECRET   - or simply:  acme --radtest NAME CODE"
    fi
fi

if [[ -n "$ISEMON_TARGET" ]]; then
    as_acme --set isemon=1 --set "isemon_targets=$ISEMON_TARGET" \
        --set "isemon_hostname=${ISEMON_HOSTNAME:-acme}" >/dev/null && good "the logs go to isemon at $ISEMON_TARGET"
fi

step "The service"
restart_daemon

if [[ -n "$WITH_WEB" ]]; then install_pages; fi
open_firewall

step "Does it work"
as_acme --status || true
if [[ -n "$WITH_WEB" && -z "$DRY_RUN" ]]; then
    code_admin="$(curl --noproxy '*' -k -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:443:127.0.0.1" "https://$SERVER_NAME/admin/" || true)"
    code_multi="$(curl --noproxy '*' -k -s -o /dev/null -w '%{http_code}' --resolve "$SERVER_NAME:443:127.0.0.1" -F a=b "https://$SERVER_NAME/admin/" || true)"
    [[ "$code_admin" == "200" ]] && good "https://$SERVER_NAME/admin/ answers" || warn "https://$SERVER_NAME/admin/ answered $code_admin"
    [[ "$code_multi" == "403" ]] && good "a multipart body is refused (php2shell)" || warn "a multipart body was answered $code_multi, not 403"
    php_says
fi

step "Done"
say "The enrolment pages:      https://$SERVER_NAME/"
say "The administration pages: https://$SERVER_NAME/admin/"
say "Next: Settings -> Active Directory, Realms and Clients (or acme --help), then"
say "      acme --enroll somebody@example.cz  and  acme --radtest somebody 123456"
[[ -n "$ISEMON_TARGET" ]] && say "On the isemon machine: deploy/isemon/11-acme.conf into /etc/rsyslog.d/, and"
[[ -n "$ISEMON_TARGET" ]] && say "      Settings -> The ACME logs switched on, with RADIUS detail."
exit 0
