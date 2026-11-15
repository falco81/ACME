# shellcheck shell=bash
# deploy/db-server.sh - a database server of its own for acme, and its agent (1.0.113).
#
# Sourced by install.sh for  --db-server postgres|mariadb  and  --db-agent  (never on its
# normal path): it uses install.sh's run, step, say, note, good, warn, fail, confirm, PKG,
# OS_ID, OS_MAJOR, DRY_RUN and ASSUME_YES. docs/external-database.md says what it does.
#
#   --db-server postgres   PostgreSQL 16 (EL 9/10: the postgresql:16 module or PGDG; Debian 12,
#                          Ubuntu 22.04/24.04: PGDG's apt repository), initialised, enabled and
#                          started; listen_addresses, wal_level = logical and what replicated HA
#                          needs; the database and the account acme; pg_hba.conf and the
#                          firewall for the acme nodes given; the agent; a join code.
#   --db-server mariadb    the distribution's MariaDB server, secured (no anonymous accounts,
#                          no test database, root only on this machine), the database and the
#                          account for the acme nodes given; the agent; a join code.
#   --db-agent             the agent alone, for a server installed already.
#   ... --uninstall        the agent taken away (the database server and its data stay).
#
# Run again, it changes only what is not as it should be (idempotent); --dry-run says what it
# would do and changes nothing.

AGENT_LIB="/usr/local/lib/acme-db-agent"
AGENT_ETC="/etc/acme-db-agent"
AGENT_STATE="/var/lib/acme-db-agent"
AGENT_LOG="/var/log/acme-db-agent"
AGENT_USER="acme-db-agent"
AGENT_UNIT="/etc/systemd/system/acme-db-agent.service"
PG_WANT=16

dbs_systemd() { [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; }

dbs_ip_ok() {      # a plain IPv4 or IPv6 address - python3 may not be here yet
    local a="$1" o
    if [[ "$a" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
        return 0
    fi
    [[ "$a" =~ ^[0-9A-Fa-f:]{2,39}$ && "$a" == *:*:* ]]
}

dbs_check_args() {
    local a
    case "${DB_SERVER:-}" in ""|postgres|mariadb) ;; *) fail "--db-server takes postgres or mariadb";; esac
    [[ "$DB_AGENT_PORT" =~ ^[0-9]{1,5}$ ]] && (( DB_AGENT_PORT > 0 && DB_AGENT_PORT < 65536 )) \
        || fail "--db-agent-port takes a port number"
    for a in $ACME_NODES; do dbs_ip_ok "$a" || fail "--acme-node takes plain addresses (192.0.2.10), not $a"; done
    [[ "$DBS_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] || fail "--db-name is letters, digits and _"
    [[ "$DBS_USER" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]] || fail "--db-user is letters, digits and _"
    case "${DBS_USER,,}" in postgres|root|mysql|replication|all|pg_*) fail "--db-user $DBS_USER is the server's own";; esac
    case "${DBS_NAME,,}" in postgres|template0|template1|mysql|sys|all) fail "--db-name $DBS_NAME is the server's own";; esac
    if [[ -n "$DBS_PASSWORD" ]]; then
        [[ "$DBS_PASSWORD" =~ ^[!-~]{8,128}$ && "$DBS_PASSWORD" != *"'"* && "$DBS_PASSWORD" != *'\'* ]] \
            || fail "--db-password is 8 to 128 printable characters, without ' and \\"
    fi
}

# ---- PostgreSQL 16 ---------------------------------------------------------------------
PG_BIN=""; PG_UNIT=""; PG_DATA=""

pg_find() {
    PG_BIN=""; PG_UNIT=""; PG_DATA=""
    local d
    for d in "/usr/pgsql-$PG_WANT/bin" "/usr/lib/postgresql/$PG_WANT/bin"; do
        [[ -x "$d/pg_ctl" ]] && { PG_BIN="$d"; break; }
    done
    if [[ -z "$PG_BIN" ]] && command -v pg_ctl >/dev/null 2>&1; then
        PG_BIN="$(dirname "$(command -v pg_ctl)")"
    fi
    if [[ -z "$PG_BIN" && -x /usr/bin/postgres ]]; then PG_BIN=/usr/bin; fi
    if [[ -d "/usr/pgsql-$PG_WANT" ]]; then
        PG_UNIT="postgresql-$PG_WANT"; PG_DATA="/var/lib/pgsql/$PG_WANT/data"
    elif [[ -x /usr/bin/postgresql-setup ]]; then
        PG_UNIT="postgresql"; PG_DATA="/var/lib/pgsql/data"
    elif [[ -d "/etc/postgresql/$PG_WANT/main" || -x "/usr/lib/postgresql/$PG_WANT/bin/postgres" ]]; then
        PG_UNIT="postgresql@$PG_WANT-main"; PG_DATA="/var/lib/postgresql/$PG_WANT/main"
    fi
}

pg_major_installed() {
    local v
    [[ -n "$PG_BIN" && -x "$PG_BIN/postgres" ]] || { echo 0; return; }
    v="$("$PG_BIN/postgres" --version 2>/dev/null | sed -n 's/.* \([0-9][0-9]*\)\..*/\1/p')"
    echo "${v:-0}"
}

pg_install() {
    pg_find
    if [[ "$(pg_major_installed)" -ge "$PG_WANT" ]]; then
        good "PostgreSQL $(pg_major_installed) is installed ($PG_BIN)"
        return
    fi
    step "Installing PostgreSQL $PG_WANT"
    case "$PKG" in
        dnf)
            if [[ "${OS_MAJOR:-9}" == "9" ]] && dnf -q module list postgresql 2>/dev/null | grep -q "^postgresql *$PG_WANT"; then
                say "AppStream's postgresql:$PG_WANT module"
                run dnf -y -q module reset postgresql
                run dnf -y -q module enable "postgresql:$PG_WANT"
                run dnf -y -q install postgresql-server postgresql postgresql-contrib
            elif [[ "${OS_MAJOR:-9}" -ge 10 ]] && dnf -q info postgresql-server 2>/dev/null | grep -q "^Version *: *$PG_WANT\."; then
                say "AppStream's PostgreSQL $PG_WANT"
                run dnf -y -q install postgresql-server postgresql postgresql-contrib
            else
                say "PostgreSQL's own repository (PGDG)"
                run dnf -y -q install "https://download.postgresql.org/pub/repos/yum/reporpms/EL-${OS_MAJOR:-9}-$(uname -m)/pgdg-redhat-repo-latest.noarch.rpm"
                [[ "${OS_MAJOR:-9}" == "9" ]] && run dnf -y -q module disable postgresql
                run dnf -y -q install "postgresql$PG_WANT-server" "postgresql$PG_WANT" "postgresql$PG_WANT-contrib"
            fi
            ;;
        apt)
            apt_update_once
            if apt-cache policy "postgresql-$PG_WANT" 2>/dev/null | grep -q 'Candidate: [0-9]'; then
                # The distribution's own is $PG_WANT (Ubuntu 24.04): taken as it is.
                say "the distribution's postgresql-$PG_WANT"
            else
                say "PostgreSQL's own apt repository (PGDG)"
                run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q postgresql-common ca-certificates gnupg curl
                if [[ ! -f /etc/apt/sources.list.d/pgdg.list && ! -f /etc/apt/sources.list.d/pgdg.sources ]]; then
                    run env DEBIAN_FRONTEND=noninteractive /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
                fi
            fi
            run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "postgresql-$PG_WANT" "postgresql-client-$PG_WANT"
            ;;
        *) fail "this system is neither EL 9/10 nor Debian/Ubuntu: install PostgreSQL $PG_WANT yourself, then  install.sh --db-agent";;
    esac
    [[ -n "$DRY_RUN" ]] && return
    pg_find
    [[ "$(pg_major_installed)" -ge "$PG_WANT" ]] || fail "PostgreSQL $PG_WANT did not install"
    good "PostgreSQL $(pg_major_installed) installed"
}

pg_initdb_start() {
    [[ -n "$DRY_RUN" && -z "$PG_UNIT" ]] && { note "[would initialise and start PostgreSQL]"; return; }
    if [[ ! -f "$PG_DATA/PG_VERSION" ]]; then
        step "Initialising PostgreSQL ($PG_DATA)"
        if [[ "$PG_UNIT" == "postgresql-$PG_WANT" ]]; then
            run env PGSETUP_INITDB_OPTIONS="-E UTF8 --locale=C.UTF-8 --auth-local=peer --auth-host=scram-sha-256" "/usr/pgsql-$PG_WANT/bin/postgresql-$PG_WANT-setup" initdb
        elif [[ "$PG_UNIT" == "postgresql" ]]; then
            run env PGSETUP_INITDB_OPTIONS="-E UTF8 --locale=C.UTF-8 --auth-local=peer --auth-host=scram-sha-256" postgresql-setup --initdb
        else
            run pg_createcluster "$PG_WANT" main -- -E UTF8 --locale=C.UTF-8 --auth-local=peer --auth-host=scram-sha-256
        fi
    else
        good "PostgreSQL's data folder is there ($PG_DATA)"
    fi
    if dbs_systemd; then
        run systemctl enable --now "$PG_UNIT" >/dev/null 2>&1 || run systemctl enable --now "$PG_UNIT"
    else
        warn "systemd is not running here: PostgreSQL is started directly (enable $PG_UNIT once it is)"
        if [[ "$PG_UNIT" == postgresql@* ]]; then
            run pg_ctlcluster "$PG_WANT" main start 2>/dev/null 9>&- || true
        else
            run runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_DATA/startup.log" -w start 2>/dev/null 9>&- || true
        fi
    fi
    [[ -n "$DRY_RUN" ]] && return
    local i
    for i in $(seq 30); do pg_psql postgres "SELECT 1" >/dev/null 2>&1 && { good "PostgreSQL answers"; return; }; sleep 1; done
    fail "PostgreSQL does not answer after its start (journalctl -u $PG_UNIT)"
}

pg_psql() {     # pg_psql DB SQL - as postgres, on its socket
    runuser -u postgres -- psql -XAtq -v ON_ERROR_STOP=1 -d "$1" -c "$2"
}

pg_set() {      # pg_set NAME VALUE - ALTER SYSTEM when it is not so; 1 when changed
    local now
    now="$(pg_psql postgres "SHOW $1" 2>/dev/null || true)"
    if [[ "$now" == "$2" ]]; then return 1; fi
    run pg_psql postgres "ALTER SYSTEM SET $1 = '$2'" >/dev/null
    say "$1 = $2 (was ${now:-?})"
    return 0
}

pg_configure() {
    step "PostgreSQL for acme"
    local restart="" pwd_made="" a line hba net
    if [[ -n "$DRY_RUN" && -z "$(pg_psql postgres 'SELECT 1' 2>/dev/null)" ]]; then
        note "[would set listen_addresses = '*', wal_level = logical, max_slot_wal_keep_size = 16GB]"
        note "[would make the account $DBS_USER (REPLICATION, pg_create_subscription) and the database $DBS_NAME]"
        note "[would let ${ACME_NODES:-no acme node yet} into $DBS_NAME in pg_hba.conf (scram-sha-256)]"
        return
    fi
    pg_set listen_addresses '*' && restart=yes
    pg_set wal_level logical && restart=yes
    pg_set max_slot_wal_keep_size 16GB || true
    if [[ "$(pg_psql postgres "SELECT 1 FROM pg_roles WHERE rolname = '$DBS_USER'")" != "1" ]]; then
        if [[ -z "$DBS_PASSWORD" ]]; then
            DBS_PASSWORD="$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))')"
            pwd_made=yes
        fi
        run pg_psql postgres "SET log_statement = 'none'; CREATE ROLE \"$DBS_USER\" LOGIN PASSWORD '$DBS_PASSWORD'" >/dev/null
        good "the account $DBS_USER was made"
    elif [[ -n "$DBS_PASSWORD" ]]; then
        run pg_psql postgres "SET log_statement = 'none'; ALTER ROLE \"$DBS_USER\" LOGIN PASSWORD '$DBS_PASSWORD'" >/dev/null
        good "the account $DBS_USER has the password given"
    else
        good "the account $DBS_USER is there (its password is left as it is)"
    fi
    run pg_psql postgres "ALTER ROLE \"$DBS_USER\" REPLICATION" >/dev/null
    run pg_psql postgres "GRANT pg_create_subscription TO \"$DBS_USER\"" >/dev/null
    if [[ "$(pg_psql postgres "SELECT 1 FROM pg_database WHERE datname = '$DBS_NAME'")" != "1" ]]; then
        run pg_psql postgres "CREATE DATABASE \"$DBS_NAME\" OWNER \"$DBS_USER\" ENCODING 'UTF8' TEMPLATE template0 LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'" >/dev/null \
            || run pg_psql postgres "CREATE DATABASE \"$DBS_NAME\" OWNER \"$DBS_USER\" ENCODING 'UTF8' TEMPLATE template0" >/dev/null
        good "the database $DBS_NAME was made"
    else
        good "the database $DBS_NAME is there"
    fi
    run pg_psql postgres "GRANT CREATE ON DATABASE \"$DBS_NAME\" TO \"$DBS_USER\"" >/dev/null
    hba="$(pg_psql postgres 'SHOW hba_file')"
    for a in $ACME_NODES; do
        case "$a" in *:*) net="$a/128";; *) net="$a/32";; esac
        if awk -v d="$DBS_NAME" -v u="$DBS_USER" -v n="$net" '($1=="host"||$1=="hostssl") && $2==d && $3==u && $4==n {f=1} END {exit !f}' "$hba"; then
            good "pg_hba.conf lets $a in already"
            continue
        fi
        line="host    $DBS_NAME    $DBS_USER    $net    scram-sha-256"
        if [[ -n "$DRY_RUN" ]]; then note "[would put in front of $hba] $line"; continue; fi
        cp -p "$hba" "$hba.acme-before-install"
        { printf '# acme node %s (install.sh --db-server, %s)\n%s\n' "$a" "$(date +%F)" "$line"; cat "$hba.acme-before-install"; } > "$hba.acme-new"
        chown --reference="$hba" "$hba.acme-new"; chmod --reference="$hba" "$hba.acme-new"
        mv -f "$hba.acme-new" "$hba"
        good "pg_hba.conf: $line"
    done
    [[ -z "$DRY_RUN" ]] && pg_psql postgres "SELECT pg_reload_conf()" >/dev/null
    if [[ -n "$restart" ]]; then
        say "PostgreSQL starts again for listen_addresses / wal_level"
        if dbs_systemd; then run systemctl restart "$PG_UNIT"
        elif [[ "$PG_UNIT" == postgresql@* ]]; then run pg_ctlcluster "$PG_WANT" main restart 9>&-
        else run runuser -u postgres -- "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_DATA/startup.log" -w -m fast restart 9>&-; fi
        local i
        for i in $(seq 30); do pg_psql postgres "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
    fi
    [[ -z "$DRY_RUN" ]] && good "wal_level = $(pg_psql postgres 'SHOW wal_level'), listen_addresses = $(pg_psql postgres 'SHOW listen_addresses')"
    if [[ -n "$pwd_made" ]]; then
        say "${C_BAD}the password of $DBS_USER, shown only now:${C_OFF} $DBS_PASSWORD"
        say "(on the acme node: acme --db-move postgres --db-host THIS-SERVER, with this password)"
    fi
    DBS_PORT="$(pg_psql postgres 'SHOW port' 2>/dev/null || echo 5432)"
}

# ---- MariaDB ------------------------------------------------------------------------------
my_q() { mariadb --protocol=socket -u root -N -B -e "$1"; }

my_install() {
    if command -v mariadbd >/dev/null 2>&1 || [[ -x /usr/libexec/mariadbd || -x /usr/sbin/mariadbd ]]; then
        good "MariaDB's server is installed"
    else
        step "Installing MariaDB's server"
        case "$PKG" in
            dnf) run dnf -y -q install mariadb-server mariadb;;
            apt) apt_update_once; run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q mariadb-server mariadb-client;;
            *) fail "install MariaDB's server yourself, then  install.sh --db-agent";;
        esac
    fi
    if dbs_systemd; then
        run systemctl enable --now mariadb >/dev/null 2>&1 || run systemctl enable --now mariadb
    else
        warn "systemd is not running here: start MariaDB yourself (mariadbd-safe &)"
        if [[ -z "$DRY_RUN" ]] && command -v mysqld_safe >/dev/null 2>&1; then
            nohup mysqld_safe </dev/null >/dev/null 2>&1 9>&- &
            sleep 3
        fi
    fi
    [[ -n "$DRY_RUN" ]] && return
    local i
    for i in $(seq 30); do my_q "SELECT 1" >/dev/null 2>&1 && { good "MariaDB answers"; return; }; sleep 1; done
    fail "MariaDB does not answer as root over its socket"
}

my_configure() {
    step "MariaDB for acme"
    local cnf_dir cnf a pwd_made=""
    if [[ -n "$DRY_RUN" ]] && ! my_q "SELECT 1" >/dev/null 2>&1; then
        note "[would secure MariaDB, make $DBS_NAME and $DBS_USER for ${ACME_NODES:-no acme node yet}, listen on the network]"
        return
    fi
    run my_q "DELETE FROM mysql.global_priv WHERE User = ''; DELETE FROM mysql.global_priv WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db = 'test' OR Db = 'test\\_%'; FLUSH PRIVILEGES"
    good "secured: no anonymous accounts, no test database, root only on this machine"
    run my_q "CREATE DATABASE IF NOT EXISTS \`$DBS_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
    if [[ -z "$DBS_PASSWORD" && "$(my_q "SELECT COUNT(*) FROM mysql.user WHERE User = '$DBS_USER'")" == "0" ]]; then
        DBS_PASSWORD="$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))')"; pwd_made=yes
    fi
    for a in localhost 127.0.0.1 $ACME_NODES; do
        if [[ -n "$DBS_PASSWORD" ]]; then
            run my_q "SET SESSION sql_log_off = 1; CREATE USER IF NOT EXISTS '$DBS_USER'@'$a' IDENTIFIED BY '$DBS_PASSWORD'; ALTER USER '$DBS_USER'@'$a' IDENTIFIED BY '$DBS_PASSWORD'; GRANT ALL PRIVILEGES ON \`$DBS_NAME\`.* TO '$DBS_USER'@'$a'"
        else
            run my_q "GRANT ALL PRIVILEGES ON \`$DBS_NAME\`.* TO '$DBS_USER'@'$a'" 2>/dev/null || warn "'$DBS_USER'@'$a' is not there: give --db-password to make it"
        fi
    done
    run my_q "FLUSH PRIVILEGES"
    good "the database $DBS_NAME and the account $DBS_USER (localhost, 127.0.0.1${ACME_NODES:+, $ACME_NODES})"
    for cnf_dir in /etc/my.cnf.d /etc/mysql/mariadb.conf.d; do [[ -d "$cnf_dir" ]] && break; done
    cnf="$cnf_dir/zz-acme-listen.cnf"
    if [[ -n "$ACME_NODES" && ! -f "$cnf" ]]; then
        printf '# written by install.sh --db-server mariadb (acme)\n[mariadb]\nbind-address = 0.0.0.0\n' | write_file "$cnf" 0644
        if dbs_systemd; then run systemctl restart mariadb; else warn "start MariaDB again for $cnf (bind-address)"; fi
        good "MariaDB listens on the network ($cnf)"
    fi
    if [[ -n "$pwd_made" ]]; then
        say "${C_BAD}the password of $DBS_USER, shown only now:${C_OFF} $DBS_PASSWORD"
    fi
    DBS_PORT="$(my_q 'SELECT @@port' 2>/dev/null || echo 3306)"
}

# ---- the firewall: the acme nodes only -----------------------------------------------------
dbs_firewall() {
    local a fam port
    if ! command -v firewall-cmd >/dev/null 2>&1 || ! firewall-cmd --state >/dev/null 2>&1; then
        note "firewalld is not running: open TCP ${DBS_PORT:-?} and $DB_AGENT_PORT to ${ACME_NODES:-the acme nodes} in the firewall there is"
        return
    fi
    [[ -z "$ACME_NODES" ]] && { note "no --acme-node given: the firewall is opened to each node when it joins (the agent does it)"; return; }
    for a in $ACME_NODES; do
        case "$a" in *:*) fam=ipv6;; *) fam=ipv4;; esac
        for port in ${DBS_PORT:-} "$DB_AGENT_PORT"; do
            [[ -z "$port" ]] && continue
            run firewall-cmd -q --permanent --add-rich-rule="rule family=\"$fam\" source address=\"$a\" port port=\"$port\" protocol=\"tcp\" accept" || true
            run firewall-cmd -q --add-rich-rule="rule family=\"$fam\" source address=\"$a\" port port=\"$port\" protocol=\"tcp\" accept" || true
        done
        good "firewalld lets $a reach TCP ${DBS_PORT:+$DBS_PORT and }$DB_AGENT_PORT"
    done
}

# ---- the agent ----------------------------------------------------------------------------
agent_engine() {
    if [[ -n "${DB_SERVER:-}" ]]; then echo "$DB_SERVER"; return; fi
    if [[ -n "${DBS_ENGINE:-}" ]]; then echo "$DBS_ENGINE"; return; fi
    if runuser -u postgres -- psql -XAtqc 'SELECT 1' >/dev/null 2>&1; then echo postgres; return; fi
    if my_q 'SELECT 1' >/dev/null 2>&1; then echo mariadb; return; fi
    fail "neither PostgreSQL nor MariaDB answers here: --db-server postgres|mariadb installs one"
}

agent_install() {
    local eng port cfg
    eng="$(agent_engine)"
    step "acme-db-agent (the agent acme looks after this $eng through)"
    command -v python3 >/dev/null 2>&1 || { case "$PKG" in dnf) run dnf -y -q install python3;; apt) run apt-get install -y -q python3;; esac; }
    command -v openssl >/dev/null 2>&1 || { case "$PKG" in dnf) run dnf -y -q install openssl;; apt) run apt-get install -y -q openssl;; esac; }
    if ! id "$AGENT_USER" >/dev/null 2>&1; then
        run useradd --system --no-create-home --home-dir "$AGENT_STATE" --shell /sbin/nologin --comment "acme-db-agent (network side)" "$AGENT_USER"
    fi
    run install -d -m 0755 "$AGENT_LIB"
    run install -d -m 0700 "$AGENT_ETC" "$AGENT_STATE"
    run install -d -m 0750 "$AGENT_LOG"
    for f in acme_db_agent.py acme_pg_ops.py acme_web.py; do
        run install -m 0644 "$SOURCE_DIR/deploy/$f" "$AGENT_LIB/$f"
    done
    run chmod 0755 "$AGENT_LIB/acme_db_agent.py"
    cfg="$AGENT_ETC/agent.json"
    if [[ -f "$cfg" ]]; then
        good "its configuration is kept: $cfg"
        if [[ -n "$DB_AGENT_PORT_GIVEN" && -z "$DRY_RUN" ]]; then
            python3 -I - "$cfg" "$DB_AGENT_PORT" <<'PY'
import json, sys
p, port = sys.argv[1], int(sys.argv[2])
c = json.load(open(p)); c['port'] = port
open(p, 'w').write(json.dumps(c, indent=1) + '\n')
PY
            say "its port: $DB_AGENT_PORT"
        fi
    else
        port="${DBS_PORT:-}"
        [[ -z "$port" ]] && port="$( [[ "$eng" == postgres ]] && (runuser -u postgres -- psql -XAtqc 'SHOW port' 2>/dev/null || echo 5432) || (my_q 'SELECT @@port' 2>/dev/null || echo 3306) )"
        python3 -I - "$eng" "$port" "$DB_AGENT_PORT" <<'PY' | write_file "$cfg" 0600
import json, sys
eng, port, aport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
c = {'listen': '0.0.0.0', 'port': aport, 'engine': eng, 'user': 'acme-db-agent',
     'state': '/var/lib/acme-db-agent', 'log': '/var/log/acme-db-agent/audit.log',
     'ha_ca': '/etc/pki/acme/ha-ca.pem'}
c['pg_port' if eng == 'postgres' else 'my_port'] = port
print(json.dumps(c, indent=1))
PY
        good "its configuration: $cfg (port $DB_AGENT_PORT)"
    fi
    run install -m 0644 "$SOURCE_DIR/deploy/acme-db-agent.service" "$AGENT_UNIT"
    if dbs_systemd; then
        run systemctl daemon-reload
        run systemctl enable acme-db-agent >/dev/null 2>&1 || true
        run systemctl restart acme-db-agent
        if [[ -z "$DRY_RUN" ]]; then
            sleep 1
            if systemctl is-active --quiet acme-db-agent; then good "acme-db-agent runs (TCP $DB_AGENT_PORT)"
            else warn "acme-db-agent did not start: journalctl -u acme-db-agent"; fi
        fi
    else
        warn "systemd is not running here: start the agent yourself:  python3 -I $AGENT_LIB/acme_db_agent.py &"
    fi
}

agent_code() {
    [[ -n "$DRY_RUN" ]] && { note "[would print a join code for an acme node]"; return; }
    local code
    code="$(python3 -I "$AGENT_LIB/acme_db_agent.py" --config "$AGENT_ETC/agent.json" --new-code 2>/dev/null)" || { warn "no join code could be made"; return; }
    step "On each acme node that uses this server (as root, within the hour):"
    say "acme --db-agent-join $code"
    note "(a new code: python3 -I $AGENT_LIB/acme_db_agent.py --new-code)"
}

agent_uninstall() {
    step "Removing acme-db-agent (the database server and its data stay)"
    if dbs_systemd; then run systemctl disable --now acme-db-agent >/dev/null 2>&1 || true; fi
    run rm -f "$AGENT_UNIT"
    dbs_systemd && run systemctl daemon-reload
    run rm -rf "$AGENT_LIB"
    good "taken away: the service and $AGENT_LIB"
    say "kept: $AGENT_ETC (its keys, the nodes it knows), $AGENT_LOG (the audit log), the user $AGENT_USER"
    say "acme's files in PostgreSQL's data folder (acme-ha.crt, acme-ha.key), /etc/pki/acme/ha-ca.pem and"
    say "the lines in pg_hba.conf stay in use - acme --ha-tls-off on the nodes takes them out first"
}

db_server_main() {
    DB_AGENT_PORT="${DB_AGENT_PORT:-9443}"
    DBS_NAME="${DBS_NAME:-acme}"; DBS_USER="${DBS_USER:-acme}"
    dbs_check_args
    if [[ -n "$DO_UNINSTALL" ]]; then
        agent_uninstall
        return 0
    fi
    step "A database server for acme${DB_SERVER:+ ($DB_SERVER)}${ACME_NODES:+ - acme nodes: $ACME_NODES}"
    case "${DB_SERVER:-}" in
        postgres) pg_install; pg_find; pg_initdb_start; pg_configure;;
        mariadb) my_install; my_configure;;
    esac
    agent_install
    dbs_firewall
    agent_code
    note "the database's TLS (a certificate from acme's own authority) is put in from acme once a node joined:"
    note "  PostgreSQL: Settings -> The database -> TLS (or High availability -> the link) - MariaDB: acme --db-agent-mariadb-tls"
    return 0
}
