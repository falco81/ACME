#!/bin/bash
# The same flow on each database engine: a copy of a database restored into
# it, the certificates, the authority, the target and acme's DNS records of
# that copy read back (and their sealed keys opened: a key exported, the
# authority signing a renewal, the target's password tried), a directory and
# an account made on the command line, the daemon started and asked, the
# configuration exported and imported again, the events read back, and a copy
# made out of it again. Last, "move": everything carried from SQLite into
# PostgreSQL and on into MariaDB by the pages' own wizard (test/test_ha.py
# EngineMove).
#
#   test/engines.sh BACKUP.json.gz [sqlite mariadb postgres move]
#
# The copy is best one with certificates in it: python3 test/test_ha.py
# --make-backup DIR makes one (a SQLite database with certificates, an
# authority, sources, a target, a deployment, jobs and a DNS record) and
# prints its path. Without a certificate "web" in the copy, the certificate
# checks are skipped.
#
# MariaDB and PostgreSQL need a database "acme" that the account acme (password
# optpw) owns on localhost, and pymysql / psycopg2 in the python3 on the PATH.
# Each is emptied before the copy is put back into it.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
acme="$here/acme.py"
backup=${1:?a copy of a database (acme --backup, or test/test_ha.py --make-backup DIR) to restore}
shift
engines=${*:-sqlite mariadb postgres move}
fails=0
say()  { printf '%-9s %s\n' "$1" "$2"; }
must() { if eval "$2" >/dev/null 2>&1; then say "$1" "ok   $3"; else say "$1" "FAIL $3"; fails=$((fails+1)); fi; }
has_certs=0
zcat "$backup" | grep -q '"name": "web"' && has_certs=1

for engine in $engines; do
    if [ "$engine" = move ]; then
        must move "cd '$here' && python3 -m unittest test.test_ha.EngineMove" "SQLite -> PostgreSQL -> MariaDB, by the wizard"
        continue
    fi
    work=$(mktemp -d)
    case $engine in
        sqlite)   db='"db_engine": "sqlite"' ;;
        mariadb)  db='"db_engine": "mariadb", "db_host": "127.0.0.1", "db_port": 3306, "db_name": "acme", "db_user": "acme", "db_password": "optpw"' ;;
        postgres) db='"db_engine": "postgres", "db_host": "127.0.0.1", "db_port": 5432, "db_name": "acme", "db_user": "acme", "db_password": "optpw"' ;;
        *) say "$engine" "FAIL not an engine"; fails=$((fails+1)); continue ;;
    esac
    printf '{%s, "api_port": 19873, "isemon": 0, "upgrade_check": 0}\n' "$db" > "$work/config.json"
    export ACME_CONFIG=$work/config.json ACME_STATE=$work/state ACME_RUN=$work/run ACME_LOGDIR=$work/log ACME_STAY_ROOT=1 ACME_PLUGINS=$work/plugins
    mkdir -p "$ACME_STATE" "$ACME_RUN" "$ACME_LOGDIR" "$ACME_PLUGINS/targets"
    # The fake target of the tests, for the target in the copy.
    (cd "$here/test" && python3 -c 'import sys; from test_certs_core import FAKE_TARGET; sys.stdout.write(FAKE_TARGET)') > "$ACME_PLUGINS/targets/fake_target.py"
    # A database left from an earlier run: emptied, so the copy is all there is.
    case $engine in
        mariadb)  (cd "$here/test" && python3 -c 'import test_ha; test_ha.my_empty()') >/dev/null 2>&1 ;;
        postgres) (cd "$here/test" && python3 -c 'import test_ha; test_ha.pg_empty()') >/dev/null 2>&1 ;;
    esac
    # the key the copy was sealed with travels beside it
    key="${backup%.json.gz}.key"
    [ -f "$key" ] && cp "$key" "$ACME_STATE/secrets.key"
    must "$engine" "python3 '$acme' --restore '$backup' --yes" "restore $(basename "$backup")"
    must "$engine" "python3 '$acme' --users | grep -q 'full admin'" "accounts read back"
    if [ "$has_certs" = 1 ]; then
        must "$engine" "python3 '$acme' --certs --json | grep -q '\"name\": \"intranet\"'" "the certificates read back"
        must "$engine" "python3 '$acme' --cert web | grep -q 'www.example.test'" "... one with its names"
        must "$engine" "python3 '$acme' --export web --format key-pem --out - | grep -q 'BEGIN PRIVATE KEY'" "its sealed key opened"
        must "$engine" "python3 '$acme' --cas | grep -q 'Test Root'" "the authority read back"
        must "$engine" "python3 '$acme' --renew intranet | grep -q 'issued: version'" "... its sealed key signs a renewal"
        must "$engine" "python3 '$acme' --target-test fake1" "the target's sealed password opened"
        must "$engine" "python3 '$acme' --dns-records | grep -q 'populated-txt'" "acme's DNS records read back"
        must "$engine" "python3 '$acme' --jobs --json | grep -q '\"kind\": \"renew\"'" "the jobs read back"
    fi
    must "$engine" "ACME_BIND_PW=x python3 '$acme' --add-directory enginetest --hosts 127.0.0.1 --base DC=example,DC=local --bind-dn x --bind-pw - --tls none" "directory saved"
    must "$engine" "ACME_PASSWORD=Engine-Test-Pw-1 python3 '$acme' --add-user enginetest --role certadmin" "a certificate administrator made"
    python3 "$acme" --daemon > "$work/daemon.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 40); do python3 "$acme" --status >/dev/null 2>&1 && break; sleep 0.25; done
    must "$engine" "python3 '$acme' --status" "the daemon answers"
    must "$engine" "python3 '$acme' --api GET /api/status | grep -q '\"ok\": true'" "/api/status"
    [ "$has_certs" = 1 ] && must "$engine" "python3 '$acme' --api GET /api/certs/overview | grep -q '\"node\"'" "the certificate manager leads"
    must "$engine" "python3 '$acme' --export-config '$work/conf.json'" "the configuration exported"
    must "$engine" "python3 '$acme' --import-config '$work/conf.json' --yes" "... and imported again"
    must "$engine" "python3 '$acme' --events | grep -q 'imported a configuration'" "the events read back"
    must "$engine" "python3 '$acme' --backup" "a copy made"
    [ "$has_certs" = 1 ] && must "$engine" "zcat \$(ls -t '$work'/state/backups/*.json.gz | head -1) | grep -q '\"table\": \"cert_versions\"'" "... with the certificates in it"
    kill "$pid"; wait "$pid" 2>/dev/null
    python3 "$acme" --del-user enginetest --yes >/dev/null 2>&1
    rm -rf "$work"
done
echo
[ "$fails" -eq 0 ] && echo "all engines passed" || echo "$fails check(s) failed"
exit "$fails"
