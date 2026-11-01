#!/bin/bash
# The same flow on each database engine: a copy of a database restored into
# it, a directory and an account made on the command line, the daemon started
# and asked, the configuration exported and imported again, the events read
# back, and a copy made out of it again.
#
#   test/engines.sh BACKUP.json.gz [sqlite mariadb postgres]
#
# MariaDB and PostgreSQL need a database "acme" that the account acme (password
# optpw) owns on localhost, and pymysql / psycopg2.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
acme="$here/acme.py"
backup=${1:?a copy of a database (acme --backup) to restore}
shift
engines=${*:-sqlite mariadb postgres}
fails=0
say()  { printf '%-9s %s\n' "$1" "$2"; }
must() { if eval "$2" >/dev/null 2>&1; then say "$1" "ok   $3"; else say "$1" "FAIL $3"; fails=$((fails+1)); fi; }

for engine in $engines; do
    work=$(mktemp -d)
    case $engine in
        sqlite)   db='"db_engine": "sqlite"' ;;
        mariadb)  db='"db_engine": "mariadb", "db_host": "127.0.0.1", "db_port": 3306, "db_name": "acme", "db_user": "acme", "db_password": "optpw"' ;;
        postgres) db='"db_engine": "postgres", "db_host": "127.0.0.1", "db_port": 5432, "db_name": "acme", "db_user": "acme", "db_password": "optpw"' ;;
    esac
    printf '{%s, "api_port": 19873, "isemon": 0}\n' "$db" > "$work/config.json"
    export ACME_CONFIG=$work/config.json ACME_STATE=$work/state ACME_RUN=$work/run ACME_LOGDIR=$work/log ACME_STAY_ROOT=1
    mkdir -p "$ACME_STATE" "$ACME_RUN" "$ACME_LOGDIR"
    # the key the copy was sealed with travels beside it
    key="${backup%.json.gz}.key"
    [ -f "$key" ] && cp "$key" "$ACME_STATE/secrets.key"
    must "$engine" "python3 '$acme' --restore '$backup' --yes" "restore $(basename "$backup")"
    must "$engine" "python3 '$acme' --users | grep -q 'full admin'" "accounts read back"
    must "$engine" "ACME_BIND_PW=x python3 '$acme' --add-directory enginetest --hosts 127.0.0.1 --base DC=example,DC=local --bind-dn x --bind-pw - --tls none" "directory saved"
    must "$engine" "ACME_PASSWORD=Engine-Test-Pw-1 python3 '$acme' --add-user enginetest --role certadmin" "a certificate administrator made"
    python3 "$acme" --daemon > "$work/daemon.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 40); do python3 "$acme" --status >/dev/null 2>&1 && break; sleep 0.25; done
    must "$engine" "python3 '$acme' --status" "the daemon answers"
    must "$engine" "python3 '$acme' --api GET /api/status | grep -q '\"ok\": true'" "/api/status"
    must "$engine" "python3 '$acme' --export-config '$work/conf.json'" "the configuration exported"
    must "$engine" "python3 '$acme' --import-config '$work/conf.json' --yes" "... and imported again"
    must "$engine" "python3 '$acme' --events | grep -q 'imported a configuration'" "the events read back"
    must "$engine" "python3 '$acme' --backup" "a copy made"
    kill "$pid"; wait "$pid" 2>/dev/null
    python3 "$acme" --del-user enginetest --yes >/dev/null 2>&1
    rm -rf "$work"
done
echo
[ "$fails" -eq 0 ] && echo "all engines passed" || echo "$fails check(s) failed"
exit "$fails"
