#!/bin/bash
# The same flow on each database engine: a copy of a database restored into
# it, a client, a realm and a token made on the command line, real RADIUS
# packets answered, the logs read back, and a copy made out of it again.
#
#   test/engines.sh BACKUP.json.gz [sqlite mariadb postgres]
#
# MariaDB and PostgreSQL need a database "acme" that the account acme (password
# optpw) owns on localhost, and pymysql / psycopg2. Needs radclient or radtest
# (freeradius-utils) for the packets; falls back to acme --radtest.
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
    printf '{%s, "api_port": 9871, "radius_auth_port": 18120, "radius_acct_port": 18130, "isemon": 0}\n' "$db" > "$work/config.json"
    export ACME_CONFIG=$work/config.json ACME_STATE=$work/state ACME_RUN=$work/run ACME_LOGDIR=$work/log ACME_STAY_ROOT=1
    mkdir -p "$ACME_STATE" "$ACME_RUN" "$ACME_LOGDIR"
    # the key the copy was sealed with travels beside it
    key="${backup%.json.gz}.key"
    [ -f "$key" ] && cp "$key" "$ACME_STATE/secrets.key"
    must "$engine" "python3 '$acme' --restore '$backup' --yes" "restore $(basename "$backup")"
    must "$engine" "python3 '$acme' --tokens | grep -q falco@dpmo.cz" "tokens read back"
    must "$engine" "python3 '$acme' --add-client localhost --address 127.0.0.1 --secret enginetest --realm example.cz" "client saved"
    must "$engine" "python3 '$acme' --add-realm example.cz --suffix example.cz" "realm saved"
    out=$(python3 "$acme" --enroll engine@example.cz --no-qr 2>&1)
    secret=$(printf '%s\n' "$out" | grep -oE '[A-Z2-7]{16,}' | head -1)
    must "$engine" "[ -n '$secret' ]" "token made"
    python3 "$acme" > "$work/daemon.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 40); do python3 "$acme" --status >/dev/null 2>&1 && break; sleep 0.25; done
    sleep 1
    code=$(python3 -c "import sys; sys.path.insert(0,'$here'); import acme; print(acme.totp(acme.b32_clean('$secret'), __import__('time').time()))" 2>/dev/null)
    if command -v radtest >/dev/null; then
        must "$engine" "radtest engine $code 127.0.0.1:18120 0 enginetest | grep -q Access-Accept" "Access-Accept for a right code"
        must "$engine" "radtest engine $code 127.0.0.1:18120 0 enginetest | grep -q Access-Reject" "Access-Reject for the same code again"
    else
        must "$engine" "python3 '$acme' --radtest engine@example.cz $code | grep -qi accept" "accepted"
    fi
    must "$engine" "python3 '$acme' --log | grep -q engine@example.cz" "RADIUS log read back"
    must "$engine" "python3 '$acme' --acme-log | grep -q engine@example.cz" "ACME log read back"
    must "$engine" "python3 '$acme' --backup" "a copy made"
    kill "$pid"; wait "$pid" 2>/dev/null
    python3 "$acme" --delete-token engine@example.cz --yes >/dev/null 2>&1
    rm -rf "$work"
done
echo
[ "$fails" -eq 0 ] && echo "all engines passed" || echo "$fails check(s) failed"
exit "$fails"
