# The acme console when root signs in (acme 1.0.130).
# Switched with `acme --console-at-login on|off`; q in the console leaves it
# for this shell, and `acme --console` opens it again. Nothing happens for a
# command run over SSH, scp/sftp, a non-interactive shell, a shell opened
# from the console itself, or when ACME_NO_CONSOLE is set.
if [ -n "${PS1:-}" ] && [ -t 0 ] && [ -t 1 ] && [ -z "${ACME_CONSOLE:-}" ] \
   && [ -z "${ACME_NO_CONSOLE:-}" ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] \
   && [ "$(id -u 2>/dev/null)" = "0" ] && [ -x /usr/local/bin/acme ] \
   && [ -f /etc/acme-console-login ] && [ ! -L /etc/acme-console-login ] \
   && [ "$(head -c 3 /etc/acme-console-login 2>/dev/null)" = "on" ]; then
    export ACME_CONSOLE=1
    /usr/local/bin/acme --console
fi
