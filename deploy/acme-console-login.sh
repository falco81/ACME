# The acme console when root signs in (acme 1.0.130).
# Switched with `acme --console-at-login on|off`; q in the console leaves it
# for this shell, and `acme --console` opens it again. Nothing happens for a
# command run over SSH, scp/sftp, a non-interactive shell, a shell opened
# from the console itself, or when ACME_NO_CONSOLE is set.
# For normal users too (1.0.240), those named by `acme --console-users` (or *):
# through sudo, with their own password - only who may become root with sudo
# gets it; anybody else is told so and keeps the ordinary shell.
if [ -n "${PS1:-}" ] && [ -t 0 ] && [ -t 1 ] && [ -z "${ACME_CONSOLE:-}" ] \
   && [ -z "${ACME_NO_CONSOLE:-}" ] && [ -z "${SSH_ORIGINAL_COMMAND:-}" ] \
   && [ -x /usr/local/bin/acme ] \
   && [ -f /etc/acme-console-login ] && [ ! -L /etc/acme-console-login ]; then
    if [ "$(id -u 2>/dev/null)" = "0" ]; then
        if [ "$(head -c 3 /etc/acme-console-login 2>/dev/null)" = "on" ]; then
            export ACME_CONSOLE=1
            /usr/local/bin/acme --console
        fi
    elif [ "$(id -u 2>/dev/null)" -ge 1000 ] 2>/dev/null; then
        _acme_users=" $(sed -n 's/^users: //p' /etc/acme-console-login 2>/dev/null | head -n 1) "
        _acme_me="$(id -un 2>/dev/null)"
        case "$_acme_users" in
            *" * "*|*" $_acme_me "*)
                export ACME_CONSOLE=1
                if id -Gn 2>/dev/null | tr ' ' '\n' | grep -qxE 'wheel|sudo|admin' \
                   || sudo -n true 2>/dev/null; then
                    echo "acme: the console - sudo asks for your password (Ctrl+C: the ordinary shell)"
                    sudo -p "[sudo] password for %p: " env ACME_CONSOLE=1 /usr/local/bin/acme --console
                else
                    echo "acme: the console is set to open for you, but it needs sudo rights (the wheel group) - the ordinary shell"
                fi
                ;;
        esac
        unset _acme_users _acme_me
    fi
fi
