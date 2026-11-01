# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- colour in every output (1.0.132) ---------------------------------------------
# With colour on, every table and every line the command line prints is
# coloured the same way - tables by their cells, other lines as they read:
# "key: value", addresses, times, and the words that say how a thing is.
# Whatever already carries its own colour is left as it is.
TABLE_PAL = None
TONE_GOOD = {'on', 'yes', 'active', 'ok', 'accept', 'accepted', 'running', 'answering',
             'in place', 'in service', 'done', 'synchronised', 'healthy', 'up', 'enabled',
             'signed in', 'good', 'valid', 'sent', 'taken', 'checked'}
TONE_BAD = {'off', 'no', 'reject', 'rejected', 'failed', 'fail', 'error', 'gone', 'down',
            'locked', 'locked out', 'expired', 'not answering', 'inactive', 'dead', 'disabled',
            'refused', 'missing', 'broken', 'lost', 'crit'}
TONE_WARN = {'pending', 'waiting', 'maintenance', 'in maintenance', 'paused', 'warn',
             'warning', 'not set up', 'unknown', 'stale', 'not yet'}
TONE_DIM = {'never', '-', '–', '(none)', 'none', 'as they come', 'not set', ''}
RE_ADDR = re.compile(r'(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?::\d{1,5})?)(?![\w.])')
RE_TIME = re.compile(r'\b(\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2})([ T]\d{2}:\d{2}(?::\d{2})?)?\b')


def tone_cell(text, pal):
    """One value coloured by what it says."""
    t = str(text)
    if not pal or not pal.on or ANSI.search(t):
        return t
    low = t.strip().lower()
    if low in TONE_GOOD:
        return pal.good(t)
    if low in TONE_BAD:
        return pal.bad(t)
    if low in TONE_WARN:
        return pal.warn(t)
    if low in TONE_DIM:
        return pal.dim(t)
    if RE_TIME.fullmatch(t.strip()):
        return pal.dim(t)
    return tone_words(t, pal)


def tone_words(t, pal):
    """Addresses and times inside a text."""
    t = RE_ADDR.sub(lambda m: pal.addr(m.group(1)), t)
    return RE_TIME.sub(lambda m: pal.dim(m.group(0)), t)


def _cut(text, width):
    """`text` no wider than `width` on the screen, its colour kept or - when it
    has to be cut - taken off."""
    if plain_len(text) <= width:
        return text
    return ANSI.sub('', text)[:width]


def table(rows, heads, widths=None):
    if not rows:
        return '  (none)'
    pal = TABLE_PAL
    cells = [[tone_cell(term_safe(c), pal) for c in r] for r in rows]
    cols = list(zip(*([heads] + [[str(c) for c in r] for r in cells])))
    w = widths or [min(48, max(plain_len(x) for x in col)) for col in cols]
    head = '  ' + '  '.join(h.upper().ljust(w[i]) for i, h in enumerate(heads))
    out = [pal.head(head) if pal and pal.on else head]
    for r in cells:
        out.append('  ' + '  '.join(plain_pad(_cut(str(c), w[i]), w[i])
                                    for i, c in enumerate(r)))
    return '\n'.join(out)


class ColourOut(object):
    """stdout, every line coloured on its way out unless it is already."""
    LINE_KV = re.compile(r'^(\s*)([A-Za-z][\w .()/\'-]{0,40}?)(:\s+|\s{2,})(\S.*)$')

    def __init__(self, stream, pal):
        self.s, self.pal, self.buf = stream, pal, ''

    def _line(self, ln):
        p = self.pal
        ln = term_safe(ln)
        if not p.on or not ln.strip() or ANSI.search(ln):
            return ln
        m = self.LINE_KV.match(ln)
        if m and not ln.lstrip().startswith(('$', '#')):
            return '%s%s%s%s' % (m.group(1), p.info(m.group(2)), m.group(3),
                                 tone_cell(m.group(4), p))
        return tone_words(ln, p)

    def write(self, text):
        self.buf += str(text)
        if '\n' in self.buf:
            done, self.buf = self.buf.rsplit('\n', 1)
            self.s.write('\n'.join(self._line(x) for x in done.split('\n')) + '\n')
        return len(text)

    def flush(self):
        if self.buf:
            self.s.write(self.buf)
            self.buf = ''
        self.s.flush()

    def __getattr__(self, name):
        return getattr(self.s, name)


def ask_password(prompt='password', twice=True, env='ACME_PASSWORD'):
    # Each secret its own variable (1.0.139): ACME_PASSWORD, set for an
    # account, became a client's shared secret.
    said = os.environ.get(env) if env else None
    if said:
        return said
    # No terminal (cron, ssh without -t, a pipe): one line of stdin, as --set
    # KEY=- takes it (1.0.205) - getpass read it, asked "and again" and ended
    # in a traceback at the end of the input.
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            raise SystemExit('acme: %s: nothing on stdin and no terminal to ask on' % prompt)
        return line.rstrip('\r\n')
    try:
        first = getpass.getpass('%s: ' % prompt)
        if twice:
            again = getpass.getpass('and again: ')
            if first != again:
                raise SystemExit('those two are not the same')
    except (EOFError, KeyboardInterrupt):
        raise SystemExit('acme: %s: not given' % prompt)
    return first


def not_on_command_line(what, value, how):
    """A secret written out on the command line is refused (1.0.187): ps, the
    shell's history and the process accounting all keep it. - asks for it."""
    # Only - (asked, or a line of stdin) or nothing (1.0.205): '@envSecret' was
    # taken as it was written, the secret on the command line after all. --set
    # KEY=@env reads ACME_VALUE_KEY before this is asked.
    if value not in (None, '', '-'):
        raise SystemExit('acme: %s is not taken on the command line, where ps and the shell\'s '
                         'history keep it: %s' % (what, how))


def ask_secret_value(key):
    """KEY=- of --set: from ACME_VALUE_<KEY>, else asked (twice), else one line of stdin."""
    env = 'ACME_VALUE_' + key.upper()
    if os.environ.get(env):
        return os.environ[env]
    if sys.stdin.isatty():
        return ask_password(key, twice=True, env=None)
    line = sys.stdin.readline().rstrip('\r\n')
    if not line:
        # Nothing on stdin (a cron job, ssh without -t) saved an empty value
        # over the secret (1.0.207). Emptied on purpose: KEY= with nothing.
        raise SystemExit('acme: %s: nothing came on stdin and there is no terminal to ask on '
                         '(to empty it on purpose: --set %s=)' % (key, key))
    return line


class CliApiHandler(ApiHandler):
    """What a page asks, asked by the command line (1.0.188): the route's own
    checks, events and words, as a full administrator called 'command line'
    (root on this machine is that already). No HTTP: no socket, no session."""

    def __init__(self, daemon, who, body=None, args=None, path=''):
        self.server = type('S', (), {'daemon': daemon})()
        self.headers = {'X-Acme-Client': '127.0.0.1'}
        self.client_address = ('127.0.0.1', 0)
        self.args = dict(args or {})
        self._body = dict(body or {})
        self.route_path = path
        self.who = who

    def me(self, role='readonly'):
        return {'id': 0, 'name': self.who, 'role': 'fulladmin', 'kind': 'admin',
                'account': {'name': self.who, 'role': 'fulladmin', 'source': 'local'}}

    def session(self, kind='admin'):
        return self.me()


def cli_api(daemon, who, method, path, body=None, args=None):
    """One route of the pages, run here: its answer, or SystemExit with its words."""
    fn = ROUTES.get((method, path))
    if not fn:
        raise SystemExit('acme: the pages have no %s %s' % (method, path))
    h = CliApiHandler(daemon, who, body, args, path)
    try:
        return fn(h)
    except ApiError as e:
        raise SystemExit('acme: %s' % e)
    except (ValueError, BadSetting) as e:
        raise SystemExit('acme: %s' % e)


def cli_ask_wait(store, kind, asked, secs=90, say=None):
    """What every node answered to an ask (asked = {'id', 'nodes'}): waited for
    until all have, or secs. {node: answer or None}."""
    end = time.time() + secs
    got = {}
    while time.time() < end:
        got = {n: v for n, v in node_ask_results(store, kind, asked['id']).items()
               if n in asked['nodes']}
        if got and all(got.get(n) for n in asked['nodes']):
            break
        time.sleep(0.5)
    return {n: got.get(n) for n in asked['nodes']}


def cli_show(obj, pal, indent=2, depth=0, most=60):
    """A view of the pages as lines: KEY  value, nested ones indented."""
    pad = ' ' * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            if v in (None, '', [], {}):
                continue
            if isinstance(v, (dict, list)) and depth < 3:
                print('%s%s' % (pad, pal.dim(str(k)) if pal else k))
                cli_show(v, pal, indent + 2, depth + 1, most)
            else:
                text = json.dumps(v, ensure_ascii=False, default=str) if isinstance(v, (dict, list)) \
                    else (stamp(v) if isinstance(v, float) and v > 1e9 and str(k).endswith(('at', 'end', 'since', 'after', 'before')) else str(v))
                print('%s%-24s %s' % (pad, k, text[:200]))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:most]):
            if isinstance(v, (dict, list)):
                print('%s- %s' % (pad, next((str(v[k]) for k in ('name', 'node', 'target', 'rule', 'key',
                                                               'kind', 'what') if v.get(k)), '')
                                  if isinstance(v, dict) else ''))
                cli_show(v, pal, indent + 2, depth + 1, most)
            else:
                print('%s- %s' % (pad, v))
        if len(obj) > most:
            print('%s… %d more' % (pad, len(obj) - most))
    else:
        print('%s%s' % (pad, obj))


def cli_ask_said(pal, answers):
    """Each node's answer to an ask, one block each; the exit code."""
    bad = 0
    for n, got in answers.items():
        if not got:
            bad += 1
            print(pal.bad_line('%s: no answer - is acme running there?' % n))
            continue
        ok = got.get('ok', not got.get('error'))
        bad += 0 if ok else 1
        print((pal.ok_line if ok else pal.bad_line)('%s: %s' % (n, got.get('error') or got.get('said') or ('ok' if ok else 'failed'))))
        cli_show({k: v for k, v in got.items() if k not in ('id', 'at', 'node', 'ok', 'error', 'said')}, pal, 4)
    return 1 if bad else 0


class HelpfulParser(argparse.ArgumentParser):
    """An ArgumentParser whose help is isemon's: two columns, in colour.
    Anything going wrong in the drawing falls back to argparse's own."""
    palette = None

    def format_help(self):
        try:
            return help_text(self, self.palette or Palette(False))
        except Exception:
            return super(HelpfulParser, self).format_help()

    def error(self, message):
        pal = self.palette or Palette(False)
        sys.stderr.write('%s\n' % pal.bad_line(message))
        sys.stderr.write(pal.dim('try:  acme --help') + '\n')
        raise SystemExit(2)


def help_option_words(action):
    names = ', '.join(action.option_strings)
    if action.nargs == 0:
        return names, ''
    if action.metavar:
        meta = ' '.join(action.metavar) if isinstance(action.metavar, tuple) else action.metavar
    elif action.choices:
        meta = '{%s}' % ','.join(str(c) for c in action.choices)
    else:
        meta = action.dest.upper()
    if action.nargs in ('+', '*'):
        meta += ' ...'
    return names, meta


def help_text(parser, pal):
    """The whole of --help, in the width of this terminal."""
    import textwrap
    width = pal.width
    out = ['%s %s' % (pal.head('acme'), pal.bold(__version__)),
           pal.dim('%s - Let\'s Encrypt and any ACME CA, your own authorities, AD CS, '
                   'SCEP; on servers, load balancers and firewalls' % ACME_WHAT),
           '',
           '%s acme %s' % (pal.paint('usage:', pal.c_key), pal.dim('[--json] [--no-color] '
                                                                  '[what to do]')),
           pal.dim('       acme is the same command; with nothing at all it says what it is doing')]
    every = [a for g in parser._action_groups for a in g._group_actions]
    left = min(34, max([len(' '.join(x for x in help_option_words(a) if x))
                        for a in every] or [20]) + 2)
    for group in parser._action_groups:
        actions = [a for a in group._group_actions if a.help != argparse.SUPPRESS]
        if not actions:
            continue
        out.append('')
        out.append(pal.head((group.title or '').upper()))
        if group.description:
            for line in textwrap.wrap(group.description, width - 2):
                out.append('  ' + pal.dim(line))
        for action in actions:
            names, meta = help_option_words(action)
            painted = pal.good(names) + (' ' + pal.warn(meta) if meta else '')
            says = action.help or ''
            if (action.default not in (None, False, '', argparse.SUPPRESS)
                    and action.nargs != 0 and action.default != []
                    and '[%s]' % action.default not in says):
                says += ' [%s]' % action.default
            lines = textwrap.wrap(says, max(24, width - left - 4)) or ['']
            if plain_len(painted) > left:
                out.append('  ' + painted)
                lines_at = 0
            else:
                out.append('  %s  %s' % (plain_pad(painted, left), lines[0]))
                lines_at = 1
            for more in lines[lines_at:]:
                out.append('  %s  %s' % (' ' * left, more))
    out.append('')
    out.append(pal.head('THINGS PEOPLE ACTUALLY TYPE'))
    wide = min(36, max(len(c.split('\n')[0]) for c, _ in HELP_EXAMPLES) + 2)
    for command, says in HELP_EXAMPLES:
        first, *rest = command.split('\n')
        if len(first) + 2 > wide:
            out.append('  ' + pal.info(first) + ('' if rest or not says else ''))
            for r in rest:
                out.append('  ' + pal.info(r))
            if says:
                out.append('  %s  %s' % (' ' * wide, pal.dim(says)))
        else:
            out.append('  %s%s' % (plain_pad(pal.info(first), wide), pal.dim(says)))
            for r in rest:
                out.append('  ' + pal.info(r))
    out.append('')
    for note in ('the pages are at https://<this machine>/ (enrolment) and /admin/ · '
                 'the configuration is %s' % CONFIG_FILE,
                 'typed with nothing at all it is --status; systemd runs the daemon as '
                 '--daemon, and only one runs at a time',
                 'colour is off when this is piped, and with --no-color or NO_COLOR=1'
                 + ('' if HAVE_COLORAMA else ' (colorama is not installed; colour is '
                                             'written by hand)')):
        for line in textwrap.wrap(note, width - 4):
            out.append('  ' + pal.dim(line))
    out.append('')
    return '\n'.join(out)


ACME_WHAT = 'certificates kept, renewed and deployed by themselves'


def build_parser():
    # Options whole, never shortened (1.0.146): --js was taken for --json -
    # and --check --js went round itself until the stack ran out.
    p = HelpfulParser(prog='acme', add_help=False, allow_abbrev=False, usage='acme [--json] [--no-color] [what to do]',
                      description='acme - %s' % ACME_WHAT,
                      formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
                          prog, max_help_position=36, width=100))
    g = p.add_argument_group('EVERYWHERE')
    g.add_argument('-h', '--help', action='store_true', help='this, and stop')
    g.add_argument('--version', action='store_true', help='which version this is, and stop')
    g.add_argument('--config', metavar='FILE', help='use this config file')
    g.add_argument('--no-color', '--no-colour', action='store_true', dest='no_color',
                   help='plain text, no colour')
    g.add_argument('--json', action='store_true', help='answer as JSON where it makes sense')
    g.add_argument('--daemon', action='store_true',
                   help='run the daemon in the foreground (what systemd starts); one at a time')
    g.add_argument('--debug', action='store_true', help='say everything, this run only')
    g = p.add_argument_group('LOOKING', 'Reading what it knows. None of these change anything.')
    g.add_argument('--status', action='store_true', help='what it is doing, in one screen')
    g.add_argument('--check', action='store_true', help='a health check, every part of it')
    g.add_argument('--events', action='store_true', help='this daemon’s own events')
    g.add_argument('--limit', type=int, default=40, metavar='N', help='how many rows [40]')
    g.add_argument('--hours', type=float, default=24, metavar='N', help='the last N hours [24]')
    g.add_argument('--search', metavar='TEXT', default='', help='only rows holding this')
    g = p.add_argument_group('ACTIVE DIRECTORY', 'The directories administrators (and the '
                             'enrolment pages) sign people in against.')
    g.add_argument('--directories', action='store_true', help='the directories')
    g.add_argument('--add-directory', metavar='NAME', help='add (or change) one: --hosts, '
                   '--base, --bind-dn, --bind-pw, --tls, --port, --no-verify')
    g.add_argument('--hosts', metavar='H1,H2', help='its servers, in order')
    g.add_argument('--base', metavar='DN', help='where to look: DC=example,DC=local')
    g.add_argument('--bind-dn', metavar='WHO', help='the account it reads with')
    g.add_argument('--bind-pw', metavar='-', help='its password: - asks for it (or '
                   'ACME_BIND_PW) - not on the command line, where ps shows it')
    g.add_argument('--tls', choices=('ldaps', 'starttls', 'none'), help='how it is reached')
    g.add_argument('--port', type=int, metavar='N', help='its port')
    g.add_argument('--no-verify', action='store_true', help='do not check its certificate')
    g.add_argument('--weak-certs', choices=('on', 'off'), help='take old, weak certificates '
                   '(a 1024-bit key, SHA-1, TLS 1.0) - still checked against the authority')
    g.add_argument('--ca', metavar='FILE', help='the certificate authority (PEM) that signed it')
    g.add_argument('--del-directory', metavar='NAME', help='take one away')
    g.add_argument('--directory-test', metavar='NAME', help='reach every server of it, step by '
                   'step')
    g.add_argument('--directory-user', nargs=2, metavar=('NAME', 'USER'),
                   help='what the directory says about one person, groups and all')
    g = p.add_argument_group('THE SETTINGS AND THE ACCOUNTS')
    g.add_argument('--settings', action='store_true', help='every setting, as it stands')
    g.add_argument('--set', action='append', metavar='KEY=VALUE', help='change one (again for '
                   'more); a secret (a password, a token) as KEY=-: asked for, or one line of '
                   'stdin, or ACME_VALUE_KEY - never written out here')
    g.add_argument('--users', action='store_true', help='who may open the administration pages')
    g.add_argument('--add-user', metavar='NAME', help='make an account (--role)')
    g.add_argument('--role', choices=ROLES_ALL, default=None, help='its role (with --add-user read-only when not given)')
    g.add_argument('--passwd', metavar='NAME', help='set or reset a password (ACME_PASSWORD '
                   'in the environment for a script)')
    g.add_argument('--set-role', metavar='NAME', help='change what an account may do (--role)')
    g.add_argument('--del-user', metavar='NAME', help='remove an account')
    g.add_argument('--disable-user', metavar='NAME', help='stop an account signing in')
    g.add_argument('--enable-user', metavar='NAME', help='let it sign in again')
    g.add_argument('--console', action='store_true',
                   help='the acme console: the whole of acme by its menus and the live log '
                        '(q leaves it)')
    g.add_argument('--console-at-login', choices=('on', 'off', 'status'), metavar='on|off|status',
                   help='open the console when root signs in at the console or over SSH')
    g.add_argument('--admin-2fa', choices=('on', 'off', 'status'), metavar='on|off|status',
                   help='the second step of signing in to these pages, for every account: '
                        'switch it on or off, or say how it stands')
    g.add_argument('--reset-2fa', metavar='NAME', help='take away the second step an account set '
                   'up for these pages: it sets it up again at its next sign-in')
    g.add_argument('--note', metavar='TEXT', default='', help='a note beside what is made')
    g = p.add_argument_group('THE DATABASE AND ISEMON')
    g.add_argument('--export-config', metavar='FILE', help='the whole configuration into a JSON '
                   'file - settings, directories, accounts, the certificates of the pages, the '
                   'web address, the firewall, and the tables a module carries (its issuers, '
                   'targets...); the certificates and the logs are in --backup')
    g.add_argument('--with-secrets', action='store_true', help='--export-config: with the '
                   'secrets in the clear (passwords, private keys)')
    g.add_argument('--import-config', metavar='FILE', help='a file of --export-config (or of the '
                   'pages\' export) put in (--yes); with --replace, what is not in the file '
                   'is taken away and settings not in it go back to their defaults')
    g.add_argument('--replace', action='store_true', help='with --import-config: replace what '
                   'is here already')
    g.add_argument('--backup', action='store_true', help='a copy of the database, now')
    # The daemon's copies made by a process of their own (1.0.150), not shown.
    g.add_argument('--dump-copy', action='store_true', help=argparse.SUPPRESS)
    g.add_argument('--read-copy', metavar='FILE', help=argparse.SUPPRESS)
    g.add_argument('--restore', metavar='FILE', help='put a copy back (--yes); without --yes, '
                   'what is in it and where it was made')
    g.add_argument('--restore-bundle', metavar='FILE', help='put back a backup sent to a '
                   'destination (acme-backup-....tar.gz.enc): everything - the database, the key '
                   'of its secrets, the node\'s name; without --yes, what is in it')
    g.add_argument('--passphrase-file', metavar='FILE', help='with --restore-bundle: the '
                   'password of the backups, one line (else ACME_BACKUP_PASSWORD, else asked)')
    g.add_argument('--keep-node-name', action='store_true', help='with --restore-bundle: this '
                   'machine keeps its node name')
    g.add_argument('--rbackup-now', action='store_true', help='a backup to every destination '
                   'switched on (Settings → Backups), now')
    g.add_argument('--rbackup-status', action='store_true', help='the backup destinations and '
                   'the last backups sent')
    g.add_argument('--backup-info', metavar='FILE', help='what a copy holds and the machine it '
                   'was made on, its config.json among it')
    g.add_argument('--tidy', action='store_true', help='delete what has been kept long enough')
    g.add_argument('--isemon-test', action='store_true', help='send one line to isemon’s '
                   'receivers and say what happened')
    g = p.add_argument_group('WHAT THE PAGES DO, HERE TOO', 'For a server without its pages '
                             '(installed --no-web) or with them down (1.0.187).')
    g.add_argument('--acme', action='store_true', help='the certificates of the pages by ACME: '
                   'each one\'s name, end, who looks after it, its last order')
    g.add_argument('--acme-order', metavar='TARGET', help='order it now, followed here: a node\'s '
                   'name, vip, or all (each one ACME looks after)')
    g.add_argument('--updates', choices=('status', 'check', 'start', 'cancel'), help='the updates '
                   'of the operating system: how they stand, look for them now, start them on '
                   '--node NAME,NAME (every node when none) one at a time, or stop them')
    g.add_argument('--reboot', choices=('ask', 'auto', 'never'), default='ask', help='with '
                   '--updates start: restart a node whose update needs it - ask on the pages, '
                   'by itself, or never [ask]')
    g.add_argument('--restart-nodes', metavar='NODE,NODE', help='restart these machines now, one '
                   'at a time, the service kept on the others (all: every node)')
    g.add_argument('--restarts', action='store_true', help='the restarts asked for, and how they '
                   'went')
    g.add_argument('--mail-test', metavar='ADDRESS', help='send a test mail now, every step said')
    g.add_argument('--sms-test', metavar='NUMBER', help='send a test SMS now (a code that opens '
                   'nothing)')
    g.add_argument('--lockouts', action='store_true', help='who and what is locked out now: '
                   'the pages\' sign-ins, the codes sent')
    g.add_argument('--lockouts-clear', metavar='all|KIND:WHO', help='forget a lockout (the KIND '
                   'and WHO --lockouts shows), or every one, on every node')
    g.add_argument('--siem-test', action='store_true', help='a test line to the syslog servers '
                   '(SIEM), sent by every node (--node: one), and what each said')
    g.add_argument('--proxy-test', metavar='URL', nargs='?', const='', help='the way out through '
                   'the proxy tried on every node (an address of your own, or the upgrades\' one)')
    g.add_argument('--snmp-test', action='store_true', help='each node\'s SNMPv3 agent asked as a '
                   'manager would ask it')
    g.add_argument('--snmp-trap', action='store_true', help='a test trap from every node to the '
                   'receivers set')
    g.add_argument('--db-tls', action='store_true', help='encryption to the database server: how '
                   'each node reaches it, and its certificates')
    g.add_argument('--db-tls-probe', metavar='MODE', choices=('require', 'verify-ca', 'verify-full'),
                   help='try that mode from every node, changing nothing')
    g.add_argument('--db-tls-apply', metavar='PHASE', choices=('server', 'connect', 'server_off'),
                   help='a step of the wizard on every node: server (acme\'s certificates into the '
                   'PostgreSQLs), connect (each node\'s connection to --db-tls-mode), server_off')
    g.add_argument('--db-tls-mode', choices=('', 'require', 'verify-ca', 'verify-full'), default=None,
                   help='with --db-tls-apply connect: the mode ("" no TLS) [verify-full]')
    g.add_argument('--db-tls-ca', choices=('acme', 'system', 'given', 'keep'), default='acme',
                   help='whose authority checks the server: acme\'s, the system\'s, one given '
                   'with --ca FILE, the one kept [acme]')
    g.add_argument('--isemon-tls', action='store_true', help='the encrypted sending to isemon: '
                   'how it stands on each node')
    g.add_argument('--isemon-tls-probe', metavar='HOST[:PORT]', help='isemon over TLS tried from '
                   'every node (--db-tls-ca acme|system|given --ca FILE; --no-verify; --mtls)')
    g.add_argument('--isemon-tls-apply', metavar='HOST[:PORT]', help='send to isemon over TLS from '
                   'now on')
    g.add_argument('--isemon-tls-off', metavar='HOST', nargs='?', const='', help='back to plain '
                   'TCP (514)')
    g.add_argument('--isemon-tls-bundle', metavar='FILE', help='the zip for isemon\'s side (its '
                   'certificate and key, locked with a passphrase asked for; --names, --mtls)')
    g.add_argument('--names', metavar='N1,N2', help='with --isemon-tls-bundle, --tls-csr, '
                   '--tls-selfsigned: the names it is for')
    g.add_argument('--mtls', action='store_true', help='with --isemon-tls-*: each node shows its '
                   'own certificate too')
    g.add_argument('--ntp', action='store_true', help='the time: each node\'s servers and how far off')
    g.add_argument('--ntp-sync', action='store_true', help='set the clock of this node (--node: '
                   'another) from its servers now')
    g.add_argument('--net', action='store_true', help='each node\'s network as it read it')
    g.add_argument('--hisec', action='store_true', help='high security: every rule, kept or not, '
                   'and its exceptions')
    g.add_argument('--hisec-waive', nargs=2, metavar=('RULE', 'on|off'), help='make RULE an '
                   'exception of high security, or not any more')
    g.add_argument('--api', nargs='+', metavar=('METHOD PATH', 'BODY'), help='any page\'s question '
                   'as the pages ask it: GET /api/ntp, or POST /api/osup \'{"action": "check"}\' '
                   '(BODY - : read from stdin, for one holding a secret) - the answer as JSON')
    g = p.add_argument_group('MAINTENANCE AND UPGRADES')
    g.add_argument('--maintenance', choices=('on', 'off', 'status'), help='this node out of '
                   'service (no work of its own, /healthz 503) or back; status says which')
    g.add_argument('--node', metavar='NAME', help='with --maintenance, --set (a node\'s own '
                   'setting; * for the cluster\'s own value), --change-keep: another node of '
                   'the cluster rather than this one')
    g.add_argument('--why', metavar='TEXT', help='with --maintenance on: why, for the events')
    g.add_argument('--upgrade-status', action='store_true', help='the package sent on the pages '
                   'and how an upgrade started there is going')
    g.add_argument('--upgrade-check', action='store_true', help='look at upgrade_url now for a '
                   'newer acme (as Settings → Upgrades → Look now)')
    g.add_argument('--upgrade-online', nargs='?', const='newest', metavar='VERSION',
                   help='fetch the newest acme (or VERSION) from upgrade_url, check its '
                        'signature, and upgrade every node one at a time - followed here with '
                        'its progress (--yes: without asking)')
    g.add_argument('--upgrade-follow', action='store_true', help='follow an upgrade going on, '
                   'with its progress, until it ends')
    g.add_argument('--downgrade-check', action='store_true', help='the versions at upgrade_url '
                   'older than this one, and whether each may be gone back to')
    g.add_argument('--downgrade', metavar='VERSION|FILE', help='go back to an older acme - VERSION '
                   'from upgrade_url, or an acme-X.Y.Z.tar.gz - only when it is safe: checked '
                   'against how far back the versions that ran here allow, and against the '
                   'database\'s tables; the database itself is not touched. Every node, one at '
                   'a time (--yes: without asking)')
    g.add_argument('--rename-from-opt', action='store_true', help=argparse.SUPPRESS)
    g.add_argument('--change-keep', metavar='net|fw', choices=('net', 'fw'),
                   help='keep a change on trial: a node\'s new network (with --node) or the '
                        'firewall - not kept, it goes back by itself')
    g.add_argument('--change-back', metavar='net|fw', choices=('net', 'fw'),
                   help='put back now what was there before a change on trial')
    g.add_argument('--upgrade-cancel', action='store_true', help='stop an upgrade started on '
                   'the pages: the nodes not yet begun stay as they are')
    g = p.add_argument_group('HIGH AVAILABILITY (TWO NODES, ONE POSTGRESQL)')
    g.add_argument('--ha-status', action='store_true', help='the nodes of the cluster and how '
                   'long since each was heard from')
    g.add_argument('--ha-setup', action='store_true', help='the wizard, on the first node (as '
                   'root): checks, opens PostgreSQL to the second node, writes the bundle')
    g.add_argument('--ha-bundle', metavar='FILE', help='only the bundle for the second node, '
                   'locked with a passphrase that is printed once')
    g.add_argument('--ha-join', metavar='FILE', help='on the second node (as root): join the '
                   'cluster the bundle came from')
    g.add_argument('--ha-peer', metavar='ADDRESS', help='the other node\'s address (for '
                   '--ha-setup)')
    g.add_argument('--ha-peer-port', type=int, metavar='N', default=None,
                   help='the other node\'s PostgreSQL port (5432)')
    g.add_argument('--ha-address', metavar='ADDRESS', help='this node\'s address as the other '
                   'reaches it (default: the one it uses to reach the outside)')
    g.add_argument('--ha-shared', action='store_true', help='with --ha-setup: both nodes open '
                   'one PostgreSQL elsewhere, instead of each its own, replicated')
    g.add_argument('--ha-pause', nargs='?', const='both', choices=('both', 'in', 'out'),
                   help='stop replicating for now (in: what this node takes, out: what the '
                   'other takes from it); it waits in the slot, up to %s' % HA_SLOT_KEEP)
    g.add_argument('--ha-resume', nargs='?', const='both', choices=('both', 'in', 'out'),
                   help='replicate again, from where it stopped')
    g.add_argument('--ha-stop', action='store_true', help='replication off for good: each node '
                   'goes on alone (--yes)')
    g.add_argument('--ha-resync', action='store_true', help='rebuild this node from the other: '
                   'its tables emptied and every row copied over')
    g.add_argument('--ha-compare', action='store_true', help='the rows of every table here and '
                   'on the other node, side by side: are they the same?')
    g.add_argument('--ha-readdress', action='store_true', help='a node\'s address changed '
                   '(as root): --ha-address NEW for this node\'s own, --ha-peer NEW for the '
                   'other\'s - this node put right and the other told (docs/renaming-and-'
                   'readdressing.md)')
    g.add_argument('--ha-tls', action='store_true', help='the link between the two databases: '
                   'how it is protected, each node\'s step and certificate')
    g.add_argument('--ha-tls-repair', action='store_true', help='encrypt and check the link '
                   'between the databases (verify-full) on both nodes - or start the steps again')
    g.add_argument('--ha-tls-off', action='store_true', help='TLS between the databases off '
                   'again on both nodes (the steps the other way round; --yes)')
    g.add_argument('--ha-renamed', metavar='OLD', help='this node was called OLD: what was '
                   'kept under that name (its own settings, maintenance, certificate, place in '
                   'the VIP address) carried to its name now, and OLD off the list')
    g.add_argument('--ha-forget', metavar='NAME', help='take a node off the list for good (one '
                   'that was removed or reinstalled under another name)')
    g.add_argument('--ha-standalone', action='store_true', help='leave the cluster and go on '
                   'alone, keeping everything: replication off, the other node forgotten, '
                   'config.json one server\'s again (--yes)')
    g.add_argument('--ha-db-host', metavar='HOST', help='the database\'s address as the other '
                   'node reaches it (default: this machine\'s)')
    g.add_argument('--node-name', metavar='NAME', help='this node\'s name (--ha-join, '
                   '--ha-setup)')
    g.add_argument('--trusted-proxy', action='append', metavar='CIDR', help='the load '
                   'balancer\'s address: nginx takes the client\'s from X-Forwarded-For when '
                   'it comes from there (again for more)')
    g = p.add_argument_group('TLS AND THE VIP ADDRESS')
    g.add_argument('--web-status', action='store_true', help='the certificates of the nodes and '
                   'of the VIP address, their TLS settings, and where the address is')
    g.add_argument('--tls-for', metavar='TARGET', help='which: a node\'s name, or vip (the web '
                   'address) [this node]')
    g.add_argument('--tls-import', nargs='+', metavar='FILE', help='a certificate in: PEM '
                   'files (certificate, key, chain, root - in any order, or all in one) or a '
                   '.pfx / .p12; its password in ACME_TLS_PASSWORD')
    g.add_argument('--tls-preset', choices=['standard', 'intermediate', 'modern'],
                   help='the protocols and ciphers: standard (TLS 1.2+1.3, ECDHE), intermediate '
                   '(Mozilla, with DHE), modern (TLS 1.3 only)')
    g.add_argument('--tls-dh', choices=sorted(DH_WORDS), help='the DH parameters')
    g.add_argument('--tls-hsts', type=int, metavar='SECONDS', help='Strict-Transport-Security '
                   '(0 = none)')
    g.add_argument('--tls-csr', metavar='CN', help='a certificate request for --tls-for (its key '
                   'waits here; --names, --org): printed, for your authority - then --tls-import what '
                   'it sends back')
    g.add_argument('--tls-selfsigned', metavar='CN', help='a certificate of its own for --tls-for '
                   '(--names; --days [825])')
    g.add_argument('--org', metavar='TEXT', default='', help='with --tls-csr, --tls-selfsigned: the '
                   'organisation')
    g.add_argument('--days', type=int, default=825, help='with --tls-selfsigned: how long [825]')
    g.add_argument('--tls-export', nargs=2, metavar=('FORMAT', 'FILE'), help='the certificate of '
                   '--tls-for into FILE: pem, fullchain, der, p7b, pfx or pemkey (the last two with '
                   'its private key, locked with a password asked for; --legacy: a PFX older Windows '
                   'open)')
    g.add_argument('--legacy', action='store_true', help='with --tls-export pfx: 3DES, for Windows '
                   'before 10 (1709) and Server 2016')
    g.add_argument('--tls-forget', action='store_true', help='acme no longer looks after the TLS of '
                   '--tls-for (nginx keeps the files it has; --yes)')
    g.add_argument('--vip-set', metavar='ADDRESS/PREFIX', help='the VIP address (192.0.2.10/24), '
                   'with --vip-fqdn, --vip-vrid, --vip-iface')
    g.add_argument('--vip-fqdn', metavar='NAME', help='its host name')
    g.add_argument('--vip-vrid', type=int, metavar='N', help='its VRRP id, 1-255 [51]')
    g.add_argument('--vip-iface', action='append', metavar='NODE=IFACE', help='the interface '
                   'it goes on, on that node (again for the other; default: the one with the '
                   'node\'s address)')
    g.add_argument('--vip', choices=['on', 'off'], help='the VIP address on or off')
    g.add_argument('--vip-move', metavar='NODE', help='the VIP address to that node')
    g.add_argument('--vip-return', metavar='NODE|stay', help='where the VIP address goes back '
                   'to when it is well: a node (always back to it), or "stay" (it stays where it '
                   'is until that node fails or it is moved by hand)')
    g.add_argument('--web-retry', action='store_true', help='this node asks root again for what '
                   'failed')
    g.add_argument('--yes', action='store_true', help='do not ask')
    g.add_argument('--discard-local', action='store_true',
                   help='--ha-join: go on even though this node holds secrets of its own, '
                        'which joining throws away (1.0.59: --yes alone no longer means that)')
    for fn in HOOKS['cli_args']:
        fn(p)
    return p


HELP_EXAMPLES = [
    ('acme', 'what it is doing (the same as --status)'),
    ('acme --check', 'every part of it: the key, the copies, PHP, the directories'),
    ('acme --console', 'the menus, on the server\'s own screen'),
    ("acme --add-directory AD --hosts dc1.example.local,dc2.example.local \\\n"
     "    --base DC=example,DC=local --bind-dn acme@example.local --bind-pw -", ''),
    ("acme --set admin_directory=AD --set 'admin_group_cert=CERT_ADMINS'", ''),
    ('acme --set isemon=1 --set isemon_targets=isemon.example.local:514/tcp', ''),
    ('acme --ha-setup --ha-peer 192.0.2.12', 'make this the first node of two; then copy the '
     'bundle over'),
    ('acme --ha-join /root/acme-join-acme1.json', 'on the second node: join'),
]



def become_service_user():
    """Run as the daemon's own account when started as root, so that nothing
    the command line writes - the database file and its journal, a copy, the
    key of the secrets - ends up root's and out of the daemon's reach."""
    if os.geteuid() != 0 or os.environ.get('ACME_STAY_ROOT'):
        return
    try:
        import pwd
        import grp
        pw = pwd.getpwnam(SERVICE_USER)
    except (KeyError, ImportError):
        return
    try:
        groups = [g.gr_gid for g in grp.getgrall() if SERVICE_USER in g.gr_mem]
        os.setgroups(sorted(set(groups + [pw.pw_gid])))
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
    except OSError as e:
        sys.stderr.write('acme: could not become %s (%s); going on as root\n' % (SERVICE_USER, e))


def chown_to_service(path, mode=None):
    """A file root just wrote, given to the daemon's account - opened without
    following a link, and changed as the open file (1.0.101): by its name,
    a link put in its place meanwhile handed the service any file."""
    if os.geteuid() != 0:
        return
    ids = service_ids()
    if not ids:
        return
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
    except OSError:
        return
    try:
        if (os.fstat(fd).st_mode & 0o170000) != 0o100000:    # not a plain file
            return
        os.fchown(fd, ids[0], ids[1])
        if mode is not None:
            os.fchmod(fd, mode)
    except OSError:
        pass
    finally:
        os.close(fd)


NGINX_CONF_PATHS = ('/etc/nginx/conf.d/acme.conf', '/etc/nginx/sites-enabled/acme.conf',
                    '/etc/nginx/sites-available/acme.conf')


def nginx_trusted_proxies(cidrs, pal):
    """The load balancer's addresses into nginx: the client's own address is
    then taken from X-Forwarded-For when a request comes from one of them -
    for the allow lists, the sign-in throttle and every log."""
    conf = next((p for p in NGINX_CONF_PATHS if os.path.exists(p)), None)
    if not conf:
        print(pal.bad_line('no nginx configuration of acme was found (%s)'
                           % ', '.join(NGINX_CONF_PATHS)))
        return False
    for c in cidrs:
        address_net(c)
    text = Path(conf).read_text()
    block = ('    # REALIP-BEGIN - the load balancer(s), written by acme --trusted-proxy\n'
             + ''.join('    set_real_ip_from %s;\n' % c for c in cidrs)
             + ('    real_ip_header X-Forwarded-For;\n    real_ip_recursive on;\n' if cidrs else '')
             + '    # REALIP-END\n')
    if '# REALIP-BEGIN' in text:
        text = re.sub(r'    # REALIP-BEGIN.*?# REALIP-END\n', lambda m: block, text, flags=re.S)
    else:
        # ...in the HTTPS server, which is the one with the pages - not the
        # first block in the file, which is the port-80 redirect. The block
        # whose `listen` names 443 is the one; failing that, the last one.
        heads = list(re.finditer(r'server\s*\{[^\n]*\n', text))
        if not heads:
            print(pal.bad_line('no server block was found in %s' % conf))
            return False
        chosen = heads[-1]
        for i, h in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            if re.search(r'^\s*listen\s[^;]*\b443\b', text[h.end():end], re.M):
                chosen = h
                break
        text = text[:chosen.end()] + block + text[chosen.end():]
    Path(conf + '.before-realip').write_text(Path(conf).read_text())
    Path(conf).write_text(text)
    got = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
    if got.returncode != 0:
        Path(conf).write_text(Path(conf + '.before-realip').read_text())
        print(pal.bad_line('nginx did not take it, so it was put back: %s'
                           % (got.stderr.strip().split('\n')[-1])))
        return False
    subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)
    print(pal.ok_line('nginx takes the client\'s address from X-Forwarded-For when it comes '
                      'from %s' % ', '.join(cidrs) if cidrs else 'nginx trusts no proxy'))
    return True


def cli_ha(args, pal):
    """The high-availability wizard and its parts, as root."""
    def ask(prompt, default=''):
        if args.yes or not sys.stdin.isatty():
            return default
        got = input('%s%s: ' % (prompt, ' [%s]' % default if default else '')).strip()
        return got or default

    if os.geteuid() != 0 and (args.ha_setup or args.ha_join or args.trusted_proxy):
        raise SystemExit('acme: run this as root - it changes PostgreSQL, nginx and the key '
                         'of the sealed secrets')
    os.environ['ACME_STAY_ROOT'] = '1'
    load_config(saved=None)
    if args.trusted_proxy and not (args.ha_setup or args.ha_join):
        return 0 if nginx_trusted_proxies(args.trusted_proxy, pal) else 1

    if args.ha_join:
        try:
            bundle = Path(args.ha_join).read_text()
        except OSError as e:
            raise SystemExit('acme: %s' % e)
        phrase = os.environ.get('ACME_HA_PASSPHRASE') or getpass.getpass(
            'The passphrase printed with the bundle: ')
        try:
            data = bundle_open(bundle, phrase)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        peer = data.get('peer') or {}
        if data.get('mode') == 'replicated':
            return cli_ha_join_replicated(args, pal, data, ask)
        print(pal.head('joining the cluster of %s' % (peer.get('name') or '?'))
              + pal.dim('  (%s)' % db_where(data['db'])))
        name = args.node_name or ask('This node\'s name', socket.gethostname().split('.')[0])
        try:
            store0 = Storage(open_db())
            HA_STORE['store'] = store0
        except Exception:                               # noqa: BLE001
            pass
        def said(step, ok, words):
            print((pal.ok_line if ok else pal.warn_line)(words))
        try:
            got = ha_join(data, name, even_if_data=args.discard_local, by='command line',
                          say=said, root_now=True)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        chown_to_service(sealing_key_path(), 0o600)
        chown_to_service(CONFIG_FILE, 0o640)
        print(pal.ok_line('the database: %s (%s record(s) in it)' % (got['where'], got['rows'])))
        print(pal.ok_line('the key that opens the sealed secrets is the cluster\'s'))
        if args.trusted_proxy:
            nginx_trusted_proxies(args.trusted_proxy, pal)
        if not os.environ.get('ACME_HA_NO_RESTART'):
            subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
            print(pal.ok_line('acme started again on it as %s' % name))
        print(pal.dim('  Both nodes are in the list:  acme --ha-status'))
        print(pal.dim('  Sign in with the accounts of the cluster - the ones of this node were '
                      'in its own database, which is no longer used.'))
        return 0

    if args.ha_resync:
        return cli_ha_resync(args, pal)
    if args.ha_standalone:
        return cli_ha_standalone(args, pal)
    # --ha-setup and --ha-bundle: the first node.
    store = Storage(open_db())
    load_config(saved=store.settings_saved())
    HA_STORE['store'] = store
    host0 = str(CONFIG.get('db_host') or '')
    if store.db.engine == 'postgres' and host0 in ('', 'localhost', '127.0.0.1', '::1') \
            and not args.ha_shared and (args.ha_setup or CONFIG.get('ha_mode') == 'replicated'):
        if not args.ha_setup and CONFIG.get('ha_mode') == 'replicated':
            return cli_ha_bundle_again(args, pal, store)
        return cli_ha_setup_replicated(args, pal, store, ask)
    print(pal.head('high availability - the first node') + pal.dim('  (%s)' % node_name()))
    bad = False
    for c in ha_checks(store):
        if c['ok'] and not c.get('warn'):
            print(pal.ok_line(c['says']))
        elif c.get('warn'):
            print(pal.warn_line(c['says']))
        else:
            print(pal.bad_line(c['says']))
            bad = True
    if bad:
        return 1
    host = str(CONFIG.get('db_host') or '')
    local = host in ('', 'localhost', '127.0.0.1', '::1')
    db_host = args.ha_db_host or (node_address() if local else host)
    if args.ha_setup:
        peer = args.ha_peer or ask('The other node\'s address')
        if local:
            if not peer:
                raise SystemExit('acme: the other node\'s address is needed: --ha-peer ADDRESS')
            try:
                peer_address(peer)
            except ValueError as e:
                raise SystemExit('acme: %s' % e)
            try:
                for line in pg_open_to(peer, CONFIG.get('db_name'), CONFIG.get('db_user')):
                    print(pal.ok_line('PostgreSQL: %s' % line))
            except ValueError as e:
                raise SystemExit('acme: PostgreSQL could not be opened to %s: %s' % (peer, e))
            if True:
                listen = pg_local_admin('SELECT pending_restart FROM pg_settings WHERE '
                                        "name = 'listen_addresses'")
                if listen == 't':
                    unit = tune_restart_unit() or 'postgresql'
                    if args.yes or ask('PostgreSQL has to start again to listen on the network '
                                       '- restart %s now? (yes/no)' % unit, 'yes') == 'yes':
                        subprocess.run(['systemctl', 'restart', unit], capture_output=True)
                        print(pal.ok_line('%s started again' % unit))
                    else:
                        print(pal.bad_line('restart %s before the other node joins' % unit))
            firewall_peer(peer, pal, 5432)
        if peer:
            cli_ha_open_now(store, peer, pal)
        if args.trusted_proxy:
            nginx_trusted_proxies(args.trusted_proxy, pal)
        name = args.node_name
        if name and name != node_name():
            write_file_settings({'node_name': name})
            chown_to_service(CONFIG_FILE, 0o640)
    data = ha_bundle_data(store, db_host)
    if args.ha_setup and args.ha_peer:
        data['joining'] = args.ha_peer
    phrase = ha_passphrase()
    target = Path(args.ha_bundle or '/root/acme-join-%s.json' % node_name())
    write_private(target, json.dumps(dict(bundle_lock(data, phrase), about=ha_bundle_about(data)),
                                     indent=1) + '\n')
    store.add_event('settings', 'a bundle for a second node was made on the command line '
                    '(the database at %s)' % db_host, 'warn', who='command line')
    print('')
    print(pal.ok_line('the bundle for the second node: %s' % target))
    print('  ' + pal.bold('its passphrase, shown only now: ') + pal.info(phrase))
    print('')
    print(pal.head('on the second node'))
    print('  1. install the same version:   ./install.sh --with-db postgres --yes')
    print('  2. copy the bundle over:       scp %s root@SECOND:/root/' % target)
    print('  3. join:                       acme --ha-join /root/%s' % target.name)
    print('')
    print(pal.head('in front of both'))
    print('  HTTPS: round robin, no stickiness needed; health check  GET /healthz  (200 = up).')
    print('  The load balancer\'s address on both nodes:  acme --trusted-proxy CIDR')
    return 0


def cli_ha_open_now(store, peer, pal):
    """The node being joined let into this node's firewall at once (1.0.210),
    for a day - before the cluster is made, the firewall knew of no other
    node and kept it out."""
    try:
        ips = ha_pending_add(store, peer, 'command line', 'the node being joined')
        got = fw_apply_wait(store, 60, run_helper=True)
    except Exception as e:                              # noqa: BLE001
        print(pal.warn_line('the firewall could not be opened to %s: %s' % (peer, e)))
        return
    if got['state'] == 'done':
        print(pal.ok_line('acme\'s firewall (ACME-IN) lets %s in, for a day until it has joined '
                          '- applied: %s' % (', '.join(ips), got['said'])))
    elif got['state'] == 'off':
        print(pal.dim('  acme\'s firewall (ACME-IN): %s' % got['said']))
    else:
        print(pal.bad_line('acme\'s firewall (ACME-IN) does NOT let %s in yet: %s' % (
            ', '.join(ips), got['said'])))
    for ip in ips:
        blocks = iptables_blocks(ip)
        if blocks:
            print(pal.bad_line(blocks))


def firewall_peer(peer, pal, port=5432):
    """firewalld letting the other node - one address - reach PostgreSQL."""
    if shutil.which('firewall-cmd'):
        a = peer_address(peer)
        rule = ('rule family="%s" source address="%s/%d" port port="%d" protocol="tcp" accept'
                % ('ipv4' if a.version == 4 else 'ipv6', a, 32 if a.version == 4 else 128,
                   port))
        # Every step checked and said as it is (1.0.210): "lets ... in" was
        # printed whatever firewall-cmd answered.
        if subprocess.run(['firewall-cmd', '--state'], capture_output=True).returncode != 0:
            return
        bad = ''
        for args in (['--permanent', '--add-rich-rule=' + rule], ['--add-rich-rule=' + rule]):
            got = subprocess.run(['firewall-cmd'] + args, capture_output=True, text=True)
            if got.returncode != 0 and 'ALREADY_ENABLED' not in (got.stderr + got.stdout):
                bad = (got.stderr or got.stdout).strip()[-200:] or 'exit %d' % got.returncode
                break
        live = subprocess.run(['firewall-cmd', '--query-rich-rule=' + rule], capture_output=True)
        if bad or live.returncode != 0:
            print(pal.bad_line('firewalld does NOT let %s reach PostgreSQL (TCP %d): %s - as '
                               'root:  firewall-cmd --permanent --add-rich-rule=\'%s\' && '
                               'firewall-cmd --reload' % (peer, port, bad or 'the rule is not '
                                                          'in force', rule)))
            return
        print(pal.ok_line('firewalld lets %s reach PostgreSQL (TCP %d, zone %s): %s'
                          % (peer, port, _fw_zone(), rule)))


def cli_ha_bundle_again(args, pal, store):
    """--ha-bundle on a node already replicating: the bundle for the other
    node, made again - nothing set up, nothing restarted (1.0.207)."""
    data = ha_replicated_bundle_data(store)
    if data['db'].get('db_password') in (None, '') or is_masked(str(data['db'].get('db_password'))):
        raise SystemExit('acme: the database password is not in config.json here - the bundle '
                         'could not carry it')
    phrase = ha_passphrase()
    target = Path(args.ha_bundle or '/root/acme-join-%s.json' % node_name())
    write_private(target, json.dumps(bundle_lock(data, phrase), indent=1) + '\n')
    store.add_event('settings', 'a bundle for the other node (slot %d) was made again on the '
                    'command line - it carries the key that opens every secret' % data['slot'],
                    'warn', who='command line')
    print(pal.ok_line('the bundle for the other node (slot %d): %s' % (data['slot'], target)))
    print('  ' + pal.bold('its passphrase, shown only now: ') + pal.info(phrase))
    print('  on the other node: acme --ha-join %s --node-name NAME' % target.name)
    return 0


def cli_ha_setup_replicated(args, pal, store, ask):
    """The first node of two, each with its own PostgreSQL, replicating."""
    say = lambda t: print(pal.ok_line(t))
    print(pal.head('high availability - the first node, replicated') + pal.dim(
        '  (%s: a PostgreSQL on each node, replicating both ways)' % node_name()))
    peer = args.ha_peer or CONFIG.get('ha_peer') or ask('The other node\'s address')
    if not peer:
        raise SystemExit('acme: the other node\'s address is needed: --ha-peer ADDRESS')
    try:
        peer_address(peer)
    except ValueError as e:
        raise SystemExit('acme: %s' % e)
    port = int(CONFIG.get('db_port') or 5432)
    name, user, pw = CONFIG.get('db_name'), CONFIG.get('db_user'), CONFIG.get('db_password')
    try:
        restart, major = pg_prepare_local(port, peer, name, user, pw, say)
        if restart:
            if args.yes or ask('PostgreSQL has to start again for this (wal_level = logical, '
                               'listening on the network) - restart it now? (yes/no)',
                               'yes') == 'yes':
                pg_restart_local(port)
                say('PostgreSQL started again')
                store.db.close()
                store.db.connect()
            else:
                raise SystemExit('acme: restart PostgreSQL, then run this again')
        pg_publication(port, name)
        say('PostgreSQL publishes every table of %s (inserts, updates, deletes)' % name)
        ha_sequences(store.db, 1)
        say('this node numbers its rows odd, the other even - they never collide')
    except ValueError as e:
        raise SystemExit('acme: %s' % e)
    firewall_peer(peer, pal, port)
    cli_ha_open_now(store, peer, pal)
    if args.trusted_proxy:
        nginx_trusted_proxies(args.trusted_proxy, pal)
    me = args.ha_address or CONFIG.get('ha_address') or node_address()
    changes = {'ha_mode': 'replicated', 'ha_slot': 1, 'ha_peer': peer,
               'ha_peer_port': int(args.ha_peer_port or 5432), 'ha_address': me}
    if args.node_name:
        changes['node_name'] = args.node_name
    write_file_settings(changes)
    chown_to_service(CONFIG_FILE, 0o640)
    load_config(saved=store.settings_saved())
    # A node's own settings saved while it was alone made its own now (1.0.206):
    # kept as the plain key, they became the cluster's - the second node greeted
    # mail servers by the first one's name.
    me_now = node_name()
    held = store.settings_saved()
    for k in NODE_KEYS:
        if k in held and (k + '@' + me_now) not in held:
            store.save_setting(k + '@' + me_now, held[k], 'acme (cluster made)')
            store.drop_setting(k)
    load_config(saved=store.settings_saved())
    # Made here if the daemon never ran yet (1.0.140): the bundle held an empty
    # key, and the second node wrote an empty secrets.key and could not start.
    data = {'mode': 'replicated', 'key': sealing_key(make=True).hex(), 'pg_major': major,
            'slot': 2,
            'db': {'db_name': name, 'db_user': user, 'db_password': pw},
            'peer': {'name': node_name(), 'address': me, 'port': port, 'slot': 1},
            'cluster': CONFIG.get('site_name') or 'acme', 'joining': peer}
    phrase = ha_passphrase()
    target = Path(args.ha_bundle or '/root/acme-join-%s.json' % node_name())
    write_private(target, json.dumps(dict(bundle_lock(data, phrase), about=ha_bundle_about(data)),
                                     indent=1) + '\n')
    store.add_event('settings', 'this node became the first of two, replicating with %s; a '
                    'bundle for the second was made on the command line' % peer, 'warn',
                    who='command line')
    if not os.environ.get('ACME_HA_NO_RESTART'):
        subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
    print('')
    say('the bundle for the second node: %s' % target)
    print('  ' + pal.bold('its passphrase, shown only now: ') + pal.info(phrase))
    print('')
    print(pal.head('on the second node (%s)' % peer))
    print('  1. install the same version:   ./install.sh --with-db postgres --yes')
    print('  2. copy the bundle over:       scp %s root@%s:/root/' % (target, peer))
    print('  3. join:                       acme --ha-join /root/%s --node-name NAME' % target.name)
    print('     It installs PostgreSQL %d there if it is missing, copies every row from this '
          'node' % major)
    print('     and sets both directions of the replication up. The same command rebuilds it '
          'after a reinstall.')
    return 0


def cli_ha_join_replicated(args, pal, data, ask):
    say = lambda t: print(pal.ok_line(t))
    peer = data.get('peer') or {}
    db = data.get('db') or {}
    name, user, pw = db.get('db_name'), db.get('db_user'), db.get('db_password')
    if not re.match(r'^[0-9a-f]{64}\Z', str(data.get('key') or '')):
        raise SystemExit('acme: the bundle holds no key - make it again on the first node '
                         '(acme --ha-bundle), with this version')
    print(pal.head('joining %s - a PostgreSQL on each node, replicating both ways'
                   % (peer.get('name') or '?')))
    node = args.node_name or ask('This node\'s name', socket.gethostname().split('.')[0])
    port = int(FILE_CONFIG.get('db_port') or 5432) if FILE_CONFIG.get('db_engine') == 'postgres' \
        else 5432
    # Marked as begun (1.0.210): a join that stops half way left a PostgreSQL
    # account with the cluster's password and config.json without it, and
    # every command said only "password authentication failed".
    try:
        write_private(HA_JOINING_FILE, json.dumps({
            'at': time.time(), 'file': str(Path(args.ha_join).resolve()), 'node': node,
            'peer': peer.get('address'), 'peer_name': peer.get('name')}) + '\n')
    except OSError:
        pass
    # This node's own address before PostgreSQL is prepared (1.0.210): its
    # line in pg_hba.conf is for the address given here, the one the other
    # node's subscription comes back to.
    if args.ha_address:
        CONFIG['ha_address'] = args.ha_address
    # The first node let into this one's firewall before anything is asked of
    # it (1.0.210): with the firewall on, the copy failed on a dropped packet.
    try:
        # The database this node has now (not HA_STORE: the rebuild below
        # writes its maintenance into that one).
        FW_HERE['store'] = Storage(open_db())
        fw = ha_join_open(FW_HERE['store'], data, 'command line', root_now=True)
        (say if fw['state'] in ('done', 'off') else (lambda t: print(pal.bad_line(t))))(
            'the firewall: %s' % fw['said'])
        blocks = iptables_blocks(peer.get('address') or '')
        if blocks:
            print(pal.bad_line(blocks))
    except Exception as e:                              # noqa: BLE001
        print(pal.warn_line('the firewall could not be opened to %s: %s' % (
            peer.get('address'), e)))
    try:
        if not pg_local_running(port):
            pg_install_local(int(data.get('pg_major') or 16), say)
        restart, major = pg_prepare_local(port, peer['address'], name, user, pw, say)
        if restart:
            pg_restart_local(port)
            say('PostgreSQL started again')
        firewall_peer(peer['address'], pal, port)
        local = db_open({'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': port,
                         'db_name': name, 'db_user': user, 'db_password': pw})
        local.make_tables()
        local.add_missing_columns()
        pg_publication(port, name)
        remote = db_open({'db_engine': 'postgres', 'db_host': peer['address'],
                          'db_port': int(peer.get('port') or 5432), 'db_name': name,
                          'db_user': user, 'db_password': pw})
        me = args.ha_address or node_address()
        # The daemon stopped while the rows come over, as --ha-resync does
        # (1.0.59): its heartbeat written into the tables being copied
        # stopped the copy on a duplicate key. Started again at the end.
        if os.geteuid() == 0 and not os.environ.get('ACME_HA_NO_RESTART') and \
                subprocess.run(['systemctl', 'is-active', '--quiet', 'acme']).returncode == 0:
            subprocess.run(['systemctl', 'stop', 'acme'], capture_output=True)
            say('acme is stopped on this node while the rows come over')
        got = ha_rebuild(local, remote, int(data.get('slot') or 2), int(peer.get('slot') or 1),
                         me, port, peer['address'], int(peer.get('port') or 5432),
                         name, user, pw, lambda t: print(pal.dim('  ' + t)))
        remote.close()
        local.close()
    except (ValueError, DbError) as e:
        if os.geteuid() == 0 and not os.environ.get('ACME_HA_NO_RESTART'):
            subprocess.run(['systemctl', 'start', 'acme'], capture_output=True)
        try:
            j = json.loads(HA_JOINING_FILE.read_text())
            j['error'] = scrub_secret(str(e))[:300]
            write_private(HA_JOINING_FILE, json.dumps(j) + '\n')
        except (OSError, ValueError):
            pass
        raise SystemExit('acme: %s\nacme: the join stopped half way - run the same command '
                         'again: it drops what was left and starts afresh' % e)
    now = sealing_key()
    if now and now.hex() != data['key']:
        write_replacing(sealing_key_path().with_name('secrets.key.before-join'), now.hex() + '\n',
                        0o600)
    write_replacing(sealing_key_path(), data['key'] + '\n', 0o600)
    chown_to_service(sealing_key_path(), 0o600)
    write_file_settings({'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': port,
                         'db_name': name, 'db_user': user, 'db_password': pw,
                         'node_name': node, 'ha_mode': 'replicated',
                         'ha_slot': int(data.get('slot') or 2), 'ha_peer': peer['address'],
                         'ha_peer_port': int(peer.get('port') or 5432), 'ha_address': me})
    chown_to_service(CONFIG_FILE, 0o640)
    try:
        HA_JOINING_FILE.unlink()
    except OSError:
        pass
    say('every row of %s is here: %d' % (peer.get('name') or 'the other node', got['rows']))
    say('both directions replicate: this node -> %s and %s -> this node'
        % (peer.get('name'), peer.get('name')))
    if args.trusted_proxy:
        nginx_trusted_proxies(args.trusted_proxy, pal)
    if not os.environ.get('ACME_HA_NO_RESTART'):
        subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
        say('acme started again as %s, on its own PostgreSQL' % node)
    print(pal.dim('  acme --ha-status shows both nodes and both directions.'))
    return 0


def cli_sure(args, what):
    """A destructive step asked about once (1.0.59): --yes says it ahead,
    a terminal is asked, anything else is refused."""
    if getattr(args, 'yes', False):
        return
    if sys.stdin.isatty():
        try:
            said = input('acme: %s. Type yes to go on: ' % what)
        except EOFError:
            said = ''
        if said.strip().lower() == 'yes':
            return
        raise SystemExit('acme: nothing was changed')
    raise SystemExit('acme: %s - again with --yes' % what)


def cli_ha_resync(args, pal):
    load_config(saved=None)
    if CONFIG.get('ha_mode') != 'replicated':
        raise SystemExit('acme: this node does not replicate (ha_mode is not "replicated")')
    # Root only (1.0.59): anybody else could not stop the daemon, and the
    # copy went on with it writing - the very thing that stops it for good.
    if os.geteuid() != 0:
        raise SystemExit('acme: --ha-resync is run as root (sudo acme --ha-resync --yes)')
    if not args.yes:
        raise SystemExit('acme: this empties this node\'s tables and copies every row from '
                         '%s - again with --yes' % CONFIG.get('ha_peer'))
    # The daemon stopped while the rows come over (1.0.47): it is another
    # process, and its heartbeat written meanwhile met the same row coming
    # from the other node - the copy stopped there for good.
    stopped = False
    if os.geteuid() == 0 and not os.environ.get('ACME_HA_NO_RESTART') and \
            subprocess.run(['systemctl', 'is-active', '--quiet', 'acme']).returncode == 0:
        subprocess.run(['systemctl', 'stop', 'acme'], capture_output=True)
        stopped = True
        print(pal.dim('  acme is stopped on this node while it is rebuilt (the other node answers)'))
    try:
        local = open_db()
        # What is here kept first, as the pages do (1.0.47): a rebuild
        # replaces all of it.
        try:
            kept = make_backup(Storage(local), 'before this node was rebuilt from the other, '
                               'on the command line')
            print(pal.ok_line('a copy of what was here: %s' % kept))
        except Exception as e:                          # noqa: BLE001
            raise SystemExit('acme: no copy of what is here could be made, so nothing was '
                             'changed: %s' % e)
        remote = ha_peer_db()
        got = ha_rebuild(local, remote, int(CONFIG.get('ha_slot') or 2),
                         3 - int(CONFIG.get('ha_slot') or 2),
                         CONFIG.get('ha_address') or node_address(),
                         int(CONFIG.get('db_port') or 5432), CONFIG.get('ha_peer'),
                         int(CONFIG.get('ha_peer_port') or 5432), CONFIG.get('db_name'),
                         CONFIG.get('db_user'), CONFIG.get('db_password'),
                         lambda t: print(pal.dim('  ' + t)))
    except (ValueError, DbError) as e:
        raise SystemExit('acme: %s' % e)
    finally:
        if stopped:
            subprocess.run(['systemctl', 'start', 'acme'], capture_output=True)
            print(pal.dim('  acme is started again on this node'))
    print(pal.ok_line('rebuilt from %s: %d row(s)' % (CONFIG.get('ha_peer'), got['rows'])))
    return 0


def cli_ha_standalone(args, pal):
    """This node out of the cluster, on its own, with everything it has
    (1.0.47): the replication taken away (as --ha-stop), what is left of it
    in this PostgreSQL removed, the other nodes forgotten, and config.json
    a single server's again. The database, the key, the settings, the
    certificates and the accounts stay as they are."""
    if os.geteuid() != 0:
        raise SystemExit('acme: run this as root - it writes config.json and restarts acme')
    if not CONFIG.get('ha_mode') and not args.yes:
        raise SystemExit('acme: this node is not one of a cluster (ha_mode is empty)')
    if not args.yes:
        raise SystemExit('acme: this takes this node out of the cluster for good: the replication '
                         'goes, the other node is forgotten, and it answers alone with what it '
                         'has - again with --yes')
    say = lambda t: print(pal.ok_line(t))
    try:
        store = Storage(open_db())
    except DbError as e:
        raise SystemExit('acme: %s' % e)
    load_config(saved=store.settings_saved())
    HA_STORE['store'] = store
    mode = CONFIG.get('ha_mode') or ''
    if mode == 'replicated' and store.db.engine == 'postgres':
        try:
            say(ha_control(store, 'stop', by='command line')['message'])
        except Exception as e:                          # noqa: BLE001
            print(pal.warn_line('the replication: %s' % str(e).split('\n')[0][:200]))
        # Whatever is left of it here - the other node gone for good, or
        # names from before - taken away too.
        for r in store.db.rows("SELECT subname FROM pg_subscription WHERE subdbid = (SELECT oid "
                               "FROM pg_database WHERE datname = current_database()) AND subname "
                               "LIKE 'acme!_from!_%' ESCAPE '!'"):
            ha_drop_sub(store.db, r['subname'])
            say('the subscription %s is gone' % r['subname'])
        for r in store.db.rows("SELECT slot_name FROM pg_replication_slots WHERE slot_name "
                               "LIKE 'acme!_from!_%' ESCAPE '!' AND database = current_database()"):
            try:
                _ha_drop_slot(store.db, r['slot_name'])
                say('the replication slot %s is gone (nothing is kept for the other node '
                    'any more)' % r['slot_name'])
            except Exception as e:                      # noqa: BLE001
                print(pal.warn_line('the slot %s: %s' % (r['slot_name'], e)))
    for n in ha_nodes(store):
        if n['me']:
            continue
        ha_forget(store, n['name'])
        store.db.run('DELETE FROM meta WHERE k IN (?, ?)',
                     ('maint:' + n['name'], 'upgrade:node:' + n['name']))
        say('%s is off the list of nodes' % n['name'])
    write_file_settings({'ha_mode': '', 'ha_slot': 0, 'ha_peer': '', 'ha_address': '',
                         'ha_peer_port': DEFAULTS.get('ha_peer_port')})
    chown_to_service(CONFIG_FILE, 0o640)
    say('%s: a single server again (the database, the key and the node\'s name are kept)'
        % CONFIG_FILE)
    store.add_event('settings', '%s left the cluster on the command line and answers alone'
                    % node_name(), 'warn', who='command line')
    store.db.close()
    if not os.environ.get('ACME_HA_NO_RESTART'):
        subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
        say('acme started again, alone')
    if mode == 'shared':
        print(pal.warn_line('the other node still opens the same database: stop it or '
                            'uninstall it there, or it goes on answering from it'))
    print(pal.dim('  The other node, if it still runs: acme --ha-standalone --yes there too, '
                  'or uninstall it.'))
    return 0


# What a row of each table of the configuration holds, compared between the
# nodes - without what changes at every sign-in (1.0.207). A module's tables of
# the configuration (HOOKS['carry_tables']) are compared row by row whole.
HA_CONTENT = {
    'settings': ('k', "concat_ws('/', k, v)"),
    'accounts': ('name', "concat_ws('/', name, role, pw, source, disabled, must_change, dn)"),
    'directories': ('name', "concat_ws('/', name, hosts, port, tls, verify, ca, base, bind_dn, "
                            "bind_pw, user_attr, nested, timeout_s, enabled, weak)"),
}


def cli_ha_compare(store, pal, as_json=False):
    """Every table counted here and on the other node (1.0.47)."""
    if CONFIG.get('ha_mode') != 'replicated':
        raise SystemExit('acme: this node does not replicate (ha_mode is %r) - with one shared '
                         'database there is nothing to compare' % (CONFIG.get('ha_mode') or ''))
    try:
        far = ha_peer_db()
    except Exception as e:                              # noqa: BLE001
        raise SystemExit('acme: the other node\'s PostgreSQL cannot be reached: %s'
                         % str(e).split('\n')[0][:200])
    rows, same = [], True
    try:
        for t in TABLES:
            if t == 'meta':
                q = ("SELECT COUNT(*) FROM meta WHERE " + ' AND '.join(
                    "k NOT LIKE '%s%%'" % p for p in META_TRANSIENT))
                here_n, there_n = store.db.value(q), far.value(q)
                here_m = there_m = None
            else:
                here_n = store.db.value('SELECT COUNT(*) FROM %s' % t)
                there_n = far.value('SELECT COUNT(*) FROM %s' % t)
                if 'id' in [c.lower() for c in store.db.columns(t)]:
                    here_m = store.db.value('SELECT MAX(id) FROM %s' % t)
                    there_m = far.value('SELECT MAX(id) FROM %s' % t)
                else:
                    here_m = there_m = None
            ok = int(here_n or 0) == int(there_n or 0) and here_m == there_m
            if ok and t not in HA_CONTENT and t in carry_tables():
                q = ("SELECT md5(COALESCE(string_agg(row_to_json(x)::text, '|' ORDER BY x.id), "
                     "'')) FROM %s x" % t)
                ok = store.db.value(q) == far.value(q)
            elif ok and t in HA_CONTENT:
                # The same number of rows, but what is in them (1.0.207): a
                # setting or an account changed on both nodes while the link
                # was down stayed swapped and was counted "same".
                q = ("SELECT md5(COALESCE(string_agg(%s, '|' ORDER BY %s COLLATE \"C\"), '')) "
                     "FROM %s" % (HA_CONTENT[t][1], HA_CONTENT[t][0], t))
                ok = store.db.value(q) == far.value(q)
            same = same and ok
            rows.append((t, here_n, there_n, here_m, there_m, ok))
    finally:
        far.close()
    if as_json:
        print(json.dumps({'same': same, 'tables': [dict(zip(
            ('table', 'here', 'there', 'max_id_here', 'max_id_there', 'same'), r))
            for r in rows]}, default=str))
        return 0 if same else 4
    print(table([(t, str(a), str(b), str(c if c is not None else '-'),
                  str(d if d is not None else '-'), 'same' if ok else 'DIFFERENT')
                 for t, a, b, c, d, ok in rows],
                ['table', 'rows here (%s)' % node_name(), 'rows there', 'last id here',
                 'last id there', '']))
    if same:
        print(pal.ok_line('both nodes hold the same rows'))
    else:
        print(pal.warn_line('they differ. A moment after a change that is normal (the logs '
                            'grow on both): ask again in a few seconds. If it stays so, see '
                            'acme --ha-status; the node that was away is rebuilt with '
                            'acme --ha-resync --yes ON THAT NODE.'))
    return 0 if same else 4


def cli_web(args, pal, store):
    """TLS and the VIP address on the command line (1.0.47)."""
    who = 'command line'
    me = node_name()
    target = args.tls_for or me
    if (args.tls_import or args.tls_preset or args.tls_dh or args.tls_hsts is not None) and \
            target not in tls_targets(store):
        raise ValueError('there is no node or address called %s (a node\'s name, or vip)'
                         % target)
    said = []
    if args.tls_import:
        pem, pfx = '', b''
        for raw in args.tls_files:
            if b'-----BEGIN' in raw:
                pem += raw.decode('utf-8', 'replace') + '\n'
            else:
                if pfx:
                    raise ValueError('one .pfx / .p12 at a time')
                pfx = raw
        prof = tls_profile(store, target) or {}
        pending = unseal_secret(prof['pending_key'], 'web:tls') if prof.get('pending_key') else ''
        got = cert_bundle(cert=pem, pfx=pfx, password=os.environ.get('ACME_TLS_PASSWORD', ''),
                          pending_key=pending)
        # As on the pages (1.0.187): one run out is not put in.
        if got['info'].get('not_after') and got['info']['not_after'] < time.time():
            raise ValueError('this certificate ran out on %s' % stamp(got['info']['not_after']))
        prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                    key=seal_secret(got['key'], 'web:tls'), info=got['info'],
                    chain_info=got['chain_info'], root_info=got['root_info'],
                    verify=got['verify'], how='imported on the command line')
        prof.pop('pending_key', None)
        prof.pop('csr', None)
        prof.setdefault('preset', 'standard')
        prof.setdefault('dh', 'none')
        tls_save(store, target, prof, who)
        # One put in by hand is kept (1.0.170; here too since 1.0.187): ACME's
        # next renewal replaced it.
        acme_care_set(store, target, False, who, 'a certificate was put in by hand')
        i = got['info']
        said.append('%s: %s, until %s, %d in the chain, root %s%s' % (
            target, i.get('subject'), stamp(i.get('not_after')), len(got['chain_info']),
            'given' if got['root'] else 'not given',
            ', chain checked' if got['verify'] == 'ok' else
            (' - the chain does not check: %s' % got['verify'] if got['verify'] else '')))
        store.add_event('settings', 'a certificate was put in for %s on the command line: %s'
                        % (target, i.get('subject')), 'warn', who=who)
    if args.tls_preset or args.tls_dh or args.tls_hsts is not None:
        prof = tls_profile(store, target) or {}
        pol = tls_policy_checked({'preset': args.tls_preset or prof.get('preset') or 'standard',
                                  'protocols': prof.get('protocols'),
                                  'ciphers': prof.get('ciphers'),
                                  'dh': args.tls_dh or prof.get('dh') or 'none',
                                  'prefer': prof.get('prefer'),
                                  'hsts': args.tls_hsts if args.tls_hsts is not None
                                  else prof.get('hsts') or 0})
        prof.update(pol)
        tls_save(store, target, prof, who)
        said.append('%s: %s, DH %s, HSTS %s' % (target, pol['preset'], pol['dh'],
                                               pol['hsts'] or 'off'))
        store.add_event('settings', 'the TLS of %s was changed on the command line: %s, DH %s, '
                        'HSTS %s' % (target, pol['preset'], pol['dh'], pol['hsts'] or 'off'), who=who)
    if args.vip_set or args.vip or args.vip_move or args.vip_return:
        if not CONFIG.get('ha_mode'):
            raise ValueError('the VIP address is for a cluster: acme --ha-setup first')
    if args.vip_set:
        v = vip_conf(store)
        ifaces = dict(v.get('ifaces') or {})
        for one in args.vip_iface or []:
            if '=' not in one:
                raise ValueError('--vip-iface NODE=IFACE')
            k, val = one.split('=', 1)
            ifaces[k.strip()] = val.strip()
        got = vip_checked({'address': args.vip_set, 'fqdn': args.vip_fqdn
                           if args.vip_fqdn is not None else v.get('fqdn'),
                           'vrid': args.vip_vrid or v.get('vrid') or 51, 'ifaces': ifaces},
                          store)
        vip_set(store, who, **got)
        said.append('the VIP address: %s%s, VRRP id %d' % (
            got['address'], ' (%s)' % got['fqdn'] if got['fqdn'] else '', got['vrid']))
    if args.vip:
        v = vip_conf(store)
        if args.vip == 'on' and not v.get('address'):
            raise ValueError('give the address first: --vip-set 192.0.2.10/24')
        vip_set(store, who, on=args.vip == 'on')
        store.add_event('settings', 'the VIP address was turned %s on the command line'
                        % args.vip, 'warn', who=who)
        said.append('the VIP address is %s' % args.vip)
    if args.vip_return:
        if args.vip_return == 'stay':
            vip_set(store, who, mode='stays')
            said.append('the VIP address stays where it is: it moves only when that node fails '
                        'or by hand')
        else:
            if args.vip_return not in {n['name'] for n in ha_nodes(store)}:
                raise ValueError('there is no node called %s' % args.vip_return)
            vip_set(store, who, mode='back', prefer=args.vip_return)
            said.append('the VIP address always goes back to %s' % args.vip_return)
        store.add_event('settings', 'the VIP address: %s, on the command line' % said[-1],
                        'warn', who=who)
    if args.vip_move:
        names = {n['name']: n for n in ha_nodes(store)}
        if args.vip_move not in names:
            raise ValueError('there is no node called %s' % args.vip_move)
        if vip_conf(store).get('mode') == 'stays':
            vip_set(store, who, move_to=args.vip_move, move_at=time.time())
        else:
            vip_set(store, who, prefer=args.vip_move)
        store.add_event('settings', 'the VIP address was moved to %s on the command line'
                        % args.vip_move, 'warn', who=who)
        said.append('the VIP address goes to %s (when it is healthy)' % args.vip_move)
    if args.web_retry:
        store.set_meta('web:retry:' + me, str(time.time()))
        said.append('%s asks root again' % me)
    for w in said:
        print(pal.ok_line(w))
    if said:
        print(pal.dim('  each node puts it in within a few seconds: acme --web-status'))
        return 0
    # --web-status
    v = vip_conf(store)
    beats = {n['name']: n for n in ha_nodes(store)}
    if args.json:
        print(json.dumps({'vip': v, 'nodes': {k: (b.get('web') if not b['me'] else web_state(store))
                                               for k, b in beats.items()},
                          'tls': {t: tls_view(tls_profile(store, t)) for t in tls_targets(store)}},
                         default=str))
        return 0
    print(pal.head('the VIP address'))
    if not CONFIG.get('ha_mode'):
        print(pal.dim('  one server: no VIP address (it is for a cluster)'))
    elif not v.get('address'):
        print(pal.dim('  not set: acme --vip-set 192.0.2.10/24 --vip-fqdn acme.example.cz'))
    else:
        print('  %s%s, VRRP id %s, %s, meant to be on %s' % (
            v['address'], ' (%s)' % v['fqdn'] if v.get('fqdn') else '', v.get('vrid') or 51,
            pal.good('ON') if v.get('on') else pal.dim('off'), vip_prefer(store, v)))
    for name, b in sorted(beats.items()):
        # What the daemons said in their heartbeats - not this command's own
        # look, which knows nothing of the daemon's health checks.
        w = b.get('web') or {}
        line = '%-16s %s' % (name, 'HOLDS THE ADDRESS' if w.get('vip_here') else
                             (w.get('role') or '-'))
        hl = w.get('health') or {}
        if v.get('on'):
            line += '  health: %s' % ('ok' if hl.get('ok') else 'NOT OK - %s' % (hl.get('why') or '?'))
        line += '  root: %s%s' % (w.get('state') or 'nothing asked yet',
                                  '' if w.get('current') or not w.get('state') else ' (not current)')
        print(('  ' + line) if b.get('alive') else pal.bad_line(line + ' (not answering)'))
        for s in (w.get('said') or [])[-3:]:
            print(pal.dim('      ' + s))
    print(pal.head('TLS'))
    for t in tls_targets(store):
        prof = tls_profile(store, t)
        b = beats.get(t, {})
        now = (b.get('web') or {}).get('cert_now') if t != 'vip' else None
        if t == me:
            now = web_state(store).get('cert_now')
        i = (prof or {}).get('info') or now or {}
        left = (float(i['not_after']) - time.time()) / 86400 if i.get('not_after') else None
        print('  %-16s %s%s' % (t, i.get('subject') or pal.dim('no certificate of its own'),
                                ', until %s (%d days)' % (stamp(i['not_after']), left)
                                if left is not None else ''))
        if prof:
            print(pal.dim('                   %s, DH %s%s%s' % (
                prof.get('preset') or 'standard', prof.get('dh') or 'none',
                ', HSTS %s s' % prof['hsts'] if prof.get('hsts') else '',
                ', a request waits for its certificate' if prof.get('pending_key') else '')))
        elif t != 'vip':
            print(pal.dim('                   as install.sh made it (acme does not look after it)'))
    return 0


def cli_stage_files(args):
    """The files named on the command line, opened as whoever typed it - root
    - before the service's account takes over (1.0.103): a backup, a
    configuration in /root was not the acme account's
    to read, and the documented recovery failed with "Permission denied".
    Copied into a folder of the service's own, taken away at the end; a file
    to write is opened now and written to later."""
    if os.geteuid() != 0 or os.environ.get('ACME_STAY_ROOT'):
        return
    ids = service_ids()
    if not ids:
        return
    import atexit
    import stat

    def reachable(path):
        """A file the acme account can get at by itself (1.0.149): any step of
        its path that account's, or under its own folders. Not copied by
        root - the acme account opens it, and a link it planted there leads
        only where it may go anyway (/etc/shadow was copied to it)."""
        p = os.path.abspath(str(path))
        try:
            real = os.path.realpath(p)
        except OSError:
            real = p
        for own in (STATE_DIR, LOG_DIR, RUN_DIR, CONFIG_FILE.parent):
            o = os.path.realpath(str(own))
            if real == o or real.startswith(o + os.sep) or p.startswith(o + os.sep):
                return True
        cur = p
        while True:
            try:
                if os.lstat(cur).st_uid == ids[0]:
                    return True
            except OSError:
                pass
            up = os.path.dirname(cur)
            if up == cur:
                return False
            cur = up

    def copy_in(src, dst):
        """One file copied by its descriptors, never by name: not through a
        link at either end, into a new file only."""
        fi = os.open(str(src), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
        try:
            if not stat.S_ISREG(os.fstat(fi).st_mode):
                raise OSError('%s is not a plain file' % src)
            fo = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                while True:
                    chunk = os.read(fi, 1 << 20)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(fo, view):]
                os.fchown(fo, ids[0], ids[1])
            finally:
                os.close(fo)
        finally:
            os.close(fi)

    def stage(path, with_key=False):
        src = Path(path)
        if not src.exists() or reachable(src):
            return path             # said by the command itself / its own to open
        if src.is_symlink():
            src = Path(os.path.realpath(str(src)))   # a link of root's own, followed
        # A folder of root's for each file, 0700 while it is filled, the acme
        # account's only once it is (1.0.149): handed over before the copy,
        # a link put in it in between had root write wherever it led.
        d = tempfile.mkdtemp(prefix='.acme-cli-', dir=str(STATE_DIR))
        atexit.register(shutil.rmtree, d, True)
        dst = Path(d) / src.name
        if src.is_dir():
            shutil.copytree(str(src), str(dst), symlinks=False)
            for root, dirs, files in os.walk(str(dst)):
                for n in dirs + files:
                    os.lchown(os.path.join(root, n), ids[0], ids[1])
            os.lchown(str(dst), ids[0], ids[1])
        else:
            copy_in(src, dst)
            if with_key:
                k = _key_beside(src)
                if k is not None and Path(k).is_file():
                    copy_in(k, Path(d) / Path(k).name)
        os.chown(d, ids[0], ids[1])
        return str(dst)
    try:
        if getattr(args, 'restore', None):
            args.restore = stage(args.restore, with_key=True)
        if getattr(args, 'restore_bundle', None):
            args.restore_bundle = stage(args.restore_bundle)
        if getattr(args, 'passphrase_file', None):
            args.passphrase_file = stage(args.passphrase_file)
        if getattr(args, 'backup_info', None):
            args.backup_info = stage(args.backup_info, with_key=True)
        if getattr(args, 'import_config', None):
            args.import_config = stage(args.import_config)
        # A package to go back to and a directory's authority (1.0.146): in
        # /root, where the docs put them, the acme account could not read them.
        if getattr(args, 'downgrade', None) and (
                args.downgrade.endswith(('.tar.gz', '.tgz')) or os.path.sep in args.downgrade):
            args.downgrade = stage(args.downgrade)
        if getattr(args, 'ca', None):
            args.ca = stage(args.ca)
        if getattr(args, 'export_config', None) and args.export_config != '-':
            mode = 0o600 if getattr(args, 'with_secrets', False) else 0o640
            fd = os.open(args.export_config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                         os.O_NOFOLLOW, mode)
            os.fchmod(fd, mode)
            args.export_fd = fd
    except OSError as e:
        raise SystemExit('acme: %s' % e)


HA_JOINING_FILE = STATE_DIR / 'ha-joining.json'


def ha_joining_words():
    """A join begun on this node and not finished (1.0.210), in words that say
    what state it is left in and what to run - '' when there is none."""
    try:
        j = json.loads(HA_JOINING_FILE.read_text())
    except (OSError, ValueError):
        return ''
    return ('this node is half joined: acme --ha-join %s (the cluster of %s at %s) began %s '
            'and did not finish%s. Its PostgreSQL account already has the cluster\'s password '
            '(so config.json\'s no longer opens it) and its tables may be half copied. Run it '
            'again - it starts afresh, dropping what was left:  acme --ha-join %s --node-name '
            '%s   (acme --ha-status on %s shows the other side)' % (
                j.get('file') or 'FILE', j.get('peer_name') or '?', j.get('peer') or '?',
                time.strftime('%Y-%m-%d %H:%M', time.localtime(float(j.get('at') or 0))),
                (' (%s)' % j['error']) if j.get('error') else '', j.get('file') or 'FILE',
                j.get('node') or 'NAME', j.get('peer_name') or 'the other node'))


def cli_store():
    become_service_user()
    load_config(saved=None)
    try:
        db = open_db()
    except DbError as e:
        half = ha_joining_words()
        if half:
            raise SystemExit('acme: %s\nacme: %s' % (e, half))
        raise SystemExit('acme: %s' % e)
    store = Storage(db, quick=True)
    _cli_name_held()
    load_config(saved=store.settings_saved())
    return store


def _cli_name_held():
    """The name the running daemon answers under (1.0.207): node_name changed in
    config.json applies when it starts again - the command line took the new
    one at once and acted as a node that was not there (maintenance of a phantom,
    --ha-forget of the running node)."""
    try:
        pid = int((STATE_DIR / 'acme.lock').read_text().strip() or 0)
        held = NODE_NAME_FILE.read_text().strip()
        if pid > 1 and held:
            os.kill(pid, 0)
        else:
            return
    except (OSError, ValueError):
        return
    if held != node_name():
        print('acme: the daemon runs as %s until it starts again (node_name %s is for then) - '
              'this acts as %s' % (held, node_name(), held), file=sys.stderr)
        CONFIG['node_name'] = held
        NAME_HELD[0] = True


def bump(store):
    store.set_meta('conf_serial', '%.6f:%s' % (time.time(), node_name()))


def upgrade_percent(st, plan):
    """How far one node is, as the pages draw it."""
    now = time.time()
    since = now - float(st.get('at') or now)
    state = st.get('state')
    if state in ('done', 'failed'):
        return 100
    if state == 'draining':
        return round(3 + 17 * min(1, since / max(1, float(plan.get('drain_s') or 20))))
    if state == 'installing':
        asked = now - float(st.get('asked') or st.get('at') or now)
        return round(min(82, 20 + 60 * min(0.95, float(st.get('part') or 0) / 6)
                         + min(6, asked / 15)))
    if state == 'checking':
        return round(85 + min(10, since / 3))
    return 0


def cli_upgrade_follow(store, pal):
    """An upgrade followed on the terminal: a bar for the whole and one for each
    node, drawn again in place every second, until it ends. Ctrl+C stops the
    following, not the upgrade."""
    tty = sys.stdout.isatty()
    drawn = 0
    last = None
    try:
        while True:
            try:
                plan = upgrade_plan(store)
            except Exception as e:                      # noqa: BLE001 - a node restarting
                plan = last
                if plan is None:
                    raise SystemExit('acme: %s' % e)
            if not plan:
                print('no upgrade going on')
                return 0
            last = plan
            steps = plan.get('steps') or []
            whole = round(sum(upgrade_percent(x, plan) for x in steps) / len(steps)) if steps else 0
            try:
                width = max(20, min(50, shutil.get_terminal_size((100, 24)).columns - 60))
            except Exception:                           # noqa: BLE001
                width = 30

            def bar(pc, bad=False, good=False):
                n = int(round(width * pc / 100.0))
                fill = '█' * n + '░' * (width - n)
                paint = pal.bad if bad else (pal.good if good else pal.info)
                return paint(fill) + ' %3d %%' % pc
            lines = [pal.head(('going back to %s' if plan.get('downgrade') else 'upgrade to %s')
                              % plan.get('version')) + pal.dim(
                '  started by %s · %s' % (plan.get('by') or '?', plan.get('state')))]
            lines.append('  %-16s %s  %d of %d node(s) done' % (
                'all', bar(whole, plan.get('state') == 'failed', plan.get('state') == 'done'),
                sum(1 for x in steps if x.get('state') == 'done'), len(steps)))
            for x in steps:
                pc = upgrade_percent(x, plan)
                words = x.get('said') or x.get('state') or 'waiting'
                if x.get('state') == 'installing' and x.get('part_words'):
                    words = x['part_words']
                lines.append('  %-16s %s  %s' % (x['name'][:16], bar(
                    pc, x.get('state') == 'failed', x.get('state') == 'done'),
                    str(words)[:60]))
            # Past ColourOut (1.0.146): it shows any escape that is not a
            # colour as text - the frame was drawn again below, never over.
            sys.stdout.flush()
            raw = getattr(sys.stdout, 's', sys.stdout)
            if tty and drawn:
                raw.write('\x1b[%dA' % drawn)
            for ln in lines:
                raw.write(('\x1b[2K' if tty else '') + term_safe(ln) + '\n')
            raw.flush()
            drawn = len(lines)
            if plan.get('state') != 'running':
                ok = plan.get('state') == 'done'
                print((pal.ok_line if ok else pal.bad_line)(
                    '%s %s' % ('going back' if plan.get('downgrade') else 'the upgrade',
                               'is done - every node runs %s' % plan.get('version')
                               if ok else 'ended: %s' % plan.get('state'))))
                return 0 if ok else 1
            if not tty:
                drawn = 0
            time.sleep(1 if tty else 5)
    except KeyboardInterrupt:
        print('\n' + pal.dim('no longer followed here - it goes on; acme --upgrade-follow '
                             'follows it again'))
        return 0


def cli_main(argv=None):
    global _LOG_TO_STDERR
    said = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    pal = Palette(colour_wanted(any(x in ('--no-color', '--no-colour') for x in said))
                  and '--json' not in said)
    parser.palette = pal
    global TABLE_PAL
    TABLE_PAL = pal
    args = parser.parse_args(argv)
    # Every line coloured (1.0.132) - not the console's own screen, nor JSON.
    # On a terminal always: what is printed is made safe there (1.0.139).
    if (pal.on or sys.stdout.isatty()) and not args.console and not args.json and \
            not args.daemon and not isinstance(sys.stdout, ColourOut):
        sys.stdout = ColourOut(sys.stdout, pal)
    if args.help:
        sys.stdout.write(parser.format_help())
        return 0
    if args.version:
        print('%s %s%s' % (pal.head('acme'), pal.bold(__version__), '' if HAVE_COLORAMA
                           else pal.dim('  (colorama is not installed; colour is written by '
                                        'hand)')))
        return 0
    global CONFIG_FILE
    if args.config:
        # A file that is not there was the defaults (1.0.207): a mistyped path ran
        # on SQLite and an empty local database.
        if not Path(args.config).is_file():
            raise SystemExit('acme: there is no config file %s' % args.config)
        CONFIG_FILE = Path(args.config)
    if args.debug:
        FROM_ARGV['debug'] = True
    # 0 is an answer (1.0.94): --tls-hsts 0 is "none", and 0 == False made it
    # "nothing asked" - the daemon started in the foreground from a script.
    # Anything not its default is asked (1.0.207) - --proxy-test alone is '' -,
    # and a default is not: --reboot, --db-tls-ca and --days have one, and
    # `acme` alone printed the help, not the status.
    acted = any(v != parser.get_default(k) and v != []
                for k, v in vars(args).items()
                if k not in ('no_color', 'json', 'debug', 'config', 'limit', 'hours', 'search',
                             'role', 'note', 'yes', 'replace', 'invert', 'pending', 'no_qr',
                             'suffix'))
    if args.daemon:
        return run_daemon()
    for fn in HOOKS['cli_run']:
        got = fn(args)
        if got is not None:
            return got
    if args.dump_copy:
        return cli_dump_copy()
    if args.read_copy:
        # copy_read_through in a process of its own (1.0.186); the key of the
        # secrets on stdin, never on the command line.
        key = sys.stdin.readline().strip()
        try:
            got = copy_read_through(args.read_copy, bytes.fromhex(key) if key else None,
                                    child=True)
        except (RbError, OSError, ValueError) as e:
            sys.stdout.write(json.dumps({'error': str(e)}) + '\n')
            return 1
        sys.stdout.write(json.dumps(got, default=str) + '\n')
        return 0
    if not acted and args.json:
        # --json alone (1.0.103): the state as JSON, asked by a script - never
        # the daemon in the foreground because stdin is not a terminal.
        args.status = True
        acted = True
    if not acted:
        # Nothing asked for. Under systemd (or anything else that is not a
        # person at a terminal) that is the daemon, as it always was; typed by
        # somebody, it is the question they meant - what is it doing - and
        # never a second daemon beside the one that is running.
        if os.environ.get('INVOCATION_ID') or not sys.stdin.isatty():
            return run_daemon()
        args.status = True
        acted = True
        if not args.json:
            print(pal.dim('(acme --help for everything it does; the daemon itself is '
                          'systemctl status acme)'))
    _LOG_TO_STDERR = False
    if args.rename_from_opt:
        return rename_from_opt(lambda words: print(pal.ok_line(words)))
    if args.ha_setup or args.ha_join or args.ha_bundle or args.trusted_proxy or args.ha_resync \
            or args.ha_standalone:
        return cli_ha(args, pal)
    # Read as whoever typed it, before the service's account takes over
    # (1.0.47): a certificate in root's folder is not the acme account's to read.
    args.tls_files = []
    for f in args.tls_import or []:
        try:
            args.tls_files.append(Path(f).read_bytes())
        except OSError as e:
            raise SystemExit('acme: %s' % e)
    if args.console_at_login:
        if args.console_at_login != 'status':
            print(pal.ok_line(console_at_login_set(args.console_at_login == 'on')))
        else:
            print(pal.ok_line('the console at login is %s' % ('ON' if console_at_login()
                                                                else 'off')))
        if not CONSOLE_PROFILE.exists():
            print(pal.warn_line('%s is not there - install.sh puts it in' % CONSOLE_PROFILE))
        return 0

    if args.console:
        return console_main(pal)

    cli_stage_files(args)
    store = cli_store()
    if args.ha_compare:
        return cli_ha_compare(store, pal, args.json)
    if args.web_status or args.tls_import or args.tls_preset or args.tls_dh or \
            args.tls_hsts is not None or args.vip_set or args.vip or args.vip_move or args.vip_return or \
            args.web_retry:
        try:
            return cli_web(args, pal, store)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
    if args.ha_tls or args.ha_tls_repair or args.ha_tls_off:
        if args.ha_tls_off:
            if not args.yes:
                raise SystemExit('acme: --ha-tls-off switches off what stops somebody between the '
                                 'nodes from reading and writing the rows going over: add --yes')
            got = hatls_off(store, 'command line', here=False)
            print(pal.warn_line(got['message']))
            print('the daemons of both nodes go through the steps; follow them with  acme --ha-tls')
        if args.ha_tls_repair:
            try:
                got = hatls_start(store, 'command line', here=False)
            except ValueError as e:
                raise SystemExit('acme: %s' % e)
            print(pal.ok_line(got['message']))
            print('the daemons of both nodes go through the steps; follow them with  acme --ha-tls')
        v = hatls_view(store)
        if args.json:
            print(json.dumps(v, indent=2, default=str, ensure_ascii=False))
            return 0
        print('the link between the databases: %s%s' % (v['mode'] or 'not encrypted',
                                                       ' (its own setting, ha_tls)' if v['own'] else ''))
        for n in v['nodes']:
            end = n.get('cert_end')
            print('  %-14s %-8s %s%s' % (n['name'], n.get('step') or '?',
                                        (n.get('error') or n.get('said') or '')[:160],
                                        ('  - certificate ends %s' % datetime.fromtimestamp(
                                            float(end)).strftime('%Y-%m-%d')) if end else ''))
        if v['authority_end']:
            print('  the authority ends %s' % datetime.fromtimestamp(
                v['authority_end'][0]).strftime('%Y-%m-%d'))
        return 0
    if args.change_keep or args.change_back:
        kind = args.change_keep or args.change_back
        act = 'keep' if args.change_keep else 'back'
        trials = trials_view(store)
        if kind == 'net':
            node = args.node or (next((x['node'] for x in trials if x['kind'] == 'net'), None)
                                 or node_name())
            try:
                said = net_trial_answer(store, node, act, 'command line')
            except ValueError as e:
                raise SystemExit('acme: %s' % e)
        else:
            try:
                said = fw_trial_answer(store, act, 'command line')
            except ValueError as e:
                raise SystemExit('acme: %s' % e)
        print(pal.ok_line(said))
        return 0

    if args.ha_readdress:
        if not args.ha_address and not args.ha_peer:
            v = readdress_view(store)
            print('this node (%s) is reached at  %s%s' % (node_name(), v['mine'] or '(not set: %s)'
                                                         % v['detected'],
                                                         '' if v['mine_here'] else
                                                         '  - NOT an address of this machine'))
            print('the other node is at          %s' % (v['peer'] or '?'))
            print('this machine has              %s' % (', '.join(v['addresses']) or '?'))
            print('change with  acme --ha-readdress --ha-address NEW  and/or  --ha-peer NEW')
            return 0
        try:
            # pg_hba.conf by the root helper (acme-web.path), as for the pages.
            got = ha_readdress(store, args.ha_address or '', args.ha_peer or '', by='command line')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        for x in got['done']:
            print(pal.ok_line(x))
        for x in got['left']:
            print(pal.warn_line(x))
        if not got['done'] and not got['left']:
            print(got['message'])
        # The daemon reads config.json again (SIGHUP, as systemctl reload).
        try:
            pid = int((STATE_DIR / 'acme.lock').read_text().strip() or 0)
            if pid > 1:
                os.kill(pid, signal.SIGHUP)
        except (OSError, ValueError):
            print('restart the service so that it reads config.json again:  systemctl '
                  'restart acme')
        return 0 if not got['left'] else 2
    if args.ha_renamed:
        said = node_carry(store, args.ha_renamed.strip(), node_name(), by='command line')
        try:
            NODE_NAME_FILE.write_text(node_name() + '\n')
        except OSError:
            pass
        print(pal.ok_line('%s is now %s; carried over: %s' % (
            args.ha_renamed, node_name(), ', '.join(said) or 'nothing (it had nothing of its own)')))
        return 0
    if args.ha_forget:
        if args.ha_forget == node_name():
            raise SystemExit('acme: that is this node')
        if not store.get_meta('node:' + args.ha_forget):
            raise SystemExit('acme: there is no node called %s in the list' % args.ha_forget)
        ha_forget(store, args.ha_forget)
        store.db.run('DELETE FROM meta WHERE k IN (?, ?)',
                     ('maint:' + args.ha_forget, 'upgrade:node:' + args.ha_forget))
        store.add_event('settings', '%s was taken off the list of nodes on the command line'
                        % args.ha_forget, 'warn', who='command line')
        print(pal.ok_line('%s is off the list (if it still runs, it writes itself back within '
                          'fifteen seconds)' % args.ha_forget))
        return 0
    if args.ha_pause or args.ha_resume or args.ha_stop:
        if args.ha_stop and not args.yes:
            raise SystemExit('acme: this takes replication away; the nodes then go their own '
                             'ways - again with --yes')
        act = 'stop' if args.ha_stop else ('pause' if args.ha_pause else 'resume')
        which = args.ha_pause or args.ha_resume
        if which in ('in', 'out'):
            act += '_' + which
        try:
            print(pal.ok_line(ha_control(store, act)['message']))
        except Exception as e:                          # noqa: BLE001
            raise SystemExit('acme: %s' % str(e).split('\n')[0])
        return 0
    if args.maintenance:
        name = args.node or node_name()
        if args.maintenance == 'status':
            row = maintenance_row(store, name)
            if args.json:
                print(json.dumps(dict(row, node=name), default=str))
            else:
                print(('%s: in maintenance since %s%s' % (
                    name, datetime.fromtimestamp(float(row.get('at') or 0)).strftime(
                        '%d-%m-%Y %H:%M:%S'), (' - ' + row['why']) if row.get('why') else ''))
                      if row.get('on') else '%s: in service' % name)
            return 0 if not row.get('on') else 3
        if args.maintenance == 'on' and not args.node:
            maintenance_ensure(store)
        try:
            maintenance_set(store, args.maintenance == 'on', args.why or 'on the command line',
                            'command line', name)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('%s: %s' % (name, 'in maintenance - no work of its own, and '
                                      '/healthz says 503' if args.maintenance == 'on'
                                      else 'back in service')))
        return 0
    if args.upgrade_cancel:
        try:
            upgrade_cancel(store, 'command line')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('the upgrade is stopped; the nodes not begun stay as they are'))
        return 0
    if args.upgrade_check:
        row = online_look(store, 'command line')
        if args.json:
            print(json.dumps(row, indent=2, default=str))
            return 0 if not row.get('error') else 1
        print(pal.head('looked at %s' % row.get('url')))
        if row.get('error'):
            print(pal.bad_line(row['error']))
            return 1
        for pk in row.get('packages') or []:
            mark = pal.good('newer') if _ver_tuple(pk['version']) > _ver_tuple(__version__) \
                else pal.dim('not newer')
            print('  %-24s %s  %s' % (pk['name'], mark, pal.dim(pk['url'])))
        n = row.get('newest')
        if not n:
            print(pal.warn_line('no acme package there'))
        elif row.get('newer'):
            print(pal.ok_line('acme %s is there - this server runs %s: acme --upgrade-online'
                              % (n['version'], __version__)))
        else:
            print(pal.ok_line('nothing newer than %s' % __version__))
        return 0

    if args.upgrade_online:
        plan = upgrade_plan(store)
        if plan and plan['state'] == 'running':
            raise SystemExit('acme: an upgrade is going on - acme --upgrade-follow')
        row = online_look(store, 'command line')
        if row.get('error'):
            raise SystemExit('acme: %s: %s' % (row.get('url'), row['error']))
        want = args.upgrade_online
        pk = row.get('newest') if want == 'newest' else next(
            (x for x in row.get('packages') or [] if x['version'] == want), None)
        if not pk:
            raise SystemExit('acme: %s is not at %s' % (want, row.get('url')))
        if _ver_tuple(pk['version']) <= _ver_tuple(__version__):
            print(pal.ok_line('nothing newer than %s at %s' % (__version__, row.get('url'))))
            return 0
        nodes = [n['name'] for n in ha_nodes(store)] or [node_name()]
        print(pal.head('acme %s → %s' % (__version__, pk['version'])) + pal.dim('  from %s'
                                                                            % pk['url']))
        print('  ' + ('the nodes %s, one at a time - each in maintenance while it is upgraded'
                      % ', '.join(nodes) if len(nodes) > 1 else
                      'this server - for a minute nothing is renewed or deployed'))
        if not args.yes:
            try:
                ok = input('  go on? (y/N) ').strip().lower() in ('y', 'yes', 'a', 'ano')
            except (EOFError, KeyboardInterrupt):
                ok = False
            if not ok:
                print('  nothing done')
                return 1
        print(pal.dim('  fetching it and checking its signature…'))
        try:
            meta = online_fetch(store, pk['version'], 'command line')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('acme %s fetched, signed by %s' % (meta['version'],
                                                             meta.get('signed_by'))))
        try:
            upgrade_start(store, 'command line')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        return cli_upgrade_follow(store, pal)

    if args.upgrade_follow:
        return cli_upgrade_follow(store, pal)

    if args.downgrade_check:
        try:
            got = downgrade_list(store)
        except Exception as e:                          # noqa: BLE001
            raise SystemExit('acme: %s' % e)
        if args.json:
            print(json.dumps(got, indent=2, default=str))
            return 0
        print(pal.head('going back from %s - looked at %s' % (__version__, got['url'])))
        print(pal.dim('  it may go back to %s or newer (set by acme %s; this machine allows %s)'
                      % (got['floor'], got['floor_by'], got['root_floor'] or 'nothing yet')))
        if not got['versions']:
            print(pal.ok_line('no version older than %s is there' % __version__))
        for v in got['versions']:
            if v['why']:
                print(pal.bad_line('%-10s %s' % (v['version'], '; '.join(v['why']))))
            else:
                print(pal.ok_line('%-10s may be gone back to: acme --downgrade %s'
                                  % (v['version'], v['version'])))
        return 0

    if args.downgrade:
        plan = upgrade_plan(store)
        if plan and plan['state'] == 'running':
            raise SystemExit('acme: an upgrade is going on - acme --upgrade-follow')
        want = args.downgrade
        is_file = want.endswith(('.tar.gz', '.tgz')) or os.path.sep in want
        if not is_file:
            why = downgrade_why_not(store, want)
            if why:
                raise SystemExit('acme: acme %s cannot be gone back to: %s' % (want, '; '.join(why)))
        nodes = [n['name'] for n in ha_nodes(store)] or [node_name()]
        print(pal.head('acme %s → %s (going back)' % (__version__, os.path.basename(want))))
        print('  ' + ('the nodes %s, one at a time - each in maintenance while it is done'
                      % ', '.join(nodes) if len(nodes) > 1 else
                      'this server - for a minute nothing is renewed or deployed'))
        print('  ' + pal.dim('the database stays as it is; what came in the newer versions is '
                             'gone until you upgrade again'))
        if not args.yes:
            try:
                ok = input('  go back? (y/N) ').strip().lower() in ('y', 'yes', 'a', 'ano')
            except (EOFError, KeyboardInterrupt):
                ok = False
            if not ok:
                print('  nothing done')
                return 1
        print(pal.dim('  checking it: its signature, how far back this may go, the tables…'))
        try:
            if is_file:
                if not os.path.isfile(want):
                    raise ValueError('%s is not a file' % want)
                meta = downgrade_file(store, want, 'command line')
            else:
                meta = downgrade_fetch(store, want, 'command line')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('acme %s checked (signed by %s) - the database can take it'
                          % (meta['version'], meta.get('signed_by'))))
        try:
            upgrade_start(store, 'command line')
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        return cli_upgrade_follow(store, pal)

    if args.upgrade_status:
        meta = json.loads(store.get_meta('upgrade:pkg') or 'null')
        plan = upgrade_plan(store)
        if args.json:
            print(json.dumps({'package': meta, 'plan': plan}, indent=2, default=str))
            return 0
        print('package: %s' % ('acme %s (%s bytes, signed by %s, sent by %s)' % (
            meta['version'], meta['bytes'], meta.get('signed_by'), meta.get('by'))
            if meta else 'none sent'))
        if not plan:
            print('no upgrade started on the pages')
            return 0
        print('upgrade to %s, started by %s: %s' % (plan['version'], plan.get('by'),
                                                     plan['state']))
        for st in plan['steps']:
            print('  %-20s %-11s %s' % (st['name'], st.get('state') or 'waiting',
                                        st.get('said') or ''))
        return 0
    if args.ha_status:
        rows = ha_nodes(store)
        if args.json:
            out = lambda data: print(json.dumps(data, indent=2, default=str))
            out({'node': node_name(), 'nodes': rows})
            return 0
        print(pal.head('the cluster') + pal.dim('  (this node: %s, database %s)'
                                              % (node_name(), store.db.where())))
        if not rows:
            print('  ' + pal.dim('no node has written a heartbeat yet - is the daemon running?'))
        for n in rows:
            mark = pal.ok_line if n['alive'] else pal.bad_line
            print(mark('%-16s %-15s %s  heard %s ago%s' % (
                n['name'], n.get('address') or '', n.get('version') or '?',
                human_span(n["age"]), '  (this one)' if n['me'] else '')))
        mine = [n for n in rows if n['me']]
        if mine and mine[0].get('mid') and mine[0]['mid'] != machine_id() and mine[0]['alive']:
            print(pal.bad_line('another machine (%s, %s) writes as %s too: two machines call '
                               'themselves %s - give one its own name (acme --set node_name=NAME '
                               'on it, then systemctl restart acme)' % (
                                   mine[0].get('address') or '?', mine[0].get('host') or '?',
                                   node_name(), node_name())))
        if store.db.engine != 'postgres':
            print(pal.dim('  one node: a cluster needs PostgreSQL - see acme --ha-setup'))
        rep = ha_repl_state(store)
        if rep['mode'] == 'replicated':
            print(pal.head('replication') + pal.dim('  (this node is %d of 2; the other: %s)'
                                                    % (int(rep['slot']), rep['peer'])))
            for r in rep['incoming']:
                # Errors counted so far do not make a running one bad (1.0.47):
                # every time the other node was away is one, for good.
                ok = r['enabled'] and r['running']
                line = 'in  <- %-12s %s, last heard %s%s' % (
                    rep['peer'], 'running' if r['running'] else
                    ('PAUSED' if not r['enabled'] else 'NOT RUNNING'),
                    human_span(time.time() - float(r['last_msg'])) + ' ago' if r.get('last_msg')
                    else 'never', ', %d error(s) counted so far (each time the other was away '
                    'is one)' % r['apply_errors'] if r['apply_errors'] else '')
                print((pal.ok_line if ok else pal.bad_line)(line))
            if not rep['incoming']:
                print(pal.bad_line('in  <- nothing is taken from the other node'))
            for r in rep['outgoing']:
                ok = r['active'] and r['wal_status'] != 'lost'
                print((pal.ok_line if ok else pal.bad_line)(
                    'out -> %-12s %s, %s behind, WAL %s' % (
                        rep['peer'], 'taken' if r['active'] else 'NOT TAKEN (the other is away '
                        'or paused)', bytes_words(r['behind']), r['wal_status'])))
            if not rep['outgoing']:
                print(pal.bad_line('out -> nothing is taken from this node'))
            if rep.get('lost'):
                print(pal.bad_line('the other node was away too long: rebuild it from this one '
                                   '(acme --ha-resync --yes, there)'))
        return 0
    out = lambda data: print(json.dumps(data, indent=2, default=str, ensure_ascii=False))
    who = 'command line'

    if args.status or args.check:
        d = Daemon(store, serve=False)
        s = d.status()
        try:
            import urllib.request
            req = urllib.request.Request('http://127.0.0.1:%d/api/health'
                                         % int(CONFIG.get('api_port') or 9861))
            with url_open(req, timeout=3) as r:
                alive = json.loads(r.read().decode()).get('ok')
        except Exception:
            alive = False
        s['daemon_alive'] = alive
        if args.json and args.check:
            # --check --json (1.0.103): the checks run as without --json, their
            # lines and their verdict in the JSON - and the same exit code. It
            # printed the state and said 0 whatever was wrong.
            words = [x for x in (sys.argv[1:] if argv is None else list(argv)) if x != '--json']
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(words + ['--no-color'])
            lines = [re.sub(r'\x1b\[[0-9;]*m', '', x).rstrip() for x in buf.getvalue().split('\n')
                     if x.strip()]
            out(dict(s, check={'ok': not rc, 'exit': rc or 0, 'lines': lines}))
            return rc or 0
        if args.json:
            # The same exit code as the text (1.0.207): 0 with the daemon down.
            out(s)
            return 0 if alive and not s['problems'] else 1
        print(pal.head('acme %s on %s' % (__version__, s['host'])) + '  ' +
              pal.dim('- ' + ACME_WHAT))
        print((pal.ok_line if alive else pal.bad_line)(
            'the daemon %s' % ('answers on 127.0.0.1:%s' % CONFIG.get('api_port') if alive
                               else 'is not answering - systemctl status acme')))
        print(pal.ok_line('the database: %s (%s)' % (store.db.where(), store.db.version())))
        # The cluster, in one line: the nodes heard from, the replication.
        nodes = s.get('nodes') or []
        rep_ = s.get('replication') or {}
        if CONFIG.get('ha_mode') or len(nodes) > 1:
            up = [n['name'] for n in nodes if n.get('alive')]
            down = [n['name'] for n in nodes if not n.get('alive')]
            fine = not down and (rep_.get('mode') != 'replicated' or rep_.get('healthy'))
            print((pal.ok_line if fine else pal.bad_line)('the cluster (%s): %s%s%s' % (
                CONFIG.get('ha_mode') or 'one database', ', '.join(up) or 'no node',
                ' - not heard from: %s' % ', '.join(down) if down else '',
                (', replication %s' % ('running' if rep_.get('healthy') else
                                       'NOT running%s' % (' (%s)' % rep_['trouble']
                                                          if rep_.get('trouble') else '')))
                if rep_.get('mode') == 'replicated' else '')))
        else:
            print(pal.ok_line('one server, node %s' % s.get('node')))
        m = s.get('maintenance') or {}
        if m.get('on'):
            print(pal.warn_line('this node is in maintenance%s' % (
                ' (%s)' % m['why'] if m.get('why') else '')))
        # The rest is the modules' to say (the certificates, their jobs).
        for fn in HOOKS['status']:
            try:
                for line in fn(store, pal) or []:
                    print(line)
            except Exception as e:                      # noqa: BLE001
                print(pal.bad_line('%s: %s' % (getattr(fn, '__qualname__', fn), e)))
        print('  isemon: %s' % (('sending to %s as "%s"' % (
            CONFIG.get('isemon_targets') or '(nowhere!)', str(CONFIG.get('isemon_hostname')
                                                              or short_host())))
                                if CONFIG.get('isemon') else 'not sent'))
        for p in s['problems']:
            print(pal.bad_line(p))
        for p in trial_problem_words(s.get('trials') or []):
            print(pal.warn_line(p))
        bad = 0
        if args.check:
            print(pal.head('checking every part of it'))
            def said(ok, text, hint=''):
                print((pal.ok_line if ok else pal.bad_line)(text))
                if hint and not ok:
                    print(pal.dim('    ' + hint))
                return 0 if ok else 1
            key = sealing_key_path()
            bad += said(key.is_file(), 'the key of the sealed secrets: %s' % key,
                        'without it no private key or password kept can be opened - put back '
                        'the .key beside the latest copy in %s' % BACKUP_DIR)
            copies = backups()
            try:                        # the nightly dumps as well (1.0.59)
                copies = sorted(copies + kept_dumps(CONFIG.get('db_engine') or 'sqlite'),
                                key=lambda c: -float(c.get('at') or 0))
            except Exception:                           # noqa: BLE001
                pass
            if copies:
                age = (time.time() - copies[0]['at']) / 3600.0
                bad += said(age < 26 or not CONFIG.get('backup_daily'),
                            'the latest copy of the database: %s, %.0f h ago'
                            % (copies[0]['name'], age), 'acme --backup makes one now')
            else:
                print(pal.dim('  no copy of the database yet (the first is made at %s; '
                              'acme --backup makes one now)' % CONFIG.get('backup_at')))
            ph = php_state()
            if ph.get('version'):
                bad += said(bool(ph.get('fixed')), 'PHP %s %s' % (
                    ph['version'], 'has the php2shell fix' if ph.get('fixed')
                    else 'does NOT have the php2shell fix (CVE-2026-109618/109619)'),
                    './install.sh --upgrade puts it right')
            dirs = {d['name']: d for d in store.directories(with_secret=True)}
            if not dirs:
                print(pal.dim('  no directory to check (Settings -> Active Directory)'))
            for one in dirs.values():
                c = Directory(one).check()
                for srv in c['servers']:
                    line = 'directory %s, %s: %s' % (one['name'], srv['host'], '; '.join(
                        '%s%s' % (st['what'], (' (%s)' % st['said']) if st['said'] else '')
                        for st in srv['steps']))
                    bad += said(srv['ok'], line)
            if CONFIG.get('isemon'):
                targets = syslog_targets(CONFIG.get('isemon_targets') or '')
                bad += said(bool(targets), 'isemon: %s' % (', '.join(
                    '%s:%s/%s' % t[:3] for t in targets) or 'switched on, but sent nowhere'),
                    'Settings -> isemon: where to send them')
        return 0 if alive and not s['problems'] and not bad else 1

    if args.events:
        # --hours when given (1.0.207): every event of any age was listed.
        given = any(w == '--hours' or w.startswith('--hours=')
                    for w in (sys.argv[1:] if argv is None else list(argv)))
        rows, total = store.events(args.limit, 0, args.search, extra=(
            'ts >= ?', [time.time() - float(args.hours) * 3600]) if given else None)
        if args.json:
            out({'rows': rows, 'total': total})
            return 0
        print(table([(stamp(r['ts']), r['kind'], r['who'] or '', r['words']) for r in rows],
                    ['when', 'kind', 'who', 'what'], [19, 22, 18, 90]))
        return 0

    if args.directories:
        rows = store.directories()
        if args.json:
            out(rows)
            return 0
        print(table([(d['name'], d['hosts'], '%s/%s' % (d['tls'], d['port']), d['base'],
                      d['bind_dn'], 'checked' if d['verify'] else 'NOT checked')
                     for d in rows], ['name', 'servers', 'how', 'base', 'reads as',
                                      'certificate']))
        return 0

    if args.add_directory:
        old = store.directory(args.add_directory) or {}
        ca = None
        if args.ca:
            ca = Path(args.ca).read_text()
        not_on_command_line('the password of the directory', args.bind_pw,
                            '--bind-pw - asks for it (or ACME_BIND_PW)')
        pw = args.bind_pw if args.bind_pw is not None else os.environ.get('ACME_BIND_PW')
        if pw == '-':
            pw = ask_password('the password of %s' % (args.bind_dn or 'the binding account'),
                              twice=False, env='ACME_BIND_PW')
        data = {'id': old.get('id'), 'name': args.add_directory,
                'hosts': args.hosts or old.get('hosts'), 'base': args.base or old.get('base'),
                'bind_dn': args.bind_dn if args.bind_dn is not None else old.get('bind_dn', ''),
                'bind_pw': pw if pw is not None else (None if old else ''),
                'tls': args.tls or old.get('tls') or 'ldaps',
                'port': args.port or (old.get('port') if not args.tls else None),
                'verify': 0 if args.no_verify else old.get('verify', 1),
                'weak': (args.weak_certs == 'on') if args.weak_certs else old.get('weak', 0),
                'nested': old.get('nested', 1), 'enabled': old.get('enabled', 1),
                'timeout_s': old.get('timeout_s') or 10,
                'user_attr': old.get('user_attr') or 'sAMAccountName',
                'note': args.note or old.get('note', '')}
        if ca is not None:
            data['ca'] = ca
        store.directory_save(data, who)
        store.add_event('directories', 'command line saved the directory %s'
                        % args.add_directory, who='command line')
        bump(store)
        print(pal.ok_line('the directory %s is saved' % args.add_directory))
        return 0

    if args.del_directory:
        one = store.directory(args.del_directory)
        if not one:
            raise SystemExit('there is no directory called %s' % args.del_directory)
        cli_sure(args, 'the directory %s is taken away' % one['name'])
        try:
            store.directory_drop(one['id'])
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        store.add_event('directories', 'command line took away the directory %s' % one['name'],
                        who='command line')
        bump(store)
        print(pal.ok_line('gone'))
        return 0

    if args.directory_test or args.directory_user:
        name = args.directory_test or args.directory_user[0]
        one = store.directory(name, with_secret=True)
        if not one:
            raise SystemExit('there is no directory called %s' % name)
        ad = Directory(one)
        if args.directory_test:
            c = ad.check()
            if args.json:
                out(c)
                return 0 if c.get('ok') else 1          # as without --json (1.0.205)
            for srv in c['servers']:
                print(pal.bold('  %s:%d' % (srv['host'], srv['port'])))
                for st in srv['steps']:
                    print('    ' + (pal.ok_line if st['ok'] else pal.bad_line)(
                        st['what'] + ((' - ' + st['said']) if st['said'] else '')))
            return 0 if c['ok'] else 1
        user = args.directory_user[1]
        entry = ad.find_user(user, 'upn' if '@' in user else 'sam')
        if not entry:
            print(pal.bad_line('the directory has nobody called %s' % user))
            return 1
        groups = ad.groups_of(entry, True)
        if args.json:
            out({'entry': entry, 'groups': groups})
            return 0
        for k in ('dn', 'upn', 'sam', 'display', 'mail', 'disabled', 'expires'):
            print('  %-10s %s' % (k, entry.get(k)))
        print('  groups:   %s' % ', '.join(sorted(cn for _, cn in groups)))
        return 0

    if args.settings:
        d = Daemon(store, serve=False)
        rows = d.settings_state(True)
        if args.search:
            # --search, as it says it does everywhere (1.0.187): it was every setting.
            q = args.search.lower()
            rows = [r for r in rows if q in ' '.join(str(r.get(k) or '') for k in
                                                     ('key', 'name', 'short', 'says')).lower()]
        if args.json:
            out(rows)
            return 0
        for s in rows:
            print('  %-28s %-34s %s' % (s['key'], json.dumps(s['value'], ensure_ascii=False)[:34],
                                       pal.dim(s['source_says'])))
        return 0

    if args.export_config:
        conf = config_export(store, bool(args.with_secrets))
        made_phrase = ''
        if args.with_secrets:
            # Locked as the pages lock it (1.0.207): with the secrets it was plain JSON
            # here - every password, the TLS keys.
            if getattr(args, 'passphrase_file', None):
                phrase = Path(args.passphrase_file).read_text().strip()
            else:
                phrase = os.environ.get('ACME_PASSPHRASE') or ''
            if not phrase:
                phrase = made_phrase = ha_passphrase()
            if len(phrase) < 10:
                raise SystemExit('acme: a passphrase of 10 characters at least locks the secrets')
            text = json.dumps(bundle_lock({'config': conf}, phrase, kind=CONFIG_BUNDLE_KIND),
                              indent=1, ensure_ascii=False, default=str)
        else:
            text = json.dumps({'config': conf}, indent=1, ensure_ascii=False, default=str)
        if args.export_config == '-':
            print(text)
        else:
            fd = getattr(args, 'export_fd', None)
            if fd is None:
                fd = os.open(args.export_config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                             0o600 if args.with_secrets else 0o640)
            # The mode of a file there already too (1.0.94): O_CREAT's mode is
            # only a new file's, and secrets went into a 0644 one.
            os.fchmod(fd, 0o600 if args.with_secrets else 0o640)
            with os.fdopen(fd, 'w') as f:
                f.write(text + '\n')
            print(pal.ok_line('%s: the configuration%s' % (
                args.export_config, ', with its secrets, locked with the passphrase'
                if args.with_secrets else ' (without the secrets)')))
        if made_phrase:
            # Said once, where the file is not (stdout may be the file itself).
            sys.stderr.write('the passphrase, written down now - it is not kept anywhere: %s\n'
                             % made_phrase)
        if args.with_secrets:
            store.add_event('settings', 'the configuration was exported with the secrets in it, '
                            'locked, on the command line', 'warn', who=who)
        return 0

    if args.import_config:
        try:
            raw = json.loads(Path(args.import_config).read_text())
        except (OSError, ValueError) as e:
            raise SystemExit('acme: %s' % e)
        if isinstance(raw, dict) and raw.get('kind') == CONFIG_BUNDLE_KIND:
            # Exported from the pages with the secrets: locked (1.0.136).
            try:
                if args.passphrase_file:
                    phrase = Path(args.passphrase_file).read_text().strip()
                else:
                    phrase = os.environ.get('ACME_PASSPHRASE') or getpass.getpass(
                        'the passphrase it was exported with: ')
                raw = bundle_open(raw, phrase, kinds=(CONFIG_BUNDLE_KIND,))
            except (OSError, ValueError) as e:
                raise SystemExit('acme: %s' % e)
        conf = raw.get('config', raw) if isinstance(raw, dict) else raw
        if not args.yes:
            raise SystemExit('this puts the configuration of %s in here, over what is set up; '
                             'again with --yes' % args.import_config)
        d = Daemon(store, serve=False)
        try:
            said = config_import(store, d, conf, who, replace=bool(args.replace))
        except ApiError as e:
            raise SystemExit('acme: %s' % e)
        except (ValueError, BadSetting) as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('imported: %s' % ', '.join('%s %d' % kv for kv in sorted(said.items()))))
        return 0

    if args.set:
        d = Daemon(store, serve=False)
        want = {}
        for one in args.set:
            if '=' not in one:
                raise SystemExit('--set takes KEY=VALUE')
            k, v = one.split('=', 1)
            if v == '@env':
                # A secret not on the command line (1.0.136): from
                # ACME_VALUE_<KEY>, as the console passes it.
                if ('ACME_VALUE_' + k.strip().upper()) not in os.environ:
                    raise SystemExit('acme: %s=@env, and ACME_VALUE_%s is not set - nothing saved'
                                     % (k.strip(), k.strip().upper()))
                v = os.environ['ACME_VALUE_' + k.strip().upper()]
            elif v == '-' and k.strip() in SECRET_KEYS:
                v = ask_secret_value(k.strip())
            elif k.strip() in SECRET_KEYS:
                not_on_command_line(k.strip(), v, '--set %s=- asks for it (or reads one line of stdin, '
                                    'or ACME_VALUE_%s)' % (k.strip(), k.strip().upper()))
            want[k.strip()] = v
        # As the pages refuse them (1.0.136): the cluster has its own steps,
        # and a database named here opens empty at the next restart.
        def differs(k):
            return str(want[k]) != str(CONFIG.get(k) if CONFIG.get(k) is not None else '')
        ha = [k for k in want if k in ('ha_mode', 'ha_slot', 'ha_peer', 'ha_peer_port',
                                       'ha_address', 'ha_tls', 'ha_tls_ca') and differs(k)]
        if ha:
            raise SystemExit('acme: the cluster is changed with acme --ha-setup / --ha-join / '
                             '--ha-standalone (or on Settings - High availability); %s not saved'
                             % ', '.join(ha))
        moved = [k for k in want if k in ('db_engine', 'db_host', 'db_port', 'db_name',
                                          'db_user', 'db_password') and differs(k)]
        if moved and not args.yes:
            raise SystemExit('acme: %s names another database: at the next restart acme opens '
                             'it as it is - nothing is carried into it (Settings - The database '
                             'does that). Only to point at the same data somewhere new (a moved '
                             'server, a new password): again with --yes' % ', '.join(moved))
        try:
            # A node's own setting for another node, or the cluster's own value
            # with --node '*' (1.0.187), as the pages can: it was this node's only.
            said = d.save_settings(want, by=who, node=args.node or None)
        except (BadSetting, OSError) as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line(said['message']))
        return 0

    if args.admin_2fa:
        if args.admin_2fa != 'status':
            d = Daemon(store, serve=False)
            try:
                d.save_settings({'admin_2fa': '1' if args.admin_2fa == 'on' else '0'}, by=who)
            except (BadSetting, OSError) as e:
                raise SystemExit('acme: %s' % e)
            CONFIG['admin_2fa'] = 1 if args.admin_2fa == 'on' else 0
        on = bool(CONFIG.get('admin_2fa'))
        mfa = mfa_all(store)
        rows = store.accounts()
        have = [a['name'] for a in rows if str(a['name']).lower() in mfa]
        if args.json:
            out({'admin_2fa': on, 'ways': mfa_methods(), 'set_up': have,
                 'not_yet': [a['name'] for a in rows if a['name'] not in have]})
            return 0
        print(pal.ok_line('the second step of signing in to these pages is %s%s' % (
            'ON' if on else 'off', (' - offered: %s' % ', '.join(mfa_methods())) if on else '')))
        print('set up: %s' % (', '.join('%s (%s)' % (n, mfa[n.lower()]['kind']) for n in have)
                              or 'nobody'))
        left = [a['name'] for a in rows if a['name'] not in have and not a['disabled']]
        if on and left:
            print('set up at their next sign-in: %s' % ', '.join(left))
        if args.admin_2fa != 'status':
            print('the running service takes it within seconds; sign-ins already open stay open')
        return 0

    if args.users:
        rows = store.accounts()
        mfa = mfa_all(store)
        for a in rows:
            a['mfa'] = mfa.get(str(a['name']).lower())
        if args.json:
            out({'users': rows, 'mfa_on': bool(CONFIG.get('admin_2fa'))})
            return 0
        print(table([(a['name'], ROLE_WORDS.get(a['role'], a['role']), a['source'] or 'local',
                      'off' if a['disabled'] else 'on',
                      ('%s %s' % (a['mfa']['kind'], a['mfa'].get('dest') or '')).strip()
                      if a['mfa'] else '-', stamp(a['last_in']) if a['last_in']
                      else 'never', a['note'] or '') for a in rows],
                    ['name', 'role', 'from', 'state', 'second step', 'last signed in', 'note']))
        if CONFIG.get('admin_2fa'):
            print('the second step is asked for (admin_2fa); acme --reset-2fa NAME takes one away')
        return 0

    if args.add_user:
        pw = ask_password('a password for %s' % args.add_user)
        try:
            store.add_account(args.add_user, args.role or 'readonly', pw, note=args.note)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        store.add_event('accounts', 'the account %s was made on the command line, as %s'
                        % (args.add_user, args.role or 'readonly'), who=who)
        print(pal.ok_line('%s may now sign in, as %s' % (args.add_user, args.role or 'readonly')))
        return 0

    if args.passwd:
        pw = ask_password('a new password for %s' % args.passwd)
        try:
            store.set_account(args.passwd, password=pw, must_change=0)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        # As the pages do (1.0.44): a new password ends the old sign-ins.
        store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                     ('admin', args.passwd.lower()))
        store.add_event('accounts', 'the password of %s was set on the command line'
                        % args.passwd, who=who)
        print(pal.ok_line('the password of %s is set' % args.passwd))
        return 0

    if args.reset_2fa:
        acc = store.account(args.reset_2fa)
        if not acc:
            raise SystemExit('acme: there is no account called %s' % args.reset_2fa)
        had = mfa_reset(store, acc['name'], who)
        store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                     ('admin', acc['name'].lower()))
        print(pal.ok_line('the second step of %s is reset - set up again at the next sign-in'
                          % acc['name']) if had else
              pal.ok_line('%s had no second step set up' % acc['name']))
        return 0

    for flag in ('set_role', 'del_user', 'disable_user', 'enable_user'):
        name = getattr(args, flag)
        if not name:
            continue
        try:
            acc = store.account(name)
            if not acc:
                raise ValueError('there is no account called %s' % name)
            if flag == 'set_role' and not args.role:
                raise ValueError('which role? --set-role %s --role %s' % (name, '|'.join(ROLES_ALL)))
            if (flag in ('del_user', 'disable_user') or (flag == 'set_role' and args.role != 'fulladmin')) \
                    and acc.get('role') == 'fulladmin' and not store.fulladmins_left(but=name):
                raise ValueError('that is the last full administrator who can sign in')
            if flag == 'set_role':
                store.set_account(name, role=args.role)
            elif flag == 'del_user':
                cli_sure(args, 'the account %s is removed' % acc['name'])
                store.drop_account(name)
            else:
                store.set_account(name, disabled=1 if flag == 'disable_user' else 0)
            if flag in ('set_role', 'disable_user'):
                # Signed out, as on the pages (1.0.187): its role decided again
                # at its next sign-in; one switched off not left signed in.
                store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                             ('admin', name.lower()))
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        store.add_event('accounts', '%s: %s on the command line' % (name, flag.replace('_', ' ')),
                        who=who)
        print(pal.ok_line('done'))
        return 0

    if args.backup:
        got = make_backup(store, 'on the command line')
        if args.json:                   # --json kept (1.0.207)
            out({'file': str(got)})
            return 0
        print(pal.ok_line('%s, and the key beside it' % got))
        return 0

    if args.backup_info or (args.restore and not args.yes):
        # What a copy holds and where it was made (1.0.63), before anything
        # is put back.
        f = args.backup_info or args.restore
        if not Path(f).is_file():
            raise SystemExit('acme: there is no file %s' % f)
        said, why = db_file_peek(f, store.db.engine, need_admin=False)
        if said is None:
            raise SystemExit('acme: %s' % why)
        if args.json:
            out(said)
        else:
            m = said.get('machine') or {}
            use = m.get('in_use') or {}
            print(pal.head('%s - %s' % (f, DUMP_WORDS.get(said['kind'], said['kind']))))
            if said.get('version'):
                print('  made by acme %s%s' % (said['version'], ', ' + stamp(said['made'])
                                              if said.get('made') else ''))
            for k, v in sorted((said.get('counts') or {}).items()):
                print('  %-12s %s' % (k, v))
            if m:
                print('  made on      %s (%s)' % (m.get('node') or '?', m.get('host') or '?'))
                print('  database     %s %s' % (use.get('db_engine') or '?', '' if use.get(
                    'db_engine') == 'sqlite' else '%s:%s/%s' % (use.get('db_host'), use.get(
                        'db_port'), use.get('db_name'))))
                if use.get('ha_mode'):
                    print('  cluster      %s, slot %s, the other node %s' % (
                        use['ha_mode'], use.get('ha_slot'), use.get('ha_peer')))
                print('  its %s (only to read - it is never put back):' % m.get('config_file'))
                for line in json.dumps(m.get('config') or {}, indent=1).split('\n'):
                    print('    ' + line)
            elif said['kind'] == 'copy':
                print(pal.dim('  (made before 1.0.63: where it was made is not in it)'))
        if args.restore:
            raise SystemExit('this replaces everything in %s with the copy; again with --yes'
                             % store.db.where())
        return 0

    if args.rbackup_status:
        v = rb_page(store)
        if args.json:
            out(v)
            return 0
        print('backups to the destinations: %s%s; %s' % (
            'on a schedule, next %s' % v['next'] if CONFIG.get('rbackup') else 'by hand only',
            '', 'locked with the password' if v['locked'] else 'NOT LOCKED (no password set)'))
        for t in v['targets']:
            last = t.get('last') or {}
            print('  %-24s %-6s %-3s %s' % (t['name'][:24], t['kind'], 'on' if t.get('enabled')
                                             else 'off', ('last %s: %s' % (
                datetime.fromtimestamp(last['at']).strftime('%Y-%m-%d %H:%M'),
                'sent' if last.get('ok') else last.get('error'))) if last else 'never sent'))
        for r in v['runs'][:10]:
            print('  %s  %-10s %-9s %s' % (datetime.fromtimestamp(r['at']).strftime(
                '%Y-%m-%d %H:%M'), r.get('node'), human_bytes(r.get('bytes') or 0),
                '; '.join('%s %s' % (x['name'], 'ok' if x['ok'] else 'FAILED: %s' % x.get('error'))
                          for x in r.get('targets') or []) or r.get('error') or ''))
        return 0

    if args.rbackup_now:
        try:
            run = rb_run(store, 'command line')
        except (RbError, ValueError) as e:
            raise SystemExit('acme: %s' % e)
        if run.get('error'):
            raise SystemExit('acme: %s' % run['error'])
        print(pal.ok_line('%s (%s, %s)' % (run.get('file'), human_bytes(run.get('bytes') or 0),
                                           'locked' if run.get('encrypted') else 'NOT locked')))
        for x in run['targets']:
            print((pal.ok_line if x['ok'] else pal.bad_line)('%s: %s' % (
                x['name'], 'sent' + (' - taken away: %s' % ', '.join(x['taken_away'])
                                     if x.get('taken_away') else '') if x['ok'] else x.get('error'))))
        return 0 if run['ok'] else 2

    if args.restore_bundle:
        path = args.restore_bundle
        if not Path(path).is_file():
            raise SystemExit('acme: there is no file %s' % path)
        password = os.environ.get('ACME_BACKUP_PASSWORD', '')
        if args.passphrase_file:
            try:
                password = Path(args.passphrase_file).read_text().split('\n')[0]
            except OSError as e:
                raise SystemExit('acme: %s' % e)
        with open(path, 'rb') as f:
            locked = f.read(8).startswith(b'Salted__')
        if locked and not password:
            password = rb_password()
            if not password:
                if not sys.stdin.isatty():
                    raise SystemExit('acme: the backup is locked: --passphrase-file FILE, or '
                                     'ACME_BACKUP_PASSWORD')
                password = getpass.getpass('the password of the backups: ')
        if not args.yes:
            work = tempfile.mkdtemp(prefix='acme-peek-', dir=str(STATE_DIR))
            try:
                _top, m = rb_open(path, password, work)
            except RbError as e:
                raise SystemExit('acme: %s' % e)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            print('%s - every file checked against its checksum' % os.path.basename(path))
            for k, words in (('made_words', 'made'), ('site', 'installation'), ('node', 'node'),
                             ('host', 'machine'), ('acme', 'acme'), ('engine_words', 'database'),
                             ('ha_mode', 'cluster')):
                print('  %-13s %s' % (words, m.get(k) if m.get(k) not in (None, '') else '-'))
            if m.get('counts'):
                print('  %-13s %s' % ('rows', ', '.join('%s %s' % (t, n) for t, n in
                                                       sorted(m['counts'].items()) if n)))
            print('it would replace everything in %s, put its key of the secrets in place%s; '
                  'again with --yes' % (store.db.where(), '' if args.keep_node_name else
                                        ' and make this machine node %s' % m.get('node')))
            return 0
        try:
            got = rb_restore(store, path, password, 'command line',
                             keep_node_name=args.keep_node_name, need_admin=False)
        except (RbError, ValueError, OSError) as e:
            raise SystemExit('acme: %s' % e)
        m = got['manifest']
        print(pal.ok_line('put back: %s, made %s on %s (acme %s); what this machine had is kept '
                          'as %s' % (os.path.basename(path), m.get('made_words'), m.get('node'),
                                     m.get('acme'), got.get('safety'))))
        for x in got['said']:
            print(pal.ok_line(x))
        print('now:  systemctl restart acme')
        if m.get('ha_mode') == 'replicated':
            print('it came from a cluster: this machine is one server now - make it two again '
                  'with  acme --ha-setup  (RESTORE.md, section 4)')
        return 0

    if args.restore:
        # The same restore as the pages (1.0.44): every kind of copy, a copy
        # of what is replaced made first, the key beside it or in it.
        if not Path(args.restore).is_file():
            raise SystemExit('acme: there is no file %s' % args.restore)
        try:
            got = db_file_restore(store, args.restore, 'command line',
                                  key_file=_key_beside(args.restore), need_admin=False)
        except (ValueError, OSError) as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('put back (%s); what it replaced is kept as %s; %s'
                          % (DUMP_WORDS.get(got['kind'], got['kind']), got['safety'], got['key'])))
        if not store.db.value("SELECT COUNT(*) FROM accounts WHERE role = 'fulladmin' AND "
                              "COALESCE(disabled, 0) = 0"):
            print(pal.bad_line('nobody can sign in to the pages as a full administrator now: '
                               'acme --add-user NAME --role fulladmin'))
        return 0

    if args.tidy:
        print(pal.ok_line('tidied: %s' % store.tidy()))
        return 0

    # ---- what the pages do, here too (1.0.187) -------------------------------------------
    if args.acme:
        v = acme_view(store)
        if args.json:
            out(v)
            return 0
        print(pal.head('certificates by ACME: %s - %s, %s' % (
            'on' if v['on'] else 'off (acme --set acme=1)', v['directory'] or '-', v['challenge'])))
        rows = []
        for t in v['targets']:
            st_ = t.get('state') or {}
            left = (float(t['not_after']) - time.time()) / 86400 if t.get('not_after') else None
            rows.append((t['target'], t.get('name') or '(no name)', '%.0f days' % left if left is not None
                         else '-', 'ACME' if t.get('care') else 'by hand', (
                             ('ok ' if st_.get('ok') else 'failed ') + stamp(st_.get('at')) +
                             ('' if st_.get('ok') else ': %s' % (st_.get('said') or st_.get('error') or '')))
                         if st_.get('at') else 'never ordered'))
        print(table(rows, ['for', 'name', 'left', 'looked after', 'last order'], [10, 30, 9, 12, 60]))
        if v.get('account', {}).get('kid'):
            print('  account: %s, made %s' % (v['account'].get('email') or '(no mail)', stamp(v['account'].get('at'))))
        return 0

    if args.acme_order:
        if not CONFIG.get('acme'):
            raise SystemExit('acme: certificates by ACME are off - acme --set acme=1 (and acme_* ) first')
        if args.acme_order == 'all':
            which = acme_targets(store)
            if not which:
                raise SystemExit('acme: this node looks after no certificate by ACME (acme --acme)')
        else:
            t = args.acme_order
            if t not in tls_targets(store) or (t == 'vip' and not vip_conf(store).get('address')):
                raise SystemExit('acme: there is no such certificate: %s' % ', '.join(tls_targets(store)))
            name = acme_name_of(store, t)
            if not name:
                raise SystemExit('acme: the name of this certificate is not known - give it on the pages '
                                 '(Its name...) or acme --set acme_node_name=NAME --node %s' % t)
            # Ordered by hand, ACME looks after it from now on - as on the pages.
            acme_care_set(store, t, True, who, 'ordered by hand')
            which = [(t, name)]
        bad = 0
        for t, name in which:
            print(pal.head('%s: %s' % (t, name)))
            try:
                acme_order(store, t, name, who, lambda w: print('  ' + str(w)))
                print(pal.ok_line('the certificate of %s is made; the nodes put it in within a few '
                                  'seconds' % name))
            except (AcmeError, ValueError, OSError) as e:
                bad += 1
                print(pal.bad_line(str(e)))
        return 1 if bad else 0

    if args.updates:
        if args.updates == 'status':
            v = osup_view(store)
            if args.json:
                out(v)
                return 0
            plan = v.get('plan') or {}
            print(pal.head('updates of the operating system: %s' % (
                '%s, %s, by %s, %s' % (plan.get('state'), ', '.join(plan.get('order') or []),
                                        plan.get('by') or '-', stamp(plan.get('at')))
                if plan else 'none going on')))
            rows = []
            for n in v['nodes']:
                chk, row = n.get('check') or {}, n.get('row') or {}
                rows.append((n['name'] + (' (this)' if n['me'] else ''), 'up' if n['alive'] else 'not heard',
                             '%s, %s' % (chk.get('state') or '-', ('%s waiting' % chk['count']) if
                                         chk.get('count') is not None else '') if chk else 'not looked',
                             row.get('state') or '-', 'needed' if n.get('reboot') else '-'))
            print(table(rows, ['node', 'state', 'last look', 'this update', 'restart'], [22, 10, 26, 14, 8]))
            return 0
        nodes = [x.strip() for x in (args.node or '').split(',') if x.strip()] or None
        try:
            if args.updates == 'check':
                got = osup_check_ask(store, nodes or host_nodes(store), who)
                print(pal.ok_line('looking for updates on %s - acme --updates status in a minute'
                                  % ', '.join(got)))
            elif args.updates == 'start':
                cli_sure(args, 'the updates are put in on %s, one node at a time%s' % (
                    ', '.join(nodes or host_nodes(store)), {'auto': ', each restarted by itself '
                                                            'where an update needs it',
                                                            'never': ', none restarted'}.get(args.reboot, '')))
                plan = osup_start(store, nodes, args.reboot, who)
                print(pal.ok_line('the update starts: %s, one at a time - acme --updates status'
                                  % ', '.join(plan['order'])))
            else:
                osup_cancel(store, who)
                print(pal.ok_line('stopped - a node being updated finishes'))
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        return 0

    if args.restart_nodes:
        alln = host_nodes(store)
        nodes = alln if args.restart_nodes == 'all' else \
            [x.strip() for x in args.restart_nodes.split(',') if x.strip()]
        wrong = [n for n in nodes if n not in alln]
        if wrong:
            raise SystemExit('acme: there is no node %s (%s)' % (', '.join(wrong), ', '.join(alln)))
        cli_sure(args, 'the machines %s are restarted now, one at a time' % ', '.join(nodes))
        try:
            plan = power_ask(store, 'reboot', nodes, 'rolling' if len(nodes) > 1 else 'one', who)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        print(pal.ok_line('asked (%s) - acme --restarts says how it goes' % plan.get('id')))
        return 0

    if args.restarts:
        v = power_view(store)
        if args.json:
            out(v)
            return 0
        plan = v.get('plan') or {}
        print(pal.head('restarts: %s' % ('%s %s, %s, by %s, %s' % (
            plan.get('how'), ', '.join(plan.get('targets') or []), plan.get('order'),
            plan.get('by') or '-', stamp(plan.get('at'))) if plan else 'none of late')))
        print(table([(n['name'] + (' (this)' if n['me'] else ''), 'up' if n['alive'] else 'not heard',
                      stamp(n.get('started')) if n.get('started') else '-', (n.get('row') or {}).get('state') or '-',
                      (n.get('row') or {}).get('said') or '') for n in v['nodes']],
                    ['node', 'state', 'started', 'restart', 'said'], [22, 10, 20, 12, 60]))
        return 0

    if args.mail_test:
        to = args.mail_test.strip()
        if not re.match(r'^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+\Z', to):
            raise SystemExit('acme: a mail address to send it to')
        try:
            steps = mail_send(store, test_mail(to, code_lang()), [to])
        except MailError as e:
            store.add_event('mail', 'a test mail to %s failed: %s' % (to, e), 'warn', who=who)
            for st_ in getattr(e, 'steps', None) or []:
                print('  ' + (st_ if isinstance(st_, str) else json.dumps(st_, ensure_ascii=False)))
            print(pal.bad_line('not sent: %s' % e))
            return 1
        for st_ in steps or []:
            print('  ' + (st_ if isinstance(st_, str) else json.dumps(st_, ensure_ascii=False)))
        store.add_event('mail', '%s sent a test mail to %s' % (who, to), who=who)
        print(pal.ok_line('sent to %s' % to))
        return 0

    if args.sms_test:
        try:
            to = phone_checked(args.sms_test)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        try:
            said = sms_send(to, code_message('sms', to, code_new(), 'verify'))
        except SmsError as e:
            store.add_event('settings', 'a test SMS to %s failed: %s' % (to, e), 'warn', who=who)
            print(pal.bad_line('not sent: %s' % e))
            return 1
        store.add_event('settings', '%s sent a test SMS to %s' % (who, to), who=who)
        print(pal.ok_line('sent to %s%s' % (to, (': %s' % said) if said else '')))
        return 0

    if args.lockouts or args.lockouts_clear:
        now = time.time()
        per = []
        for n in [node_name()] + [x['name'] for x in ha_nodes(store) if x['name'] != node_name()]:
            try:
                got = json.loads(store.get_meta('lockouts:' + n) or '{}')
            except ValueError:
                got = {}
            rows = [dict(r, node=n) for r in (got.get('rows') or []) if float(r.get('forgets') or 0) > now]
            for r in rows:
                if r.get('locked') and float(r.get('until') or 0) <= now:
                    r['locked'] = False
            per.append((n, got.get('at'), rows))
        shared = [dict(r, node='*') for r in lockouts_shared(store)]
        if args.lockouts_clear:
            asked = args.lockouts_clear
            if asked != 'all' and ':' not in asked:
                raise SystemExit('acme: --lockouts-clear all, or KIND:WHO as acme --lockouts shows them')
            kind, _, whom = asked.partition(':')
            n_done = 0
            for r in shared:
                if asked == 'all' or (r['kind'] == kind and r['who'].lower() == whom.lower()):
                    n_done += lockouts_shared_clear(store, r['kind'], r['who'], who) or 0
            # Each daemon clears its own within a few seconds (as the other node's pages ask).
            ask = {'all': 1, 'by': who} if asked == 'all' else {'key': [kind, whom], 'by': who}
            told = []
            for n, _at, rows in per:
                # As the shared ones, whatever the case (1.0.205); the node told
                # the name as it counts it.
                hit = [r for r in rows if r['kind'] == kind and r['who'].lower() == whom.lower()]
                if asked != 'all' and hit:
                    ask = {'key': [kind, hit[0]['who']], 'by': who}
                if asked == 'all' or hit:
                    try:
                        pending = json.loads(store.get_meta('lockouts:ask:' + n) or '[]')
                    except ValueError:
                        pending = []
                    store.set_meta('lockouts:ask:' + n, json.dumps(
                        (pending if isinstance(pending, list) else [])[-50:] + [ask]))
                    told.append(n)
            if not n_done and not told:
                raise SystemExit('acme: that is not counted any more')
            print(pal.ok_line('cleared%s' % ((' - %s within a few seconds' % ', '.join(told)) if told else '')))
            return 0
        allrows = shared + [r for _n, _a, rows in per for r in rows]
        if args.json:
            out(allrows)
            return 0
        print(table([(r['node'], '%s:%s' % (r['kind'], r['who']), r.get('what') or '',
                      '%d of %d' % (r.get('fails') or 0, r.get('limit') or 0),
                      ('locked until %s' % stamp(r['until'])) if r.get('locked') and r.get('until') else
                      ('locked' if r.get('locked') else 'counting')) for r in allrows],
                    ['node', 'kind:who', 'what', 'counted', 'state'], [10, 40, 30, 9, 30]))
        stale = [n for n, at, _r in per if not at or now - float(at) > 120]
        if stale:
            print(pal.dim('  not heard from of late: %s (its list may be old)' % ', '.join(stale)))
        return 0

    # ---- 1.0.188: the rest of what the pages do ----------------------------------------
    def api(method, path, body=None, qs=None):
        return cli_api(Daemon(store, serve=False), who, method, path, body, qs)

    def asked(kind, got, secs=90):
        if args.json:
            out(cli_ask_wait(store, kind, got, secs))
            return 0
        print(pal.dim('  asked of %s - each answers within seconds' % ', '.join(got['nodes'])))
        return cli_ask_said(pal, cli_ask_wait(store, kind, got, secs))

    def shown(got):
        if args.json:
            out(got)
        else:
            if isinstance(got, dict) and got.get('message'):
                print(pal.ok_line(got['message']))
                got = {k: v for k, v in got.items() if k != 'message'}
            cli_show(got, pal)
        return 0

    only = args.node or ''
    if args.siem_test:
        return asked('siem', api('POST', '/api/siem', {'action': 'test', 'node': only}))
    if args.proxy_test is not None:
        return asked('proxy', api('POST', '/api/proxy', {'action': 'try', 'url': args.proxy_test}), 60)
    if args.snmp_test or args.snmp_trap:
        return asked('snmp', api('POST', '/api/snmp', {'action': 'trap' if args.snmp_trap else 'test',
                                                      'node': only}))
    ca_pem = Path(args.ca).read_text() if args.ca else ''
    if args.db_tls:
        return shown(api('GET', '/api/dbtls'))
    if args.db_tls_probe:
        return asked('dbtls_probe', api('POST', '/api/dbtls', {
            'action': 'probe', 'mode': args.db_tls_probe, 'ca_source': args.db_tls_ca,
            'ca_pem': ca_pem, 'node': only}), 120)
    if args.db_tls_apply:
        mode = args.db_tls_mode if args.db_tls_mode is not None else 'verify-full'
        cli_sure(args, 'encryption to the database server, on %s: %s' % (only or 'every node', {
            'server': 'acme\'s certificates put into the PostgreSQLs (each reloaded)',
            'connect': 'each node\'s connection to its database made again with %s' % (mode or 'no TLS'),
            'server_off': 'acme\'s certificates taken out of the PostgreSQLs'}[args.db_tls_apply]))
        return asked('dbtls_apply', api('POST', '/api/dbtls', {
            'action': 'apply', 'phase': args.db_tls_apply, 'mode': mode, 'ca_source': args.db_tls_ca,
            'ca_pem': ca_pem, 'node': only}), 300)

    def host_port(v):
        host, _, port = str(v).rpartition(':') if re.match(r'^[^:]+:\d+$', str(v)) else (v, '', '')
        return {'host': host, 'port': int(port) if port else 6514}

    isemon_src = args.db_tls_ca if args.db_tls_ca in ('acme', 'system', 'given') else 'acme'
    if args.isemon_tls:
        got = api('GET', '/api/isemon')
        return shown(got.get('tls') or {})
    if args.isemon_tls_probe:
        return asked('isemon_tls', api('POST', '/api/isemon', dict(
            host_port(args.isemon_tls_probe), action='tls_probe', ca_source=isemon_src,
            ca_pem=ca_pem, verify=not args.no_verify, mtls=args.mtls)), 60)
    if args.isemon_tls_apply:
        cli_sure(args, 'every node sends to isemon at %s over TLS from now on' % args.isemon_tls_apply)
        return shown(api('POST', '/api/isemon', dict(
            host_port(args.isemon_tls_apply), action='tls_apply', ca_source=isemon_src,
            ca_pem=ca_pem, verify=not args.no_verify, mtls=args.mtls)))
    if args.isemon_tls_off is not None:
        cli_sure(args, 'isemon is sent to over plain TCP (514) again - not encrypted')
        return shown(api('POST', '/api/isemon', {'action': 'tls_off', 'host': args.isemon_tls_off}))
    if args.isemon_tls_bundle:
        phrase = os.environ.get('ACME_PASSPHRASE') or ask_password(
            'a passphrase to lock the zip with (12 characters or more)', twice=True, env=None)
        got = api('POST', '/api/isemon', {'action': 'tls_bundle', 'port': 6514, 'mtls': args.mtls,
                                          'names': args.names or '', 'passphrase': phrase})
        fd = os.open(args.isemon_tls_bundle, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(base64.b64decode(got['file']))
        print(pal.ok_line('%s: isemon\'s certificate and key, locked with the passphrase given'
                          % args.isemon_tls_bundle))
        return 0
    target = args.tls_for or node_name()
    if args.tls_csr:
        got = api('POST', '/api/web', {'action': 'tls_csr', 'target': target, 'cn': args.tls_csr,
                                       'names': args.names or '', 'org': args.org})
        if args.json:
            out(got)
            return 0
        print(pal.ok_line(got.get('message') or 'made'))
        print(got.get('csr') or '')
        return 0
    if args.tls_selfsigned:
        cli_sure(args, 'a certificate of its own, made here, for %s - in place of the one it has' % target)
        return shown(api('POST', '/api/web', {'action': 'tls_selfsigned', 'target': target,
                                              'cn': args.tls_selfsigned, 'names': args.names or '',
                                              'days': args.days, 'org': args.org}))
    if args.tls_export:
        kind, path = args.tls_export
        if kind not in TLS_EXPORT_KINDS:
            raise SystemExit('acme: --tls-export %s FILE' % '|'.join(TLS_EXPORT_KINDS))
        body = {'action': 'tls_export', 'target': target, 'kind': kind, 'legacy': args.legacy}
        if TLS_EXPORT_KINDS[kind][2]:
            body['passphrase'] = os.environ.get('ACME_PASSPHRASE') or ask_password(
                'a password for the file (10 characters or more)', twice=True, env=None)
        got = api('POST', '/api/web', body)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if TLS_EXPORT_KINDS[kind][2] else 0o644)
        with os.fdopen(fd, 'wb') as f:
            f.write(base64.b64decode(got['file']))
        print(pal.ok_line('%s: %s' % (path, TLS_EXPORT_KINDS[kind][0])))
        return 0
    if args.tls_forget:
        cli_sure(args, 'acme no longer looks after the TLS of %s; nginx keeps the files it has' % target)
        return shown(api('POST', '/api/web', {'action': 'tls_forget', 'target': target}))
    if args.ntp:
        return shown(api('GET', '/api/ntp'))
    if args.ntp_sync:
        return shown(api('POST', '/api/ntp', {'action': 'sync', 'node': only or node_name()}))
    if args.net:
        return shown(api('GET', '/api/net'))
    if args.hisec:
        got = api('GET', '/api/hisec')
        if args.json:
            out(got)
            return 0
        print(pal.head('high security: %s' % ('on' if got.get('on') else 'off (acme --set high_security=1)')))
        for part, words in (('block', 'not kept'), ('waived', 'exceptions'), ('warn', 'to look at')):
            rows = got.get(part) or []
            if rows:
                print(pal.head('  %s (%d)' % (words, len(rows))))
                print(table([(r.get('rule'), r.get('title') or r.get('what'), r.get('fix') or '')
                             for r in rows], ['rule', 'what', 'put right by'], [18, 70, 40]))
        if not any(got.get(p) for p in ('block', 'waived', 'warn')):
            print(pal.ok_line('every rule kept'))
        return 0
    if args.hisec_waive:
        rule, on = args.hisec_waive
        if on not in ('on', 'off'):
            raise SystemExit('acme: --hisec-waive RULE on|off')
        return shown(api('POST', '/api/hisec', {'action': 'waive', 'rule': rule, 'on': on == 'on'}))
    if args.api:
        method = args.api[0].upper()
        if method not in ('GET', 'POST') or len(args.api) < 2:
            raise SystemExit('acme: --api GET|POST /api/... [BODY]')
        path, _, query = args.api[1].partition('?')
        body = None
        if len(args.api) > 2:
            raw = sys.stdin.read() if args.api[2] == '-' else args.api[2]
            try:
                body = json.loads(raw)
            except ValueError:
                raise SystemExit('acme: the body is JSON: {"action": "..."}')
            if not isinstance(body, dict):
                raise SystemExit('acme: the body is a JSON object')
            def keys(o):
                if isinstance(o, dict):
                    for k, v in o.items():
                        yield str(k)
                        yield from keys(v)
                elif isinstance(o, list):
                    for v in o:
                        yield from keys(v)
            # A setting known not to be one is not taken for a secret (1.0.207):
            # acme_key, acme_account_key were refused.
            secretish = [k for k in keys(body) if k in SECRET_KEYS or (re.search(
                r'pass|secret|token|key|pin', k, re.I) and not (k in DEFAULTS and k not in
                                                                SECRET_KEYS))]
            if args.api[2] != '-' and secretish:
                raise SystemExit('acme: %s - a secret is not taken written out on the command '
                                 'line: give the body through stdin (--api POST PATH -)'
                                 % ', '.join(sorted(set(secretish))))
        qs = dict(x.split('=', 1) if '=' in x else (x, '') for x in query.split('&') if x)
        got = cli_api(Daemon(store, serve=False), who, method, path,
                      body if method == 'POST' else None, qs)
        print(json.dumps(got, indent=1, ensure_ascii=False, default=str))
        return 0

    def daemon_here():
        try:
            os.kill(int((Path(STATE_DIR) / 'acme.lock').read_text().strip() or 0), 0)
            return True
        except (OSError, ValueError):
            return False

    if args.isemon_test and CONFIG.get('isemon') and daemon_here():
        # From every node, by each daemon's own sender (1.0.188), as the pages do.
        return asked('isemon', api('POST', '/api/isemon', {'action': 'test', 'node': only}), 60)
    if args.isemon_test:
        if not CONFIG.get('isemon_targets'):
            raise SystemExit('nothing to send to: acme --set isemon_targets=HOST:514')
        sh = Shipper()
        CONFIG['isemon'] = 1
        sh.configure()
        sh.put('acme', 'daemon', 'a test from acme %s on the command line - isemon reads nothing '
               'from this line' % __version__)
        sh.flush(3)
        time.sleep(0.5)
        st = sh.state()
        for t in st['targets']:
            if t in st['trouble']:
                print(pal.bad_line('%s: %s' % (t, st['trouble'][t])))
            else:
                print(pal.ok_line('%s: sent (%d)' % (t, st['sent'].get(t, 0))))
        return 1 if st['trouble'] else 0               # trouble said is a failure (1.0.205)

    build_parser().print_help()
    return 2


_DAEMON_LOCK = None


def daemon_lock():
    """One daemon at a time. A second one - started by hand beside the
    service - would share nothing and answer half the requests."""
    global _DAEMON_LOCK
    import fcntl
    path = Path(STATE_DIR) / 'acme.lock'
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError:
        fd = os.open(str(path), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        try:
            pid = os.read(os.open(str(path), os.O_RDONLY), 32).decode().strip()
        except OSError:
            pid = ''
        raise SystemExit('acme is running already%s - this one stops here.\n'
                         '  what it is doing:  acme --status\n'
                         '  the service:       systemctl status acme'
                         % (' (pid %s)' % pid if pid else ''))
    try:
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
    except OSError:
        pass
    _DAEMON_LOCK = fd


def cli_dump_copy():
    """The daemon's copy of every table, written to stdout (1.0.150): made in
    this process, its work no longer took the daemon's own time - a copy of
    a big database is minutes of Python."""
    load_config(saved=None)
    try:
        db = open_db()
    except DbError as e:
        sys.stderr.write('acme: %s\n' % e)
        return 1
    try:
        dump_tables(db, sys.stdout.buffer, child=True)
        sys.stdout.buffer.flush()
    finally:
        db.close()
    return 0


def run_daemon():
    signal.signal(signal.SIGHUP, lambda *_: HUP_ASKED.set())
    become_service_user()
    load_config()
    daemon_lock()
    log_open()
    try:
        db = open_db()
        store = Storage(db)
        DAEMON_DB[0] = db
    except Exception as e:
        log('the database %s could not be opened: %s' % (CONFIG.get('db_engine'), e), 'error')
        raise SystemExit(1)
    load_config(saved=store.settings_saved())
    log_open()
    if not store.accounts():
        pw = secrets.token_urlsafe(12)
        store.add_account('admin', 'fulladmin', pw, note='made on the first start',
                          must_change=1)
        try:
            write_replacing(STATE_DIR / 'first-login.txt', 'name: admin\npassword: %s\n' % pw,
                            0o600)
        except OSError:
            pass
        store.add_event('accounts', 'there was no account, so admin was made; its password '
                        'is in %s' % (STATE_DIR / 'first-login.txt'), 'warn')
    Daemon(store).run()
    return 0


def entry():
    """The command: run as a script, or imported by /usr/local/bin/acme so its
    compiled form is kept (1.0.136) - a run no longer compiles 1.6 MB first."""
    try:
        sys.exit(cli_main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (ValueError, OSError, LdapError, DbError) as e:
        # Said as one line, not a trace (1.0.44): a missing file, a name
        # with a comma, a directory that is not there.
        if isinstance(e, BrokenPipeError):
            sys.exit(0)
        if '--daemon' in sys.argv:
            raise                       # the service keeps its whole trace
        sys.stderr.write('acme: %s\n' % e)
        sys.exit(1)
    except BrokenPipeError:
        sys.exit(0)


def acme_argv(here=None):
    """How this program runs itself again (the console's commands): imported,
    so its compiled form is used."""
    here = os.path.dirname(os.path.abspath(here or __file__))
    return [sys.executable, '-I', '-c', 'import sys; sys.path.insert(0, %r); sys.argv[0] = "acme"; '
            'import acme; acme.entry()' % here]


