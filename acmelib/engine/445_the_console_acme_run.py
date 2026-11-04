# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the console: acme run by its menus, on the server's own screen (1.0.130) --------
# `acme --console` - and, with `acme --console-at-login on`, what root sees first
# after signing in at the console or over SSH. Everything is done by the same
# `acme ...` commands the command line has (each one run as it would be typed,
# so nothing here can do more than they do), plus the live log and the
# journal. q leaves it for the ordinary shell; ! opens a shell and
# comes back when it is closed. English, coloured with colorama when present.
import textwrap
# In /etc itself, where only root writes (1.0.136) - not in /etc/acme, whose
# group the daemon's account is in.
CONSOLE_FLAG = Path(os.environ.get('ACME_CONSOLE_FLAG', '/etc/acme-console-login'))
CONSOLE_PROFILE = Path('/etc/profile.d/zz-acme-console.sh')


class ConsoleBack(Exception):
    """Back to the menu."""


class Console(object):
    def __init__(self, pal):
        self.pal = pal
        self.me = os.path.abspath(sys.argv[0] if sys.argv and sys.argv[0].endswith('.py')
                                  else __file__)
        try:
            __import__('readline')     # arrows and history in input()
        except ImportError:
            pass

    # ---- small things ---------------------------------------------------------------
    def cmd(self, *args, show=True):
        """`acme ARGS`, its output on the screen; its exit code."""
        argv = acme_argv(self.me) + [str(a) for a in args]
        if not self.pal.on:
            argv.append('--no-color')
        if show:
            print(self.pal.dim('$ acme ' + ' '.join(self._quote(a) for a in args)))
        try:
            return subprocess.call(argv)
        except KeyboardInterrupt:
            print()
            return 130

    def out(self, *args):
        """`acme ARGS --json`, read."""
        try:
            got = subprocess.run(acme_argv(self.me) + [str(a) for a in args] + ['--json'],
                                 capture_output=True, text=True, timeout=60)
            return json.loads(got.stdout or 'null')
        except Exception:                               # noqa: BLE001
            return None

    @staticmethod
    def _quote(a):
        a = str(a)
        return a if re.match(r'^[A-Za-z0-9_@%+=:,./-]+\Z', a) else "'%s'" % a.replace("'", "'\\''")

    # ---- keys on the ordinary terminal: Esc goes back everywhere (1.0.132) ---------
    def _raw(self):
        """The terminal's settings, to be put back; None without a terminal."""
        try:
            import termios
            return termios.tcgetattr(sys.stdin.fileno())
        except Exception:                               # noqa: BLE001
            return None

    def _restore(self, was):
        if was is None:
            return
        import termios
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, was)

    def key(self, wait=None):
        """One key, without Enter: 'esc', 'enter', 'bs', 'up'..., a character -
        or None when `wait` seconds went by without one."""
        import select
        import tty
        fd = sys.stdin.fileno()
        was = self._raw()
        try:
            if was is not None:
                # TCSANOW: what was typed ahead is kept, not thrown away.
                import termios
                tty.setcbreak(fd, termios.TCSANOW)
            r, _w, _x = select.select([fd], [], [], wait)
            if not r:
                return None
            ch = os.read(fd, 1)
            if ch == b'\x1b':
                # Alone, Esc; followed at once by more, a key's sequence.
                r, _w, _x = select.select([fd], [], [], 0.05)
                if not r:
                    return 'esc'
                rest = os.read(fd, 8)
                full = {b'[5~': 'pgup', b'[6~': 'pgdn', b'[1~': 'home', b'[4~': 'end',
                        b'[7~': 'home', b'[8~': 'end', b'[H': 'home', b'[F': 'end',
                        b'OH': 'home', b'OF': 'end'}.get(rest)
                if full:
                    return full
                return {b'[A': 'up', b'[B': 'down', b'[C': 'right', b'[D': 'left', b'OA': 'up',
                        b'OB': 'down', b'OC': 'right', b'OD': 'left'}.get(rest[:2], 'seq')
            if ch in (b'\r', b'\n'):
                return 'enter'
            if ch in (b'\x7f', b'\x08'):
                return 'bs'
            if ch == b'\x03':
                return 'ctrl-c'
            if ch == b'\x04':
                return 'ctrl-d'
            if ch == b'\x15':
                return 'ctrl-u'
            try:
                return ch.decode('utf-8')
            except UnicodeDecodeError:
                more = ch
                while len(more) < 4:
                    more += os.read(fd, 1)
                    try:
                        return more.decode('utf-8')
                    except UnicodeDecodeError:
                        continue
                return ''
        finally:
            self._restore(was)

    def ask(self, words, default='', secret=False):
        """A line typed; Esc (or Ctrl+C) goes back to the menu. A secret shows
        a star for each character, never the characters."""
        p = self.pal
        hint = (' [%s]' % default) if default else ''
        prompt = '  %s%s: ' % (p.info(words), p.dim(hint))
        if self._raw() is None:
            try:
                got = input(prompt)
            except EOFError:
                raise ConsoleBack()
            return got.strip() or default
        sys.stdout.write(prompt)
        sys.stdout.flush()
        got = ''
        while True:
            k = self.key()
            if k in ('esc', 'ctrl-c', 'ctrl-d'):
                sys.stdout.write(p.dim('  (back)') + '\n')
                sys.stdout.flush()
                raise ConsoleBack()
            if k == 'enter':
                sys.stdout.write('\n')
                sys.stdout.flush()
                return got.strip() or default
            if k == 'bs':
                if got:
                    got = got[:-1]
                    sys.stdout.write('\b \b')
            elif k == 'ctrl-u':
                sys.stdout.write('\b \b' * len(got))
                got = ''
            elif k and len(k) == 1 and k.isprintable():
                got += k
                sys.stdout.write('*' if secret else k)
            sys.stdout.flush()

    def yes(self, words):
        return self.ask(words + ' (y/N)').lower() in ('y', 'yes', 'a', 'ano')

    def pause(self):
        sys.stdout.write(self.pal.dim('\n  Enter or Esc - back to the menu '))
        sys.stdout.flush()
        if self._raw() is None:
            try:
                input()
            except EOFError:
                pass
            return
        while self.key() not in ('enter', 'esc', 'ctrl-c', 'ctrl-d', 'q'):
            pass
        sys.stdout.write('\n')

    def stopped(self, wait):
        """In a live view: True when Esc, q or Ctrl+C was pressed within
        `wait` seconds."""
        if self._raw() is None:
            time.sleep(wait)
            return False
        return self.key(wait) in ('esc', 'q', 'ctrl-c', 'ctrl-d')

    def clear_screen(self):
        if sys.stdout.isatty():
            sys.stdout.write('\033[H\033[2J')
            sys.stdout.flush()

    # ---- the menus: a text screen, arrows and Enter (1.0.131) ----------------------
    # curses: only what changed is written, so nothing blinks; a window made
    # bigger or smaller (PuTTY's too) is drawn again to its new size. Leaving it
    # for a command's output and coming back is the one full redraw.
    HELP = ' Up/Down move   Enter choose   Esc back   ! shell   q leave '

    def status_thread(self):
        """The line at the top, asked for again every 20 s off the screen's
        thread - the menu never waits for it."""
        def look():
            vip, vip_at = None, 0.0
            while not self.closing:
                # Nothing asked while nobody sees the bar (1.0.136): in a live
                # view, a page or a shell - asked again on the way back.
                if self.plain and not self.st_now:
                    time.sleep(0.5)
                    continue
                self.st_now = False
                st = self.out('--status') or {}
                active = '?'
                if shutil.which('systemctl'):
                    try:
                        active = subprocess.run(['systemctl', 'is-active', 'acme'],
                                                capture_output=True, text=True,
                                                timeout=10).stdout.strip() or '?'
                    except Exception:                   # noqa: BLE001
                        pass
                if time.time() - vip_at > 60 or getattr(self, 'vip_now', False):
                    self.vip_now = False
                    vip, vip_at = self.vip_where(), time.time()
                self.st = dict(st, _active=active, _vip=vip)
                self.st_gen += 1
                for _ in range(60):
                    if self.closing or self.st_now:
                        break
                    time.sleep(0.5)
        threading.Thread(target=look, name='acme-console-status', daemon=True).start()

    def vip_where(self):
        """The VIP address (VRRP) and which node holds it now (1.0.135):
        {'address', 'on', 'holders': [nodes]} - or None when there is none."""
        got = self.out('--web-status') or {}
        vip = got.get('vip') or {}
        if not isinstance(vip, dict) or not vip.get('address'):
            return None
        holders = [n for n, v in sorted((got.get('nodes') or {}).items())
                   if isinstance(v, dict) and (v.get('vip_here') or v.get('role') == 'MASTER')]
        return {'address': str(vip['address']).split('/')[0], 'on': bool(vip.get('on')),
                'holders': holders}

    def _put(self, y, x, text, attr=0):
        try:
            h, w = self.scr.getmaxyx()
            if y < 0 or y >= h or x >= w:
                return
            self.scr.addnstr(y, x, str(text), max(0, w - x - (1 if y == h - 1 else 0)), attr)
        except Exception:                               # noqa: BLE001 - the edge
            pass

    def _colours(self):
        c = self.curses
        self.A = {'head': c.A_REVERSE, 'sel': c.A_REVERSE | c.A_BOLD, 'ok': c.A_BOLD,
                  'warn': c.A_BOLD, 'bad': c.A_BOLD, 'dim': c.A_DIM, 'key': c.A_BOLD,
                  'title': c.A_BOLD}
        if not c.has_colors():
            return
        try:
            c.start_color()
            try:
                c.use_default_colors()
                bg = -1
            except Exception:                           # noqa: BLE001
                bg = c.COLOR_BLACK
            c.init_pair(1, c.COLOR_BLACK, c.COLOR_CYAN)
            c.init_pair(2, c.COLOR_BLACK, c.COLOR_GREEN)
            c.init_pair(3, c.COLOR_GREEN, bg)
            c.init_pair(4, c.COLOR_YELLOW, bg)
            c.init_pair(5, c.COLOR_RED, bg)
            c.init_pair(6, c.COLOR_CYAN, bg)
            self.A.update(head=c.color_pair(1), sel=c.color_pair(2) | c.A_BOLD,
                          ok=c.color_pair(3) | c.A_BOLD, warn=c.color_pair(4) | c.A_BOLD,
                          bad=c.color_pair(5) | c.A_BOLD, key=c.color_pair(6) | c.A_BOLD)
        except Exception:                               # noqa: BLE001
            pass

    def draw(self, title, items, sel, top, path):
        scr, A = self.scr, self.A
        scr.erase()
        h, w = scr.getmaxyx()
        st = self.st or {}
        # The bar at the top: what this is, and how it is.
        self._put(0, 0, ' ' * w, A['head'])
        left = ' acme %s  %s ' % (__version__, socket.gethostname())
        self._put(0, 0, left, A['head'] | self.curses.A_BOLD)
        active = st.get('_active') or '...'
        svc = ' service %s ' % active
        self._put(0, len(left) + 1, svc, A['sel'] if active == 'active' else
                  (A['head'] if active == '...' else self.curses.A_REVERSE | A['bad']))
        # As --status --json says it (1.0.133): maintenance is {'on': …}, the
        # nodes a list.
        bits = []
        if st.get('node'):
            bits.append('node ' + str(st['node']))
        nodes = st.get('nodes') or []
        if len(nodes) > 1:
            alive = sum(1 for n in nodes if n.get('alive'))
            rep_ = st.get('replication') or {}
            bits.append('%d of %d nodes%s' % (alive, len(nodes), (
                ', replication %s' % ('ok' if rep_.get('healthy') else 'NOT ok'))
                if rep_.get('mode') == 'replicated' else ''))
        vip = st.get('_vip')
        vip_bad = False
        if vip:
            if not vip['on']:
                bits.append('VIP off')
            elif vip['holders']:
                bits.append('VIP %s on %s' % (vip['address'], ', '.join(vip['holders'])))
                vip_bad = len(vip['holders']) > 1
            else:
                bits.append('VIP %s on NO node' % vip['address'])
                vip_bad = True
        # Too long for the bar: the words get shorter; still too long, it goes
        # on the line under the bar.
        short = [b.replace(' of ', '/').replace('replication', 'repl.')
                 .replace('node ', '', 1 if b.startswith('node ') else 0) for b in bits]
        tries = [bits, short]
        y = 1
        for b in tries:
            right = ' ' + ' | '.join(b) + ' '
            if len(left) + len(svc) + len(right) + 2 < w:
                self._put(0, w - len(right), right, A['head'])
                break
        else:
            self._put(1, 1, ' | '.join(bits), A['key'])
            y = 2
        if vip_bad:
            self._put(y, 1, 'the VIP address %s is held by %s' % (
                vip['address'], ', '.join(vip['holders']) if vip['holders'] else 'no node'),
                A['bad'])
            y += 1
        if ((st.get('maintenance') or {}).get('on') if isinstance(st.get('maintenance'), dict)
                else st.get('maintenance') is True):
            why = (st.get('maintenance') or {}).get('why') or ''
            self._put(y, 1, 'THIS NODE IS IN MAINTENANCE - it does no work of its own%s' % (
                (' (%s)' % why) if why else ''), A['warn'])
            y += 1
        others = [n for n in (st.get('maint_nodes') or []) if str(n) != str(st.get('node'))]
        if others:
            self._put(y, 1, 'in maintenance: %s' % ', '.join(str(n) for n in others), A['warn'])
            y += 1
        for t in st.get('trials') or []:
            left = max(0, int(float(t.get('until') or 0) - time.time()))
            self._put(y, 1, '%s waits to be kept: %d:%02d left (Cluster > Keep or put back)' % (
                'the new network of %s' % t.get('node') if t.get('kind') == 'net'
                else 'the change of the firewall', left // 60, left % 60), A['warn'])
            y += 1
        if st and st.get('daemon_alive') is False:
            self._put(y, 1, 'the daemon is not answering', A['bad'])
            y += 1
        for one in (st.get('problems') or [])[:max(0, min(4, h - 12))]:
            self._put(y, 1, '! ' + str(one), A['warn'])
            y += 1
        y += 1
        self._put(y, 2, path, A['dim'])
        self._put(y, 2 + len(path), title, A['title'])
        y += 2
        # The items, a window of them when the screen is short.
        room = max(1, h - y - 2)
        if sel < top:
            top = sel
        if sel >= top + room:
            top = sel - room + 1
        width = max(20, min(w - 6, max(len(it[1]) for it in items) + 10))
        for n, it in enumerate(items[top:top + room]):
            i = top + n
            line = ' %3s  %s' % (it[0], it[1])
            line = line + ' ' * max(0, width - len(line))
            if i == sel:
                self._put(y + n, 2, line, A['sel'])
            else:
                self._put(y + n, 2, ' %3s' % it[0], A['key'])
                self._put(y + n, 8, it[1])
        if top > 0:
            self._put(y - 1, 4, '^ more', A['dim'])
        if top + room < len(items):
            self._put(y + room, 4, 'v more', A['dim'])
        self._put(h - 1, 0, ' ' * (w - 1), A['head'])
        self._put(h - 1, 0, self.HELP[:w - 1], A['head'])
        scr.noutrefresh()
        return top

    def menu(self, title, items, path=''):
        """items: [(key, words, function[, 'plain'])]; returns 'back' or 'quit'."""
        c = self.curses
        sel, top, typed, typed_at, seen = 0, 0, '', 0.0, -1
        while True:
            if self.plain:
                # Back from a command's screen: drawn whole, once.
                c.reset_prog_mode()
                self.scr.clear()
                self.plain = False
                self.st_now = True
            top = self.draw(title, items, sel, top, path)
            self.curses.doupdate()
            self.backdrop = (lambda _s=sel, _t=top: self.draw(title, items, _s, _t, path))
            seen = self.st_gen
            self.scr.timeout(500)
            while True:
                k = self.scr.getch()
                if k != -1 or self.st_gen != seen:
                    break
                # The window's size looked at too (PuTTY and others whose
                # change is not always told): drawn again to the new one.
                try:
                    size = os.get_terminal_size(sys.__stdout__.fileno())
                    if (size.lines, size.columns) != self.scr.getmaxyx():
                        c.resizeterm(size.lines, size.columns)
                        k = c.KEY_RESIZE
                        break
                except (OSError, ValueError, c.error):
                    pass
            if k == -1:
                continue
            if k == 27:
                # An arrow some terminals send as ESC [ B rather than as the
                # key the terminal description names: read whole here.
                self.scr.nodelay(True)
                k2 = self.scr.getch()
                if k2 in (ord('['), ord('O')):
                    k3 = self.scr.getch()
                    k = {ord('A'): c.KEY_UP, ord('B'): c.KEY_DOWN, ord('C'): c.KEY_RIGHT,
                         ord('D'): c.KEY_LEFT, ord('H'): c.KEY_HOME,
                         ord('F'): c.KEY_END}.get(k3, -1)
                    if k3 in (ord('5'), ord('6')):            # PgUp / PgDn: ESC [ 5 ~
                        self.scr.getch()
                        k = c.KEY_PPAGE if k3 == ord('5') else c.KEY_NPAGE
                    if k == -1:
                        continue
                elif k2 != -1:
                    c.ungetch(k2)
                self.scr.nodelay(False)
            if k == c.KEY_RESIZE:
                try:
                    c.update_lines_cols()
                except Exception:                       # noqa: BLE001
                    pass
                self.scr.clear()
                continue
            if k in (c.KEY_UP, ord('k')):
                sel = (sel - 1) % len(items)
            elif k in (c.KEY_DOWN, ord('j'), 9):
                sel = (sel + 1) % len(items)
            elif k in (c.KEY_HOME, c.KEY_PPAGE):
                sel = 0
            elif k in (c.KEY_END, c.KEY_NPAGE):
                sel = len(items) - 1
            elif k in (27, c.KEY_LEFT, c.KEY_BACKSPACE, 127, 8):
                if path:
                    return 'back'
            elif k in (ord('q'), ord('Q')):
                return 'quit'
            elif k == ord('!'):
                self.go_plain(self.shell)
            elif ord('0') <= k <= ord('9'):
                now = time.time()
                typed = (typed if now - typed_at < 1.0 else '') + chr(k)
                typed_at = now
                hit = [i for i, it in enumerate(items) if it[0] == typed]
                if hit:
                    sel = hit[0]
                    # One that no longer number can grow into: chosen at once.
                    if not any(it[0].startswith(typed) and it[0] != typed for it in items):
                        k = 10
                        typed = ''
            if k in (10, 13, c.KEY_ENTER, c.KEY_RIGHT):
                it = items[sel]
                # Run on the text screen - its questions are windows there
                # (1.0.135); only a view of its own ('plain') leaves it.
                if len(it) > 3 and it[3] == 'plain':
                    r = self.go_plain(it[2])
                else:
                    try:
                        r = it[2]()
                    except ConsoleBack:
                        r = None
                if r == 'quit':
                    return 'quit'

    def go_plain(self, fn):
        """`fn` on the ordinary terminal - a command's output, a question, the
        live log - and back to the screen after it."""
        c = self.curses
        c.def_prog_mode()
        c.endwin()
        self.plain = True
        # A clean screen for it - not what the last command left there.
        if sys.stdout.isatty():
            sys.stdout.write('\033[H\033[2J\033[3J')
            sys.stdout.flush()
        try:
            return fn()
        except ConsoleBack:
            return None
        except KeyboardInterrupt:
            print()
            return None

    def run(self):
        main = [
            ('1', 'Status and checks', self.m_status),
            ('2', 'Live log', self.m_live_log),
            ('3', 'Accounts of the administration', self.m_accounts),
            ('4', 'Settings', self.m_settings),
            ('5', 'Directories (Active Directory, LDAP)', self.m_directories),
            ('6', 'Cluster, VIP address and maintenance', self.m_cluster),
            ('7', 'Backups', self.m_backups),
            ('8', 'Upgrades', self.m_upgrades),
            ('9', 'The service', self.m_service),
            ('10', 'The pages\' certificates, updates, restarts, tests', self.m_ops),
            ('11', 'Encryption, sending out, time, network, high security', self.m_more),
        ]
        for fn in HOOKS['console_main']:
            main[:0] = list(fn(self) or [])
        os.environ.setdefault('ESCDELAY', '25')     # Esc at once, not after a second
        # Lines and blocks drawn as UTF-8 characters, as PuTTY in UTF-8 shows
        # them - not the line-drawing set, which it draws as letters.
        os.environ.setdefault('NCURSES_NO_UTF8_ACS', '1')
        try:
            import locale
            locale.setlocale(locale.LC_ALL, '')
        except Exception:                               # noqa: BLE001
            pass
        import curses
        self.curses = curses
        self.st, self.st_gen, self.st_now, self.closing, self.plain = {}, 0, False, False, False

        def body(scr):
            self.scr = scr
            try:
                curses.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass
            scr.keypad(True)
            self._colours()
            self.status_thread()
            # It opens on the live log, every line (1.0.135); Esc: the menu.
            if os.environ.get('ACME_CONSOLE_START', 'log') == 'log':
                self.go_plain(lambda: self.live_log(''))
            self.menu('Main menu', main)
        try:
            curses.wrapper(body)
        finally:
            self.closing = True
        print(self.pal.dim('  The acme console is closed - `acme --console` opens it again.'))
        return 0

    def shell(self):
        sh = os.environ.get('SHELL') or '/bin/bash'
        print(self.pal.dim('  A shell - exit (or Ctrl+D) comes back to the acme console.'))
        try:
            subprocess.call([sh], env=dict(os.environ, ACME_CONSOLE='1'))
        except KeyboardInterrupt:
            pass

    def sub(self, title, items):
        r = self.menu(title, items, path='Main menu > ')
        return 'quit' if r == 'quit' else None

    # ---- long output: a screen of its own, scrolled (1.0.134) -------------------
    # As the fullscreen pickers of video_tools: the terminal is not scrolled, a
    # window (top) into the lines is; each frame is one write (home, each line
    # cleared to its end, the rest cleared) so nothing blinks, and the scroll
    # bar is drawn after it into the last column. Arrows, PgUp/PgDn, Home/End,
    # Space; Esc, q or Enter back. A window made bigger or smaller is drawn
    # again to its size.
    def capture(self, argv, env=None):
        """What a command writes, its colour kept: (text, exit code)."""
        e = dict(os.environ, **(env or {}))
        if self.pal.on:
            e.update(FORCE_COLOR='1', SYSTEMD_COLORS='1')
        e['COLUMNS'] = str(max(60, self._cols() - 2))
        try:
            got = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, env=e, timeout=1800)
            # Made safe here whatever the colour (1.0.146): with colour off the
            # command wrote what a packet carried as it came, and page() put it
            # on root's terminal - the title, the clipboard, the screen.
            return term_safe(got.stdout.decode('utf-8', 'replace')), got.returncode
        except subprocess.TimeoutExpired:
            return 'it took more than 30 minutes and was stopped', 124
        except OSError as ex:
            return str(ex), 127

    @staticmethod
    def _cols():
        try:
            return os.get_terminal_size(sys.__stdout__.fileno()).columns
        except (OSError, ValueError):
            return 100

    @staticmethod
    def _fit(line, width):
        """`line` cut to `width` columns on the screen, its colours kept."""
        out, seen = [], 0
        for part in re.split(r'(\x1b\[[0-9;?]*[A-Za-z])', line):
            if not part:
                continue
            if part.startswith('\x1b['):
                out.append(part)
                continue
            if seen + len(part) > width:
                out.append(part[:max(0, width - seen)])
                out.append('\x1b[0m')
                return ''.join(out)
            out.append(part)
            seen += len(part)
        return ''.join(out) + ('\x1b[0m' if '\x1b[' in line else '')

    def page(self, title, text):
        p = self.pal
        lines = [ln.expandtabs(8).replace('\r', '') for ln in text.rstrip('\n').split('\n')] or ['']
        tty = self._raw() is not None and sys.stdout.isatty()
        if not tty:
            print(text)
            return
        out = sys.stdout
        out.write('\x1b[?1049h\x1b[?25l')
        top, size = 0, None
        try:
            while True:
                try:
                    sz = os.get_terminal_size(sys.__stdout__.fileno())
                    cols, rows = max(40, sz.columns), max(8, sz.lines)
                except OSError:
                    cols, rows = 100, 30
                avail = max(3, rows - 2)
                top = max(0, min(top, max(0, len(lines) - avail)))
                end = min(len(lines), top + avail)
                head = ' %s ' % title
                where = ' %d-%d of %d ' % (top + 1, end, len(lines)) if len(lines) > avail \
                    else ' %d lines ' % len(lines)
                bar = (head + ' ' * max(0, cols - len(head) - len(where)) + where)[:cols]
                foot = (' Up/Down PgUp/PgDn Home/End scroll   Esc, q or Enter back ')[:cols - 1]
                body = [self._fit(ln, cols - 2) for ln in lines[top:end]]
                body += [''] * (avail - len(body))
                frame = ['\x1b[7m' + bar + '\x1b[0m' if p.on else bar] + body + \
                    ['\x1b[7m' + foot + ' ' * max(0, cols - 1 - len(foot)) + '\x1b[0m'
                     if p.on else foot]
                out.write('\x1b[H' + '\n'.join(ln + '\x1b[K' for ln in frame) + '\x1b[J')
                self._scrollbar(2, avail, len(lines), avail, top, cols)
                out.flush()
                size = (cols, rows)
                while True:
                    k = self.key(0.3)
                    if k is not None:
                        break
                    try:
                        sz = os.get_terminal_size(sys.__stdout__.fileno())
                        if (max(40, sz.columns), max(8, sz.lines)) != size:
                            break
                    except OSError:
                        pass
                if k in ('esc', 'q', 'enter', 'ctrl-c', 'ctrl-d'):
                    return
                if k in ('up', 'k'):
                    top -= 1
                elif k in ('down', 'j'):
                    top += 1
                elif k in ('pgup', 'b'):
                    top -= avail - 1
                elif k in ('pgdn', ' ', 'f'):
                    top += avail - 1
                elif k in ('home', 'g'):
                    top = 0
                elif k in ('end', 'G'):
                    top = len(lines)
        finally:
            out.write('\x1b[?25h\x1b[?1049l')
            out.flush()

    def _scrollbar(self, base_row, nrows, total, visible, top, cols):
        if total <= visible or nrows <= 0:
            return
        thumb = max(1, min(nrows, round(nrows * visible / total)))
        span = nrows - thumb
        denom = max(1, total - visible)
        tstart = max(0, min(span, round(span * (top / denom))))
        on = self.pal.on
        parts = ['\x1b[?7l']
        for r in range(nrows):
            hit = tstart <= r < tstart + thumb
            g = '\u2588' if hit else '\u2502'
            if on:
                g = ('\x1b[36m' if hit else '\x1b[2m') + g + '\x1b[0m'
            parts.append('\x1b[%d;%dH%s' % (base_row + r, cols, g))
        parts.append('\x1b[?7h')
        sys.stdout.write(''.join(parts))

    def show(self, *args):
        """`acme ARGS`, its output on a screen of its own."""
        # A question left empty is nothing asked for: back to the menu.
        if any(a is None or str(a).strip() == '' for a in args):
            return
        self.clear_screen()
        print(self.pal.dim('  working… $ acme ' + ' '.join(self._quote(a) for a in args)))
        argv = acme_argv(self.me) + [str(a) for a in args]
        text, rc = self.capture(argv)
        if rc not in (0, None):
            text += '\n' + self.pal.dim('(it ended with %d)' % rc)
        self.page('$ acme ' + ' '.join(self._quote(a) for a in args), text)

    def show_live(self, *args):
        """`acme ARGS` straight on the terminal - one that asks something."""
        if any(a is None or str(a).strip() == '' for a in args):
            return
        self.clear_screen()
        self.cmd(*args)
        self.pause()

    # ---- 1 status ---------------------------------------------------------------
    def m_status(self):
        def events():
            got = self.form('Events', [
                {'key': 'n', 'label': 'how many', 'kind': 'number', 'value': '40',
                 'range': (1, 5000), 'need': True},
                {'key': 'q', 'label': 'only with the words', 'help':
                 'Empty: every event. Or a name, a kind (sign-ins, accounts) or a word.'}])
            if got:
                self.act('--events', '--limit', got['n'], *(['--search', got['q']]
                                                             if got['q'] else []))

        return self.sub('Status and checks', [
            ('1', 'Status', lambda: self.act('--status')),
            ('2', 'Checks (the database, the key, the directories…)',
             lambda: self.act('--check')),
            ('3', 'Events', events),
        ])

    # ---- 2 live log -------------------------------------------------------------
    LOG_TONES = {'error': 'bad', 'crit': 'bad', 'warn': 'warn', 'info': '', 'debug': 'dim'}

    def m_live_log(self):
        self.live(lambda: self.live_log(''))

    # ---- live views: scrolled, and what is typed is a grep (1.0.135) ------------
    # The log and the journal come into one screen of
    # their own: the newest at the bottom, followed while the view is at the
    # end. Up/PgUp/Home scroll back (the view then stays where it is and counts
    # what came meanwhile), End follows again; a bar on the right shows where
    # the window is. Whatever is typed filters the lines as `grep -i` does (a
    # regular expression, or the words as they are when it is not one), the
    # hits marked; Backspace takes a character back, Ctrl+U all of them. Esc
    # clears the filter first, then goes back to the menu.
    LIVE_KEEP = 20000

    def live_log(self, what=''):
        path = LOG_DIR / 'acme.log'
        st = {'f': None, 'ino': None}

        def opened():
            # Not through a link, nor stuck on a FIFO (1.0.149): the folder is
            # the acme account's, and this is root's console.
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                import stat as _st
                if not _st.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError('not a plain file')
            except OSError:
                os.close(fd)
                raise
            return os.fdopen(fd, 'r', encoding='utf-8', errors='replace')

        def first():
            try:
                f = opened()
            except OSError as e:
                return [self.pal.bad_line('%s cannot be read: %s' % (path, e))]
            st['f'] = f
            st['ino'] = os.fstat(f.fileno()).st_ino
            # Read from near the end only: a log can be gigabytes.
            f.seek(0, 2)
            start = max(0, f.tell() - 2 * 1024 * 1024)
            f.seek(start)
            got = f.read().splitlines()
            # The first line only when reading began inside it (1.0.146): a short
            # log lost its first whole line.
            if start and len(got) > 1:
                got = got[1:]
            return got[-self.LIVE_KEEP:]

        def more():
            f = st['f']
            if f is None:
                return []
            out = []
            while len(out) < 5000:
                ln = f.readline()
                if not ln:
                    break
                out.append(ln.rstrip('\n'))
            if not out:
                try:
                    if os.stat(str(path)).st_ino != st['ino']:      # rotated
                        f.close()
                        st['f'] = opened()
                        st['ino'] = os.fstat(st['f'].fileno()).st_ino
                except OSError:
                    pass
            return out
        try:
            self.live_view('Live log  %s' % path, first, more, self._log_text, what)
        finally:
            if st['f']:
                st['f'].close()

    def journal(self):
        """journalctl -u acme -f, in the live view."""
        try:
            pr = subprocess.Popen(['journalctl', '-u', 'acme', '-f', '-n', '400', '--no-pager'],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                  errors='replace')
        except OSError as e:
            self.page('journalctl', self.pal.bad_line(str(e)))
            return
        q = collections.deque()

        def pump():
            for ln in pr.stdout:
                q.append(ln.rstrip('\n'))
        threading.Thread(target=pump, daemon=True).start()

        def more():
            out = []
            while q:
                out.append(q.popleft())
            return out

        def paint(ln):
            return self._log_text(ln) if re.match(
                r'^\S+ \S+ (info|warn|error|debug|crit) ', ln) else tone_words(ln, self.pal)
        try:
            self.live_view('journalctl -u acme -f', lambda: [], more, paint, '')
        finally:
            pr.terminate()
            try:
                pr.wait(3)
            except Exception:                           # noqa: BLE001
                pr.kill()

    @staticmethod
    def _grep(find):
        """What is typed as `grep -i` takes it: a test of one line."""
        if not find:
            return lambda s: True
        try:
            rx = re.compile(find, re.I)
            return lambda s: rx.search(s) is not None
        except (re.error, OverflowError, RecursionError):   # a{9999999999} too (1.0.139)
            low = find.lower()
            return lambda s: low in s.lower()

    def _mark(self, coloured, find):
        """The hits of `find` shown reversed - in the text between the colours."""
        if not find or not self.pal.on:
            return coloured
        try:
            rx = re.compile(find, re.I)
        except (re.error, OverflowError, RecursionError):
            rx = re.compile(re.escape(find), re.I)
        out = []
        for part in re.split(r'(\x1b\[[0-9;?]*[A-Za-z])', coloured):
            if part.startswith('\x1b['):
                out.append(part)
            elif part:
                out.append(rx.sub(lambda m: '\x1b[7m' + m.group(0) + '\x1b[27m'
                                  if m.group(0) else '', part))
        return ''.join(out)

    @staticmethod
    def _slice(line, start, width):
        """Columns start..start+width of `line` on the screen, its colours kept."""
        out, seen = [], 0
        end = start + width
        for part in re.split(r'(\x1b\[[0-9;?]*[A-Za-z])', line):
            if not part:
                continue
            if part.startswith('\x1b['):
                out.append(part)
                continue
            a, b = seen, seen + len(part)
            if b > start and a < end:
                out.append(part[max(0, start - a):max(0, end - a)])
            seen = b
        return ''.join(out) + ('\x1b[0m' if '\x1b[' in line else '')

    def live_view(self, title, first, more, paint, find=''):
        """The live screen: `first()` the lines there are, `more()` those come
        since (asked a few times a second), `paint(line)` its colours."""
        p = self.pal
        if self._raw() is None or not sys.stdout.isatty():
            for ln in first() + more():
                print(ln)
            return
        import termios
        import tty
        fd = sys.stdin.fileno()
        was = termios.tcgetattr(fd)
        out = sys.stdout
        lines = []                       # (plain, coloured)

        def add(raw):
            for ln in raw:
                ln = term_safe(ln.expandtabs(8).replace('\r', ''))
                col = (paint(ln) if paint else ln) if p.on else self._plain_text(ln)
                lines.append((self._plain_text(col), col))
        add(first())
        test = self._grep(find)
        hits = [i for i, x in enumerate(lines) if test(x[0])]
        top, follow, xoff, new, dirty, size = 0, True, 0, 0, True, None
        tty.setcbreak(fd, termios.TCSANOW)
        out.write('\x1b[?1049h\x1b[?25l')
        try:
            while True:
                came = more()
                if came:
                    n0 = len(lines)
                    add(came)
                    got = [i for i in range(n0, len(lines)) if test(lines[i][0])]
                    hits += got
                    if not follow:
                        new += len(got)
                    if len(lines) > self.LIVE_KEEP * 1.25:
                        cut = len(lines) - self.LIVE_KEEP
                        gone = sum(1 for i in hits if i < cut)
                        del lines[:cut]
                        hits = [i - cut for i in hits if i >= cut]
                        top = max(0, top - gone)
                    dirty = dirty or bool(got)
                try:
                    sz = os.get_terminal_size(sys.__stdout__.fileno())
                    cols, rows = max(40, sz.columns), max(8, sz.lines)
                except OSError:
                    cols, rows = 100, 30
                if (cols, rows) != size:
                    size, dirty = (cols, rows), True
                avail = max(3, rows - 2)
                last = max(0, len(hits) - avail)
                if follow:
                    top = last
                top = max(0, min(top, last))
                if dirty:
                    end = min(len(hits), top + avail)
                    where = (' %d-%d of %d ' % (top + 1, end, len(hits))) if hits else ' 0 '
                    state = ' following ' if follow else (' PAUSED%s ' % (
                        ', %d new below' % new if new else ''))
                    head = ' %s ' % title
                    gp = '  grep -i: %s_ ' % find if find else '  type to grep '
                    right = state + where
                    bar = (head + gp)[:max(0, cols - len(right))]
                    bar = bar + ' ' * max(0, cols - len(bar) - len(right)) + right
                    foot = (' type: grep (any case)  Bksp  Ctrl+U clear   Up/Down PgUp/PgDn '
                            'Home  End: follow   Left/Right  Esc back ')[:cols - 1]
                    body = [self._slice(self._mark(lines[i][1], find), xoff, cols - 2)
                            for i in hits[top:end]]
                    if not hits:
                        body = ['', '   ' + (p.dim('nothing with "%s" yet' % find) if find
                                             else p.dim('nothing yet'))]
                    body += [''] * (avail - len(body))
                    inv = (lambda t: '\x1b[7m' + t + '\x1b[0m') if p.on else (lambda t: t)
                    tone = '\x1b[33m' if (not follow and p.on) else ''
                    frame = [tone + inv(bar[:cols])] + body[:avail] + \
                        [inv(foot + ' ' * max(0, cols - 1 - len(foot)))]
                    out.write('\x1b[H' + '\n'.join(ln + '\x1b[K' for ln in frame) + '\x1b[J')
                    self._scrollbar(2, avail, len(hits), avail, top, cols)
                    out.flush()
                    dirty = False
                k = self.key(0.25)
                if k is None:
                    continue
                dirty = True
                if k in ('esc', 'ctrl-c', 'ctrl-d'):
                    if find and k == 'esc':
                        find = ''
                    else:
                        return
                elif k == 'up':
                    follow, top = False, top - 1
                elif k == 'down':
                    top += 1
                    follow = top >= last
                elif k == 'pgup':
                    follow, top = False, top - (avail - 1)
                elif k == 'pgdn':
                    top += avail - 1
                    follow = top >= last
                elif k == 'home':
                    follow, top = False, 0
                elif k in ('end', 'enter'):
                    follow, new = True, 0
                elif k == 'left':
                    xoff = max(0, xoff - 20)
                    continue
                elif k == 'right':
                    xoff += 20
                    continue
                elif k == 'bs':
                    find = find[:-1]
                elif k == 'ctrl-u':
                    find = ''
                elif k and len(k) == 1 and k.isprintable():
                    find += k
                else:
                    continue
                if k in ('bs', 'ctrl-u', 'esc') or (k and len(k) == 1 and k.isprintable()):
                    test = self._grep(find)
                    hits = [i for i, x in enumerate(lines) if test(x[0])]
                    follow, new = True, 0
                if follow:
                    new = 0
        finally:
            out.write('\x1b[?25h\x1b[?1049l')
            out.flush()
            termios.tcsetattr(fd, termios.TCSADRAIN, was)

    def _log_text(self, ln):
        """One line of the log, coloured (colorama when it is there): the time
        dim, the level by how bad, what it is about in cyan, addresses in
        magenta, accept and reject in green and red, a whole warning in yellow
        and a whole error in red."""
        p = self.pal
        ln = ln.rstrip('\n')
        m = re.match(r'^(\S+ \S+) (\w+)(\s+)(.*)$', ln)
        if not m or not p.on:
            return ln
        lvl, rest = m.group(2), m.group(4)
        tone = self.LOG_TONES.get(lvl, '')
        paint = {'bad': p.bad, 'warn': p.warn, 'dim': p.dim}.get(tone)
        what = re.match(r'^([a-z][a-z -]{1,30}): (.*)$', rest)
        head, body = (what.group(1) + ':', what.group(2)) if what else ('', rest)

        def words(t):
            t = re.sub(r'(\[?[0-9a-fA-F:]*\d{1,3}(?:\.\d{1,3}){3}\]?(?::\d+)?|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b)',
                       lambda x: p.addr(x.group(1)) + (p.c_warn if tone == 'warn' else
                                                       p.c_bad if tone == 'bad' else ''), t)
            t = re.sub(r'\b(accept(?:ed)?|signed in|in place|done|ok)\b',
                       lambda x: p.good(x.group(1)) + (p.c_warn if tone == 'warn' else ''), t)
            t = re.sub(r'\b(reject(?:ed)?|refused|failed|wrong|locked out|not answering)\b',
                       lambda x: p.bad(x.group(1)) + (p.c_warn if tone == 'warn' else ''), t)
            return t
        body = words(body)
        if paint is not None and tone != 'dim':
            body = paint(body)
        elif tone == 'dim':
            body = p.dim(body)
        lv = (paint or p.info)(lvl.ljust(5))
        return '%s %s %s%s' % (p.dim(m.group(1)), lv, p.info(head) + (' ' if head else ''), body)

    def _log_line(self, ln):
        print(self._log_text(ln))

    # ---- 3 accounts -------------------------------------------------------------
    ROLES = [('fulladmin', 'fulladmin - everything'),
             ('certadmin', 'certadmin - the certificates, no settings'),
             ('readonly', 'readonly - looks, changes nothing'),
             ('portal', 'portal - the enrolment pages only, rights from teams')]

    def _pw_fields(self):
        return [{'key': 'pw', 'label': 'password', 'kind': 'secret', 'need': True,
                 'help': 'At least 8 characters; only stars are shown.',
                 'check': lambda v, _: None if len(v) >= 8 else 'at least 8 characters'},
                {'key': 'again', 'label': 'again', 'kind': 'secret', 'need': True,
                 'check': lambda v, vals: None if v == vals.get('pw')
                 else 'the two passwords are not the same'}]

    def m_accounts(self):
        def load():
            got = self.out('--users') or {}
            self._mfa_on = bool(got.get('mfa_on')) if isinstance(got, dict) else False
            return self._rows(got, 'users')

        cols = [('account', lambda u: u.get('name'), 24, None),
                ('role', lambda u: u.get('role'), 10, None),
                ('state', lambda u: 'off' if u.get('disabled') else 'on', 5,
                 lambda u: 'dim' if u.get('disabled') else 'ok'),
                ('from', lambda u: u.get('source') or 'local', 9, None),
                ('second step', lambda u: (u.get('mfa') or {}).get('kind') or '-'
                 if isinstance(u.get('mfa'), dict) else (u.get('mfa') or '-'), 11, None),
                ('last in', lambda u: self._when(u.get('last_in')), 16, None),
                ('note', lambda u: u.get('note') or '', 40, lambda u: 'dim')]
        return self.sub('Accounts of the administration', [
            ('1', 'Browse them (Enter: what to do with one)',
             lambda: self.pick('Accounts of the administration', load, cols, self.account_do)),
            ('2', 'Make one', self.account_new),
            ('3', 'The second step of signing in, for everybody', self.mfa_switch),
        ])

    def account_do(self, u):
        name = u['name']
        local = (u.get('source') or 'local') == 'local'
        opts = []
        if local:
            opts.append(('pw', 'Set its password'))
        opts.append(('role', 'Change its role (now %s)' % u.get('role')))
        opts.append(('on', 'Switch it on again') if u.get('disabled') else
                    ('off', 'Switch it off'))
        if u.get('mfa'):
            opts.append(('mfa', 'Reset its second step (it sets one up again)'))
        opts += [('show', 'Show it all'), ('delete', 'Delete it')]
        what = self.choose(name, opts, '%s, %s, %s' % (u.get('role'), u.get('source') or 'local',
                                                      'off' if u.get('disabled') else 'on'))
        if what == 'pw':
            got = self.form('A new password for %s' % name, self._pw_fields())
            if got:
                self.act('--passwd', name, env={'ACME_PASSWORD': got['pw']})
        elif what == 'role':
            r = self.choose('The role of %s' % name, self.ROLES,
                            cur=[x[0] for x in self.ROLES].index(u.get('role'))
                            if u.get('role') in [x[0] for x in self.ROLES] else 0)
            if r and r != u.get('role'):
                self.act('--set-role', name, '--role', r)
        elif what == 'off':
            if self.confirm('Switch off', '%s can no longer sign in to the administration.'
                            % name, 'Switch it off'):
                self.act('--disable-user', name)
        elif what == 'on':
            self.act('--enable-user', name)
        elif what == 'mfa':
            if self.confirm('Reset the second step', '%s sets its second step up again at '
                            'its next sign-in.' % name, 'Reset it'):
                self.act('--reset-2fa', name)
        elif what == 'show':
            self.details(name, u, skip=('prefs',))
        elif what == 'delete':
            if self.confirm('Delete', 'The account %s is deleted. This cannot be undone.' % name,
                            'Delete it', danger=True):
                self.act('--del-user', name)

    def account_new(self):
        got = self.form('Make an account', [
            {'key': 'name', 'label': 'name', 'need': True,
             'help': 'What it signs in with: letters, digits, . _ -',
             'check': lambda v, _: None if re.match(r'^[A-Za-z0-9._@-]{1,64}$', v)
             else 'letters, digits and . _ - @ only'},
            {'key': 'role', 'label': 'role', 'kind': 'choice', 'value': 'readonly',
             'options': self.ROLES,
             'help': 'fulladmin may do everything; certadmin the certificates; readonly looks.'}]
            + self._pw_fields())
        if got:
            self.act('--add-user', got['name'], '--role', got['role'],
                     env={'ACME_PASSWORD': got['pw']})

    def mfa_switch(self):
        got = self.out('--users') or {}
        on = bool(got.get('mfa_on')) if isinstance(got, dict) else False
        r = self.choose('The second step for the administration', [
            ('on', 'On - every account gives a code after its password'),
            ('off', 'Off - the password is enough'),
            ('status', 'Show how it stands, account by account')],
            'It is %s now.' % ('ON' if on else 'off'), cur=0 if on else 1)
        if r == 'status':
            self.act('--admin-2fa', 'status')
        elif r and (r == 'on') != on:
            self.act('--admin-2fa', r)
        elif r:
            self.note('The second step', 'It is %s already.' % r)

    # ---- 6 settings -------------------------------------------------------------
    def m_settings(self):
        def by_key():
            keys = sorted(set(DEFAULTS) | set(TUNABLE))
            key = self.ask_one('Change one by its key', 'the key', help_=(
                'Its key, as `acme --settings` shows it - e.g. lockout_after, mail_host. '
                'Then the same window as in Browse opens.'),
                check=lambda v, _: None if v in keys else 'there is no setting %s' % v)
            if not key:
                return
            row = next((r[1] for r in self._settings_rows() if r[0] == 'set'
                        and r[1]['key'] == key), None)
            if not row:
                self.note('Change one', 'there is no setting %s' % key, 'bad')
                return
            done = self._edit_one(row)
            if done:
                self.note('Change one', done[0], 'bad' if done[1] else 'ok')

        def export():
            got = self.form('Export the settings', [
                {'key': 'file', 'label': 'to the file', 'value': '/root/acme-config.json',
                 'need': True, 'help': 'A JSON file; the secrets are left out of it.',
                 'check': lambda v, _: None if v.startswith('/') else 'a full path, from /'}])
            if got:
                self.act('--export-config', got['file'])
        return self.sub('Settings', [
            ('1', 'Browse and change (arrows, Enter)', self.settings_tui),
            ('2', 'Change one by its key', by_key),
            ('3', 'All of them as text', lambda: self.act('--settings')),
            ('4', 'Export them to a file', export),
        ])

    # ---- 5 directories ----------------------------------------------------------
    def m_directories(self):
        def directories():
            return self.pick('Directories', lambda: self._rows(self.out('--directories')), [
                ('directory', lambda r: r.get('name'), 14, None),
                ('hosts', lambda r: r.get('hosts'), 34, None),
                ('tls', lambda r: '%s:%s' % (r.get('tls'), r.get('port')), 12, None),
                ('base', lambda r: r.get('base'), 40, None)], self.directory_do)
        return self.sub('Directories (Active Directory, LDAP)', [
            ('1', 'Directories (Enter: try one, change it)', directories),
            ('2', 'Add a directory', lambda: self.directory_edit(None)),
        ])

    def directory_edit(self, r):
        """A directory added, or changed (1.0.187); its password asked, never shown."""
        r = r or {}
        got = self.form('Change the directory %s' % r['name'] if r.get('name') else 'Add a directory', ([] if r.get('name') else [
            {'key': 'name', 'label': 'its name', 'need': True,
             'check': lambda v, _: None if re.match(r'^[A-Za-z0-9_.-]+$', v) else 'letters, digits, . _ -'}]) + [
            {'key': 'hosts', 'label': 'servers', 'need': True, 'value': r.get('hosts') or '',
             'help': 'dc1.example.local,dc2.example.local - in order.'},
            {'key': 'base', 'label': 'where to look', 'need': True, 'value': r.get('base') or '',
             'help': 'DC=example,DC=local'},
            {'key': 'bind_dn', 'label': 'the account it reads with', 'value': r.get('bind_dn') or ''},
            {'key': 'bind_pw', 'label': 'its password', 'kind': 'secret', 'need': not r.get('name'),
             'help': 'Empty: the one it has is kept.' if r.get('name') else ''},
            {'key': 'tls', 'label': 'reached by', 'kind': 'choice', 'value': r.get('tls') or 'ldaps',
             'options': [('ldaps', 'LDAPS (636)'), ('starttls', 'StartTLS (389)'), ('none', 'plain (389) - not encrypted')]},
            {'key': 'port', 'label': 'port', 'value': str(r.get('port') or ''), 'help': 'Empty: as reached by says.'}])
        if not got:
            return
        args = ['--add-directory', got.get('name') or r['name'], '--hosts', got['hosts'], '--base', got['base'],
                '--bind-dn', got['bind_dn'], '--tls', got['tls']] + (['--port', got['port']] if got['port'] else [])
        env = None
        if got.get('bind_pw'):
            args += ['--bind-pw', '-']
            env = {'ACME_BIND_PW': got['bind_pw']}
        self.act(*args, env=env, title='$ acme --add-directory %s' % (got.get('name') or r['name']))

    def directory_do(self, r):
        what = self.choose(r['name'], [('test', 'Try it (and look somebody up)'),
                                        ('show', 'Show it all'), ('edit', 'Change it'),
                                        ('delete', 'Delete it')],
                           r.get('hosts') or '')
        if what == 'edit':
            return self.directory_edit(r)
        if what == 'test':
            who = self.ask_one('Try %s' % r['name'], 'look up too', need=False, help_=(
                'Empty: only the connection and the binding are tried. A name (novak): '
                'it is looked up, with its groups.'))
            if who is not None:
                # --directory-user is NAME USER, and a command of its own (1.0.139).
                self.act('--directory-test', r['name'])
                if who:
                    self.act('--directory-user', r['name'], who)
        elif what == 'show':
            self.details(r['name'], r, skip=('bind_pw', 'ca'))
        elif what == 'delete' and self.confirm(
                'Delete', 'The directory %s is deleted; nobody signs in from it any more.'
                % r['name'], 'Delete it', danger=True):
            self.act('--del-directory', r['name'])

    # ---- 6 cluster --------------------------------------------------------------
    def _nodes(self):
        got = self.out('--ha-status') or {}
        return [n.get('name') for n in (got.get('nodes') or []) if n.get('name')]

    def m_cluster(self):
        def maint():
            st = self.st or {}
            m = st.get('maintenance')
            on = m.get('on') if isinstance(m, dict) else bool(m)
            r = self.choose('Maintenance of this node', [
                ('on', 'Into maintenance - it does no work of its own'),
                ('off', 'Back into service')], 'It is %s now.' % (
                    'IN MAINTENANCE' if on else 'in service'), cur=1 if on else 0)
            if r == 'on':
                why = self.ask_one('Into maintenance', 'why', 'from the console', help_=(
                    'Shown to the other administrators. The other node (if any) answers '
                    'meanwhile.'))
                if why is not None:
                    self.act('--maintenance', 'on', '--why', why)
            elif r == 'off':
                self.act('--maintenance', 'off')

        def vip_move():
            nodes = self._nodes()
            vip = (self.st or {}).get('_vip') or {}
            if len(nodes) < 2:
                self.note('Move the VIP address', 'There is only one node.')
                return
            to = self.choose('Move the VIP address %s' % (vip.get('address') or ''),
                             [(n, n + ('   (holds it now)' if n in (vip.get('holders') or [])
                                       else '')) for n in nodes])
            if to and self.confirm('Move the VIP address', 'The VIP address moves to %s; '
                                   'the pages are away for a few seconds.' % to, 'Move it'):
                self.act('--vip-move', to)
                self.vip_now = self.st_now = True

        def sure(flag, title, words):
            def go():
                if self.confirm(title, words, title):
                    self.act(flag)
            return go
        def trials():
            st = self.out('--status') or {}
            got = st.get('trials') or []
            if not got:
                self.note('Changes on trial', 'Nothing waits to be kept.')
                return
            t = self.choose('Changes on trial', [
                (i, '%s - %d min left' % ('the new network of %s' % x['node']
                                          if x['kind'] == 'net' else 'the firewall and access',
                                          max(0, int((x['until'] - time.time()) // 60))))
                for i, x in enumerate(got)], 'Not kept in time, each goes back by itself.')
            if t is None:
                return
            x = got[t]
            act = self.choose('What to do', [('keep', 'Keep it'),
                                             ('back', 'Put the old back now')])
            if act == 'back' and not self.confirm('Put the old back', (
                    '%s goes back to its old network and restarts.' % x['node'])
                    if x['kind'] == 'net' else 'The firewall goes back to what it was.',
                    'Put it back', danger=True):
                return
            if act:
                self.act('--change-keep' if act == 'keep' else '--change-back', x['kind'],
                         *(['--node', x['node']] if x.get('node') else []))
                self.st_now = True
        return self.sub('Cluster, VIP address and maintenance', [
            ('0', 'Keep or put back a change on trial (network, firewall)', trials),
            ('1', 'The cluster', lambda: self.act('--ha-status')),
            ('2', 'The VIP address, certificates, firewall', lambda: self.act('--web-status')),
            ('3', 'Maintenance of this node', maint),
            ('4', 'Move the VIP address to a node', vip_move),
            ('5', 'Pause replication', sure('--ha-pause', 'Pause replication',
                                            'The nodes stop copying each other\'s changes until '
                                            'it is resumed.')),
            ('6', 'Resume replication', lambda: self.act('--ha-resume')),
            ('7', 'Compare the two databases', lambda: self.act('--ha-compare')),
        ])

    # ---- settings on the text screen: arrows, Enter, a window to change one (1.0.134)
    PANE_TITLES = [('codes', 'Codes by e-mail and SMS'), ('portal', 'The enrolment pages'),
                   ('mail', 'Mail'), ('people', 'Accounts'), ('hisec', 'High security'),
                   ('acme', 'Automatic certificates'), ('fw', 'Firewall and access'),
                   ('network', 'Network'), ('proxy', 'Proxy'), ('ha', 'High availability'),
                   ('power', 'Restart and power off'), ('logs', 'Disks and logs'),
                   ('db', 'The database'), ('backup', 'Backups'),
                   ('alerts', 'Alerts and reports'), ('monitor', 'Monitoring'),
                   ('isemon', 'isemon'), ('siem', 'Syslog and SIEM'),
                   ('osup', 'System updates'), ('upgrade', 'Upgrades'),
                   ('about', 'About and debugging')]

    def _settings_rows(self):
        got = self.out('--settings') or []
        rows = got.get('settings') if isinstance(got, dict) else got
        by = {r['key']: r for r in rows or [] if isinstance(r, dict) and r.get('key')}
        out, seen = [], set()
        for pane, words in self.PANE_TITLES:
            keys = [k for k in PANES.get(pane, []) if k in by]
            if not keys:
                continue
            out.append(('head', words))
            for k in keys:
                out.append(('set', by[k]))
                seen.add(k)
        rest = [k for k in by if k not in seen]
        if rest:
            out.append(('head', 'Everything else'))
            out += [('set', by[k]) for k in rest]
        return out

    @staticmethod
    def _shown(v):
        if v is True:
            return 'on'
        if v is False:
            return 'off'
        return '' if v is None else str(v)

    def _kind(self, key):
        shape = TUNABLE.get(key)
        d = DEFAULTS.get(key)
        if isinstance(d, bool) or shape == (0, 1):
            return 'switch', ['1', '0']
        if isinstance(shape, tuple) and shape and isinstance(shape[0], str):
            return 'choice', [str(x) for x in shape]
        if isinstance(shape, tuple) and len(shape) == 2:
            return 'number', list(shape)
        return 'text', None

    def settings_tui(self):
        c, A = self.curses, self.A
        rows = self._settings_rows()
        if not rows:
            return None
        sel = next(i for i, r in enumerate(rows) if r[0] == 'set')
        top, said, said_bad, find = 0, '', False, ''
        while True:
            if self.plain:
                c.reset_prog_mode()
                self.scr.clear()
                self.plain = False

            def paint():
                nonlocal top
                h, w = self.scr.getmaxyx()
                self.scr.erase()
                self._put(0, 0, ' ' * w, A['head'])
                self._put(0, 0, ' acme %s  Settings' % __version__, A['head'] | c.A_BOLD)
                if find:
                    self._put(0, max(0, w - len(find) - 12), ' find: %s ' % find, A['head'])
                avail = max(3, h - 3)
                if sel < top:
                    top = sel
                if sel >= top + avail:
                    top = sel - avail + 1
                top = max(0, min(top, max(0, len(rows) - avail)))
                if top > 0 and rows[top - 1][0] == 'head' and sel - top < avail - 1:
                    top -= 1                    # the group's heading with its first setting
                namew = max(20, min(44, w // 3))
                valw = max(10, min(40, w - namew - 30))
                for n, r in enumerate(rows[top:top + avail]):
                    y = 1 + n
                    if r[0] == 'head':
                        self._put(y, 1, r[1].upper(), A['key'])
                        continue
                    st = r[1]
                    val = self._shown(st.get('value'))
                    line = '  %-*s %-*s %s' % (namew, (st.get('name') or st['key'])[:namew], valw,
                                              val[:valw], st.get('key'))
                    if top + n == sel:
                        self._put(y, 0, line + ' ' * max(0, w - 2 - len(line)), A['sel'])
                    else:
                        self._put(y, 0, '  ' + (st.get('name') or st['key'])[:namew])
                        tone = A['dim'] if st.get('source') == 'default' else A['ok']
                        self._put(y, 3 + namew, val[:valw], tone)
                        self._put(y, 4 + namew + valw, st.get('key'), A['dim'])
                # The bar on the right.
                total = len(rows)
                if total > avail:
                    thumb = max(1, min(avail, round(avail * avail / total)))
                    tstart = max(0, min(avail - thumb, round((avail - thumb) * top
                                                              / max(1, total - avail))))
                    utf = 'utf' in (sys.stdout.encoding or '').lower()
                    for r in range(avail):
                        hit = tstart <= r < tstart + thumb
                        self._put(1 + r, w - 1, ('\u2588' if hit else '\u2502') if utf
                                  else ('#' if hit else '|'), A['key'] if hit else A['dim'])
                if said:
                    self._put(h - 2, 1, said[:w - 2], A['bad'] if said_bad else A['ok'])
                help_ = ' Up/Down PgUp/PgDn Home/End move   Enter change   / find   Esc back '
                self._put(h - 1, 0, ' ' * (w - 1), A['head'])
                self._put(h - 1, 0, help_[:w - 1], A['head'])
                self.scr.noutrefresh()
                return h, avail
            self.backdrop = paint
            h, avail = paint()
            c.doupdate()
            self.scr.timeout(500)
            k = self._getkey()
            if k is None:
                continue
            said = ''
            sets = [i for i, r in enumerate(rows) if r[0] == 'set']
            if k == 'esc':
                if find:
                    find = ''
                    continue
                return None
            if k == 'q':
                return 'quit'
            if k in ('up', 'down', 'pgup', 'pgdn', 'home', 'end'):
                pos = sets.index(sel) if sel in sets else 0
                pos = {'up': pos - 1, 'down': pos + 1, 'pgup': pos - (avail - 2),
                       'pgdn': pos + (avail - 2), 'home': 0, 'end': len(sets) - 1}[k]
                sel = sets[max(0, min(len(sets) - 1, pos))]
            elif k == '/':
                find = self._line_in(h - 2, 'Find (a word of its name or key): ', '') or ''
                if find:
                    hit = [i for i in sets if find.lower() in (
                        str(rows[i][1].get('name')) + ' ' + rows[i][1]['key']).lower()]
                    if hit:
                        sel = hit[0]
                    else:
                        said, said_bad = 'nothing with "%s"' % find, True
            elif k == 'n' and find:
                hit = [i for i in sets if i > sel and find.lower() in (
                    str(rows[i][1].get('name')) + ' ' + rows[i][1]['key']).lower()]
                if hit:
                    sel = hit[0]
            elif k == 'enter':
                done = self._edit_one(rows[sel][1])
                if done:
                    said, said_bad = done
                    if not said_bad:
                        cur = rows[sel][1]['key']
                        rows = self._settings_rows()
                        sel = next((i for i, r in enumerate(rows)
                                    if r[0] == 'set' and r[1]['key'] == cur), sel)

    def _getkey(self, win=None):
        """A key on the text screen, by name: 'up', 'enter', 'esc', or the character."""
        c = self.curses
        src = win or self.scr
        k = src.getch()
        if k == -1:
            # The window's size looked at, as the menus do.
            try:
                size = os.get_terminal_size(sys.__stdout__.fileno())
                if (size.lines, size.columns) != self.scr.getmaxyx():
                    c.resizeterm(size.lines, size.columns)
                    self.scr.clear()
                    return 'resize'
            except (OSError, ValueError, c.error):
                pass
            return None
        if k == 27:
            src.nodelay(True)
            k2 = src.getch()
            if k2 in (ord('['), ord('O')):
                seq = ''
                while True:
                    k3 = src.getch()
                    if k3 == -1:
                        break
                    seq += chr(k3)
                    if chr(k3).isalpha() or chr(k3) == '~':
                        break
                src.nodelay(False)
                return {'A': 'up', 'B': 'down', 'C': 'right', 'D': 'left', 'H': 'home',
                        'F': 'end', '5~': 'pgup', '6~': 'pgdn', '1~': 'home', '4~': 'end',
                        '7~': 'home', '8~': 'end', '3~': 'del'}.get(seq, None)
            if k2 != -1:
                c.ungetch(k2)
            src.nodelay(False)
            return 'esc'
        named = {c.KEY_UP: 'up', c.KEY_DOWN: 'down', c.KEY_LEFT: 'left', c.KEY_RIGHT: 'right',
                 c.KEY_PPAGE: 'pgup', c.KEY_NPAGE: 'pgdn', c.KEY_HOME: 'home', c.KEY_END: 'end',
                 c.KEY_ENTER: 'enter', 10: 'enter', 13: 'enter', c.KEY_BACKSPACE: 'bs',
                 127: 'bs', 8: 'bs', c.KEY_DC: 'del', c.KEY_RESIZE: 'resize', 21: 'ctrl-u',
                 9: 'tab'}
        if k in named:
            if k == c.KEY_RESIZE:
                try:
                    c.update_lines_cols()
                except Exception:                       # noqa: BLE001
                    pass
            return named[k]
        if 0xc0 <= k < 0xf8:
            # getch() gives UTF-8 a byte at a time (1.0.139): "ž" came as two
            # Latin-1 letters, and a password typed here was not the one meant.
            raw = bytearray([k])
            src.nodelay(True)
            try:
                for _ in range(1 if k < 0xe0 else 2 if k < 0xf0 else 3):
                    k2 = src.getch()
                    if not 0x80 <= k2 < 0xc0:
                        break
                    raw.append(k2)
            finally:
                src.nodelay(False)
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return None
        if 32 <= k < 0x110000:
            try:
                return chr(k)
            except ValueError:
                return None
        return None

    def _line_in(self, y, prompt, text, secret=False, win=None, x=1, width=None):
        """A line typed on the text screen: Enter gives it, Esc gives None."""
        c = self.curses
        scr = win or self.scr
        pos = len(text)
        try:
            c.curs_set(1)
        except Exception:                               # noqa: BLE001
            pass
        try:
            while True:
                h, w = scr.getmaxyx()
                room = (width or (w - x - len(prompt) - 2))
                shown = ('*' * len(text)) if secret else text
                start = max(0, pos - room + 1)
                try:
                    scr.addstr(y, x, prompt, self.A['key'])
                    scr.addstr(y, x + len(prompt), shown[start:start + room].ljust(room),
                               self.curses.A_UNDERLINE)
                    scr.move(y, x + len(prompt) + pos - start)
                except c.error:
                    pass
                scr.refresh()
                scr.timeout(500)
                k = self._getkey(scr)
                if k == 'enter':
                    return text
                if k == 'esc':
                    return None
                if k == 'bs' and pos > 0:
                    text = text[:pos - 1] + text[pos:]
                    pos -= 1
                elif k == 'del':
                    text = text[:pos] + text[pos + 1:]
                elif k == 'left':
                    pos = max(0, pos - 1)
                elif k == 'right':
                    pos = min(len(text), pos + 1)
                elif k == 'home':
                    pos = 0
                elif k == 'end':
                    pos = len(text)
                elif k == 'ctrl-u':
                    text, pos = '', 0
                elif k and len(k) == 1 and k.isprintable():
                    text = text[:pos] + k + text[pos:]
                    pos += 1
        finally:
            try:
                c.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass

    def _box(self, win, h, w):
        """A frame round a window, in UTF-8 lines where the terminal takes them."""
        c, A = self.curses, self.A
        if 'utf' in (sys.stdout.encoding or '').lower():
            hz, vt, tl, tr, bl, br = '\u2500', '\u2502', '\u250c', '\u2510', '\u2514', '\u2518'
        else:
            hz, vt, tl, tr, bl, br = '-', '|', '+', '+', '+', '+'
        for y, line in ((0, tl + hz * (w - 2) + tr), (h - 1, bl + hz * (w - 2) + br)):
            try:
                win.addstr(y, 0, line, A['key'])
            except c.error:
                pass                                    # the bottom-right corner
        for y in range(1, h - 1):
            for x in (0, w - 1):
                try:
                    win.addstr(y, x, vt, A['key'])
                except c.error:
                    pass

    def _edit_one(self, st):
        """The window to change one setting: what it is, what it may be, the
        value checked as the daemon checks it before it is saved. Returns
        (words, bad) or None when nothing was done."""
        c, A = self.curses, self.A
        key = st['key']
        if key.startswith(('db_', 'ha_')):
            # Their own steps (1.0.136), as on the pages: a database named
            # here opens empty at the next restart, a cluster is made whole.
            self.note(st.get('name') or key, (
                '%s is changed by the cluster\'s own steps: Settings - High availability on '
                'the pages, or acme --ha-setup / --ha-join / --ha-standalone.' % key)
                if key.startswith('ha_') else (
                '%s names the database: it is moved on the pages (Settings - The database - '
                'Move to another database) or with acme --db-move ENGINE. Only to point at '
                'the same data somewhere new (a moved server, a new password), on the command '
                'line:  acme --set %s=%s --yes' % (key, key, '-' if key in SECRET_KEYS else '...')))
            return None
        kind, shape = self._kind(key)
        secret = bool(st.get('secret'))
        cur = self._shown(st.get('value'))
        if kind == 'switch':
            cur = '1' if st.get('value') in (True, 1, '1', 'on') else '0'
        text = '' if secret else cur
        choice = shape.index(cur) if kind in ('switch', 'choice') and cur in (shape or []) else 0
        err = ''
        helptext = re.sub(r'<[^>]+>', '', html.unescape(str(st.get('says') or '')))
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(40, min(96, w - 4))
            body = []
            for para in helptext.split('\n'):
                body += textwrap.wrap(para, ww - 4) or ['']
            # A secret as the pages show it to a full administrator: dots and its last two.
            facts = ['now: %s%s' % ((self._shown(st.get('value')) or '(not set)') if secret else
                                    (self._shown(st.get('value')) or '(empty)'),
                                    '' if st.get('source') == 'default' else
                                    '   - %s' % (st.get('source_says') or st.get('source'))),
                     'as it comes: %s' % (self._shown(st.get('default')) or '(empty)')]
            if kind == 'number':
                facts.append('a whole number from %s to %s' % (shape[0], shape[1]))
            elif kind == 'choice':
                facts.append('one of: ' + ', '.join(shape))
            if st.get('file_only'):
                facts.append('kept in config.json on this machine - it takes effect after a restart')
            if st.get('node_key'):
                facts.append('this node\'s own (each node of a cluster has its own)')
            # The help cut to what the screen has room for - the rest always fits.
            fixed = len(facts) + 9 + (len(shape) - 1 if kind == 'choice' else 0)
            body = body[:max(1, h - 2 - fixed)]
            wh = min(h - 2, len(body) + fixed)
            win = c.newwin(wh, ww, max(0, (h - wh) // 2), max(0, (w - ww) // 2))
            win.keypad(True)
            win.erase()
            self._box(win, wh, ww)
            title = ' %s ' % (st.get('name') or key)
            try:
                win.addnstr(0, 2, title, ww - 4, A['title'])
                win.addnstr(1, 2, key, ww - 4, A['dim'])
                y = 2
                for ln in body:
                    win.addnstr(y, 2, ln, ww - 4)
                    y += 1
                y += 1
                for f in facts:
                    win.addnstr(y, 2, f, ww - 4, A['dim'])
                    y += 1
                y += 1
                if err:
                    win.addnstr(wh - 2, 2, err[:ww - 4], ww - 4, A['bad'])
                else:
                    win.addnstr(wh - 2, 2, ('Left/Right choose' if kind in ('switch', 'choice')
                                            else 'type the new value') +
                                '   Enter save   Esc cancel', ww - 4, A['dim'])
            except c.error:
                pass
            if kind in ('switch', 'choice'):
                words = {'1': 'on', '0': 'off'} if kind == 'switch' else {}
                x = 2
                for i, opt in enumerate(shape):
                    lab = ' %s ' % (words.get(opt) or (CHOICE_WORDS.get(key, {}).get(opt) or opt))
                    if kind == 'choice':
                        # One under the other: their words can be long.
                        lab = (' > ' if i == choice else '   ') + lab.strip() + ' '
                        try:
                            win.addnstr(y, 2, lab, ww - 4, A['sel'] if i == choice else 0)
                        except c.error:
                            pass
                        y += 1
                        continue
                    try:
                        win.addnstr(y, x, lab, max(0, ww - x - 2), A['sel'] if i == choice else 0)
                    except c.error:
                        pass
                    x += len(lab) + 1
                win.noutrefresh()
                c.doupdate()
                win.timeout(500)
                k = self._getkey(win)
                if k == 'esc':
                    return None
                if k in ('left', 'up'):
                    choice = (choice - 1) % len(shape)
                elif k in ('right', 'down', 'tab', ' '):
                    choice = (choice + 1) % len(shape)
                elif k == 'enter':
                    value = shape[choice]
                else:
                    continue
                if k != 'enter':
                    continue
            else:
                win.noutrefresh()
                c.doupdate()
                got = self._line_in(y, 'value: ', text, secret=secret, win=win, x=2,
                                    width=ww - 14)
                if got is None:
                    return None
                text = got
                if secret and not got:
                    return ('nothing typed - %s stays as it was' % key, False)
                value = got
            # Checked here as the daemon checks it, then saved by `acme --set`.
            try:
                check_setting(key, value)
            except (BadSetting, ValueError, TypeError) as e:
                err = str(e)
                continue
            # A secret goes by the environment, not the command line (1.0.136).
            env = {'ACME_VALUE_' + key.upper(): value} if secret else None
            out, rc = self.capture(acme_argv(self.me) + ['--set', '%s=%s' % (
                key, '@env' if secret else value), '--no-color'], env=env)
            if rc != 0:
                err = (out.strip().splitlines() or ['it was not saved'])[-1]
                continue
            return ('%s = %s - saved%s' % (key, secret_shown(value) if secret else value,
                                           '; the running service takes it within seconds'
                                           if not st.get('file_only') else
                                           '; restart the service for it'), False)

    # ---- windows on the text screen for every menu: arrows and Enter (1.0.135) ----
    # Nothing is typed at a bare prompt any more: a question is a window (a
    # form) whose fields are moved between by the arrows, a choice is picked
    # by the arrows, a list (accounts, directories, files…) is scrolled and
    # Enter on one offers what can be done with it. What is typed is checked
    # before anything is run; Esc closes the window and goes back. The screen
    # under a window is drawn again by `self.backdrop` - so a window made
    # bigger or smaller (PuTTY's too) is drawn right.
    def _fresh(self):
        """Back from a command's own screen: the text screen drawn whole again."""
        if self.plain:
            self.curses.reset_prog_mode()
            self.scr.clear()
            self.plain = False
            self.st_now = True

    def _under(self):
        """The screen under a window, written but not yet shown."""
        self._fresh()
        fn = getattr(self, 'backdrop', None)
        if fn:
            try:
                fn()
                return
            except Exception:                           # noqa: BLE001
                pass
        self.scr.noutrefresh()

    def _window(self, want_h, want_w):
        """A framed window in the middle of the screen; (win, h, w)."""
        c = self.curses
        h, w = self.scr.getmaxyx()
        ww = max(20, min(want_w, w - 2))
        wh = max(5, min(want_h, h - 2))
        win = c.newwin(wh, ww, max(0, (h - wh) // 2), max(0, (w - ww) // 2))
        win.keypad(True)
        win.erase()
        self._box(win, wh, ww)
        return win, wh, ww

    def _wput(self, win, y, x, text, attr=0, width=None):
        try:
            wh, ww = win.getmaxyx()
            if 0 < y < wh - 1 and x < ww - 1:
                win.addnstr(y, x, str(text), max(0, (width or ww) - (x if width is None else 0)
                                                 - (1 if width is None else 0)), attr)
        except self.curses.error:
            pass

    def _wkey(self, win, wait=500):
        win.timeout(wait)
        return self._getkey(win)

    def _wrap(self, text, width):
        out = []
        for para in str(text or '').split('\n'):
            out += textwrap.wrap(para, max(10, width)) or ['']
        return out

    @staticmethod
    def _plain_text(text):
        return re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', str(text or ''))

    def note(self, title, text, tone=''):
        """Words in a window; any of Enter, Esc, q or Space closes it."""
        A = self.A
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(30, min(100, w - 4))
            lines = self._wrap(text, ww - 4)[:max(1, h - 6)]
            win, wh, ww = self._window(len(lines) + 4, max(len(title) + 8, min(
                ww, max(len(x) for x in lines + ['']) + 6, ww)))
            self._wput(win, 0, 2, ' %s ' % title, A['title'])
            try:
                win.addnstr(0, 2, ' %s ' % title, ww - 4, A['title'])
            except self.curses.error:
                pass
            for i, ln in enumerate(lines):
                self._wput(win, 1 + i, 2, ln, A.get(tone, 0) if tone else 0)
            self._wput(win, wh - 2, 2, 'Enter or Esc - back', A['dim'])
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ('enter', 'esc', 'q', ' '):
                return

    def working(self, words):
        """A window that says something is being done (the screen waits for it)."""
        self._under()
        win, wh, ww = self._window(3, min(100, len(words) + 6))
        self._wput(win, 1, 2, words, self.A['dim'])
        win.noutrefresh()
        self.curses.doupdate()

    def confirm(self, title, words, yes='Yes', no='No', danger=False):
        """Yes or no, chosen by the arrows (or y / n); No unless chosen."""
        A = self.A
        pick = 1
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = max(40, min(80, w - 4))
            lines = self._wrap(words, ww - 4)[:max(1, h - 8)]
            win, wh, ww = self._window(len(lines) + 5, ww)
            try:
                win.addnstr(0, 2, ' %s ' % title, ww - 4, A['bad'] if danger else A['title'])
            except self.curses.error:
                pass
            for i, ln in enumerate(lines):
                self._wput(win, 1 + i, 2, ln)
            x = 2
            y = wh - 2
            for i, lab in enumerate((yes, no)):
                lab = '  %s  ' % lab
                self._wput(win, y, x, lab, (A['bad'] if danger and i == 0 else A['sel'])
                           if i == pick else A['key'])
                x += len(lab) + 2
            self._wput(win, y, x + 2, 'Left/Right  Enter  Esc', A['dim'])
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ('esc', 'n', 'N'):
                return False
            if k in ('y', 'Y'):
                return True
            if k in ('left', 'right', 'tab', 'up', 'down'):
                pick = 1 - pick
            elif k == 'enter':
                return pick == 0

    def choose(self, title, options, words='', cur=0):
        """One of `options` ([(value, words)]), picked by the arrows; Esc None."""
        A = self.A
        if not options:
            return None
        sel = max(0, min(cur or 0, len(options) - 1))
        top = 0
        typed, typed_at = '', 0.0
        while True:
            self._under()
            h, w = self.scr.getmaxyx()
            ww = min(90, w - 4, max(36, max(len(o[1]) for o in options) + 12,
                                    len(title) + 8, len(words) + 6 if words else 0))
            head = self._wrap(words, ww - 4) if words else []
            room = max(1, min(len(options), h - 6 - len(head)))
            win, wh, ww = self._window(room + len(head) + (4 if head else 3), ww)
            try:
                win.addnstr(0, 2, ' %s ' % title, ww - 4, A['title'])
            except self.curses.error:
                pass
            y = 1
            for ln in head:
                self._wput(win, y, 2, ln, A['dim'])
                y += 1
            if head:
                y += 1
            if sel < top:
                top = sel
            if sel >= top + room:
                top = sel - room + 1
            for n, (val, lab) in enumerate(options[top:top + room]):
                i = top + n
                line = ' %2d  %s' % (i + 1, lab)
                if i == sel:
                    self._wput(win, y + n, 2, line.ljust(ww - 5), A['sel'])
                else:
                    self._wput(win, y + n, 2, ' %2d' % (i + 1), A['key'])
                    self._wput(win, y + n, 7, lab)
            if len(options) > room:
                self._wbar(win, y, room, len(options), top, ww - 2)
            win.noutrefresh()
            self.curses.doupdate()
            k = self._wkey(win)
            if k in ('esc', 'left'):
                return None
            if k == 'q':
                return None
            if k == 'up':
                sel = (sel - 1) % len(options)
            elif k in ('down', 'tab'):
                sel = (sel + 1) % len(options)
            elif k in ('home', 'pgup'):
                sel = 0
            elif k in ('end', 'pgdn'):
                sel = len(options) - 1
            elif k and k.isdigit():
                # A number typed as in the menus (1.0.206): taken at once only when
                # no longer one can grow from it - "12" of a list of twelve picked
                # the first ("all") on its 1, and cleared every lockout.
                now = time.time()
                typed = (typed if now - typed_at < 1.0 else '') + k
                typed_at = now
                n = int(typed) - 1
                if 0 <= n < len(options):
                    sel = n
                    if not any(str(i + 1).startswith(typed) and str(i + 1) != typed
                               for i in range(len(options))):
                        return options[sel][0]
                else:
                    typed = ''
            elif k in ('enter', 'right'):
                return options[sel][0]

    def _wbar(self, win, y0, rows, total, top, x):
        """The scroll bar on the right of a list in a window."""
        A = self.A
        if total <= rows:
            return
        thumb = max(1, min(rows, round(rows * rows / total)))
        tstart = max(0, min(rows - thumb, round((rows - thumb) * top / max(1, total - rows))))
        utf = 'utf' in (sys.stdout.encoding or '').lower()
        for r in range(rows):
            hit = tstart <= r < tstart + thumb
            try:
                win.addstr(y0 + r, x, ('█' if hit else '│') if utf else
                           ('#' if hit else '|'), A['key'] if hit else A['dim'])
            except self.curses.error:
                pass

    def form(self, title, fields, words='', check=None, ok='OK'):
        """Questions in one window. fields: [{'key', 'label', 'kind': 'text' |
        'secret' | 'choice' | 'number', 'value', 'options': [(value, words)],
        'need': True, 'range': (a, b), 'help', 'check': fn(value, values) ->
        an error or None, 'when': fn(values) -> shown or not}]. Up/Down (Tab)
        move between them, a choice is changed by Left/Right, Enter checks
        them all and gives {key: value}; Esc gives None. A secret shows a star
        for each character, never the characters."""
        c, A = self.curses, self.A
        vals, pos = {}, {}
        for f in fields:
            f.setdefault('kind', 'text')
            if f['kind'] == 'choice':
                opts = [o[0] for o in f['options']]
                vals[f['key']] = f.get('value') if f.get('value') in opts else opts[0]
            else:
                vals[f['key']] = str(f.get('value') if f.get('value') is not None else '')
            pos[f['key']] = len(vals[f['key']]) if f['kind'] != 'choice' else 0
        at, err, err_at = 0, '', None
        try:
            c.curs_set(1)
        except Exception:                               # noqa: BLE001
            pass
        try:
            while True:
                shown = [f for f in fields if not f.get('when') or f['when'](vals)]
                at = max(0, min(at, len(shown) - 1))
                f = shown[at]
                self._under()
                h, w = self.scr.getmaxyx()
                ww = max(50, min(100, w - 4))
                head = self._wrap(words, ww - 4) if words else []
                labw = min(30, max(len(x.get('label') or x['key']) for x in shown) + 1)
                fieldw = max(8, ww - labw - 7)
                helps = self._wrap(f.get('help') or '', ww - 4) if f.get('help') else []
                helps = helps[:4]
                wh = len(head) + (1 if head else 0) + len(shown) + 2 + 4 + 1
                win, wh, ww = self._window(wh, ww)
                try:
                    win.addnstr(0, 2, ' %s ' % title, ww - 4, A['title'])
                except c.error:
                    pass
                y = 1
                for ln in head:
                    self._wput(win, y, 2, ln, A['dim'])
                    y += 1
                if head:
                    y += 1
                cursor = None
                for i, x in enumerate(shown):
                    lab = (x.get('label') or x['key'])[:labw - 1]
                    here = i == at
                    self._wput(win, y, 2, lab.rjust(labw), A['key'] if here else 0)
                    vx = 3 + labw + 1
                    v = vals[x['key']]
                    if x['kind'] == 'choice':
                        words_ = dict(x['options']).get(v, v)
                        txt = ('< %s >' % words_) if here else ('  %s' % words_)
                        self._wput(win, y, vx, txt[:fieldw], A['sel'] if here else A['ok'])
                    else:
                        t = ('*' * len(v)) if x['kind'] == 'secret' else v
                        p = pos[x['key']] if here else len(t)
                        start = max(0, p - fieldw + 1)
                        self._wput(win, y, vx, t[start:start + fieldw].ljust(fieldw),
                                   c.A_UNDERLINE | (A['key'] if here else 0))
                        if here:
                            cursor = (y, vx + p - start)
                    if err and err_at == x['key']:
                        self._wput(win, y, ww - 3, '!', A['bad'])
                    y += 1
                y += 1
                for ln in helps:
                    self._wput(win, y, 2, ln, A['dim'])
                    y += 1
                if err:
                    self._wput(win, wh - 2, 2, err[:ww - 4], A['bad'])
                else:
                    self._wput(win, wh - 2, 2, ('Up/Down field   ' + ('Left/Right choose   '
                               if any(x['kind'] == 'choice' for x in shown) else '') +
                               'Enter %s   Esc cancel' % ok)[:ww - 4], A['dim'])
                if cursor:
                    try:
                        c.curs_set(1)
                        win.move(*cursor)
                    except c.error:
                        pass
                else:
                    try:
                        c.curs_set(0)
                    except Exception:                   # noqa: BLE001
                        pass
                win.noutrefresh()
                c.doupdate()
                k = self._wkey(win)
                if k is None or k == 'resize':
                    continue
                key, kind = f['key'], f['kind']
                if k == 'esc':
                    return None
                if k in ('up',) or (k == 'tab' and False):
                    at = (at - 1) % len(shown)
                elif k in ('down', 'tab'):
                    at = (at + 1) % len(shown)
                elif k == 'enter':
                    err, err_at = '', None
                    for i, x in enumerate(shown):
                        v = vals[x['key']]
                        if x['kind'] != 'choice':
                            v = v.strip() if x['kind'] != 'secret' else v
                            vals[x['key']] = v
                        bad = None
                        if x.get('need') and v == '':
                            bad = '%s - it is needed' % (x.get('label') or x['key'])
                        elif x['kind'] == 'number' and v != '':
                            try:
                                n = int(v)
                                lo, hi = x.get('range') or (None, None)
                                if (lo is not None and n < lo) or (hi is not None and n > hi):
                                    bad = '%s - a whole number from %s to %s' % (
                                        x.get('label') or x['key'], lo, hi)
                            except ValueError:
                                bad = '%s - a whole number' % (x.get('label') or x['key'])
                        if not bad and x.get('check') and v != '':
                            try:
                                bad = x['check'](v, vals)
                            except Exception as e:              # noqa: BLE001
                                bad = str(e)
                        if bad:
                            err, err_at, at = bad, x['key'], i
                            break
                    if err:
                        continue
                    got = {x['key']: vals[x['key']] for x in shown}
                    if check:
                        bad = check(got)
                        if bad:
                            err, err_at = (bad if isinstance(bad, tuple) else (bad, None))
                            if err_at:
                                at = next((i for i, x in enumerate(shown) if x['key'] == err_at),
                                          at)
                            continue
                    return got
                elif kind == 'choice':
                    opts = [o[0] for o in f['options']]
                    i = opts.index(vals[key]) if vals[key] in opts else 0
                    if k in ('left',):
                        vals[key] = opts[(i - 1) % len(opts)]
                    elif k in ('right', ' '):
                        vals[key] = opts[(i + 1) % len(opts)]
                    err = ''
                else:
                    t, p = vals[key], pos[key]
                    if k == 'bs' and p > 0:
                        t, p = t[:p - 1] + t[p:], p - 1
                    elif k == 'del':
                        t = t[:p] + t[p + 1:]
                    elif k == 'left':
                        p = max(0, p - 1)
                    elif k == 'right':
                        p = min(len(t), p + 1)
                    elif k == 'home':
                        p = 0
                    elif k == 'end':
                        p = len(t)
                    elif k == 'ctrl-u':
                        t, p = '', 0
                    elif k and len(k) == 1 and k.isprintable():
                        if kind == 'number' and not (k.isdigit() or (k == '-' and p == 0)):
                            continue
                        t, p = t[:p] + k + t[p:], p + 1
                    else:
                        continue
                    vals[key], pos[key] = t, p
                    if err_at == key:
                        err, err_at = '', None
        finally:
            try:
                c.curs_set(0)
            except Exception:                           # noqa: BLE001
                pass

    def ask_one(self, title, label, value='', help_='', need=True, secret=False, check=None):
        """One question in a window; its answer, or None (Esc)."""
        got = self.form(title, [{'key': 'v', 'label': label, 'value': value, 'help': help_,
                                 'need': need, 'kind': 'secret' if secret else 'text',
                                 'check': check}])
        return None if got is None else got['v']

    def pick(self, title, load, cols, act=None, empty='nothing here', words=''):
        """A list to scroll with the arrows: `load()` gives its rows (asked
        again after something was done to one), `cols` [(heading, fn(row),
        width, tone fn(row) or None)]. Enter calls `act(row)`; / finds. Esc
        back, q leaves the console."""
        c, A = self.curses, self.A
        rows = load() or []
        sel, top, find, said, said_bad = 0, 0, '', '', False
        while True:
            self._fresh()
            h, w = self.scr.getmaxyx()
            seen = [r for r in rows if not find or find.lower() in ' '.join(
                str(fn(r)) for _h, fn, _w, _t in cols).lower()]
            sel = max(0, min(sel, len(seen) - 1))
            avail = max(3, h - 5 - (1 if words else 0))
            if sel < top:
                top = sel
            if sel >= top + avail:
                top = sel - avail + 1
            top = max(0, min(top, max(0, len(seen) - avail)))
            # Widths: as given; the last one takes what is left.
            ws = [cw for _h, _f, cw, _t in cols]
            fixed = sum(x + 2 for x in ws[:-1])
            ws[-1] = max(8, min(ws[-1] or 200, w - 4 - fixed))

            def paint(_title=title, _seen=seen, _top=top, _sel=sel, _ws=ws, _avail=avail):
                self.scr.erase()
                self._put(0, 0, ' ' * w, A['head'])
                self._put(0, 0, ' acme %s  %s ' % (__version__, _title), A['head'] | c.A_BOLD)
                right = ' %d%s ' % (len(_seen), (' of %d, with "%s"' % (len(rows), find))
                                    if find else '')
                self._put(0, max(0, w - len(right) - 1), right, A['head'])
                y = 1
                if words:
                    self._put(y, 1, words[:w - 2], A['dim'])
                    y += 1
                x = 2
                for (hd, _f, _w, _t), cw in zip(cols, _ws):
                    self._put(y + 1, x, hd[:cw], A['key'])
                    x += cw + 2
                y += 2
                if not _seen:
                    self._put(y + 1, 4, empty if not find else 'nothing with "%s"' % find,
                              A['dim'])
                for n, r in enumerate(_seen[_top:_top + _avail]):
                    i = _top + n
                    x = 2
                    if i == _sel:
                        self._put(y + n, 1, ' ' * (w - 3), A['sel'])
                    for (hd, fn, _w, tone), cw in zip(cols, _ws):
                        try:
                            v = str(fn(r))
                        except Exception:               # noqa: BLE001
                            v = '?'
                        attr = A['sel'] if i == _sel else (A.get(tone(r) or '', 0) if tone else 0)
                        self._put(y + n, x, v[:cw], attr)
                        x += cw + 2
                if len(_seen) > _avail:
                    thumb = max(1, min(_avail, round(_avail * _avail / len(_seen))))
                    ts = max(0, min(_avail - thumb, round((_avail - thumb) * _top
                                                          / max(1, len(_seen) - _avail))))
                    utf = 'utf' in (sys.stdout.encoding or '').lower()
                    for r_ in range(_avail):
                        hit = ts <= r_ < ts + thumb
                        self._put(y + r_, w - 1, ('█' if hit else '│') if utf
                                  else ('#' if hit else '|'), A['key'] if hit else A['dim'])
                if said:
                    self._put(h - 2, 1, said[:w - 2], A['bad'] if said_bad else A['ok'])
                help_ = ' Up/Down PgUp/PgDn Home/End move   Enter %s   / find   Esc back ' % (
                    'what to do with it' if act else 'look')
                self._put(h - 1, 0, ' ' * (w - 1), A['head'])
                self._put(h - 1, 0, help_[:w - 1], A['head'])
                self.scr.noutrefresh()
            self.backdrop = paint
            paint()
            c.doupdate()
            self.scr.timeout(500)
            k = self._getkey()
            if k is None:
                continue
            said = ''
            if k == 'esc':
                if find:
                    find = ''
                    continue
                return None
            if k == 'q':
                return 'quit'
            if k in ('up', 'down', 'pgup', 'pgdn', 'home', 'end'):
                sel = {'up': sel - 1, 'down': sel + 1, 'pgup': sel - (avail - 1),
                       'pgdn': sel + (avail - 1), 'home': 0, 'end': len(seen) - 1}[k]
            elif k == '/':
                got = self.ask_one('Find', 'with the words', find, need=False,
                                   help_='Only the rows with these words in them stay; '
                                         'Esc in the list shows them all again.')
                if got is not None:
                    find, sel, top = got, 0, 0
            elif k in ('enter', 'right') and seen and act:
                r = act(seen[sel])
                if r == 'quit':
                    return 'quit'
                if isinstance(r, tuple):
                    said, said_bad = r
                rows = load() or []

    def act(self, *args, env=None, title=None, quiet_ok=None):
        """`acme ARGS` run: a short answer in a window, a long one on a screen
        of its own to scroll. Returns the exit code."""
        argv = acme_argv(self.me) + [str(a) for a in args]
        shown = '$ acme ' + ' '.join(self._quote(a) for a in args)
        return self.act_argv(argv, title or shown, env=env, quiet_ok=quiet_ok)

    def act_argv(self, argv, title, env=None, quiet_ok=None):
        self.working('working…  ' + title)
        text, rc = self.capture(argv, env=env)
        plain = self._plain_text(text).rstrip()
        if rc == 0 and not plain and quiet_ok:
            plain = text = quiet_ok
        h, w = self.scr.getmaxyx()
        lines = self._wrap(plain, max(30, min(100, w - 4)) - 4)
        if len(lines) <= max(3, min(14, h - 8)):
            self.note(title if rc == 0 else '%s - it ended with %d' % (title, rc),
                      plain or '(it said nothing)', '' if rc == 0 else 'bad')
        else:
            if rc not in (0, None):
                text += '\n' + self.pal.dim('(it ended with %d)' % rc)
            self.go_plain(lambda: self.page(title, text))
        return rc

    def live(self, fn):
        """A view of its own on the terminal (a live log, a progress)."""
        self.go_plain(fn)

    # ---- small parts the lists use ------------------------------------------------
    @staticmethod
    def _when(ts):
        if not ts:
            return '-'
        try:
            return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(ts)))
        except (TypeError, ValueError):
            return str(ts)

    @staticmethod
    def _rows(got, *keys):
        if isinstance(got, dict):
            for k in keys:
                if isinstance(got.get(k), list):
                    return got[k]
            return []
        return got if isinstance(got, list) else []

    def details(self, title, row, skip=()):
        """One row's fields as words, in a window or on its own screen."""
        lines = []
        for k, v in row.items():
            if k in skip or v in (None, '', [], {}):
                continue
            if isinstance(v, (list, dict)):
                v = json.dumps(v, default=str, ensure_ascii=False)
            elif k in ('created', 'last_used', 'last_seen', 'last_in', 'activated', 'at',
                       'pending_at', 'locked_until') and isinstance(v, (int, float)):
                v = self._when(v)
            lines.append('%-16s %s' % (k, v))
        h, w = self.scr.getmaxyx()
        if len(lines) <= h - 8:
            self.note(title, '\n'.join(lines))
        else:
            self.go_plain(lambda: self.page(title, '\n'.join(lines)))

    # ---- 9 backups --------------------------------------------------------------
    def _kept_files(self):
        out = []
        for folder in (STATE_DIR / 'backups', STATE_DIR / 'dumps'):
            try:
                for f in folder.iterdir():
                    if f.is_file():
                        st = f.stat()
                        out.append({'path': str(f), 'name': f.name, 'folder': folder.name,
                                    'at': st.st_mtime, 'bytes': st.st_size})
            except OSError:
                continue
        return sorted(out, key=lambda x: x['at'], reverse=True)

    def m_backups(self):
        def kept():
            return self.pick('Backups kept here', self._kept_files, [
                ('made', lambda f: self._when(f['at']), 16, None),
                ('size', lambda f: human_bytes(f['bytes']), 10, None),
                ('in', lambda f: f['folder'], 8, lambda f: 'dim'),
                ('file', lambda f: f['name'], 60, None)], self.backup_do,
                'no copy is kept here yet')

        def by_path(restore):
            def go():
                path = self.ask_one('Put a copy back' if restore else 'What is in a file',
                                    'the file', str(STATE_DIR / 'backups') + '/', help_=(
                                        'A copy made here or brought from elsewhere '
                                        '(.json.gz, .sql.gz or a .tar with its key).'),
                                    check=lambda v, _: None if os.path.isfile(v)
                                    else 'there is no such file')
                if path:
                    self.backup_do({'path': path, 'name': os.path.basename(path)},
                                   'restore' if restore else 'info')
            return go
        return self.sub('Backups', [
            ('1', 'A copy now', lambda: self.act('--backup')),
            ('2', 'The copies kept here (Enter: look in one, put it back)', kept),
            ('3', 'What is in a file', by_path(False)),
            ('4', 'Put a copy back from a file', by_path(True)),
            ('5', 'Backups to other machines: how they went',
             lambda: self.act('--rbackup-status')),
            ('6', 'Backups to other machines: one now', lambda: self.act('--rbackup-now')),
        ])

    def backup_do(self, f, what=None):
        if what is None:
            what = self.choose(f['name'], [('info', 'What is in it'),
                                            ('restore', 'Put it back (replaces everything)')])
        if what == 'info':
            self.act('--backup-info', f['path'])
        elif what == 'restore':
            if self.confirm('Put a copy back', 'Everything in the database is replaced by '
                            '%s. The certificates, accounts and settings changed since are lost.'
                            % f['name'], 'Put it back', danger=True):
                self.act('--restore', f['path'], '--yes')

    # ---- 10 upgrades ------------------------------------------------------------
    def m_ops(self):
        """What the pages do, for a server without them (1.0.187): ACME for the
        pages, the updates of the system, restarts, a test mail or SMS, lockouts."""
        def nodes():
            got = self.out('--updates', 'status') or {}
            return [n.get('name') for n in got.get('nodes') or [] if n.get('name')]

        def acme_order():
            got = self.out('--acme') or {}
            opts = [('all', 'every one ACME looks after on this node')] + [
                (t['target'], '%s - %s' % (t['target'], t.get('name') or 'no name yet'))
                for t in got.get('targets') or []]
            which = self.choose('Order a certificate now', opts)
            if which is not None:
                self.live(lambda: self.show_live('--acme-order', which))

        def updates_start():
            ns = nodes()
            if not ns:
                return
            how = self.choose('A node whose update needs a restart', [
                ('ask', 'ask on the pages first'), ('auto', 'restarted by itself, one at a time'),
                ('never', 'not restarted')])
            if how is None:
                return
            if self.confirm('Update now', 'The updates are put in on %s, one node at a time.'
                            % ', '.join(ns), 'Update', danger=True):
                self.act('--updates', 'start', '--reboot', how, '--yes')

        def restart():
            ns = nodes()
            opts = [('all', 'every node, one at a time')] + [(n, n) for n in ns]
            which = self.choose('Restart a machine', opts)
            if which is None:
                return
            if self.confirm('Restart', ('Every node restarts now, one at a time' if which == 'all'
                                        else 'The machine %s restarts now' % which) +
                            '; the service goes on on the others.', 'Restart', danger=True):
                self.act('--restart-nodes', which, '--yes')

        def mail_test():
            got = self.form('A test mail', [{'key': 'to', 'label': 'to', 'need': True,
                                             'check': lambda v, _: None if re.match(
                                                 r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v) else 'not an e-mail address'}])
            if got:
                self.act('--mail-test', got['to'])

        def sms_test():
            got = self.form('A test SMS', [{'key': 'to', 'label': 'to', 'need': True,
                                            'help': 'The number, +420…; the code in it opens nothing.'}])
            if got:
                self.act('--sms-test', got['to'])

        def lockout_clear():
            rows = [r for r in (self.out('--lockouts') or []) if isinstance(r, dict)]
            if not rows:
                self.note('Lockouts', 'Nobody and nothing is counted now.')
                return
            opts = [('all', 'every one')] + [('%s:%s' % (r['kind'], r['who']), '%s:%s (%s)' % (
                r['kind'], r['who'], r.get('node'))) for r in rows]
            which = self.choose('Forget a lockout', opts)
            if which is not None:
                self.act('--lockouts-clear', which)

        return self.sub('The pages\' certificates, updates, restarts, tests', [
            ('1', 'The pages\' certificates by ACME: how they stand', lambda: self.act('--acme')),
            ('2', 'Order a certificate for the pages by ACME now', acme_order),
            ('3', 'Updates of the system: how they stand', lambda: self.act('--updates', 'status')),
            ('4', 'Look for updates now', lambda: self.act('--updates', 'check')),
            ('5', 'Put the updates in (one node at a time)', updates_start),
            ('6', 'Stop the updates going on', lambda: self.act('--updates', 'cancel')),
            ('7', 'Restarts: how they went', lambda: self.act('--restarts')),
            ('8', 'Restart a machine (the service kept)', restart),
            ('9', 'Send a test mail', mail_test),
            ('10', 'Send a test SMS', sms_test),
            ('11', 'Lockouts: who is locked out now', lambda: self.act('--lockouts')),
            ('12', 'Forget a lockout', lockout_clear),
        ])

    def m_more(self):
        """The rest of the pages (1.0.188): the wizards' looks and tries, the tests
        of what is sent out, the time and network of each node, high security."""
        def db_probe():
            m = self.choose('Try encryption to the database server (nothing changed)', [
                ('verify-full', 'verify-full - the certificate and its name checked'),
                ('verify-ca', 'verify-ca - the certificate checked'), ('require', 'require - encrypted only')])
            if m:
                self.act('--db-tls-probe', m)

        def db_apply():
            ph = self.choose('A step of encryption to the database server, on every node', [
                ('server', 'acme\'s certificates into the PostgreSQLs (each reloaded)'),
                ('connect', 'each node\'s connection made again, verify-full'),
                ('server_off', 'acme\'s certificates out of the PostgreSQLs')])
            if ph and self.confirm('Encryption to the database server', {
                    'server': 'Each node\'s PostgreSQL gets acme\'s certificate and is reloaded; '
                              'the connections stay as they are.',
                    'connect': 'Each node connects to its database again, with TLS that checks the '
                               'certificate and its name; the requests are answered meanwhile.',
                    'server_off': 'acme\'s certificates are taken out of the PostgreSQLs.'}[ph],
                    'Do it', danger=True):
                self.act('--db-tls-apply', ph, '--db-tls-mode', 'verify-full', '--yes')

        def isemon_probe():
            got = self.form('Try isemon over TLS from every node', [
                {'key': 'at', 'label': 'isemon at', 'need': True, 'help': 'HOST or HOST:PORT (6514).'}])
            if got:
                self.act('--isemon-tls-probe', got['at'])

        def proxy():
            got = self.form('Try the way out (proxy) from every node', [
                {'key': 'url', 'label': 'an address', 'help': 'Empty: the one upgrades are looked for at.'}])
            if got is not None:
                self.act('--proxy-test', got.get('url') or '')

        def waive():
            got = self.out('--hisec') or {}
            rows = (got.get('block') or []) + (got.get('waived') or [])
            if not rows:
                self.note('High security', 'Every rule is kept: there is nothing to make an exception of.')
                return
            r = self.choose('An exception of high security (or not any more)', [
                (x['rule'], '%s %s - %s' % ('[exception]' if x in (got.get('waived') or []) else '[not kept]',
                                           x['rule'], x.get('title') or x.get('what'))) for x in rows])
            if r:
                on = r not in [x['rule'] for x in got.get('waived') or []]
                if self.confirm('High security', ('%s becomes an exception: high security holds without it.'
                                                  if on else '%s is a rule again.') % r,
                                'Yes', danger=on):
                    self.act('--hisec-waive', r, 'on' if on else 'off')

        def se_step():
            st = self.choose('SELinux: a step on this machine', [
                ('prepare', 'make it ready - permissive at the next start (from disabled)'),
                ('apply', 'put in what acme needs (while permissive)'),
                ('enforce', 'switch to enforcing'),
                ('permissive', 'back to permissive')])
            if st and self.confirm('SELinux on this machine', {
                    'prepare': 'The configuration says permissive, and every file is labelled at '
                               'the next start of the machine. The machine is not restarted now.',
                    'apply': 'acme\'s module, the labels of its files, the booleans and the ports it '
                             'needs are put in. Still permissive: nothing is refused.',
                    'enforce': 'From now on SELinux refuses what its policy does not allow - and '
                               'stays enforcing after a restart. Refused while anything is missing '
                               'or was refused.',
                    'permissive': 'SELinux no longer refuses anything, now and after a restart.'}[st],
                    'Do it', danger=st in ('enforce', 'prepare')):
                self.act('--selinux', st, '--yes')

        return self.sub('Encryption, sending out, time, network, high security', [
            ('1', 'Encryption to the database server: how it stands', lambda: self.act('--db-tls')),
            ('2', 'Encryption to the database server: try a mode', db_probe),
            ('3', 'Encryption to the database server: a step on every node', db_apply),
            ('4', 'Encrypted sending to isemon: how it stands', lambda: self.act('--isemon-tls')),
            ('5', 'Encrypted sending to isemon: try it', isemon_probe),
            ('6', 'A test line to isemon, from every node', lambda: self.act('--isemon-test')),
            ('7', 'A test line to the syslog servers (SIEM), from every node', lambda: self.act('--siem-test')),
            ('8', 'The way out (proxy): try it', proxy),
            ('9', 'SNMPv3: ask each node\'s agent', lambda: self.act('--snmp-test')),
            ('10', 'SNMPv3: a test trap', lambda: self.act('--snmp-trap')),
            ('11', 'The time of each node', lambda: self.act('--ntp')),
            ('12', 'Set this node\'s clock now', lambda: self.act('--ntp-sync')),
            ('13', 'The network of each node', lambda: self.act('--net')),
            ('14', 'High security: every rule', lambda: self.act('--hisec')),
            ('15', 'High security: an exception, or not any more', waive),
            ('16', 'SELinux: how it stands on this machine', lambda: self.act('--selinux-check')),
            ('17', 'SELinux: a step on this machine', se_step),
            ('18', 'SELinux: the report for acme\'s module (a file)', lambda: self.act('--selinux-report')),
            ('19', 'The guard against writes to the database: rows not as acme wrote them',
             lambda: self.act('--guard-status')),
        ])

    def m_upgrades(self):
        def online():
            self.working('working…  looking for a new version')
            row = self.out('--upgrade-check') or {}
            if row.get('error'):
                self.note('Upgrade from the web', '%s:\n%s' % (row.get('url'), row['error']),
                          'bad')
                return
            here = _ver_tuple(__version__)
            newer = [p for p in row.get('packages') or []
                     if _ver_tuple(p.get('version')) > here]
            if not newer:
                self.note('Upgrade from the web', 'Nothing newer than %s at %s.' % (
                    __version__, row.get('url')), 'ok')
                return
            ver = self.choose('Upgrade from the web', [
                (p['version'], 'acme %s%s' % (p['version'], '   (the newest)' if i == 0 else ''))
                for i, p in enumerate(newer)], 'This server runs %s. Found at %s:' % (
                    __version__, row.get('url')))
            if not ver:
                return
            nodes = self._nodes()
            if not self.confirm('Upgrade to %s' % ver, (
                    'The nodes %s are upgraded one at a time - each in maintenance while '
                    'it is, the other answering.' % ', '.join(nodes)) if len(nodes) > 1 else
                    'This server is upgraded - for a minute nothing is renewed or deployed and '
                    'the pages do not answer.',
                    'Upgrade'):
                return
            self.live(lambda: self.show_live('--upgrade-online', ver, '--yes'))

        def install():
            path = self.ask_one('Upgrade this node from a package', 'the package', '/root/',
                                help_='acme-X.Y.Z.tar.gz, or the folder it was unpacked to.',
                                check=lambda v, _: None if (
                                    os.path.isfile(v) and v.endswith('.tar.gz')) or
                                os.path.isfile(os.path.join(v, 'install.sh'))
                                else 'neither an acme-X.Y.Z.tar.gz nor a folder with install.sh')
            if not path:
                return
            folder = path
            if path.endswith('.tar.gz'):
                # A package goes through root's own helper (1.0.149): copied out
                # of reach, its signature checked before anything of it is
                # unpacked or run - a package in /var/lib/acme/upgrade is the acme
                # account's to change, and was unpacked and run as it was.
                helper = str(UPGRADE_HELPER)
                if not os.path.isfile(helper):
                    self.note('Upgrade', '%s is not installed - upgrade once with install.sh '
                              '--upgrade from a package you checked' % helper, 'bad')
                    return
                if not self.confirm('Upgrade', 'This node is upgraded with %s once its '
                                    'signature is checked.' % path, 'Upgrade'):
                    return

                def run_signed():
                    self.clear_screen()
                    subprocess.call(['/usr/bin/python3', '-I', helper, '--run', path])
                    self.pause()
                self.live(run_signed)
                return
            script = os.path.join(folder, 'install.sh')
            if not os.path.isfile(script):
                self.note('Upgrade', 'there is no install.sh in %s' % folder, 'bad')
                return
            # The version the package says (1.0.146), not its folder's name: in
            # acmelib/__init__.py, beside acme.py (acme.py itself in a package
            # made before the engine was split).
            m = None
            for one in (os.path.join(folder, 'acmelib', '__init__.py'),
                        os.path.join(folder, 'acme.py')):
                try:
                    with open(one, encoding='utf-8') as f:
                        m = re.search(r"^__version__ = ['\"](\d+\.\d+\.\d+)['\"]", f.read(),
                                      re.M)
                except OSError:
                    continue
                if m:
                    break
            if m and _ver_tuple(m.group(1)) < _ver_tuple(__version__):
                # Never past the checks (1.0.143): an older one goes the safe way.
                self.note('Upgrade', '%s is older than %s, which runs here. Going back is '
                          'checked first - Upgrades → Go back to an older version, or\n'
                          'acme --downgrade %s' % (m.group(1), __version__,
                                                  path if path.endswith('.tar.gz') else
                                                  'acme-%s.tar.gz' % m.group(1)), 'warn')
                return
            # A folder carries no signature (1.0.149): said so, and only one of
            # root's own - nobody else may have changed what root runs.
            try:
                st = os.lstat(folder)
                owned = st.st_uid == 0 and not st.st_mode & 0o022 and \
                    os.lstat(script).st_uid == 0 and not os.lstat(script).st_mode & 0o022
            except OSError:
                owned = False
            if not owned:
                self.note('Upgrade', '%s is not root\'s alone - another account could have '
                          'changed what would be run as root. Use the signed package '
                          '(acme-X.Y.Z.tar.gz).' % folder, 'bad')
                return
            if self.confirm('Upgrade', 'This node is upgraded with %s. A folder is not '
                            'checked for a signature - only one you unpacked yourself from a '
                            'signed package.' % script, 'Upgrade unchecked'):
                def go():
                    self.clear_screen()
                    subprocess.call(['bash', script, '--upgrade'])
                    self.pause()
                self.live(go)

        def cancel():
            if self.confirm('Stop the upgrade', 'The nodes not yet begun stay as they are; '
                            'one being upgraded finishes.', 'Stop it'):
                self.act('--upgrade-cancel')

        def back():
            # Going back to an older version (1.0.143): only one that is safe.
            self.working('working…  looking for older versions')
            got = self.out('--downgrade-check') or {}
            if not got.get('versions') and got.get('url') is None:
                self.note('Go back to an older version', 'The versions could not be read: '
                          'is upgrade_url set? (acme --downgrade-check says why)', 'bad')
                return
            vs = got.get('versions') or []
            ok = [v for v in vs if not v.get('why')]
            if not ok:
                self.note('Go back to an older version', 'Nothing older at %s may be gone back '
                          'to.\n\n%s' % (got.get('url'), '\n'.join(
                              '%s: %s' % (v['version'], '; '.join(v['why'])) for v in vs)
                              or 'No older version is there.'), 'warn')
                return
            ver = self.choose('Go back to an older version', [
                (v['version'], 'acme %s' % v['version']) for v in ok],
                'This server runs %s and may go back to %s or newer (the database is not '
                'touched). Found at %s:' % (__version__, got.get('floor'), got.get('url')))
            if not ver:
                return
            nodes = self._nodes()
            if not self.confirm('Go back to %s' % ver, (
                    'The nodes %s go back one at a time - each in maintenance while it is, '
                    'the other answering.' % ', '.join(nodes) if len(nodes) > 1 else
                    'This server goes back - for a minute nothing is renewed or deployed and the '
                    'pages do not answer.') +
                    ' The package is checked against the database first. What came in the '
                    'newer versions is gone until you upgrade again.', 'Go back',
                    danger=True):
                return
            self.live(lambda: self.show_live('--downgrade', ver, '--yes'))
        return self.sub('Upgrades', [
            ('1', 'How it stands', lambda: self.act('--upgrade-status')),
            ('2', 'Look for a new version on the web now', lambda: self.act('--upgrade-check')),
            ('3', 'Upgrade from the web (every node, with its progress)', online),
            ('4', 'Follow the upgrade going on', lambda: self.show_live('--upgrade-follow'),
             'plain'),
            ('5', 'Upgrade this node from a package file', install),
            ('6', 'Stop an upgrade going on', cancel),
            ('7', 'Go back to an older version (only a safe one)', back),
        ])

    # ---- 11 the service ---------------------------------------------------------
    def m_service(self):
        def restart():
            if self.confirm('Restart the service', 'The pages do not answer for a few seconds '
                            '(the other node does, if there is one).', 'Restart'):
                self.act_argv(['systemctl', 'restart', 'acme'], '$ systemctl restart acme',
                              quiet_ok='restarted')
                self.st_now = True

        def at_login():
            on = console_at_login()
            r = self.choose('The console at login', [
                ('on', 'On - root sees this console first when signing in'),
                ('off', 'Off - root gets the ordinary shell')],
                'It is %s now.' % ('ON' if on else 'off'), cur=0 if on else 1)
            if r and (r == 'on') != on:
                try:
                    self.note('The console at login', console_at_login_set(r == 'on'), 'ok')
                except SystemExit as e:
                    self.note('The console at login', str(e), 'bad')
        return self.sub('The service', [
            ('1', 'Its state', lambda: self.act_argv(
                ['systemctl', 'status', 'acme', '--no-pager', '-n', '60', '-l'],
                '$ systemctl status acme')),
            ('2', 'Restart it', restart),
            ('3', 'The pages (nginx, PHP)', lambda: self.act_argv(
                ['systemctl', 'status', 'nginx', 'php-fpm', '--no-pager', '-n', '5'],
                '$ systemctl status nginx php-fpm')),
            ('4', 'Its journal, live', self.journal, 'plain'),
            ('5', 'The console at login: on or off', at_login),
        ])


def console_at_login():
    try:
        fd = os.open(str(CONSOLE_FLAG), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        import stat as _stat
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        return os.read(fd, 8).decode('ascii', 'replace').strip() == 'on'
    finally:
        os.close(fd)


def console_at_login_set(on):
    if os.geteuid() != 0:
        raise SystemExit('acme: only root sets that')
    # Written beside it and put in its place (1.0.136): a link or a pipe
    # found there is replaced, never followed.
    tmp = '%s.%d.tmp' % (CONSOLE_FLAG, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, b'on\n' if on else b'off\n')
        os.fchmod(fd, 0o644)
    finally:
        os.close(fd)
    os.rename(tmp, str(CONSOLE_FLAG))
    return ('the acme console opens when root signs in at the console or over SSH (q leaves '
            'it for the shell)' if on else 'root signs in to the ordinary shell; '
            '`acme --console` opens the console')


