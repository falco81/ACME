# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Colour - as isemon does it
# ---------------------------------------------------------------------------
# colorama when it is installed, and the same escape sequences written by hand
# when it is not. A nicety, never a dependency: a server being put right at two
# in the morning is not the one to find that the token server will not start
# because a colour library is missing. colorama adds a Windows console, a
# terminal reset however the program ends, and nothing else on Linux.
# acme carries colorama with it (acmelib/vendor/colorama): the one installed on
# the system is taken when there is one, the carried one when not.
try:
    try:
        import colorama
    except ImportError:
        from acmelib.vendor import colorama
        sys.modules.setdefault("colorama", colorama)
    from colorama import Fore as _Fore, Style as _Style
    HAVE_COLORAMA = True
except Exception:                       # not installed, or installed broken
    colorama = None
    HAVE_COLORAMA = False

    class _Fore(object):
        RED = '\033[31m'; GREEN = '\033[32m'; YELLOW = '\033[33m'
        BLUE = '\033[34m'; MAGENTA = '\033[35m'; CYAN = '\033[36m'
        WHITE = '\033[37m'; RESET = '\033[39m'

    class _Style(object):
        BRIGHT = '\033[1m'; DIM = '\033[2m'; NORMAL = '\033[22m'
        RESET_ALL = '\033[0m'

_COLORAMA_READY = False


def write_private(path, text):
    """A file only root reads, so from its first byte (1.0.94)."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def start_colour():
    global _COLORAMA_READY
    if _COLORAMA_READY or not HAVE_COLORAMA:
        return
    _COLORAMA_READY = True
    try:
        if hasattr(colorama, 'just_fix_windows_console'):
            colorama.just_fix_windows_console()
        else:
            colorama.init()
    except Exception:
        pass


ANSI = re.compile(r'\033\[[0-9;]*m')
TERM_CTL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')


def term_safe(text):
    """What came from outside, safe on a terminal (1.0.139): a User-Name or a
    reason from a packet carried escapes that cleared the screen, set the
    title or wrote the clipboard. Colours are kept; any other control
    character is shown as \\xNN."""
    t = str(text)
    out, at = [], 0
    for m in ANSI.finditer(t):
        out.append(TERM_CTL.sub(lambda c: '\\x%02x' % ord(c.group(0)), t[at:m.start()]))
        out.append(m.group(0))
        at = m.end()
    out.append(TERM_CTL.sub(lambda c: '\\x%02x' % ord(c.group(0)), t[at:]))
    return ''.join(out)


def plain_len(text):
    """How wide something looks, the colour taken out."""
    return len(ANSI.sub('', str(text)))


def plain_pad(text, width):
    return str(text) + ' ' * max(0, width - plain_len(text))


class Palette(object):
    """Every colour the command line uses, in one place."""

    def __init__(self, on):
        self.on = bool(on)
        if self.on:
            start_colour()

        def code(*parts):
            return ''.join(parts) if self.on else ''

        self.c_ok = code(_Fore.GREEN)
        self.c_warn = code(_Fore.YELLOW)
        self.c_bad = code(_Style.BRIGHT, _Fore.RED)
        self.c_info = code(_Fore.CYAN)
        self.c_head = code(_Style.BRIGHT, _Fore.CYAN)
        self.c_key = code(_Fore.WHITE)
        self.c_addr = code(_Fore.MAGENTA)
        self.c_hi = code(_Style.BRIGHT)
        self.c_dim = code(_Style.DIM)
        self.off = code(_Style.RESET_ALL)
        try:
            self.width = max(60, min(120, shutil.get_terminal_size((100, 24)).columns))
        except Exception:
            self.width = 100

    def paint(self, text, colour):
        if not self.on or not colour:
            return str(text)
        return '%s%s%s' % (colour, text, self.off)

    def good(self, t):
        return self.paint(t, self.c_ok)

    def bad(self, t):
        return self.paint(t, self.c_bad)

    def warn(self, t):
        return self.paint(t, self.c_warn)

    def info(self, t):
        return self.paint(t, self.c_info)

    def dim(self, t):
        return self.paint(t, self.c_dim)

    soft = dim

    def head(self, t):
        return self.paint(t, self.c_head)

    def bold(self, t):
        return self.paint(t, self.c_hi)

    hi = bold

    def addr(self, t):
        return self.paint(t, self.c_addr)

    def ok_line(self, t):
        return (self.good('✔ ') if self.on else '[ ok ] ') + str(t)

    def warn_line(self, t):
        return (self.warn('! ') if self.on else '[warn] ') + str(t)

    def bad_line(self, t):
        return (self.bad('✘ ') if self.on else '[fail] ') + str(t)


def colour_wanted(no_color=False, stream=None):
    """What the person asked for, then NO_COLOR, then FORCE_COLOR, then the
    terminal itself - in that order, as isemon decides it."""
    if no_color or os.environ.get('NO_COLOR') is not None:
        return False
    if os.environ.get('FORCE_COLOR') or os.environ.get('CLICOLOR_FORCE'):
        return True
    if str(os.environ.get('TERM') or '').lower() in ('dumb', '') \
            and not os.environ.get('TERM_PROGRAM'):
        return False
    try:
        return bool((stream or sys.stdout).isatty())
    except Exception:
        return False


