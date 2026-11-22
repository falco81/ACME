# -*- coding: utf-8 -*-
"""
A small PDF writer of its own (1.0.140, docs/reports.md) - the periodic reports' PDF without a
library: headings, words, tiles of numbers and tables that run over as many pages as they need,
each page with its header, the table's head again and "page N of M".

Only the fonts every PDF reader has (Helvetica and Helvetica-Bold, the standard 14) - nothing
embedded. Czech and Slovak letters are given their glyph names in the font's encoding
(/Differences): č ř ě ů ň ť ď ľ ĺ ŕ š ž and the capitals, the dashes, quotes and the bullet; the
rest of Latin-1 is WinAnsi's own. A character none of them has is written without its accent
(NFKD), else as "?". Streams are compressed (zlib, FlateDecode).

    doc = Doc(title='Certificate inventory', subtitle='acme · example', meta='22.11.2026 08:00')
    doc.tiles([('Certificates', '42', 'info'), ('Ending in 30 days', '3', 'warn')])
    doc.heading('Every certificate')
    doc.table(['Name', 'Team', '#Days left'], rows)        # '#' first: aligned right
    data = doc.output(page_words='Page {0} of {1}')
"""
from __future__ import annotations

import time
import unicodedata
import zlib

PAGE_W, PAGE_H = 842.0, 595.0           # A4, landscape
MARGIN = 36.0

# Helvetica and Helvetica-Bold, characters 32-126 (Adobe's AFM of the standard fonts).
_W_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556,
          556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667,
          667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722,
          667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500,
          556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278,
          556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_W_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556,
           556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722,
           722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722,
           667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556,
           611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333,
           611, 556, 778, 556, 556, 500, 389, 280, 389, 584]

# Codes 128-159 given glyphs of their own (the font's /Differences); 160-255 are Latin-1 as
# WinAnsi has them.
_EXTRA = [('–', 'endash', 556, 556), ('—', 'emdash', 1000, 1000),
          ('•', 'bullet', 350, 350), ('…', 'ellipsis', 1000, 1000),
          ('„', 'quotedblbase', 333, 500), ('“', 'quotedblleft', 333, 500),
          ('”', 'quotedblright', 333, 500), ('‘', 'quoteleft', 222, 278),
          ('’', 'quoteright', 222, 278), ('š', 'scaron', 500, 556),
          ('ž', 'zcaron', 500, 500), ('Š', 'Scaron', 667, 667),
          ('Ž', 'Zcaron', 611, 611), ('č', 'ccaron', 500, 556),
          ('Č', 'Ccaron', 722, 722), ('ď', 'dcaron', 643, 743),
          ('Ď', 'Dcaron', 722, 722), ('ě', 'ecaron', 556, 556),
          ('Ě', 'Ecaron', 667, 667), ('ň', 'ncaron', 556, 611),
          ('Ň', 'Ncaron', 722, 722), ('ř', 'rcaron', 333, 389),
          ('Ř', 'Rcaron', 722, 722), ('ť', 'tcaron', 317, 389),
          ('Ť', 'Tcaron', 611, 611), ('ů', 'uring', 556, 611),
          ('Ů', 'Uring', 722, 722), ('ľ', 'lcaron', 299, 400),
          ('Ľ', 'Lcaron', 556, 611), ('ĺ', 'lacute', 222, 278),
          ('Ĺ', 'Lacute', 556, 611), ('ŕ', 'racute', 333, 389)]
_CODE = {u: 128 + i for i, (u, _n, _r, _b) in enumerate(_EXTRA)}
_EXTRA_W = {128 + i: (r, b) for i, (_u, _n, r, b) in enumerate(_EXTRA)}
_SAY = {'→': '->', '←': '<-', '✔': '+', '✖': 'x', '✘': 'x',
        '≤': '<=', '≥': '>=', '≠': '!=', ' ': ' ', ' ': ' ',
        ' ': ' ', '‑': '-', '−': '-', '⚠': '!', '✓': '+'}
_LATIN_W = {0xd7: 584, 0xb0: 400, 0xb1: 584, 0xa7: 556, 0xa9: 737, 0xae: 737, 0xab: 556,
            0xbb: 556, 0xb5: 556, 0xb7: 278, 0xa0: 278, 0xad: 333}

TONES = {  # (ink, background) - the colours of the pages' pills and the mails'
    'info': ((0.114, 0.306, 0.847), (0.937, 0.965, 1.0)),
    'good': ((0.086, 0.396, 0.204), (0.941, 0.992, 0.957)),
    'warn': ((0.573, 0.251, 0.055), (1.0, 0.984, 0.922)),
    'bad': ((0.600, 0.106, 0.106), (0.996, 0.949, 0.949)),
    'dim': ((0.294, 0.333, 0.388), (0.953, 0.957, 0.965)),
}
BAND = (0.118, 0.227, 0.541)            # the head of the first page (#1e3a8a)
INK = (0.067, 0.094, 0.153)
MUTED = (0.420, 0.447, 0.502)
RULE = (0.898, 0.906, 0.922)
ZEBRA = (0.976, 0.980, 0.984)


def encode(text):
    """Bytes of the fonts' encoding for `text`."""
    out = bytearray()
    # composed first: a name written decomposed (c + a combining caron, as macOS and some
    # directories keep it) came out as "c?" - the mark alone has no glyph
    for ch in unicodedata.normalize('NFC', str(text if text is not None else '')):
        ch = _SAY.get(ch, ch)
        for c in ch:
            o = ord(c)
            if 32 <= o < 127:
                out.append(o)
            elif c in _CODE:
                out.append(_CODE[c])
            elif 0xa0 <= o <= 0xff:
                out.append(o)
            elif c in ('\t', '\n', '\r'):
                out.append(32)
            else:
                base = ''.join(x for x in unicodedata.normalize('NFKD', c)
                               if not unicodedata.combining(x))
                if base and all(32 <= ord(x) < 127 for x in base):
                    out.extend(base.encode('ascii'))
                elif base and all(x in _CODE or 0xa0 <= ord(x) <= 0xff for x in base):
                    out.extend(encode(base))
                else:
                    out.append(ord('?'))
    return bytes(out)


def _cw(code, bold):
    if 32 <= code < 127:
        return (_W_BOLD if bold else _W_REG)[code - 32]
    if code in _EXTRA_W:
        return _EXTRA_W[code][1 if bold else 0]
    if code in _LATIN_W:
        return _LATIN_W[code]
    base = ''.join(x for x in unicodedata.normalize('NFKD', chr(code))
                   if not unicodedata.combining(x))
    if len(base) == 1 and 32 <= ord(base) < 127:
        return (_W_BOLD if bold else _W_REG)[ord(base) - 32]
    return 556


def width(text, size, bold=False):
    """The width of `text` in points at `size`."""
    return sum(_cw(b, bold) for b in encode(text)) * size / 1000.0


def fit(text, size, room, bold=False):
    """`text` cut to `room` points with an ellipsis where it does not fit."""
    text = ' '.join(str(text if text is not None else '').split())
    if width(text, size, bold) <= room:
        return text
    dots = width('…', size, bold)
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if width(text[:mid], size, bold) + dots <= room:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo].rstrip() + '…'


def wrap(text, size, room, bold=False, most=0):
    """`text` in lines no wider than `room` (words kept whole where they fit)."""
    lines, cur = [], ''
    for word in str(text or '').split():
        trial = (cur + ' ' + word) if cur else word
        if width(trial, size, bold) <= room:
            cur = trial
            continue
        if cur:
            lines.append(cur)
        cur = word if width(word, size, bold) <= room else fit(word, size, room, bold)
    if cur:
        lines.append(cur)
    if most and len(lines) > most:
        lines = lines[:most]
        lines[-1] = fit(lines[-1] + ' …', size, room, bold)
    return lines or ['']


def _s(data):
    """A PDF string of bytes: ( ) \\ escaped."""
    return b'(' + data.replace(b'\\', b'\\\\').replace(b'(', b'\\(').replace(b')', b'\\)') + b')'


def _n(v):
    s = ('%.2f' % v).rstrip('0').rstrip('.')
    return s if s not in ('', '-0') else '0'


class _Page(object):
    def __init__(self):
        self.ops = []

    def add(self, s):
        self.ops.append(s if isinstance(s, bytes) else s.encode('latin-1'))

    def fill(self, rgb):
        self.add('%s %s %s rg' % tuple(_n(c) for c in rgb))

    def stroke(self, rgb):
        self.add('%s %s %s RG' % tuple(_n(c) for c in rgb))

    def rect(self, x, y, w, h, rgb, radius=0.0):
        self.fill(rgb)
        if radius <= 0:
            self.add('%s %s %s %s re f' % (_n(x), _n(y), _n(w), _n(h)))
            return
        r = min(radius, w / 2.0, h / 2.0)
        k = 0.5523 * r
        p = [('%s %s m', (x + r, y)), ('%s %s l', (x + w - r, y)),
             ('%s %s %s %s %s %s c', (x + w - r + k, y, x + w, y + r - k, x + w, y + r)),
             ('%s %s l', (x + w, y + h - r)),
             ('%s %s %s %s %s %s c', (x + w, y + h - r + k, x + w - r + k, y + h, x + w - r, y + h)),
             ('%s %s l', (x + r, y + h)),
             ('%s %s %s %s %s %s c', (x + r - k, y + h, x, y + h - r + k, x, y + h - r)),
             ('%s %s l', (x, y + r)),
             ('%s %s %s %s %s %s c', (x, y + r - k, x + r - k, y, x + r, y))]
        self.add(' '.join(f % tuple(_n(v) for v in a) for f, a in p) + ' f')

    def line(self, x1, y1, x2, y2, rgb, w=0.6):
        self.stroke(rgb)
        self.add('%s w %s %s m %s %s l S' % (_n(w), _n(x1), _n(y1), _n(x2), _n(y2)))

    def text(self, x, y, words, size, rgb=INK, bold=False, align='left', room=None):
        if room is not None:
            words = fit(words, size, room, bold)
        if align == 'right':
            x -= width(words, size, bold)
        elif align == 'center':
            x -= width(words, size, bold) / 2.0
        self.fill(rgb)
        self.add(b'BT /' + (b'F2' if bold else b'F1') + (' %s Tf %s %s Td ' % (
            _n(size), _n(x), _n(y))).encode('ascii') + _s(encode(words)) + b' Tj ET')


class Doc(object):
    """A document laid out top to bottom; output() makes the bytes."""

    def __init__(self, title, subtitle='', meta='', author='acme'):
        self.title, self.subtitle, self.meta, self.author = str(title), str(subtitle), str(meta), \
            str(author)
        self.pages = []
        self.y = 0.0
        self._new_page(first=True)

    # ---- the pages -------------------------------------------------------------------
    def _new_page(self, first=False):
        p = _Page()
        self.pages.append(p)
        top = PAGE_H - MARGIN
        if first:
            band = 74.0
            p.rect(MARGIN, top - band, PAGE_W - 2 * MARGIN, band, BAND, radius=10)
            p.text(MARGIN + 22, top - 24, self.subtitle.upper(), 8.5, (0.80, 0.85, 0.97),
                   bold=True, room=PAGE_W - 2 * MARGIN - 44)
            p.text(MARGIN + 22, top - 50, self.title, 20, (1, 1, 1), bold=True,
                   room=PAGE_W - 2 * MARGIN - 260)
            if self.meta:
                p.text(PAGE_W - MARGIN - 22, top - 50, self.meta, 9.5, (0.86, 0.90, 0.98),
                       align='right', room=230)
            self.y = top - band - 18
        else:
            p.text(MARGIN, top - 10, self.title, 10, INK, bold=True, room=PAGE_W / 2)
            p.text(PAGE_W - MARGIN, top - 10, self.subtitle, 8.5, MUTED, align='right',
                   room=PAGE_W / 2 - MARGIN)
            p.line(MARGIN, top - 17, PAGE_W - MARGIN, top - 17, RULE, 0.8)
            self.y = top - 32
        return p

    @property
    def page(self):
        return self.pages[-1]

    def _room(self, h):
        """A new page unless `h` points still fit above the footer."""
        if self.y - h < MARGIN + 26:
            self._new_page()
            return True
        return False

    # ---- what goes on them ---------------------------------------------------------------
    def space(self, h=8.0):
        self.y -= h

    def heading(self, words, note=''):
        self._room(52)
        self.y -= 8
        self.page.text(MARGIN, self.y - 12, words, 13, INK, bold=True, room=PAGE_W - 2 * MARGIN)
        self.y -= 18
        if note:
            for ln in wrap(note, 9, PAGE_W - 2 * MARGIN, most=3):
                self.page.text(MARGIN, self.y - 10, ln, 9, MUTED)
                self.y -= 12.5
        self.y -= 6

    def para(self, words, size=9.5, rgb=MUTED):
        for ln in wrap(words, size, PAGE_W - 2 * MARGIN, most=30):
            self._room(size + 6)
            self.page.text(MARGIN, self.y - size, ln, size, rgb)
            self.y -= size + 4
        self.y -= 4

    def tiles(self, tiles):
        """[(label, value, tone)] - numbers in tinted boxes side by side."""
        tiles = list(tiles)[:8]
        if not tiles:
            return
        h, gap = 54.0, 10.0
        self._room(h + 8)
        w = (PAGE_W - 2 * MARGIN - gap * (len(tiles) - 1)) / len(tiles)
        for i, (label, value, tone) in enumerate(tiles):
            ink, back = TONES.get(tone, TONES['dim'])
            x = MARGIN + i * (w + gap)
            self.page.rect(x, self.y - h, w, h, back, radius=8)
            self.page.rect(x, self.y - h, 3.5, h, ink, radius=1.5)
            self.page.text(x + 14, self.y - 27, str(value), 19, ink, bold=True, room=w - 20)
            self.page.text(x + 14, self.y - 44, str(label), 8.5, MUTED, room=w - 20)
        self.y -= h + 14

    def table(self, heads, rows, tones=None, size=8.5, empty='-'):
        """A table: `heads` (a '#' first: a number, aligned right), `rows` of words; `tones`
        (optional) a tone per row and column - {(row, col): tone} - for a word in colour."""
        heads = [str(h) for h in heads]
        right = [h.startswith('#') for h in heads]
        heads = [h.lstrip('#') for h in heads]
        rows = [[('' if c is None else str(c)) for c in r] for r in rows]
        tones = tones or {}
        room = PAGE_W - 2 * MARGIN
        pad = 6.0
        n = len(heads)
        natural = []
        for i in range(n):
            most = width(heads[i], size, True)
            for r in rows[:400]:
                if i < len(r):
                    most = max(most, width(r[i], size))
            natural.append(min(most, room * 0.45) + 2 * pad)
        total = sum(natural) or 1.0
        if total > room:
            # the narrow ones keep what they need; the wide ones share the rest
            floor = [min(x, 70.0) for x in natural]
            spare = room - sum(floor)
            wide = sum(x - f for x, f in zip(natural, floor)) or 1.0
            widths = [f + (x - f) * spare / wide for x, f in zip(natural, floor)]
        else:
            widths = [x + (room - total) * x / total for x in natural]
        row_h = size + 8.5

        def head_row():
            self.page.rect(MARGIN, self.y - row_h - 1, room, row_h + 1, (0.953, 0.957, 0.965),
                           radius=4)
            x = MARGIN
            for i in range(n):
                tx = x + widths[i] - pad if right[i] else x + pad
                self.page.text(tx, self.y - row_h + 4.5, heads[i].upper(), size - 1.2, MUTED,
                               bold=True, align='right' if right[i] else 'left',
                               room=widths[i] - 2 * pad)
                x += widths[i]
            self.y -= row_h + 3

        self._room(row_h * 3)
        head_row()
        if not rows:
            self.page.text(MARGIN + pad, self.y - row_h + 4.5, empty, size, MUTED)
            self.y -= row_h + 6
            return
        for ri, r in enumerate(rows):
            if self._room(row_h + 2):
                head_row()
            if ri % 2:
                self.page.rect(MARGIN, self.y - row_h, room, row_h, ZEBRA)
            x = MARGIN
            for i in range(n):
                words = r[i] if i < len(r) else ''
                tone = tones.get((ri, i))
                rgb = TONES[tone][0] if tone in TONES else INK
                tx = x + widths[i] - pad if right[i] else x + pad
                self.page.text(tx, self.y - row_h + 4.5, words, size, rgb, bold=bool(tone),
                               align='right' if right[i] else 'left', room=widths[i] - 2 * pad)
                x += widths[i]
            self.page.line(MARGIN, self.y - row_h, MARGIN + room, self.y - row_h, RULE, 0.4)
            self.y -= row_h
        self.y -= 10

    # ---- the file ---------------------------------------------------------------------
    def output(self, page_words='Page {0} of {1}', foot=''):
        count = len(self.pages)
        for i, p in enumerate(self.pages):
            p.line(MARGIN, MARGIN + 12, PAGE_W - MARGIN, MARGIN + 12, RULE, 0.6)
            if foot:
                p.text(MARGIN, MARGIN, foot, 7.5, MUTED, room=PAGE_W - 2 * MARGIN - 120)
            said = page_words(i + 1, count) if callable(page_words) else \
                page_words.replace('{0}', str(i + 1)).replace('{1}', str(count))
            p.text(PAGE_W - MARGIN, MARGIN, said, 7.5, MUTED, align='right')
        objs = []                                       # (number, bytes)

        def obj(data):
            objs.append(data if isinstance(data, bytes) else data.encode('latin-1'))
            return len(objs)
        diffs = ' '.join('/' + name for _u, name, _r, _b in _EXTRA)
        enc = obj('<< /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [128 %s] >>'
                  % diffs)
        f1 = obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding %d 0 R >>' % enc)
        f2 = obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding %d 0 R >>'
                 % enc)
        pages_no = len(objs) + 2 * count + 1          # after every page and its content
        kids = []
        for p in self.pages:
            body = zlib.compress(b'\n'.join(p.ops), 6)
            c = obj(b'<< /Length %d /Filter /FlateDecode >>\nstream\n' % len(body) + body +
                    b'\nendstream')
            kids.append(obj('<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %s %s] /Resources << '
                            '/Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>'
                            % (pages_no, _n(PAGE_W), _n(PAGE_H), f1, f2, c)))
        got = obj('<< /Type /Pages /Kids [%s] /Count %d >>' % (' '.join('%d 0 R' % k for k in kids),
                                                                count))
        assert got == pages_no
        cat = obj('<< /Type /Catalog /Pages %d 0 R >>' % pages_no)
        stamp = time.strftime('D:%Y%m%d%H%M%S')
        info = obj(b'<< /Title ' + _s(encode(self.title)) + b' /Author ' + _s(encode(self.author))
                   + b' /Producer (acme) /CreationDate (' + stamp.encode('ascii') + b') >>')
        out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        offsets = []
        for i, data in enumerate(objs):
            offsets.append(len(out))
            out += b'%d 0 obj\n' % (i + 1) + data + b'\nendobj\n'
        xref = len(out)
        out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objs) + 1)
        for off in offsets:
            out += b'%010d 00000 n \n' % off
        out += (b'trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n'
                % (len(objs) + 1, cat, info, xref))
        return bytes(out)
