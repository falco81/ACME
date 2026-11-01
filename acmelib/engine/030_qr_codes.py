# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# QR codes
# ---------------------------------------------------------------------------
# The picture the phone scans, made here rather than by a package: the
# standard (ISO/IEC 18004) in byte mode, every version, every level of error
# correction, the mask chosen the way the standard says. It comes out as SVG
# for the pages and as half-block characters for a terminal.
_QR_ECC_PER_BLOCK = {
    'L': (-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    'M': (-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
    'Q': (-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30,
          28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    'H': (-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28,
          30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
}
_QR_BLOCKS = {
    'L': (-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12,
          12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    'M': (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20,
          21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
    'Q': (-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25,
          27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68),
    'H': (-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30,
          32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81),
}
_QR_FORMAT = {'L': 1, 'M': 0, 'Q': 3, 'H': 2}


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z & 0xFF


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(len(result)):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < len(result):
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _qr_raw_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        align = ver // 7 + 2
        result -= (25 * align - 10) * align - 55
        if ver >= 7:
            result -= 36
    return result


def _qr_data_codewords(ver, ecl):
    return (_qr_raw_modules(ver) // 8
            - _QR_ECC_PER_BLOCK[ecl][ver] * _QR_BLOCKS[ecl][ver])


class QrCode(object):
    """One QR code: `modules[y][x]` is True where the square is dark."""

    def __init__(self, text, ecl='M'):
        data = text.encode('utf-8') if isinstance(text, str) else bytes(text)
        self.ecl = ecl
        for ver in range(1, 41):
            count_bits = 8 if ver <= 9 else 16
            need = 4 + count_bits + 8 * len(data)
            if need <= _qr_data_codewords(ver, ecl) * 8:
                break
        else:
            raise ValueError('that is too long for a QR code')
        self.version = ver
        self.size = ver * 4 + 17
        bits = []

        def put(value, n):
            for i in reversed(range(n)):
                bits.append((value >> i) & 1)
        put(0x4, 4)
        put(len(data), count_bits)
        for b in data:
            put(b, 8)
        capacity = _qr_data_codewords(ver, ecl) * 8
        put(0, min(4, capacity - len(bits)))
        put(0, (8 - len(bits) % 8) % 8)
        pad = 0xEC
        while len(bits) < capacity:
            put(pad, 8)
            pad ^= 0xEC ^ 0x11
        words = [int(''.join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
        all_words = self._with_ecc(words)
        size = self.size
        self.modules = [[False] * size for _ in range(size)]
        self.function = [[False] * size for _ in range(size)]
        self._function_patterns()
        self._codewords(all_words)
        best, best_penalty = 0, None
        for mask in range(8):
            self._mask(mask)
            self._format(mask)
            penalty = self._penalty()
            if best_penalty is None or penalty < best_penalty:
                best, best_penalty = mask, penalty
            self._mask(mask)
        self._mask(best)
        self._format(best)
        self.mask = best

    # ---- the pieces ------------------------------------------------------
    def _set(self, x, y, dark):
        self.modules[y][x] = bool(dark)
        self.function[y][x] = True

    def _function_patterns(self):
        size = self.size
        for i in range(size):
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for x, y in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    xx, yy = x + dx, y + dy
                    if 0 <= xx < size and 0 <= yy < size:
                        self._set(xx, yy, max(abs(dx), abs(dy)) not in (2, 4))
        places = self._alignment_places()
        last = len(places) - 1
        for i, a in enumerate(places):
            for j, b in enumerate(places):
                if (i == 0 and j == 0) or (i == 0 and j == last) or (i == last and j == 0):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(a + dx, b + dy, max(abs(dx), abs(dy)) != 1)
        self._format(0)
        if self.version >= 7:
            rem = self.version
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            value = self.version << 12 | rem
            for i in range(18):
                bit = (value >> i) & 1
                a, b = size - 11 + i % 3, i // 3
                self._set(a, b, bit)
                self._set(b, a, bit)

    def _alignment_places(self):
        ver = self.version
        if ver == 1:
            return []
        count = ver // 7 + 2
        step = (ver * 8 + count * 3 + 5) // (count * 4 - 4) * 2
        result = [self.size - 7 - i * step for i in range(count - 1)] + [6]
        return list(reversed(result))

    def _format(self, mask):
        data = _QR_FORMAT[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1
        size = self.size
        for i in range(0, 6):
            self._set(8, i, bit(i))
        self._set(8, 7, bit(6))
        self._set(8, 8, bit(7))
        self._set(7, 8, bit(8))
        for i in range(9, 15):
            self._set(14 - i, 8, bit(i))
        for i in range(0, 8):
            self._set(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self._set(8, size - 15 + i, bit(i))
        self._set(8, size - 8, True)

    def _with_ecc(self, data):
        ver, ecl = self.version, self.ecl
        blocks_n = _QR_BLOCKS[ecl][ver]
        ecc_len = _QR_ECC_PER_BLOCK[ecl][ver]
        raw = _qr_raw_modules(ver) // 8
        short_n = blocks_n - raw % blocks_n
        short_len = raw // blocks_n
        divisor = _rs_divisor(ecc_len)
        blocks = []
        k = 0
        for i in range(blocks_n):
            take = short_len - ecc_len + (0 if i < short_n else 1)
            dat = data[k:k + take]
            k += take
            ecc = _rs_remainder(dat, divisor)
            if i < short_n:
                dat = dat + [0]
            blocks.append(dat + ecc)
        out = []
        for i in range(len(blocks[0])):
            for j, blk in enumerate(blocks):
                if i != short_len - ecc_len or j >= short_n:
                    out.append(blk[i])
        return out

    def _codewords(self, data):
        size = self.size
        i = 0
        right = size - 1
        total = len(data) * 8
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = size - 1 - vert if upward else vert
                    if not self.function[y][x] and i < total:
                        self.modules[y][x] = bool((data[i >> 3] >> (7 - (i & 7))) & 1)
                        i += 1
            right -= 2

    def _mask(self, mask):
        test = (lambda x, y: (x + y) % 2 == 0,
                lambda x, y: y % 2 == 0,
                lambda x, y: x % 3 == 0,
                lambda x, y: (x + y) % 3 == 0,
                lambda x, y: (x // 3 + y // 2) % 2 == 0,
                lambda x, y: x * y % 2 + x * y % 3 == 0,
                lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
                lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0)[mask]
        for y in range(self.size):
            row, fn = self.modules[y], self.function[y]
            for x in range(self.size):
                if not fn[x] and test(x, y):
                    row[x] = not row[x]

    def _penalty(self):
        size, m = self.size, self.modules
        score = 0
        lines = [m[y] for y in range(size)] + [[m[y][x] for y in range(size)]
                                                for x in range(size)]
        finder = ([True, False, True, True, True, False, True, False, False, False, False],
                  [False, False, False, False, True, False, True, True, True, False, True])
        for line in lines:
            run, last = 0, None
            for v in line:
                if v == last:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run, last = 1, v
            if run >= 5:
                score += 3 + run - 5
            for i in range(len(line) - 10):
                seg = line[i:i + 11]
                if seg == finder[0] or seg == finder[1]:
                    score += 40
        for y in range(size - 1):
            for x in range(size - 1):
                v = m[y][x]
                if v == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    score += 3
        dark = sum(sum(1 for v in row if v) for row in m)
        total = size * size
        k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        score += k * 10
        return score

    # ---- drawn -------------------------------------------------------------
    def svg(self, scale=6, border=4, dark='#000', light='#fff'):
        """The code as an SVG picture, light squares and all - a phone needs
        the quiet zone round it, so it is part of the picture."""
        size = self.size + border * 2
        path = []
        for y in range(self.size):
            x = 0
            while x < self.size:
                if self.modules[y][x]:
                    start = x
                    while x < self.size and self.modules[y][x]:
                        x += 1
                    path.append('M%d %dh%dv1h-%dz' % (start + border, y + border,
                                                      x - start, x - start))
                else:
                    x += 1
        return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" '
                'height="%d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" '
                'fill="%s"/><path d="%s" fill="%s"/></svg>'
                % (size, size, size * scale, size * scale, light, ''.join(path), dark))

    def terminal(self, border=2, invert=False):
        """The code as half-block characters, two rows of squares a line.
        Drawn for a dark terminal: a dark square is the terminal's own dark
        and a light one is a full block. `invert` for a light terminal."""
        size = self.size
        out = []
        def light(x, y):
            if x < 0 or y < 0 or x >= size or y >= size:
                return not invert
            return (not self.modules[y][x]) != invert
        for y in range(-border, size + border, 2):
            row = []
            for x in range(-border, size + border):
                top, bottom = light(x, y), light(x, y + 1)
                row.append('█' if top and bottom else
                           '▀' if top else '▄' if bottom else ' ')
            out.append(''.join(row))
        return '\n'.join(out)


def qr_svg(text, scale=6):
    return QrCode(text, 'M').svg(scale=scale)


def qr_data_uri(text, scale=6):
    return 'data:image/svg+xml;base64,' + base64.b64encode(
        qr_svg(text, scale).encode('ascii')).decode('ascii')


