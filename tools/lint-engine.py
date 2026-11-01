#!/usr/bin/env python3
"""The engine's parts checked as the one namespace they run in.

    python3 tools/lint-engine.py            undefined names, and what pyflakes finds
    python3 tools/lint-engine.py --all      every message, unused imports too

Each part is a file of its own, but every part sees the names of all the
others: checked one by one, every name looks undefined. Here they are put
together in their order (as acmelib/engine/__init__.py runs them), checked
once with pyflakes, and each message said against the part and the line it
came from. Exit 1 when something is undefined or does not compile.
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(os.path.dirname(HERE), 'acmelib', 'engine')
QUIET = ('imported but unused', 'redefinition of unused', 'is assigned to but never used',
         'unable to detect undefined names', "f-string is missing placeholders",
         'shadowed by loop variable')


def main():
    try:
        from pyflakes import api, reporter
    except ImportError:
        sys.exit('pyflakes is needed: pip install pyflakes')
    parts = sorted(f for f in os.listdir(ENGINE) if f[:3].isdigit() and f.endswith('.py'))
    src, where = [], []
    for p in parts:
        with open(os.path.join(ENGINE, p), encoding='utf-8') as f:
            lines = f.read().split('\n')
        for i, line in enumerate(lines, 1):
            if line.startswith('from __future__ import'):
                line = ''
            src.append(line)
            where.append((p, i))
    src.insert(0, 'from __future__ import annotations')
    where.insert(0, ('-', 0))
    out, err = io.StringIO(), io.StringIO()
    api.check('\n'.join(src), 'engine', reporter.Reporter(out, err))
    bad = 0
    for line in (out.getvalue() + err.getvalue()).splitlines():
        try:
            _, n, rest = line.split(':', 2)
            part, pn = where[int(n) - 1]
        except (ValueError, IndexError):
            print(line)
            bad += 1
            continue
        if '--all' not in sys.argv and any(q in rest for q in QUIET):
            continue
        print('acmelib/engine/%s:%d:%s' % (part, pn, rest))
        if 'undefined name' in rest or 'invalid syntax' in rest or 'Error' in rest:
            bad += 1
    print('%d part(s), %d line(s); %d problem(s)' % (len(parts), len(src), bad),
          file=sys.stderr)
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
