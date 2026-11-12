# -*- coding: utf-8 -*-
"""
What the Cisco and Aruba targets added in 1.0.95 share (not a module: the name starts with
"_"): the versions of a module the FortiGate way - one class per range of software versions
whose calls are the same, the plain one reading the version and acting on it, a versioned
one refusing a device that says another version before anything is changed.
"""
from __future__ import annotations

from acmelib.plugins.targets._common import PluginError


def words(ver, n=3):
    """(17, 12, 1) -> '17.12.1'."""
    return '.'.join(str(x) for x in tuple(ver)[:n])


class Ranges(object):
    """The ranges of one module: ((module_version, label, first, last|None), ...)."""

    def __init__(self, ranges, plain_label='any version (detects it)'):
        self.ranges = tuple(ranges)
        self.plain_label = plain_label

    def version_for(self, ver):
        """(module_version, label) made for the software version `ver`, ('', '') if none."""
        if ver is None:
            return '', ''
        for mv, label, lo, hi in self.ranges:
            if tuple(ver) >= tuple(lo) and (hi is None or tuple(ver) <= tuple(hi)):
                return mv, label
        return '', ''


class VersionCheck(object):
    """Mixed into a target: `sw_min` / `sw_max` say the software versions a module version is
    for (None: any - the plain one); `sw_version()` reads the device's (the module's own),
    `sw_name` names the software in words."""
    sw_name = 'the software'
    sw_min = None
    sw_max = None
    sw_checked_to = None            # the newest version in the documents it was checked by
    ranges = None                   # a Ranges

    def sw_version(self):
        raise NotImplementedError

    def sw_words(self, ver):
        ver = tuple(ver)
        if len(ver) >= 3 and ver[2] >= 999:          # the last of a minor release: 17.11
            return words(ver, 2)
        return words(ver)

    def range_words(self):
        if self.sw_min is None:
            return 'any %s' % self.sw_name
        lo = self.sw_words(self.sw_min)
        if self.sw_max is None:
            return '%s %s and later' % (self.sw_name, lo)
        return '%s %s - %s' % (self.sw_name, lo, self.sw_words(self.sw_max))

    def check_version(self, ver=None):
        """A versioned module on a device it is not for: refused before anything is changed.
        The version not known: said, and gone on with the module version's own way."""
        if self.sw_min is None:
            return
        if ver is None:
            ver = self.sw_version()
        if ver is None:
            self.ctx.step('the %s version cannot be read - the way of %s is used'
                          % (self.sw_name, self.range_words()), 'warn')
            return
        ver = tuple(ver)
        if ver < tuple(self.sw_min) or (self.sw_max is not None and ver > tuple(self.sw_max)):
            fit = (self.ranges.version_for(ver)[1] if self.ranges else '') or \
                (self.ranges.plain_label if self.ranges else 'any version (detects it)')
            raise PluginError(
                'this device runs %s %s - the module version "%s" is for %s; choose the '
                'version "%s" of the target' % (self.sw_name, self.sw_words(ver),
                                                self.version_label, self.range_words(), fit),
                retry=False)
        if self.sw_checked_to and ver[:len(self.sw_checked_to)] > tuple(self.sw_checked_to):
            self.ctx.step('%s %s is newer than the documents this module version was checked '
                          'against (%s)' % (self.sw_name, self.sw_words(ver),
                                            self.sw_words(self.sw_checked_to)), 'warn')
