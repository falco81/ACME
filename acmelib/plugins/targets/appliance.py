# -*- coding: utf-8 -*-
"""
This acme server itself: a certificate of the manager becomes the certificate
of acme's own pages - each node's, the VIP address's, or both - through the
engine's Settings → Certificates and TLS (the profile of the node or of the
VIP address). Every node puts its own into nginx within seconds; the VIP's is
served by whichever node holds the address. A renewal deploys it again by
itself, so the pages are renewed with it on every node.

The engine's own ACME (Settings → Automatic certificates) is told to leave
those pages alone from then on, as with a certificate uploaded by hand.
"""
from __future__ import annotations

import time

from acmelib.plugins.base import PluginError, Target, field

WHERE = [['auto', 'every node, and the VIP address in a cluster that has one'],
         ['nodes', 'every node\'s own pages'],
         ['this', 'this node only (the one that deploys)'],
         ['vip', 'the VIP address only'],
         ['list', 'the ones named below']]


def _fp(v):
    return str(v or '').replace(':', '').strip().lower()


class ApplianceTarget(Target):
    kind = 'appliance'
    title = 'This acme server (its pages)'
    vendor = 'acme'
    description = ('The certificate becomes the one of acme\'s own pages - each node\'s and/or '
                   'the VIP address\'s - as Settings → Certificates and TLS would take it; '
                   'renewals put the new one there on every node by themselves.')
    doc = 'targets.md'
    dual = True             # a dual certificate: the twin is the pages' second certificate
    fields = []
    deploy_fields = [
        field('where', 'Which pages', 'select', default='auto', options=WHERE,
              help='The pages of each node are reached by the node\'s own name; the VIP '
                   'address\'s by its name (Settings → High availability).'),
        field('names', 'Nodes (or vip)', 'list', show_if={'where': ['list']},
              placeholder='acme1\nacme2\nvip',
              help='One a line: a node\'s name as the cluster knows it, or vip.'),
        field('check_names', 'The certificate must hold the names', 'bool', default=True,
              advanced=True,
              help='Refuse it when a node\'s name (or the VIP address\'s) is not one of its '
                   'names - a browser would refuse it there.'),
    ]

    def test(self):
        w = self.ctx.pages_where()
        parts = ['this node is %s' % w['node']]
        if w['cluster']:
            parts.append('nodes: %s' % ', '.join(w['nodes']))
            parts.append('the VIP address %s' % ((w['vip'].get('fqdn') or w['vip'].get('address')
                                                  or 'is set') if w['vip']['on'] else 'is off'))
        for one in self._all(w, {'where': 'auto'}):
            got = self.ctx.pages_get(one)
            parts.append('%s: %s' % (one, ('%s, %s' % (got.get('cn') or '?', got.get('how') or
                                                       'put in')) if got else 'no certificate'))
        return '; '.join(parts)

    # -- where -------------------------------------------------------------------------------
    def _all(self, w, options):
        how = str((options or {}).get('where') or 'auto')
        vip = ['vip'] if w['vip']['on'] else []
        if how == 'auto':
            out = list(w['nodes']) + vip
        elif how == 'nodes':
            out = list(w['nodes'])
        elif how == 'this':
            out = [w['node']]
        elif how == 'vip':
            if not w['vip']['on']:
                raise PluginError('there is no VIP address here (Settings → High availability)',
                                  retry=False)
            out = ['vip']
        elif how == 'list':
            got = options.get('names') or []
            if isinstance(got, str):
                got = got.replace(',', '\n').split('\n')
            out = [str(x).strip() for x in got if str(x).strip()]
            known = set(w['nodes']) | {'vip'}
            bad = [x for x in out if x not in known]
            if bad:
                raise PluginError('not a node of this cluster (nor vip): %s - the nodes are %s'
                                  % (', '.join(bad), ', '.join(w['nodes'])), retry=False)
        else:
            raise PluginError('which pages? %r' % how, retry=False)
        if not out:
            raise PluginError('no pages to put it on', retry=False)
        return list(dict.fromkeys(out))

    @staticmethod
    def _covers(names, host):
        host = str(host or '').lower().rstrip('.')
        for n in names or []:
            n = str(n).lower().rstrip('.')
            if n == host or (n.startswith('*.') and '.' in host and
                             host.split('.', 1)[1] == n[2:]):
                return True
        return False

    def _host_of(self, w, one):
        if one == 'vip':
            return w['vip'].get('fqdn') or ''
        return ''

    # -- the contract ---------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        w = self.ctx.pages_where()
        where = self._all(w, options)
        if options.get('check_names', True) not in (False, 0, '0', 'false', 'off'):
            for one in where:
                host = self._host_of(w, one)
                if host and not self._covers(bundle.names, host):
                    raise PluginError('the certificate does not hold %s, the name of the VIP '
                                      'address (it holds %s)' % (host, ', '.join(bundle.names)),
                                      retry=False)
        put, same = [], []
        for one in where:
            if self.ctx.cancelled():
                raise PluginError('the job was stopped')
            have = self.ctx.pages_get(one) or {}
            alt = getattr(bundle, 'alt', None)
            want_alt = _fp(alt.fingerprint) if alt is not None else ''
            if have.get('fingerprint') == _fp(bundle.fingerprint) and not options.get('force') \
                    and (have.get('alt_fingerprint') or '') == want_alt:
                same.append(one)
                continue
            more = {'alt': (alt.cert_pem, alt.key_pem, alt.chain_pems)} if alt is not None \
                else {}
            got = self.ctx.pages_put(one, bundle.cert_pem, bundle.key_pem, bundle.chain_pems,
                                     how='the certificate manager: %s' % bundle.name, **more)
            self.ctx.step('the pages of %s take %s (until %s)%s' % (
                'the VIP address' if one == 'vip' else one, got.get('cn') or bundle.name,
                time.strftime('%Y-%m-%d', time.gmtime(bundle.not_after))
                if bundle.not_after else '?',
                '' if got.get('verify') in ('', 'ok') else ' - the chain: %s' % got['verify']))
            if alt is not None:
                self.ctx.step('and its twin (%s) as the second certificate of those pages - '
                              'nginx gives each client the one it takes' % alt.key_type)
            put.append(one)
        if same:
            self.ctx.step('already on the pages of %s' % ', '.join(same))
        if not put:
            return 'already on the pages of %s' % ', '.join(same)
        return 'on the pages of %s: each node puts it into nginx within seconds' % ', '.join(put)

    def verify(self, bundle, options):
        w = self.ctx.pages_where()
        for one in self._all(w, options or {}):
            have = self.ctx.pages_get(one) or {}
            if have.get('fingerprint') != _fp(bundle.fingerprint):
                return False
            alt = getattr(bundle, 'alt', None)
            if alt is not None and have.get('alt_fingerprint') != _fp(alt.fingerprint):
                return False
        return True
