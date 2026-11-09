# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The daemon
# ---------------------------------------------------------------------------
class Daemon(object):
    def __init__(self, store, serve=True):
        self.store = store
        self.serving = serve        # the daemon itself, not the command line (1.0.188)
        # The lanes - connections of their own for the threads named lane-*
        # (1.0.136) - in the serving daemon only; the command line keeps its one.
        if serve:
            store.db.lanes_on = True
        self._reader = None
        self._reader_lock = threading.Lock()
        self.started = time.time()
        self.stop_flag = threading.Event()
        self.shipper = None
        self.siem = None
        self.snmp = None
        self.sshgate = None
        _HS_WAIVE['store'][0] = store       # the exceptions to high security read from it
        self.dirs = {}
        self.reload_directories()
        self.api = None
        self.serial = 0
        self.conf_serial = store.get_meta('conf_serial', '0')
        # When this node last read the settings in (1.0.42): said in its heartbeat with the
        # mark it read, so that every card of Settings can say whether the other node has
        # what is saved.
        self.conf_loaded_at = time.time()
        self.beat_asked_seen = beat_asked_last(store)
        self.login_fails = collections.defaultdict(list)
        # What each count is (1.0.112): its limit, how long it lasts, and the
        # names tried from an address / the addresses a name was tried from -
        # for Settings - Accounts - Locked out.
        self.login_info = {}
        if serve:
            self.shipper = Shipper()
            DETAIL_SINK[0] = self.shipper       # the certificates' work in detail (1.0.44)
            self.siem = Siem()
            # Both told of each event (1.0.166); each only queues it.
            store.on_event = lambda *a, _s=(self.shipper, self.siem): [x.event_line(*a) for x in _s]
            # SNMPv3 (1.0.182): an agent of its own, in a thread of its own.
            self.snmp = SnmpAgent(self)
            # SSH with a code (1.0.40, as otp 1.0.181): a gate of its own on 127.0.0.1.
            self.sshgate = SshGate(self)

    def reload_directories(self):
        self.store._dirs = None
        fresh = {}
        for row in self.store.directories(with_secret=True):
            if row.get('enabled', 1):
                fresh[row['name'].lower()] = Directory(row)
        # Swapped in whole (1.0.44): emptied and filled again, a request in
        # between found no directory at all.
        self.dirs = fresh

    RELOAD_LOCK = threading.RLock()

    def dbguard_switch(self, on, by):
        """The guard of root's actions switched on or off on this node (1.0.231): written to
        its config.json at once, in effect at once."""
        if on == bool(CONFIG.get('db_guard')):
            return []
        if on:
            if not dbguard_key():
                raise BadSetting('db_guard: this node has no secrets.key to sign with')
            old = [n['name'] for n in ha_nodes(self.store)
                   if not n.get('me') and n.get('alive') and
                   _ver_tuple(n.get('version') or '0') < (1, 0, 40)]
            if old:
                raise BadSetting('db_guard: %s run an older version that does not sign what it '
                                 'writes - upgrade them first' % ', '.join(old))
            n = dbguard_resign(self.store, 'switched on by %s: what the database holds now is '
                                         'taken as acme\'s word' % by)
            write_file_settings({'db_guard': 1})
            CONFIG['db_guard'] = 1
            # Read again by the running service too (1.0.232): from the command line it went on
            # only at its next reload.
            self.store.set_meta('conf_serial', '%.6f:%s' % (time.time(), node_name()))
            log('root\'s actions only from rows acme signed: on (%d rows signed)' % n)
            return ['this node acts as root only on rows acme signed (%d signed now)' % n]
        write_file_settings({'db_guard': 0})
        CONFIG['db_guard'] = 0
        self.store.set_meta('conf_serial', '%.6f:%s' % (time.time(), node_name()))
        self.store.add_event('security', '%s switched off the guard of root\'s actions on %s: '
                             'rows of the database are acted on whoever wrote them'
                             % (by, node_name()), 'bad', who=by)
        return ['this node acts on rows of the database whoever wrote them, as before 1.0.40']

    def reload_all(self, why=''):
        """Everything read again from the database: the settings and the
        directories. One at a time (1.0.94): a save on the pages and the
        loop's own both did it at once."""
        with self.RELOAD_LOCK:
            return self._reload_all(why)

    def _reload_all(self, why=''):
        # The mark of the change read before the settings (1.0.234): read after them, a change
        # made on the other node meanwhile was taken as read - and never loaded.
        serial = self.store.get_meta('conf_serial', '0')
        # The settings that reach root as signed only, with the guard on (1.0.231).
        load_config(saved=dbguard_settings(self.store.settings_saved(), self.store))
        self.reload_directories()
        if self.shipper:
            self.shipper.configure()
        if self.siem:
            self.siem.configure()
        self.conf_serial = serial
        self.conf_loaded_at = time.time()
        if why:
            log('read the configuration again (%s)' % why)

    def changed(self, what=''):
        """Something the other processes (the command line) must notice."""
        try:
            # A mark of its own, not a count: two nodes counting up at the
            # same moment would write the same number, and neither would
            # see that the other changed something. (1.0.14)
            mark = '%.6f:%s' % (time.time(), node_name())
            self.store.set_meta('conf_serial', mark)
            self.conf_serial = mark
            self.conf_loaded_at = time.time()
        except Exception:
            pass
        if what in ('directories', 'all'):
            self.reload_directories()

    # ---- settings ---------------------------------------------------------------
    def cluster_nodes(self):
        try:
            return [n['name'] for n in ha_nodes(self.store)]
        except Exception:                               # noqa: BLE001
            return [node_name()]

    def save_settings(self, changes, by='', node=None, drawn_by=None, keep_session=None):
        checked = {}
        was_2fa = bool(CONFIG.get('admin_2fa'))
        # The page's boxes were drawn by one node and the save reached
        # another through the VIP address (1.0.110): acme1 took acme2's name
        # from a page acme2 had drawn. What belongs to one machine is saved
        # only on the machine the page was drawn by.
        drawn_by = str(drawn_by or '').strip()
        if drawn_by and drawn_by != node_name():
            local = sorted(k for k in (changes or {}) if k in FILE_ONLY_KEYS and
                           not (k in SECRET_KEYS and is_masked(changes[k])))
            if local:
                raise NodeMoved('this page was drawn by %s, but %s answers now (the VIP address '
                                'moved): %s belongs to one machine, so nothing was saved - load '
                                'the page again' % (drawn_by, node_name(), ', '.join(local)))
            if node is None:
                node = drawn_by
        # In a cluster a node's own settings go to that node alone (1.0.37).
        many = bool(CONFIG.get('ha_mode')) or len(self.cluster_nodes()) > 1
        node = str(node or node_name())
        # '*': the cluster's own value of a node's setting (1.0.67) - the one
        # every node takes that has none of its own. It could not be changed
        # from the pages at all in a cluster.
        cluster_wide = node == '*'
        if cluster_wide:
            node = node_name()
        if node not in self.cluster_nodes() + [node_name()]:
            raise BadSetting('there is no node %s' % node)
        # A secret kept goes to the server it was given for only (1.0.207): saved as
        # its dots with another server beside it, it was sent there - in clear with
        # TLS off - while nobody had seen more than its last two letters.
        for secret_key, where in SECRET_GOES_TO.items():
            if not CONFIG.get(secret_key):
                continue
            given = (changes or {}).get(secret_key)
            if given is not None and not is_masked(given):
                continue                    # a new one typed in, or taken away
            moved = [k for k in where if k in (changes or {}) and
                     str((changes or {})[k]).strip() != str(CONFIG.get(k) if CONFIG.get(k) is not None
                                                            else '').strip()]
            if moved:
                raise BadSetting('%s changed: type %s again' % (
                    ', '.join(moved), str(NAMES.get(secret_key, secret_key)).lower()))
        for key, value in (changes or {}).items():
            if key in SECRET_KEYS and is_masked(value):
                continue
            checked[key] = check_setting(key, value)
            # A secret kept in the database is sealed with this installation's
            # key (1.0.20): a copy of the database alone does not give it away.
            if key in SEALED_KEYS and checked[key]:
                checked[key] = seal_secret(checked[key])
        hisec_guard_settings(self.store, checked)        # 1.0.168
        if any(k in checked for k in ('web_proxy', 'web_proxy_from')):
            # Never on without the balancers named (otp 1.0.237): the header of anybody would be
            # the client's address - the sign-in pause and the allow lists fooled by one line.
            after = dict(CONFIG)
            after.update(checked)
            if after.get('web_proxy') and not str(after.get('web_proxy_from') or '').split():
                raise BadSetting('behind a load balancer or WAF: say which addresses are the '
                                 'balancers first (The load balancers and WAFs)')
        if any(k in checked for k in ('portal_sso', 'portal_sso_from', 'portal_sso_key')):
            # Signed in by the balancer only from the balancers, with the key (otp 1.0.239): on
            # without either, a header of anybody's would have been a sign-in.
            after = dict(CONFIG)
            after.update(checked)
            if after.get('portal_sso'):
                if not str(after.get('portal_sso_from') or '').split():
                    raise BadSetting('signed in by the load balancer: say which addresses are the '
                                     'balancers first (The balancers that sign people in)')
                if not unseal_secret(str(after.get('portal_sso_key') or '')):
                    raise BadSetting('signed in by the load balancer: make the key first (Make a key)')
        if any(k in checked for k in PORTAL_CODE_KEYS):
            # The code at every sign-in only with a way to send it (as otp 1.0.228): switched on
            # without one, or the mail or the SMS switched off under it, nobody could sign in.
            after = dict(CONFIG)
            after.update(checked)
            why = portal_code_problem(after)
            if why:
                raise BadSetting(why)
        if 'node_name' in checked:
            taken = node_name_taken(self.store, checked['node_name'])
            if taken:
                raise BadSetting('node_name: %s is the name of another node (%s, answering now) - '
                                 'two machines with one name look like one, and the other as '
                                 'gone' % (checked['node_name'], taken.get('address') or '?'))
        if checked.get('split_prefer'):
            # A node of this cluster (1.0.19), as the card asks: one named that is not
            # (`acme --set`, a file read back) made neither node the preferred one - with
            # "priority" both stepped aside while apart.
            names = [n['name'] for n in ha_nodes(self.store)] or [node_name()]
            if checked['split_prefer'] not in names:
                raise BadSetting('split_prefer: there is no node called %s'
                                 % checked['split_prefer'])
        if 'clock_warn_s' in checked or 'clock_aside_s' in checked:
            # Stepping aside comes after the warning (1.0.21, as the card asks).
            w = int(checked.get('clock_warn_s', CONFIG.get('clock_warn_s') or 2))
            a = int(checked.get('clock_aside_s', CONFIG.get('clock_aside_s') or 20))
            if a <= w:
                raise BadSetting('clock_aside_s: stepping aside comes after the warning - more '
                                 'seconds than clock_warn_s (%d)' % w)
        file_side = {k: v for k, v in checked.items() if k in FILE_ONLY_KEYS}
        if file_side and node != node_name() and not cluster_wide:
            raise NodeMoved('%s belongs to the machine %s and is saved on it (its own address), '
                            'not from %s' % (', '.join(sorted(file_side)), node, node_name()))
        db_side = {k: v for k, v in checked.items() if k not in FILE_ONLY_KEYS}
        saved_now = self.store.settings_saved()
        # The proxy's uses kept as rows of their own, off too (1.0.206): a 0 equal
        # to the default was dropped, and the setting of before 1.0.202 that
        # keeps a proxy on for the updates switched them on again at once. The
        # proxy switched on now: its uses as they are set, off unless said.
        if 'proxy' in db_side:
            for k in ('proxy_update', 'proxy_os'):
                if k not in saved_now and k not in db_side:
                    db_side[k] = int(CONFIG.get(k) or 0) if not db_side.get('proxy') else 0
        for k, v in db_side.items():
            if k in NODE_KEYS and many and not cluster_wide:
                shared = saved_now.get(k, FILE_CONFIG.get(k, DEFAULTS[k]))
                if v == shared:
                    self.store.drop_setting(k + '@' + node)
                else:
                    self.store.save_setting(k + '@' + node, v, by)
                continue
            # Kept as rows off too (otp 1.0.238): "switched off" is what takes acme's lines out
            # of nginx again - a 0 equal to the default was dropped, and read as "never
            # switched on", the balancer's lines stayed.
            if v == FILE_CONFIG.get(k, DEFAULTS[k]) and k not in KEPT_OFF_KEYS:
                self.store.drop_setting(k)
            else:
                self.store.save_setting(k, v, by)
        SAVED_KEYS['at'] = 0.0          # read again by the web state (otp 1.0.239)
        said = []
        if 'db_guard' in file_side:
            said += self.dbguard_switch(bool(file_side.pop('db_guard')), by)
        if file_side:
            if any(k in DB_KEYS for k in file_side) and (
                    file_side.get('db_engine', CONFIG.get('db_engine')) != 'sqlite' or
                    CONFIG.get('db_engine') != 'sqlite'):
                test = dict(CONFIG)
                test.update(file_side)
                try:
                    probe = open_db(test)
                    probe.make_tables()
                    probe.close()
                except Exception as e:
                    raise BadSetting('the database could not be used, so nothing was '
                                     'changed: %s' % e)
            write_file_settings(file_side)
            said.append('the database settings go into %s and take effect when the service '
                        'is restarted (systemctl restart acme)' % CONFIG_FILE)
        # Who may sign in from the directory changed (1.0.33): everybody
        # signed in from it is signed out, so their role is decided again by
        # the groups as they are now - not kept until their session ends.
        if any(k in checked for k in ('admin_directory', 'admin_group_full',
                                      'admin_group_cert', 'admin_group_readonly',
                                      'admin_group_portal')):
            try:
                self.store.db.run(
                    "DELETE FROM sessions WHERE kind = 'admin' AND LOWER(name) IN "
                    "(SELECT LOWER(name) FROM accounts WHERE source = 'directory')")
            except Exception as e:                      # noqa: BLE001
                log('the directory sign-ins could not be ended: %s' % e, 'warn')
        if checked:
            self.store.add_event('settings', 'changed: %s' % ', '.join(
                '%s%s=%s' % (k, ('@' + node) if (k in NODE_KEYS and many and not cluster_wide)
                             else '',
                         '***' if k in SECRET_KEYS else json.dumps(v, ensure_ascii=False))
                for k, v in sorted(checked.items())), who=by)
        if not was_2fa and CONFIG.get('admin_2fa'):
            # The second step for those signed in already too (1.0.149): their
            # sessions, opened with the password alone, stayed whole for hours.
            # The one saving it stays - it is how it was switched on. Here, not
            # on the pages only (1.0.187): from the command line and the console
            # they all stayed.
            try:
                gone = self.store.db.run('DELETE FROM sessions WHERE kind = ? AND id <> ?',
                                         ('admin', int(keep_session or 0)))
                if gone:
                    self.store.add_event('accounts', 'the second step was switched on: %d other '
                                         'sign-in(s) to the pages ended' % gone, 'warn', who=by)
            except Exception as e:                      # noqa: BLE001
                log('the sign-ins to the pages could not be ended: %s' % e, 'warn')
        self.changed('settings')
        self.reload_all()
        return {'message': ' '.join(['%d setting(s) saved.' % len(checked)] + said),
                'saved': sorted(checked)}

    def settings_state(self, may_change=True):
        out = []
        saved = self.store.settings_saved()
        written = self.store.settings_written()
        for key in DEFAULTS:
            if key in ('ha_mode', 'ha_slot', 'ha_peer', 'ha_peer_port', 'ha_address', 'ha_tls',
                       'ha_tls_ca'):
                continue                    # the cluster's own wiring, set by its wizard
            if key in CARD_DRAWN:
                # Its own card on High availability (1.0.14, as otp 1.0.219): drawn as boxes
                # of the pane they were drawn again, the card's rules (try the arbiter first)
                # aside.
                continue
            value = CONFIG.get(key)
            shape = TUNABLE.get(key)
            source = 'saved' if key in saved else ('file' if key in FILE_KEYS else 'default')
            one = {'key': key, 'value': value, 'default': DEFAULTS[key],
                   'name': NAMES.get(key, key), 'says': SAYS.get(key, ''),
                   'short': SAYS_SHORT.get(key, ''),
                   'secret': key in SECRET_KEYS, 'source': source,
                   'source_says': {'saved': 'saved on these pages',
                                   'file': 'from config.json',
                                   'default': 'the built-in default'}[source],
                   'in_file': key in FILE_KEYS,
                   'file': FILE_CONFIG.get(key) if key in FILE_KEYS else None,
                   'file_only': key in FILE_ONLY_KEYS,
                   'node_key': key in NODE_KEYS, 'hisec': hisec_ui(key),
                   # Several lines (1.0.19): a PEM or the records of the DNS server
                   # typed into a box of one line lost their line breaks.
                   'tall': key in SETTING_TALL}
            if key in NODE_KEYS:
                one['per_node'] = {k.split('@', 1)[1]: v for k, v in saved.items()
                                   if k.startswith(key + '@')}
                one['shared'] = saved.get(key, FILE_CONFIG.get(key, DEFAULTS[key]))
                if key + '@' + node_name() in saved:
                    one['source'], one['source_says'] = 'node', 'saved for this node'
            if key in written:
                one['saved_at'] = written[key]['at']
                one['saved_by'] = written[key]['by']
            if key in SECRET_KEYS:
                # Dots and the last two to a full administrator, dots alone to
                # anybody else - never in clear, nor in what sits beside it.
                plain = unseal_secret(value) if key in SEALED_KEYS else value
                one['value'] = (secret_shown(plain or '', last=may_change) or
                                secret_shown('x', last=False)) if value else ''
                one['set'] = bool(value)
                one['file'] = None
                one['default'] = secret_shown(DEFAULTS[key] or '', last=False)
                for k in ('shared',):
                    if one.get(k):
                        one[k] = secret_shown('x', last=False)
                if one.get('per_node'):
                    one['per_node'] = {n: secret_shown('x', last=False) if v else ''
                                       for n, v in one['per_node'].items()}
            if isinstance(shape, tuple) and shape and isinstance(shape[0], str):
                one['choices'] = list(shape)
                if key in CHOICE_WORDS:
                    one['choice_words'] = CHOICE_WORDS[key]
            elif isinstance(shape, tuple):
                one['min'], one['max'] = shape
            out.append(one)
        return out

    # ---- what it is doing ------------------------------------------------------
    def status(self):
        """What the daemon says of itself (GET /api/status): the engine's own -
        the node, the database, the cluster, maintenance, what is wrong. A
        module's numbers come from its own routes (and its `status` hook for
        acme --status)."""
        ev = self.store.db.value('SELECT MAX(id) AS n FROM events', (), 0) or 0
        problems = []
        sh = self.shipper.state() if self.shipper else {}
        if sh.get('on') and not sh.get('targets'):
            problems.append('sending to isemon is on and nowhere to send to is set')
        if sh.get('trouble'):
            problems.extend('isemon %s: %s' % kv for kv in sorted(sh['trouble'].items()))
        si = self.siem.state() if self.siem else {}
        if si.get('trouble'):
            problems.extend('syslog %s: %s' % kv for kv in sorted(si['trouble'].items()))
        if not sealing_key() and sealed_held(self.store.db):
            problems.append('the key that opens the sealed secrets and private keys (%s) is '
                            'missing: put it back from beside a backup' % sealing_key_path())
        if name_clash_words():
            problems.insert(0, name_clash_words())
        try:
            if ntp_problem():
                problems.append(ntp_problem())
        except Exception:                               # noqa: BLE001
            pass
        try:
            trials = trials_view(self.store)
        except Exception:                               # noqa: BLE001
            trials = []
        try:
            attention = hand_all(self.store)
        except Exception:                               # noqa: BLE001
            attention = []
        started = self.started
        if not self.serving:
            # The command line asks (1.0.45): the daemon's start, from its heartbeat - not the
            # command's own (an uptime of 0.0004 s).
            try:
                started = float((_meta_obj(self.store, 'node:' + node_name())).get('started')
                                or 0) or None
            except (TypeError, ValueError):
                started = None
        return {
            'ok': True, 'version': __version__, 'site': CONFIG.get('site_name') or short_host(),
            'host': socket.gethostname(), 'started': started,
            'uptime': (time.time() - started) if started else None, 'now': time.time(),
            'isemon': sh, 'directories': len(self.dirs),
            'serial': '%s' % ev, 'problems': problems,
            'attention': attention,
            'database': {'engine': self.store.db.engine, 'where': self.store.db.where()},
            'lang': CONFIG.get('ui_lang') or 'cs', 'php': php_state(),
            'high_security': bool(CONFIG.get('high_security')),
            'hisec_waived': sorted(hisec_waived(self.store)),
            'node': node_name(),
            'nodes': [{'name': n['name'], 'alive': n['alive'], 'age': n['age'],
                       'version': n.get('version')} for n in ha_nodes(self.store)],
            # The overview's second row of cards (1.0.37): this server, the
            # cluster, the database, maintenance.
            'maintenance': maintenance_now(self.store),
            'maint_nodes': [n['name'] for n in ha_nodes(self.store)
                            if n.get('alive') and maintenance_row(self.store, n['name']).get('on')],
            'replication': self._repl_summary(),
            'db': self._db_summary(),
            'upgrade': self._upgrade_summary(),
            'trials': trials,
        }

    def _repl_summary(self):
        if CONFIG.get('ha_mode') != 'replicated':
            return {'mode': CONFIG.get('ha_mode') or ''}
        try:
            r = ha_repl_state(self.store)
            return {'mode': 'replicated', 'healthy': bool(r.get('healthy')),
                    'lost': bool(r.get('lost')), 'trouble': r.get('trouble') or '',
                    'behind': max([int(x.get('behind') or 0) for x in r.get('outgoing') or []]
                                  or [0])}
        except Exception as e:                          # noqa: BLE001
            return {'mode': 'replicated', 'healthy': False, 'trouble': str(e)[:200]}

    DB_SUMMARY = {'at': 0, 'got': {}}

    def _db_summary(self):
        if time.time() - self.DB_SUMMARY['at'] > 60:
            got = {'engine': self.store.db.engine, 'where': self.store.db.where()}
            try:
                got['size'] = self.store.db.size()
            except Exception:                           # noqa: BLE001
                got['size'] = None
            try:
                kept = backups()
                got['backups'] = len(kept)
                # The nightly dumps count as a copy too (1.0.59): they are
                # kept in their own folder, and only the copies were looked at.
                try:
                    kept = kept + kept_dumps(self.store.db.engine)
                except Exception:                       # noqa: BLE001
                    pass
                got['last_backup'] = max([float(b.get('at') or b.get('mtime') or 0)
                                          for b in kept] or [0]) or None
            except Exception:                           # noqa: BLE001
                pass
            got['key_there'] = bool(sealing_key())
            # Why the card is not green (1.0.39), said under it as well.
            try:
                ns = nightly_state(self.store)
                got['nightly_why'] = ns['why']
                got['nightly_on'] = ns['on']
            except Exception:                           # noqa: BLE001
                pass
            self.DB_SUMMARY.update(at=time.time(), got=got)
        return self.DB_SUMMARY['got']

    def _upgrade_summary(self):
        try:
            plan = upgrade_plan(self.store)
            pkg = json.loads(self.store.get_meta('upgrade:pkg') or 'null')
        except Exception:                               # noqa: BLE001
            return {}
        return {'plan': {'state': plan['state'], 'version': plan['version']} if plan else None,
                'package': pkg['version'] if pkg else None}

    # ---- running -------------------------------------------------------------------
    def run(self):
        NAME_HELD[0] = True                 # a new node_name waits for the next start (1.0.206)
        log('acme %s starting: the database is %s' % (__version__, self.store.db.where()))
        try:
            downgrade_floor_note(self.store)        # how far back it may go (1.0.143)
        except Exception as e:                      # noqa: BLE001
            log('the floor for going back could not be written: %s' % e, 'warn')
        stale_work_away()
        if not sealing_key():
            # A database that already holds sealed secrets gets no new key in
            # place of a missing one (1.0.33): the secrets would stay lost, and
            # on two nodes each would seal with a key of its own.
            if sealed_held(self.store.db):
                log('%s is missing, and the database holds secrets sealed with it: no new '
                    'key is made. Put the key back (it is beside every backup), or the private '
                    'keys and passwords kept cannot be opened.' % sealing_key_path(), 'error')
                self.store.add_event('starting and stopping', 'the key that opens the sealed '
                                     'secrets is missing: %s' % sealing_key_path(), 'bad')
            else:
                sealing_key(make=True)
        if CONFIG.get('ha_mode') == 'replicated':
            # The other node's tables given the columns this version adds
            # (1.0.76): logical replication sends every column of a row, and
            # one the other node does not have yet stopped what goes to it
            # until it was upgraded too. Old code there never reads them.
            threading.Thread(target=ha_peer_columns, name='peer-columns', daemon=True).start()
        self.api = ApiServer(self)
        self.api.start()
        for fn in HOOKS['daemon_start']:
            try:
                fn(self)
            except Exception as e:                      # noqa: BLE001
                log('a module did not start: %s: %s\n%s' % (getattr(fn, '__qualname__', fn), e,
                                                         traceback.format_exc()), 'error')
        HA_STORE['store'] = self.store
        node_name_check(self.store)             # renamed since the last start? (1.0.48)
        try:
            self._pwp_at = time.time()
            pwp_migrate(self.store)             # acme 1.0.42's password policy taken over (1.0.43)
        except Exception as e:                  # noqa: BLE001
            log('the password policy of acme 1.0.42 could not be taken over: %s' % e, 'warn')
        try:
            dbguard_adopt(self.store)           # rows newly under the guard (1.0.44)
        except Exception as e:                  # noqa: BLE001
            log('the guard could not take its new rows: %s' % e, 'warn')
        try:
            machine_changed_check(self.store)   # another machine under this name? (1.0.43)
        except Exception as e:                  # noqa: BLE001
            log('the machine of this node could not be compared: %s' % e, 'warn')
        self.store.add_event('starting and stopping', 'acme %s started on %s'
                             % (__version__, node_name()))
        try:
            heartbeat(self.store, self)
        except Exception as e:                          # noqa: BLE001
            log('the heartbeat could not be written: %s' % e, 'warn')
        last_beat = time.monotonic()    # a clock stepped back stops nothing (1.0.94)
        maintenance_ensure(self.store)

        # The outgoing mail (1.0.95): what was not taken yet, tried again.
        def mail_queue():
            while not self.stop_flag.wait(10):
                if HA_REBUILDING.is_set():
                    continue
                try:
                    mailq_tick(self.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('mail-queue', 'the outgoing mail: %s' % e, 'warn', every=300)
        threading.Thread(target=mail_queue, name='mail-queue', daemon=True).start()
        # The cluster's VIP address: whether this node may hold it (1.0.47).
        threading.Thread(target=vip_watch, args=(self,), name='vip-watch', daemon=True).start()
        # A connection on this machine broken by its TLS mended (1.0.170) -
        # its own thread: the loop below waits for the database.
        threading.Thread(target=dbtls_watch, args=(self,), name='dbtls-watch', daemon=True).start()
        try:
            upgrade_tick(self)
        except Exception as e:                          # noqa: BLE001
            log_sparing('tick:upgrade:' + str(e)[:80], 'the upgrade: %s' % e, 'warn', 3600)
        signal.signal(signal.SIGTERM, lambda *_: self.stop_flag.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop_flag.set())
        # Only noted in the handler (1.0.94): read again in this loop, not in
        # the middle of whatever the main thread was doing - a log line
        # holding its lock, a query on the connection - every night when
        # logrotate reloads.
        self.hup_asked = HUP_ASKED
        try:
            self.conf_sig = hashlib.sha256(CONFIG_FILE.read_bytes()).hexdigest()
        except OSError:
            self.conf_sig = None
        signal.signal(signal.SIGHUP, self._hup_signal)
        last_tidy = time.monotonic() - 3601
        last_backup_day = self.store.get_meta('backup_day', '')
        while not self.stop_flag.wait(5):
            dbguard_flush()                             # the counters seen (1.0.231)
            if run_dir_keep():                          # 1.0.232
                log('/run/acme was given back to acme:acme (systemctl reload?) - readable by the pages again',
                    'warn')
            if self.hup_asked.is_set():
                self.hup_asked.clear()
                self._hup()
            if HA_REBUILDING.is_set():
                continue                # nothing of its own written meanwhile (1.0.44)
            try:
                # Each on its own (1.0.136): one of these breaking skipped
                # everything after it - the backups, the time, the tidying -
                # with a traceback every 5 s.
                try:
                    if time.monotonic() - last_beat >= HEARTBEAT_S:
                        last_beat = time.monotonic()
                        heartbeat(self.store, self)
                    elif CONFIG.get('ha_mode'):
                        try:
                            fw_now_publish(self.store)  # asked by the other node (1.0.71)
                        except Exception:               # noqa: BLE001
                            pass
                except DbError:
                    raise
                except Exception as e:                  # noqa: BLE001
                    log_sparing('heartbeat-tick', 'the heartbeat: %s\n%s' % (
                        e, traceback.format_exc()), 'error', every=600)
                try:
                    beat_now = False
                    if self.store.get_meta('conf_serial', '0') != self.conf_serial:
                        self.reload_all('changed elsewhere')
                        beat_now = True     # said at once (1.0.42): the cards wait for it
                    asked = beat_asked_last(self.store)
                    try:
                        load_peer_tick(self.store)      # the meter of another node's pages (1.0.48)
                    except DbError:
                        raise
                    except Exception as e:              # noqa: BLE001
                        log_sparing('load-peer', 'the performance meter: %s' % e, 'warn', every=3600)
                    try:
                        hand_tick(self.store)           # what waits for a person (1.0.54)
                        if time.time() - getattr(self, '_pwp_at', 0) > 600:
                            # Not at the start alone (1.0.62): in a replicated pair one node
                            # takes it over, once it hears the other (ha_lead_heard).
                            self._pwp_at = time.time()
                            pwp_migrate(self.store)
                    except DbError:
                        raise
                    except Exception as e:              # noqa: BLE001
                        log_sparing('hand-tick', 'what waits for a person: %s' % e, 'warn', every=3600)
                    if asked != self.beat_asked_seen:
                        # Asked from a card of Settings (its refresh): what this node has, now.
                        self.beat_asked_seen = asked
                        beat_now = True
                    if beat_now and CONFIG.get('ha_mode'):
                        last_beat = time.monotonic()
                        heartbeat(self.store, self)
                except DbError:
                    raise
                except Exception as e:                  # noqa: BLE001
                    log_sparing('reload-tick', 'reading the settings again: %s\n%s' % (
                        e, traceback.format_exc()), 'error', every=600)
                try:
                    upgrade_tick(self)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('tick:upgrade:' + str(e)[:80], 'the upgrade: %s' % e, 'warn', 3600)
                try:
                    web_tick(self.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('tick:web:' + str(e)[:80], 'TLS and the VIP address: %s' % e, 'warn', 3600)
                try:
                    rb_tick(self)               # backups to the destinations (1.0.109)
                except Exception as e:          # noqa: BLE001
                    log_sparing('rbackup-tick', 'the scheduled backup: %s' % e, 'warn', every=600)
                if CONFIG.get('ha_mode') == 'replicated':
                    try:
                        hatls_tick(self.store)  # the link between the databases (1.0.104)
                    except Exception as e:      # noqa: BLE001
                        log_sparing('hatls-tick', 'the link between the databases: %s' % e,
                                    'warn', every=600)
                    try:
                        readdress_dropold_tick(self.store)  # a new address kept (1.0.137)
                    except Exception as e:      # noqa: BLE001
                        log_sparing('dropold-tick', 'the other node\'s old address: %s' % e,
                                    'warn', every=600)
                    # In a thread of its own (1.0.205): it waits up to a minute on the
                    # root helper, and the heartbeat waited with it - the other
                    # node took this one for gone.
                    def readdress(daemon=self):
                        try:
                            readdress_tick(daemon.store, daemon)    # told a new address (1.0.106)
                        except Exception as e:      # noqa: BLE001
                            log_sparing('tick:readdress:' + str(e)[:80],
                                        'a new address of the cluster: %s' % e, 'warn', 3600)
                    self.background('readdress', readdress)
                try:
                    online_tick(self)           # a new version on the web (1.0.123)
                except Exception as e:          # noqa: BLE001
                    log_sparing('online-tick', 'a new version: %s' % e, 'warn', every=3600)
                try:
                    fw_trial_tick(self.store)   # a firewall change not kept (1.0.137)
                except Exception as e:          # noqa: BLE001
                    log_sparing('fw-trial-tick', 'the firewall on trial: %s' % e, 'warn',
                                every=600)
                try:
                    ntp_tick(self)              # the time (1.0.120)
                except Exception as e:          # noqa: BLE001
                    log_sparing('ntp-tick', 'the time: %s' % e, 'warn', every=600)
                try:
                    console_login_tick(self)    # the console at login (1.0.141)
                except Exception as e:          # noqa: BLE001
                    log_sparing('console-tick', 'the console at login: %s' % e, 'warn',
                                every=600)
                try:
                    selinux_tick(self)          # SELinux of this node (as otp 1.0.233)
                except Exception as e:          # noqa: BLE001
                    log_sparing('selinux-tick', 'SELinux: %s' % e, 'warn', every=600)
                try:
                    sshkeys_tick(self)          # root's SSH keys (1.0.158)
                except Exception as e:          # noqa: BLE001
                    log_sparing('sshkeys-tick', 'root\'s SSH keys: %s' % e, 'warn', every=600)
                try:
                    osroots_tick(self)          # the system's trusted roots (1.0.59)
                except Exception as e:          # noqa: BLE001
                    log_sparing('osroots-tick', 'the system\'s trusted roots: %s' % e, 'warn',
                                every=600)
                try:
                    osu_tick(self)              # the local users of the machines (1.0.243)
                except Exception as e:          # noqa: BLE001
                    log_sparing('osu-tick', 'the local users: %s (%s)' % (e, where_it_broke()),
                                'warn', every=600)
                try:
                    osup_sched_tick(self)      # updates and restarts on a schedule (1.0.164)
                except Exception as e:          # noqa: BLE001
                    log_sparing('osup-sched', 'the schedule of updates: %s' % e, 'warn', every=600)
                try:
                    node_ask_tick(self)         # tests asked of every node (1.0.169)
                except Exception as e:          # noqa: BLE001
                    log_sparing('node-ask', 'a test asked of every node: %s' % e, 'warn', every=600)
                try:
                    acme_tick(self)             # certificates by ACME (1.0.169)
                except Exception as e:          # noqa: BLE001
                    log_sparing('acme-tick', 'ACME: %s' % e, 'warn', every=600)
                try:
                    isemon_tls_tick(self)       # isemon over TLS (1.0.172)
                except Exception as e:          # noqa: BLE001
                    log_sparing('isemon-tls-tick', 'isemon over TLS: %s' % e, 'warn', every=600)
                try:
                    dbtls_tick(self)            # the connection to the database (1.0.170)
                except Exception as e:          # noqa: BLE001
                    log_sparing('dbtls-tick', 'the encryption to the database: %s' % e, 'warn',
                                every=600)
                try:
                    sshd_tick(self)             # the SSH server and the notices (1.0.163)
                except Exception as e:          # noqa: BLE001
                    log_sparing('sshd-tick', 'the SSH server: %s' % e, 'warn', every=600)
                try:
                    split_tick(self)            # the nodes losing each other (1.0.14)
                except Exception as e:          # noqa: BLE001
                    log_sparing('split-tick', 'watching the other node: %s' % e, 'warn', every=600)
                try:
                    clock_tick(self)            # the clocks of the nodes (1.0.21)
                except Exception as e:          # noqa: BLE001
                    log_sparing('clock-tick', 'watching the clocks: %s' % e, 'warn', every=600)
                try:
                    alerts_tick(self)           # alerts by mail, the report (1.0.162)
                except Exception as e:          # noqa: BLE001
                    log_sparing('alerts-tick', 'the alerts: %s' % e, 'warn', every=600)
                try:
                    osup_tick(self)             # the updates of the system (1.0.158)
                except Exception as e:          # noqa: BLE001
                    log_sparing('osup-tick', 'the update of the system: %s' % e, 'warn',
                                every=600)
                try:
                    net_tick(self)              # the network, restart, power off (1.0.119)
                except Exception as e:          # noqa: BLE001
                    log_sparing('net-tick', 'the network: %s' % e, 'warn', every=600)
                try:
                    lockouts_tick(self)         # who is locked out, for the pages (1.0.112)
                except Exception as e:          # noqa: BLE001
                    log_sparing('lockouts-tick', 'the list of who is locked out: %s' % e,
                                'warn', every=600)
                try:
                    ha_watch_tick(self.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('tick:ha_watch:' + str(e)[:80], 'the cluster\'s history: %s' % e, 'warn', 3600)
                if time.monotonic() - last_tidy > 3600:
                    last_tidy = time.monotonic()
                    # In a thread of its own (1.0.57): long directory lookups
                    # and a big first tidy held the heartbeat back, and the
                    # other node took this one for gone.
                    self.background('tidy', self.hourly)
                if CONFIG.get('backup_daily'):
                    today = datetime.now().strftime('%Y-%m-%d')
                    # 3:30 is 03:30 (1.0.44): compared as numbers, not as text.
                    try:
                        hh, mm = (int(x) for x in str(CONFIG.get('backup_at') or '03:30')
                                  .strip().split(':', 1))
                    except ValueError:
                        hh, mm = 3, 30
                    nw = datetime.now()
                    if today != last_backup_day and (nw.hour, nw.minute) >= (hh, mm):
                        # One node of a cluster makes it: the one whose
                        # conditional UPDATE took the day. (1.0.13) The day
                        # counts as done only once that was asked (1.0.94):
                        # a database away just then lost the day's copy.
                        mine = claim_once(self.store, 'backup_day' + (
                            ':' + node_name() if CONFIG.get('ha_mode') == 'replicated' else ''),
                            today)
                        last_backup_day = today
                    else:
                        mine = False
                    if mine:
                        self.background('dump', self.nightly)
            except DbError as e:
                # The database away is said once in a while, not with a
                # traceback every 5 seconds (1.0.59).
                log_sparing('housekeeping-db', 'housekeeping waits for the database: %s'
                            % str(e).split('\n')[0][:200], 'error', every=60)
            except Exception as e:
                log('housekeeping broke: %s\n%s' % (e, traceback.format_exc()), 'error')
        self.stop()

    def stop(self):
        """Going down: the modules told first (daemon_stop), while the
        database and the API are still there; then the lines waiting for
        isemon and the SIEM sent, and the API closed."""
        for fn in HOOKS['daemon_stop']:
            try:
                fn(self)
            except Exception as e:                      # noqa: BLE001
                log('a module did not stop cleanly: %s: %s\n%s' % (
                    getattr(fn, '__qualname__', fn), e, traceback.format_exc()), 'error')
        try:
            self.store.add_event('starting and stopping', 'acme stopped on %s' % node_name())
        except Exception:                               # noqa: BLE001
            pass                # the database away: the rest still stops cleanly (1.0.94)
        if self.shipper:
            self.shipper.flush()
        if self.siem:
            self.siem.flush()
        if self.api:
            self.api.stop()

    def background(self, name, fn):
        """`fn` in a thread of its own, never two of one name at once."""
        busy = getattr(self, '_bg', None)
        if busy is None:
            busy = self._bg = {}
        t = busy.get(name)
        if t is not None and t.is_alive():
            return
        t = threading.Thread(target=fn, name='acme-' + name, daemon=True)
        busy[name] = t
        t.start()

    def reader(self):
        """The database as the pages' long lists read it (1.0.101): the Log
        searched over months, the suggestions under a search box - on a
        connection of their own, with a limit of 20 s a statement. On the one
        the daemon shares, four such searches at once held it for seconds and
        the health check failed."""
        main = self.store.db
        if main.engine == 'sqlite':
            return self.store
        with self._reader_lock:
            r = self._reader
            if r is not None and r.db.where() != main.where():
                try:
                    r.db.close()
                except Exception:                       # noqa: BLE001
                    pass
                r = self._reader = None
            if r is None:
                try:
                    r = self._reader = Storage.view(
                        db_open({k: CONFIG.get(k) for k in DB_KEYS}, statement_s=20))
                except Exception as e:                  # noqa: BLE001
                    log_sparing('reader-db', 'the lists of the pages read through the shared '
                                'connection: their own could not be opened (%s)'
                                % str(e).split('\n')[0][:200], 'warn')
                    return self.store
            return r

    def _hup_signal(self, *_):
        # The token readable by the pages again at once (1.0.232): systemd gave /run/acme to
        # acme:acme just before it sent this (systemctl reload), and the loop below sees the
        # signal only up to 5 s later - the VIP address had already gone.
        try:
            run_dir_keep()
        except Exception:                               # noqa: BLE001
            pass
        self.hup_asked.set()

    def hourly(self):
        if CONFIG.get('ha_mode') == 'replicated' and self.store.db.engine == 'postgres':
            try:
                ha_sequences_check(self.store.db, int(CONFIG.get('ha_slot') or 1))
            except Exception as e:                      # noqa: BLE001
                log('the numbering of the tables could not be checked: %s' % e, 'warn')
            # The other node's columns again (1.0.94): tried once at start, a
            # peer away just then kept replication to it stalled until its
            # own upgrade. Adding what is there already does nothing.
            ha_peer_columns()
            # A table the other node has and this node's subscription does
            # not take yet - one a later version added, the two nodes
            # upgraded by hand - taken from now on (1.0.101).
            try:
                db = self.store.db
                sub = ha_sub_here(db, 3 - int(CONFIG.get('ha_slot') or 1))
                if sub and int(db.value('SELECT COUNT(*) FROM pg_subscription_rel r JOIN '
                                        'pg_subscription s ON s.oid = r.srsubid WHERE '
                                        's.subname = ?', (sub,)) or 0) < len(TABLES):
                    db.run(RawSql('ALTER SUBSCRIPTION %s REFRESH PUBLICATION WITH '
                                  '(copy_data = false)' % sub))
            except Exception as e:                      # noqa: BLE001
                log('the tables taken from the other node could not be read again: %s'
                    % str(e).split('\n')[0][:200], 'info')
        try:
            dbguard_tidy(self.store)                    # signatures of sign-ins over (1.0.231)
        except Exception:                               # noqa: BLE001
            pass
        try:
            node_asks_of_gone_tidy(self.store)          # asks for nodes forgotten (1.0.46)
        except Exception:                               # noqa: BLE001
            pass
        try:
            once_tidy(self.store)                       # used once, long ago (1.0.101)
        except Exception as e:                          # noqa: BLE001
            log('the codes used once could not be tidied: %s' % e, 'warn')
        try:
            adpw_tidy(self.store)                       # wrong directory passwords, over
        except Exception as e:                          # noqa: BLE001
            log('the counts of wrong directory passwords could not be tidied: %s' % e, 'warn')
        try:
            sshotp_fails_tidy(self.store)               # wrong SSH codes, over (1.0.44)
        except Exception as e:                          # noqa: BLE001
            log('the counts of wrong SSH codes could not be tidied: %s' % e, 'warn')
        try:
            mfa_marks_adopt(self.store)                 # second steps noted (1.0.44)
        except Exception as e:                          # noqa: BLE001
            log('the second steps could not be noted on the accounts: %s' % e, 'warn')
        try:
            dbguard_adopt(self.store)                   # once every node runs 1.0.44
        except Exception as e:                          # noqa: BLE001
            log('the guard could not take its new rows: %s' % e, 'warn')
        try:
            # One node of two deletes the old rows; the deletes go over to the
            # other anyway (1.0.57).
            if CONFIG.get('ha_mode') == 'replicated' and not claim_once(
                    self.store, 'tidy_hour', time.strftime('%Y-%m-%d %H')):
                return
            gone = self.store.tidy()
            if any(gone.values()):
                log('tidied: %s' % gone)
        except Exception as e:                          # noqa: BLE001
            log('tidying broke: %s' % e, 'warn')

    def nightly(self):
        try:
            # As isemon's: the engine's own dump every night, or a portable
            # copy where its program is missing.
            make_dump(self.store, 'daily')
        except Exception as e:                          # noqa: BLE001
            self.store.add_event('backups', 'the daily dump failed: %s' % e, 'bad')
        try:
            note_size(self.store)
        except Exception:                               # noqa: BLE001
            pass

    def _hup(self):
        log_open()
        # logrotate's every night (1.0.186): the logs opened again and nothing
        # else - read again, every cache started empty and the directories
        # were made anew. config.json changed (acme --set,
        # systemctl reload after an edit): read again, as before.
        try:
            sig = hashlib.sha256(CONFIG_FILE.read_bytes()).hexdigest()
        except OSError:
            sig = None
        if sig is not None and sig == getattr(self, 'conf_sig', None):
            log('the logs opened again (SIGHUP; config.json as it was)')
            return
        self.conf_sig = sig
        try:
            self.reload_all('SIGHUP')
        except Exception as e:
            log('reading the configuration again failed: %s' % e, 'error')


# ---------------------------------------------------------------------------
# Moving to another database, looking after the one in use, tuning its
# server - the database page, as isemon has it
# ---------------------------------------------------------------------------
ENGINE_WORDS = {'sqlite': 'the file on this machine (SQLite)', 'mariadb': 'MariaDB',
                'postgres': 'PostgreSQL'}
# DB_KEYS is 00_head's (1.0.94): a second one here, without db_tls and
# db_tls_ca, left the database's TLS out of the test before a save, of the
# cluster's bundle and of the move to another database.
DB_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,62}\Z')


def file_db_settings():
    """The database settings as config.json has them now - Set it up writes
    the address and the password made there while the old database is
    still the one in use, and the steps after it must find them (1.0.37)."""
    try:
        with open(str(CONFIG_FILE), encoding='utf-8') as f:
            got = json.load(f)
        return {k: got[k] for k in DB_KEYS if k in got} if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def engine_asked(given):
    """The database the page means: what it typed, over what is set."""
    c = {k: CONFIG.get(k) for k in DB_KEYS}
    on_file = file_db_settings()
    for k, v in on_file.items():
        if k != 'db_engine':
            c[k] = v
    was = dict(c)
    kept_pw = False
    for k, v in (given or {}).items():
        if k not in DB_KEYS or v is None:
            continue
        if k == 'db_password' and is_masked(v):
            kept_pw = True
            continue
        c[k] = v
    if kept_pw and was.get('db_password') and any(
            str(c.get(k) or '') != str(was.get(k) or '')
            for k in ('db_engine', 'db_host', 'db_port', 'db_user')):
        # The password kept goes to the database it was given for only (1.0.207):
        # another server typed in was sent the one of this - asked for in clear,
        # libpq gives it.
        raise ValueError('another database server or account: type its password')
    if c.get('db_engine') not in ('sqlite', 'mariadb', 'postgres'):
        raise ValueError('the engine is sqlite, mariadb or postgres')
    for k in ('db_name', 'db_user'):
        if c['db_engine'] != 'sqlite' and not DB_IDENT.match(str(c.get(k) or '')):
            raise ValueError('%s is letters, digits and _ only, starting with a letter' % k)
    return c


def db_open(c, statement_s=None):
    return Db(c.get('db_engine') or 'sqlite', c.get('db_host') or '', c.get('db_port') or 0,
              c.get('db_name') or 'acme', c.get('db_user') or 'acme', c.get('db_password') or '',
              c.get('db_timeout_s') or 10,
              tls=c.get('db_tls') if 'db_tls' in c else CONFIG.get('db_tls'),
              tls_ca=c.get('db_tls_ca') if 'db_tls_ca' in c else CONFIG.get('db_tls_ca'),
              statement_s=statement_s, path=c.get('db_path') or None)


def db_own(store, statement_s=0):
    """A connection of its own to the database in use, for a long job
    (1.0.101): a VACUUM FULL, a check of every table - on the one every
    sign-in shares, each held them all for as long as it took. SQLite has
    one file and one connection: that one. Closed by the caller."""
    if store.db.engine == 'sqlite':
        return None
    return db_open({k: CONFIG.get(k) for k in DB_KEYS}, statement_s=statement_s)


def same_database(c, db):
    """Whether the page's database is the one in use."""
    if c.get('db_engine') != db.engine:
        return False
    if db.engine == 'sqlite':
        # The file named (1.0.210): another file is another database.
        try:
            return os.path.realpath(str(c.get('db_path') or DB_FILE)) == \
                os.path.realpath(str(db.path))
        except (OSError, TypeError, ValueError):
            return True
    port = int(c.get('db_port') or {'mariadb': 3306, 'postgres': 5432}[db.engine])
    here = {'', 'localhost', '127.0.0.1', '::1'}
    a, b = str(c.get('db_host') or '').lower(), str(db.host or '').lower()
    return ((a == b or (a in here and b in here)) and port == int(db.port or port)
            and str(c.get('db_name')) == str(db.name))


def db_try(c):
    """Reach a database as this program would. Never raises."""
    out = {'reached': False, 'engine': c.get('db_engine'),
           'words': ENGINE_WORDS.get(c.get('db_engine'), c.get('db_engine'))}
    try:
        db = db_open(c)
    except Exception as e:
        out['trouble'] = str(e).split('\n')[0][:300]
        return out
    try:
        out['reached'] = True
        out['where'] = db.where()
        out['version'] = db.version()
        names = db.tables()
        ours = [t for t in TABLES if t in names]
        out['tables'] = ours
        out['rows'] = sum(int(db.value('SELECT COUNT(*) FROM %s' % t) or 0)
                          for t in ours if t not in ('meta',))
        try:
            db.run('CREATE TABLE acme_probe (x INTEGER)')
            db.run('DROP TABLE acme_probe')
            out['writable'] = True
        except Exception as e:
            out['writable'] = False
            out['trouble'] = 'it answers, but this account may not make a table: %s' % (
                str(e).split('\n')[0][:200])
    except Exception as e:
        out['trouble'] = str(e).split('\n')[0][:300]
    finally:
        db.close()
    return out


def db_password_made():
    alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(24))


def db_make(c, admin_user, admin_password):
    """The database and its account, made by an administrator of that
    server who is used for this one connection and kept nowhere."""
    eng = c['db_engine']
    host = str(c.get('db_host') or '127.0.0.1')
    port = int(c.get('db_port') or {'mariadb': 3306, 'postgres': 5432}[eng])
    name, user, pw = c['db_name'], c['db_user'], c['db_password']
    done = []
    if eng == 'mariadb':
        import pymysql
        conn = pymysql.connect(host=host, port=port, user=admin_user, password=admin_password,
                               connect_timeout=int(c.get('db_timeout_s') or 10), autocommit=True)
        try:
            cur = conn.cursor()
            cur.execute('CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 '
                        'COLLATE utf8mb4_unicode_ci' % name)
            done.append('the database %s' % name)
            local = host in ('localhost', '127.0.0.1', '::1')
            try:
                cur.execute('SET SESSION sql_log_off = 1')      # its general log (1.0.207)
            except Exception:                                   # noqa: BLE001
                pass
            for at in (('localhost', '127.0.0.1') if local else ('%',)):
                cur.execute("CREATE USER IF NOT EXISTS %s@%s IDENTIFIED BY %s", (user, at, pw))
                cur.execute("ALTER USER %s@%s IDENTIFIED BY %s", (user, at, pw))
                cur.execute('GRANT ALL PRIVILEGES ON `%s`.* TO %%s@%%s' % name, (user, at))
                done.append("the account '%s'@'%s', with every right on %s and none elsewhere"
                            % (user, at, name))
            cur.execute('FLUSH PRIVILEGES')
        finally:
            conn.close()
        return done
    import psycopg2
    conn = psycopg2.connect(host=host, port=port, user=admin_user, password=admin_password,
                            dbname='postgres', connect_timeout=int(c.get('db_timeout_s') or 10))
    conn.autocommit = True
    try:
        cur = conn.cursor()
        # Not into the server's own log (1.0.207): the statement with the password in
        # it was logged on any error (log_min_error_statement) or with log_statement
        # ddl. Only a superuser may say so - tried, and on without it.
        for quiet in ("SET log_statement = 'none'", "SET log_min_error_statement = 'panic'"):
            try:
                cur.execute(quiet)
            except Exception:                           # noqa: BLE001
                pass
        cur.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (user,))
        if cur.fetchone():
            cur.execute('ALTER ROLE "%s" WITH LOGIN PASSWORD %%s' % user, (pw,))
            done.append('the account %s was there; its password is new' % user)
        else:
            cur.execute('CREATE ROLE "%s" WITH LOGIN PASSWORD %%s' % user, (pw,))
            done.append('the account %s' % user)
        cur.execute('SELECT 1 FROM pg_database WHERE datname = %s', (name,))
        if cur.fetchone():
            cur.execute('ALTER DATABASE "%s" OWNER TO "%s"' % (name, user))
            done.append('the database %s was there; %s owns it now' % (name, user))
        else:
            # Compared and lowered as the other engines and a cluster's databases
            # are (1.0.208): a server set up under C knew no Ž from ž, one under
            # a language put clients in another order.
            try:
                cur.execute("CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE "
                            "template0 LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8'" % (name, user))
            except psycopg2.Error:
                cur.execute("CREATE DATABASE \"%s\" OWNER \"%s\" ENCODING 'UTF8' TEMPLATE "
                            "template0" % (name, user))
            done.append('the database %s, owned by %s' % (name, user))
    finally:
        conn.close()
    conn = psycopg2.connect(host=host, port=port, user=admin_user, password=admin_password,
                            dbname=name, connect_timeout=int(c.get('db_timeout_s') or 10))
    conn.autocommit = True
    try:
        conn.cursor().execute('GRANT ALL ON SCHEMA public TO "%s"' % user)
    except Exception:
        pass
    finally:
        conn.close()
    return done


def db_empty(c):
    db = db_open(c)
    try:
        gone = []
        for t in reversed(TABLES):
            if t in db.tables():
                db.run('DROP TABLE %s' % t)
                gone.append(t)
        return gone
    finally:
        db.close()


