# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the whole configuration as one file (1.0.62) ------------------------------------
# Everything that is set up rather than recorded: the settings (those of each
# node too), the RADIUS clients, the realms, the directories, the accounts of
# the pages, the certificates and keys of the pages and the VIP address, the
# VIP address itself, who may reach which page, the firewall and the mail
# server's authorities. Not the tokens - they are in the copies of the
# database. With the secrets it carries what opens all of it in the clear.
CONFIG_FORMAT = 2
CONFIG_BUNDLE_KIND = 'acme-config-locked'


def config_export(store, whole):
    settings = store.settings_saved()
    # Secrets kept in the database are sealed with this machine's key
    # (1.0.33): exported as they are, they came back sealed twice and opened
    # nowhere. Opened for an export with the secrets, left out otherwise.
    for k in list(settings):
        base = k.split('@', 1)[0]
        if base in SEALED_KEYS:
            if whole and settings[k]:
                settings[k] = unseal_secret(settings[k]) or ''
            else:
                settings.pop(k)
    accounts = []
    for a in store.db.rows('SELECT name, role, pw, source, disabled, must_change, note, display, '
                           'dn, group_list, prefs, cols FROM accounts ORDER BY name'):
        a = dict(a)
        if not whole:
            a.pop('pw', None)
        accounts.append(a)
    tls = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'web:tls:%'"):
        try:
            prof = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        for kk in ('key', 'pending_key'):
            if prof.get(kk):
                if whole:
                    prof[kk] = unseal_secret(prof[kk], 'web:tls') or ''
                else:
                    prof.pop(kk)
        # The second certificate's key as the first's (1.0.205): left sealed with
        # this machine's key, it opened nowhere else - and nginx's every change
        # was refused there ("a certificate needs its key").
        alt = prof.get('alt')
        if isinstance(alt, dict):
            if whole and alt.get('key'):
                prof['alt'] = dict(alt, key=unseal_secret(alt['key'], 'web:tls') or '')
            else:
                prof.pop('alt')
        tls[r['k'][len('web:tls:'):]] = prof

    def meta_json(k):
        try:
            return json.loads(store.get_meta(k) or 'null')
        except ValueError:
            return None
    return {'acme': __version__, 'made': time.time(), 'format': CONFIG_FORMAT,
            'node': node_name(), 'secrets': bool(whole),
            'settings': settings,
            'clients': store.clients(with_secret=whole, last=False),
            'realms': store.realms(),
            'directories': store.directories(with_secret=whole, last=False),
            'accounts': accounts,
            'web': {'tls': tls, 'access': meta_json('web:access'), 'vip': meta_json('web:vip')},
            'firewall': meta_json('fw:conf'),
            'mail_ca': mail_ca_pem(store),
            'sms_ca': sms_ca_pem(store),
            'logo': (lambda o: {k: o.get(k) for k in ('type', 'b64', 'name')}
                     if o else None)(logo_read(store, 'portal')),
            'art': art_read(store, 'portal'),
            'admin_logo': (lambda o: {k: o.get(k) for k in ('type', 'b64', 'name')}
                           if o else None)(logo_read(store, 'admin')),
            'admin_art': art_read(store, 'admin')}


def config_import(store, daemon, conf, by, keep_account='', access_check=None, nodes_as=None,
                  replace=False):
    """A configuration file put in. Checked whole before anything is saved;
    whatever was saved is in use even where something after it stopped.
    Returns what was imported, counted."""
    if not isinstance(conf, dict):
        raise ApiError(400, 'the configuration is not an object')
    for part in ('directories', 'realms', 'clients', 'accounts'):
        if not isinstance(conf.get(part) or [], list) or \
                not all(isinstance(x, dict) for x in conf.get(part) or []):
            raise ApiError(400, '%s is not a list of objects' % part)
    for part in ('settings', 'web', 'firewall'):
        if not isinstance(conf.get(part) or {}, dict):
            raise ApiError(400, '%s is not an object' % part)
    # Checked before anything is saved (1.0.44): a realm naming a directory
    # that neither is here nor comes with it stopped the import halfway.
    dirs = set(x['name'].lower() for x in store.directories()) | \
        set(str(d.get('name') or '').lower() for d in conf.get('directories') or [])
    for r in conf.get('realms') or []:
        if r.get('directory') and str(r['directory']).lower() not in dirs:
            raise ApiError(400, 'the realm %s names the directory %s, which is neither here '
                                'nor in the file - nothing was imported'
                           % (r.get('name'), r['directory']))
    web = conf.get('web') or {}
    access = None
    if web.get('access'):
        access = access_checked_api(web['access'])
        if access_check:
            access_check(access)
    # The certificates of the pages: a node of this cluster keeps its own
    # name; a file of one other machine's (a new machine put in its place)
    # is this node's.
    tls_in = web.get('tls') or {}
    if not isinstance(tls_in, dict):
        raise ApiError(400, 'web.tls is not an object')
    here = set(tls_targets(store))
    mapping = dict(nodes_as or {})
    src = str(conf.get('node') or '')
    if src and src not in here and src not in mapping and not CONFIG.get('ha_mode'):
        mapping[src] = node_name()      # the file of the machine this one replaces
    foreign = [t for t in tls_in if t != 'vip' and t not in here and t not in mapping]
    if len(foreign) == 1 and len([t for t in tls_in if t != 'vip']) == 1:
        mapping[foreign[0]] = node_name()
    fw = conf.get('firewall') or None
    rules_left_out = 0
    if fw:
        rules = []
        for r in fw.get('rules') or []:
            if not isinstance(r, dict):
                raise ApiError(400, 'a firewall rule is not an object')
            # A rule of one node, named as this machine names it (1.0.146): one of
            # a node this machine does not have stopped the whole import.
            r = dict(r)
            if r.get('scope') in mapping:
                r['scope'] = mapping[r['scope']]
            try:
                one = fw_rule_checked(r, store)
            except ApiError as e:
                if 'no node' not in str(e):
                    raise
                rules_left_out += 1
                continue
            for k in ('id', 'scope', 'disabled'):
                if k in r:
                    one[k] = r[k]
            rules.append(one)
        fw = dict(fw, rules=rules, off=[k for k in (fw.get('off') or [])
                                         if k in FW_AUTO_OPTIONAL])
    for t, prof in tls_in.items():
        if not isinstance(prof, dict):
            raise ApiError(400, 'the TLS of %s is not an object' % t)
        for kk in ('cert', 'key', 'chain', 'root', 'pending_key', 'csr'):
            if prof.get(kk) is not None and not isinstance(prof.get(kk), str):
                raise ApiError(400, 'the TLS of %s: %s is not text' % (t, kk))
        # Checked as the page checks it (1.0.94): a word where a number
        # belongs stopped the web side being applied at all.
        try:
            prof.update(tls_policy_checked(prof))
        except (ValueError, TypeError) as e:
            raise ApiError(400, 'the TLS of %s in the file: %s' % (t, e))
    vip_in = web.get('vip')
    if isinstance(vip_in, dict) and vip_in.get('address'):
        try:
            vip_in.update(vip_checked(vip_in, store))
        except (ValueError, TypeError) as e:
            raise ApiError(400, 'the VIP address in the file: %s' % e)
    logos_in = {}
    for slot, k in (('portal', 'logo'), ('admin', 'admin_logo')):
        one = conf.get(k)
        if isinstance(one, dict) and one.get('b64'):
            try:
                logos_in[slot] = base64.b64decode(str(one['b64']), validate=True)
                logo_check(logos_in[slot])
            except (binascii.Error, ValueError) as e:
                raise ApiError(400, 'the picture of the sign-in in the file: %s' % e)
        elif one is not None and not isinstance(one, dict):
            raise ApiError(400, 'the picture of the sign-in in the file is not an object')
    pem = str(conf.get('mail_ca') or '').strip()
    if pem and not all(describe_certificate(b) for b in split_certificates(pem)):
        raise ApiError(400, 'the mail server\'s authorities in the file are not certificates')
    sms_pem = str(conf.get('sms_ca') or '').strip()
    if sms_pem and not all(describe_certificate(b) for b in split_certificates(sms_pem)):
        raise ApiError(400, 'the SMS gateway\'s certificates in the file are not certificates')

    said = collections.Counter()
    imported_keys = set()
    if rules_left_out:
        said['firewall rules left out: of a node not here'] = rules_left_out
    try:
        for d in conf.get('directories') or []:
            d = dict(d)
            old = store.directory(d.get('name'))
            d['id'] = old['id'] if old else None
            store.directory_save(d, by)
            said['directories'] += 1
        for r in conf.get('realms') or []:
            r = dict(r)
            old = next((x for x in store.realms() if x['name'] == r.get('name')), None)
            r['id'] = old['id'] if old else None
            store.realm_save(r, by)
            said['realms'] += 1
        for c in conf.get('clients') or []:
            c = dict(c)
            old = next((x for x in store.clients() if x['name'] == c.get('name')), None)
            c['id'] = old['id'] if old else None
            if is_masked(c.get('secret')) and not old:
                # Said, not left out without a word (1.0.103): an export without
                # its secrets cannot make a client its NAS would be answered by.
                said['clients left out: no shared secret in the file'] += 1
                continue
            store.client_save(c, by)
            said['clients'] += 1
        if conf.get('settings'):
            # Never what belongs to this machine alone (1.0.57): an imported
            # file switched the database or the cluster at the next restart.
            # A node's own value (key@node) comes too (1.0.62).
            want, per_node = {}, []
            for k, v in conf['settings'].items():
                base, _at, node = str(k).partition('@')
                if base not in DEFAULTS or base in FILE_ONLY_KEYS:
                    continue
                if node and (base not in NODE_KEYS or not re.match(r'^[A-Za-z0-9._-]{1,64}\Z', node)):
                    continue
                if base in SEALED_KEYS and str(v or '').startswith('sealed:'):
                    continue
                if node:
                    per_node.append((base, mapping.get(node, node), v))
                else:
                    want[base] = v
            if want:
                # A secret of this machine is not sent to a server the file names
                # (1.0.207): taken away where the file moves its server and does
                # not bring one of its own - to be typed again.
                for sk, where in SECRET_GOES_TO.items():
                    if CONFIG.get(sk) and sk not in want and any(
                            k in want and str(want[k]).strip() != str(CONFIG.get(k) or '').strip()
                            for k in where):
                        want[sk] = ''
                        said['secrets to type again (another server)'] += 1
                # The cluster's own value (1.0.206): a node's setting shared in the
                # file was saved for the node that imported it alone - and with
                # "replace" then taken away again.
                daemon.save_settings(want, by, node='*')
                imported_keys |= set(want)
                said['settings'] += len(want)
            # A node's own after the shared ones (1.0.146): on a machine of its
            # own a node's value is kept as the plain key, and the file's shared
            # value saved after it wrote over it.
            for base, node, v in per_node:
                try:
                    daemon.save_settings({base: v}, by, node=node)
                    said['settings'] += 1
                    imported_keys.update((base, '%s@%s' % (base, node)))
                except BadSetting:
                    pass            # a node this cluster does not have
        for a in conf.get('accounts') or []:
            name = str(a.get('name') or '').strip()
            if not name or name.lower() == str(keep_account or '').lower():
                continue                # never the one importing: not shut out by a file
            if not ACCOUNT_NAME_RE.match(name):
                continue                # a name the pages would not take (1.0.101)
            role = str(a.get('role') or 'readonly')
            if role not in ROLES_ALL:
                continue
            fields = {'role': role, 'disabled': int(bool(a.get('disabled'))),
                      'must_change': int(bool(a.get('must_change'))),
                      'note': str(a.get('note') or '')[:400],
                      'display': str(a.get('display') or ''), 'dn': str(a.get('dn') or ''),
                      'group_list': str(a.get('group_list') or ''),
                      'source': str(a.get('source') or 'local')}
            pw = a.get('pw')
            # Only a password's hash as this program makes it: never text
            # taken for one.
            if not (isinstance(pw, str) and pw.startswith('pbkdf2_sha256$')):
                pw = ''
            old = store.account(name)
            if old:
                if isinstance(pw, str) and pw:
                    fields['pw'] = pw
                store.db.run('UPDATE accounts SET %s WHERE id = ?' % ', '.join(
                    '%s = ?' % k for k in fields), tuple(fields.values()) + (old['id'],))
                if (fields.get('pw') and fields['pw'] != old.get('pw')) or fields['disabled'] or \
                        fields['role'] != old.get('role'):
                    # Its sign-ins ended (1.0.101), as a password set on the
                    # pages ends them: the old password's sessions went on.
                    store.db.run('DELETE FROM sessions WHERE kind = ? AND LOWER(name) = ?',
                                 ('admin', name.lower()))
            else:
                if fields['source'] == 'local' and not (isinstance(pw, str) and pw):
                    # Without its password (an export without the secrets): made,
                    # switched off, until somebody gives it one.
                    fields['disabled'] = 1
                    said['accounts switched off: no password in the file'] += 1
                store.db.run('DELETE FROM meta WHERE k = ?', ('adm2fa:' + name.lower(),))
                store.db.insert('accounts', dict(fields, name=name, pw=pw or '',
                                                 created=time.time(), last_in=None,
                                                 last_from='', prefs=str(a.get('prefs') or '{}')))
            said['accounts'] += 1
        for t, prof in tls_in.items():
            prof = dict(prof)
            for kk in ('key', 'pending_key'):
                if prof.get(kk):
                    prof[kk] = seal_secret(prof[kk], 'web:tls')
                else:
                    prof.pop(kk, None)
            alt = prof.get('alt')
            if isinstance(alt, dict) and isinstance(alt.get('key'), str) and alt['key'].strip() \
                    and not alt['key'].startswith(('sealed:', SEALED2)):
                prof['alt'] = dict(alt, key=seal_secret(alt['key'], 'web:tls'))
            else:
                prof.pop('alt', None)       # without its own key it is nothing (1.0.205)
            target = mapping.get(t, t)
            old_key = (_json_meta(store, 'web:tls:' + target) or {}).get('key')
            if not prof.get('key') and old_key:
                # A file without the secrets does not take a key away - kept
                # where it is the certificate's own (1.0.147): beside another
                # certificate, nginx would not start with the pair.
                try:
                    mine = prof.get('cert') and _pub_of_cert(prof['cert']) == _pub_of_key(
                        unseal_secret(old_key, 'web:tls') or '')
                except Exception:                       # noqa: BLE001
                    mine = False
                if mine or not prof.get('cert'):
                    prof['key'] = old_key
                else:
                    said['certificates without their key (put it in on the pages)'] += 1
            tls_save(store, target, prof, by)
            said['certificates'] += 1
        if access is not None:
            fw_trial_begin(store, by)
            store.set_meta('web:access', json.dumps(dict(access, at=time.time(), by=by)))
            said['page access'] += 1
        if isinstance(web.get('vip'), dict):
            vip = dict(web['vip'])
            if not CONFIG.get('ha_mode'):
                vip['on'] = False       # a VIP address is a cluster's
            store.set_meta('web:vip', json.dumps(dict(vip, at=time.time(), by=by)))
            said['VIP address'] += 1
        if fw is not None:
            fw_trial_begin(store, by)
            store.set_meta('fw:conf', json.dumps(dict(fw, at=time.time(), by=by)))
            said['firewall'] += 1
        if pem:
            store.set_meta(MAIL_CA_META, '\n'.join(split_certificates(pem)))
            said['mail authorities'] += 1
        if sms_pem:
            store.set_meta(SMS_CA_META, '\n'.join(split_certificates(sms_pem)))
            said['SMS gateway certificates'] += 1
        for slot, k, ak in (('portal', 'logo', 'art'), ('admin', 'admin_logo', 'admin_art')):
            if slot in logos_in:
                logo_set(store, slot, logos_in[slot], by, str(conf[k].get('name') or ''))
            elif k in conf and replace and logo_read(store, slot):
                logo_set(store, slot, b'', by)
            want = conf.get(ak)
            if slot == 'admin' and want is None and isinstance(conf.get('art'), dict) \
                    and conf['art'].get('admin'):
                want = conf['art']                      # a file from 1.0.71
                if 'admin' not in logos_in and 'portal' in logos_in:
                    logo_set(store, 'admin', logos_in['portal'], by,
                             str((conf.get('logo') or {}).get('name') or ''))
            if isinstance(want, dict) and want.get('art') in ART_NAMES:
                try:
                    art_set(store, slot, want['art'])
                except ValueError:
                    art_set(store, slot, ART_SLOTS[slot][2])
                said['sign-in pictures'] += 1
        if replace:
            # The file as the whole of it (1.0.62): what is here and not in
            # the file goes - the clients, realms, directories and accounts
            # (never the one importing), and the settings back to their
            # defaults. Realms before the directories they name.
            def names(part):
                return set(str(x.get('name') or '').lower() for x in conf.get(part) or [])
            for c in store.clients():
                if c['name'].lower() not in names('clients'):
                    store.client_drop(c['id'])
                    said['clients taken away'] += 1
            for r in store.realms():
                if r['name'].lower() not in names('realms'):
                    store.realm_drop(r['id'], force=True)
                    said['realms taken away'] += 1
            for d in store.directories():
                if d['name'].lower() not in names('directories'):
                    store.directory_drop(d['id'])
                    said['directories taken away'] += 1
            if 'accounts' in conf:
                for a in store.db.rows('SELECT name FROM accounts'):
                    if a['name'].lower() not in names('accounts') and \
                            a['name'].lower() != str(keep_account or '').lower():
                        store.drop_account(a['name'])
                        said['accounts taken away'] += 1
            if 'settings' in conf:
                have = set(str(k) for k in (conf.get('settings') or {})) | imported_keys
                for k in list(store.settings_saved()):
                    base = k.split('@', 1)[0]
                    if k not in have and base in DEFAULTS and base not in FILE_ONLY_KEYS and \
                            not (base in SEALED_KEYS and conf.get('secrets') is not True):
                        store.drop_setting(k)
                        said['settings back to default'] += 1
    except (ValueError, BadSetting) as e:
        if said:
            raise ApiError(400, '%s - imported before it stopped: %s' % (e, ', '.join(
                '%s %d' % kv for kv in sorted(said.items()))))
        raise
    finally:
        # Whatever was saved is in use, even when something after it was not
        # (1.0.44).
        if said:
            try:
                daemon.changed('all')
                # Read in here too (1.0.62): a setting put back to its default
                # stayed at the old value in this process until a restart.
                daemon.reload_all('a configuration was imported')
            except Exception:                           # noqa: BLE001
                bump(store)
            store.add_event('settings', '%s imported a configuration: %s' % (by, dict(said)),
                            who=by)
    if not said:
        raise ApiError(400, 'there is nothing in this file to import - is it an export of acme?')
    return said


