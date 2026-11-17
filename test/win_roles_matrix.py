"""The options the role scripts of _win_roles are compared with (test_agent_windows_parity.py):
every role with its defaults, everything on, each switch of the role turned the other way, each
choice of a select, values with quotes - the same list rendered before and after a change, the
two compared line by line (a fixture of the scripts as they were: win_roles_before.json)."""

ENV = {'names': ['www.example.test', 'example.test'], 'pfx': 'C:/Windows/Temp/r.pfx',
       'pfx_pw': "pfx'pw", 'ccs_pfx': 'C:/Windows/Temp/c.pfx', 'ccs_pw': "it's"}
ENV_EMPTY = {'names': ['*.example.test', 'a.example.test']}

VALUES = {'rds_broker': "cb'1.example.test", 'sql_instance': 'SQLEXPRESS',
          'winrm_hostname': 'win.example.test', 'ccs_path': '\\\\files\\ccs',
          'ccs_password': "it's", 'ftp_site': "Bob's FTP", 'sp_url': 'https://intranet.example.test',
          'sp_host': 'intranet.example.test', 'sp_port': 8443, 'sp_zone': 'Internet',
          'wac_msi': 'C:\\i\\wac.msi', 'wac_port': 6516}


def cases(WR):
    out = []
    fields = WR.role_fields()
    for key, _l, _t, _n in WR.ROLES:
        own = [f for f in fields if f.get('show_if') and ('role_' + key) in f['show_if']]
        base = {'role_' + key: True}
        if key == 'ccs':
            base['ccs_path'] = 'D:\\CCS'
        if key == 'sharepoint':
            base['sp_url'] = 'https://sp.example.test'
        out.append(('%s/defaults' % key, key, dict(base), ENV))
        out.append(('%s/defaults-noenv' % key, key, dict(base), ENV_EMPTY))
        allv = dict(base)
        for f in own:
            if f['type'] == 'bool':
                allv[f['key']] = True
            elif f['key'] in VALUES:
                allv[f['key']] = VALUES[f['key']]
        out.append(('%s/all' % key, key, allv, ENV))
        for f in own:
            if f['type'] == 'bool':
                for v in (True, False):
                    out.append(('%s/%s=%s' % (key, f['key'], v), key, dict(allv, **{f['key']: v}),
                                ENV))
                    out.append(('%s/base-%s=%s' % (key, f['key'], v), key,
                                dict(base, **{f['key']: v}), ENV))
            elif f['type'] == 'select':
                for v, _w in f['options']:
                    out.append(('%s/%s=%s' % (key, f['key'], v), key, dict(allv, **{f['key']: v}),
                                ENV))
            elif f['key'] in VALUES:
                out.append(('%s/%s=empty' % (key, f['key']), key, dict(allv, **{f['key']: ''}),
                            ENV))
    return out
