"""Hunt t8: Aruba AOS-CX hides the URL-encoded password; docker swarm refuses a comma in a
secret's file name."""
import os, sys, unittest, urllib.parse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from acmelib.plugins.base import PluginError
from acmelib.plugins.targets import aruba_aoscx, docker_swarm


class Aruba(unittest.TestCase):
    def test_encoded_password_hidden(self):
        pw = 'p@ss w/rd&1'
        t = aruba_aoscx.ArubaAosCxTarget.__new__(aruba_aoscx.ArubaAosCxTarget)
        t.c = lambda k: {'user': 'admin', 'password': pw}.get(k)
        t.v = lambda: '/rest/v10.08'
        def req(*a, **k):
            raise PluginError('https://sw/rest/v10.08/login?username=admin&password=%s refused'
                              % urllib.parse.quote_plus(pw))
        t.req = req
        with self.assertRaises(PluginError) as cm:
            t.login()
        m = str(cm.exception)
        self.assertNotIn(urllib.parse.quote_plus(pw), m)
        self.assertNotIn(pw, m)


class Swarm(unittest.TestCase):
    def test_comma_refused(self):
        src = open(docker_swarm.__file__).read()
        self.assertIn("',' in v or '=' in v", src)


if __name__ == '__main__':
    unittest.main()
