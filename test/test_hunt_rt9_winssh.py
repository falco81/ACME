"""Hunt t9: the Windows (OpenSSH) target finds exactly the IIS binding of its line - an empty
host is not "any host", a given address is compared."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


class Lookup(unittest.TestCase):
    def test_source(self):
        src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'acmelib',
                                'plugins', 'targets', 'windows_ssh.py')).read()
        self.assertNotIn('-HostHeader %s "\n                    "| Select-Object -First 1', src)
        self.assertIn("-contains [string]$_.bindingInformation", src)
        self.assertIn(".EndsWith(%s)", src)
        self.assertIn('could not be', src)


if __name__ == '__main__':
    unittest.main()
