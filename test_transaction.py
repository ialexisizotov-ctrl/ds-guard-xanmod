import unittest
from transaction import foreign_rules,managed_hook

class Ownership(unittest.TestCase):
    def test_exact_forms_only(self):
        self.assertTrue(managed_hook('-A OUTPUT -o eth0 -m ndpi --proto bittorrent -j DROP'))
        self.assertFalse(managed_hook('-A INPUT -o eth0 -m ndpi --proto bittorrent -j DROP'))
        self.assertFalse(managed_hook('-A OUTPUT -o eth0 -m ndpi --proto skype -j DROP'))
        self.assertFalse(managed_hook('-A OUTPUT -o eth0 -p udp -j NFQUEUE --queue-num 7'))
    def test_foreign_order_and_drop_policy_preserved(self):
        base='*filter\n:INPUT DROP [1:2]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n'
        after=base+'-A OUTPUT -o eth0 -j DS_DOMAINS\n:DS_DOMAINS - [0:0]\n-A DS_DOMAINS -j DS_DOM_A\n'
        self.assertEqual(foreign_rules(base),foreign_rules(after))
        self.assertNotEqual(foreign_rules(base),foreign_rules(after.replace(':INPUT DROP',':INPUT ACCEPT')))
        self.assertNotEqual(foreign_rules(base),foreign_rules(after.replace('--dport 22','--dport 23')))
    def test_empty_accept_table_is_inert(self):
        self.assertEqual(foreign_rules(''),foreign_rules('*filter\n:OUTPUT ACCEPT [0:0]\n'))

if __name__=='__main__':unittest.main()
