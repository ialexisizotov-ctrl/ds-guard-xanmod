import unittest
from preflight import assess

class CompatibilityGate(unittest.TestCase):
    def check_kernel(self, kernel, cfg=None, lockdown='', ram=4*1024**3):
        if cfg is None: cfg='CONFIG_MODULES=y\nCONFIG_NETFILTER=y\nCONFIG_NF_CONNTRACK=m\nCONFIG_LIVEPATCH=y\n'
        return assess(kernel,cfg,'ubuntu','x86_64',False,lockdown,20*1024**3,ram)
    def test_accepted_family(self):
        self.assertEqual(self.check_kernel('6.8.0-87-generic'), [])
        self.assertEqual(self.check_kernel('6.8.0-147-generic'), [])
        self.assertEqual(self.check_kernel('7.0.12-x64v2-dsg1-xanmod1'), [])
        self.assertEqual(self.check_kernel('7.2.9-x64v3-dsg1-xanmod1'), [])
    def test_stock_xanmod_rejected_before_mutation(self):
        self.assertTrue(self.check_kernel('7.0.12-x64v2-xanmod1','CONFIG_MODULES=y\nCONFIG_NETFILTER=y\nCONFIG_NF_CONNTRACK=m\n'))
    def test_unknown_future_kernel_rejected(self):
        self.assertTrue(self.check_kernel('8.0.0-generic'))
    def test_unverified_same_family_rejected(self):
        self.assertTrue(self.check_kernel('6.8.0-999-generic'))
        self.assertTrue(self.check_kernel('6.8.0-custom'))
    def test_lockdown_not_weakened(self):
        self.assertTrue(self.check_kernel('6.8.0-147-generic',lockdown='none [integrity] confidentiality'))
    def test_low_memory_rejected(self):
        self.assertTrue(self.check_kernel('6.8.0-147-generic',ram=512*1024**2))

if __name__=='__main__': unittest.main()
