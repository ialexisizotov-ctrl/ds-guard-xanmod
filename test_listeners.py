import unittest
from controller import listener_endpoints
class ListeningEndpoints(unittest.TestCase):
 def test_socket_activation_fd_change_is_not_loss(self):
  before='LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("systemd",pid=1,fd=150))'
  after=before.replace('fd=150','fd=158').replace('LISTEN 0','LISTEN 1')
  self.assertEqual(listener_endpoints(before),listener_endpoints(after))
 def test_removed_or_rebound_listener_is_loss(self):
  before='LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*'
  for after in ['',before.replace('0.0.0.0:22','127.0.0.1:22'),before.replace(':22',':23')]:
   self.assertFalse(listener_endpoints(before)<=listener_endpoints(after))
