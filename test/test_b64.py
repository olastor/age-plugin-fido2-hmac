import unittest
from age_plugin_fido2_hmac.b64 import b64encode_no_padding, b64decode_no_padding

class TestStringMethods(unittest.TestCase):
    def test_padding(self):
        self.assertEqual(b'test', b64decode_no_padding(b64encode_no_padding('test')))
        self.assertEqual('YXNkZg', b64encode_no_padding('asdf'))
        self.assertEqual(b'asdf', b64decode_no_padding('YXNkZg'))

if __name__ == '__main__':
    unittest.main()

