import unittest


class TestBasics(unittest.TestCase):

    def test_basic_init(self):
        """ Test basic module import """
        import kskm.ksr
        self.assertEqual(kskm.ksr.__author__, 'ft')
