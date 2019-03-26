import unittest
import hashlib
from kskm.tools_common.wordlist import pgp_wordlist


TESTS = [
    {
        'message': 'mekmitasdigoat'.encode(),
        'hexdigest': '8d9eadc1f305d46f1f203886aa5df98f1ed62fcbacc23d2f6732d24d928703e8',
        'words': 'optic onlooker ringbolt recover upset almighty steamship hemisphere billiard butterfat classic letterhead reward filament waffle midsummer berserk speculate cement revival ribcage repellent commence combustion freedom component standard disruptive physique liberty acme typewriter'
    },
    {
        'message': 'The quick brown fox jumps over the lazy dog'.encode(),
        'hexdigest': 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
        'words': 'stopwatch paramount watchword pocketful ahead stethoscope merit molecule gazelle revenue pupil pyramid ruffled antenna buzzard document optic escapade drunken tradition goggles crossover suspense impetus button aftermath stagnate rebellion clamshell retrospect topmost misnomer'
    }
]


class Test_PGP_Wordlist(unittest.TestCase):

    def test_wordlist(self):
        for test in TESTS:
            m = hashlib.new('sha256')
            m.update(test['message'])
            self.assertEqual(test['hexdigest'], m.hexdigest())
            self.assertEqual(' '.join(pgp_wordlist(m.digest())), test['words'])


if __name__ == '__main__':
    unittest.main()
