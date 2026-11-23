import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('rotation_crypto',ROOT/'deploy/maintenance/internal_secret_crypto.py')
crypto=importlib.util.module_from_spec(spec);spec.loader.exec_module(crypto)


class RotationCryptoTests(unittest.TestCase):
    def test_ca_plaintext_and_certificate_key_are_preserved(self):
        old='rotation-unit-old';new='rotation-unit-new';plain=b'fictional private key bytes'
        source=crypto.CA_PREFIX+crypto._seal(plain,crypto.ca_key(old),crypto.CA_DOMAIN)
        revised=crypto.rewrap_ca(source,old,new)
        self.assertEqual(crypto._open(revised[len(crypto.CA_PREFIX):],crypto.ca_key(new),crypto.CA_DOMAIN),plain)
        with self.assertRaises(Exception):crypto._open(revised[len(crypto.CA_PREFIX):],crypto.ca_key(old),crypto.CA_DOMAIN)
        self.assertNotEqual(source,revised)

    def test_queue_payload_and_result_keep_exact_aad(self):
        for kind in ('payload','result'):
            aad=f'tenant/request/7/{kind}'.encode();plain='中文内容，不丢弃待检任务'.encode()
            value=crypto._seal(plain,crypto.queue_key('old-unit-key'),aad)
            revised=crypto.rewrap_part(value,'tenant','request',7,kind,'old-unit-key','new-unit-key')
            self.assertEqual(crypto._open(revised,crypto.queue_key('new-unit-key'),aad),plain)
            with self.assertRaises(Exception):crypto._open(revised,crypto.queue_key('new-unit-key'),b'other/request/7/'+kind.encode())

    def test_bad_ciphertext_fails_before_any_replacement(self):
        with self.assertRaises(Exception):crypto.rewrap_part('invalid','t','r',0,'payload','old','new')
        self.assertEqual(crypto.rewrap_part('','t','r',0,'result','old','new'),'')


if __name__=='__main__':unittest.main()
