"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import hashlib
import hmac

# 10,000 iterations keeps this lab fast. It is NOT a production work-factor recommendation.
def encode(password,salt):
    digest=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,10000)
    return {'salt':salt,'digest':digest}
def verify(password,record):
    return hmac.compare_digest(encode(password,record['salt'])['digest'],record['digest'])
def insecure(password): return hashlib.sha256(password.encode()).digest()

class Checks(unittest.TestCase):
    def test_unsalted_equal_password_contrast(self):
        self.assertEqual(insecure('fixture password'),insecure('fixture password'))
    def test_distinct_salts_change_stored_digest(self):
        a=encode('fixture password',b'fixture-salt-A01'); b=encode('fixture password',b'fixture-salt-B02')
        self.assertNotEqual(a['digest'],b['digest'])
    def test_correct_password_control(self):
        self.assertTrue(verify('fixture password',encode('fixture password',b'fixture-salt-A01')))
    def test_wrong_password_denied(self):
        self.assertFalse(verify('wrong',encode('fixture password',b'fixture-salt-A01')))
    def test_unicode_password_and_salt_binding(self):
        record=encode('pássword-اختبار',b'fixture-salt-A01')
        self.assertTrue(verify('pássword-اختبار',record))
        record['salt']=b'fixture-salt-B02'
        self.assertFalse(verify('pássword-اختبار',record))

if __name__ == "__main__":
    unittest.main(verbosity=2)
