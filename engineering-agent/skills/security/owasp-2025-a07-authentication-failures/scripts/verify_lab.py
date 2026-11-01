"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import secrets

class Recovery:
    def __init__(self): self.tokens={}; self.deliveries=[]; self.passwords={'a':'old','b':'old'}
    def request(self,account,recipient,secure=True):
        verified={'a':'a@fixture.invalid','b':'b@fixture.invalid'}
        if secure and recipient!=verified.get(account): return
        token=secrets.token_urlsafe(24)
        self.tokens[token]=account; self.deliveries.append((recipient,token))
    def reset(self,token,account,password):
        if self.tokens.get(token)!=account: return False
        self.passwords[account]=password; del self.tokens[token]; return True

class Checks(unittest.TestCase):
    def setUp(self): self.r=Recovery()
    def test_unverified_delivery_contrast(self):
        self.r.request('a','b@fixture.invalid',False)
        self.assertEqual(self.r.deliveries[0][0],'b@fixture.invalid')
    def test_unverified_delivery_denied(self):
        self.r.request('a','b@fixture.invalid'); self.assertEqual(self.r.deliveries,[])
    def test_verified_recipient_control(self):
        self.r.request('a','a@fixture.invalid'); token=self.r.deliveries[0][1]
        self.assertTrue(self.r.reset(token,'a','new')); self.assertEqual(self.r.passwords['a'],'new')
    def test_token_bound_to_account(self):
        self.r.request('a','a@fixture.invalid'); token=self.r.deliveries[0][1]
        self.assertFalse(self.r.reset(token,'b','new')); self.assertEqual(self.r.passwords['b'],'old')
    def test_one_time_reset(self):
        self.r.request('a','a@fixture.invalid'); token=self.r.deliveries[0][1]
        self.assertTrue(self.r.reset(token,'a','new')); self.assertFalse(self.r.reset(token,'a','newer'))

if __name__ == "__main__":
    unittest.main(verbosity=2)
