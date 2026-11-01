"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import hashlib
import hmac
import json

KEY=b'public synthetic lab key, never for deployment'
def sign(body,key=KEY): return hmac.new(key,body,hashlib.sha256).hexdigest()
class Receiver:
    def __init__(self): self.seen=set(); self.ledger=[]
    def accept(self,body,signature,secure=True):
        if secure and not hmac.compare_digest(sign(body),signature): return False
        event=json.loads(body)
        if event['id'] in self.seen: return False
        if set(event)!={'id','amount'} or type(event['amount']) is not int: return False
        self.seen.add(event['id']); self.ledger.append(event['amount']); return True

class Checks(unittest.TestCase):
    def setUp(self): self.r=Receiver(); self.body=b'{"id":"fixture-1","amount":10}'
    def test_no_verification_contrast(self):
        changed=self.body.replace(b'10',b'99')
        self.assertTrue(self.r.accept(changed,sign(self.body),False)); self.assertEqual(self.r.ledger,[99])
    def test_modified_bytes_denied_before_effect(self):
        self.assertFalse(self.r.accept(self.body.replace(b'10',b'99'),sign(self.body))); self.assertEqual(self.r.ledger,[])
    def test_wrong_authority_denied(self):
        self.assertFalse(self.r.accept(self.body,sign(self.body,b'other fixture authority'))); self.assertEqual(self.r.ledger,[])
    def test_valid_then_replay_denied(self):
        self.assertTrue(self.r.accept(self.body,sign(self.body))); self.assertFalse(self.r.accept(self.body,sign(self.body)))
        self.assertEqual(self.r.ledger,[10])
    def test_signed_forbidden_property_denied(self):
        body=b'{"id":"fixture-2","amount":10,"admin":true}'
        self.assertFalse(self.r.accept(body,sign(body))); self.assertEqual(self.r.ledger,[])

if __name__ == "__main__":
    unittest.main(verbosity=2)
