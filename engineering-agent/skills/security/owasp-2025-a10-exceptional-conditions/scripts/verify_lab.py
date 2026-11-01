"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import sqlite3

class Transfer:
    def __init__(self):
        self.db=sqlite3.connect(':memory:')
        self.db.executescript('CREATE TABLE balance(value INT); INSERT INTO balance VALUES(100); CREATE TABLE ledger(op TEXT UNIQUE, amount INT);')
    def run(self,op,amount,decision=True,fail=False,secure=True):
        if secure and decision is not True: return False
        if self.db.execute('SELECT 1 FROM ledger WHERE op=?',(op,)).fetchone(): return True
        try:
            self.db.execute('UPDATE balance SET value=value-?',(amount,))
            if not secure: self.db.commit()
            if fail: raise TimeoutError('fixture dependency unavailable')
            self.db.execute('INSERT INTO ledger VALUES(?,?)',(op,amount)); self.db.commit(); return True
        except TimeoutError:
            self.db.rollback(); return False
    def balance(self): return self.db.execute('SELECT value FROM balance').fetchone()[0]

class Checks(unittest.TestCase):
    def setUp(self): self.t=Transfer()
    def tearDown(self): self.t.db.close()
    def test_partial_commit_contrast(self):
        self.assertFalse(self.t.run('1',10,fail=True,secure=False)); self.assertEqual(self.t.balance(),90)
    def test_failure_rolls_back(self):
        self.assertFalse(self.t.run('1',10,fail=True)); self.assertEqual(self.t.balance(),100)
        self.assertEqual(self.t.db.execute('SELECT count(*) FROM ledger').fetchone()[0],0)
    def test_unknown_authorization_denied(self):
        self.assertFalse(self.t.run('1',10,decision=None)); self.assertEqual(self.t.balance(),100)
    def test_permitted_transaction_control(self):
        self.assertTrue(self.t.run('1',10)); self.assertEqual(self.t.balance(),90)
    def test_retry_after_lost_response_idempotent(self):
        self.t.run('1',10); self.t.run('1',10)
        self.assertEqual(self.t.balance(),90); self.assertEqual(self.t.db.execute('SELECT count(*) FROM ledger').fetchone()[0],1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
