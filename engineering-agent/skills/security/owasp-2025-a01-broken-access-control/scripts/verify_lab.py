"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import sqlite3

class Service:
    def __init__(self):
        self.db=sqlite3.connect(':memory:')
        self.db.executescript("CREATE TABLE docs(id TEXT, tenant TEXT, owner TEXT, body TEXT); INSERT INTO docs VALUES ('a','A','alice','alpha'),('b','B','bob','beta');")
    def get(self, actor, tenant, ident, secure=True):
        if secure:
            return self.db.execute('SELECT body FROM docs WHERE id=? AND tenant=? AND owner=?',(ident,tenant,actor)).fetchall()
        return self.db.execute('SELECT body FROM docs WHERE id=?',(ident,)).fetchall()
    def edit(self, actor, tenant, ident, body):
        self.db.execute('UPDATE docs SET body=? WHERE id=? AND tenant=? AND owner=?',(body,ident,tenant,actor))
    def close(self): self.db.close()

class Checks(unittest.TestCase):
    def setUp(self): self.s=Service()
    def tearDown(self): self.s.close()
    def test_insecure_contrast(self):
        self.assertEqual(self.s.get('alice','A','b',False),[('beta',)])
    def test_other_tenant_denied(self):
        self.assertEqual(self.s.get('alice','A','b'),[])
    def test_wrong_owner_denied(self):
        self.assertEqual(self.s.get('alice','B','b'),[])
    def test_owner_control(self):
        self.assertEqual(self.s.get('bob','B','b'),[('beta',)])
    def test_denied_write_has_no_effect(self):
        self.s.edit('alice','A','b','changed')
        self.assertEqual(self.s.get('bob','B','b'),[('beta',)])

if __name__ == "__main__":
    unittest.main(verbosity=2)
