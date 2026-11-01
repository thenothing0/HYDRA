"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import sqlite3

class Search:
    def __init__(self):
        self.db=sqlite3.connect(':memory:')
        self.db.executescript("CREATE TABLE items(name TEXT,price INT); INSERT INTO items VALUES ('apple',2),('pear',3);")
        self.db.execute('INSERT INTO items VALUES (?,?)',("O'Reilly",4))
    def query(self,term,secure=True):
        if secure: return self.db.execute('SELECT name FROM items WHERE name=?',(term,)).fetchall()
        return self.db.execute("SELECT name FROM items WHERE name='"+term+"'").fetchall()
    def sort(self,choice):
        column={'name':'name','price':'price'}.get(choice)
        if column is None: raise ValueError('unknown sort')
        return self.db.execute('SELECT name FROM items ORDER BY '+column).fetchall()

class Checks(unittest.TestCase):
    def setUp(self): self.s=Search()
    def tearDown(self): self.s.db.close()
    def test_insecure_query_contrast(self):
        self.assertEqual(len(self.s.query("' OR 1=1 --",False)),3)
    def test_query_syntax_remains_data(self):
        self.assertEqual(self.s.query("' OR 1=1 --"),[])
    def test_apostrophe_control(self):
        self.assertEqual(self.s.query("O'Reilly"),[("O'Reilly",)])
    def test_structure_denied(self):
        with self.assertRaises(ValueError): self.s.sort('price DESC')
    def test_permitted_structure_control(self):
        self.assertEqual(self.s.sort('price'),[('apple',),('pear',),("O'Reilly",)])

if __name__ == "__main__":
    unittest.main(verbosity=2)
