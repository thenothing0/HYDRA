"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import io
import json
import logging

class Pipeline:
    def __init__(self,secure=True): self.stream=io.StringIO(); self.receipts=[]; self.secure=secure
    def emit(self,event):
        if self.secure:
            allowed={k:event[k] for k in ('id','actor','outcome')}
            self.stream.write(json.dumps(allowed)+'\n')
        else: self.stream.write(event['actor']+' '+event['outcome']+'\n')
    def collect(self):
        records=[json.loads(line) for line in self.stream.getvalue().splitlines()]
        for record in records:
            if record['outcome']=='denied': self.receipts.append(record['id'])
        return records

class Checks(unittest.TestCase):
    def test_line_forging_contrast(self):
        p=Pipeline(False); p.emit({'id':'1','actor':'fixture\nforged-event','outcome':'ok'})
        self.assertEqual(len(p.stream.getvalue().splitlines()),2)
    def test_structured_log_is_one_event(self):
        p=Pipeline(); p.emit({'id':'1','actor':'fixture\nforged-event','outcome':'ok'})
        records=p.collect(); self.assertEqual(len(records),1); self.assertEqual(records[0]['actor'],'fixture\nforged-event')
    def test_sensitive_field_excluded(self):
        p=Pipeline(); p.emit({'id':'1','actor':'fixture','outcome':'denied','password':'UNIQUE-LAB-SECRET'})
        self.assertNotIn('UNIQUE-LAB-SECRET',p.stream.getvalue())
    def test_denial_reaches_test_sink(self):
        p=Pipeline(); p.emit({'id':'correlation-1','actor':'fixture','outcome':'denied'}); p.collect()
        self.assertEqual(p.receipts,['correlation-1'])
    def test_benign_control_does_not_alert(self):
        p=Pipeline(); p.emit({'id':'1','actor':'fixture','outcome':'ok'}); p.collect()
        self.assertEqual(p.receipts,[])

if __name__ == "__main__":
    unittest.main(verbosity=2)
