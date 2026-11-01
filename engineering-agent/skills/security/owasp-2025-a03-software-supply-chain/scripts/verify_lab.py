"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import hashlib
import io
import zipfile

def artifact(payload):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        info=zipfile.ZipInfo('module.txt',(2020,1,1,0,0,0)); z.writestr(info,payload)
    return stream.getvalue()

def install(blob, metadata, approved, deployed, secure=True):
    # approved is out-of-band fixture policy, never supplied by the artifact.
    if secure:
        if metadata['publisher']!=approved['publisher']: raise ValueError('unapproved publisher')
        if hashlib.sha256(blob).hexdigest()!=approved['sha256']: raise ValueError('unexpected artifact bytes')
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        # No extraction or execution; retain inert text in memory.
        deployed.append(z.read('module.txt').decode())

class Checks(unittest.TestCase):
    def setUp(self):
        self.good=artifact('approved fixture'); self.bad=artifact('modified fixture')
        self.policy={'publisher':'trusted','sha256':hashlib.sha256(self.good).hexdigest()}; self.live=[]
    def test_unverified_artifact_contrast(self):
        install(self.bad,{'publisher':'trusted'},self.policy,self.live,False)
        self.assertEqual(self.live,['modified fixture'])
    def test_modified_artifact_denied_before_use(self):
        with self.assertRaises(ValueError): install(self.bad,{'publisher':'trusted'},self.policy,self.live)
        self.assertEqual(self.live,[])
    def test_correct_digest_wrong_publisher(self):
        with self.assertRaises(ValueError): install(self.good,{'publisher':'unknown'},self.policy,self.live)
        self.assertEqual(self.live,[])
    def test_valid_artifact_control(self):
        install(self.good,{'publisher':'trusted'},self.policy,self.live)
        self.assertEqual(self.live,['approved fixture'])
    def test_supplied_checksum_does_not_override_policy(self):
        meta={'publisher':'trusted','sha256':hashlib.sha256(self.bad).hexdigest()}
        with self.assertRaises(ValueError): install(self.bad,meta,self.policy,self.live)
        self.assertEqual(self.live,[])

if __name__ == "__main__":
    unittest.main(verbosity=2)
