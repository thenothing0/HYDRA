"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import json

def effective(overrides, secure=True):
    settings={'debug':False,'admin_public':False}
    if not secure: settings.update(debug=True,admin_public=True)
    settings.update(overrides)
    return settings

def route(config,path):
    if path=='/admin': return (200,'admin') if config['admin_public'] else (403,'denied')
    if path=='/fail':
        try: raise ValueError('private internal path: /srv/fixture')
        except ValueError as e:
            return 500,json.dumps({'error':str(e) if config['debug'] else 'request failed','request_id':'fixture-1'})
    return 200,'public'

class Checks(unittest.TestCase):
    def test_insecure_first_boot_contrast(self):
        self.assertEqual(route(effective({},False),'/admin')[0],200)
    def test_secure_first_boot(self):
        self.assertEqual(route(effective({}),'/admin')[0],403)
    def test_effective_override_wins(self):
        self.assertEqual(route(effective({'admin_public':True}),'/admin')[0],200)
    def test_error_redaction_and_correlation(self):
        status,body=route(effective({}),'/fail')
        self.assertEqual(status,500)
        self.assertNotIn('/srv/fixture',body)
        self.assertEqual(json.loads(body)['request_id'],'fixture-1')
    def test_public_control(self):
        self.assertEqual(route(effective({}),'/public'),(200,'public'))

if __name__ == "__main__":
    unittest.main(verbosity=2)
