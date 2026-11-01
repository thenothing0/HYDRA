"""Synthetic local constructor-marker laboratory, not an exploit gadget.
The intentionally unsafe pickle contrast changes an in-memory marker only.
No commands, network, credential reads or persistent side effects are performed.
"""
import json,pickle,unittest
EVENTS=[]
def construct_marker():
    EVENTS.append('constructed-from-external-bytes'); return {'label':'fixture','amount':1}
class Fixture:
    def __reduce__(self): return construct_marker,()

def parse_data(raw):
    value=json.loads(raw)
    if type(value) is not dict or set(value)!={'label','amount'}: raise ValueError('schema')
    if type(value['label']) is not str or type(value['amount']) is not int: raise ValueError('types')
    return value

class Checks(unittest.TestCase):
    def setUp(self): EVENTS.clear()
    def tearDown(self): EVENTS.clear()
    def test_unsafe_object_decoder_runs_inert_constructor(self):
        raw=pickle.dumps(Fixture()); self.assertEqual(EVENTS,[])
        pickle.loads(raw)
        self.assertEqual(EVENTS,['constructed-from-external-bytes'])
    def test_plain_json_control_has_no_constructor_effect(self):
        self.assertEqual(parse_data(b'{"label":"fixture","amount":1}'),{'label':'fixture','amount':1})
        self.assertEqual(EVENTS,[])
    def test_object_bytes_rejected_without_constructor(self):
        with self.assertRaises((ValueError,UnicodeDecodeError)): parse_data(pickle.dumps(Fixture()))
        self.assertEqual(EVENTS,[])
    def test_unapproved_property_rejected(self):
        with self.assertRaises(ValueError): parse_data(b'{"label":"fixture","amount":1,"admin":true}')
        self.assertEqual(EVENTS,[])
    def test_boolean_is_not_the_required_integer(self):
        with self.assertRaises(ValueError): parse_data(b'{"label":"fixture","amount":true}')
        self.assertEqual(EVENTS,[])

if __name__=='__main__': unittest.main(verbosity=2)
