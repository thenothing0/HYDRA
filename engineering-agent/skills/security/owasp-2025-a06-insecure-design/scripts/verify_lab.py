"""Synthetic local laboratory, not a scanner or reproduction of a historical CVE.
Run with Python 3.10+; standard library only; no network or external credentials.
Checks include insecure contrasts plus secure and legitimate controls.
Passing does not establish model accuracy or real-application security.
"""
import unittest

import concurrent.futures
import threading

def redeem_pair(secure):
    state={'used':False,'ledger':[]}; gate=threading.Barrier(2); lock=threading.Lock()
    def worker(i):
        if secure:
            gate.wait(timeout=5)
            with lock:
                if state['used']: return False
                state['used']=True; state['ledger'].append(i); return True
        # Force both attempts past the stale check, without timing-based sleeps.
        allowed=not state['used']; gate.wait(timeout=5)
        if allowed:
            state['used']=True; state['ledger'].append(i); return True
        return False
    with concurrent.futures.ThreadPoolExecutor(2) as pool: outcomes=list(pool.map(worker,[1,2]))
    return outcomes,state['ledger']

def transition(state,action):
    allowed={('paid','ship'):'shipped',('shipped','deliver'):'delivered'}
    if (state,action) not in allowed: raise ValueError('invalid transition')
    return allowed[state,action]

class Checks(unittest.TestCase):
    def test_stale_check_contrast(self):
        outcomes,ledger=redeem_pair(False); self.assertEqual(sum(outcomes),2); self.assertEqual(len(ledger),2)
    def test_atomic_one_time_redemption(self):
        outcomes,ledger=redeem_pair(True); self.assertEqual(sum(outcomes),1); self.assertEqual(len(ledger),1)
    def test_invalid_transition_denied(self):
        with self.assertRaises(ValueError): transition('unpaid','ship')
    def test_valid_transition_control(self):
        self.assertEqual(transition('paid','ship'),'shipped')
    def test_completed_action_cannot_repeat(self):
        with self.assertRaises(ValueError): transition('shipped','ship')

if __name__ == "__main__":
    unittest.main(verbosity=2)
