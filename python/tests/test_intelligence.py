import json
import unittest

from pun_mcp.intelligence import correlate_sessions, deep_security_analysis
from pun_mcp.logichunter import workflow_state_graph


TRAFFIC = [
    {'id':'a1','timestamp':1000,'host':'test.example','role':'userA','method':'GET','path':'/api/orders/123',
     'status':200,'input_keys':[],'output_keys':['email'],
     'cookie_insights':[{'name':'session','structure':'json','fingerprint':'sample-1','json_keys':['user_id']}]},
    {'id':'b1','timestamp':2000,'host':'test.example','role':'userB','method':'GET','path':'/api/orders/456',
     'status':403,'input_keys':[],'output_keys':[],
     'cookie_insights':[{'name':'session','structure':'json','fingerprint':'sample-2','json_keys':['user_id']}]},
    {'id':'a2','timestamp':3000,'host':'test.example','role':'userA','method':'POST','path':'/api/checkout/create',
     'status':200,'input_keys':['order_id'],'output_keys':['id'],
     'cookie_insights':[{'name':'session','structure':'json','fingerprint':'sample-1'}]},
    {'id':'a3','timestamp':4000,'host':'test.example','role':'userA','method':'POST','path':'/api/checkout/complete',
     'status':200,'input_keys':['order_id'],'output_keys':['status']},
]


class IntelligenceTests(unittest.TestCase):
    def test_deep_analysis_never_promotes_hypothesis_to_finding(self):
        result = deep_security_analysis(TRAFFIC)
        self.assertTrue(result['role_endpoint_matrix'])
        self.assertTrue(result['hypotheses'])
        self.assertTrue(all(h['confirmed'] is False for h in result['hypotheses']))
        self.assertTrue(any('userA' in item['by_role'] and 'userB' in item['by_role'] for item in result['role_endpoint_matrix']))
        self.assertNotIn('raw_session_secret', json.dumps(result))

    def test_cookie_correlations_are_pseudonymous(self):
        result = correlate_sessions(TRAFFIC)
        self.assertEqual(result['correlations'][0]['request_count'], 2)
        self.assertEqual(result['correlations'][0]['roles'], ['userA'])
        self.assertFalse(result['alerts'])

    def test_workflow_transitions_are_noncausal(self):
        data = workflow_state_graph(TRAFFIC)
        self.assertTrue(data['edges'])
        self.assertIn('do not prove', data['caveat'])


if __name__ == '__main__':
    unittest.main()

class LifecycleTests(unittest.TestCase):
    def test_login_cookie_rotation_is_only_a_review_hint(self):
        events = [{'id': 'login1', 'host': 'test.example', 'role': 'test',
                   'path': '/login', 'method': 'POST', 'status': 200,
                   'cookie_insights': [{'name': 'session', 'fingerprint': 'x'}],
                   'set_cookie_insights': [{'name': 'session', 'fingerprint': 'x'}]}]
        hints = correlate_sessions(events)['session_lifecycle_hints']
        self.assertEqual(hints[0]['event'], 'same_cookie_reissued')
        self.assertIn('not a session fixation finding', hints[0]['review_hint'])
