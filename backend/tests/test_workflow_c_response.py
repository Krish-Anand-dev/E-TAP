from test_workflow_c_security import client, headers
from db.connection import get_db

def test_recovery_wording_and_options(client):
    response = client.get('/recovery',headers=headers())
    assert len(response.json()) == 7
    assert 'you are infected' not in response.text.lower()
    assert 'you are safe' not in response.text.lower()
    assert all(x['version'] and x['uncertainty'] for x in response.json())

def test_reporter_cannot_confirm_or_reopen_final(client):
    payload = {'state':'confirmed_malicious','expected_state':'analyzed','note':'test'}
    assert client.patch('/investigations/bob-report/workflow',headers=headers('bob'),json=payload).status_code == 403
    payload['state'] = 'needs_review'
    assert client.patch('/investigations/bob-report/workflow',headers=headers('bob'),json=payload).status_code == 200
    assert client.patch('/investigations/bob-report/workflow',headers=headers('bob'),json=payload).status_code == 403
    assert client.get('/investigations/bob-report/related',headers=headers()).status_code == 404

def test_analyst_history_cas_and_related(client):
    db=get_db()
    for eid,subject in [('a','Payroll verification request now'),('b','Payroll verification request now')]:
        db['analyzed_emails'].insert_one({'_id':eid,'owner_id':'alice','subject':subject,'workflow':{'state':'analyzed'}})
    payload={'state':'confirmed_malicious','expected_state':'analyzed','note':'<script>alert(1)</script>','explanation':'Review complete'}
    r=client.patch('/investigations/a/workflow',headers=headers(),json=payload)
    assert r.status_code == 200
    assert r.json()['history'][0]['role'] == 'analyst'
    assert client.patch('/investigations/a/workflow',headers=headers(),json=payload).status_code == 409
    result=client.get('/investigations/a/related',headers=headers()).json()
    assert [m['email_id'] for m in result['matches']] == ['b']
    assert result['matches'][0]['differences']['subject_changed'] is False
