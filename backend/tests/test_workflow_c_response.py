from test_workflow_c_api import client
from db.connection import get_db

def test_recovery_wording_and_options(client):
    response = client.get('/recovery')
    assert len(response.json()) == 7
    assert 'you are infected' not in response.text.lower()
    assert 'you are safe' not in response.text.lower()
    assert all(x['version'] and x['uncertainty'] for x in response.json())

def test_review_rejects_invalid_and_missing(client):
    get_db()['analyzed_emails'].insert_one({'_id':'r1','subject':'x','workflow':{'state':'analyzed'}})
    bad = {'state':'analyzed','expected_state':'analyzed','note':'t'}
    assert client.patch('/investigations/r1/workflow', json=bad).status_code == 400
    assert client.patch('/investigations/missing/workflow', json={**bad,'state':'needs_review'}).status_code == 404

def test_history_cas_and_related(client):
    db=get_db()
    for eid,subject in [('a','Payroll verification request now'),('b','Payroll verification request now')]:
        db['analyzed_emails'].insert_one({'_id':eid,'subject':subject,'workflow':{'state':'analyzed'}})
    payload={'state':'confirmed_malicious','expected_state':'analyzed','note':'<script>alert(1)</script>','explanation':'Review complete'}
    r=client.patch('/investigations/a/workflow',json=payload)
    assert r.status_code == 200
    assert r.json()['history'][0]['state'] == 'confirmed_malicious'
    assert client.patch('/investigations/a/workflow',json=payload).status_code == 409
    result=client.get('/investigations/a/related').json()
    assert [m['email_id'] for m in result['matches']] == ['b']
    assert result['matches'][0]['differences']['subject_changed'] is False
    assert client.get('/investigations/missing/related').status_code == 404
