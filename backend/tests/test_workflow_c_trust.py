from datetime import timedelta
from db.fake_mongo import FakeDatabase
from workflow_c import delete_record, purge_expired, now, share_pack
from test_workflow_c_api import client

def test_delete_removes_vector_and_campaign():
    db = FakeDatabase()
    db['analyzed_emails'].insert_one({'_id':'a','rag_embedding':[1], 'rag_summary':'secret', 'campaign_id':'c'})
    db['campaigns'].insert_one({'campaign_id':'c','members':['a']})
    delete_record(db, db['analyzed_emails'].find_one({'_id':'a'}))
    assert not list(db['analyzed_emails'].find())
    assert not list(db['campaigns'].find())

def test_expiry():
    db = FakeDatabase()
    db['analyzed_emails'].insert_one({'_id':'expired','expires_at':now()-timedelta(days=1)})
    db['analyzed_emails'].insert_one({'_id':'current','expires_at':now()+timedelta(days=1)})
    purge_expired(db)
    assert [d['_id'] for d in db['analyzed_emails'].find()] == ['current']

def test_share_has_no_sensitive_text():
    import json
    secret = 'recipient@example.test secretToken <script>alert(1)</script>'
    doc = {'_id':'synthetic-report', 'subject':secret, 'body_text':secret, 'from_email':secret, 'to_email':secret, 'verdict':'LOW RISK', 'risk_score':10, 'final_assessment':{'explanation':secret}, 'ioc_analysis':{'urls':['https://secretToken.example.test/path?recipient=recipient@example.test'], 'domains':['secretToken.example.test'], 'hashes':['a'*64]}, 'header_analysis': {'spf': secret}}
    value = json.dumps(share_pack(doc))
    for fragment in ['recipient@','secretToken','<script>','body_text']:
        assert fragment not in value
    assert 'a'*64 in value

def test_delete_export_and_preferences(client):
    assert client.delete('/investigations/missing').status_code == 404
    assert client.get('/investigations/missing/share').status_code == 404
    assert client.delete('/investigations').json()['deleted'] == 0
    assert client.put('/preferences', json={'retention_days':0}).status_code == 422
    assert client.put('/preferences', json={'retention_days':7}).status_code == 200
