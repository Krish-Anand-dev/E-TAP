import pytest
from test_workflow_c_api import client
from db.connection import get_db
from integrations import MockOriginalMessageProvider, validate_target, webhook_body, sign, verify, retry_delay

def test_mock_original_preserves_bytes_and_account_boundary():
    raw=b'From: synthetic@example.test\r\n\r\nOriginal'
    provider=MockOriginalMessageProvider({('alice','message'):raw})
    assert provider.retrieve_selected('alice','message') == raw
    with pytest.raises(KeyError): provider.retrieve_selected('bob','message')

@pytest.mark.parametrize('target,address', [('http://example.test','8.8.8.8'),('https://example.test','127.0.0.1'),('https://example.test','169.254.169.254'),('https://example.test','::1'),('https://user:secret@example.test','8.8.8.8'),('https://example.test:444','8.8.8.8')])
def test_webhook_target_denied(target,address):
    with pytest.raises(ValueError): validate_target(target,lambda *a,**kw:[(None,None,None,None,(address,443))])

def test_webhook_integrity_replay_and_reserved_event():
    secret=b'synthetic-test-secret-only'
    body=webhook_body('analysis.completed','evt-1','report-1')
    signature=sign(body,secret,1000)
    seen=set()
    assert verify(body,secret,1000,signature,seen,current_time=1000)
    assert not verify(body,secret,1000,signature,seen,current_time=1000)
    assert not verify(body+b' ',secret,1000,signature,set(),current_time=1000)
    assert not verify(body,secret,1000,signature,set(),current_time=2000)
    with pytest.raises(ValueError): webhook_body('sandbox.completed','evt','report')
    with pytest.raises(ValueError): webhook_body('analysis.completed','<script>','report')
    assert [retry_delay(i) for i in range(5)] == [5,10,20,40,80]

def test_baseline_case_and_measured_analytics(client):
    db=get_db()
    db['analyzed_emails'].insert_one({'_id':'a','risk_score':99,'verdict':'HIGH-RISK PHISHING','ioc_analysis':{'domains':['vendor.example']},'provider_status':{'analysis_duration_ms':42,'providers':{'gemini':{'status':'disabled'}}}})
    assert client.put('/baselines',json={'domains':['vendor.example']}).status_code == 200
    assert client.get('/baselines').json()['domains'] == ['vendor.example']
    assert db['analyzed_emails'].find_one({'_id':'a'})['risk_score'] == 99
    assert client.put('/investigations/missing/case',json={'label':'review','assignee':'analyst'}).status_code == 404
    assert client.put('/investigations/a/case',json={'label':'review','assignee':'analyst'}).status_code == 200
    assert client.put('/investigations/a/feedback',json={'value':'helpful'}).status_code == 200
    stats=client.get('/analytics',).json()
    assert stats['investigations'] == 1
    assert stats['mean_latency_ms'] == 42 and stats['latency_samples'] == 1
    assert stats['mean_time_to_triage_seconds'] is None
    assert stats['feedback'] == {'helpful':1}
