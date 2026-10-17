"""Owner-scoped trust features. No dynamic attachment execution."""
from datetime import datetime, timedelta, timezone
import re
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from db.connection import get_db
from db.repository import get_analysis, update_analysis_fields

router = APIRouter()

def now():
    return datetime.now(timezone.utc)

def owned(email_id):
    doc = get_analysis(get_db(), email_id)
    if doc is None:
        raise HTTPException(404, 'Investigation not found')
    return doc

def delete_record(db, doc):
    """Embedded RAG vectors are removed with their analysis. Rebuild campaign references."""
    eid = str(doc['_id'])
    db['analyzed_emails'].delete_many({'_id': doc['_id']})
    db['emails'].delete_many({'email_id': eid})
    for campaign in db['campaigns'].find({}):
        remaining = [d for d in db['analyzed_emails'].find({'campaign_id': campaign['campaign_id']})]
        if not remaining:
            db['campaigns'].delete_many({'_id': campaign['_id']})
        else:
            indicators = sorted({v for d in remaining for values in (d.get('ioc_analysis') or {}).values() if isinstance(values, list) for v in values if isinstance(v, str)})
            db['campaigns'].update_one({'_id': campaign['_id']}, {'$set': {'members': [str(d['_id']) for d in remaining], 'shared_infrastructure': indicators}})
    # Stored graph/correlation snapshots can contain the deleted ID/indicators.
    for remaining in db['analyzed_emails'].find({}):
        db['analyzed_emails'].update_one({'_id': remaining['_id']}, {'$set': {'graph_diffusion': {}, 'correlation': {}, 'historical_correlation': {}, 'evidence_report': None, 'rag_summary': None, 'rag_embedding': None}})
    from ai_engine.graph_diffusion import invalidate_graph_cache
    invalidate_graph_cache()

def purge_expired(db):
    for doc in list(db['analyzed_emails'].find({'expires_at': {'$lte': now()}})):
        delete_record(db, doc)

def finish_analysis(report):
    db = get_db()
    prefs = db['preferences'].find_one({'kind': 'settings'}) or {}
    days = prefs.get('retention_days', 30)
    fields = {'expires_at': now() + timedelta(days=days), 'retention_days': days}
    doc = get_analysis(db, report['email_id']) or {}
    if not doc.get('workflow'):
        fields['workflow'] = {'state': 'analyzed', 'history': [{'state': 'submitted', 'at': now().isoformat()}, {'state': 'analyzed', 'at': now().isoformat()}], 'notes': []}
    update_analysis_fields(db, report['email_id'], fields)
    declared = set((db['preferences'].find_one({'kind':'baselines'}) or {}).get('domains',[]))
    observed = set((report.get('iocs') or {}).get('domains',[]))
    report['baseline_context'] = {'matched_domains':sorted(declared & observed), 'source':'user-declared context', 'effect':'No change to verdict or risk score.'}
    update_analysis_fields(db, report['email_id'], {'baseline_context':report['baseline_context']})
    report['retention'] = {'days': days, 'expires_at': fields['expires_at'].isoformat()}
    return report

class Preferences(BaseModel):
    retention_days: int = Field(30, ge=1, le=365)

@router.get('/preferences')
def preferences():
    doc = get_db()['preferences'].find_one({'kind':'settings'}) or {}
    return {'retention_days': doc.get('retention_days',30)}

@router.put('/preferences')
def save_preferences(payload: Preferences):
    get_db()['preferences'].update_one({'kind':'settings'}, {'$set': payload.model_dump()}, upsert=True)
    return {**payload.model_dump(), 'applies_to': 'future analyses; delete existing reports separately'}

@router.delete('/investigations/{email_id}')
def delete_investigation(email_id: str):
    delete_record(get_db(), owned(email_id))
    return {'deleted': True}

@router.delete('/investigations')
def delete_all():
    db = get_db()
    count = db['analyzed_emails'].delete_many({}).deleted_count
    db['emails'].delete_many({})
    db['campaigns'].delete_many({})
    from ai_engine.graph_diffusion import invalidate_graph_cache
    invalidate_graph_cache()
    return {'deleted': count}

def share_pack(doc):
    """No raw text, recipient, URL, domain or AI prose can enter this allowlist.

    Even hostnames may encode secrets: omit them rather than promise heuristic redaction.
    Hashes, enumerated checks and evidence IDs still support a useful review.
    """
    from verdicts import finalize_verdict
    decision = finalize_verdict(doc.get('verdict'), doc.get('risk_score',0))
    headers = doc.get('header_analysis') or {}
    checks = {k: headers.get(k) if headers.get(k) in {'pass','fail','none','neutral','softfail','temperror','permerror','unavailable'} else 'unknown' for k in ('spf','dkim','dmarc')}
    hashes = [h for h in (doc.get('ioc_analysis') or {}).get('hashes',[]) if isinstance(h,str) and re.fullmatch(r'[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}', h)]
    evidence = [{'id': e['id'], 'kind': e.get('kind'), 'status': e.get('status')} for e in (doc.get('evidence_report') or {}).get('evidence', []) if re.fullmatch(r'[a-zA-Z0-9_.:-]{1,100}', str(e.get('id','')))]
    # kind/status are also restricted; never trust stored free-form data for a share export.
    for e in evidence:
        e['kind'] = e['kind'] if e['kind'] in {'observed','reputation','ai_inferred'} else 'unknown'
        e['status'] = e['status'] if e['status'] in {'present','absent','unavailable'} else 'unknown'
    return {'schema_version': 1, 'report_id': str(doc['_id']), 'verdict': decision['verdict'], 'risk_score': decision['risk_score'], 'header_checks': checks, 'hashes': hashes, 'evidence': evidence, 'reasoning': 'Review the referenced evidence and unavailable checks; this assessment does not establish compromise or safety.', 'limitations': 'Body, addresses, free-form reasoning, filenames and all URL/domain values omitted, including secret-bearing hosts. Original artifact is not included.'}

@router.get('/investigations/{email_id}/share')
def share(email_id: str):
    return share_pack(owned(email_id))


@router.get('/recovery')
def recovery():
    from recovery import GUIDANCE, guidance
    return [guidance(k) for k in GUIDANCE]


STATES = {'submitted', 'analyzed', 'needs_review', 'confirmed_malicious', 'benign_or_spam', 'unresolved'}

class Review(BaseModel):
    state: str
    expected_state: str
    note: str = Field('', max_length=2000)
    explanation: str = Field('', max_length=1000)

@router.get('/investigations/{email_id}/workflow')
def workflow(email_id: str):
    return owned(email_id).get('workflow') or {'state':'analyzed', 'history':[], 'notes':[], 'legacy':True}

@router.patch('/investigations/{email_id}/workflow')
def review(email_id: str, payload: Review, request: Request):
    doc = owned(email_id)
    role = request.state.principal['role']
    current = doc.get('workflow') or {'state':'analyzed', 'history':[], 'notes':[]}
    if payload.state not in STATES or payload.state in {'submitted','analyzed'}:
        raise HTTPException(400, 'Invalid review transition')
    if role == 'reporter' and (payload.state != 'needs_review' or current['state'] not in {'submitted','analyzed','unresolved'}):
        raise HTTPException(403, 'Analyst role required for this transition')
    if payload.expected_state != current['state']:
        raise HTTPException(409, 'Review changed; refresh before editing')
    if len(current.get('history',[])) >= 200:
        raise HTTPException(409, 'Review history limit reached')
    event = {'state':payload.state, 'at':now().isoformat(), 'actor':request.state.principal['owner_id'], 'role':role}
    update = {'$set': {'workflow.state':payload.state, 'workflow.explanation':payload.explanation}, '$push': {'workflow.history':event, 'workflow.notes': {'text':payload.note, **event}}}
    query = {'_id':doc['_id'], 'workflow.state':doc.get('workflow',{}).get('state')}
    changed = get_db()['analyzed_emails'].find_one_and_update(query, update)
    if changed is None:
        raise HTTPException(409, 'Review changed; refresh before editing')
    return workflow(email_id)


@router.get('/investigations/{email_id}/related')
def related(email_id: str):
    doc = owned(email_id)
    tokens = set(re.findall(r'\w+', (doc.get('subject') or '').lower()))
    own_iocs = {v for values in (doc.get('ioc_analysis') or {}).values() if isinstance(values,list) for v in values if isinstance(v,str)}
    matches = []
    candidates = list(get_db()['analyzed_emails'].find({}).sort('analyzed_at',-1).limit(200))
    for other in candidates:
        if str(other['_id']) == email_id:
            continue
        theirs = set(re.findall(r'\w+', (other.get('subject') or '').lower()))
        score = len(tokens & theirs) / max(1,len(tokens | theirs))
        their_iocs = {v for values in (other.get('ioc_analysis') or {}).values() if isinstance(values,list) for v in values if isinstance(v,str)}
        if (score >= .8 and len(tokens) >= 3) or own_iocs & their_iocs:
            matches.append({'email_id':str(other['_id']), 'campaign_id':other.get('campaign_id'), 'subject_similarity':round(score,3), 'basis':'inferred subject similarity or observed indicator overlap', 'differences': {'subject_changed':doc.get('subject') != other.get('subject'), 'sender_changed':doc.get('from_email') != other.get('from_email'), 'indicators_only_here':sorted(own_iocs-their_iocs), 'indicators_only_there':sorted(their_iocs-own_iocs)}, 'seen':other.get('analyzed_at')})
    dates = [m['seen'] for m in matches if m['seen']] + ([doc['analyzed_at']] if doc.get('analyzed_at') else [])
    return {'matches':matches, 'first_seen':min(dates) if dates else None, 'last_seen':max(dates) if dates else None, 'scope':'At most 200 recent submissions owned by this account; not mailbox prevalence. Similarity does not change the threat verdict.'}


class CaseAssignment(BaseModel):
    label: str = Field(..., min_length=1, max_length=80)
    assignee: str = Field(..., min_length=1, max_length=80)

@router.put('/investigations/{email_id}/case')
def assign_case(email_id: str, payload: CaseAssignment, request: Request):
    doc = owned(email_id)
    actor = request.state.principal
    if actor['role'] not in {'analyst','admin'}:
        raise HTTPException(403, 'Analyst role required')
    if payload.assignee != actor['owner_id']:
        raise HTTPException(400, 'Cross-owner assignment is not enabled')
    record = {**payload.model_dump(), 'at':now().isoformat(), 'actor':actor['owner_id'], 'campaign_id':doc.get('campaign_id')}
    if len(doc.get('case_history', [])) >= 100:
        raise HTTPException(409, 'Assignment history limit reached')
    get_db()['analyzed_emails'].update_one({'_id':doc['_id']}, {'$set':{'case':record}, '$push':{'case_history':record}})
    return record


class Baselines(BaseModel):
    domains: list[str] = Field(default_factory=list, max_length=100)

@router.get('/baselines')
def baselines():
    return {'domains':(get_db()['preferences'].find_one({'kind':'baselines'}) or {}).get('domains',[]), 'purpose':'User-declared context only; never overrides threat evidence.'}

@router.put('/baselines')
def save_baselines(payload: Baselines):
    domains = sorted(set(d.strip().lower() for d in payload.domains))
    if any(len(d)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',d) for d in domains):
        raise HTTPException(400, 'Use bare ASCII domain names')
    get_db()['preferences'].update_one({'kind':'baselines'}, {'$set':{'domains':domains}},upsert=True)
    return baselines()


class Feedback(BaseModel):
    value: str

@router.put('/investigations/{email_id}/feedback')
def feedback(email_id: str, payload: Feedback):
    doc = owned(email_id)
    if payload.value not in {'helpful','incorrect'}:
        raise HTTPException(400,'Unsupported feedback')
    get_db()['analyzed_emails'].update_one({'_id':doc['_id']},{'$set':{'feedback':{'value':payload.value,'at':now().isoformat()}}})
    return {'saved':True}


@router.get('/analytics')
def analytics():
    from collections import Counter
    docs = list(get_db()['analyzed_emails'].find({}).sort('analyzed_at',-1).limit(5000))
    outcomes = Counter((d.get('workflow') or {}).get('state','unrecorded') for d in docs)
    provider = Counter()
    latencies, triage = [], []
    for doc in docs:
        status=doc.get('provider_status') or {}
        for name, entry in status.get('providers',{}).items():
            provider[name+':'+str(entry.get('status','unknown'))] += 1
        duration=status.get('analysis_duration_ms')
        if isinstance(duration,(int,float)):
            latencies.append(duration)
        history=(doc.get('workflow') or {}).get('history',[])
        start=next((x['at'] for x in history if x['state']=='submitted'),None)
        reviewed=next((x['at'] for x in history if x['state'] in {'confirmed_malicious','benign_or_spam','unresolved'}),None)
        if start and reviewed:
            triage.append((datetime.fromisoformat(reviewed)-datetime.fromisoformat(start)).total_seconds())
    domains=Counter(v for d in docs for v in (d.get('ioc_analysis') or {}).get('domains',[]) if isinstance(v,str))
    campaigns=Counter(d['campaign_id'] for d in docs if d.get('campaign_id'))
    return {'scope':'At most 5000 recent owner submissions; no detection accuracy or mailbox prevalence estimate.', 'investigations':len(docs), 'outcomes':dict(outcomes), 'provider_status_counts':dict(provider), 'mean_latency_ms':sum(latencies)/len(latencies) if latencies else None, 'latency_samples':len(latencies), 'mean_time_to_triage_seconds':sum(triage)/len(triage) if triage else None, 'triage_samples':len(triage), 'top_domains':domains.most_common(10), 'campaigns':campaigns.most_common(10), 'feedback':dict(Counter((d.get('feedback') or {}).get('value','unrated') for d in docs))}
