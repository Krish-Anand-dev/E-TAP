"""Not live: original-message and webhook contracts. No outbound dispatcher."""
import hashlib
import hmac
import ipaddress
import json
import socket
import time
from typing import Protocol
from urllib.parse import urlsplit

EVENTS = {'analysis.completed', 'review.changed'}
RESERVED_EVENTS = {'sandbox.completed'}  # extension point only; never emitted

class OriginalMessageProvider(Protocol):
    def retrieve_selected(self, account_id: str, message_id: str) -> bytes: ...

class MockOriginalMessageProvider:
    def __init__(self, messages):
        self.messages = messages

    def retrieve_selected(self, account_id, message_id):
        raw = self.messages[(account_id, message_id)]
        if not isinstance(raw, bytes) or len(raw) > 25 * 1024 * 1024:
            raise ValueError('Invalid original artifact')
        return raw

def validate_target(url, resolver=socket.getaddrinfo):
    """Validation contract only. A future sender must pin returned IPs and forbid redirects."""
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.port not in {None,443}:
        raise ValueError('Only HTTPS port 443 targets without credentials/fragments')
    addresses = {row[4][0] for row in resolver(parsed.hostname,443,type=socket.SOCK_STREAM)}
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('Target must resolve entirely to public addresses')
    return sorted(addresses)

def webhook_body(event, event_id, report_id):
    if event not in EVENTS:
        raise ValueError('Unsupported or reserved event')
    # No content, notes, indicator strings or AI output in notifications.
    for identifier in (event_id,report_id):
        if not isinstance(identifier,str) or not 1 <= len(identifier) <= 100 or not all(c.isalnum() or c in '-_:' for c in identifier):
            raise ValueError('Invalid event identifier')
    return json.dumps({'event':event,'id':event_id,'report_id':report_id},sort_keys=True,separators=(',',':')).encode()

def sign(body, secret, timestamp):
    return hmac.new(secret, str(timestamp).encode()+b'.'+body, hashlib.sha256).hexdigest()

def verify(body, secret, timestamp, signature, seen, current_time=None):
    current_time = int(time.time()) if current_time is None else current_time
    if abs(current_time-timestamp) > 300 or not hmac.compare_digest(sign(body,secret,timestamp), signature):
        return False
    event = json.loads(body)
    if webhook_body(event['event'],event['id'],event['report_id']) != body or event['id'] in seen:
        return False
    seen.add(event['id'])
    return True

def retry_delay(attempt):
    if not 0 <= attempt < 5:
        raise ValueError('Retry budget exhausted')
    return min(300, 2**attempt * 5)
