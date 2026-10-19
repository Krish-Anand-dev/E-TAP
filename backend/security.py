"""HTTP identity boundary. Provision random bearer keys; retain only SHA-256 hashes."""
import hashlib
import hmac
import json
import os
import time
import threading
from contextvars import ContextVar
from starlette.responses import JSONResponse

principal = ContextVar('etap_principal', default=None)
_usage = {}
_lock = threading.Lock()

def identity(token):
    if not token or len(token) > 512:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    try:
        entries = json.loads(os.getenv('ETAP_API_KEYS', '[]'))
        for entry in entries:
            if (hmac.compare_digest(digest, entry['sha256']) and
                entry['role'] in {'reporter', 'analyst', 'admin'} and
                isinstance(entry['owner_id'], str) and entry['owner_id'] and
                entry['owner_id'] != '__quarantine__'):
                return {'owner_id': entry['owner_id'], 'role': entry['role']}
    except (ValueError, KeyError, TypeError):
        return None
    return None

class SecurityBoundary:
    """Authenticate before parsing bodies, including chunked multipart requests.

    Quotas are process-local: run one worker until a shared quota store is deployed.
    Both analyze and chat consume the expensive-operation budget before execution.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] == 'OPTIONS' or scope['path'] in {'/', '/health', '/ready', '/docs', '/openapi.json', '/docs/oauth2-redirect'}:
            return await self.app(scope, receive, send)
        headers = dict(scope.get('headers', []))
        authorization = headers.get(b'authorization', b'').decode('latin1')
        user = identity(authorization[7:]) if authorization.startswith('Bearer ') else None
        async def reject(code, detail):
            await JSONResponse({'detail': detail}, status_code=code)(scope, receive, send)
        if user is None:
            return await reject(401, 'A valid E-TAP API key is required.')
        now = int(time.time())
        with _lock:
            for key in list(_usage):
                if key[2] < now - 86400:
                    del _usage[key]
            buckets = [('requests', now // 60 * 60, int(os.getenv('ETAP_REQUESTS_PER_MINUTE', '120')))]
            if scope['path'] in {'/analyze', '/chat'}:
                buckets.append(('provider_operations', now // 86400 * 86400, int(os.getenv('ETAP_PROVIDER_OPERATIONS_PER_DAY', '100'))))
            limited = any(_usage.get((user['owner_id'], name, period), 0) >= limit for name, period, limit in buckets)
            if not limited:
                for name, period, _ in buckets:
                    key = (user['owner_id'], name, period)
                    _usage[key] = _usage.get(key, 0) + 1
        if limited:
            return await reject(429, 'Identity request or provider-operation budget exhausted.')
        maximum = 26 * 1024 * 1024 if scope['path'] == '/analyze' else 64 * 1024
        try:
            if int(headers.get(b'content-length', b'0')) > maximum:
                return await reject(413, 'Request body exceeds limit.')
        except ValueError:
            return await reject(400, 'Invalid content length.')
        # Bounded buffering prevents the multipart parser from spooling an unbounded body.
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > maximum:
                return await reject(413, 'Request body exceeds limit.')
            chunks.append(message)
            if not message.get('more_body', False):
                break
        async def bounded_receive():
            return chunks.pop(0) if chunks else await receive()
        token = principal.set(user)
        scope.setdefault('state', {})['principal'] = user
        try:
            import asyncio
            from db.connection import get_db
            from workflow_c import purge_expired
            await asyncio.to_thread(purge_expired, get_db())
            await self.app(scope, bounded_receive, send)
        finally:
            principal.reset(token)
