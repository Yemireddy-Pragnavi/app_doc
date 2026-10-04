"""Operational readiness and stale-job recovery without exposing configuration values."""
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, update, text
from cryptography.fernet import Fernet
from redis import Redis
from .config import settings
from .db import Scan, RuntimeScan, Event


def reconcile_stale(db, user_id=None):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
    changed = 0
    for model in (Scan, RuntimeScan):
        query = select(model).where(model.status.in_(['queued', 'running']), model.created_at < cutoff)
        if user_id:
            query = query.where(model.user_id == user_id)
        for scan in db.scalars(query):
            values = {'status': 'failed', 'data': {**scan.data, 'error': 'Scan exceeded its scheduling/runtime window. Retry after checking worker health.', 'decision': 'INCOMPLETE'}}
            if model is Scan:
                values['score'] = None
            result = db.execute(update(model).where(model.id == scan.id, model.status.in_(['queued', 'running'])).values(**values))
            changed += result.rowcount
    db.commit()
    return changed


def service_status(db, include_worker=False):
    checks = {}
    try:
        db.execute(text('SELECT 1'))
        checks['database'] = True
    except Exception:
        db.rollback()
        checks['database'] = False
    try:
        with Redis.from_url(settings().redis_url, socket_connect_timeout=2, socket_timeout=2) as redis:
            checks['queue'] = bool(redis.ping())
    except Exception:
        checks['queue'] = False
    try:
        Fernet(settings().token_encryption_key.encode())
        encryption = True
    except Exception:
        encryption = False
    checks['github_oauth'] = bool(settings().github_client_id and settings().github_client_secret and len(settings().session_secret) >= 32 and encryption)
    if include_worker:
        from .worker import celery
        try:
            checks['worker'] = bool(celery.control.inspect(timeout=2).ping()) if checks['queue'] else False
        except Exception:
            checks['worker'] = False
    return {'ready': all(checks.values()), 'checks': checks, 'runtime_hosts_configured': bool(settings().runtime_allowed_hosts)}
