"""Run inside the API container: python -m app.preflight. Never prints secret values."""
import json
from urllib.parse import urlsplit
from .config import settings
from .db import Session
from .operations import service_status


def main():
    cfg=settings()
    with Session() as db:
        result=service_status(db,include_worker=True)
    frontend=urlsplit(cfg.frontend_url)
    callback=urlsplit(cfg.github_callback_url)
    result['checks']['callback_path']=callback.path.endswith('/api/auth/callback')
    result['checks']['frontend_origin']=bool(frontend.hostname and frontend.path in ('','/'))
    if cfg.cookie_secure:
        result['checks']['https']=frontend.scheme=='https' and callback.scheme=='https'
    result['ready']=all(result['checks'].values())
    print(json.dumps(result,indent=2))
    return 0 if result['ready'] else 1

if __name__=='__main__':raise SystemExit(main())
