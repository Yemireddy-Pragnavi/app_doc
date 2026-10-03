import hashlib, re, secrets, time
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request, Depends
from sqlalchemy.orm import Session as DBSession
from .config import settings
from .db import get_db, LoginSession, User

def cipher():
    key=settings().token_encryption_key
    if not key: raise RuntimeError('TOKEN_ENCRYPTION_KEY must be configured')
    return Fernet(key.encode())
def encrypt(token): return cipher().encrypt(token.encode()).decode()
def decrypt(value): return cipher().decrypt(value.encode()).decode()
def repo_name(url):
    parsed=urlparse(url)
    if parsed.scheme!='https' or parsed.hostname!='github.com' or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
        raise ValueError('Use an https://github.com/owner/repository URL')
    path=parsed.path.rstrip('/')
    if path.endswith('.git'):path=path[:-4]
    if not re.fullmatch(r'/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}',path):raise ValueError('Invalid GitHub repository URL')
    return path[1:]
def secret_hash(raw):return hashlib.sha256(raw.encode()).hexdigest()
def create_session(db,user_id):
    raw=secrets.token_urlsafe(40)
    db.add(LoginSession(id=secret_hash(raw),user_id=user_id,expires=int(time.time())+86400))
    return raw
def current_user(request:Request,db:DBSession=Depends(get_db)):
    raw=request.cookies.get('asd_session','')
    if not raw:raise HTTPException(401,'Please sign in with GitHub')
    session=db.get(LoginSession,secret_hash(raw))
    if not session or session.expires<int(time.time()):raise HTTPException(401,'Please sign in with GitHub')
    user=db.get(User,session.user_id)
    if not user:raise HTTPException(401,'Session expired')
    if request.method not in ('GET','HEAD','OPTIONS') and request.headers.get('origin')!=settings().frontend_url.rstrip('/'):
        raise HTTPException(403,'Invalid request origin')
    return user

def redact(text):
    text=str(text)
    # Redact all values resembling tokens, private keys, credential assignments or DB URLs.
    text=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----','[REDACTED PRIVATE KEY]',text)
    text=re.sub(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://\S+','[REDACTED CONNECTION]',text)
    text=re.sub(r'(?i)((?:secret|token|password|api[_-]?key|service[_-]?role)[\w-]*\s*[=:]\s*)[\S]+',r'\1[REDACTED]',text)
    text=re.sub(r'\b(?:sk-[\w-]+|gh[pousr]_[\w]+|AKIA[0-9A-Z]+|eyJ[\w.-]+|[A-Za-z0-9_+/=-]{32,})\b','[REDACTED]',text)
    return text[:3000]
