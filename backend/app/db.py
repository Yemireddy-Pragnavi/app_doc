import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Integer, Text, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import settings

def uid(): return str(uuid.uuid4())
def now(): return datetime.now(timezone.utc).isoformat()
class Base(DeclarativeBase): pass
engine = create_engine(settings().database_url, pool_pre_ping=True, **({'connect_args': {'check_same_thread': False}} if settings().database_url.startswith('sqlite') else {}))
Session = sessionmaker(engine, expire_on_commit=False)
class User(Base):
    __tablename__='users'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    github_id:Mapped[str]=mapped_column(String,unique=True)
    login:Mapped[str]=mapped_column(String)
    encrypted_token:Mapped[str]=mapped_column(Text)
class LoginSession(Base):
    __tablename__='login_sessions'
    id:Mapped[str]=mapped_column(String,primary_key=True)
    user_id:Mapped[str]=mapped_column(ForeignKey('users.id'))
    expires:Mapped[int]=mapped_column(Integer)
class Installation(Base):
    __tablename__='github_installations'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    user_id:Mapped[str]=mapped_column(ForeignKey('users.id'),unique=True)
    kind:Mapped[str]=mapped_column(String,default='oauth')
class Repository(Base):
    __tablename__='repositories'
    __table_args__=(UniqueConstraint('user_id','full_name'),)
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    user_id:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    full_name:Mapped[str]=mapped_column(String)
    data:Mapped[dict]=mapped_column(JSON,default=dict)
class Scan(Base):
    __tablename__='repository_scans'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    repository_id:Mapped[str]=mapped_column(ForeignKey('repositories.id'),index=True)
    user_id:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    created_at:Mapped[str]=mapped_column(String,default=now)
    status:Mapped[str]=mapped_column(String,default='queued')
    stage:Mapped[int]=mapped_column(Integer,default=0)
    score:Mapped[int|None]=mapped_column(Integer,nullable=True)
    data:Mapped[dict]=mapped_column(JSON,default=dict)
class Finding(Base):
    __tablename__='security_findings'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    scan_id:Mapped[str]=mapped_column(ForeignKey('repository_scans.id'),index=True)
    user_id:Mapped[str]=mapped_column(ForeignKey('users.id'),index=True)
    status:Mapped[str]=mapped_column(String,default='open')
    data:Mapped[dict]=mapped_column(JSON)
class Event(Base):
    __tablename__='scan_events'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    scan_id:Mapped[str]=mapped_column(ForeignKey('repository_scans.id'),index=True)
    created_at:Mapped[str]=mapped_column(String,default=now)
    data:Mapped[dict]=mapped_column(JSON)
class Audit(Base):
    __tablename__='audit_logs'
    id:Mapped[str]=mapped_column(String,primary_key=True,default=uid)
    user_id:Mapped[str]=mapped_column(String,index=True)
    action:Mapped[str]=mapped_column(String)
    target:Mapped[str]=mapped_column(String)
    created_at:Mapped[str]=mapped_column(String,default=now)
# Separate typed artifact tables retain the scan relationship and normalized JSON.
for table in ['detected_technologies','application_components','application_edges','dependency_findings','secret_findings','scan_summaries','security_scores']:
    type(''.join(x.title() for x in table.split('_')), (Base,), {'__tablename__':table,'__module__':__name__, '__annotations__':{'id':Mapped[str],'scan_id':Mapped[str],'data':Mapped[dict]},'id':mapped_column(String,primary_key=True,default=uid),'scan_id':mapped_column(ForeignKey('repository_scans.id'),index=True),'data':mapped_column(JSON)})
def artifact(db,table,scan_id,data):
    db.execute(Base.metadata.tables[table].insert().values(id=uid(),scan_id=scan_id,data=data))
def get_db():
    with Session() as db: yield db
