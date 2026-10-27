"""Disposable Windows CI backend. Never load real credentials or a real database."""
import os
import secrets
import sys
from datetime import timedelta
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'backend'))
from alembic import command
from alembic.config import Config
from app.config import Settings
from app.models import User,Enrollment,utcnow
from app.services import password_hasher,digest
from app.main import create_app
import uvicorn
lab=Path(os.environ['SENTINEL_CI_LAB'])
url='sqlite:///'+(lab/'windows-ci.sqlite').as_posix()
cfg=Config(str(ROOT/'backend/alembic.ini'));cfg.attributes['database_url']=url;command.upgrade(cfg,'head')
settings=Settings(environment='test',database_url=url,session_secret=secrets.token_urlsafe(48),allowed_hosts=['127.0.0.1'],request_limit=10000,ingest_limit=10000)
app=create_app(settings)
with app.state.sessions() as db:
    user=db.query(User).filter(User.username=='windows-ci').one_or_none()
    if user is None:
        user=User(username='windows-ci',password_hash=password_hasher.hash(secrets.token_urlsafe(32)),role='administrator');db.add(user);db.flush()
        token=secrets.token_urlsafe(40);db.add(Enrollment(digest=digest(token),label='Isolated Windows CI',group='CI',created_by=user.id,expires_at=utcnow()+timedelta(minutes=30)))
        db.commit();(lab/'enrollment-token.txt').write_text(token)
uvicorn.run(app,host='127.0.0.1',port=18443,log_level='warning')
