import os
import secrets
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from app.config import Settings, ROOT
from app.main import create_app
from app.models import Base, User
from app.services import password_hasher, audit

@pytest.fixture
def settings(tmp_path):
    url=os.environ.get("SENTINEL_TEST_DATABASE_URL",f"sqlite:///{tmp_path/'test.sqlite'}")
    # Override only with an isolated disposable test database; the suite drops its schema.
    engine=create_engine(url,connect_args={"prepare_threshold":None} if url.startswith("postgresql") else {})
    Base.metadata.drop_all(engine)
    with engine.begin() as conn:
        from sqlalchemy import text
        conn.execute(text('DROP TABLE IF EXISTS alembic_version'))
    engine.dispose()
    cfg=Config(str(ROOT/'alembic.ini'));cfg.attributes['database_url']=url
    command.upgrade(cfg,'head')
    return Settings(environment='test',database_url=url,session_secret=secrets.token_urlsafe(48),allowed_hosts=['testserver','localhost','127.0.0.1'],allowed_origins=['http://127.0.0.1:3000'],stream_seconds=0.01,request_limit=10000,login_limit=100,ingest_limit=1000)

@pytest.fixture
def app(settings):
    app=create_app(settings)
    with app.state.sessions() as db:
        for name,role in [('admin','administrator'),('analyst','analyst')]:
            user=User(username=name,role=role,password_hash=password_hasher.hash('test-only-long-password'))
            db.add(user);db.flush();audit(db,'test-fixture','user.created',user.id)
        db.commit()
    return app

@pytest.fixture
def client(app):
    with TestClient(app) as client: yield client

def signin(client,username='admin'):
    response=client.post('/api/v1/auth/login',json={'username':username,'password':'test-only-long-password'},headers={'Origin':'http://127.0.0.1:3000'})
    assert response.status_code==200,response.text
    return {'Origin':'http://127.0.0.1:3000','X-CSRF-Token':response.json()['csrfToken']}

@pytest.fixture
def admin(client): return signin(client)

def enroll(client,admin,hostname='LAB-WIN-01'):
    grant=client.post('/api/v1/enrollments',json={'label':hostname,'group':'Lab'},headers=admin)
    assert grant.status_code==201,grant.text
    payload={'token':grant.json()['token'],'hostname':hostname,'ip':'192.0.2.80','os':'Windows Server lab fixture','agent_version':'lab-test-2'}
    response=client.post('/api/v1/agent/enroll',json=payload)
    assert response.status_code==201,response.text
    return response.json(),payload,grant.json()
