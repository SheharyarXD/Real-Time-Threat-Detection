"""Optional complete Next.js -> FastAPI -> database -> SSE contract test."""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import httpx
import pytest
import uvicorn
from app.config import ROOT
from test_api import telemetry

@pytest.mark.skipif(os.environ.get('SENTINEL_RUN_PROXY_TEST')!='1',reason='Requires a completed Next production build; set SENTINEL_RUN_PROXY_TEST=1')
def test_next_proxy_cookie_csrf_ingestion_and_stream(app):
    backend_sock=socket.socket();backend_sock.bind(('127.0.0.1',0));backend_port=backend_sock.getsockname()[1]
    front_sock=socket.socket();front_sock.bind(('127.0.0.1',0));front_port=front_sock.getsockname()[1];front_sock.close()
    backend_url=f'http://127.0.0.1:{backend_port}';frontend_url=f'http://127.0.0.1:{front_port}'
    app.state.settings.allowed_origins.append(frontend_url)
    api=uvicorn.Server(uvicorn.Config(app,log_level='error'))
    thread=threading.Thread(target=api.run,kwargs={'sockets':[backend_sock]},daemon=True);thread.start()
    process=subprocess.Popen(['node','node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port',str(front_port)],cwd=ROOT.parent,env={**os.environ,'SENTINEL_API_URL':backend_url,'NEXT_TELEMETRY_DISABLED':'1'},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        with httpx.Client(base_url=frontend_url,timeout=15,trust_env=False) as client:
            for _ in range(200):
                if process.poll() is not None: pytest.fail('Next production server exited before readiness')
                try:
                    if client.get('/live').status_code==200: break
                except httpx.ConnectError: pass
                time.sleep(.05)
            else: pytest.fail('Frontend did not become ready')
            login=client.post('/api/v1/auth/login',json={'username':'admin','password':'test-only-long-password'},headers={'Origin':frontend_url})
            assert login.status_code==200,login.text
            assert 'HttpOnly' in login.headers['set-cookie'] and 'SameSite=strict' in login.headers['set-cookie']
            headers={'Origin':frontend_url,'X-CSRF-Token':login.json()['csrfToken']}
            assert client.get('/api/v1/session').status_code==200
            assert client.post('/api/v1/enrollments',json={'label':'Proxy lab'}).status_code==403
            grant=client.post('/api/v1/enrollments',json={'label':'Proxy lab'},headers=headers)
            assert grant.status_code==201,grant.text
            assert client.post('/api/v1/agent/enroll',json={}).status_code in {404,405}
            with httpx.Client(base_url=backend_url,trust_env=False,timeout=10) as agent:
                enrolled=agent.post('/api/v1/agent/enroll',json={'token':grant.json()['token'],'hostname':'PROXY-LAB','ip':'192.0.2.90','os':'Lab fixture','agent_version':'lab-test'})
                assert enrolled.status_code==201,enrolled.text
                auth={'Authorization':'Bearer '+enrolled.json()['agentToken']}
                with client.stream('GET','/api/v1/stream') as stream:
                    assert stream.status_code==200
                    assert agent.post('/api/v1/agent/telemetry',json=telemetry(),headers=auth).status_code==202
                    for line in stream.iter_lines():
                        if line.startswith('data: '):
                            event=json.loads(line[6:])
                            if event['type']=='event.created':
                                assert event['data']['origin']=='lab';break
                    else: pytest.fail('Frontend proxy did not deliver the event stream')
            assert client.get('/api/v1/events').json()['total']==1
            assert client.get('/api/v1/endpoints').json()['items'][0]['hostname']=='PROXY-LAB'
            assert client.post('/api/v1/auth/logout',headers=headers).status_code==200
            assert client.get('/api/v1/session').status_code==401
    finally:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill();process.wait()
        api.should_exit=True;thread.join(timeout=5);backend_sock.close()
