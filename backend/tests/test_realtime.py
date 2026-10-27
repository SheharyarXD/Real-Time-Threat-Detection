import json
import socket
import threading
import time
import httpx
import uvicorn
from app.models import StreamEvent
from sqlalchemy import select
from conftest import signin,enroll
from test_api import telemetry


def test_authenticated_http_stream_delivery_reconnect_and_logout(app):
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,log_level='error',lifespan='on'))
    thread=threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);thread.start()
    for _ in range(200):
        if server.started: break
        time.sleep(.01)
    assert server.started
    url=f'http://127.0.0.1:{port}'
    try:
        with httpx.Client(base_url=url,timeout=10,trust_env=False) as client:
            admin=signin(client)
            if app.state.engine.dialect.name=='postgresql':
                from concurrent.futures import ThreadPoolExecutor
                grant=client.post('/api/v1/enrollments',json={'label':'Concurrent lab'},headers=admin).json()
                body={'token':grant['token'],'hostname':'CONCURRENT-LAB','ip':'192.0.2.91','os':'Lab','agent_version':'lab-test'}
                with ThreadPoolExecutor(max_workers=2) as pool:
                    statuses=list(pool.map(lambda _:client.post('/api/v1/agent/enroll',json=body).status_code,range(2)))
                assert sorted(statuses)==[201,401]
            identity,_,_=enroll(client,admin)
            with client.stream('GET','/api/v1/stream') as response:
                assert response.status_code==200
                sent=client.post('/api/v1/agent/telemetry',json=telemetry(),headers={'Authorization':'Bearer '+identity['agentToken']})
                assert sent.status_code==202
                cursor=None
                for line in response.iter_lines():
                    if line.startswith('data: '):
                        event=json.loads(line[6:])
                        if event['type']=='event.created':
                            cursor=event['sequence'];assert event['data']['origin']=='lab';break
                assert cursor is not None
            with client.stream('GET','/api/v1/stream',headers={'Last-Event-ID':str(cursor)}) as response:
                client.post('/api/v1/agent/telemetry',json=telemetry(),headers={'Authorization':'Bearer '+identity['agentToken']})
                lines=response.iter_lines()
                for line in lines:
                    if line.startswith('data: '):
                        event=json.loads(line[6:]);assert event['sequence']>cursor;break
                assert client.post('/api/v1/auth/logout',headers=admin).status_code==200
                assert any(line=='event: session.expired' for line in lines)
            assert client.get('/api/v1/stream').status_code==401
    finally:
        server.should_exit=True;thread.join(timeout=5);sock.close()
    assert not thread.is_alive()
