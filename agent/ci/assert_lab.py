"""Inspect only the disposable local CI database; no production credentials."""
import os,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'backend'))
from sqlalchemy import create_engine,select,func
from sqlalchemy.orm import Session
from app.models import Endpoint,SecurityEvent,TelemetryBatch
engine=create_engine('sqlite:///'+(Path(os.environ['SENTINEL_CI_LAB'])/'windows-ci.sqlite').as_posix())
mode=sys.argv[1]
for _ in range(60):
    with Session(engine) as db:
        host=db.scalar(select(Endpoint))
        count=db.scalar(select(func.count()).select_from(TelemetryBatch))
        if mode=='inventory' and host and host.inventory and host.agent_health:
            assert host.telemetry_origin=='agent' and host.agent_version=='0.3.0'
            assert host.inventory['processes'] and host.inventory['services']
            print('PASS actual Windows service enrolled and reported native inventory/resources/health');break
        if mode=='events':
            event=db.scalar(select(SecurityEvent).where(SecurityEvent.windows_event_id==4242))
            change=db.scalar(select(SecurityEvent).where(SecurityEvent.source=='File integrity',SecurityEvent.details['file_path'].as_string()==str(Path(os.environ['SENTINEL_CI_LAB'])/'selected.txt')))
            if event and change:
                assert event.telemetry_origin=='agent' and event.external_id and change.external_id
                print('PASS actual EventLog subscription and selected-file change reached the backend');break
        if mode=='drained' and count>=int(sys.argv[2])+3:
            print('PASS buffered batches delivered after backend and service restart');break
    time.sleep(2)
else: raise SystemExit('Native integration assertion timed out: '+mode)
