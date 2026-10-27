"""Cross-platform operator launcher: Python 3.12+ must be installed first."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import venv

ROOT=Path(__file__).resolve().parent

def main():
    if sys.version_info<(3,12): raise SystemExit('Install Python 3.12 or later before running the backend.')
    os.chdir(ROOT)
    interpreter=ROOT/'.venv'/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    if not interpreter.exists():
        print('[SETUP] Creating the backend virtual environment...')
        venv.EnvBuilder(with_pip=True).create(ROOT/'.venv')
    fingerprint=hashlib.sha256((ROOT/'requirements.lock').read_bytes()).hexdigest()
    stamp=ROOT/'.venv'/'requirements.sha256'
    if not stamp.exists() or stamp.read_text()!=fingerprint or '--reinstall' in sys.argv:
        stamp.unlink(missing_ok=True)
        subprocess.run([str(interpreter),'-m','pip','install','-r','requirements.lock'],check=True)
        stamp.write_text(fingerprint)
    if not (ROOT/'.env').exists():
        print('[SETUP] Configure an existing local PostgreSQL database. No database service is provisioned automatically.')
        subprocess.run([str(interpreter),'-m','app.cli','init-config'],check=True)
    subprocess.run([str(interpreter),'-m','alembic','upgrade','head'],check=True)
    result=subprocess.run([str(interpreter),'-m','app.cli','has-users'])
    if result.returncode==3:
        print('[SETUP] Create the first administrator. No default password is supplied.')
        subprocess.run([str(interpreter),'-m','app.cli','create-user','--role','administrator'],check=True)
    elif result.returncode!=0: raise SystemExit(result.returncode)
    print('[START] Backend: http://127.0.0.1:8000. Keep this window open; Ctrl+C stops it.')
    return subprocess.call([str(interpreter),'-m','uvicorn','app.main:create_app','--factory','--host','127.0.0.1','--port','8000','--no-proxy-headers'])

if __name__=='__main__':
    try: sys.exit(main())
    except KeyboardInterrupt: sys.exit(0)
    except subprocess.CalledProcessError: raise SystemExit('Setup failed. Check the output above and backend/README.md.')
