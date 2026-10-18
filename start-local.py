"""Start the complete E-TAP web app on loopback, with a dynamic API port.

First run: python start-local.py --install
No MongoDB installed: python start-local.py --install --memory-db
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent
VENV_PYTHON = ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def wait_for_http(url, process, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f'Service exited during startup ({process.returncode}). See logs above.')
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(0.3)
    raise RuntimeError(f'Timed out waiting for {url}. See logs above.')


def available_port(preferred=0):
    with socket.socket() as sock:
        try:
            sock.bind(('127.0.0.1', preferred))
        except OSError:
            if not preferred:
                raise
            sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def stop_process(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def interrupt(signum, frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', action='store_true', help='Create .venv and install Python/frontend dependencies')
    parser.add_argument('--memory-db', action='store_true', help='Use ephemeral storage; investigations are lost on shutdown')
    parser.add_argument('--backend-port', type=int, default=0, help='Preferred API port (default: randomly assigned available port)')
    parser.add_argument('--frontend-port', type=int, default=5173, help='Preferred frontend port (default: 5173, falls back if busy)')
    parser.add_argument('--no-browser', action='store_true', help='Do not open the dashboard automatically')
    args = parser.parse_args()
    for port in (args.backend_port, args.frontend_port):
        if not 0 <= port <= 65535:
            parser.error('Ports must be between 0 and 65535.')

    if sys.version_info < (3, 10):
        raise RuntimeError('Python 3.10+ is required (3.11/3.12 recommended). Run with a newer Python executable.')
    node = shutil.which('node')
    npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
    if not node or not npm:
        raise RuntimeError('Install Node.js 20+ (including npm) and reopen your terminal.')

    env_path = ROOT / '.env'
    if not env_path.exists():
        shutil.copyfile(ROOT / '.env.example', env_path)
        print('Created .env with empty API key placeholders. Add your keys there and restart.', flush=True)

    if args.install:
        if not VENV_PYTHON.exists():
            subprocess.run([sys.executable, '-m', 'venv', str(ROOT / '.venv')], check=True)
        subprocess.run([str(VENV_PYTHON), '-m', 'pip', 'install', '-r', str(ROOT / 'backend/requirements.txt')], check=True)
        subprocess.run([npm, 'ci'], cwd=ROOT / 'frontend', check=True)

    if not VENV_PYTHON.exists():
        raise RuntimeError('Dependencies are not installed. Run again with --install.')
    vite = ROOT / 'frontend/node_modules/vite/bin/vite.js'
    if not vite.exists():
        raise RuntimeError('Frontend dependencies are missing. Run again with --install.')

    # Re-enter using the project venv so dotenv and backend dependencies resolve.
    if Path(sys.prefix).resolve() != (ROOT / '.venv').resolve():
        forwarded = [arg for arg in sys.argv[1:] if arg != '--install']
        return subprocess.call([str(VENV_PYTHON), str(Path(__file__).resolve()), *forwarded])

    from dotenv import load_dotenv
    load_dotenv(env_path, override=False)
    env = os.environ.copy()
    if args.memory_db:
        env['USE_FAKE_DB'] = '1'
    if env.get('USE_FAKE_DB') == '1':
        print('Storage: IN MEMORY. Reports/correlation are lost when this backend stops.', flush=True)
    else:
        # Do not advertise a working app while every upload will fail on get_db().
        sys.path.insert(0, str(ROOT / 'backend'))
        from db.connection import get_db
        try:
            get_db()
        except Exception as exc:
            raise RuntimeError('MongoDB is unavailable. Start MongoDB, configure MONGODB_URI in .env, '
                               'or use --memory-db for temporary storage.') from exc

    for key in ('GEMINI_API_KEY', 'VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY'):
        print(f'{key}: {"configured" if env.get(key, "").strip() else "empty (add to .env and restart)"}', flush=True)
    print(f'THREAT_INTEL_LIVE: {env.get("THREAT_INTEL_LIVE", "0")}', flush=True)

    backend_port = available_port(args.backend_port)
    frontend_port = available_port(args.frontend_port)
    while frontend_port == backend_port:
        frontend_port = available_port()
    api_url = f'http://127.0.0.1:{backend_port}'
    frontend_url = f'http://127.0.0.1:{frontend_port}'
    env['PORT'] = str(backend_port)
    env['ETAP_BACKEND_URL'] = api_url
    # Keep browser requests same-origin through Vite even if a deployed API URL
    # exists in a frontend .env file or the inherited shell environment.
    env['VITE_API_BASE_URL'] = ''
    env['PYTHONUNBUFFERED'] = '1'
    origins = env.get('ALLOWED_ORIGINS', '').split(',')
    env['ALLOWED_ORIGINS'] = ','.join(filter(None, [*origins, frontend_url, f'http://localhost:{frontend_port}']))

    processes = []
    try:
        # Also clean up on console close/automation stop signals where supported.
        signal.signal(signal.SIGTERM, interrupt)
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, interrupt)
        backend = subprocess.Popen(
            [str(VENV_PYTHON), '-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', str(backend_port)],
            cwd=ROOT / 'backend', env=env,
        )
        processes.append(backend)
        wait_for_http(api_url + '/health', backend)
        frontend = subprocess.Popen(
            [node, str(vite), '--host', '127.0.0.1', '--port', str(frontend_port), '--strictPort'],
            cwd=ROOT / 'frontend', env=env,
        )
        processes.append(frontend)
        wait_for_http(frontend_url + '/health', frontend)
        print(f'\nE-TAP dashboard: {frontend_url}\nBackend API: {api_url}\nAPI docs: {api_url}/docs', flush=True)
        print('Upload an .eml/.msg in the dashboard to get its report. Ctrl+C stops both services.\n', flush=True)
        if not args.no_browser:
            webbrowser.open(frontend_url)
        while all(process.poll() is None for process in processes):
            time.sleep(0.5)
        raise RuntimeError('A service stopped unexpectedly. See logs above.')
    except KeyboardInterrupt:
        print('\nStopping E-TAP...', flush=True)
    finally:
        for process in reversed(processes):
            stop_process(process)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'\nE-TAP startup failed: {exc}', file=sys.stderr)
        sys.exit(1)
