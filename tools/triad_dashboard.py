"""Loopback-only, read-only operational dashboard. Never serves evidence or credentials."""
import argparse
import json
import re
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import psutil

HUB = Path(__file__).resolve().parents[1]
ASSETS = HUB / 'dashboard'
RUN_RE = re.compile(r'[0-9]{8}_[0-9]{6}_q505r2_[a-f0-9]{6}')
ROLES = ('hub', 'outbox', 'agent-codex', 'agent-hermes', 'agent-workbuddy',
         'bridge-codex', 'bridge-hermes', 'bridge-workbuddy')


def read_json(path):
    if path.stat().st_size > 2_000_000:
        raise ValueError('oversized_metadata')
    return json.loads(path.read_text(encoding='utf-8'))


def inside(path, root):
    root = root.resolve()
    path = Path(path)
    if not path.resolve().is_relative_to(root):
        raise ValueError('outside_run')
    for item in (path, *path.parents):
        if item == root:
            break
        if item.is_symlink() or (item.exists() and getattr(item.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('linked_path')
    return path


def run_paths(run_id):
    if not RUN_RE.fullmatch(run_id):
        raise ValueError('invalid_run')
    root = inside(HUB / '_sr2_qualify' / run_id, HUB / '_sr2_qualify')
    manifest = read_json(inside(root / 'manifest.json', root))
    if manifest.get('run_id') != run_id:
        raise ValueError('run_mismatch')
    database = inside(manifest['iso_db']['path'], root)
    runtime = inside(manifest['runtime_dir'], HUB / '.gate4_iso' / 'r2fix2' / run_id)
    return root, database, runtime


def list_runs():
    return sorted([p.name for p in (HUB / '_sr2_qualify').iterdir()
                   if RUN_RE.fullmatch(p.name) and (p / 'manifest.json').is_file()], reverse=True)[:30]


def safe_label(value):
    # State/error fields are enums, never provider text or identifiers.
    return value if isinstance(value, str) and re.fullmatch('[a-z_]{1,64}', value) else 'unknown'


def snapshot(run_id):
    root, database, runtime = run_paths(run_id)
    result = {'run_id': run_id, 'observed_at': time.time(), 'roles': [], 'tasks': [],
              'calls': [], 'memory': {}, 'database': 'unavailable', 'cleanup': 'not_recorded'}
    try:
        registry = read_json(inside(runtime / 'runtime_registry.json', runtime))
        roles = registry['roles']
    except (OSError, ValueError, KeyError):
        roles = {}
    for role in ROLES:
        row = roles.get(role, {})
        status = 'offline'
        connected = False
        age = None
        try:
            hb = read_json(inside(runtime / (role + '.heartbeat.json'), runtime))
            age = round(max(0, time.time() - float(hb['updated_ts'])), 1)
            pid = row.get('runtime_pid') or row.get('pid')
            proc = psutil.Process(pid) if type(pid) is int and pid > 0 else None
            identity = (proc is not None and abs(proc.create_time() - float(row['start_ts'])) < 0.05 and
                        proc.name().casefold() == row['image'].casefold() and
                        hb.get('runtime_pid') == pid and hb.get('run_id') == row.get('run_id') and
                        hb.get('launch_nonce') == row.get('launch_nonce') and row.get('run_id') and
                        row.get('launch_nonce'))
            if identity and age <= 90 and row.get('status') != 'stopped':
                status = safe_label(hb.get('state'))
                connected = status == 'running' and hb.get('last_status') == 'connected'
        except (OSError, ValueError, TypeError, KeyError, psutil.Error):
            pass  # Read-only display: never repairs missing or stale runtime files.
        result['roles'].append({'role': role, 'state': status, 'connected': connected, 'heartbeat_age_s': age})
    try:
        with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True, timeout=0.5) as conn:
            conn.row_factory = sqlite3.Row
            result['tasks'] = [dict(r) for r in conn.execute(
                'SELECT task_id,owner,state,revision,updated_at FROM tasks ORDER BY updated_at DESC LIMIT 30')]
            for task in result['tasks']:
                call = conn.execute(
                    'SELECT c.state,c.error_code FROM call_attempts c '
                    'JOIN events e ON CAST(c.event_seq AS INTEGER)=e.event_seq '
                    'WHERE e.task_id=? ORDER BY c.rowid DESC LIMIT 1', (task['task_id'],)).fetchone()
                task.update(task_display(task['state'], dict(call) if call else None))
            result['calls'] = [dict(r) for r in conn.execute(
                'SELECT agent,state,error_code,started_at,completed_at FROM call_attempts ORDER BY rowid DESC LIMIT 30')]
            for row in result['calls']:
                row['error_code'] = safe_label(row['error_code']) if row['error_code'] else None
            result['memory'] = {
                'events': conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],
                'verified_summaries': conn.execute("SELECT COUNT(*) FROM shared_summaries WHERE status='verified'").fetchone()[0],
                'cursors': [dict(r) for r in conn.execute('SELECT agent,last_consumed_event_seq FROM consumer_cursors')],
            }
            result['database'] = 'readable'
    except sqlite3.Error:
        result['database'] = 'unavailable'
    try:
        clean = read_json(inside(root / 'cleanup_claim.json', root))
        result['cleanup'] = safe_label(clean.get('state', clean.get('status')))
    except (OSError, ValueError):
        pass
    try:
        resident = read_json(inside(root / 'resident_status.json', root))
        result['resident'] = {key: resident.get(key) for key in
                              ('state', 'lease_end', 'updated_at', 'reason')}
    except (OSError, ValueError):
        result['resident'] = None
    result['codex_binding_scope'] = 'dedicated_worker_session_not_dashboard_chat'
    return result


def task_display(state, latest_call):
    """Derived display only. Never rewrite historical task/evidence state."""
    if state in ('active', 'reviewing') and latest_call and latest_call['state'] in (
            'result_unknown', 'failed', 'blocked'):
        return {'display_state': 'result_unknown' if latest_call['state'] == 'result_unknown' else 'blocked',
                'blocked_reason': safe_label(latest_call.get('error_code') or latest_call['state'])}
    return {'display_state': state, 'blocked_reason': None}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # No query, private task identifiers or browser headers in server logs.

    def respond(self, status, payload, content_type='application/json; charset=utf-8'):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        local_host = f'127.0.0.1:{self.server.server_port}'
        tailnet_host = getattr(self.server, 'tailnet_host', None)
        host = self.headers.get('Host')
        from_private_proxy = bool(tailnet_host and host == tailnet_host and
                                  self.client_address[0] == '127.0.0.1')
        if (host != local_host and not from_private_proxy) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return self.respond(403, b'{"error":"local_only"}')
        origin = self.headers.get('Origin')
        expected_origin = 'https://' + tailnet_host if from_private_proxy else 'http://' + local_host
        if origin and origin != expected_origin:
            return self.respond(403, b'{"error":"local_only"}')
        req = urlsplit(self.path)
        try:
            if req.path == '/api/runs':
                data = {'runs': list_runs()}
            elif req.path == '/api/status':
                data = snapshot(parse_qs(req.query).get('run', [''])[0])
            elif req.path in ('/', '/app.js', '/style.css'):
                file, mime = {'/': ('index.html', 'text/html; charset=utf-8'),
                              '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                              '/style.css': ('style.css', 'text/css; charset=utf-8')}[req.path]
                return self.respond(200, (ASSETS / file).read_bytes(), mime)
            else:
                return self.respond(404, b'{"error":"not_found"}')
            self.respond(200, json.dumps(data, ensure_ascii=False).encode('utf-8'))
        except (OSError, ValueError, KeyError, TypeError):
            self.respond(400, b'{"error":"metadata_unavailable"}')

    def do_POST(self):
        self.respond(405, b'{"error":"read_only"}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8910)
    parser.add_argument('--tailnet-host', default='',
                        help='Exact private Tailscale Serve FQDN; never enables a public listener')
    args = parser.parse_args()
    if args.tailnet_host and not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ts\.net', args.tailnet_host):
        parser.error('invalid_tailnet_host')
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.tailnet_host = args.tailnet_host or None
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
