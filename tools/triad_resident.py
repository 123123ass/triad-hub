"""Bounded resident lease for an already-qualified isolated Phase2 topology.

Idle consumes no model calls. No automatic starts, restarts, cleanup retries or
unprompted agent calls. A lease expires after <=24 hours and cleans up once.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

HUB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HUB))
RECONNECT_GRACE_SEC = 300


def health():
    try:
        with urllib.request.urlopen('http://127.0.0.1:8900/health/ready', timeout=3) as response:
            return response.status == 200
    except (OSError, ValueError):
        return False


def write_state(path, state):
    temp = path.with_suffix('.tmp')
    with temp.open('w', encoding='utf-8') as out:
        json.dump(state, out, ensure_ascii=False, indent=2)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)


def serve(run_id, hours):
    from tools import sr2_r2_contract as contract
    from tools.triad_dashboard import snapshot
    if not 0 < hours <= 24:
        raise ValueError('resident_lease_invalid')
    manifest = contract.load_and_verify_manifest(run_id)
    contract.verify_launch_env_isolation(run_id, manifest)
    root = HUB / '_sr2_qualify' / run_id
    if (root / 'cleanup_claim.json').exists() or (root / 'TERMINAL_FAILED.json').exists():
        raise ValueError('resident_run_closed')
    p2 = json.loads((root / 'evidence/phase2_startup.json').read_text(encoding='utf-8'))
    if not p2.get('phase2_done') or not p2.get('silent', {}).get('ok'):
        raise ValueError('resident_phase2_unqualified')
    gateway = contract.recorded_gateway_snapshot(run_id)
    launch = contract.load_launch_env(run_id) if not gateway else {}
    cli_transport = (launch.get('TRIAD_WB_TRANSPORT') == 'cli_fixed_session'
                     and p2.get('wb_transport') == 'cli_fixed_session'
                     and p2.get('gw_pid') is None and p2.get('gw_identity') == {})
    if not gateway and not cli_transport:
        raise ValueError('resident_gateway_identity_missing')
    # Claim once for this run, never takes over another resident process.
    import psutil
    with (root / 'resident_claim.json').open('x', encoding='utf-8') as out:
        json.dump({'pid': os.getpid(), 'create_time': psutil.Process().create_time(), 'run_id': run_id}, out)
    path = root / 'resident_status.json'
    end = time.monotonic() + hours * 3600
    state = {'run_id': run_id, 'state': 'running', 'started_at': time.time(),
             'lease_end': time.time() + hours * 3600, 'automatic_restarts': 0,
             'automatic_model_calls': 0, 'health_failures': 0}
    failures = 0
    disconnected_since = None
    reason = 'resident_lease_expired'
    try:
        while time.monotonic() < end:
            if (root / 'resident_stop.json').exists():
                reason = 'resident_user_stop'
                break
            current = snapshot(run_id)
            live = sum(r['state'] not in ('offline', 'stopped', 'failed') for r in current['roles'])
            bridges = [r for r in current['roles'] if r['role'].startswith('bridge-')]
            ready = health()
            healthy = live == 8 and len(bridges) == 3 and all(r['connected'] for r in bridges) and ready
            # Only a live, fresh bridge reconnecting gets grace. Missing workers,
            # stale identities and an unhealthy Hub retain fail-closed behavior.
            reconnecting = (not healthy and ready and live == 8 and len(bridges) == 3
                            and all(r['state'] == 'running' for r in current['roles']
                                    if not r['role'].startswith('bridge-'))
                            and all(r['state'] in ('running', 'starting') and
                                    r.get('heartbeat_age_s') is not None and
                                    0 <= r['heartbeat_age_s'] <= 90 for r in bridges))
            now = time.monotonic()
            if healthy:
                if disconnected_since is not None:
                    state['recovery_count'] = state.get('recovery_count', 0) + 1
                disconnected_since = None
            elif reconnecting and disconnected_since is None:
                disconnected_since = now
            failures = 0 if healthy or reconnecting else failures + 1
            observation = {
                'observed_at': time.time(), 'ready': ready, 'healthy': healthy,
                'roles': [{'role': r['role'], 'state': r['state'],
                           'connected': bool(r.get('connected')),
                           'heartbeat_age_s': r.get('heartbeat_age_s')}
                          for r in current['roles']],
            }
            state.update(updated_at=time.time(), trusted_roles=live, health_failures=failures,
                         last_health=observation, state='reconnecting' if reconnecting else 'running',
                         reconnect_elapsed_s=0 if disconnected_since is None else now-disconnected_since,
                         reconnect_grace_s=RECONNECT_GRACE_SEC)
            # Retain a small diagnostic ring; no payloads, credentials or model calls.
            if not healthy:
                state['failed_observations'] = (state.get('failed_observations', []) + [observation])[-3:]
            write_state(path, state)
            if reconnecting and now - disconnected_since >= RECONNECT_GRACE_SEC:
                reason = 'resident_reconnect_timeout'
                break
            if failures >= 3:
                reason = 'resident_health_failed'
                break
            time.sleep(min(10, max(0, end - time.monotonic())))
    except KeyboardInterrupt:
        reason = 'resident_interrupted'
    except Exception:
        reason = 'resident_monitor_failed'
    finally:
        cleanup = contract.controlled_cleanup(run_id, gateway_snapshot=gateway, reason=reason)
        state.update(state='stopped' if cleanup.get('stop_rc') == 0 and not cleanup.get('cleanup_incomplete') else 'cleanup_incomplete',
                     stopped_at=time.time(), reason=reason, cleanup=cleanup)
        write_state(path, state)
    return 0 if state['state'] == 'stopped' and reason in ('resident_lease_expired', 'resident_user_stop') else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run_id')
    parser.add_argument('--hours', type=float, default=8)
    parser.add_argument('--stop', action='store_true')
    args = parser.parse_args()
    if args.stop:
        from tools.triad_dashboard import run_paths
        root, _, _ = run_paths(args.run_id)
        # Does not stop by process name or act outside this explicitly selected run.
        with (root / 'resident_stop.json').open('x', encoding='utf-8') as out:
            json.dump({'requested_at': time.time()}, out)
        return 0
    return serve(args.run_id, args.hours)


if __name__ == '__main__':
    raise SystemExit(main())
