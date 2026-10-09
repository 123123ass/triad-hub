"""Explicit controller-only bounded handoff. No HTTP endpoint or automatic routing.

Tasks follow a controller-selected fixed route. Completed verified output is required;
ownership, event and delivery change atomically. Agent text never authorizes a hop.
"""
import hashlib
import json

import repository as repo
from db import connect, transaction
from redaction import assert_no_secret

CHAIN = ('codex', 'hermes', 'workbuddy')
FEISHU_CHAINS = {
    'codex': CHAIN,
    'hermes': ('hermes', 'codex', 'workbuddy'),
    'workbuddy': ('workbuddy', 'codex', 'hermes'),
}


def chain_for(task_id):
    """The ingress-issued task ID fixes the route; agent prose cannot change it."""
    if isinstance(task_id, str) and task_id.startswith('feishu-task:'):
        parts = task_id.split(':', 2)
        if len(parts) == 3 and parts[1] in FEISHU_CHAINS:
            return FEISHU_CHAINS[parts[1]]
    return CHAIN


class HandoffError(ValueError):
    pass


def _verified_output(call_id):
    """Slow file/ACL checks before BEGIN IMMEDIATE, then compare snapshots in tx."""
    conn = connect(read_only=True)
    try:
        call = conn.execute('SELECT * FROM call_attempts WHERE call_id=?', (call_id,)).fetchone()
        if not call:
            raise HandoffError('handoff_source_missing')
        rec = conn.execute("SELECT * FROM stdout_evidence WHERE raw_ref=? AND status='verified'",
                           (call['stdout_ref'],)).fetchone()
        reply = conn.execute('SELECT * FROM events WHERE event_seq=?', (call['response_event_seq'],)).fetchone()
        if not rec or not reply or rec['agent'] != call['agent']:
            raise HandoffError('handoff_evidence_failed')
        record, text = dict(rec), reply['text']
    finally:
        conn.close()
    from adapters.extract import _record_fully_verified, _record_paths
    if not _record_fully_verified(record):
        raise HandoffError('handoff_evidence_failed')
    reviewed = _record_paths(record)[1]
    if not reviewed or reviewed.read_text(encoding='utf-8') != text:
        raise HandoffError('handoff_reply_evidence_conflict')
    return record, text


def _event(conn, *, event_id, task_id, trace, source, target, text, hop, parent=None, root=None, max_hops=2):
    cur = conn.execute(
        'INSERT INTO events(event_id,idempotency_key,trace_id,parent_event_id,root_event_id,'
        'source_agent,source_type,message_type,text,mentions_json,refs_json,task_id,'
        'hop_count,max_hops,created_at,received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (event_id, event_id, trace, parent, root or event_id, source, 'controller', 'system',
         text, json.dumps([target]), '{}', task_id, hop, max_hops, repo._now(), repo._now()))
    repo._create_deliveries(conn, cur.lastrowid, [target])
    conn.execute('UPDATE deliveries SET task_id=?,trace_id=? WHERE event_seq=?',
                 (task_id, trace, cur.lastrowid))
    return cur.lastrowid


def start_task(*, task_id, trace_id, objective, acceptance):
    if not all(isinstance(x, str) and x.strip() for x in (task_id, trace_id, objective, acceptance)):
        raise HandoffError('task_contract_invalid')
    for value in (task_id, trace_id, objective, acceptance):
        assert_no_secret(value)
    event_id = 'task-start:' + hashlib.sha256(task_id.encode()).hexdigest()
    chain = chain_for(task_id)
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation='start_handoff_task', role='hub'):
            old = conn.execute('SELECT * FROM tasks WHERE task_id=?', (task_id,)).fetchone()
            if old:
                if (old['trace_id'], old['objective'], old['acceptance_criteria']) != (trace_id, objective, acceptance):
                    raise HandoffError('task_idempotency_conflict')
                row = conn.execute('SELECT event_seq FROM events WHERE event_id=?', (event_id,)).fetchone()
                if not row:
                    raise HandoffError('task_start_inconsistent')
                return {'event_seq': row[0], 'duplicate': True}
            conn.execute('INSERT INTO tasks(task_id,owner,objective,acceptance_criteria,trace_id,state,'
                         'evidence_refs_json,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
                         (task_id, chain[0], objective, acceptance, trace_id, 'active', '[]', 0,
                          repo._now(), repo._now()))
            seq = _event(conn, event_id=event_id, task_id=task_id, trace=trace_id, source='codex',
                         target=chain[0], text=objective, hop=0)
            return {'event_seq': seq, 'duplicate': False}
    finally:
        conn.close()


def handoff(*, task_id, completed_call_id, expected_revision, target, instruction):
    if type(expected_revision) is not int or expected_revision not in (0, 1):
        raise HandoffError('handoff_hop_limit')
    chain = chain_for(task_id)
    if target != chain[expected_revision + 1] or not isinstance(instruction, str) or not instruction.strip():
        raise HandoffError('handoff_target_invalid')
    assert_no_secret(instruction)
    verified_record, verified_text = _verified_output(completed_call_id)
    event_id = 'task-hop:' + hashlib.sha256(f'{task_id}:{expected_revision}'.encode()).hexdigest()
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation='task_handoff', role='hub'):
            task = conn.execute('SELECT * FROM tasks WHERE task_id=?', (task_id,)).fetchone()
            call = conn.execute('SELECT * FROM call_attempts WHERE call_id=?', (completed_call_id,)).fetchone()
            if not task or not call:
                raise HandoffError('handoff_source_missing')
            control = conn.execute('SELECT state FROM trace_controls WHERE trace_id=?',
                                   (task['trace_id'],)).fetchone()
            if control and control[0] != 'active':
                raise HandoffError('handoff_trace_inactive')
            trigger = conn.execute('SELECT * FROM events WHERE event_seq=?', (call['event_seq'],)).fetchone()
            reply = conn.execute('SELECT * FROM events WHERE event_seq=?', (call['response_event_seq'],)).fetchone()
            if (call['state'] != 'completed' or call['exit_code'] != 0 or
                    call['agent'] != chain[expected_revision] or not trigger or not reply or
                    trigger['task_id'] != task_id or reply['task_id'] != task_id or
                    trigger['trace_id'] != task['trace_id'] or reply['trace_id'] != task['trace_id'] or
                    reply['source_agent'] != call['agent'] or reply['message_type'] != 'agent_reply' or
                    reply['parent_event_id'] != trigger['event_id'] or
                    trigger['hop_count'] != expected_revision):
                raise HandoffError('handoff_source_not_verified')
            rec = conn.execute("SELECT * FROM stdout_evidence WHERE raw_ref=? AND status='verified'",
                               (call['stdout_ref'],)).fetchone()
            if not rec or dict(rec) != verified_record:
                raise HandoffError('handoff_evidence_failed')
            if verified_text != reply['text']:
                raise HandoffError('handoff_reply_evidence_conflict')
            old = conn.execute('SELECT * FROM events WHERE event_id=?', (event_id,)).fetchone()
            if old:
                if (old['text'] != instruction or old['parent_event_id'] != reply['event_id'] or
                        old['mentions_json'] != json.dumps([target])):
                    raise HandoffError('handoff_idempotency_conflict')
                return {'event_seq': old['event_seq'], 'duplicate': True}
            if task['revision'] != expected_revision or task['owner'] != call['agent'] or task['state'] != 'active':
                raise HandoffError('handoff_revision_conflict')
            seq = _event(conn, event_id=event_id, task_id=task_id, trace=task['trace_id'],
                         source=call['agent'], target=target, text=instruction, hop=expected_revision + 1,
                         parent=reply['event_id'], root=trigger['root_event_id'])
            refs = json.loads(task['evidence_refs_json'] or '[]')
            refs.append(call['stdout_ref'])
            conn.execute('UPDATE tasks SET owner=?,revision=revision+1,evidence_refs_json=?,updated_at=? '
                         'WHERE task_id=? AND revision=?',
                         (target, json.dumps(refs), repo._now(), task_id, expected_revision))
            conn.execute('INSERT INTO task_events(task_event_id,task_id,revision,from_state,to_state,actor,'
                         'evidence_refs_json,created_at) VALUES(?,?,?,?,?,?,?,?)',
                         (event_id, task_id, expected_revision + 1, 'active', 'active', call['agent'],
                          json.dumps([call['stdout_ref']]), repo._now()))
            return {'event_seq': seq, 'duplicate': False}
    finally:
        conn.close()


def finish_task(*, task_id, completed_call_id):
    final_agent = chain_for(task_id)[2]
    record, text = _verified_output(completed_call_id)
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation='finish_handoff_task', role='hub'):
            task = conn.execute('SELECT * FROM tasks WHERE task_id=?', (task_id,)).fetchone()
            call = conn.execute('SELECT * FROM call_attempts WHERE call_id=?', (completed_call_id,)).fetchone()
            trigger = conn.execute('SELECT * FROM events WHERE event_seq=?', (call['event_seq'],)).fetchone()
            reply = conn.execute('SELECT * FROM events WHERE event_seq=?', (call['response_event_seq'],)).fetchone()
            rec = conn.execute('SELECT * FROM stdout_evidence WHERE evidence_id=?', (record['evidence_id'],)).fetchone()
            if (not task or not trigger or not reply or not rec or dict(rec) != record or
                    call['agent'] != final_agent or call['state'] != 'completed' or call['exit_code'] != 0 or
                    call['stdout_ref'] != record['raw_ref'] or reply['message_type'] != 'agent_reply' or
                    trigger['task_id'] != task_id or trigger['hop_count'] != 2 or
                    trigger['trace_id'] != task['trace_id'] or reply['task_id'] != task_id or
                    reply['trace_id'] != task['trace_id'] or reply['source_agent'] != final_agent or
                    reply['parent_event_id'] != trigger['event_id'] or reply['text'] != text):
                raise HandoffError('handoff_final_source_invalid')
            if task['state'] == 'completed' and task['revision'] == 3 and task['result_ref'] == call['stdout_ref']:
                return {'state': 'completed', 'duplicate': True}
            if task['state'] != 'active' or task['revision'] != 2 or task['owner'] != final_agent:
                raise HandoffError('handoff_revision_conflict')
            control = conn.execute('SELECT state FROM trace_controls WHERE trace_id=?', (task['trace_id'],)).fetchone()
            if control and control[0] != 'active':
                raise HandoffError('handoff_trace_inactive')
            refs = json.loads(task['evidence_refs_json'] or '[]') + [call['stdout_ref']]
            conn.execute("UPDATE tasks SET state='completed',revision=3,result_ref=?,evidence_refs_json=?,"
                         'updated_at=? WHERE task_id=?',
                         (call['stdout_ref'], json.dumps(refs), repo._now(), task_id))
            conn.execute('INSERT INTO task_events(task_event_id,task_id,revision,from_state,to_state,actor,'
                         'evidence_refs_json,created_at) VALUES(?,?,?,?,?,?,?,?)',
                         ('task-finish:' + hashlib.sha256(task_id.encode()).hexdigest(), task_id, 3,
                         'active', 'completed', final_agent, json.dumps([call['stdout_ref']]), repo._now()))
            return {'state': 'completed', 'duplicate': False}
    finally:
        conn.close()
