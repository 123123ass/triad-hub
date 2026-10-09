"""Opt-in independent CodeBuddy CLI, fixed session and fresh terminal evidence.

No desktop profile, no fresh-session fallback, no automatic model/request retry.
Tool-bearing calls require a controller-issued, expiring, exact-file grant.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

from config import config
from .base import AdapterResult, BindingVerification
from .wb import WBAdapter
from .extract import AgentResultExtractor, store_raw_stdout


def exact_edit_grant(task_id, cwd):
    """Missing grant means tool-free; a present malformed grant fails closed."""
    folder_name = config.WB_CLI_EDIT_GRANTS
    if not folder_name or not isinstance(task_id, str) or not task_id:
        return None
    folder = Path(folder_name).resolve()
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError('edit_grant_directory_invalid')
    file = folder / (uuid.uuid5(uuid.NAMESPACE_URL, task_id).hex + '.json')
    if not file.exists():
        return None
    if file.is_symlink() or file.stat().st_size > 4096:
        raise ValueError('edit_grant_invalid')
    data = json.loads(file.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or set(data) != {'task_id', 'path', 'expires_at'}:
        raise ValueError('edit_grant_invalid')
    if data['task_id'] != task_id or type(data['expires_at']) not in (int, float) or data['expires_at'] <= time.time():
        raise ValueError('edit_grant_invalid')
    target = Path(data['path'])
    if not target.is_absolute() or not target.is_file() or not target.resolve().is_relative_to(cwd):
        raise ValueError('edit_grant_target_invalid')
    for part in (target, *target.parents):
        if part == cwd:
            break
        if part.is_symlink():
            raise ValueError('edit_grant_target_invalid')
    return target.resolve()


def edit_settings(target):
    guard = Path(__file__).resolve().parents[1] / 'tools' / 'wb_edit_guard.py'
    command = f'"{sys.executable}" "{guard}" "{target}"'
    return {'hooks': {'PreToolUse': [{'matcher': 'Edit|Write',
                                      'hooks': [{'type': 'command', 'command': command}]}]},
            'permissions': {'defaultMode': 'dontAsk',
                            'deny': ['Bash', 'Write', 'NotebookEdit', 'WebFetch', 'WebSearch']}}


def terminal_receipt(before, after, *, session, marker, model):
    if not after.startswith(before):
        raise ValueError('history_changed')
    records = [json.loads(line) for line in after[len(before):].splitlines() if line.strip()]
    users = [i for i, r in enumerate(records) if r.get('role') == 'user'
             and marker in json.dumps(r.get('content', []))]
    answers = [(i, r) for i, r in enumerate(records) if r.get('role') == 'assistant']
    if len(users) != 1 or len(answers) != 1 or answers[0][0] <= users[0]:
        raise ValueError('fresh_terminal_missing')
    final = answers[0][1]
    if (records[users[0]].get('sessionId') != session or final.get('sessionId') != session
            or final.get('status') != 'completed' or final.get('providerData', {}).get('model') != model):
        raise ValueError('terminal_identity_mismatch')
    content = final.get('content', [])
    if not isinstance(content, list) or any(c.get('type') != 'output_text' for c in content):
        raise ValueError('unexpected_terminal_content')
    return ''.join(c.get('text', '') for c in content)


class WBCLIAdapter(WBAdapter):
    command_mode = 'cli_fixed_session'

    def _paths(self, binding):
        sid = binding.get('actual_session_id')
        if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,100}', sid):
            raise ValueError('binding_session_invalid')
        if not all((config.WB_CLI_PROFILE, config.WB_CLI_CWD, config.WB_CLI_ENTRY)):
            raise ValueError('cli_config_missing')
        profile = Path(config.WB_CLI_PROFILE).resolve()
        desktop = (Path.home() / '.workbuddy').resolve()
        if desktop == profile or desktop in profile.parents or '.workbuddy' in [p.lower() for p in profile.parts]:
            raise ValueError('desktop_profile_forbidden')
        cwd, entry = Path(config.WB_CLI_CWD).resolve(), Path(config.WB_CLI_ENTRY).resolve()
        if not profile.is_dir() or not cwd.is_dir() or not entry.is_file():
            raise ValueError('cli_path_missing')
        if config.WB_CLI_MODEL not in ('hy3', 'hy4-preview'):
            raise ValueError('cli_model_not_approved')
        paths = list((profile / 'projects').glob(f'*/{sid}.jsonl'))
        if len(paths) != 1 or paths[0].is_symlink() or profile not in paths[0].resolve().parents:
            raise ValueError('binding_transcript_missing')
        return sid, profile, cwd, entry, paths[0]

    def verify_binding(self, binding):
        result = super().verify_binding(binding)
        if not result.ok:
            return result
        try:
            self._paths(binding)
        except (ValueError, OSError):
            return BindingVerification(ok=False, error_code='binding_cli_invalid',
                                       error_message_redacted='Independent CLI binding or configuration invalid')
        return result

    def _run(self, argv, *, cwd, env, timeout):
        return subprocess.run(argv, cwd=cwd, env=env, timeout=timeout, shell=False,
                              capture_output=True, text=True, encoding='utf-8', errors='replace')

    def call(self, *, binding, context_packet, rendered_prompt, idempotency_key, timeout):
        check = self.verify_binding(binding)
        if not check.ok:
            return AdapterResult(success=False, error_code=check.error_code,
                                 error_message_redacted=check.error_message_redacted)
        try:
            sid, profile, cwd, entry, transcript = self._paths(binding)
            before = transcript.read_text(encoding='utf-8')
            marker = 'triad_call_' + uuid.uuid4().hex
            prompt = f'Controller correlation: {marker}\n{rendered_prompt}'
            env = os.environ.copy()
            for key in list(env):
                if key.startswith('CODEBUDDY_') or key in ('NODE_OPTIONS', 'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL'):
                    env.pop(key)
            env.update(CODEBUDDY_CONFIG_DIR=str(profile), DISABLE_AUTOUPDATER='1', CODEBUDDY_SKIP_BUILTIN_MARKETPLACE='1')
            grant = exact_edit_grant(getattr(context_packet, 'current_task_id', None), cwd)
            argv = [config.NODE, str(entry), '--resume', sid, '-p', prompt,
                    '--model', config.WB_CLI_MODEL, '--tools', 'Edit' if grant else '', '--strict-mcp-config',
                    '--mcp-config', '{"mcpServers":{}}', '--setting-sources', 'user',
                    '--max-turns', '2' if grant else '1', '--effort', 'low', '--output-format', 'json']
            if grant:
                env['CODEBUDDY_CODE_GIT_BASH_PATH'] = config.WB_CLI_GIT_BASH
                if not config.WB_CLI_GIT_BASH or not Path(config.WB_CLI_GIT_BASH).is_file():
                    raise ValueError('edit_hook_shell_missing')
                with tempfile.TemporaryDirectory(prefix='triad-wb-edit-') as temp:
                    settings = Path(temp) / 'settings.json'
                    settings.write_text(json.dumps(edit_settings(grant)), encoding='utf-8')
                    argv += ['--settings', str(settings), '--permission-mode', 'dontAsk']
                    run = self._run(argv, cwd=cwd, env=env, timeout=timeout)
            else:
                run = self._run(argv, cwd=cwd, env=env, timeout=timeout)
            if run.returncode != 0:
                return AdapterResult(success=False, exit_code=run.returncode, error_code='result_unknown',
                                     error_message_redacted='CLI failed; do not automatically replay')
            after = transcript.read_text(encoding='utf-8')
            text = terminal_receipt(before, after, session=sid, marker=marker, model=config.WB_CLI_MODEL)
            ex = AgentResultExtractor().extract(self.agent, text)
            if not ex.ok:
                return AdapterResult(success=False, error_code=ex.error_code)
            ref, error = store_raw_stdout(self.agent, text, idempotency_key, reviewed_text=ex.text)
            if error or not ref:
                return AdapterResult(success=False, error_code=error or 'agent_result_evidence_failed')
            return AdapterResult(success=True, text=ex.text, actual_session_id=sid,
                                 exit_code=0, stdout_ref=ref, preverified=check.preverified)
        except subprocess.TimeoutExpired:
            return AdapterResult(success=False, error_code='timeout', error_message_redacted='CLI timed out; do not replay')
        except (ValueError, OSError, TypeError, AttributeError):
            return AdapterResult(success=False, error_code='result_unknown',
                                 error_message_redacted='Fresh CLI receipt could not be verified; do not replay')
