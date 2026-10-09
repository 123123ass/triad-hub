"""Portable, explicit first-use Codex CLI binding for a fresh Triad Hub.

Three bounded read-only CLI calls establish a new dedicated session and verify
two resume turns before committing the binding. No historical operator files,
desktop task IDs, raw stdout, tokens, or automatic retries are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

HUB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HUB))

SESSION_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class BootstrapError(Exception):
    pass


def cli_prefix(config) -> list[str]:
    if config.CODEX_BIN:
        return [config.CODEX_BIN]
    if config.NODE and config.CODEX_JS:
        return [config.NODE, config.CODEX_JS]
    raise BootstrapError("codex_cli_not_configured")


def manifest_digest() -> str:
    digest = hashlib.sha256()
    for rel in ("tools/bootstrap_codex_portable.py", "adapters/codex.py"):
        path = HUB / rel
        digest.update(rel.encode("utf-8") + b"\0" + path.read_bytes())
    return digest.hexdigest()


def command(config, prompt: str, session: str | None = None) -> list[str]:
    if config.CODEX_MODEL and not MODEL_RE.fullmatch(config.CODEX_MODEL):
        raise BootstrapError("codex_model_invalid")
    argv = cli_prefix(config) + ["exec", "--json", "--skip-git-repo-check",
                                 "-c", 'sandbox_mode="read-only"']
    if config.CODEX_MODEL:
        argv += ["-m", config.CODEX_MODEL]
    if session is not None:
        if not SESSION_RE.fullmatch(session):
            raise BootstrapError("codex_session_invalid")
        argv += ["resume", session]
    argv.append(prompt)
    if any("bypass" in part for part in argv):
        raise BootstrapError("unsafe_codex_command")
    return argv


def parse_result(stdout: str, expected_session: str | None = None) -> tuple[str, dict]:
    events = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError as exc:
            raise BootstrapError("codex_stream_invalid") from exc
        if not isinstance(event, dict):
            raise BootstrapError("codex_stream_invalid")
        events.append(event)
    sessions = {e.get("thread_id") for e in events if e.get("type") == "thread.started"}
    if len(sessions) != 1:
        raise BootstrapError("codex_session_ambiguous")
    session = next(iter(sessions))
    if not isinstance(session, str) or not SESSION_RE.fullmatch(session):
        raise BootstrapError("codex_session_invalid")
    if expected_session is not None and session != expected_session:
        raise BootstrapError("codex_session_mismatch")
    if sum(e.get("type") == "turn.completed" for e in events) != 1 or any(
        e.get("type") in ("turn.failed", "error") for e in events
    ):
        raise BootstrapError("codex_turn_incomplete")
    texts = [e["item"].get("text") for e in events
             if e.get("type") == "item.completed" and isinstance(e.get("item"), dict)
             and e["item"].get("type") == "agent_message"]
    if len(texts) != 1 or not isinstance(texts[0], str):
        raise BootstrapError("codex_reply_ambiguous")
    try:
        answer = json.loads(texts[0])
    except ValueError as exc:
        raise BootstrapError("codex_reply_invalid") from exc
    if not isinstance(answer, dict):
        raise BootstrapError("codex_reply_invalid")
    return session, answer


def prompt_for(stage: int, challenge: str, digest: str) -> str:
    common = ("Dedicated Triad Hub bootstrap, read-only. Do not use tools, files, or network. "
              "Return one JSON object only, without Markdown. ")
    if stage == 0:
        return common + (f'Return exactly keys stage, bootstrap_nonce, manifest_hash with '
                         f'stage="create", bootstrap_nonce="{challenge}", manifest_hash="{digest}".')
    if stage == 1:
        return common + ("From the previous turn, repeat bootstrap_nonce and manifest_hash exactly. "
                         f'Return exactly keys stage, bootstrap_nonce, manifest_hash, challenge_nonce '
                         f'with stage="resume_one" and challenge_nonce="{challenge}".')
    return common + ("From earlier turns, repeat bootstrap_nonce, manifest_hash, and the "
                     "previous challenge_nonce exactly; do not infer missing values. "
                     f'Return exactly keys stage, bootstrap_nonce, manifest_hash, '
                     f'previous_challenge_nonce, challenge_nonce with stage="resume_two" '
                     f'and challenge_nonce="{challenge}".')


def verify_answer(stage: int, answer: dict, bootstrap: str, digest: str,
                  previous_challenge: str | None, current_challenge: str) -> None:
    expected = {"stage": ("create", "resume_one", "resume_two")[stage],
                "bootstrap_nonce": bootstrap, "manifest_hash": digest}
    if stage >= 1:
        expected["challenge_nonce"] = current_challenge
    if stage == 2:
        expected["previous_challenge_nonce"] = previous_challenge
    if stage == 0:
        expected["bootstrap_nonce"] = current_challenge
    if answer != expected:
        raise BootstrapError("codex_continuity_mismatch")


def run_command(argv: list[str], workspace: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["NODE_OPTIONS"] = ""
    if os.environ.get("TRIAD_HTTPS_PROXY"):
        env["HTTPS_PROXY"] = os.environ["TRIAD_HTTPS_PROXY"]
    return subprocess.run(argv, cwd=workspace, env=env, capture_output=True,
                          text=True, encoding="utf-8", errors="strict",
                          timeout=240, shell=False)


def record_verification(repo, *, stage: int, session: str, stdout: str,
                        challenge: str, digest: str) -> str:
    verification_id = "bv_" + secrets.token_hex(10)
    evidence_dir = HUB / "evidence" / "bindings"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / (verification_id + ".json")
    evidence = {"stage": stage, "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
                "session_sha256": hashlib.sha256(session.encode("utf-8")).hexdigest(),
                "challenge_sha256": hashlib.sha256(challenge.encode("utf-8")).hexdigest(),
                "manifest_hash": digest, "raw_output_retained": False}
    with evidence_path.open("x", encoding="utf-8") as out:
        json.dump(evidence, out, sort_keys=True)
    repo.insert_binding_verification(rec={
        "verification_id": verification_id, "agent": "codex",
        "logical_session": "triad-codex-main", "requested_session_id": session if stage else None,
        "actual_session_id": session,
        "verification_type": ("fresh_create", "resume_nonce", "continuity")[stage],
        "command_mode": "fresh" if stage == 0 else "resume",
        "nonce_hash": evidence["challenge_sha256"], "bootstrap_manifest_hash": digest,
        "exit_code": 0, "evidence_ref": evidence_path.relative_to(HUB).as_posix(),
        "status": "created" if stage == 0 else "verified", "error_code": None,
    })
    return verification_id


def bind() -> dict:
    from config import config
    import repository as repo

    if repo.has_verified_codex_binding():
        raise BootstrapError("codex_already_bound")
    if repo.get_binding_row("codex") is not None:
        raise BootstrapError("codex_unverified_binding_requires_review")
    prefix = cli_prefix(config)
    if any(not Path(p).is_file() for p in prefix):
        raise BootstrapError("codex_cli_not_found")
    workspace = HUB / "runtime" / "codex_bootstrap_workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    lock = HUB / "runtime" / "codex_bootstrap_portable.lock"
    try:
        with lock.open("x", encoding="utf-8") as out:
            out.write(str(os.getpid()))
    except FileExistsError as exc:
        raise BootstrapError("codex_bootstrap_locked") from exc
    try:
        digest = manifest_digest()
        bootstrap = secrets.token_hex(16)
        challenges = [bootstrap, secrets.token_hex(16), secrets.token_hex(16)]
        session = None
        verification_ids = []
        for stage, challenge in enumerate(challenges):
            argv = command(config, prompt_for(stage, challenge, digest), session)
            try:
                result = run_command(argv, workspace)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise BootstrapError("codex_call_unknown") from exc
            if result.returncode != 0:
                raise BootstrapError("codex_cli_failed")
            actual, answer = parse_result(result.stdout, session)
            verify_answer(stage, answer, bootstrap, digest,
                          challenges[1] if stage == 2 else None, challenge)
            session = actual
            if stage == 0:
                # Verification rows reference the binding. Keep it offline and
                # unverified until all three calls and the atomic commit pass.
                repo.set_binding("codex", "triad-codex-main", session, "cli", status="offline")
            verification_ids.append(record_verification(
                repo, stage=stage, session=session, stdout=result.stdout,
                challenge=challenge, digest=digest))
        version = repo.commit_verified_binding(
            agent="codex", logical_session="triad-codex-main", actual_session_id=session,
            adapter="cli", verification_ids=verification_ids,
            metadata={"bootstrap": "portable_v1", "manifest_hash": digest})
        return {"status": "verified", "binding_version": version, "calls": 3}
    finally:
        if lock.is_file() and lock.read_text(encoding="utf-8") == str(os.getpid()):
            lock.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="Read-only prerequisite check")
    group.add_argument("--bind", action="store_true", help="Create and verify a new session (3 model calls)")
    args = parser.parse_args()
    try:
        from config import config
        import repository as repo
        prefix = cli_prefix(config)
        if any(not Path(p).is_file() for p in prefix):
            raise BootstrapError("codex_cli_not_found")
        if not Path(config.DB_PATH).is_file():
            raise BootstrapError("database_missing_run_migrations")
        if args.check:
            print(json.dumps({"status": "ready", "already_bound": repo.has_verified_codex_binding(),
                              "model_configured": bool(config.CODEX_MODEL)}))
            return 0
        print(json.dumps(bind()), flush=True)
        return 0
    except BootstrapError as exc:
        print(json.dumps({"status": "blocked", "error_code": str(exc)}), flush=True)
        return 1
    except Exception:
        # Never print provider output, physical session IDs, or credentials.
        print(json.dumps({"status": "blocked", "error_code": "bootstrap_internal_error"}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
