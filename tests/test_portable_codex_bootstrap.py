"""Offline protocol and safety checks for first-use Codex binding."""
import json
import re
import subprocess
import uuid
from types import SimpleNamespace

import pytest

from tools import bootstrap_codex_portable as bootstrap


def stream(session, answer):
    return "\n".join(json.dumps(row) for row in (
        {"type": "thread.started", "thread_id": session},
        {"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(answer)}},
        {"type": "turn.completed"},
    ))


def test_parse_result_requires_one_completed_session_and_answer():
    session = str(uuid.uuid4())
    assert bootstrap.parse_result(stream(session, {"ok": True})) == (session, {"ok": True})
    with pytest.raises(bootstrap.BootstrapError, match="codex_session_mismatch"):
        bootstrap.parse_result(stream(session, {}), str(uuid.uuid4()))
    with pytest.raises(bootstrap.BootstrapError, match="codex_stream_invalid"):
        bootstrap.parse_result("not-json")
    with pytest.raises(bootstrap.BootstrapError, match="codex_reply_ambiguous"):
        bootstrap.parse_result(stream(session, {}) + "\n" + json.dumps(
            {"type": "item.completed", "item": {"type": "agent_message", "text": "{}"}}))


def test_command_is_read_only_and_never_resumes_without_explicit_session(tmp_path):
    cli = tmp_path / "codex.exe"
    cli.write_bytes(b"placeholder")
    config = SimpleNamespace(CODEX_BIN=str(cli), NODE="", CODEX_JS="", CODEX_MODEL="test-model")
    fresh = bootstrap.command(config, "safe prompt")
    assert "resume" not in fresh
    assert 'sandbox_mode="read-only"' in fresh
    assert fresh[-1] == "safe prompt"
    resumed = bootstrap.command(config, "next", str(uuid.uuid4()))
    assert resumed.count("resume") == 1
    assert not any("bypass" in part for part in resumed)


def test_continuity_requires_original_and_previous_challenge():
    digest, first, second, third = "a" * 64, "b" * 32, "c" * 32, "d" * 32
    good = {"stage": "resume_two", "bootstrap_nonce": first,
            "manifest_hash": digest, "previous_challenge_nonce": second,
            "challenge_nonce": third}
    bootstrap.verify_answer(2, good, first, digest, second, third)
    with pytest.raises(bootstrap.BootstrapError, match="codex_continuity_mismatch"):
        bootstrap.verify_answer(2, {**good, "previous_challenge_nonce": first},
                                first, digest, second, third)


def test_evidence_contains_only_hashes(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap, "HUB", tmp_path)
    records = []
    repo = SimpleNamespace(insert_binding_verification=lambda rec: records.append(rec))
    session, raw = str(uuid.uuid4()), "PRIVATE ANSWER"
    bootstrap.record_verification(repo, stage=0, session=session, stdout=raw,
                                  challenge="nonce", digest="f" * 64)
    evidence = next((tmp_path / "evidence" / "bindings").glob("*.json")).read_text()
    assert session not in evidence and raw not in evidence and "nonce" not in evidence
    assert records[0]["status"] == "created"


def test_bind_creates_offline_parent_then_commits_after_three_verified_calls(tmp_path, monkeypatch):
    from config import config
    import repository as repo

    cli = tmp_path / "codex.exe"
    cli.write_bytes(b"placeholder")
    monkeypatch.setattr(config, "CODEX_BIN", str(cli))
    monkeypatch.setattr(config, "CODEX_MODEL", "test-model")
    monkeypatch.setattr(bootstrap, "HUB", tmp_path)
    monkeypatch.setattr(bootstrap, "manifest_digest", lambda: "f" * 64)
    monkeypatch.setattr(repo, "has_verified_codex_binding", lambda: False)
    monkeypatch.setattr(repo, "get_binding_row", lambda agent: None)
    events, records = [], []
    monkeypatch.setattr(repo, "set_binding", lambda *a, **kw: events.append(("parent", kw["status"])))
    monkeypatch.setattr(repo, "insert_binding_verification", lambda rec: (events.append(("verify", rec["status"])), records.append(rec)))
    monkeypatch.setattr(repo, "commit_verified_binding", lambda **kw: (events.append(("commit", len(records))), 2)[1])
    session = str(uuid.uuid4())
    state = {}

    def fake_run(argv, workspace):
        prompt = argv[-1]
        challenge = re.search(r'challenge_nonce="([0-9a-f]+)"', prompt)
        if 'stage="create"' in prompt:
            stage = "create"
            state["first"] = re.search(r'bootstrap_nonce="([0-9a-f]+)"', prompt).group(1)
            state["digest"] = "f" * 64
            answer = {"stage": stage, "bootstrap_nonce": state["first"],
                      "manifest_hash": state["digest"]}
        elif 'stage="resume_one"' in prompt:
            state["second"] = challenge.group(1)
            answer = {"stage": "resume_one", "bootstrap_nonce": state["first"],
                      "manifest_hash": state["digest"], "challenge_nonce": state["second"]}
        else:
            answer = {"stage": "resume_two", "bootstrap_nonce": state["first"],
                      "manifest_hash": state["digest"], "previous_challenge_nonce": state["second"],
                      "challenge_nonce": challenge.group(1)}
        return subprocess.CompletedProcess(argv, 0, stdout=stream(session, answer), stderr="")

    monkeypatch.setattr(bootstrap, "run_command", fake_run)
    result = bootstrap.bind()
    assert result == {"status": "verified", "binding_version": 2, "calls": 3}
    assert events == [("parent", "offline"), ("verify", "created"),
                      ("verify", "verified"), ("verify", "verified"), ("commit", 3)]
