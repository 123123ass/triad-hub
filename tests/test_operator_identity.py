"""Neutral operator identity with fail-closed legacy configuration compatibility."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import security
from config import config
from schemas import EnvelopeV1
from services.feishu_ingress import IngressRejected, identify_sender, resolve_targets


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("operator_value", "legacy_value", "expected"),
    [(None, "legacy-id", "legacy-id"), ("new-id", "legacy-id", "new-id")],
)
def test_operator_environment_precedence(operator_value, legacy_value, expected):
    env = os.environ.copy()
    env.pop("FEISHU_OPERATOR_UNION_ID", None)
    env["FEISHU_YANGGE_UNION_ID"] = legacy_value
    if operator_value is not None:
        env["FEISHU_OPERATOR_UNION_ID"] = operator_value
    result = subprocess.run(
        [sys.executable, "-c", "from config import config; print(config.FEISHU_OPERATOR_UNION_ID)"],
        cwd=ROOT, env=env, check=True, capture_output=True, text=True,
    )
    assert result.stdout.strip() == expected


def test_operator_union_id_is_authoritative(monkeypatch):
    monkeypatch.setattr(config, "FEISHU_OPERATOR_UNION_ID", "union-owner")
    monkeypatch.setattr(config, "FEISHU_OPERATOR_USER_ID", "legacy-open")
    assert identify_sender("any-open", "union-owner") == "operator"
    with pytest.raises(IngressRejected, match="sender_denied"):
        identify_sender("legacy-open", "wrong-union")
    assert security.authorize_admin_command(
        "/pause trace", "operator", "legacy-open", "union-owner"
    ) == security.OK
    assert security.authorize_admin_command(
        "/pause trace", "operator", "legacy-open", "wrong-union"
    ) == security.ERR_ADMIN_DENIED


def test_missing_operator_identity_never_authorizes_admin(monkeypatch):
    monkeypatch.setattr(config, "FEISHU_OPERATOR_UNION_ID", "")
    monkeypatch.setattr(config, "FEISHU_OPERATOR_USER_ID", "")
    assert security.authorize_admin_command("/stop trace", "operator") == security.ERR_ADMIN_DENIED


def test_legacy_envelope_actor_normalizes_to_operator():
    envelope = EnvelopeV1(event_id="event", trace_id="trace", source_agent="yangge")
    assert envelope.source_agent == "operator"
    assert resolve_targets("operator", [], False) == []
