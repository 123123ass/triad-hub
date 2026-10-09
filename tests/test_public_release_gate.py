"""Protect the public source allowlist from accidental private-state inclusion."""
from pathlib import Path

from tools.build_public_beta import audit_file, selected_files


def test_release_allowlist_excludes_private_bootstrap_and_state():
    names = {p.as_posix() for p in selected_files()}
    assert "tools/bootstrap_codex.py" not in names
    assert "tools/bootstrap_codex_portable.py" in names
    assert ".env" not in names
    assert not any(name.startswith(("evidence/", "runtime/", "_sr2_qualify/")) for name in names)


def test_release_scanner_catches_split_session_identifier(tmp_path):
    path = tmp_path / "fake.py"
    first = "1234" + "abcd"
    path.write_text(f'ID = "-".join(["{first}", "5678", "9abc", "def0", "123456789abc"])',
                    encoding="utf-8")
    hits = audit_file(path, Path("fake.py"))
    assert any(hit["rule"] == "split_uuid_literal" for hit in hits)
