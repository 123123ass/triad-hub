"""Build a conservative, auditable source candidate outside the live Hub.

This command never publishes, commits, uploads, overwrites, or deletes. An
audit finding blocks the candidate even if the copied files are usable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1]
ROOT_FILES = (
    ".env.example", ".gitignore", "LICENSE", "README.md", "SECURITY.md",
    "CONTRIBUTING.md", "requirements.txt",
    "pytest.ini", "config.py", "context_builder.py", "db.py",
    "evidence_redaction.py", "feishu_listen.py", "feishu_reply.py",
    "hub_bridge.py", "logging_config.py", "main.py", "migrate.py",
    "models.py", "redaction.py", "repository.py", "run_bridges_bg.py",
    "run_triad_runtime.py", "schemas.py", "security.py", "start_bridges.py",
)
SOURCE_DIRS = {
    "adapters": {".py"},
    "services": {".py"},
    "migrations": {".sql"},
    "prompts": {".txt"},
    "dashboard": {".html", ".css", ".js"},
}
TOOLS = (
    "bootstrap_codex_portable.py", "build_public_beta.py", "project_memory_cli.py",
    "run_agent_worker.py", "run_outbox_worker.py", "triad_dashboard.py",
    "triad_resident.py", "verify_public_beta.py", "wb_edit_guard.py",
)
DOCS = ("architecture.md", "security.md")
TESTS = ("test_protocol.py", "test_public_smoke.py", "test_public_release_gate.py",
         "test_portable_codex_bootstrap.py", "test_operator_identity.py")

# These are review triggers, not a substitute for human inspection or a
# history-aware secret scanner. Never print a matched value.
RULES = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "openai_style_key": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    "bearer_literal": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{18,}", re.I),
    "feishu_app_id_literal": re.compile(r"\bcli_[0-9a-f]{32}\b"),
    "feishu_open_id_literal": re.compile(r"\bou_[0-9a-f]{24,}\b"),
    "home_path": re.compile(r"[A-Za-z]:[/\\]Users[/\\][^/\\\s]+", re.I),
    "private_workspace_path": re.compile(r"[A-Za-z]:[/\\]triad_shared[/\\]", re.I),
    "credential_assignment": re.compile(
        r"\b(?:SECRET|TOKEN|PASSWORD|API_KEY)\s*=\s*['\"][^'\"\s]{6,}['\"]", re.I
    ),
    "split_uuid_literal": re.compile(
        r"['\"][0-9a-f]{8}['\"]\s*,\s*['\"][0-9a-f]{4}['\"]", re.I
    ),
}
FORBIDDEN_NAMES = {".env", "auth.json", "credentials.json", "triad.db",
                   "project_memory.sqlite3"}
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".log", ".bak", ".pem",
                      ".key", ".p12", ".pfx", ".pyc"}


def selected_files() -> list[Path]:
    selected = [Path(x) for x in ROOT_FILES]
    selected += [Path("tools") / x for x in TOOLS]
    selected += [Path("docs") / x for x in DOCS]
    selected += [Path("tests") / x for x in TESTS]
    for folder, suffixes in SOURCE_DIRS.items():
        selected += [p.relative_to(SOURCE) for p in (SOURCE / folder).rglob("*")
                     if p.is_file() and p.suffix in suffixes and "__pycache__" not in p.parts]
    return sorted(set(selected), key=lambda p: p.as_posix())


def audit_file(path: Path, rel: Path) -> list[dict]:
    hits = []
    if rel.name.casefold() in FORBIDDEN_NAMES or rel.suffix.casefold() in FORBIDDEN_SUFFIXES:
        hits.append({"path": rel.as_posix(), "line": 0, "rule": "forbidden_name"})
    try:
        data = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return hits + [{"path": rel.as_posix(), "line": 0, "rule": "non_utf8"}]
    for no, line in enumerate(data.splitlines(), 1):
        for name, pattern in RULES.items():
            if pattern.search(line):
                hits.append({"path": rel.as_posix(), "line": no, "rule": name})
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="New empty output directory, outside source")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    src = SOURCE.resolve()
    if out == src or src in out.parents or out in src.parents:
        parser.error("output must be separate from the live source tree")
    if out.exists():
        parser.error("output already exists; refusing overwrite")
    manifest = []
    files = selected_files()
    for rel in files:
        origin = SOURCE / rel
        if not origin.is_file() or origin.is_symlink() or SOURCE.resolve() not in origin.resolve().parents:
            parser.error(f"missing or unsafe source file: {rel.as_posix()}")
    out.mkdir(parents=True)
    hits = []
    for rel in files:
        origin, target = SOURCE / rel, out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, target)
        manifest.append({"path": rel.as_posix(), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
        hits.extend(audit_file(target, rel))
    (out / "RELEASE_MANIFEST.json").write_text(
        json.dumps({"files": manifest}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    audit = {"candidate": str(out), "file_count": len(files), "finding_count": len(hits),
             "findings": hits, "content_scan_clear": not hits,
             "release_ready": False,
             "release_ready_reason": "requires independent portability and human review"}
    audit_path = out.parent / (out.name + ".audit.json")
    audit_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"candidate": str(out), "files": len(files), "findings": len(hits),
                      "audit": str(audit_path), "content_scan_clear": not hits,
                      "release_ready": False}, ensure_ascii=False))
    return 0 if not hits else 2


if __name__ == "__main__":
    raise SystemExit(main())
