"""Recheck an allowlisted candidate before any local commit or publication."""
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path

sys.dont_write_bytecode = True
from build_public_beta import audit_file


def verify(root: Path) -> dict:
    root = root.resolve()
    manifest_path = root / "RELEASE_MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError("invalid_manifest")
    expected = {}
    for entry in entries:
        rel = Path(entry["path"])
        if rel.is_absolute() or ".." in rel.parts or rel.as_posix() in expected:
            raise ValueError("unsafe_manifest_path")
        expected[rel.as_posix()] = entry["sha256"]
    actual = {}
    for path in root.rglob("*"):
        if ".git" in path.relative_to(root).parts:
            continue
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
        if path.is_symlink() or attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("reparse_point_in_candidate")
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            if rel != "RELEASE_MANIFEST.json":
                actual[rel] = path
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = []
    findings = []
    for rel, path in actual.items():
        if rel in expected and hashlib.sha256(path.read_bytes()).hexdigest() != expected[rel]:
            changed.append(rel)
        findings.extend(audit_file(path, Path(rel)))
    return {"file_count": len(actual), "missing": missing, "extra": extra,
            "changed": sorted(changed), "scan_findings": len(findings),
            "candidate_integrity_ok": not (missing or extra or changed or findings)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    result = verify(Path(args.root))
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["candidate_integrity_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
