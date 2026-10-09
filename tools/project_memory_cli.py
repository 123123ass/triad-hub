"""Local controller only. No HTTP/agent write endpoint; no personal-memory import."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from services.project_memory import initialize, publish_reviewed, read_snapshot, ProjectMemoryError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--project", default="triad-collaboration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    read = sub.add_parser("read")
    read.add_argument("--agent", choices=["codex", "hermes", "workbuddy"], default="codex")
    publish = sub.add_parser("publish-reviewed")
    publish.add_argument("--request", required=True, help="Reviewed JSON; includes expected head revision+digest")
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args.root)
            result = {"initialized": True}
        elif args.command == "read":
            result = read_snapshot(args.root, args.project, args.agent)
        else:
            request = json.loads(Path(args.request).read_text(encoding="utf-8"))
            if set(request) != {"body", "evidence", "expected_revision", "expected_digest"}:
                raise ProjectMemoryError("project_memory_request_invalid")
            result = publish_reviewed(args.root, args.project, **request)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except ProjectMemoryError as exc:
        print(json.dumps({"ok": False, "error_code": str(exc)}))
    except Exception:
        print(json.dumps({"ok": False, "error_code": "project_memory_cli_failed"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
