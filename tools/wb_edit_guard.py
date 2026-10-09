"""Fail-closed CodeBuddy PreToolUse gate for one controller-granted file."""
import json
import sys
from pathlib import Path


def decision():
    target = Path(sys.argv[1])
    request = json.load(sys.stdin)
    supplied = request.get('tool_input', {}).get('file_path')
    if request.get('tool_name') != 'Edit' or not isinstance(supplied, str):
        return 'deny'
    path = Path(supplied)
    if (not path.is_absolute() or not path.is_file() or path.is_symlink() or
            not target.is_file() or target.is_symlink()):
        return 'deny'
    if any(parent.is_symlink() for parent in path.parents):
        return 'deny'
    return 'allow' if path.resolve() == target.resolve() else 'deny'


try:
    result = decision()
except (OSError, ValueError, IndexError, TypeError):
    result = 'deny'
print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                                         'permissionDecision': result,
                                         'permissionDecisionReason': 'controller_exact_file_grant'}}))
