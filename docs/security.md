# Security policy and release hygiene

## Never publish

- `.env` and all credential backups, API keys, Feishu App Secrets, tokens, cookies, or HMAC keys.
- SQLite databases and WAL files, raw evidence, logs, request/response dumps, private chats, memory checkpoints, and agent session identifiers.
- Local absolute paths and non-public hostnames/IPs that identify the operator's machine or deployments.

Prepare releases from an explicit file allowlist into an empty directory. Inspect the exact resulting tree and scan both file names and contents before any Git commit. A `.gitignore` is a defense-in-depth filter, **not** proof that an already-copied secret is safe. If a secret was ever committed, remove it from history and rotate it; deleting the latest file alone is insufficient.

The historical local Codex bootstrap helper is intentionally **not** part of the public beta candidate: it references a private desktop task and machine-specific acceptance manifests. The separate portable Codex binder creates a new session and requires two verified resumes before committing a binding; a fresh-database live handshake has passed on the maintainer's machine. Hermes and WorkBuddy onboarding still need independently reproducible first-use verification, so this is not a turnkey three-agent installer.

The default network boundary is loopback. Do not expose the Hub admin surface or a Feishu bridge without configuring HMAC/admin secrets, verified bot identities, and chat/user allowlists. Model output cannot authorize new commands, routes, credentials, files, or other agents.

Report vulnerabilities privately to the repository maintainers once a public repository exists. Do not include live credentials or raw user data in a GitHub issue. This public beta is not warranted for unattended operation; operators must run their own isolated tests and review external-account permissions.
