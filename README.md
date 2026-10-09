# Triad Hub

Triad Hub is a local-first collaboration controller for Codex, Hermes, and WorkBuddy/CodeBuddy. A single human message can start a bounded handoff; the Hub records task state, evidence references, per-agent consumption cursors, and the final review instead of treating bot replies as proof of completion.

This repository is being prepared for a public beta. It is **not** an autonomous multi-agent swarm or a hosted service. The three model accounts, their private chat histories, and their credentials stay separate. The Hub supplies reviewed shared context; it does not copy private memories between products.

## What is distinctive

- **One visible task ledger.** Events, task/trace identity, owner, versions, and evidence are recorded centrally. Each agent receives only the bounded context it needs and advances its own cursor after a completed call.
- **Evidence-gated handoff.** A multi-agent task has an explicit route and a single final review. Model text cannot silently change the route or mark itself accepted.
- **Reviewed cross-run memory.** A controller can publish a versioned project checkpoint. All three agents read the same revision and digest when the two opt-in environment variables are set. This is curated project knowledge, not an automatic merge of full chat histories.
- **Safe defaults.** The Hub and dashboard bind to loopback by default; outbound model calls and Feishu connections require local configuration. WorkBuddy's edit tool is disabled by default and requires an exact, expiring task/file grant. Unknown call outcomes are not blindly retried.

## Status and limits

The local integration has passed an isolated full regression of 1,390 tests (2 Windows symlink-permission skips) and bounded live Feishu handoffs initiated separately from Codex, Hermes, and WorkBuddy. A separate project-memory-enabled Codex → Hermes → WorkBuddy handoff passed with one shared checkpoint revision and no automatic retries. The portable Codex binder also passed a fresh-database, three-call live handshake in a separate candidate tree. These are local acceptance results, **not** a guarantee that an arbitrary installation is ready without its own credentials, session bindings, and end-to-end tests. Hermes and WorkBuddy first-use onboarding is not yet turnkey.

The desktop Codex chat is not automatically the Hub's bound Codex CLI session. The dashboard does not prove a worker can call its model solely because a process is visible. A recalled Feishu message does not yet cancel an already accepted task. The dashboard is local-only unless an operator deliberately configures a private reverse proxy; there is no public dashboard deployment here.

## Local setup (Windows / Python 3.11+)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
# Fill .env locally. Never commit it or paste its values into issues or logs.
.\.venv\Scripts\python.exe migrate.py
.\.venv\Scripts\python.exe run_triad_runtime.py --preflight
```

The preflight is diagnostic; it does not establish a live three-agent route. For a minimal local Hub process after configuration:

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8900
```

Full Feishu and CLI operation additionally needs three application identities, allowed chat/user IDs, each agent's own authenticated CLI or gateway, session bindings, and an explicitly started supervised run. Do not copy someone else's `.env`, SQLite files, evidence, or sessions. See `docs/architecture.md` and `docs/security.md` in the public beta package before enabling external messages.

Set `FEISHU_OPERATOR_UNION_ID` to the designated human operator's Feishu union ID. `FEISHU_OPERATOR_USER_ID` is a transitional open-ID fallback only when no union ID is configured; with a union ID, mismatches fail closed. Older local deployments may temporarily keep `FEISHU_YANGGE_UNION_ID` and `FEISHU_YANGGE_USER_ID`; the neutral names take precedence. Remove the legacy variables after migration. The internal human actor is now `operator`; legacy `yangge` envelope values are normalized on input. This compatibility does not copy or expose any real identity values.

For a fresh Codex CLI binding, configure either `TRIAD_CODEX_BIN` as an absolute executable path or both `TRIAD_NODE` and `TRIAD_CODEX_JS` as absolute file paths. Log into your own CLI first. Then run the prerequisite check and explicitly start the three-call read-only handshake:

```powershell
.\.venv\Scripts\python.exe tools\bootstrap_codex_portable.py --check
.\.venv\Scripts\python.exe tools\bootstrap_codex_portable.py --bind
```

The binder creates a **new dedicated CLI session**, verifies two resumes and only then commits it to the local database. It never reuses this desktop chat, copies credentials or retries an uncertain call. If it reports `blocked`, inspect the stable error code and do not rerun blindly. Hermes and WorkBuddy require their own separately verified bindings; this Codex step alone is not an end-to-end triad setup.

## Shared project checkpoint

This feature is opt-in and fail-closed. Set both variables **before starting a new run**:

```powershell
$env:TRIAD_PROJECT_MEMORY_ROOT='C:/path/to/private/project_memory'
$env:TRIAD_PROJECT_MEMORY_ID='your-project-name'
```

The checkpoint database and its evidence are private runtime state, never a GitHub artifact. If either variable is missing, that run does not receive cross-run project memory. It still has its own task/event context. Publishing a checkpoint requires controller review and an evidence digest; model output is not automatically trusted as memory.

## Development

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest -q
```

The historical full-suite result belongs to the original private workspace. A curated public package must be tested again from a fresh checkout. No credentials are needed for offline unit tests; live Feishu/CLI tests are opt-in and may consume account quota.

## Security and license

Never put secrets, private conversations, session files, raw evidence, or local databases in a repository. Follow the allowlisted release process and review its scan report before publishing. Report vulnerabilities privately rather than posting credentials in a public issue. Source code is licensed under [Apache License 2.0](LICENSE); third-party services and SDKs retain their own terms.
