# Architecture and trust boundary

Triad Hub runs on the operator's machine. Feishu is an optional visible entry and reply surface; the Hub is the task ledger and scheduler; Codex, Hermes, and WorkBuddy/CodeBuddy remain independent clients with separate authentication and sessions.

```text
human @ one bot -> identity/mention checks -> task + trace in SQLite
                -> bounded agent call -> evidence reference + result
                -> next allowed handoff -> single final review
                -> Feishu reply / local read-only dashboard
```

The route is a controller rule, not a model-supplied instruction. Ordinary bot-to-bot mentions do not create another task. A model's assertion of completion is not acceptance: call receipts, task/trace identity, parent event, result state, and evidence references are checked. After a call outcome becomes unknown, the Hub does not automatically replay a potentially side-effecting action.

## Shared state versus private memory

The SQLite task ledger stores bounded events, tasks, evidence references, and per-agent cursors. A context builder gives each agent the relevant task plus unconsumed events and verified summaries. This supports cross-agent handoff within a run.

A separate, opt-in project checkpoint can carry reviewed facts across runs. The controller publishes a new revision with evidence and expected-head checks. Every agent sees the same revision/digest when configured; the frozen call payload does not change mid-call. The checkpoint is advisory context, not a grant of permissions. It never imports private Codex, Hermes, or WorkBuddy chats automatically.

Keep both databases, evidence, and personal session files out of source control. Checkpoint integrity is an application-level control; processes with the same operating-system account are not isolated from one another by it.

## Deployment boundary

The Hub and dashboard bind to `127.0.0.1` by default. A public reverse proxy is not part of the default architecture. If remote viewing is needed, use a private network and preserve Host/Origin checks; do not expose an unreviewed dashboard or credentials to the internet. The UI is read-only and its role cards require current process/heartbeat validation; a historical successful task is not proof a worker is presently online.

WorkBuddy's CLI edit mode is disabled by default. A controller may opt in to a short-lived exact task/file grant, with the tool and path checked before execution. This is a narrow execution capability, not blanket permission for agents to edit the host filesystem.
