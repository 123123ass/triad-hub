# Contributing

Please open an issue describing the behavior and a reproducible, redacted test case before substantial changes. Do not upload a real `.env`, database, log, session, evidence folder, or private deployment address.

For code changes, keep the task/trace and fail-closed security boundaries intact. Add an offline regression test, run `python -m pytest -q`, and state whether any live Feishu or model call was made. Treat an unknown external-call outcome as unknown rather than retrying automatically.

The public beta package contains a small, dependency-independent smoke suite; its result is not a substitute for the maintainer's full private integration suite. Contributions are intended to be licensed under Apache-2.0, matching the repository license.
