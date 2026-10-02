# Audit intent before a side effect

This is the RAGBAZ suite convention for state-changing actions in Frog, Ephor,
WeftMark, Sylvae, Rebekah and Dash.

1. Apply cheap authentication and per-identity/global admission limits first.
2. Validate and bound the proposed action. Minimize fields; do not place secrets,
   raw credentials, unrestricted tool arguments or unbounded text in an intent.
3. Commit a small `*.requested`/`*.started` audit intent before the side effect.
   For resources not yet created, put their proposed IDs/paths in the payload;
   do not use a foreign key to a row that does not exist yet.
4. Perform the action. Append a bounded outcome (`succeeded`, `failed`, or
   `unknown`) linked to the intent. After a crash, a durable intent without an
   outcome means the operation may have started and must be reconciled.
5. If intent persistence fails, refuse the protected side effect. Do not turn
   this into a fail-open path.

Rate limiting applies before detailed event creation. Keep event payload sizes,
accepted intent rates, and retained counter cardinality bounded. Represent the
first rejected burst per actor/window and global window with one compact event;
subsequent denied attempts in the same saturated window must not each write an
event. They must also never proceed to the protected action. Enforce upstream
request/body limits and authentication; an audit log is not a substitute for
network-level DDoS protection.

For remote side effects, persist an outbox intent before sending, use an
idempotency key, and record the remote receipt/result after. “Intent committed”
does not mean “action succeeded”. A successful database transaction can make a
state change and its outcome atomic, but cannot preserve evidence of an action
that crashes before the transaction commits; use a prior durable intent when
that evidence matters.

An event log must resist edits independently of ordering. Prefer Nostoi's
append-only chain/store, and periodically anchor its head somewhere the writer
cannot rewrite. A hash chain without an external trusted head cannot detect
truncation of its tail or a fully rewritten chain. Keep raw personal data out of
logs; apply approved redaction before the durable intent is written.

## Current suite evidence and follow-up

- **Ephor tool gate:** the agent proxy calls `/capture` before forwarding an
  allowed tool call and returns a gateway error when capture fails. Human
  approval is recorded before the held action is released. Preserve this
  fail-closed ordering and bound authentication failures at the edge.
- **Frog:** implement this contract for repository creation/registration and
  instruction-file writes. The generic event table uses repository foreign
  keys, so pre-create intent rows leave `repo_path` null and carry the proposed
  path in bounded payload. The intent transaction uses SQLite FULL sync and
  separate global/per-actor per-minute budgets. A limited window emits at most
  one compact rate-limit event; further attempts are refused without database
  writes for that window.
- **WeftMark:** audit mutating Git/control operations before launching or
  committing them; review which scope-audit operations necessarily inspect the
  changed files afterward and pair those results with a prior intent.
- **Sylvae:** record a run-start intent before invoking a model/provider, then
  append completion/failure. Preserve run identity and avoid logging full
  prompts unless the data policy explicitly permits them.
- **Rebekah and Dash:** keep state changes and their audit rows in a single
  transaction where possible; create durable intents before external calls,
  deployments, instance commands or agent releases. Apply edge rate limits so
  unauthenticated/rejected traffic cannot flood audit storage.

These are implementation requirements, not a claim that every listed path has
already been migrated. Check each project's current control flow and tests as
its Nostoi integration is picked up.
