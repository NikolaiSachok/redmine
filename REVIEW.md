# For the review team

`README.md` documents **the feature**. This file documents **the work**: how it went, what was
decided and against what alternative, how the AI development workflow started and what it became,
and why a task calibrated at two hours ran to twenty.

**Candidate:** Nikolai Sachok — Staff Product Engineer, TaxDome technical challenge.
**Code:** `github.com/NikolaiSachok/redmine`, pull request **#13**,
`feat/personal-access-tokens` → `base-6.1.2`, open and unmerged as the brief requires.

**One thing about layout, because this file may reach you on its own.** The deliverable is three
things side by side, not one: the **git repository** (`README.md` and the code), the **`notes/`
directory**, and the **unedited Claude Code transcripts**. Every `notes/…` path below refers to that
sibling directory — it is deliberately *not* committed, so the pull request diff shows exactly the
engineering slice and nothing else. Paths beginning `~/.claude/` are the agent definitions, which
travel with the transcripts.

---

## Where everything is

| | |
|---|---|
| **The code** | PR **#13**, `feat/personal-access-tokens` → `base-6.1.2`, open and unmerged. 27 commits, +8,478 lines: 4,674 test, 2,560 application, the rest documentation |
| **The scoping trace** | The issue board — **39 issues**, one per unit of work, opened before the work and referenced from every commit. 26 closed, 13 open: 6 `deferred`, 3 `pre-existing`, 1 needing a product decision, and the 4 core issues that stay open only because the PR is deliberately unmerged |
| **The feature** | `README.md` — design, limits, and `curl` transcripts against a running server |
| **The reasoning** | `notes/DECISIONS.md` (1,707 lines) — every non-obvious decision, written as it happened, with the rejected alternative |
| **The traceability** | `notes/REQUIREMENTS.md` — 128 requirements across 9 families, each with status and evidence |
| **The adversarial record** | `notes/ATTACKS.md` — 115 attacks, including the ones that failed |
| **The interface record** | `notes/UI-CHECKS.md` — 91 probes across persona × surface × setting |
| **The measurements** | `notes/SCALE-AUDIT.md` — 200,000-row performance study, method included |
| **The autonomous run** | `notes/LOOP-LOG.md` (880 lines) — an overnight run of four features, marking exactly where a human was needed |
| **The harness** | `~/.claude/agents/*.md` — four agent definitions and one command, shipped with the transcripts |
| **The raw record** | The unedited Claude Code transcripts |

A reader with fifteen minutes should read this file, then `README.md`'s "Limits" section, then skim
`notes/UI-CHECKS.md` — that last one is the shortest demonstration of what the harness became.

---

## Why this took twenty hours, not two

Wall clock from first commit to last: **2026-08-12 21:28 → 2026-08-13 17:49**. Five reasons, in
order of how much they cost.

**1. The scope grew, deliberately and with the candidate's agreement.** The brief's required core is
pillar 1 of Redmine #43881. That was complete and verified in about three hours. What followed —
token scopes, CORS, granular endpoint control, and structured audit logging — is four more of the
ticket's six pillars, taken on after the core was solid because the optional pillars carry credit and
the harness needed something to be tested *on*. Rate limiting remains excluded, as the brief requires.

**2. Verification cost more than implementation, on purpose.** The gate is five independent axes and
they are re-run after every fix. Every regression test in this branch was proved by **disabling the
fix and watching it fail** — a test that passes either way is not evidence. Two adversarial agents
run against a live server rather than reading the diff. This is most of the twenty hours, and it is
the part the candidate considers the deliverable.

**3. Wall-clock is not thinking time.** The full suite is ~5 minutes and was run dozens of times.
Subagents run in real time — the two interface passes were 20 and 27 minutes each, the scale study
23 minutes. The overnight autonomous run occupied several hours by design, with nobody at the
keyboard. The container also degraded measurably partway through: an identical suite that took 265s
early took 809s later, which distorted one performance claim badly enough that it had to be retracted
(see below).

**4. Setup and finalisation are real work.** Before any code: reproducing the problem, and three
parallel read-only agents producing the code maps that every later agent was pointed at instead of
re-deriving. After the code: issue hygiene, the README, the PR body, the requirement matrix, and this
file.

**5. Building the harness was a deliberate choice, not overrun.** Around the halfway point the
candidate chose explicitly to invest in the workflow rather than in more features, on the reasoning
that a harness which verifies work generalises beyond one ticket and a fifth feature does not. That
choice is why this document exists.

**What two hours would have bought:** pillar 1, tested, with a README. It existed, and it was
demonstrably not finished — the gate found an authentication regression and a privilege escalation in
it *after* the suite was green.

---

## The trajectory

**Phase 0 — map before building.** The problem reproduced against a running server; three read-only
subagents in parallel produced `CODE-MAP-auth.md`, `CODE-MAP-ui.md`, `CODE-MAP-tests.md`. Every later
agent was handed those paths rather than re-investigating. This is the single highest-leverage thing
in the whole run: it is what made briefing an implementation agent by *path* possible later.

**Phase 1 — the core, written by the orchestrator.** Design decisions taken with the human, then
pillar 1 implemented directly in the main session. A deliberate choice at the time: the durable
artifacts did not yet exist, so an agent could only have been briefed by conversation.

**Phase 2 — the first gate, and the discovery that green means nothing.** Completeness, blast radius,
`/code-review`, `/security-review`, and a red team against a live instance. The suite was green
throughout and the gate still found an authentication regression, a privilege escalation the feature
introduced, and — after that was fixed — **a bypass of its own fix**. That last one produced the rule
that governs everything after it: *a fix is a new surface*.

**Phase 3 — the harness formalised.** The reviewers became durable agent definitions; the attack
record became a living ledger with regress/vary/extend/chain obligations; `/ship-check` chained the
axes. The red team was split into three views — full source, git history only, and blind — because
the blind one attacks what a user can actually see.

**Phase 4 — the overnight autonomous run.** Four features implemented unattended by sequential agent
teams, each with its own gate round, with **park-and-continue** on unbriefed decisions: open an issue,
take the smallest reversible option, mark it `PROVISIONAL`, keep going. Three human intervention
points, all recorded in `LOOP-LOG.md`: the design decisions before, three parked decisions confirmed
in the morning, and the review after. Everything between was autonomous, including issue planning,
test authoring, attacking, and fixing.

**Phase 5 — the human found what four gates could not.** Manual review turned up two defects in
minutes: the audit log's default view could not say *which* token was used, and a **saved query was
reachable from nowhere in the product**. Neither is a code defect a reviewer would spot; both are
reachability defects. This produced the fifth axis, `ui-verifier`, and it is the most interesting
thing in the run — see below.

**Phase 6 — measure, freeze, prepare.** A 200,000-row scale study settled two deferred performance
questions with numbers instead of intuition, and turned up a correctness defect neither had predicted.
Then implementation froze and the deliverables were reconciled.

---

## Major decisions and their trade-offs

Full reasoning in `notes/DECISIONS.md`; this is the index.

| decision | rejected alternative | cost accepted |
|---|---|---|
| **A separate `PersonalAccessToken` model** | Extending Redmine's `Token` registry with a new action | ~15 lines of honest duplication and a second place to look for credentials. Bought: `Token` untouched, so every existing login, feed and 2FA path passes *by construction*. `Token`'s expiry is per-action not per-record, and its `varchar(40)` cannot hold a SHA-256 digest — the reuse benefit evaporates on contact |
| **Refuse `?key=` for tokens** | Matching the API key's three transports | A migration inconvenience, and the new credential is *stricter* than the old one beside it. Bought: no credential in a URL, where Rails filtering cleans only Rails' own log — not proxies, `Referer`, or shell history. Chosen after the human pushed back on an earlier answer that favoured compatibility |
| **SHA-256, not bcrypt** | A slow KDF | None worth naming: the secret is 256 bits of `SecureRandom`, not a human password, so a slow KDF taxes every API request and buys nothing |
| **Hand-rolled CORS** | `rack-cors` | Reimplementing well-tested edge cases (`null`, preflight, `Vary`) — covered by tests, which is not a decade of production use. Bought: no new dependency in someone else's repository |
| **A controller filter for CORS, not Rack middleware** | Middleware | Responses built outside the controller (routing 404s, malformed-body 400s) carry no CORS headers, so a browser client sees an opaque error. Bought: no duplication of routing logic to answer "is this an API request" |
| **Audit default = writes + auth failures** | Log everything | Reads are invisible at the default level, which surprised the human immediately. Bought: an order of magnitude less volume on an instance that is 90–95% polling GETs. Still the right default; the surprise was a *documentation* failure |
| **Unknown endpoint = enabled** | Unknown = disabled | A plugin's new action lands enabled inside a group an administrator believes is off. Bought: upgrades never silently break running integrations. Genuinely in tension; argued both ways in `README.md` |
| **Self-service token screens gated on the API setting; the admin screen deliberately not** | Consistency between them | An asymmetry that needs a test to stop someone "fixing" it. Bought: switching the API off — the first move in an incident — no longer removes the only route to the screen that revokes tokens |
| **No headless browser** | Selenium + screenshots + vision | No visual, layout or accessibility verification, and one JavaScript handler whose *behaviour* is unverified. Reasoning below — this was offered and declined |
| **Agents implement; the orchestrator verifies** | Orchestrator writes everything | Briefing overhead, and one agent that exposed a credential. Bought: four features in a night without the orchestrator's context collapsing. This *reversed* an earlier decision, and the reversal is recorded with its date rather than edited over |

---

## The AI development workflow: start and finish

**Start.** One interactive Claude Code session. No agents, no ledgers, no gate. Verification meant
running the test suite. The first feature was built this way and it worked — and then the first
adversarial pass found two real defects in it, both invisible to a green suite.

**Finish.** A five-axis gate, three self-extending ledgers, four durable agent definitions, and a loop
that can take an issue from planning through implementation, testing, adversarial review and fixing
without a human in it.

| axis | question | agent | ledger |
|---|---|---|---|
| completeness | is anything *missing*, measured against the ticket and the brief — never against the issues, which cannot find work nobody tracked | `completeness-reviewer` | `REQUIREMENTS.md` |
| blast radius | what *existing* behaviour can break, and is it pinned | `blast-radius-reviewer` | — |
| correctness | is the diff right | `/code-review` | — |
| adversarial | can it be abused on a running server | `redteam` | `ATTACKS.md` |
| interface | can the right people *reach* it, and does it tell the truth | `ui-verifier` | `UI-CHECKS.md` |

**Five things made it work, and they transfer to any codebase:**

1. **Artifacts, not prompts.** Agents are pointed at grep-anchored files, never handed pasted context.
   This is what let an implementation agent be briefed in a paragraph.
2. **The inventory is derived, never supplied.** Both adversarial agents build their own target list
   from the diff. A list of things to check can only contain what someone already thought of.
3. **Disable the fix and watch the test fail.** Applied to every regression test here. It caught a
   test of the orchestrator's own whose assertion could not fail at all.
4. **Blind re-runs after fixing.** The second interface pass found five defects, and *three were
   caused by the first pass's fixes*. Re-running the gate against fixed code is where that appears.
5. **No allowlists.** Deliberate asymmetries are re-reported every run with their in-code evidence and
   ruled on by a human. A suppression list rots and turns a verifier into a rubber stamp.

**What the gate caught that a green suite did not:** an authentication regression; a privilege
escalation and the bypass of its own fix; a cleartext credential in the log; a fail-open default
granting full access; a cross-origin containment failure; a CSV formula injection; a 500 in a file the
diff never touched; thirteen interface defects; and several claims contradicted by their own
behaviour — including two inside `DECISIONS.md` itself, one of which an agent falsified by measuring
the precedent that decision *cited*.

### The interface axis, in more detail

It exists because a human beat four automated gates in about five minutes, and it is the clearest
demonstration of how the harness improved.

The naive design — "every route the diff adds must be linked from somewhere" — **passes this branch**.
The route was linked; the *saved object* was not. So the agent performs each create affordance and
re-crawls, requiring the artifact to be discoverable. It probes each surface as four personas across
each relevant setting value, and — the part that matters most — **re-requests every discovered URL as
every other persona**, because hiding a link is not authorization. That probe found two screens
reachable by URL while their links were correctly hidden.

Run 1: seven defects, including both the human's. Run 2, against the fixed branch: five more, three of
them created by run 1's fixes.

---

## Limits, honestly

**No browser.** Offered and declined, and the reasoning matters more than the conclusion: every UI
defect this project produced was DOM- or copy-level, where fetching HTML is a *faster and more
deterministic* detector than a screenshot plus vision — and vision only finds a missing element if
told what should have been there, which is exactly the hint the system must work without. The deciding
argument was evidence quality: a vision check contributes "it looks right", a soft signal, to a project
that had already retracted one overclaim. Zero visual coverage declared as a gap beats fuzzy visual
coverage reported as confidence. The costs are real and named: no layout, RTL or accessibility
judgement; `test/system/` never ran locally; one JavaScript handler is verified by its wiring only.

**Other gaps, stated rather than discovered:** `require_sudo_mode` was read in source, never exercised
(sudo mode is off in the container). SQLite only — the scale numbers do not transfer to PostgreSQL.
Single machine, no concurrency testing. Assertion counts are nondeterministic run to run, so only run
counts are used as evidence. Three of ticket pillar 2's four bullets, and one of pillar 4's three, are
not built — each an open, labelled issue.

**Two defects remain open on purpose.** #34 needs a product decision about whether a scoped token may
impersonate at all; guessing during a freeze would be worse than documenting it. #37 is inherited from
Redmine's own `Query` and changing it would alter shared upstream behaviour.

---

## Where this goes next

- **A browser, used for the existing suite first.** The highest-value use is not screenshots — it is
  running Redmine's own `test/system/` and closing the JavaScript gap. Visual diffing is a later,
  weaker layer.
- **The gate in CI, not in a session.** The agents run when someone remembers. Reachability assertions
  are already checked-in tests; the adversarial axes are not.
- **Ledgers that outlive the branch.** `ATTACKS.md` and `UI-CHECKS.md` regress their own findings, but
  only within one repository and one session's memory.
- **Automatic triage of `intentional?`.** Every deliberate asymmetry currently costs a human ruling.
  Most could be resolved against the in-code evidence the agent already gathers.
- **Cost control.** Nothing here budgets tokens or wall-clock against the value of a finding. At this
  depth that is affordable; at ten times the scope it would not be.

---

## The orchestrator's own mistakes

Included because a workflow document that only reports the harness catching *other* people's errors
is not evidence of much.

- **A false 3.2× performance claim**, asserted from an uncontrolled comparison, retracted after a
  controlled A/B showed the environment had degraded and the feature had not.
- **A −2.1% index write cost** — impossible, an index cannot make `INSERT` faster. Same uncontrolled
  before/after shape, one day later. Re-measured interleaved: below the noise floor.
- **A regression test whose assertion could not fail**, written one commit after criticising exactly
  that pattern in a test it superseded. Found by the interface agent, not by review.
- **A credential printed to the transcript** by a careless `env | grep` alternation where `hub` matched
  `github`. Reported immediately, token rotated, and the environment moved off environment-variable
  auth entirely.
- **A measurement that silently reported zeros** because `payload[:duration]` does not exist on
  `sql.active_record`. Nearly published.
- **A 404 reported as a product defect** that was an artifact of copying a WAL-mode SQLite database
  with `cp`. Corrected in the same message.

Every one of these is recorded where the claim was originally made, rather than edited over. A
reviewer who finds one overclaim discounts everything else, which is the argument for writing them
down rather than the argument against making them.
