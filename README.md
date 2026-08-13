# Personal access tokens for the Redmine REST API

This branch implements pillar #1 of [Redmine #43881](https://www.redmine.org/issues/43881) —
**personal access tokens**: named API credentials, several per user, individually expiring, stored
only as a digest, revocable from My account.

It is a deliberately small slice of a large ticket, branched from tag `6.1.2`. Redmine's own
`README.rdoc` is unchanged and still describes the product; this file describes the change.

> **Reviewers: start with [`REVIEW.md`](REVIEW.md).** This file documents *the feature*. That one
> documents *the work* — the trajectory, the decisions and what they cost, how the AI development
> workflow began and what it became, and why a task calibrated at two hours ran to twenty.

---

## What is here

| | |
|---|---|
| **Done** | PAT model with hashed storage and per-token expiry; REST API authentication; My account management screen; **administration overview of every user's tokens**; **an administrator ceiling on token lifetime**; **cleanup of long-expired rows**; unit, integration, functional and routing tests |
| **Also done** | **Permission scopes for tokens** — one of pillar #2's four bullets: a read-only preset, a full-access preset and a permission picker, enforced through the mechanism Redmine already uses for OAuth2 scopes; **CORS for the REST API** (pillar #6) — an administrator allowlist of origins, off by default; **granular API endpoint control** (pillar #5) — one checkbox per API endpoint, everything enabled by default; **structured API audit logging** (pillar #4) — two of that pillar's three bullets: a table, a filterable administration screen with CSV export, a level setting defaulting to writes and refused requests, a retention setting and a prune task |
| **Deferred** | The rest of pillar #2 — per-tracker scoping, per-project scoping and an administrator-defined scope vocabulary; the third bullet of pillar #4 — notifications for anomalous API activity; a REST endpoint for the audit log; the 2FA posture; migration off the legacy API key — each an issue with reasoning |
| **Out of scope** | Rate limiting, excluded by the brief |
| **Untouched** | The existing `api_key`, and `Token`, which it is built on |

Deferred work is on the issue tracker rather than in this file's small print: issues #10,
#15, #17, #18, #19 and #20, labelled `deferred`. CORS (#8), granular endpoint control (#7) and audit
logging (#6) all started there and were implemented after the core was solid; they and the scopes
work each have their own section below. Two pre-existing weaknesses found while reading the code are recorded as #11
and #12; #11 is now fixed, because the red team showed this feature makes it reachable with a new
credential, and #12 stays open because closing it fully belongs to the OAuth path, not to this slice.

**Known and not fixed**, so that the issue board and this file agree. Issue **#34**: a read-only
scoped token belonging to an administrator makes `User#admin?` false, so `X-Redmine-Switch-User` is
never evaluated — the request runs as the administrator themselves and the impersonation *attempt* is
recorded nowhere. It is not a privilege escalation, it is a silence, and closing it needs a product
decision about whether a scoped token may impersonate at all; that decision was not taken, so the
defect is documented rather than guessed at. Issue **#37**: one administrator's *private* saved query
is listed to every other administrator, inherited from `Query` and identical on Redmine's own
`UserQuery` screens; changing it would alter shared upstream behaviour, so it is filed as
`pre-existing` and left alone. Issues #1–#4 are the core work and remain open only because the pull
request that implements them is deliberately never merged.

## The problem, reproduced

Before writing anything, the current behaviour was demonstrated on this checkout rather than taken
from the ticket:

| Limitation | How it was shown |
|---|---|
| One key per user | Creating a second `api` token leaves the count at 1, and the first key stops resolving. Rotation means downtime; a script cannot have its own credential. |
| Plaintext at rest | The stored row is byte-identical to the key that just authenticated. Anyone with database read access has every user's key. |
| Never expires | A token backdated ten years still reports `expired? == false` and still authenticates. |
| Nothing to audit | The non-secret columns are `action`, `created_on`, `updated_on`. No name, no last use — you cannot tell two keys apart or notice a stolen one in use. |
| Leaks into logs | Redmine filters only `:password`, so one `?key=` request wrote the admin key in cleartext into `log/development.log`. |

## How personal access tokens work

A token is `rmpat_` followed by 40 hex characters from `Redmine::Utils.random_hex(20)`. The prefix
exists so the credential is recognisable on sight in a log, a config file or a leaked repository, the
way `ghp_` and `glpat-` are.

Only `SHA256(token)` is stored, in `personal_access_tokens.token_digest`, under a unique index.
Authentication hashes the presented value and looks the digest up directly, so there is no scan and
no cleartext column. The value itself is returned once, in memory, on the page that created it — it
is never placed in the flash or the session, and cannot be recovered afterwards.

Each token carries a `name`, an optional `expires_on`, and a `last_used_on` that is written on every
successful authentication. Locking a user does not delete their tokens: authentication resolves only
for an active user, so locking disables and unlocking restores, and a locked account's tokens remain
visible to audit and revoke.

### The management screen

**My account → Personal access tokens**, in three pages following the shape of the list screens
Redmine already has: the list with an "add" link, a separate creation form, and a page that shows the
new token on its own.

Creation defaults to a **30-day** lifetime, with 60 and 90 offered and "No expiration" available but
never the default — choosing a permanent credential has to be deliberate, and the form says what it
means. The token value is then shown on its **own page, titled with that token's name**, so creating
several in a row can never leave you copying the wrong secret. It has a copy button, reusing the
Stimulus controller Redmine already ships for the API key.

GitHub redirects back to the list and highlights the new row instead. That is not safely available
here: Redmine keeps sessions in a **cookie**, so anything put in `flash` travels to the browser, and
the digest-only storage means the value cannot be re-fetched server-side after a redirect the way
Redmine's two-factor backup codes are. Rendering the page directly from the POST keeps the secret in
one response and out of the cookie. The trade-off is that a browser refresh on that page re-submits
the form and produces a duplicate-name error.

**Accepted transports:** the `X-Redmine-API-Key` header, and the HTTP Basic username. **Not** the
`?key=` query parameter — see the limits below.

### Why a separate model instead of extending `Token`

Redmine already has a token abstraction, and today's API key is a `Token` with action `api`. Reusing
it was the first design considered and was rejected on five specifics:

1. **Expiry is per-action, not per-record.** `validity_time` lives on the action registry and expiry
   is `created_on + validity_time`. It cannot express "this token expires on the date its owner
   chose, that one never", which is the point of a PAT.
2. **`tokens.value` is `varchar(40)` with a unique index**, exactly filled by `random_hex(20)`. A
   SHA-256 digest is 64 characters, so hashing means widening a column on the table used by every
   login, session, feed and 2FA flow.
3. **`Token.find_token` looks up by cleartext value.** A hashed token needs its own lookup path
   regardless, so the main reuse benefit disappears on contact.
4. **The `/\A[a-z0-9]+\z/i` value guard is shared** with six other token actions, so permitting a
   prefixed value there changes behaviour for all of them.
5. **`destroy_expired` and `delete_previous_tokens` both encode the old model** — expire by age, cap
   at one instance per user.

Extending would have meant five changes to a model on the critical path of every authentication in
Redmine. A separate table touches none of it, which is why the existing suite passes unchanged.

**The cost, stated plainly:** roughly fifteen lines of "find the active user, check expiry" are
duplicated rather than shared; there are now two token concepts, so an operator auditing credentials
has two places to look; and `redmine:tokens:prune` does not cover PATs. A Redmine maintainer might
reasonably prefer the registry for consistency. This is a judgement call with a real alternative, not
an obvious win.

### Why SHA-256 and not bcrypt

Redmine uses bcrypt for passwords and Doorkeeper uses it for application secrets, so bcrypt is the
locally consistent choice — and it is the wrong one here. Bcrypt's cost factor exists to make
*low-entropy, human-chosen* secrets expensive to brute-force. A PAT is 160 bits of `SecureRandom`
output with no dictionary to run against it, so a deliberately slow KDF would tax every API request
and buy nothing. It also cannot be used for lookup, since a salted hash is not indexable. GitHub and
GitLab hash their tokens the same way and for the same reason.

## Limits of this approach

Naming these is part of the deliverable, so none of them are buried:

- **A scope narrows where authorisation is asked, and nowhere else.** Scopes are enforced at the two
  places Redmine's own OAuth2 scopes are enforced, so any code path that never calls
  `User#allowed_to?` is not covered by them. The limits this leaves are listed in the scopes section
  below, and measured rather than asserted.
- **A write on every request.** `last_used_on` is updated on each successful authentication, so a busy
  API client causes one extra `UPDATE` per request. Coarsening it (only write if the stored value is
  older than *n* minutes) is the obvious optimisation and was left out as premature.
- **No query-parameter support**, deliberately. A client that can only pass credentials in a URL cannot
  use PATs and must keep using the API key. This asymmetry is intentional; the reasoning is below.
- **Locking is not revocation.** A locked user's tokens stop working while the account is locked and
  resume on unlock. If a token leaks, revoke it.
- **Changing your password does not revoke your tokens.** Each one has to be revoked individually.
  This matches both the existing API key and GitHub's behaviour, but it is the opposite of what
  `destroy_tokens` does for sessions, so it is worth knowing. Found by the red team (`PAT-011`).
- **`require_sudo_mode` on create and revoke is config-gated.** Redmine ships with `sudo_mode`
  unset, so on a default installation the guard is a no-op and no password re-entry is required.
  The protection is real only where `sudo_mode: true` is configured; the tests pin it by enabling
  it explicitly. Found by the red team (`PAT-010`).
- **Expiry is mandatory only when an administrator says so.** Pillar 1 of #43881 says tokens must
  expire. Out of the box the creation form makes you *choose* a lifetime — 30 days by default — with
  "No expiration" available, because the credential being replaced never expires and forbidding
  permanent tokens outright would break long-running integrations with no migration path offered in
  the same slice. Setting **Maximum personal access token lifetime** (Administration → Settings →
  API) turns it into a hard requirement: "No expiration" disappears, over-limit presets are dropped,
  and the ceiling is enforced by a model validation so a crafted request cannot exceed it either.
- **PATs inherit the existing API-key posture on 2FA and forced password change.** Neither blocks API
  key authentication in Redmine today, and PATs behave the same. Changing it is a product decision
  beyond this slice.
- **Expiry is a date, not an instant**, evaluated in the **token owner's** timezone via `User#today`.
  The creation side uses the current user's zone, which is the same person; enforcement deliberately
  does not, because `User.current` is the anonymous user while a request is being authenticated.
- **`test/system/` cannot run in the development container** — aarch64, no browser, no root to install
  one. It is covered by CI instead: Redmine's own `Tests` workflow runs the system suite with Chrome,
  and it passes on this branch, so `test/system/api_key_copy_test.rb` — which asserts the markup of
  the API-key sidebar block the new link sits beside — **is** verified, just not locally. The block's
  markup was left byte-for-byte untouched regardless, and a functional test now pins the same
  selectors as a runnable proxy.
- **The JavaScript this branch adds is unverified by behaviour.** One handler exists — the scope
  radios on the token form expand the permissions fieldset — and with no browser here its test can
  only assert that the wiring is present and addresses the elements actually rendered. It is worth
  naming precisely because the server-side half of that same fix shipped first and was found to be
  only half a fix; the same class of gap could hide a second time. `toggleFieldset`, `checkAll`, the
  `data-confirm` dialogs, the CSV export modal and the copy-to-clipboard button are all in the same
  position: markup-verified, behaviour unverified locally.
- **`require_sudo_mode` is unverified locally.** Sudo mode is switched off in the development
  container, and turning it on means editing `config/configuration.yml`, which is shared with the
  instance a human is using. The three state-changing token actions declare it and the declaration
  was read in source; that it *prompts* has not been observed here.

### Administration

**Administration → Personal access tokens** lists every user's tokens — owner, name, created,
expiry, last use — with per-row revoke behind `require_sudo_mode`, paginated like the other admin
lists. It shows **no token value and no digest**: only digests are stored, so there is nothing there
for an administrator to read even by accident, and the screen does not create a second place where a
credential could leak.

**Administration → Settings → API** carries the lifetime ceiling described above.

Long-expired tokens are swept by `redmine:tokens:prune`, alongside the existing `Token` sweep. They
are kept for 30 days *after* expiry on purpose, so a user who finds a token stopped working can still
see why rather than finding it silently gone.

### What an adversarial pass changed

A red-team agent attacked a running instance rather than reading the diff, working from a ledger of
attacks that it also extends — `notes/ATTACKS.md`, which ships *beside* this repository rather than
inside it (see `REVIEW.md`). Ten hypotheses, two landed, and both were weaknesses this feature
*introduces* rather than inherits:

- **A token could be traded up for the permanent API key.** `GET /my/account.json` returns the
  user's `api_key` unconditionally, so a credential that expires and can be revoked bought one that
  does neither — and works on the `?key=` transport tokens refuse. Fixed: a request authenticated by
  a token no longer sees `api_key` in either `my/account` or `users/show`. The underlying
  unconditional disclosure to OAuth callers is pre-existing and stays as issue #12.
- **A token pasted into `?key=` was written to the log in cleartext.** It does not authenticate
  there — but the logged value is still live via the header, so a user's mistake leaked a working
  credential. Fixed by adding `:key` to `config.filter_parameters`, which also closes the
  pre-existing leak of the API key and the Atom key (issue #11).

The defences that held are recorded too, because that inventory is what makes the next run smarter:
name output is escaped at every sink, strong parameters reject injected `user_id`/`token_digest`,
cross-user revoke is scoped to the caller, every unintended transport is refused, CSRF is enforced,
and enumeration is infeasible against a 16^40 keyspace.

### What a user-interface pass changed

The red team asks whether a screen can be *abused*. It never asks whether a screen can be *reached*,
and that turned out to be the larger gap: a human opened the audit log and found, in minutes, two
defects that four automated gates had passed. So a second adversarial agent was written —
`ui-verifier`, with its own ledger at `notes/UI-CHECKS.md`, beside this repository rather than inside it.

It checks three properties for every affordance the branch adds: **reachable** by the users entitled
to it, **wired** to a route that does what the control implies, and **honest** in what its labels,
flashes and confirmations claim. Four design choices in it are worth stating, because each rejects
the more obvious alternative:

- **The inventory is derived from the diff, never handed over.** The agent is told a commit range and
  nothing else. A list of screens to check can only contain what somebody already thought of.
- **Create-then-find, not route reachability.** The obvious design — "every new route must be linked
  from somewhere" — *passes this branch*: `/api_audit_events` is linked from the administration menu,
  and the unreachable thing was a saved *query*. So the agent performs each create affordance and
  re-crawls, requiring the artifact to be discoverable afterwards. That round trip is what caught it.
- **Persona × surface × setting state, with four probes each.** Rendered-for-entitled,
  hidden-from-unentitled, **enforced**-against-unentitled, and enforced-across-ownership. The third
  matters most: hiding a link is not authorization, so every discovered URL is re-requested as every
  other persona. Ownership is a separate axis from role — two non-admin users, because a role-only
  matrix passes "A must not see B's token" trivially.
- **No allowlist.** Deliberate asymmetries are reported with their in-code evidence and marked
  `intentional?` for a human to rule on once. A suppression list rots silently and turns a verifier
  into a rubber stamp.

Across two blind runs it found thirteen defects. The first run caught both of the human's findings
plus five nobody had seen, including an administration screen that stayed reachable by URL while its
link was hidden — and, by measuring the precedent a decision log *cited*, proved that decision's
justification false: the entry claimed the open route was inherited from Redmine's OAuth screens, and
those screens return 403 on the same setting. That reversed the fix.

The second run, against the fixed branch, is the one that earned the exercise. Three of its five
findings were consequences of the first round's fixes — a scope fix that was server-side only, an
administration screen left silent about the state it was deliberately kept open for, and **a
regression test of mine whose assertion could not fail**, one commit after criticising exactly that
pattern in somebody else's test. A fix is a new surface, and re-running the verifier against fixed
code is what surfaces that.

What it cannot see is stated in its own ledger and repeated here: there is no browser in this
container, so anything JavaScript-only is verified by the presence of its wiring and not by its
behaviour; `require_sudo_mode` could not be exercised because sudo mode is off in the development
container; and visual layout, accessibility and non-English locales were not judged at all.

### Why the query parameter is refused

The existing API key authenticates three ways, including `?key=`. PATs support only two, and that is
the one place where this branch is deliberately stricter than what it sits beside.

Redmine adds only `:password` to `config.filter_parameters`, so a credential in the query string is
written to the application log in cleartext — reproduced here, not hypothesised. Adding `:key` to that
list would clean Rails' own log and nothing else: not the access log of any proxy in front of it, not
`Referer` headers, not browser history, not shell history. A credential that must never appear in a
URL cannot be safely accepted from one, so the transport is refused rather than half-mitigated. The
legacy key keeps all three transports; nothing existing was taken away.

## Token scopes (issue #5, ticket pillar #2)

**Pillar #2 of the ticket has four bullets, and one of them is built here.** It asks for tokens
"restricted to a subset of the user's permissions, e.g. read-only" — which is what this does, reusing
the OAuth2 scope mechanism the ticket names rather than inventing a second authorisation system
beside the one already in the tree. It also asks for scoping by **specific trackers**, for limiting a
token to **specific projects**, and for **administrators defining which scopes are available
globally**. None of those three is implemented; each is an open issue with the reasoning, and they
are listed again under the limits below.

**The creation form offers three things.** *Read-only* (the default), *Full access*, and *Custom*
with a permission picker grouped by project module, the same grouping the roles screen uses. What is
stored is always the **resolved permission list**, never the name of the preset, so a token issued
from the read-only preset cannot silently widen later because a plugin registered a new read
permission. `NULL` means no scope at all — which is what every token issued before this feature has,
and it means unrestricted.

**Enforcement is Redmine's, not ours.** `PersonalAccessToken.authenticate` stamps the token's
permission list onto the `User` object for that request only — never persisted, exactly like
`oauth_scope` — and `User#allowed_to?` hands it to `role.allowed_to?(action, scope)`, where
`Role#allowed_permissions` intersects it with what the role actually grants. `User#admin?` consults
it too, the way it already did for OAuth: without `:admin` in the scope, an administrator's token is
not an administrator's. Those are the three places a scope is consulted: `User#admin?` and the two
`role.allowed_to?(action, scope)` call sites in `User#allowed_to?`.

The choices worth defending:

- **A separate ivar, not `oauth_scope`.** Reusing `oauth_scope` would have been two lines shorter and
  would have made `authorized_by_oauth?` true for token requests — and `authorized_by_oauth?` is what
  `users/show.api.rsb` uses to decide whether to disclose the API key. Overloading it would have made
  a security decision as a side effect of a naming convenience. `User#request_permission_scope`
  returns whichever of the two applies; OAuth's behaviour is byte-for-byte unchanged.
- **Intersection, never union.** A scope cannot grant. The check runs against the owner's roles at
  request time, so a token naming `:delete_issues` for an owner whose role lost that permission
  yesterday gets nothing. Proved with a test that removes the permission from the role and then asks.
- **A create request that names no scope gets the form's default, not full access.** The radio is
  always posted by the form, so this only happens to a hand-built submission — which is exactly the
  case that must not be read as asking for the widest credential there is. `MyController` fills in
  `PersonalAccessToken::DEFAULT_SCOPE_PRESET`, so stripping the radio out of the form produces the
  same token the untouched form would. Assigning nothing at all *in code* is still unrestricted,
  because that is what every token issued before scopes existed has, but no request can reach that
  state. A preset that is not one of the three is refused rather than treated as "custom".
- **`NULL` is unrestricted, `[]` is nothing.** These are opposite meanings and Rails' `blank?`
  collapses them: `Role#allowed_permissions` reads a blank scope as unrestricted, so an empty list
  would **fail open**. It is refused by a model validation, and refused again in `User#allowed_to?`
  in case one ever reaches there. Verified by deleting the second guard and watching the test fail.
- **The scope is fixed at issue time.** There is no edit path, and `attr_readonly :permissions` makes
  that structural rather than a property of which controller actions happen to exist. Raising the
  scope of a token already in the wild is the same escalation as issuing an over-wide one.
- **The stored column is never parsed as YAML.** It uses a custom coder that scans for symbol names
  with a regular expression, copied from `Role::PermissionsAttributeCoder` for exactly this reason —
  Redmine whitelists permitted YAML classes in `config/application.rb` because a serialized column is
  a deserialization sink. The one deliberate difference from Role's coder is that `nil` round-trips
  as `nil` instead of `[]`, because for a token those two mean opposite things.
- **The read-only preset is not `Redmine::AccessControl`'s `read?` flag.** That flag means "still
  allowed while the project is closed", which is not the same thing: `close_project` and
  `delete_project` are both flagged `read` so that a closed project can be reopened or removed. A
  preset built straight from the flag would have handed a read-only token the power to delete the
  project it could read. The two are excluded by name and a test pins the exclusion.
- **The scope survives `X-Redmine-Switch-User`.** Impersonation loads a fresh `User` record, and a
  per-request property recorded on the old object is silently dropped — that bug already happened
  once in this branch, to the flag that hides the API key. Verified the same way: by deleting the
  carry-over line and watching the impersonated request perform a write its scope forbids.

### The limits of scopes, measured

- **Authorisation is scoped; visibility is not.** `Project.allowed_to_condition`
  (`app/models/project.rb:211` and `:225`) calls `role.allowed_to?(permission)` with no scope, and
  every `visible` scope in Redmine is built on it. So a controller action gated by `authorize` is
  scoped and a listing action gated by visibility alone is not: `GET /projects/1.json` is refused to
  a token whose scope omits `:view_project`, while `GET /projects.json` still lists projects.
  Redmine's own OAuth2 scoping is porous in exactly the same place — this inherits the hole rather
  than introducing it, and fixing it would change existing OAuth behaviour, which is a different
  change from this one. Pinned by `test_scope_010_a_listing_gated_only_by_visibility_ignores_the_scope`
  so that it is a stated cost rather than a surprise.
- **Endpoints that ask no permission are outside the vocabulary.** The audit of every controller
  declaring `accept_api_auth` found exactly three writes gated by nothing stronger than
  `require_login`: `PUT /my/account`, and `PATCH`/`DELETE` on an attachment uploaded via `POST
  /uploads` and not yet attached to anything (where the check degrades to "are you the author"). The
  account one is a password-reset pivot — a token that could rewrite its owner's email address could
  take the account — so a **scoped** token is refused it outright: a scope is written in permission
  names, no permission means "edit your own account", and something no scope can name should not be
  granted by default. Unscoped tokens and the legacy API key are unaffected. The attachment case is
  left as a stated limit; it reaches only the caller's own orphaned upload.
- **A scope narrows what you may do, not what a response contains.** Nothing here filters fields out
  of a representation the caller was allowed to fetch.
- **Reference data is readable by any API credential.** `require_admin_or_api_request` returns true
  for every API request, so `/trackers.json`, `/issue_statuses.json`, `/roles.json` and the
  enumerations answer a read-only token. That predates this branch and is unchanged by it.
- **Tokens authenticate HTML too, and the scope goes with them.** An earlier draft of this file said
  scopes reach the API only, because a token authenticates only an `api_request?`. That was wrong,
  and worth correcting rather than quietly deleting: `find_current_user` gates the token on
  `accept_api_auth?`, which has no format check at all, so `GET /my/account` as **HTML** with a token
  answers `200` where anonymous is redirected to the sign-in page. No credential is disclosed through
  that path — the API key is hidden from token-authenticated requests wherever it is rendered — and
  the scope narrows there at the same enforcement points, which is now pinned by
  `test_scope_006_an_html_action_that_accepts_api_auth_is_still_narrowed` rather than assumed. Atom
  is a separate path (`accept_atom_auth`) and tokens do not authenticate it.
- **Three quarters of ticket pillar #2 is not built.** The ticket asks for four things and this
  implements one of them. Scoping a token to **specific trackers** is issue #17; limiting a token to
  **specific projects** is #18; letting **administrators define which scopes are available globally**
  is #19. The first two are a different shape of restriction from a permission list — they narrow
  *which records* rather than *which verbs*, so they belong at `Project.allowed_to_condition` and in
  the query scopes, which is where this design is deliberately porous (the first limit above). The
  third is an administration screen over a vocabulary that is currently `Redmine::AccessControl`'s
  whole permission list. Each is an open, labelled issue rather than a sentence here.
- **The legacy `api_key` is unscoped and unchanged**, on all three of its transports.

## Cross-origin resource sharing (issue #8, ticket pillar #6)

A personal access token is only useful to a browser application if the browser is allowed to read the
response, so CORS is the pillar that pairs most naturally with the core. **Administration → Settings →
API → "Allowed origins for cross-origin API requests"** takes a comma-separated list; empty — the
default — allows nothing.

How it works, and the four choices worth defending:

- **A controller filter, not middleware.** `ApplicationController#set_cors_headers` runs inside the
  request Redmine has already classified, so it can reuse `Setting.rest_api_enabled?` and Redmine's own
  notion of an API request rather than re-deriving "is this an API call" from the path. It is
  *prepended*, so it runs before every other filter: a filter that renders halts the chain, and three
  of the refusals a browser client most needs to read — a revoked OAuth token, HTTP Basic while 2FA is
  active, and a password that must be changed — are rendered inside `user_setup` itself. Running after
  `user_setup` would have missed exactly those. The cost of prepending is that `Setting.check_cache`
  has not run yet, so the filter calls it itself; otherwise removing an origin would only take effect
  on the request *after* next. The only exception to all this is the preflight, which has no route to
  run a filter on: `OPTIONS` on a `.json`/`.xml` path goes to a catch-all route and `CorsController`.
- **Scoped by the route, not by `?format=`.** Redmine's `api_request?` reads `params[:format]`, and a
  caller can set that with a query parameter on *any* route — `/attachments/download/1?format=json`
  answers with the raw file bytes. Using it here would have let the caller, rather than the route
  table, decide which responses the policy covers. The filter therefore tests
  `request.path_parameters[:format]`, which routing writes from the path extension and which no query
  string can reach. `api_request?` itself is deliberately left alone: it is pre-existing behaviour
  shared with the CSRF skip and the authentication path.
- **Echoed, never wildcarded, and never with credentials.** `Access-Control-Allow-Credentials` is
  never sent, at all. That is what makes echoing the origin safe: a cross-origin caller cannot use the
  session cookie, so it must present an API key or a personal access token in a header — which is
  exactly the credential this branch added. Wildcards are not accepted in the setting either; `*`
  typed into the box allows nothing rather than everything.
- **Exact matching.** Scheme, host and port must all agree. Configured values are tidied (whitespace,
  a trailing slash, letter case); the `Origin` that arrives on the wire is compared as it stands,
  because a browser always serialises it canonically and anything else did not come from one.
  `null` can never be allowed, even if an administrator types it in.
- **`Vary: Origin` on every API response while the feature is on** — including responses to origins
  that are *not* allowed, and to requests with no `Origin` at all. Otherwise a shared cache could
  store a headerless response and replay it to an allowed origin, or the reverse. Note that a refused
  origin does get `Vary: Origin`; what it never gets is any `Access-Control-*` header.
- **`Access-Control-Expose-Headers: Location`.** Creating an issue or a project answers `201` with the
  new URL in `Location` and nothing else, and a browser will not let a script read that header unless
  it is named here. Without it the create flow — a large part of why a browser client wants the REST
  API at all — is only half usable. The list is fixed, like the allowed methods and headers: nothing
  is reflected from the request.

The preflight answers identically for every path — `204`, empty body, same headers — so it cannot be
used to enumerate which resources exist or which ones the caller could read. It asserts nothing about
authorisation; the real request that follows is authenticated exactly as before.

**Limits of the CORS slice**, named rather than buried:

- **Hand-rolled rather than `rack-cors`.** The gem is not in the `Gemfile` and adding a dependency to
  a slice this size needs a better reason than convenience. The honest cost is that its well-tested
  edge cases — `null`, preflight, `Vary` — are reimplemented here; they are covered by tests, which is
  not the same as a decade of production use.
- **One allowlist for the whole API.** No per-endpoint or per-origin method restriction. The allowed
  methods and request headers are a fixed list, not reflected from the preflight request.
- **Only controllers that inherit `ApplicationController`.** The Doorkeeper OAuth endpoints do not,
  so a browser-based OAuth flow is not covered by this setting.
- **`jsonp_enabled` is untouched.** It predates this work and, when switched on, already lets any
  origin read `GET` responses through a script tag — a wider hole than this setting can open. It is
  off by default and was left alone rather than quietly changed.
- **Removing an origin is not instant** for a browser that has cached a preflight: `Access-Control-Max-Age`
  is 600 seconds. The actual request is re-checked every time, so a removed origin loses read access
  immediately; only the preflight is stale.
- **Responses produced outside the controller carry no CORS headers at all** — a routing `404` for a
  path that matches nothing, the `400` for a malformed JSON body, the `406` from `UnknownFormat`. They
  are built by the exception app, which never runs a controller filter, so a browser client sees an
  opaque network error rather than the status. This is the price of choosing a controller filter over
  Rack middleware, taken knowingly: middleware would cover them but would have to re-derive "is this
  an API request" from the raw path, duplicating routing. Nothing is leaked by it — a response with no
  `Access-Control-Allow-Origin` is simply unreadable — but the diagnostics are worse.
- **The preflight is an allowlist oracle.** `OPTIONS /anything.json` answers `204` for a configured
  origin and `404` for any other, with no credential required, so anyone can test whether a domain is
  on the list. This is inherent to CORS — the same signal leaks from the presence or absence of
  `Access-Control-Allow-Origin` on a normal response — and it discloses nothing about resources, only
  about the policy. Accepted rather than fixed. (Rate limiting, the usual mitigation, is explicitly out
  of scope for this exercise.)
- **A plugin cannot answer `OPTIONS` on a `.json` or `.xml` path.** The preflight catch-all is a glob,
  and although it is now drawn *after* the plugin routes loop so that a plugin route defined there wins,
  a plugin that draws its routes some other way, or any future route added below it in
  `config/routes.rb`, would be shadowed for `OPTIONS`. `test/integration/routing/cors_test.rb` fails if
  the glob stops being the last route drawn.
- **A malformed origin is dropped silently.** `app.example.com` with no scheme, or a space-separated
  rather than comma-separated list, parses to nothing: the setting is saved, the screen shows what was
  typed, and the feature is inert. It fails closed, which is the right direction, but an administrator
  gets no feedback that the value was rejected. Validating the field on save and reporting the rejected
  entries is the fix and is not done here.

## Granular API endpoint control (issue #7, ticket pillar #5)

`rest_api_enabled` is all-or-nothing: either every REST endpoint is reachable with a credential, or
none is. **Administration → Settings → API → "Available API endpoints"** breaks that into one
checkbox per endpoint — 81 of them across 24 controllers — grouped by controller in the same fieldset
layout as the roles permission screen. Unchecking one makes it answer `403` to API callers while
leaving the HTML pages a human browses untouched.

**Read this before switching anything off.** Disabling a *read* endpoint does **not** stop the same
data being read, because Redmine serves much of it a second time through `.atom` feeds, which are a
separate authentication path this setting does not cover. With `issues#index`, `issues#show`,
`projects#index`, `news#index` and `timelog#index` all disabled, the red team read every one of them
back through its feed — with an atom key, with an API key, and, for public projects, **with no
credential at all**. So this feature restricts *the REST API*; it is not a read-exfiltration control,
and treating it as one would be a mistake an administrator could reasonably make from the screen's
wording alone. Gating feeds too was rejected deliberately: an atom key is the credential ordinary feed
subscribers already hold, their reader would break with no diagnosis, and the same URL would then be
served or refused depending on which credential it carried. The write endpoints, which have no feed,
are fully covered.

Five choices worth defending:

- **The vocabulary is `accept_api_auth`, not a new registry.** Redmine already enumerates its API
  surface: `accept_api_auth :index, :show, :create, …` in each controller, backed by the
  `accept_api_auth_actions` class attribute, and `accept_api_auth?` is already consulted on every
  request in `find_current_user`. An endpoint here is exactly that controller/action pair, written
  `"issues#index"`. Nothing in the codebase enumerated the declarations before, so
  `Redmine::ApiEndpoints.grouped` walks `ApplicationController.descendants` after
  `Rails.application.eager_load!` — the same technique `Redmine::SubclassFactory` uses. Inventing a
  second list of "what the API is" would have guaranteed the two drifting apart.
- **The setting stores what is *disabled*, never what is enabled.** An endpoint the setting has never
  seen — a plugin's, or one a later Redmine version adds — is therefore available, and an upgrade
  cannot silently break a running integration. That is a structural property, not a default value:
  there is no configuration in which an unknown endpoint is refused. The admin checkbox still reads as
  "enabled" (checked = available, as on the roles screen); the inversion happens in
  `Setting.rest_api_disabled_endpoints_from_params`, and the hidden companion field is what carries
  the "disabled" value for an unchecked box.
- **The gate is wider than `api_request?`, deliberately.** `accept_api_auth?` has **no format check**,
  so a credential in a header authenticates an `accept_api_auth` action even when the request asks for
  HTML: `GET /my/account` with `X-Redmine-API-Key` answers `200` where an anonymous browser is
  redirected to the login form. A gate written as "only when `api_request?`" would have left that path
  open — and `.csv` too. `ApplicationController#check_api_endpoint_enabled` therefore fires when the
  request asks for an API representation **or** when an API credential is what authenticated it, which
  it learns from a flag set in `find_current_user`. A human with a session cookie never enters that
  branch, so **HTML pages** render exactly as before even when the same request also carries an API
  key. What that does *not* mean: a session request for `/issues.json` **is** refused when
  `issues#index` is disabled, because `api_request?` alone satisfies the condition — the JSON
  representation is the API, however it authenticated. No stock UI path breaks (Redmine's own XHR goes
  through `auto_completes` and filter endpoints, which declare no `accept_api_auth`), but a plugin or
  a script that fetches a disabled endpoint's JSON with a session cookie will be refused.
- **The refusal is a bare `403` with an empty body on every format.** That is `render_error` minus its
  `format.html` branch, and the subtraction is the point: `render_error` answers an HTML request with a
  full error page naming the reason, so the very path this gate exists to cover — HTML plus a header
  credential — would have leaked what a `.json` caller is not told. What is left is byte-for-byte what
  `require_login` already answers when `rest_api_enabled` is off, content type included, and the reason
  goes to the application log for the administrator instead. The filter is declared in
  `ApplicationController` after `user_setup` and `check_if_login_required` and before every filter a
  subclass declares, so a disabled write never reaches the action: `POST /issues.json` against a
  disabled `issues#create` creates nothing.
- **Nothing a form posts can name something that is not an endpoint.** The posted list is intersected
  with the enumeration from the code, so `Kernel#system` simply is not stored, and enforcement is a
  string `include?` — no `constantize`, no `send`, no route lookup anywhere in the path. The
  intersection alone was a fail-open, though, and that had to be fixed: the screen only shows what the
  enumeration lists, so it can only post that back, and an entry the walk stopped seeing — a plugin
  whose controller failed to load — was silently dropped and thereby *re-enabled*. Stored entries the
  enumeration cannot see are now carried over instead, and the carry is written to the log, because a
  screen that does not show every stored value should not also keep that quiet.

**How it interacts with token scopes.** They are independent narrowings and neither can widen the
other. A scope says *which permissions* a credential carries; the endpoint gate says *which actions
the API answers at all*. The gate runs first, before authorisation, and applies to every credential —
API key, personal access token, OAuth bearer, HTTP Basic, and after `X-Redmine-Switch-User` — with no
exemption for administrators. So a disabled endpoint refuses an unscoped admin token exactly as it
refuses a read-only one, and enabling an endpoint grants nobody a permission they did not have.

**An administrator cannot lock themselves out.** The screen that re-enables endpoints is
`SettingsController`, which declares no `accept_api_auth` — so it is not in the enumeration and
`check_api_endpoint_enabled` returns before doing anything for it. Disabling all 81 endpoints leaves
the settings screen working; there is no configuration in which it does not.

Limits, stated rather than left to be discovered:

- **`.atom` feeds are not covered**, which is the limit that most changes what the feature is worth —
  see the paragraph at the top of this section. Neither are the Doorkeeper OAuth token endpoints,
  which do not inherit `ApplicationController`, nor `sys_controller` and `mail_handler_controller`,
  which authenticate against their own shared-secret settings rather than a `Token` and have their own
  enable flags.
- **The grain is the controller action, not the HTTP method, the project or the record.**
  `issues#update` covers `PUT` and `PATCH` together because they are the same action; disabling
  `issues#index` disables it for every project; and nothing here can say "this endpoint, but only for
  these issues". Per-method, per-project and per-record control would each need a different key.
- **A credential holder can still map the configuration, and so, on a common setup, can a stranger.**
  A caller who *would* have been served can tell `403` from `200`, which is inherent: an endpoint that
  is off has to behave differently from one that is on. What is *not* inherent, and was originally
  claimed as defended when it is not: with `login_required` off — the default, and a common
  configuration for a public tracker — an **anonymous** caller reaches the gate too, so a disabled
  endpoint answers `403` where an enabled one answers `401` (needs authentication) or `200` (public).
  All 81 endpoints are therefore mappable with **no credential at all**. Only `login_required` closes
  that, by refusing the anonymous request before the gate can say anything. The information disclosed
  is the administrator's configuration, not data, but it is disclosed.
- **Disabling a whole controller group silently gains members later.** The `<fieldset>` per controller
  is a UI convenience — the "toggle all" link ticks the boxes that exist when the page is rendered, and
  what is stored is those endpoint names, one by one. There is no stored notion of "all of
  `issues`". So a plugin that adds `issues#some_new_action`, or a Redmine upgrade that does, lands
  **enabled** inside a group an administrator believes they switched off. That is the direct cost of
  the "unknown means enabled" rule, and the two really are in tension: storing groups would honour the
  administrator's evident intent, and would also mean an upgrade could disable an endpoint nobody chose
  to disable, silently breaking a working integration. The rule was kept because a feature that removes
  API surface must fail towards *available*, and because the failure it prevents is invisible to the
  administrator while this one is at least visible on the screen — every endpoint is listed with its
  own checkbox, so an unticked group with a new ticked member shows as exactly that. It stays a real
  limit, not a settled argument.
- **A disabled endpoint is still advertised.** Nothing removes it from the routes, from the API
  documentation, or from any UI that links to it; the enforcement is server-side only, which is the
  right way round, but a client discovers the restriction by being refused.
- **The list is only as accurate as `accept_api_auth`.** An action that is reachable with an API
  credential without declaring it — there are none in core, because the declaration is what makes it
  reachable — would not appear on the screen and could not be disabled.
- **Rendering the settings screen eager-loads the application.** `common/_tabs.html.erb` renders every
  tab's partial on every settings page, so enumerating the endpoints happens on any `GET /settings`,
  not just the API tab. The cost is not the problem (0.72 s cold, 20 µs warm, and in production Rails
  has eager-loaded at boot already); the exposure is that a load error anywhere under `app/`, `lib/` or
  a plugin would have taken down the one screen an administrator would use to undo it. So the walk
  rescues, logs, and enumerates whatever did load — and because unseen stored entries are now carried
  over rather than dropped, a degraded walk cannot re-enable anything either.
- **No audit of the refusals.** They are logged at info level with the endpoint name; there is no
  structured record of who was refused what. That is pillar #4, issue #6, and is not built.

### Endpoint control, against a running server

Unedited, with `issues#index` and `my#account` unchecked. The credential is read into a shell variable
and never printed — the point of running this by hand is the fourth and sixth blocks, which no test
would have shown as plainly.

```console
### 1. an enabled endpoint, unchanged
GET /news.json           X-Redmine-API-Key    -> HTTP 200  49 bytes  application/json; charset=utf-8

### 2. a disabled endpoint, every format -- bare 403, empty body
GET /issues.json         X-Redmine-API-Key    -> HTTP 403  0 bytes  application/json
GET /issues.xml          X-Redmine-API-Key    -> HTTP 403  0 bytes  application/xml
GET /my/account (HTML)   X-Redmine-API-Key    -> HTTP 403  0 bytes  */*

### 3. the same request with the whole REST API switched off
GET /issues.json         X-Redmine-API-Key    -> HTTP 403  0 bytes  application/json

### 4. Atom is a separate read path and is NOT gated (a limit, not a bug)
GET /issues.atom?key=<atom key>               -> HTTP 200  2541 bytes  application/atom+xml; charset=utf-8
GET /issues.atom?key=<api key>                -> HTTP 200  2541 bytes  application/atom+xml; charset=utf-8
GET /issues.atom            (no credential)   -> HTTP 200  2496 bytes  application/atom+xml; charset=utf-8

### 5. the HTML interface is untouched
GET /issues                 (no credential)   -> HTTP 200  35467 bytes  text/html; charset=utf-8

### 6. the configuration oracle, anonymous, login_required off
GET /issues.json  disabled        (no cred.)  -> HTTP 403  0 bytes  application/json
GET /users.json   enabled, private (no cred.) -> HTTP 401  0 bytes  application/json
GET /news.json    enabled, public  (no cred.) -> HTTP 200  49 bytes  application/json; charset=utf-8
```

Block 2 is what the manual pass was for. Before this round the third line answered `403` with a
**7,804-byte HTML page** saying the endpoint had been disabled by the administrator, while this file
asserted the opposite; block 3 is the baseline it now matches byte for byte. Every enforcement test
runs through the real Rack stack, and none of them caught it, because they compared the `.json` path
only.

## Structured API audit logging (issue #6, ticket pillar #4)

Redmine records API activity only in the Rails log, as unstructured lines mixed in with everything
else.

Pillar #4 of the ticket has **three** bullets, and this implements **two** of them:

| ticket bullet, quoted | here |
|---|---|
| "**Log all API calls** in a dedicated, queryable format (not just standard application logs): token used, endpoint, HTTP method, source IP, timestamp, response status" | **done** — a table with exactly those columns plus the acting and impersonating identities, a `Query` subclass over it, a level setting, a retention setting and a prune task |
| "Provide an admin UI **or API** to query and export audit logs" | **done as the UI half** — Administration → API audit log, with filters, sorting, pagination and CSV export. The API half is deliberately *not* built; see the limits below |
| "Enable **notifications** for anomalous activity: excessive request volume, requests from unknown IPs, repeated authentication failures" | **not built** — issue **#20**, and see [the limits below](#limits-of-the-audit-log) |

**Administration → API audit log** lists what was recorded. **Administration → Settings → API**
carries the two settings that govern it.

### What a row holds, and what it deliberately does not

| column | value |
|---|---|
| `created_on` | when |
| `user_id`, `login` | who the request acted **as** |
| `impersonator_id`, `impersonator_login` | who actually held the credential, when `X-Redmine-Switch-User` was used |
| `credential_type` | `api_key`, `personal_access_token`, `oauth` or `http_basic` |
| `personal_access_token_id` | **which token**, by id — including when the token was *refused*, so an authentication failure names the credential that failed. Empty only when the value matched no token at all (an unknown value, or one already revoked), where there is no id to record |
| `http_method`, `endpoint`, `path` | what was called — `issues#create`, `POST`, `/issues.json` |
| `ip` | where from |
| `status` | what came back |

**No credential value is stored, and the query string is not stored either.** Only
`request.path` is kept, never `request.fullpath`, because `?key=` is a supported transport for the
legacy API key and an audit table full of live keys would be the softest place in the installation to
steal every one of them at once. A personal access token is referenced by its id; its value exists
nowhere but the caller's own keeping, and only a digest of it is stored, in a different table.

The login is stored **beside** the user id rather than only as a foreign key, so the row still names
who acted after the account is deleted — which is exactly what somebody covering their tracks would
do next. There are no foreign keys and no `dependent:` options anywhere near this table.

### The level setting, and why the default is not "everything"

Volume decides this feature's shape. A fifty-person team with one polling client each is on the order
of 72k API requests a day, 90–95% of them polling `GET`s; a year at 20k/day is ~7.3M rows. Redmine's
own list pattern runs `COUNT(*)` on every page view, so the count degrades before the row fetch does.

Three levels:

| level | records |
|---|---|
| **Off** | nothing |
| **Writes and refused requests** (default) | every non-`GET`/`HEAD`/`OPTIONS` call, every `401`/`403`/`412`, and every request that offered an API credential which did not authenticate |
| **Every API request** | all of it |

The default cuts the volume by an order of magnitude and loses nothing an audit trail is for: "who
changed what, and who tried to get in", never "who polled the issue list".

The third clause of the default level is the one worth arguing for. Status alone is not a sufficient
definition of "authentication failure": an **HTML** request carrying a bad API key is answered with a
`302` to the login form, which no list of refusal statuses can tell apart from the redirect after a
successful write. So a credential that was offered and rejected is recorded whatever status followed.
Line 4 of the transcript below is that case, observed against a running server.

### Where it hooks, and why not an `after_action`

The recorder is called from an `ensure` around `ApplicationController#process_action`, not from an
`after_action`. Rails **skips** `after_action` callbacks entirely when an earlier filter renders and
halts the chain — and the responses this log most needs are exactly those: the three refusals
rendered inside `user_setup` itself (a revoked OAuth token, HTTP Basic while 2FA is active, an
unchanged password), `require_login`'s `401`, and the endpoint gate's `403`. An `after_action` would
record every successful call and none of the authentication failures, which is the wrong half.

That is not an argument, it is a measurement. Replacing the `ensure` with an `after_action` and
re-running the file **fails 12 of its 27 tests** (10 failures, 2 errors), including every
authentication-failure case: the `401` for a rejected key, the `412` for a refused
`X-Redmine-Switch-User`, and all three of the refusals rendered inside `user_setup` — HTTP Basic
while 2FA is active, a revoked OAuth token, and `must_change_password`. (It was 7 of 21 when the
feature was written; the two 2FA and OAuth cases were added in fix round 1, since only
`must_change_password` had been pinned and one of three passing does not prove the other two.) The
`ensure` was then restored.

Two consequences follow from the same choice and are stated rather than hidden:

- The recorder also runs when the action raises. The status is then taken from the exception the same
  way Rails' own exception middleware takes it, rather than from the response, which still holds its
  default at that point.
- **Nothing outside a controller is recorded.** A routing `404`, a malformed JSON body's `400` and
  the Doorkeeper OAuth token endpoints (which do not inherit `ApplicationController`) never reach it.

### Reliability

`Redmine::ApiAudit.record` wraps everything in one `rescue` that logs and returns nil. An audit trail
that can take the product down is a denial of service with good intentions. Pinned by a test that
makes the insert raise and asserts the `POST` still answers `201` and the issue still exists.

With the level off, the first thing the recorder does is read one memoised setting and return. That
is the cheap case and it is *not* the shipped one — the default is `writes`, and the cost of the
default is measured in the limits below rather than left as "negligible when off".

### Retention, and the anti-forensics question

`redmine:api_audit:prune` deletes events older than the configured retention (90 days by default; `0`
keeps them forever). It sits next to `redmine:tokens:prune`, and like it, **nothing schedules it for
you**.

Pruning is **by age, never by count**. That is the whole answer to "can an attacker flood the log to
push earlier evidence out of it": a flood costs disk, but a "keep the newest N rows" policy is what
would let it erase anything, and this is not one. Pinned by
`test_audit_003_prune_should_remove_by_age_so_a_flood_cannot_evict_earlier_evidence`, which writes
one old row, floods 50 newer ones, prunes, and asserts the old row is still there.

What is **accepted**: an unauthenticated caller can still make the table grow — one row per
`GET /issues.json` with `Authorization: Basic <garbage>`, no account needed — because refused
requests are recorded at the default level and that is the point of recording them. Rate limiting is
excluded from this exercise by the brief, so nothing here throttles that. Stated at length in the
limits below, because it is the property of this feature most likely to be met first in production.

### Querying it

`ApiAuditQuery` is a `Query` subclass, so filters, column selection, sorting, pagination and CSV
export all come from machinery Redmine already has and already tests — the same route `UserQuery`
takes for the administration user list. Filters: time, login, impersonator, credential type, method,
endpoint, path, status, IP. The export is capped by `issues_export_limit`, like every other export.

**The default view is time-windowed to 7 days.** This is the one table in the installation that grows
without an upper bound, and the screen's `COUNT(*)` is what degrades first. The window is a real
default filter on the query, not a view accident, and it can be widened or removed from the filter
form like any other.

Administrators only, in both directions: `require_admin` on the controller, and `ApiAuditQuery.visible`
returns nothing to anybody else so a saved query cannot be borrowed.

### Limits of the audit log

- **No REST endpoint for the log itself**, deliberately. The ticket asks for "an admin UI **or** API",
  so the UI satisfies the bullet — but the API half is a real thing not built, and it is named here
  rather than left implied by the word "or". It is self-referential — reading the log would be an API
  call the log records — and it concentrates who-did-what for every user in the installation, which
  deserves its own decision rather than arriving as a side effect of this one.
  `/api_audit_events.json` and `.xml` are refused by a route constraint, so that is a fact rather
  than an omission. Pinned by `test/integration/routing/api_audit_events_test.rb`.
- **No anomaly detection and no notifications** — the third bullet of ticket pillar #4, tracked as
  issue **#20**. The ticket asks for alerts on "excessive request volume, requests from unknown IPs,
  repeated authentication failures": four separate detections, each needing a threshold, a window, a
  notification channel and an answer to alert fatigue, and the first of them overlaps the rate
  limiting the brief excludes from this exercise. What is here is the *substrate* for them — every
  one of those detections is a query over `api_audit_events` rather than new instrumentation — but
  the detections themselves are not built, and nothing in this branch notices an anomaly or tells
  anybody about one. Reading the log is a thing an administrator has to decide to do.
- **HTML pages browsed with a session cookie are not recorded at all.** Redmine has no audit trail
  for the web interface and this does not add one. The precise surface is narrower than "anything an
  API credential was offered to", and the boundary is worth stating exactly: a request is recorded
  when `api_request?` is true, **or** when an API credential authenticated it, **or** when a
  credential was offered on a path where Redmine would have *tried* it — that last one means
  `Setting.rest_api_enabled?` and the action declaring `accept_api_auth`. So `GET /my/account` (which
  declares it) with a bad key is recorded even as HTML; `GET /my/page` (which does not) with the same
  bad key is answered `302` as anonymous and recorded nowhere, because Redmine never looked at the
  header and there was no authentication attempt to fail. Widening the signal would mean recording an
  `Authorization` header the product ignored, on every HTML page in it. Both sides pinned by
  `test_a_credential_offered_to_an_action_that_does_not_accept_api_auth_is_not_recorded`.
- **Only what the request carried, not what it changed.** A row says `PUT /issues/1.json` returned
  `204`; it does not say which fields moved. Redmine's journals already record that for issues, and
  duplicating them here would be a different feature.
- **Response bodies, request bodies and query strings are never recorded.** Deliberate for the query
  string; the other two are a size decision.
- **The credential type is what the request offered when nothing authenticated.** A personal access
  token used as an HTTP Basic *username* is recorded as `personal_access_token` when it works,
  because the user object says so, but a *rejected* one is recorded as `http_basic`, because at that
  point the request is indistinguishable from a bad password.
- **The recorded IP is only as trustworthy as your proxy configuration.** `ip` is
  `request.remote_ip`, and Rails' `RemoteIp` middleware honours `X-Forwarded-For` when the immediate
  peer is a trusted proxy — and **loopback is trusted by default**. So on a direct-exposed
  installation, or from anything that reaches Redmine over loopback (a co-located process, an SSRF),
  `curl -H 'X-Forwarded-For: 1.2.3.4'` stores `1.2.3.4` as the source of the call. Behind a reverse
  proxy that *overwrites* `X-Forwarded-For` rather than appending to it, the value holds and is
  genuinely forensic. This column is therefore evidence about the network path, not an identity
  claim: read it with `config.action_dispatch.trusted_proxies` in hand. Recording the raw peer
  (`request.remote_addr`) alongside it in a second column would close the gap and is the obvious next
  change; it is not in this slice, and saying so is better than implying a guarantee the code does
  not make.
- **An unauthenticated caller can make the table grow, and this is the limit that will bite a real
  installation first.** With the REST API on, `GET /issues.json` plus `Authorization: Basic <garbage>`
  writes one audit row per request, at the default level, from a caller with no account and no
  credential — retained for 90 days. That is not a bug: recording refused requests is the entire
  point of the "authentication failures" half of the default level, and a log that stops recording
  under load is a log an attacker can switch off. But nothing here throttles it, because **rate
  limiting is excluded from this exercise by the brief**, and it is the one property of this feature
  that an operator should size disk for before switching it on. The mitigations that exist are
  retention (`rest_api_audit_retention_days`, 90 by default, swept by `redmine:api_audit:prune` which
  *nothing schedules for you*) and, if it becomes acute, the level setting. Pruning by age rather than
  by count means the flood costs disk but cannot evict earlier evidence. Pinned as a stated property
  by `test_an_unauthenticated_caller_writes_a_row_per_request_at_the_default_level`, so this
  paragraph cannot quietly stop being true.
- **CSV formula injection is neutralised in this export only.** A cell whose first character is `=`,
  `+`, `-`, `@`, tab or CR is prefixed with an apostrophe on the way out, so a spreadsheet reads it as
  text. This is a **correction**: the first version of this feature *accepted* the risk, on the
  argument that every exported column was bounded — and that argument was wrong, because it
  enumerated columns instead of naming provenance and simply omitted the one that mattered. The audit
  log has two user-controlled columns: `login`, which is stored as text so a row outlives the
  account, and `personal_access_token`, which renders `PersonalAccessToken#name` — validated for
  presence, length and uniqueness and **for no format at all**. So any user who could create a token
  could name it `=cmd|'/C calc'!A0` and wait for an administrator to open the exported log. The HTML
  screen was never affected (`content_tag` escapes it); only the CSV was raw. Two changes were
  possible and the narrower one was taken: neutralising this export touches nothing else, where
  changing `Redmine::Export::CSV` would alter every export in the product and validating token-name
  format would take away a freedom users already have to fix a problem that lives in the reader.
  **The limit that remains:** every other CSV export in Redmine is still injectable, and this branch
  does not change that. Pinned by `test_audit_005_a_token_name_should_not_inject_a_csv_formula`,
  `test_audit_005_the_export_should_neutralise_every_formula_prefix` and
  `test_audit_005_an_ordinary_cell_should_not_be_rewritten`, the first two proved by removing the
  neutraliser and watching them fail.
- **Turning the log off is not itself recorded**, because settings changes are not API calls. An
  administrator who can reach the settings screen can silence the log.
- **`rest_api_audit_level` defaults to on, so the shipped cost is not the off cost.** An upgrade
  starts writing rows without being asked to. That is deliberate — an audit trail nobody switched on
  records nothing on the day it is needed — but it means the honest number is the *default* one, and
  it was measured directly rather than inferred from suite wall-clock: **16 µs** added to a request
  the feature does not record, **0.4–0.9 ms** to one it does (a single `INSERT`), and **0.18 µs** for
  the `recording?` check itself, which reads a class-level memoised hash that `user_setup` has already
  warmed. An in-process A/B over 480 recorded requests came out below the noise floor on three of four
  workloads. *(An earlier note in this project claimed this commit made the test suite 3.2× slower.
  It did not: five runs of the same file with the same code took 174/136/97/106/126 s — a 1.8× spread
  caused by other agents on the host, not by this code. The claim is withdrawn, and it is recorded
  here rather than deleted because it was measurement error asserted as a finding.)*

### End to end, against a running server

Unedited output of a script run against an isolated instance on port 3005 with its own database. The
token is held in a shell variable and never echoed.

```console
$ sh audit_e2e.sh
=== level = writes (the default) ===
GET  /issues.json           (read, valid token)            HTTP 200   rows 0 -> 0
POST /issues.json           (write, valid token)           HTTP 201   rows 0 -> 1
GET  /users/current.json    (bad API key)                  HTTP 401   rows 1 -> 2
GET  /users/current         (bad key, HTML)                HTTP 302   rows 2 -> 3
POST /issues.json           (switch-user bob)              HTTP 201   rows 3 -> 4

=== what the log holds ===
created_on          login        impersonator credential             method endpoint               st
2026-08-13 05:30:22 audit_admin               personal_access_token  POST   issues#create          201
2026-08-13 05:30:26                           api_key                GET    users#show             401
2026-08-13 05:30:29                           api_key                GET    users#show             302
2026-08-13 05:30:33 audit_bob    audit_admin  personal_access_token  POST   issues#create          201

=== no credential value is anywhere in the table (AUDIT-R7) ===
token value present in the table:  false
token digest present in the table: false
token referenced by id:            [7]
any column holding a query string: false

=== the same read at level = all, and at level = off ===
GET  /issues.json           (level = all)                  HTTP 200   rows 4 -> 5
POST /issues.json           (level = off)                  HTTP 201   rows 5 -> 5

=== retention prunes by age, so a flood cannot evict earlier evidence ===
rows before prune: 5 (oldest 2026-01-25)
rows after  prune: 4 (oldest 2026-08-13)

=== the log is administrators only (AUDIT-R6) ===
GET  /api_audit_events      (as a non-administrator)       HTTP 403
GET  /api_audit_events      (as an administrator)          HTTP 200
GET  /api_audit_events.csv  (as an administrator)          HTTP 200
GET  /api_audit_events.json (no API representation)        HTTP 404

--- first lines of the CSV export ---
Time,Login,Impersonated by,Credential,Method,Endpoint,Response,IP address
08/13/2026 05:30 AM,audit_admin,"",Personal access token,GET,issues#index,200,127.0.0.1
08/13/2026 05:30 AM,audit_bob,audit_admin,Personal access token,POST,issues#create,201,127.0.0.1
08/13/2026 05:30 AM,"","",API key,GET,users#show,302,127.0.0.1
```

Line 1 is the level default doing its job — a read with a valid token costs no row. Line 4 is the
`302` case argued above: the HTML request carried a rejected credential and was recorded anyway. The
fifth row of the table is the impersonation requirement: `audit_bob` acted, `audit_admin` was the one
holding the token, and both are in the row.

## Running and verifying

```bash
bundle install
bundle exec rake generate_secret_token
bundle exec rake db:migrate
RAILS_ENV=test bundle exec rake db:migrate
bin/rails server -b 0.0.0.0 -p 3000
```

Tests for this slice:

```bash
bin/rails test test/unit/personal_access_token_test.rb
bin/rails test test/integration/api_test/personal_access_token_auth_test.rb
bin/rails test test/functional/my_controller_test.rb
bin/rails test test/integration/routing/my_test.rb
bin/rails test test/unit/lib/redmine/cors_test.rb
bin/rails test test/integration/api_test/cors_test.rb
bin/rails test test/integration/routing/cors_test.rb
bin/rails test test/unit/api_audit_event_test.rb
bin/rails test test/functional/api_audit_events_controller_test.rb
bin/rails test test/integration/api_test/api_audit_test.rb
bin/rails test test/integration/routing/api_audit_events_test.rb
```

The audit log adds a migration, so `rake db:migrate` (and `RAILS_ENV=test rake db:migrate`) has to be
re-run on an existing checkout before the server will boot.

**CI status.** Redmine's own `Tests` workflow passes on this branch — all nine cells of its matrix
(SQLite, PostgreSQL, MySQL × Ruby 3.2, 3.3, 3.4) plus the Chrome system-test job — most recently in
full at commit `d27baa506`, which is the last commit that changed any code.

**Two of Redmine's own tests flake, and the proof that they flake is unusually clean.** The commit
after that one, `5d3073dbb`, is a **documentation-only** change — `git diff --stat d27baa506..5d3073dbb`
is `README.md | 141 +++---` and nothing else — and its run reported three failures:
`OauthProviderSystemTest#test_application_creation_and_authorization` in the Chrome job, and
`IssuesControllerTest#test_index_sort_by_spent_hours` plus `test_index_sort_by_total_spent_hours` in
the `mysql2 ruby-3.4` cell alone. A markdown edit cannot break a browser-driven OAuth authorization
flow or the ordering of a `spent_hours` sort. All three are upstream Redmine tests that this branch
does not touch, and the same suite failed once earlier on this branch (`f8af5d282`) and passed on the
commit before and after.

This is recorded rather than smoothed over because a reviewer will see a red tick and deserves to know
which failures are ours. The honest summary is: **no test this branch adds or touches has failed in
CI**, and the flakes are in Redmine's own suite, reproduced against an unchanged tree. A local
full-suite run also failed once in five for a test whose identity went uncaptured, which is likely the
same phenomenon seen from the other side.

The `Lint` workflow
is **red for a pre-existing reason unrelated to this branch**: its `bundle-audit` job reports
advisories against Rails 7.2.3, the version the `6.1.2` tag pins in `Gemfile:5` as an exact version
rather than a pessimistic constraint, so bundler cannot resolve the patch release the advisories ask
for. `Gemfile.lock` is gitignored here, so CI resolves dependencies fresh every run and still gets
7.2.3 — the pin blocks the fix, not a stale lockfile. The advisories are CVE-2026-33169
(ReDoS in `number_to_delimited`), CVE-2026-33170 (XSS in `SafeBuffer#%`) and CVE-2026-33176 (DoS in
the number helpers), all resolved by `>= 7.2.3.1`, against `activesupport`, `actionview` and
`activestorage`. This branch does not touch the `Gemfile` — `git diff base-6.1.2..HEAD -- Gemfile` is
empty — so the job was red before the branch existed. The `rubocop` and `stylelint` jobs pass.

Full suite, run on this checkout:

| | runs | assertions | failures | errors | skips |
|---|---|---|---|---|---|
| Before any change (tag `6.1.2`) | 5479 | 24753 | 0 | 0 | 44 |
| Current | 5797 | 26000 | 0 | 0 | 44 |

The difference is the 318 tests this branch adds, across the core, scopes, CORS, endpoint control,
audit logging and the two rounds of UI fixes; nothing existing changed state. Per-feature arithmetic
is deliberately not restated here, because every earlier version of this paragraph went stale within
a day and a stale measurement presented as current is the same defect as an unmeasured claim.

Two honest notes about that row. **Run counts reconcile; assertion counts do not** — repeated runs of
the identical tree produced 25994, 25996 and 26000 assertions against a stable 5797 runs, so only the
run count is used as evidence here. And **one full-suite run out of five failed once**, in a single
test whose identity was not captured; four subsequent full runs were green and the touched files
passed twelve consecutive randomised runs, so it could not be reproduced. It is recorded rather than
rounded away: "it passes now" is not the same as "it was a fluke", and CI runs the suite on every
push with full logs, which is where it would surface with a name attached.

A run performed while another agent was working the same checkout produced one spurious
`SQLite3::BusyException`; under concurrency SQLite failures look exactly like real ones, so re-run the
file alone before believing them. `test/system/` is excluded from `bin/rails test` and was not run
locally (see limits).

### End to end, against a running server

What follows is the **unedited output of a script** run against a running server, not a hand-written
illustration. Token values are held in shell variables and never echoed, which is why the transcript
shows prefixes and status codes rather than credentials. The scripts themselves are in the session
transcripts shipped alongside this repository.

```console
$ ./pat-verify.sh
### 1. issue a token for admin (value shown once, at creation)
    issued: rmpat_...(46 chars, prefix visible, rest withheld from this log)

### 2. it authenticates a real API request via the header
    X-Redmine-API-Key header          -> HTTP 200
{"user":{"id":1,"login":"admin","admin":true,"firstname":"Redmine","lastname":"Admin","mail":"admin@example.net","create

### 3. and as the HTTP Basic username
    HTTP Basic username               -> HTTP 200

### 4. but NOT as a query parameter (it would be written to the log)
    ?key= query parameter             -> HTTP 401

### 5. a second token does not invalidate the first (the API key cannot do this)
    first token still works           -> HTTP 200
    second token works too            -> HTTP 200

### 6. stored hashed, and last use recorded
    token_digest                      : d75a62bdda77... (SHA-256, 64 chars)
    cleartext recoverable from the DB : false
    last_used_on                      : 2026-08-12 21:31:40 UTC
    expires_on                        : 2026-11-10

### 7. expiry is enforced
    expired token                     -> HTTP 401

### 8. revocation is immediate
    revoked token                     -> HTTP 401

### 9. the existing API key is unaffected, on all three of its transports
    api key, header                   -> HTTP 200
    api key, basic username           -> HTTP 200
    api key, query parameter          -> HTTP 200
```

The management screen was walked the same way — logging in over HTTP and driving the real pages,
because assert_select proves structure but not that a screen works:

```console
$ ./ui-verify.sh
### 1. the list page only lists
    GET  list -> HTTP 200
    add link present   : 1
    create form on it  : 0

### 2. the creation form defaults to 30 days
    GET  new  -> HTTP 200
    selected option    : 30 days
    no-expiry warning  : 1

### 3. creating lands on a page of its own, naming the token
    POST      -> HTTP 200
    heading            : My account » Personal access tokens » laptop
    value shown        : rmpat_d97b37...(truncated on purpose)
    copy button        : 2
    expiry stated      : Expires: 09/11/2026
    back link          : 1

### 4. a second token gets its own page, so the two cannot be confused
    heading            : My account » Personal access tokens » ci-runner
    expiry stated      : Expires: No expiration

### 5. neither value is recoverable from the list
    token values on list: 0
    rows listed         : ci-runner laptop

### 6. revoking one
    DELETE    -> HTTP 302
    rows remaining      : 1
```

### CORS, against the same running server

Unedited `curl` headers, with **Allowed origins** set to `https://app.example.com`:

```console
### 1. allowed origin, authenticated GET
HTTP/1.1 200 OK
vary: Origin
access-control-allow-origin: https://app.example.com
access-control-expose-headers: Location

### 2. hostile origin
HTTP/1.1 200 OK
vary: Origin

### 3. suffix / prefix / scheme / port variants -- count of Allow-Origin headers
https://app.example.com.evil.net         -> 0
https://evil-app.example.com             -> 0
http://app.example.com                   -> 0
https://app.example.com:8443             -> 0
null                                     -> 0

### 4. create: 201 with a Location the browser is now allowed to read
HTTP/1.1 201 Created
vary: Origin
access-control-allow-origin: https://app.example.com
access-control-expose-headers: Location
location: http://localhost:3001/issues/2

### 5. a 403 rendered inside user_setup (this account must change its password)
HTTP/1.1 403 Forbidden
vary: Origin
access-control-allow-origin: https://app.example.com
access-control-expose-headers: Location

### 6. preflight, allowed
HTTP/1.1 204 No Content
vary: Origin
access-control-allow-origin: https://app.example.com
access-control-expose-headers: Location
access-control-allow-methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
access-control-allow-headers: Accept, Authorization, Content-Type, X-Redmine-API-Key, X-Redmine-Switch-User, X-Redmine-Nometa
access-control-max-age: 600

### 7. preflight, hostile
HTTP/1.1 404 Not Found
vary: Origin

### 8. HTML page, allowed origin
HTTP/1.1 200 OK
vary: Accept

### 9. a file download opted into the policy with ?format=json -- the attack the
###    red team found, re-run after the fix: the bytes come back, the headers do not
HTTP/1.1 200 OK
content-type: text/plain
TOP-SECRET-ATTACHMENT-BODY

### 10. the same trick on HTML routes -- count of access-control / vary: Origin headers
/admin?format=json         -> 0
/settings?format=json      -> 0
/my/page?format=json       -> 0
```

No `access-control-allow-credentials` appears anywhere above, by design. With the setting emptied
again, the same requests return `HTTP/1.1 200 OK` with no `vary` and no CORS header at all, and the
preflight returns `404` — which is what an `OPTIONS` request to Redmine did before this feature
existed. A `*` typed into the setting behaves identically to an empty one.

Cases 5, 9 and 10 are the ones the review gate produced. Case 5 used to answer `403` with no CORS
header, because the filter ran after `user_setup` and `user_setup` renders that refusal itself; cases
9 and 10 used to answer with `access-control-allow-origin` attached, because `?format=json` was enough
to make Redmine call the request an API request. Both are re-runs of the exact commands from the
attack ledger, against a server running the fixed code.

### Token scopes, against the same running server

Two tokens for the same **administrator**: one from the read-only preset, one with no scope. Values
are read from a file into `$RO` / `$FULL` and never printed.

```
$ # 1. read-only token: a read
GET  /issues/1.json          -> 200
$ # 2. read-only token: the same issue, written
PUT  /issues/1.json          -> 403
$ # 3. read-only token: create, delete, log time
POST /issues.json            -> 403
DEL  /issues/1.json          -> 403
POST /time_entries.json      -> 403
$ # 4. the owner is an administrator; the token is not
GET  /users.json (read-only) -> 403
GET  /users.json (full)      -> 200
$ # 5. account self-service is not expressible as a permission, so it is refused
PUT  /my/account.json (r-o)  -> 403
PUT  /my/account.json (full) -> 204
$ # 6. the unscoped token can still do all of it
PUT  /issues/1.json (full)   -> 204
$ # subject after all of the above:
rewritten by the unscoped token
```

The subject at the end is the point: the only write that landed is the one made by the token that was
allowed to make it.

And the impersonation case, with a third token scoped to `[:admin, :view_issues]`:

```
$ # token scope [admin, view_issues], owned by admin, impersonating "member"
GET  /users/current.json     -> login member
GET  /issues/1.json          -> 200
PUT  /issues/1.json          -> 403   (member may edit; the scope carried over refuses)
$ # the same impersonation with an unscoped token is unchanged
PUT  /issues/1.json (full)   -> 204
```

## Assumptions

- Local development used SQLite, chosen so setup needs one small native gem instead of a database
  client toolchain. Portability is no longer an assumption: CI runs the suite across
  **SQLite, PostgreSQL and MySQL on Ruby 3.2, 3.3 and 3.4**, and all nine cells pass on this branch.
- `Setting.rest_api_enabled` must be on, as for the existing API key. With it off, a PAT gets the same
  403 the API key gets.
- Upstream Redmine trunk has moved in this area since 6.1.2. Those commits were deliberately **not**
  read, so this design is argued from 6.1.2 rather than reproduced from a later maintainer decision.
  The cost is that it may diverge from where Redmine actually went.

## AI tooling

All of it was written with **Claude Code** (Claude Opus 5), driven interactively, with the full
unedited transcripts shipped alongside this repository as required by the brief.

Three read-only **subagents** ran in parallel before any code was written, each with a narrow
grep-first brief, mapping the authentication paths, the UI/i18n/migration conventions, and the test
blast radius. Their reports — `CODE-MAP-auth.md`, `CODE-MAP-ui.md`, `CODE-MAP-tests.md` — are in the
`notes/` directory shipped with the transcripts, and several decisions above come straight from them:
the shared value guard, the `varchar(40)` ceiling, and which existing tests would have broken had the
`api_token` association been pluralised.

Beyond that, the work was run through a **verification gate** rather than a review pass, because a
green suite proved repeatedly to be no evidence at all. Five axes, none of which subsumes another:

| axis | asks | agent | artifact |
|---|---|---|---|
| completeness | is anything *missing*, measured against the ticket and the brief rather than against the issues | `completeness-reviewer` | `notes/REQUIREMENTS.md` |
| blast radius | what *existing* behaviour can break, and is it pinned by a test | `blast-radius-reviewer` | — |
| correctness | is the diff right | `/code-review` | — |
| adversarial | can it be abused on a running server | `redteam` | `notes/ATTACKS.md` |
| interface | can the right people *reach* it, and does it tell the truth | `ui-verifier` | `notes/UI-CHECKS.md` |

Agent definitions live in `~/.claude/agents/` and ship with the transcripts. Two of the ledgers are
living documents that regress their own past findings on every run, which is what makes a second run
worth more than the first.

The gate found, across the six features, defects that the suite could not: an authentication
regression, a privilege escalation *and* the bypass of its own fix, a cleartext credential in the log,
a fail-open default granting full access, a cross-origin containment failure, a CSV formula injection,
a 500 in a file the diff never touched, thirteen interface defects, and several claims contradicted by
their own behaviour — including two in `notes/DECISIONS.md` itself.

Scale and performance claims were measured rather than argued, on a seeded 200,000-row database:
`notes/SCALE-AUDIT.md`. Two measurements in this repository had to be **retracted** after a
controlled re-run — a 3.2× speedup that was an artifact of a degrading environment, and a −2.1% index
write cost that is thermodynamically impossible and came from an uncontrolled before/after
comparison. Both retractions are recorded where the claims were made.

`notes/DECISIONS.md` is the running log of every non-obvious decision, written as the work happened,
and is the source this README was condensed from. `notes/LOOP-LOG.md` records an overnight autonomous
run of four features, marking exactly which three points needed a human.
