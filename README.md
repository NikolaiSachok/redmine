# Personal access tokens for the Redmine REST API

This branch implements pillar #1 of [Redmine #43881](https://www.redmine.org/issues/43881) —
**personal access tokens**: named API credentials, several per user, individually expiring, stored
only as a digest, revocable from My account.

It is a deliberately small slice of a large ticket, branched from tag `6.1.2`. Redmine's own
`README.rdoc` is unchanged and still describes the product; this file describes the change.

---

## What is here

| | |
|---|---|
| **Done** | PAT model with hashed storage and per-token expiry; REST API authentication; My account management screen; unit, integration, functional and routing tests |
| **Deferred** | Token scopes, audit logging, granular endpoint control, CORS, **admin lifetime policy and admin token overview**, expired-token cleanup, the 2FA posture, migration off the legacy API key — each an issue with reasoning |
| **Out of scope** | Rate limiting, excluded by the brief |
| **Untouched** | The existing `api_key`, and `Token`, which it is built on |

Deferred work is on the issue tracker rather than in this file's small print: issues #5–#10, #14 and
#15, labelled `deferred`. Two pre-existing weaknesses found while reading the code are recorded as #11
and #12; they are not fixed here, because fixing them would widen a diff that should read as one slice.

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

- **No scopes.** A PAT carries its owner's full permissions. It is a better-managed credential, not a
  narrower one. Issue #5 sketches how scoping could reuse the OAuth mechanism already in the codebase.
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
- **The ticket asks for *mandatory* expiration; this implements a forced *choice*.** Pillar 1 of
  #43881 says tokens must expire. Here the creation form makes you pick a lifetime — 30 days by
  default — but "No expiration" is one of the options. The reason is that the credential being
  replaced never expires, so forbidding permanent tokens outright would break the long-running
  integrations that use the current API key, with no migration path offered in the same slice. Real
  enforcement belongs with the administrator policy that can set a ceiling, deferred as issue #9.
  This is a deliberate deviation from the ticket, not an oversight.
- **No admin oversight.** An administrator cannot list or revoke another user's tokens, and cannot
  enforce a maximum lifetime. That is the ticket's admin panel and policy work, deferred as issue #9.
- **Expired and revoked rows are never swept.** `redmine:tokens:prune` covers the `tokens` table only,
  so `personal_access_tokens` grows without bound. Issue #14.
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

### What an adversarial pass changed

A red-team agent attacked a running instance rather than reading the diff, working from a ledger of
attacks that it also extends — `notes/ATTACKS.md`, shipped with this repository. Ten hypotheses, two
landed, and both were weaknesses this feature *introduces* rather than inherits:

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

### Why the query parameter is refused

The existing API key authenticates three ways, including `?key=`. PATs support only two, and that is
the one place where this branch is deliberately stricter than what it sits beside.

Redmine adds only `:password` to `config.filter_parameters`, so a credential in the query string is
written to the application log in cleartext — reproduced here, not hypothesised. Adding `:key` to that
list would clean Rails' own log and nothing else: not the access log of any proxy in front of it, not
`Referer` headers, not browser history, not shell history. A credential that must never appear in a
URL cannot be safely accepted from one, so the transport is refused rather than half-mitigated. The
legacy key keeps all three transports; nothing existing was taken away.

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
```

**CI status.** Redmine's own `Tests` workflow is green on this branch — all nine cells of its matrix
(SQLite, PostgreSQL, MySQL × Ruby 3.2, 3.3, 3.4) plus the Chrome system-test job. The `Lint` workflow
is **red for a pre-existing reason unrelated to this branch**: its `bundle-audit` job reports
advisories against Rails 7.2.3, the version the `6.1.2` tag pins, and this branch does not touch the
`Gemfile`. The `rubocop` and `stylelint` jobs in that workflow pass.

Full suite, run on this checkout:

| | runs | assertions | failures | errors | skips |
|---|---|---|---|---|---|
| Before any change (tag `6.1.2`) | 5479 | 24753 | 0 | 0 | 44 |
| After | 5528 | 24901 | 0 | 0 | 44 |

The difference is exactly the 49 tests added here — 18 in `personal_access_token_test.rb`, 18 in
`personal_access_token_auth_test.rb`, 13 in `my_controller_test.rb` — and nothing existing changed
state. Note that a run performed while another agent was working the same checkout produced one
spurious `SQLite3::BusyException`; under concurrency SQLite failures look exactly like real ones, so
re-run the file alone before believing them. `test/system/` is
excluded from `bin/rails test` and was not run locally (see limits).

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

`notes/DECISIONS.md` is the running log of every non-obvious decision, written as the work happened,
and is the source this README was condensed from.
