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
| **Deferred** | Token scopes, audit logging, granular endpoint control, CORS, admin lifetime policy, migration off the legacy API key — each an issue with reasoning |
| **Out of scope** | Rate limiting, excluded by the brief |
| **Untouched** | The existing `api_key`, and `Token`, which it is built on |

Deferred work is on the issue tracker rather than in this file's small print: issues #5–#10, labelled
`deferred`. Two pre-existing weaknesses found while reading the code are recorded as #11 and #12; they
are not fixed here, because fixing them would widen a diff that should read as one slice.

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
- **No admin oversight.** An administrator cannot list or revoke another user's tokens, and cannot
  enforce a maximum lifetime. That is the ticket's admin panel and policy work, deferred as issue #9.
- **PATs inherit the existing API-key posture on 2FA and forced password change.** Neither blocks API
  key authentication in Redmine today, and PATs behave the same. Changing it is a product decision
  beyond this slice.
- **Expiry is a date, evaluated in the current user's timezone** via `User#today`, not an instant.
- **`test/system/` was never run.** The development container is aarch64 with no browser and no root
  to install one, so `test/system/api_key_copy_test.rb` — which asserts the markup of the API-key
  sidebar block that the new link sits beside — is covered by CI only. The block's markup was left
  untouched precisely because of this.

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

Full suite, run on this checkout:

| | runs | assertions | failures | errors | skips |
|---|---|---|---|---|---|
| Before any change (tag `6.1.2`) | 5479 | 24753 | 0 | 0 | 44 |
| After | 5513 | 24834 | 0 | 0 | 44 |

The difference is exactly the 34 tests added here; nothing existing changed state. `test/system/` is
excluded from `bin/rails test` and was not run locally (see limits).

### End to end, against a running server

Issue a token from **My account → Personal access tokens**, then:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -H "X-Redmine-API-Key: $PAT" \
    http://localhost:3000/users/current.json
200

$ curl -s -o /dev/null -w '%{http_code}\n' -u "$PAT:whatever" \
    http://localhost:3000/users/current.json
200

$ curl -s -o /dev/null -w '%{http_code}\n' \
    "http://localhost:3000/users/current.json?key=$PAT"
401
```

A second token does not invalidate the first — the behaviour the single API key cannot offer:

```console
$ curl -s -o /dev/null -w 'first  %{http_code}\n' -H "X-Redmine-API-Key: $PAT"  .../users/current.json
first  200
$ curl -s -o /dev/null -w 'second %{http_code}\n' -H "X-Redmine-API-Key: $PAT2" .../users/current.json
second 200
```

Expiry and revocation both take effect immediately:

```console
$ # after setting expires_on to yesterday
$ curl -s -o /dev/null -w '%{http_code}\n' -H "X-Redmine-API-Key: $PAT" .../users/current.json
401
$ # after revoking from the UI
$ curl -s -o /dev/null -w '%{http_code}\n' -H "X-Redmine-API-Key: $PAT" .../users/current.json
401
```

And the existing API key is unaffected on all three of its transports:

```console
api key, header             -> HTTP 200
api key, basic username     -> HTTP 200
api key, query parameter    -> HTTP 200
```

## Assumptions

- The reviewer runs SQLite. It is what `config/database.yml` was set to here, chosen so setup needs one
  small native gem instead of a database client toolchain. Nothing in the change is SQLite-specific;
  the unique indexes and the `date` column are portable.
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
