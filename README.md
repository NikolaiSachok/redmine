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
| **Done** | PAT model with hashed storage and per-token expiry; REST API authentication; My account management screen; **administration overview of every user's tokens**; **an administrator ceiling on token lifetime**; **cleanup of long-expired rows**; unit, integration, functional and routing tests |
| **Also done** | **Permission scopes for tokens** — one of pillar #2's four bullets: a read-only preset, a full-access preset and a permission picker, enforced through the mechanism Redmine already uses for OAuth2 scopes; **CORS for the REST API** (pillar #6) — an administrator allowlist of origins, off by default |
| **Deferred** | The rest of pillar #2 — per-tracker scoping, per-project scoping and an administrator-defined scope vocabulary; audit logging, granular endpoint control, the 2FA posture, migration off the legacy API key — each an issue with reasoning |
| **Out of scope** | Rate limiting, excluded by the brief |
| **Untouched** | The existing `api_key`, and `Token`, which it is built on |

Deferred work is on the issue tracker rather than in this file's small print: issues #6, #7, #10,
#15, #17, #18 and #19, labelled `deferred`. CORS (#8) started there and was implemented
after the core was solid; it and the scopes work each have their own section below. Two pre-existing weaknesses found while reading the code are recorded as #11
and #12; #11 is now fixed, because the red team showed this feature makes it reachable with a new
credential, and #12 stays open because closing it fully belongs to the OAuth path, not to this slice.

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
leaving it untouched for a human in the web interface.

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
  branch, so the HTML interface is unaffected even when the same request also carries an API key.
- **A disabled endpoint is indistinguishable from a disabled API.** The refusal is a bare `403` with an
  empty body, which is byte-for-byte what `require_login` already answers when `rest_api_enabled` is
  off. So a caller cannot read the configuration back out of the responses, and the reason goes to the
  application log for the administrator instead. The filter is declared in `ApplicationController`
  after `user_setup` and `check_if_login_required` and before every filter a subclass declares, so a
  disabled write never reaches the action: `POST /issues.json` against a disabled `issues#create`
  creates nothing.
- **Nothing a form posts can name something that is not an endpoint.** The posted list is intersected
  with the enumeration from the code, so `Kernel#system` simply is not stored, and enforcement is a
  string `include?` — no `constantize`, no `send`, no route lookup anywhere in the path.

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

- **The grain is the controller action, not the HTTP method or the record.** `issues#update` covers
  `PUT` and `PATCH` together because they are the same action, and disabling `issues#index` disables
  it for every project. Per-method and per-project control would need a different key.
- **`.atom` is a separate authentication path** (`accept_atom_auth`, feeds keys) and is not gated
  here. Neither are the Doorkeeper OAuth token endpoints, which do not inherit `ApplicationController`.
- **A disabled endpoint is still advertised.** Nothing removes it from the routes, from the API
  documentation, or from any UI that links to it; the enforcement is server-side only, which is the
  right way round, but a client discovers the restriction by being refused.
- **The list is only as accurate as `accept_api_auth`.** An action that is reachable with an API
  credential without declaring it — there are none in core, because the declaration is what makes it
  reachable — would not appear on the screen and could not be disabled.
- **No audit of the refusals.** They are logged at info level with the endpoint name; there is no
  structured record of who was refused what. That is pillar #4, issue #6, and is not built.

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
| After the personal-access-token work | 5528 | 24901 | 0 | 0 | 44 |

The CORS work landed after that measurement and adds 48 tests (12 in `test/unit/lib/redmine/cors_test.rb`,
30 in `test/integration/api_test/cors_test.rb`, 5 in `test/integration/routing/cors_test.rb`, 1 in
`test/functional/settings_controller_test.rb`).
Those files, `test/integration/api_test/`, `test/integration/routing/`,
`test/functional/my_controller_test.rb` and `test/functional/settings_controller_test.rb` were run and
are green; the full-suite row is re-measured rather than extrapolated, so it is not restated here.

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

`notes/DECISIONS.md` is the running log of every non-obvious decision, written as the work happened,
and is the source this README was condensed from.
