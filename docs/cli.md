# The `meros-client` command-line helper

`meros-client` puts every client in this crate behind one command, for apps
not written in Rust. Each call:

- reads one JSON object, the command's input, from stdin (or from
  `--input <file>`);
- prints one JSON object on stdout;
- exits with one of the codes below.

The helper keeps nothing in memory between calls. What it keeps lives in a
state directory the caller chooses.

Build it with the `cli` feature:

```sh
cargo build --release --features cli --bin meros-client
```

```sh
echo '{"state_dir": "/var/lib/example/meros"}' | meros-client device.identity
```

`meros-client commands` lists the commands, and `meros-client --version`
prints the version.

## Prebuilt binaries

Each `vX.Y.Z` tag publishes a GitHub release of this repository with:

| File | Platform |
|---|---|
| `meros-client-windows-x64.exe` | Windows x64 |
| `meros-client-windows-arm64.exe` | Windows ARM64 |
| `meros-client-macos-universal` | macOS, Apple silicon and Intel |
| `meros-client-linux-x64` | Linux x64, static (musl): any distribution |
| `meros-client-linux-arm64` | Linux ARM64, static (musl) |
| `SHA256SUMS` | Checksums of the five |
| `SHA256SUMS.sigstore.json` | The checksums' Sigstore signature |

Pin a release, download the binary for the platform with `SHA256SUMS` and
its bundle, and check both before use. On macOS and Linux, mark the binary
executable after downloading.

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json   --certificate-oidc-issuer https://token.actions.githubusercontent.com   --certificate-identity-regexp '^https://github.com/meros-co/meros-client/\.github/workflows/release\.yml@refs/tags/v'
sha256sum --check --ignore-missing SHA256SUMS
```

The signature is keyless: it proves the checksums came from this
repository's release workflow at a version tag, with no key to keep.
Each binary also carries a build-provenance attestation
(`gh attestation verify <file> --repo meros-co/meros-client`).

The binaries aren't code-signed for Windows SmartScreen or macOS
Gatekeeper. Products that ship the helper inside a signed app sign it with
the app.

## Output and exit codes

Success prints `{"ok": true, ...}` with the command's fields. Failure prints:

```json
{"ok": false, "error": {"code": "unknown_license_key", "message": "…", "status": 404}}
```

`code` is the service's own error code, unchanged. `message` is meant for
people. `status` (the HTTP status), `retry_after` (seconds, on 429) and
`head_version` (on a document `version_conflict`) appear when they apply.

| Exit | Meaning | Typical codes |
|---|---|---|
| 0 | Done | |
| 1 | The service refused | the service's code, e.g. `unknown_license_key`, `no_seats_available`, `access_denied`, `version_conflict` |
| 2 | No connection to the service | `network` |
| 3 | Wrong command or input | `unknown_command`, `bad_input` |
| 4 | Local state is missing or doesn't verify | `no_sign_in`, `verify_failed`, `token_rejected`, `not_activated`, `state_error`, `no_device_identity` |

Codes 0 to 4 are stable. New service codes can appear under exit 1.

## Common input

Every command takes the fields it needs from one flat object. Pass the same
settings on every call, and add the command's own fields.

| Field | Used by | Meaning |
|---|---|---|
| `state_dir` | all but `--version`/`commands` | The state directory (below). Created if missing, except by the read-only commands |
| `issuer` | service calls | The service origin, e.g. the staging or production one. No trailing slash needed. Nothing is built in. `fake:` runs against a fake service instead (see Fake mode) |
| `product` | server, cloud, support, events | The product id |
| `app_name`, `app_version` | licensing, events | Used in the default device name and reported to the service |
| `client_id`, `scopes` | sign-in | The app's public OAuth client and the scopes it asks for (array or space-separated string). Server activation with a login needs `licenses:activate`; refresh tokens need `offline_access` |
| `keys` | licensing | The product's signing keys, `{"kid": "base64url Ed25519 public key"}`. Statements and tokens are verified against them before they're stored or reported |
| `device_base_url` | device licensing, device support | The product's device base. Default `{issuer}/app/{product}`, where Meros serves both |
| `model`, `device_name` | licensing | How the device appears on the service. `model` defaults to the OS and architecture |
| `account_id` | cloud, server login | A team account; omitted means the user's default |
| `session` | sign-in, cloud, server login, account support, events | Which identity to act as: a handle the caller picks (letters, digits, `_`, `-`). Default `default` |
| `sub` | the same | Act as whichever session is signed in as this subject, instead of naming the `session` |
| `key_file` | all | Seal every stored file with the key in this file (below). Made on first use; must be outside the state directory |

## The state directory

| File | Holds |
|---|---|
| `device.json` | The device id and its Ed25519 key seed. Made on first use; never sent anywhere except as signatures and the public key |
| `sessions/{session}.json` | One identity's Sign in with Meros session: refresh token, user, current access token, and login-token requests waiting to be redeemed |
| `sessions/{session}.signin.json` | That identity's device sign-in in progress |
| `server.json` | The Server statement and its feature token |
| `license.json` | The device entitlement token |
| `events/` | The local event log, the install's identity, and undelivered events (`outbox.json`) |
| `cache/` | The last entitlements answer (per session) and the latest copy of each pack, for offline use. A session's entries are cleared when it signs out |
| `lock` | Held for the length of each call |

On Unix the directory is `0700` and every file `0600`, owned by the calling
user. On Windows they inherit the directory's ACL, so put the state directory
in a location only the app's user can read (its profile, or a directory with
an explicit ACL). Files are replaced atomically.

Each call holds an exclusive lock on `lock`, so concurrent calls run one
after another. That matters because refresh tokens rotate, and a refresh
token used twice ends the session: Meros revokes the whole family. The new
refresh token is stored before the access token is used.

### Sealing with `key_file`

Without `key_file`, secrets are protected by the file permissions above:
another user on the machine can't read them, but anyone who copies the
state directory (a backup, a support bundle, a shared drive) carries them
along.

With `key_file`, every file the helper writes is sealed with
ChaCha20-Poly1305 under a 32-byte key kept in that file (64 hex digits,
`0600`, made on first use). That covers the device key, sessions, statements,
tokens and caches. Keep the key file outside the state directory; the helper
refuses one inside it.
- Copying the state directory alone then carries no secret.
- Tampering is detected: a sealed file that doesn't open is an error
  (`state_error`), never silently replaced by a new key or session.

This matches the at-rest encryption products already use for stored
refresh tokens. Like theirs, it doesn't protect against someone who can read
both the directory and the key file. That would need a passphrase typed at
start, which unattended devices can't have.

### Several identities

Each `session` handle is one identity, with its own client id and scopes
(passed on each call), its own rotating refresh token, and its own pending
device grant. A console can keep its own session and any number of people's
sessions side by side. Sessions never appear in anything the app exports:
they live only in the state directory.

The helper never decides who a person is locally: it reports `sub`, `name`
and `email`. Key people on `sub`, never on email.

**Read-only commands** (`server.status`, `server.verify`, `license.status`,
`signin.status`, `signin.list`) create nothing: no directory, no key, no lock file. They
take only a shared lock when the lock file exists, so a privileged process
(an update installer running as root, say) can ask about a service user's
state directory without leaving root-owned files there. They verify the
stored statement or token against `keys` on every call and trust no cached
result.

## Device

### `device.identity`

Returns `{device_id, pubkey}` and makes the key on first use.

## Sign in with Meros (device grant)

For devices without a browser. The person approves a code on another device.

### `signin.start`

Asks for a code. Returns:

```json
{"user_code": "WDJB-0001", "verification_uri": "https://…/link",
 "verification_uri_complete": "https://…/link?user_code=WDJB-0001",
 "interval": 5, "expires_at": 1792239000}
```

Show `user_code` and `verification_uri`, or `verification_uri_complete` as a
QR code.

Optional `acr_values`, such as `urn:meros:acr:mfa`, asks for a two-factor
sign-in: the step-up after a `mfa_required` refusal. It is kept with the
pending grant. When the poll completes on a session already signed in as
the same user, that session is upgraded in place: same handle, same user,
new tokens.

### `signin.poll`

Call it every `interval` seconds:

- `{"status": "pending", "interval": 5}`: wait and poll again. The interval
  goes up when the service says to slow down; use the new value.
- `{"status": "signed_in", "user": {"id", "name", "email"}}`: done. The
  session is stored. When the grant asked for `acr_values`, they're echoed
  back as `acr_values`.
- Exit 1 with `access_denied` or `expired_token`: the sign-in is forgotten;
  start again.
- Exit 4 with `no_sign_in`: nothing was started.

### `signin.status`

`{"signed_in": false}` or `{"signed_in": true, "user": {...}}`. Read-only.

### `signin.list`

`{"sessions": [{"session", "signed_in", "user"}]}`, every identity in the
state directory. Read-only.

### `signin.cancel`

Forgets the session's pending device grant.

### `signin.redeem.begin` and `signin.redeem.complete`

Signs a user in from a login token minted elsewhere (see
`signin.login_token`), as this session's client.

1. `signin.redeem.begin` returns `{request_id, code_challenge,
   code_challenge_method, nonce, expires_at}`. Pass the challenge and nonce
   to whoever mints the token. Up to 16 requests wait at once, each for five
   minutes.
2. `signin.redeem.complete` takes `request_id` and `login_token`, and
   returns `{user, replaced_previous}`.

The redeem uses the `urn:meros:params:oauth:grant-type:sso-ticket` grant
with the PKCE verifier and the configured scopes. The id_token must:
- be for this client;
- carry the request's nonce and a subject;
- be unexpired;
- come from the issuer;
- arrive with a refresh token.

If any check fails, the tokens are revoked and the call exits 1 with
`invalid_response`. A different user already signed in to the session is
revoked first, and `replaced_previous` is `true`. Other refusals: the
service's `invalid_grant` (the token was used, expired or for another
client), and exit 4 `unknown_request` (not begun here, or expired). Offline,
the request is kept, so the call can be retried.

A refused refresh (`invalid_grant`) ends the session: the identity is
forgotten rather than retried. Sign-out revokes with the session's client
id, without which Meros revokes nothing.

### `signin.token`

`{"access_token": "…"}` for calling other Meros APIs directly. The token is
reused until a minute before it runs out. `"force": true` refreshes it now,
after an API refused it.

### `signin.signout`

Revokes the session on the service and forgets it locally, even offline.
Returns `{revoked}`:
- `true` when the service revoked it;
- `false` when the service couldn't be reached, or there was no session. In
  that case the refresh token stays valid on the service until it idles
  out; sign out again online to revoke it.

It also clears the session's entries in `cache/`.

### `signin.login_token`

Mints a single-use login token for a connected service, so that service can
sign the same user in as its own client.

- Input: `audience` (the service), plus optional `code_challenge` (the
  service's S256 PKCE challenge), `nonce`, and `acr_values` (such as
  `urn:meros:acr:mfa` to require a two-factor sign-in).
- Returns `{login_token, token_type, expires_in, audience, client_id}`. The
  token lasts 120 seconds and is redeemed by `client_id`.
- Refusals include `invalid_target` and `mfa_required`.

## Server licenses

Perpetual, online-only activation for Server editions.

### `server.activate`

Input: `license_key`, optional `device_name`. Returns `{licence, token}`:

- `licence` is the verified statement's payload: `product`, `edition`,
  `account_id`, `account_name`, `license_id`, `seat_id`, `device_id`,
  `licence` (`perpetual`), `updates_until` (`YYYY-MM-DD`), `features`;
- `token` is the 30-day feature token as issued.

Codes include `unknown_license_key`, `license_key_disabled`,
`no_seats_available` (another instance holds the key; the message names it),
`device_id_in_use` and `bad_signature`.

### `server.activate_login`

Activates with the signed-in user's license, through the device grant
above. Input: optional `account_id` and `device_name`. Call it after every
sign-in on an activated instance too: a key no account owns is adopted into
the user's account. Codes include `no_licence` (the message has the buy
link), `device_id_in_use`, `forbidden`, `insufficient_scope` and
`unauthenticated`. Without a session it exits 4 with `no_sign_in`.

### `server.renew`

Renew at least daily while online. Optional `device_info` object is reported
with the renewal. Always exits 0 unless the input is wrong:

| `result` | Meaning | Do |
|---|---|---|
| `renewed` | A fresh statement and token, returned as `licence` and `token` | Nothing |
| `revoked` | The seat is gone (revoked, refunded, released or moved). Deactivated | Stop Server features; activation is allowed again |
| `suspended` | The key is suspended (`error` says why) | Keep running; show the message |
| `kept` | Anything else, offline included (`error` says what) | Keep running |

### `server.release`

Frees the seat so the license can move, and deactivates the instance.

### `server.status`

`{"active": false}`, or `{"active": true, "licence", "token"}` when the
stored statement verifies. With `build_date` (`YYYY-MM-DD`) it adds
`covers_build`: whether a build released that day may be installed under
the statement. Read-only, and it verifies on every call.

### `server.verify`

Verifies `statement` against `keys`, for `product` and the device (this
state directory's, or `device_id` and `device_pubkey` given). Returns
`{licence}`; exit 4 `verify_failed` otherwise. Read-only.

## Device licenses

For apps that activate per device with a key or an account.

| Command | Input | Returns |
|---|---|---|
| `license.activate` | `license_key`, `device_name?` | `{entitlement, token}` (the verified token payload and the token) |
| `license.renew` | `device_info?` | `{renewed, entitlement?, token?}`. Quiet on failure: grace covers outages |
| `license.release` | | `{}` |
| `license.status` | | `{active: false}` or `{active: true, valid, entitlement, token}`, where `valid` is false once `exp` has passed. Read-only |
| `license.offline_request` | `license_key`, `device_name?` | `{blob}`, to paste into the offline activation page |
| `license.offline_import` | `blob` (the token from that page) | `{entitlement, token}` |
| `license.manage_url` | | `{url}`, the license management page for this device |
| `license.claim` | `device_name?` | Claims a seat on the signed-in user's account: `{entitlement, token}` |
| `license.adopt` | `device_name?` | After sign-in: `{result}` `claimed`, `kept_current` or `not_licensed` |
| `license.seats` | | `{seats: [{seat_id, device_id, name, model, activated_at, last_seen_at, account_id, account_name, account_type, can_release}]}` |
| `license.release_seat` | `seat_id` | `{}` |

## Meros Cloud

All need a session (exit 4 `no_sign_in` without one). `account_id` picks a
team account; omitted means the personal one.

| Command | Input | Returns |
|---|---|---|
| `cloud.accounts` | | `{accounts: [{id, name, team, role, is_default}]}` |
| `cloud.entitlements` | `product` | `{account_id, features, tier, expires_at, held, in_grace, lapsed, fetched_at, cached}` (below) |
| `cloud.inventory.get` | `product` | `{product, count, updated_at, devices}` |
| `cloud.inventory.put` | `product`, `devices` (the full set; each needs `id`) | `{product, count, updated_at}`. Devices left out are deleted; `[]` clears |
| `cloud.profile.get` | `namespace` | `{keys, updated}` |
| `cloud.profile.put` | `namespace`, `keys` (a null value deletes a key) | `{keys, updated}` |
| `cloud.profile.delete` | `namespace` | `{}` |
| `cloud.docs.list` | `product`, `collection` | `{docs: [{key, head_version, updated}]}` |
| `cloud.docs.get` | `product`, `collection`, `key`, `version?` | `{key, version, head_version, body, content_hash}` |
| `cloud.docs.put` | `product`, `collection`, `key`, `body`, `base_version?` | `{version, content_hash, unchanged}`. Exit 1 `version_conflict` with `head_version`, `head_content_hash` and `head_updated_at` (when the other copy was saved) when someone saved different content first; an identical copy is `unchanged: true` with the head's version, and nothing is written |
| `cloud.docs.delete` | `product`, `collection`, `key` | `{}` |
| `cloud.docs.versions` | `product`, `collection`, `key` | `{versions: [{version, created, size_bytes}]}` |
| `cloud.files.list` | `product`, `collection` | `{files: [{sha256, size, status, created, download_url}]}` |
| `cloud.files.put` | `product`, `collection`, `content_base64` or `path` | `{file}` |
| `cloud.files.get` | `product`, `collection`, `sha256`, `path?` | `{sha256, size, content_base64}`, or writes `path` |
| `cloud.files.delete` | `product`, `collection`, `sha256` | `{}` |

### Entitlements, grace and `held`

- `features` lists what the service says the account has.
- `expires_at` is the soonest expiry across the product's entitlements (null
  when none expires).
- Offline, the last answer comes back with `cached: true` and its
  `fetched_at`; with none cached, exit 2.
- A cached answer is honored for 30 days past `expires_at`: `in_grace` is
  true during those days, and after them `lapsed` is true.
- `held` is the honest answer to "does the account hold this now": the
  features, or nothing once lapsed. Gate features on `held`. Whether a
  missing feature actually withholds anything is the product's decision.

### Documents and `content_hash`

`content_hash` is the sha256 of the body's canonical JSON:
- object keys sorted recursively, array order kept;
- no whitespace;
- `/` and non-ASCII left unescaped.

It is the same value Meros computes, so two machines holding the same
document agree without asking. The version number decides conflicts; the
hash only tells an identical copy from a real one. Floating-point numbers
may render differently across languages, so keep them out of documents that
rely on this.

## Signed data packs

Packs need the product's `keys` and no session unless the pack is entitled.
They are verified on every call, from the cache too.

### `cloud.feed`

Input: `product`, `pack`, optional `version`. Returns:

```json
{"product": "…", "pack": "…", "version": 3, "kid": "…", "issued_at": "…",
 "payload": {…}, "from_cache": false, "fetched_at": 1792238400}
```

`payload` is read from the verified signed bytes. The latest version is
cached with its `ETag`:

- an unchanged pack costs a `304` and comes from the cache;
- offline, the cached copy is returned with `from_cache: true`.

An entitled pack answers exit 1 with `http_401` without a session, and
`not_entitled` without the entitlement. A pack that doesn't verify against
`keys` is exit 4 `verify_failed`.

With `"cache_only": true` no request is made at all, and no `issuer` is
needed: the cached latest copy is verified and returned, or the call exits 4
with `not_cached`. Use it where waiting on the network isn't acceptable, and
refresh with a normal call when it is.

### `cloud.feed_versions`

Input: `product`, `pack`. Returns the service's list of versions.

## Support

`via` picks how the app is known: `device` (default) signs with the device
key and needs an activated device license; `account` uses the signed-in user
(scope `support:write`).

| Command | Input | Returns |
|---|---|---|
| `support.create` | `subject`, `message`, `diagnostics?` | `{ticket}` |
| `support.list` | | `{tickets: [{id, subject, status, created_at, last_message_at}]}` |
| `support.thread` | `ticket_id` | `{ticket, messages: [{author, body, at}]}` (`author` is `you` or `support`) |
| `support.reply` | `ticket_id`, `message` | `{ticket}` |

`status` is `open` (waiting on support), `pending` (support answered) or
`closed`. Expect `rate_limited` and `too_many_open_tickets` refusals.

`via: device` works for any device the service has registered for the
product, so a Server instance activated with `server.activate` or
`server.activate_login` files tickets as itself, the same as a device
license.

## Events

Meros Event Envelope v1, logged in `events/` and delivered to collectors.

### `events.send`

Input: `events`, an array of:

```json
{"type": "product.subject.verb", "severity": "info",
 "occurred_at": "2026-10-30T19:42:07.125Z",
 "subject": {"kind": "show", "id": "s1", "name": "Main"},
 "actor": {"kind": "user", "id": "u1"},
 "attrs": {"key": "value"}, "trace": "…"}
```

- Only `type` is required. `severity` is `debug`, `info` (default),
  `notice`, `warning`, `error` or `critical`.
- `occurred_at` (RFC 3339) stamps when it happened, for apps that batch
  events before calling. It defaults to the time of the call.
- The helper adds the id (a ULID, so a resent batch is recognized as
  duplicates), time, sequence and source.
- Limits follow the envelope: attributes over 16 KiB keep as many keys as
  fit, an event over 64 KiB is dropped (and reported in a
  `{product}.events.dropped` event), batches go 500 at a time, and at most
  10,000 events wait.
- It delivers at once unless `"flush": false`.
- Optional: `edition`, `site`, and `collectors`
  (`[{"url": …, "auth": "signin" | "none"}]`; default: the issuer with the
  session).

Returns `{instance, pending, delivered, accepted, duplicates, rejected,
failed}`. What isn't delivered stays in `events/outbox.json` and goes with
the next `events.send` or `events.flush`, under the same ids. A collector
that already took one counts it as a duplicate.

### `events.relay`

Forwards other products' events unchanged, for an app that collects events
locally and passes them on.

- Input: `events`, an array of complete Envelope v1 events (`envelope`, `id`,
  `occurred_at`, `seq`, `source`, `type`, `severity`, and the optional
  fields).
- They go on exactly as given: same id, time, sequence and source. A
  collector that already has one counts it as a duplicate.
- They wait in the outbox, retry and clear like the app's own events, but
  aren't written to its local log.
- An event that isn't Envelope v1, lacks `id`, `occurred_at` or `type`, or
  is over 64 KiB, is exit 3 (`bad_input`, naming its index).
- Same output as `events.send`; `"flush": false` queues without sending.

### `events.flush`

Delivers what's waiting. Same output.

### `events.clear`

Drops every event waiting in `events/outbox.json` without sending it. Use it
when the app's user turns event reporting off, so nothing queued earlier
leaves later. Returns `{cleared, pending: 0}`. Needs no `issuer` or
`product`. The local log is kept.

## Fake mode

With `"issuer": "fake:"`, every command runs against an in-memory copy of
the Meros services instead of the network. Its state lives in
`{state_dir}/fake.json` between calls, so a product can test against the
real binary without writing its own fake.

- The fake answers as `https://fake.meros.test`. Use the keys from
  `fake.keys` for `keys`.
- It isn't for concurrent calls.
- Delete `fake.json` to start over.

### Seeded data

| What | Value |
|---|---|
| The signed-in user | `sub` `u1`, name `Pat`, email `pat@example.com` |
| Their personal account | `acct-personal` |
| The clock | 2026-10-17 12:00 UTC, moved with `fake.advance` |
| Device sign-in | 10-minute codes, a 5-second interval; approve with `fake.approve_device` |
| Tokens | Access tokens last an hour; refresh tokens rotate and work once |
| Entitlement tokens and Server statements | Signed with the keys in `fake.keys` |
| Everything else | Empty: no license keys, features, packs or documents |

### Controls

| Command | Input | Does |
|---|---|---|
| `fake.keys` | | Returns `{server, entitlement}` key tables (kid → key) and the `issuer` |
| `fake.state` | | Returns the whole state, to check what arrived (`events`, `tickets`, `docs`, `seats`, `inventory`) |
| `fake.set` | `patch` | Sets state fields, e.g. `{"license_keys": ["KEY-1"], "server_keys": {"SRV-1": "acct-personal"}, "features": ["my-product.sync"], "free_seats": 2, "team": "acct-team"}`. An unknown field is refused |
| `fake.approve_device` / `fake.deny_device` | `user_code` | Decides a pending device sign-in |
| `fake.publish_pack` | `product`, `pack`, `payload`, `entitled?` | Publishes the next version of a pack |
| `fake.support_reply` | `ticket_id`, `message` | Support answers a ticket |
| `fake.advance` | `seconds` | Moves the clock, e.g. past a device code's expiry |

Useful knobs for `fake.set`:

- licensing:
  - `license_keys` (device keys that activate);
  - `server_keys` (Server key → owning account);
  - `unowned_keys`;
  - `suspended_keys` and `revoked_keys`;
  - `free_seats`, `team`, `features`;
  - `entitlement_expires_at` (RFC 3339);
- sign-in: `device_grant` (false hides the grant), `sso_audiences`, `sso_sub`;
- refusals: `support_rate_limited`, `open_ticket_cap`, `unknown_products`;
- limits: `event_batch_cap`, `file_cap` and `file_quota`.

## Testing

The helper's tests run every command against `FakeMeros` (`cargo test
--features cli,fake --test cli`). There is no built-in host: without
`issuer`, every service command refuses before sending anything, and a test
checks that no host is written into the helper. Point manual runs at a
staging issuer, never production.
