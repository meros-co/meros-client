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
| `issuer` | service calls | The service origin, e.g. the staging or production one. No trailing slash needed. Nothing is built in |
| `product` | server, cloud, support, events | The product id |
| `app_name`, `app_version` | licensing, events | Used in the default device name and reported to the service |
| `client_id`, `scopes` | sign-in | The app's public OAuth client and the scopes it asks for (array or space-separated string). Server activation with a login needs `licenses:activate`; refresh tokens need `offline_access` |
| `keys` | licensing | The product's signing keys, `{"kid": "base64url Ed25519 public key"}`. Statements and tokens are verified against them before they're stored or reported |
| `device_base_url` | device licensing, device support | The product's device base, if it isn't the service root |
| `model`, `device_name` | licensing | How the device appears on the service. `model` defaults to the OS and architecture |
| `account_id` | cloud, server login | A team account; omitted means the user's default |

## The state directory

| File | Holds |
|---|---|
| `device.json` | The device id and its Ed25519 key seed. Made on first use; never sent anywhere except as signatures and the public key |
| `session.json` | The Sign in with Meros session: refresh token, user, and the current access token |
| `signin.json` | A device sign-in in progress |
| `server.json` | The Server statement and its feature token |
| `license.json` | The device entitlement token |
| `events/` | The local event log, the install's identity, and undelivered events (`outbox.json`) |
| `cache/` | The last entitlements answer and the latest copy of each pack, for offline use. Cleared at sign-out |
| `lock` | Held for the length of each call |

On Unix the directory is `0700` and every file `0600`, owned by the calling
user. On Windows they inherit the directory's ACL, so put the state directory
in a location only the app's user can read (its profile, or a directory with
an explicit ACL). Files are replaced atomically.

Each call holds an exclusive lock on `lock`, so concurrent calls run one
after another. That matters because refresh tokens rotate, and a refresh
token used twice ends the session.

**Read-only commands** (`server.status`, `server.verify`, `license.status`,
`signin.status`) create nothing: no directory, no key, no lock file. They
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

### `signin.poll`

Call it every `interval` seconds:

- `{"status": "pending", "interval": 5}`: wait and poll again. The interval
  goes up when the service says to slow down; use the new value.
- `{"status": "signed_in", "user": {"id", "name", "email"}}`: done. The
  session is stored.
- Exit 1 with `access_denied` or `expired_token`: the sign-in is forgotten;
  start again.
- Exit 4 with `no_sign_in`: nothing was started.

### `signin.status`

`{"signed_in": false}` or `{"signed_in": true, "user": {...}}`. Read-only.

### `signin.token`

`{"access_token": "…"}` for calling other Meros APIs directly. The token is
reused until a minute before it runs out. `"force": true` refreshes it now,
after an API refused it.

### `signin.signout`

Revokes the session on the service and forgets it locally, even offline. It
also clears `cache/`.

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
| `cloud.entitlements` | `product` | `{features: ["product.flag", …], tier, fetched_at, cached}`. Offline, the last answer comes back with `cached: true` and its `fetched_at`; with none, exit 2 |
| `cloud.inventory.get` | `product` | `{product, count, updated_at, devices}` |
| `cloud.inventory.put` | `product`, `devices` (the full set; each needs `id`) | `{product, count, updated_at}`. Devices left out are deleted; `[]` clears |
| `cloud.profile.get` | `namespace` | `{keys, updated}` |
| `cloud.profile.put` | `namespace`, `keys` (a null value deletes a key) | `{keys, updated}` |
| `cloud.profile.delete` | `namespace` | `{}` |
| `cloud.docs.list` | `product`, `collection` | `{docs: [{key, head_version, updated}]}` |
| `cloud.docs.get` | `product`, `collection`, `key`, `version?` | `{key, version, head_version, body}` |
| `cloud.docs.put` | `product`, `collection`, `key`, `body`, `base_version?` | `{version}`; exit 1 `version_conflict` with `head_version` when someone saved first |
| `cloud.docs.delete` | `product`, `collection`, `key` | `{}` |
| `cloud.docs.versions` | `product`, `collection`, `key` | `{versions: [{version, created, size_bytes}]}` |
| `cloud.files.list` | `product`, `collection` | `{files: [{sha256, size, status, created, download_url}]}` |
| `cloud.files.put` | `product`, `collection`, `content_base64` or `path` | `{file}` |
| `cloud.files.get` | `product`, `collection`, `sha256`, `path?` | `{sha256, size, content_base64}`, or writes `path` |
| `cloud.files.delete` | `product`, `collection`, `sha256` | `{}` |

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

## Events

Meros Event Envelope v1, logged in `events/` and delivered to collectors.

### `events.send`

Input: `events`, an array of:

```json
{"type": "product.subject.verb", "severity": "info",
 "subject": {"kind": "show", "id": "s1", "name": "Main"},
 "actor": {"kind": "user", "id": "u1"},
 "attrs": {"key": "value"}, "trace": "…"}
```

- Only `type` is required. `severity` is `debug`, `info` (default),
  `notice`, `warning`, `error` or `critical`.
- The helper adds the id, time, sequence and source.
- It delivers at once unless `"flush": false`.
- Optional: `edition`, `site`, and `collectors`
  (`[{"url": …, "auth": "signin" | "none"}]`; default: the issuer with the
  session).

Returns `{instance, pending, delivered, accepted, duplicates, rejected,
failed}`. What isn't delivered stays in `events/outbox.json` and goes with
the next `events.send` or `events.flush`, under the same ids. A collector
that already took one counts it as a duplicate.

### `events.flush`

Delivers what's waiting. Same output.

## Testing

The helper's tests run every command against `FakeMeros` (`cargo test
--features cli,fake --test cli`). Point manual runs at a staging issuer,
never production.
