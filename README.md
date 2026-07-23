# BlackBox

BlackBox is a self-hosted, encrypted personal file vault. It was built to run on a small always-on machine at home (a Raspberry Pi in a drawer, say) so you have a physical, private place to keep important files - the digital equivalent of a fireproof box, on hardware you own, on your own network.

The backend is **q/kdb+**. The frontend is plain HTML/CSS/JavaScript with no build step. Files are encrypted **in the browser** before they ever leave the client; the server only ever stores and serves ciphertext.

## Contents

- [What it is](#what-it-is)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Adding users](#adding-users)
- [Getting started](#getting-started)
- [Running on a Raspberry Pi](#running-on-a-raspberry-pi)
- [Configuration reference](#configuration-reference)
- [Directory structure](#directory-structure)
- [Known limitations](#known-limitations)
- [License](#license)

## What it is

Open `index.html` in a browser, log in, and you get a small vault UI: drag-and-drop file uploads (with per-file progress, multi-file batches, and live image thumbnails), a searchable/tagged file list with hierarchical folder navigation (any tag containing `/`, e.g. `Documents/Tax/2026`), image/PDF/text preview, download, version history with the ability to upload a new revision of an existing file, and multi-select batch delete or bulk download as a ZIP. Everything is scoped per authenticated user - one vault, multiple accounts, each user only ever sees their own files - and stays in sync live across every open tab/device for that user.

There's no cloud, no third-party storage, and no account system beyond what you set up yourself on the box it runs on.

## How it works

1. **Frontend → backend transport.** The browser opens a WebSocket to the q process (`html/js/connect.js`) and speaks a small JSON-over-IPC protocol (`html/js/external/c.js` handles the kdb+ serialization). Downloads happen separately over a plain HTTP `GET`, so the browser's native download/streaming path can handle large files instead of piping them through the WebSocket/JSON round trip.
2. **Authentication.** The password itself never crosses the wire, not even at login. The client requests a single-use challenge (`getAuthChallenge`), then proves it knows the password by computing HMAC-MD5 of the server's stored auth hash and the challenge nonce - `authUser` just checks that proof matches. On success, the server records a session against the WebSocket handle - every subsequent request derives "who is this" from that handle server-side, never from anything the client claims.
3. **Key wrapping.** Each user has one random Master Encryption Key (MEK), generated client-side the first time they ever log in and never changed after that. The MEK is itself encrypted ("wrapped") with a key derived (PBKDF2) from the login password, and only that wrapped form is stored server-side. On login, the browser unwraps it into memory (`window.sessionMEK`) - the server never sees the MEK or the password-derived key that protects it.
4. **Per-file encryption.** Every file gets its own random key, generated client-side and wrapped with the session MEK before upload. The file itself is encrypted (AES-256-GCM) with that per-file key; only the ciphertext, its wrapped key, and a random IV are sent to the server. If it's an image, a small downscaled thumbnail is generated client-side and encrypted with that same per-file key, so the grid view can show a real preview without ever fetching the full file.
5. **Chunked upload.** The encrypted bytes are base64-encoded and streamed to the server in fixed-size chunks over the WebSocket (`startUpload` → repeated `uploadChunk` → `finishUpload`), so upload memory use stays bounded regardless of file size and a single file is never forced into one WebSocket/JSON message.
6. **Download.** The client requests a short-lived, single-use HTTP download token over the WebSocket, then fetches the ciphertext via `GET /download?...` (handled natively in q via `.z.ph`), unwraps that file's key with the session MEK, and decrypts client-side.
7. **Live sync.** After an upload or delete, the server pushes a lightweight `fileListUpdated` signal to every other active session (tab, device) for that user, the same broadcast mechanism already used for the online-user count - so other open tabs refresh automatically instead of showing stale state.
8. **Session hygiene.** The tab auto-locks (clears the in-memory password and MEK, and logs out) after 5 minutes of inactivity. Failed logins are rate-limited per connection.

## Security model

- The server never sees your password, your MEK, or any file's encryption key, even in transit - only a salted auth hash, a login proof derived from it, the password-wrapped MEK, and each file's MEK-wrapped key, alongside the ciphertext.
- The auth challenge-response uses HMAC-MD5, not a true zero-knowledge protocol like SRP. q has no SHA-256 or bignum support to build real SRP on safely, and hand-rolling big-integer modular exponentiation in a language never designed for it is a bigger risk than the gap this closes. HMAC-MD5 still means the password is never transmitted or logged anywhere, which is the practical goal here - it just means the server's stored auth hash is "password-equivalent" (whoever has the `userinfo` table can forge a valid login) the same way a stolen bcrypt hash would be for any conventional site. That's an explicit trade-off, not an oversight.
- This means: anyone with access to the vault directory and database on disk sees only encrypted blobs and wrapped keys, never your files or your password.
- It does **not** mean the wire traffic is protected on its own - the WebSocket is currently plain `ws://`, not `wss://`. That's fine on a trusted LAN. If you want to reach your BlackBox from outside your home network, put it behind a TLS-terminating reverse proxy (Caddy, nginx) or a private tunnel (Tailscale, WireGuard) rather than exposing the raw port to the internet.
- **Changing your own password** (the "Change Password" button once logged in) re-wraps your existing MEK under the new password - every file, including everything uploaded before the change, stays readable. Nothing on disk gets re-encrypted.
- **An admin resetting a forgotten password** via the console (`addUser`, below) is a different story: the admin doesn't have the old password, so the previously-wrapped MEK can't be re-wrapped - it's orphaned. The next login bootstraps a brand new MEK automatically, but any file encrypted under the old one becomes permanently unreadable. There's no way around this without knowing the original password, by design - it's the same tradeoff every zero-knowledge-encrypted system makes.

## Adding users

There's no self-service sign-up on purpose - this is a personal/family vault, not a public service. The **first** account always has to be created from the running q process's console:

```q
addUser `userid`passphrase!("someuser";"their-password")
```

This salts and hashes the password and writes the user record to the `userinfo` table (persisted under `BLACKBOX_DB_DIR`). The user can log in from the web UI immediately after, which is when their master encryption key actually gets generated (see [Security model](#security-model)).

Calling `addUser` again for an existing `userid` resets their password - but it's a blunt instrument, appropriate for "this person forgot their password," not for routine password changes. It always breaks access to any file encrypted before the reset (see [Security model](#security-model)). A logged-in user changing their own password from the UI ("Change Password" button) doesn't have this problem.

### Admins and the web-based user management panel

Nobody is an admin by default. Grant it from the console (also the only way - promoting/revoking admin rights over the network felt like a bigger decision than anything else exposed to the web UI):

```q
setAdmin[`someuser; 1b]   / grant
setAdmin[`someuser; 0b]   / revoke
```

Once a user has `isAdmin`, they get an "Admin" button in the header leading to a panel that can create new accounts and delete existing ones (which also deletes every file that account owns - there'd be no way to ever decrypt them again anyway). Creating a user from this panel still never sends the chosen password over the wire: the admin's own browser computes the salted auth hash locally (the same derivation `changePassword` already uses) and sends only that. Admins can't delete their own account from the panel, to avoid locking everyone out.

## Getting started

### Prerequisites

- **kdb+** - the free [Personal Edition](https://kx.com/kdb-personal-edition-download/) is enough. Make sure `$QHOME` is set and the `q` binary for your platform is on it.
- **rlwrap** (optional but used by the provided startup script, for readline history in the console).
- A modern browser (uses `crypto.subtle`, WebSockets, `fetch`).

### Environment variables

`bin/startup.sh` sets these before launching q - adjust `BLACKBOX_HOME` for wherever you clone the repo:

| Variable | Purpose |
|---|---|
| `BLACKBOX_HOME` | Repo root. Not read by the scripts directly but everything else below is derived from it in `startup.sh`. |
| `BLACKBOX_PORT` | Port the WebSocket/HTTP server listens on (default `50667`). |
| `BLACKBOX_KX_HOME` | `kx/` - the q workspace root. |
| `BLACKBOX_Q_SCRIPT_DIR` | `kx/q` - where `starter.q`, `web.q`, `blackbox.q`, `util.q` live. |
| `BLACKBOX_DB_DIR` | `kx/db/qdb` - persisted kdb+ tables (`userinfo`, `uploads`, session history). |
| `BLACKBOX_VAULT_DIR` | `kx/db/vault` - encrypted file storage, one file per upload. |
| `BLACKBOX_USER_CONFIG` | `kx/db/misc/users` - reserved, currently unused by the app logic but required to be set at startup. |
| `BLACKBOX_HTML_DIR` | `html/` - served as the static site root. |

### Running it

```bash
export BLACKBOX_HOME=/path/to/BlackBox
./bin/startup.sh
```

This starts q in dev mode on `BLACKBOX_PORT` (default `50667`) and, on macOS, opens `http://localhost:50667/index.html` in Chrome automatically. On other platforms, just open that URL yourself.

Once it's up, add a user from the q console (see [Adding users](#adding-users)) and log in.

## Running on a Raspberry Pi

This is the intended deployment target - small, silent, always-on, physically in your house.

1. Install a 64-bit kdb+ build for your Pi's OS/architecture and point `$QHOME` at it.
2. `bin/startup.sh` hard-codes `$QHOME/m64/q` (the macOS binary) and is meant for local development only (see below for why). For a real deployment, use `bin/blackbox.service` instead, and change its `ExecStart` line to whichever kdb+ subdirectory matches your Pi (e.g. `l64arm/q`).
3. Clone the repo onto the Pi, edit the paths/user in `bin/blackbox.service` for your install location, then:
   ```bash
   sudo cp bin/blackbox.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now blackbox
   ```
   This runs BlackBox as a proper service - starts on boot, restarts on crash, logs to `journalctl -u blackbox`. It deliberately does **not** reuse `bin/startup.sh`: that script hard-codes `rlwrap` (a readline wrapper for an interactive terminal, which a systemd service doesn't have) and the `-dev` flag (which skips the production error handling in `starter.q` - an uncaught startup error crashes with a raw stack trace instead of logging and exiting cleanly).
4. The server binds `BLACKBOX_PORT` on all interfaces, so it's reachable from other devices on your LAN at `http://<pi-ip>:50667`. For access away from home, use a private tunnel (Tailscale is the easiest option) rather than port-forwarding - see [Security model](#security-model).
5. Set up automated backups the same way:
   ```bash
   sudo cp bin/blackbox-backup.service bin/blackbox-backup.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now blackbox-backup.timer
   ```
   This runs `bin/backup.sh` daily, snapshotting `kx/db/qdb` and `kx/db/vault` to a timestamped tarball (default: `$BLACKBOX_HOME/backups`, keeping the newest 14 - both configurable via `BLACKBOX_BACKUP_DIR`/`BLACKBOX_BACKUP_KEEP` in the unit file). The script only handles the *local* snapshot - point external storage or a cloud backend at that output directory with your own `rclone`/`rsync` job for actual off-box redundancy; that part is provider-specific and deliberately not baked in here.
6. Watch your disk anyway. `startUpload` checks real, live free space on `BLACKBOX_VAULT_DIR`'s filesystem (via `df`) and rejects new uploads once headroom drops below `.config.MIN_DISK_HEADROOM_PCT` (5% by default) - but on a small SD card, that 5% might only be a few hundred MB. Keep an eye on it.

*Caveat: I wrote and manually reviewed the systemd unit files, but couldn't actually execute-test them - macOS has no `systemd-analyze` to verify against, unlike everything else in this README, which was run against a real server before being documented. Check `systemctl status blackbox` after enabling it.*

## Configuration reference

Defined in `kx/q/starter.q`:

| Setting | Default | Meaning |
|---|---|---|
| `.config.MAXUPLOAD` | 2 GiB | Cap on a single file's base64-encoded size. Must be changed in lockstep with `MAX_UPLOAD_BASE64_BYTES` in `html/js/blackbox.js` - the two are not read from a shared source. |
| `.config.MAXFAILS` | 5 | Failed login attempts allowed per WebSocket connection before further attempts are rejected. |
| `.config.MIN_DISK_HEADROOM_PCT` | 5 | `startUpload` rejects new uploads once the vault filesystem's free space (checked live via `df -Pk`) drops below this percentage, or would drop below it once this file is written. |

The "storage used" bar in the UI (`getSystemStats`) is real, not a fixed quota: capacity shown is `(what you've used) + (whatever's actually free on the host disk right now)`, so it shrinks or grows as anything else on that disk - the OS, other apps, other users - uses or frees space.

## Directory structure

```
bin/
  startup.sh        entry point: sets env vars, launches q
html/
  index.html         UI shell
  js/connect.js       WebSocket lifecycle, request/response routing
  js/blackbox.js       encryption, chunked upload/download, UI logic
  js/external/         c.js (kdb+ IPC serialization), jQuery
  css/, img/, fonts/    styling and assets
kx/
  q/
    starter.q          env var validation, startup sequencing
    web.q               WebSocket handlers (.z.wo/.z.ws/.z.wc), HTTP download route (.z.ph)
    blackbox.q          business logic: auth, upload/download, file metadata, user stats
    util.q              password hashing, persistence, misc helpers
  db/
    qdb/                persisted tables: userinfo, uploads, session history (gitignored)
    vault/              encrypted file blobs, one per upload (gitignored)
    misc/users          reserved/unused placeholder
```

## Known limitations

- No self-service registration, and no recovery for a genuinely forgotten password (see [Adding users](#adding-users)) - intentional for a personal vault, but worth knowing before you hand this to family members who'll forget passwords. Changing a *known* password is self-service (see [Security model](#security-model)).
- WebSocket transport is unencrypted (`ws://`) by default; see [Security model](#security-model) for how to expose this safely off-LAN.
- Single global vault per install - access control is per-user-account, but there's no sharing or permission tiers between users.
- Deleting a file only removes that one revision. If older versions exist, the newest remaining one becomes current; there's no "delete this document and all its history" action from the main list.
- Batch ZIP export decrypts and holds every selected file in browser memory before bundling them, so it's sized for "a handful of documents," not your entire vault at once.
- "Folders" aren't a real schema feature - any tag containing `/` is treated as a path client-side. Simple and needs no migration, but it means a folder only exists as long as at least one file has a tag naming it, and renaming a folder means re-tagging every file in it. Matching is exact-depth, like a real filesystem: a file tagged `Documents/Tax/2025` lives *inside* a `2025` folder and won't show up while browsing `Documents` or `Documents/Tax` - you have to click all the way in. Tag shallower (e.g. plain `2025` as a second, non-folder tag alongside `Documents/Tax`) if you want a file to surface higher up.
- Thumbnails only cover images (generated client-side via canvas, zero new dependencies). PDF thumbnails would need an actual PDF renderer - there's no browser-native way to get one, and pulling in something like pdf.js felt like a disproportionate dependency for a nice-to-have in an otherwise no-build-step app. PDFs still show a distinct icon and preview fine, just not a rendered thumbnail.
- The first admin has to be granted from the console (`setAdmin`) - there's no way to become an admin purely from the web UI, by design (see [Adding users](#adding-users)).

## License

MIT - see [LICENSE](LICENSE).
