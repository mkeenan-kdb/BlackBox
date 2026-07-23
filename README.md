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

Open `index.html` in a browser, log in, and you get a small vault UI: drag-and-drop file uploads (with per-file progress, multi-file batches), a searchable/tagged file list, image/PDF/text preview, and download. Everything is scoped per authenticated user - one vault, multiple accounts, each user only ever sees their own files.

There's no cloud, no third-party storage, and no account system beyond what you set up yourself on the box it runs on.

## How it works

1. **Frontend → backend transport.** The browser opens a WebSocket to the q process (`html/js/connect.js`) and speaks a small JSON-over-IPC protocol (`html/js/external/c.js` handles the kdb+ serialization). Downloads happen separately over a plain HTTP `GET`, so the browser's native download/streaming path can handle large files instead of piping them through the WebSocket/JSON round trip.
2. **Authentication.** The client sends a userid/password to `authUser`. The backend hashes the password (salted, stretched) and compares it against the `userinfo` table. On success, the server records a session against the WebSocket handle - every subsequent request derives "who is this" from that handle server-side, never from anything the client claims.
3. **Encryption.** On successful login the password is kept **only in browser memory** (`window.sessionPassword`) for the session - it's never sent again and the server never stores or sees the actual encryption key. Each file gets its own random salt; the browser runs PBKDF2 on the session password to derive an AES-256-GCM key, encrypts the file client-side, and only the ciphertext (plus the random IV/salt) is uploaded.
4. **Chunked upload.** The encrypted bytes are base64-encoded and streamed to the server in fixed-size chunks over the WebSocket (`startUpload` → repeated `uploadChunk` → `finishUpload`), so upload memory use stays bounded regardless of file size and a single file is never forced into one WebSocket/JSON message.
5. **Download.** The client requests a short-lived, single-use HTTP download token over the WebSocket, then fetches the ciphertext via `GET /download?...` (handled natively in q via `.z.ph`), and decrypts it client-side with the key re-derived from the session password and the file's stored salt.
6. **Session hygiene.** The tab auto-locks (clears the in-memory password and logs out) after 5 minutes of inactivity. Failed logins are rate-limited per connection.

## Security model

- The server authenticates you (it needs the password once, in cleartext, over the connection, to check it against the stored hash) but it never persists your password or your derived encryption key - only a salted hash for auth, and per-file salts/IVs alongside the ciphertext.
- This means: anyone with access to the vault directory on disk sees only encrypted blobs, not your files.
- It does **not** mean the wire traffic is protected on its own - the WebSocket is currently plain `ws://`, not `wss://`. That's fine on a trusted LAN. If you want to reach your BlackBox from outside your home network, put it behind a TLS-terminating reverse proxy (Caddy, nginx) or a private tunnel (Tailscale, WireGuard) rather than exposing the raw port to the internet.
- There is no password-reset flow. If a user forgets their password, an admin has to set a new one for them via the q console (see below) - there's no way to recover encrypted files without the original password, by design.

## Adding users

There's no self-service sign-up in the UI on purpose - this is a personal/family vault, not a public service. New accounts are created directly from the running q process's console:

```q
addUser `userid`passphrase!("someuser";"their-password")
```

This salts and hashes the password and writes the user record to the `userinfo` table (persisted under `BLACKBOX_DB_DIR`). The user can log in from the web UI immediately after. To change a password, just call `addUser` again for the same `userid` - it upserts.

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
2. `bin/startup.sh` hard-codes `$QHOME/m64/q` (the macOS binary). Change that line to whichever subdirectory matches your Pi's kdb+ install (e.g. a Linux ARM build), or the process won't start.
3. Clone the repo onto the Pi, `export BLACKBOX_HOME=...`, and run `./bin/startup.sh`.
4. The server binds `BLACKBOX_PORT` on all interfaces, so it's reachable from other devices on your LAN at `http://<pi-ip>:50667`. For access away from home, use a private tunnel (Tailscale is the easiest option) rather than port-forwarding - see [Security model](#security-model).
5. Consider running it under `systemd` (or `screen`/`tmux` at minimum) so it survives reboots and SSH disconnects - none of that is set up in this repo yet.
6. Watch your disk. Every upload is written to `BLACKBOX_VAULT_DIR` on the Pi's storage (SD card or attached drive) - there's no free-space check before a write starts, so a nearly-full disk can produce a silently truncated, unrecoverable file. Keep some headroom, especially on smaller SD cards.

## Configuration reference

Defined in `kx/q/starter.q`:

| Setting | Default | Meaning |
|---|---|---|
| `.config.MAXUPLOAD` | 2 GiB | Cap on a single file's base64-encoded size. Must be changed in lockstep with `MAX_UPLOAD_BASE64_BYTES` in `html/js/blackbox.js` - the two are not read from a shared source. |
| `.config.MAXFAILS` | 5 | Failed login attempts allowed per WebSocket connection before further attempts are rejected. |

The "storage used" bar in the UI (`getSystemStats`) compares total uploaded bytes against a **hardcoded 64 GiB constant** in `blackbox.q` - it's cosmetic, not tied to actual free disk space on the host. Don't rely on it to know how much room you actually have left.

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

- No self-service registration or password reset (see [Adding users](#adding-users)) - intentional for a personal vault, but worth knowing before you hand this to family members who'll forget passwords.
- WebSocket transport is unencrypted (`ws://`) by default; see [Security model](#security-model) for how to expose this safely off-LAN.
- No disk-space check before accepting an upload - a write that runs out of space partway through can leave a corrupt file that has to be re-uploaded.
- The "storage used / capacity" indicator is cosmetic (see [Configuration reference](#configuration-reference)), not a real quota.
- Single global vault per install - access control is per-user-account, but there's no sharing, folders, or permission tiers between users.

## License

MIT - see [LICENSE](LICENSE).
