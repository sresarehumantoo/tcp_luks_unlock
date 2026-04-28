# luks-unlock

A small TCP server/client for delivering LUKS unlock passphrases at boot,
written in C with libsodium. Conceptually similar to Mandos and Tang/Clevis:
the server holds passphrases for authorized clients; clients fetch their own
passphrase during initramfs and pipe it into cryptsetup. No SSH in the
runtime path.

## How it works

- Each side has a long-term **Ed25519** identity keypair.
- The client pins the server's pubkey; the server keeps a directory of
  authorized clients — one file per client, named by the client's pubkey hex,
  whose contents are that client's LUKS passphrase.
- On connect, both sides exchange ephemeral **X25519** keys and sign the
  transcript with their long-term Ed25519 key, giving mutual authentication
  with forward secrecy.
- The session is sealed with libsodium's
  `crypto_secretstream_xchacha20poly1305`.
- After the handshake the server pushes the client's passphrase and closes.
  The client writes it to the configured output (default
  `/lib/cryptsetup/passfifo`) and exits.

## Build

Requires `libsodium-dev`, `gcc` (or `clang`), `make`, and POSIX threads.

```sh
sudo apt install libsodium-dev
make
```

Binaries land in `build/`:

- `build/luks-unlock-server`
- `build/luks-unlock-client`
- `build/luks-unlock-keygen`
- `build/luks-unlock-enroll`

## Setup

### 1. Generate the server identity (once, on the server)

```sh
sudo install -d -m 0700 /etc/luks-unlock
sudo ./build/luks-unlock-keygen /etc/luks-unlock/server.key
# prints SERVER_PUBKEY_HEX on stdout — keep this
```

### 2. Generate a client identity (on each client)

```sh
sudo install -d -m 0700 /etc/luks-unlock
sudo ./build/luks-unlock-keygen /etc/luks-unlock/client.key
# prints CLIENT_PUBKEY_HEX on stdout — keep this
```

### 3. Enroll each client on the server

```sh
sudo install -d -m 0700 /var/lib/luks-unlock/keys
printf '%s' 'YOUR_LUKS_PASSPHRASE' | \
  sudo ./build/luks-unlock-enroll /var/lib/luks-unlock/keys CLIENT_PUBKEY_HEX
```

### 4. Configure

Copy `etc/server.conf.example` → `/etc/luks-unlock/server.conf` on the server.
Copy `etc/client.conf.example` → `/etc/luks-unlock/client.conf` on each client
and fill in `server_host`, `server_port`, and `server_pubkey` (hex from step 1).

### 5. Run the server

```sh
sudo ./build/luks-unlock-server -c /etc/luks-unlock/server.conf
```

### 6. Wire the client into your initramfs

Simplest pattern: an init hook runs the client and pipes its output to
`cryptsetup luksOpen`. See `scripts/cryptroot-tcp-unlock.sh`.

`tools/initramfs_pack.sh` is the legacy unpack/repack helper for editing the
initramfs image directly — edit the variables at the top before running.

## Project layout

```
src/server/        luks-unlock-server (handles connections, looks up keystore)
src/client/        luks-unlock-client (fetches key, writes to output)
src/common/        shared protocol/net/config/log code
include/           public headers for the modules above
third_party/inih/  vendored INI parser (BSD-3, by Ben Hoyt)
tools/             keygen/enroll CLIs and the initramfs packing script
etc/               example configs
scripts/           example initramfs hook
```

## Security notes

- The keystore directory should be `0700`, files `0600`, owned by the user
  running the server. Plaintext passphrases live there at rest by design —
  protect with filesystem perms (or layer dm-crypt under it).
- Forward secrecy: ephemeral X25519 keys are discarded after each session.
  Compromise of a long-term identity does not let an attacker decrypt past
  sessions captured on the wire.
- Mutual authentication: both halves of the handshake are signed and bind to
  each other. A client whose pubkey is not in the keystore directory is
  rejected before any passphrase is touched. A server that does not match the
  client's pinned `server_pubkey` is rejected before any key material is sent.
