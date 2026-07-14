# Vault Rust

<div align="center">
  <img src="logo.png" alt="Vault Logo" width="200"/>
</div>

## / ! \ Disclaimer / ! \

Vault Rust is a personal project, for fun and to practice Rust. It is **not**
meant for production use. It now protects against overwriting a vault with a
wrong master password, but you remain responsible for your backups: if you
lose the master password, the data is unrecoverable.

## What it is

Vault Rust is a CLI password manager, in the spirit of KeePass. Data is
encrypted with **AES-256-GCM**, the key being derived from your master
password with **Argon2id**. Secrets are wiped from memory (zeroize) once they
are no longer needed.

## Features

- Create an encrypted vault file
- Store / retrieve / list / delete credentials
- Generate secure random passwords
- Interactive shell **and** one-shot command mode (`vault get github`)
- Configurable vault file (`-f` / `$VAULT_FILE`)
- Native file picker when a display is available, keyboard fallback over SSH
- In-memory secret zeroization (master password, keys, decrypted data)

## Installation

### From GitHub

```bash
cargo install --git https://github.com/LittleXa/vault-rust
# a specific version:
cargo install --git https://github.com/LittleXa/vault-rust --tag 1.4.0
```

The binary is named `vault-rust`. To call it `vault`, create an alias or a
symlink (e.g. `ln -sf ~/.cargo/bin/vault-rust ~/.cargo/bin/vault`).

### From sources

```bash
cargo build --release   # binary in target/release/vault-rust
```

### Cross-compile for Linux with Docker

```bash
docker run --rm -v "$PWD":/usr/src/vault-rust -w /usr/src/vault-rust \
  rust:latest cargo build --release --target x86_64-unknown-linux-gnu
```

## Usage

### Interactive shell

Run without arguments to open the interactive shell:

```bash
vault
 >> init          # create a new vault
 >> add github
 >> get github
 >> list
 >> quit          # (or exit, or Ctrl-D)
```

### One-shot commands (great for SSH / scripts)

Pass a command as arguments to run a single action and exit:

```bash
vault init
vault add github
vault get github
vault list
vault delete github
vault gen 24
vault version
```

### Choosing the vault file

By default the vault is `./safe.vault` in the current directory. Override it:

```bash
vault -f ~/perso.vault get gmail
# or via environment variable:
VAULT_FILE=~/perso.vault vault list
```

### Over SSH

The master password is read from the terminal, so allocate a TTY with `-t`:

```bash
ssh -t myserver vault get github
```

If there is no graphical display, `open` / `init` ask for the vault path on
the keyboard instead of opening a file dialog.

## Commands

| Command            | Description                                     |
|--------------------|-------------------------------------------------|
| `init`             | Create a new vault                              |
| `add [alias]`      | Add a new entry                                 |
| `get [alias]`      | Show an entry                                   |
| `list`             | List all entries                                |
| `delete [alias]`   | Delete an entry                                 |
| `gen [length]`     | Generate a password (default length: 20)        |
| `open`             | Open another vault (file picker / path prompt)  |
| `version`          | Show version                                    |
| `help`             | Show help                                       |
| `quit` / `exit`    | Leave the interactive shell (or Ctrl-D)         |

## Prerequisites

- Rust (cargo / rustc)
- Git
