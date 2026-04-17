# fly

A tiny FUSE filesystem that stores its entire contents, encrypted, inside a
single regular file. One backing file can host up to **8 independent
volumes** -- one "no password" slot plus up to seven password-protected
slots -- each with its own private file listing.

## Usage

```bash
uv sync                                   # install dependencies
uv run python -m fly.fuse_app <backing> [mountpoint] [--ttl SECONDS] [--debug]
```

On mount `fly` prompts for a password via `getpass`. The empty string is
a real, stable password that always maps to slot 0; any non-empty
password either unlocks its existing slot (slots 1..7) or grabs the
first free slot to start a new volume. A slot only becomes "occupied"
when the first file is written, and reverts to free when the last file
is removed. If every password slot is occupied and the provided
password matches none of them, the mount fails with
`password does not match`.

Unmount with `fusermount -u <mountpoint>`; `fly` also auto-unmounts after
`--ttl` seconds of idleness (default 300).

## Security model

* **Cipher:** AES-256-GCM, 4 KiB plaintext per chunk, fresh random nonce
  per chunk write. GCM's built-in tag authenticates every chunk.
* **Key derivation:** Argon2id(password, global_salt) -> master key, then
  HKDF-SHA256 expands the master into a distinct per-slot key.
* **Slot table:** eight 80-byte slots at a fixed offset at the start of
  the backing file. Each slot stores an encrypted wrap of
  `(volume_key, file_table_chunk_id)` under its own per-slot key.
* **Leakage we accept:** the per-slot *occupancy flag* is plaintext, so
  an attacker can observe how many volumes the container holds. This is
  deliberate; it makes "pick the first free slot" easy and avoids
  VeraCrypt-grade steganography tricks.
* **Not a production secrets store.** No compaction of dead chunks, no
  protection against physical memory inspection, no multi-user keying.

## Development

```bash
uv sync                                     # create the venv
uv run pytest -q                            # run the whole suite
uv run pre-commit run --all-files           # ruff + pyrefly
```

The whole test suite stays under one second. Tests use
`KDFParams.fast()` to keep Argon2id cheap; production mounts use the
full Argon2id cost parameters.
