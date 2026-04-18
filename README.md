# stashfs

A tiny FUSE filesystem that stores its entire contents, encrypted, inside a
single regular file. One backing file can host up to **8 independent
volumes** -- one "no password" slot plus up to seven password-protected
slots -- each with its own private file listing.

(Previously named `fly`, then briefly `fyl`. The published PyPI name is
`stashfs`; `fly` is taken on PyPI and `fyl` tripped PyPI's
similar-name check.)

## Usage

```bash
uv sync                                              # install dependencies
uv run stashfs mount <backing> [mountpoint] [--ttl SECONDS] [--debug]
uv run stashfs optimize <backing>                    # reclaim space
```

On mount `stashfs` prompts for a password via `getpass`. The empty
string is a real, stable password that always maps to slot 0; any
non-empty password either unlocks its existing slot (slots 1..7) or
grabs the first free slot to start a new volume. A slot only becomes
"occupied" when the first file is written, and reverts to free when
the last file is removed. If every password slot is occupied and the
provided password matches none of them, the mount fails with
`password does not match`.

Unmount with `fusermount -u <mountpoint>`; `stashfs` also auto-unmounts
after `--ttl` seconds of idleness (default 300).

Directories are supported: `mkdir`, `rmdir`, nested writes (`cp -r`,
`tar x`, file managers), and subtree rename (`mv /a /b`) all work the
way POSIX tools expect. Empty directories persist across unmount.

Every mutation appends fresh chunks (append-only layer for crash
safety) and marks the superseded ones DEAD in a plaintext allocation
table. `stashfs optimize` reads that table and rebuilds the file
with only the live chunks — **no password required**, even when the
container holds multiple password-protected volumes. Locked slots
pass through untouched (with their own marked-dead chunks reclaimed);
pass `--drop-locked` to purge a slot whose password is unknown. Must
not be run while the file is mounted.

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
* **Allocation table leak.** Chunk metadata lives in a plaintext
  allocation table (see `stashfs/allocation.py`): a `STSHALOC`-magic
  chain at the head of the chunk area with one `u32` entry per logical
  chunk (`DEAD` or live-physical-slot). This lets `stashfs optimize`
  reclaim dead chunks **without any password**. An observer of the
  backing file can therefore see, over time, the liveness of every
  chunk and the total live/dead counts. They **cannot** see which slot
  owns which chunk — slot membership stays inside the AEAD envelope.
* **Not a production secrets store.** Compaction is available offline
  via `stashfs optimize`; no protection against physical memory
  inspection, no multi-user keying.

## Development

```bash
uv sync                                     # create the venv
uv run pytest -q                            # run the whole suite
uv run pre-commit run --all-files           # ruff + pyrefly
```

The whole test suite stays under one second. Tests use
`KDFParams.fast()` to keep Argon2id cheap; production mounts use the
full Argon2id cost parameters.
