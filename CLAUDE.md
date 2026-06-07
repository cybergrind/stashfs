# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`stashfs` (formerly `fly`, briefly `fyl`) is a small FUSE filesystem that stores its entire contents, encrypted, inside a single regular host file ("backing file"). One backing file can host up to **8 independent volumes** — slot 0 is always the empty-password volume; slots 1–7 hold password-protected volumes. See `README.md` for the security model (AES-256-GCM per 4 KiB chunk, Argon2id → HKDF key derivation, 8×80B slot table).

`TODO.md` tracks ongoing migration work.

## Workflow

**Use red/green TDD.** Write a failing test first, then the minimum implementation to make it pass. Keep each test under 1 second — use `KDFParams.fast()` (cheap Argon2id: 1 iter, 8 MiB) for anything that goes through key derivation. The whole suite is expected to stay under one second.

**Before declaring work done, always run `uv run pytest` and `uv run pre-commit run -a`** and make sure both are clean. These are the gates the user checks against.

## Commands

- `uv sync` — install deps (Python ≥3.13; dev group has ruff, pre-commit, pyrefly).
- `uv run pytest` — full suite. Run this after every change.
- `uv run pytest tests/test_volume.py::TestVolume::test_add_one_file` — single test.
- `uv run pre-commit run -a` — ruff (check + format) and pyrefly across the whole tree. Run this before considering a change complete.
- `uv run stashfs mount <backing_file> [mountpoint] [--ttl 300] [--debug]` — mount. Prompts for password via `getpass`; empty string always maps to slot 0. Auto-unmounts after `--ttl` seconds idle. Debug log goes to `/tmp/stashfs.log`. (`uv run python -m stashfs.fuse_app ...` still works.)
- `uv run stashfs <backing_file>` — shorthand for `stashfs mount <backing_file>`. Triggered when the first positional arg isn't a known subcommand and points at an existing file.
- `uv run stashfs optimize <backing_file> [--password PW ...] [--drop-locked] [--debug]` — rebuild the backing file to reclaim space. **No password required**: each volume commits record superseded chunks in the plaintext allocation table, so `optimize` can compact every slot — including locked ones — without unlocking anything. Must **not** be run while the file is mounted. `--drop-locked` is an explicit destructive opt-in: with it, any occupied slot no supplied `--password` unlocks gets freed (slot wrap cleared + chunks marked dead); CLI prompts for passwords interactively when this flag is set and none were passed.
- `uv run stashfs unmount` (alias `u`) — scan `/proc/mounts` for every active stashfs mount (fstype prefix `fuse.stashfs`) and run `fusermount -u` on each. No arguments; exits non-zero if any unmount fails.
- `uv tool install .` — install the `stashfs` binary globally via uv so it can be invoked as `stashfs ...` outside the repo.

The Python package is `stashfs` (previously `fly`, briefly `fyl`): `fly` is taken on PyPI, and `fyl` tripped PyPI's similar-name check. Current on-disk format is **v2** — magic bytes are `0STSHFMT` (legacy format), `STSHCOVR` (cover footer), and `STSHALOC` (allocation chunk); no containers were in the wild under the old names.

## Architecture

Code lives in the `stashfs/` package. Layered low → high; each module owns one concern and depends only on the layers below it.

1. **`storage.py`** — byte-level backing. `Storage` protocol (`read`/`write`/`truncate`/`size`) with two implementations: `FileWrapper` (plain file) and `CoverStorage` (hides a container inside an existing host file by keeping a 16-byte footer `STSHCOVR`+`QWORD cover_length` at EOF).
2. **`crypto.py`** — primitives only. `KDF` does Argon2id(password, global_salt) → master, HKDF-SHA256 → per-slot key. `KDFParams.fast()` is the test preset. `AEADChunk` seals/opens with AES-256-GCM (12B nonce + ciphertext + 16B tag framed inline). `KEY_SIZE=32`.
3. **`container.py`** — fixed-layout framed chunk store over any `Storage`. On-disk header (32B): `16B salt || 4B format_version || 4B flags || 8B alloc_head_offset`. Slot table is 640B (8×80B) right after the header; chunk area starts at `DATA_START=672`. Every chunk frame is `CHUNK_FRAME_SIZE=4124B` (12+4096+16). Data chunk reads/writes go through `Allocation`, so callers see stable **logical chunk ids** regardless of physical layout. Raises `ContainerCorrupt`.
4. **`allocation.py`** — plaintext allocation table mapping logical chunk id → physical slot (or `DEAD`). Lives as a `STSHALOC`-magic chain of chunk-sized frames in the chunk area; each alloc chunk carries a `u32` count + 1026 `u32` entries. `Allocation.mark_dead(id)` is called by `Volume` at commit time (after the slot wrap is updated) to record superseded chunks so `optimize` can reclaim them *without any password*. Leaks chunk liveness over time but **not** slot ownership.
5. **`slot_table.py`** — password → `(volume_key, file_table_chunk_id)` lookup. Each 80B slot: 1B flag + 68B AEAD frame wrapping `(32B volume_key, 8B chunk_id)` + 11B padding. Invariants: empty password is pinned to slot 0 (never scans 1–7); non-empty passwords never touch slot 0. Free slots are filled with random bytes (only the flag byte at offset 0 is forced to `FLAG_FREE=0x00`) so free/used slots look indistinguishable apart from the flag. Raises `PasswordDoesNotMatch`.
6. **`file_index.py`** — metadata format (**FIDXv002**). `FileIndex(files: dict[str, VolumeFile], dirs: set[str])`. Names may contain `/`; every `/`-prefixed entry is an implicit parent directory. `dirs` records explicit `mkdir`s (so empty dirs persist). Serialised layout: `u32 num_files` + file entries + `u32 num_dirs` + dir-name entries. Chunk-chain magic is `INDEX_MAGIC = b'FIDXv002'` — older chains are refused at open.
7. **`volume.py`** — one password's view of a container. Holds the slot, file list, directory set, and chunk I/O. **Append-only at the chunk layer** — new data is written to fresh chunks; the file index and the slot are rewritten *last*. After the slot wrap commits, `Volume` calls `Container.mark_chunk_dead` on every superseded chunk so `optimize` can later reclaim them. A crash between append and mark-dead leaves data intact; a future commit re-marks. Directory ops: `mkdir`/`rmdir`/`is_dir`/`iter_children(parent)` plus subtree-aware `rename` (rewrites every `_files` key and `_dirs` entry under the old prefix). Not thread-safe (FUSE serializes calls). Raises `VolumeCorrupt`.
8. **`optimize.py`** — offline compaction. Reads the plaintext allocation table, copies only the live chunks into a new file (preserving logical ids so slot wraps and file indexes stay valid untouched), atomically renames over the source. Requires **no password**. `--drop-locked` is the single opt-in destructive mode: supply passwords for every slot you want preserved; occupied slots no supplied password unlocks get freed.
9. **`legacy_fs.py`** — pre-crypto byte-offset layout (`FileStructure`, `FileRecord`, `MAGIC_BYTES`). Kept for backward compat during the migration; new code should not extend it. Old-format blobs without `INDEX_MAGIC` are auto-detected as a single-chunk index.
10. **`fuse_app.py`** — FUSE glue. `Stash(fuse.Fuse)` is a thin wrapper that delegates everything to a `Volume`. Handles password prompt, TTL idle check (updates `_ctime` on every VFS call; `getattr` triggers `auto_unmount` when expired, via a child `multiprocessing.Process` running `fusermount -u`), and error conversion to `-EIO`. Exposes `main`/`mount`/`parse_args`. Also contains the `TIME_PAT` (`/<digits>.<digits>`) quirk — `getattr` fakes an empty regular file for matching paths.

`stashfs/__init__.py` re-exports the public API so `from stashfs import X` keeps working across the split.

## Tests & fixtures

`tests/conftest.py` provides the shared fixtures — reuse them rather than rebuilding from scratch:

- `fast_kdf` — `KDF(KDFParams.fast())`. Use for every test that touches crypto.
- `backing_file` — factory for fresh empty tmp-path backing files.
- `file_wrapper` — `FileWrapper` on an empty backing.
- `password` — parametrized over `''` and a non-empty value, so any test using it runs twice (covers slot-0 and slot-1+ paths).
- `make_stash` — returns `(Stash, path, reopen)` for persistence / remount tests.
- `stash` — ready `Stash` instance, parametrized over `password`.
- `multi_stash` — `MultiStash` helper that yields a factory for mounting the same backing file under several passwords; auto-cleans at teardown.

Test files are organized per module (`test_container.py`, `test_crypto.py`, `test_slot_table.py`, `test_storage.py`, `test_volume.py`); `test_stash.py` contains the integration-style tests against `Stash`.

## Style

Ruff config in `pyproject.toml`: line length 120, single quotes (double for docstrings), target `py314`, isort with 2 lines after imports. `T201` (print) and `G004` (f-string in logging) are intentionally allowed. Pre-commit also runs `pyrefly` for type checks.
