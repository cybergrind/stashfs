"""Tests for the versioned file-index serialisation (FIDXv002)."""

from __future__ import annotations

import pytest

from stashfs.file_index import FileIndex, FileIndexCorrupt, VolumeFile, parse, serialize


class TestFileIndexRoundTrip:
    def test_round_trip_empty(self):
        idx = FileIndex(files={}, dirs=set())
        assert parse(serialize(idx)) == idx

    def test_round_trip_files_only(self):
        idx = FileIndex(
            files={
                'a.txt': VolumeFile(name='a.txt', size=10, chunk_ids=[0, 1, 2]),
                'nested/file': VolumeFile(name='nested/file', size=4096, chunk_ids=[3]),
            },
            dirs=set(),
        )
        reparsed = parse(serialize(idx))
        assert set(reparsed.files) == set(idx.files)
        for name, vf in idx.files.items():
            assert reparsed.files[name].size == vf.size
            assert reparsed.files[name].chunk_ids == vf.chunk_ids
        assert reparsed.dirs == set()

    def test_round_trip_dirs_only(self):
        idx = FileIndex(files={}, dirs={'a', 'a/b', 'empty'})
        reparsed = parse(serialize(idx))
        assert reparsed.files == {}
        assert reparsed.dirs == {'a', 'a/b', 'empty'}

    def test_round_trip_mixed(self):
        idx = FileIndex(
            files={'docs/readme.md': VolumeFile(name='docs/readme.md', size=5, chunk_ids=[7])},
            dirs={'docs', 'docs/drafts', 'photos'},
        )
        reparsed = parse(serialize(idx))
        assert reparsed == idx


class TestFileIndexCorruption:
    def test_rejects_truncated(self):
        idx = FileIndex(files={}, dirs={'x'})
        blob = serialize(idx)
        with pytest.raises(FileIndexCorrupt):
            parse(blob[:-2])
