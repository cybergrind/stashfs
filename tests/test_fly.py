import errno

import pytest

from fly import MAGIC_BYTES, FileRecord, FileStructure, FileWrapper, Fly


class TestFileWrapper:
    def test_write(self, tmp_path):
        temp_file = tmp_path / 'test_write'
        fw = FileWrapper(temp_file)
        fw.write(10, b'hello')
        assert temp_file.read_bytes() == b'\0' * 10 + b'hello'

    def test_remove_data(self, tmp_path):
        temp_file = tmp_path / 'test_remove_data'
        temp_file.write_bytes(b'\0hello\0')
        fw = FileWrapper(temp_file)
        fw.remove_data(1, 3)
        assert temp_file.read_bytes() == b'\0lo\0'


class TestFileStructure:
    def test_empty(self):
        fs = FileStructure(b'')
        assert fs.files_list == []

    def test_some_files(self):
        fs = FileStructure(b'')
        fr = FileRecord('test_name', 99999, 0)
        fs.files_list.append(fr)
        assert fs.pack() == (
            b'\x01\x00\x00\x00\x09\x00\x00\x00test_name\x9f\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        )

    def test_more_files(self):
        fs = FileStructure(b'')
        fr1 = FileRecord('test_name', 99999, 0)
        fr2 = FileRecord('test_name2', 88888, 0)
        fs.files_list.extend([fr1, fr2])
        assert fs.pack() == (
            b'\x02\x00\x00\x00\x09\x00\x00\x00test_name'
            b'\x9f\x86\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x0a\x00\x00\x00test_name2'
            b'\x38\x5b\x01\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
        )


class WrappedFly(Fly):
    def __init__(self):
        pass


class TestBasicFly:
    def test_add_one_file(self, tmp_path):
        temp_file = tmp_path / 'test_add_one_file'
        temp_file.write_bytes(b'this_is_sample_content')  # len=22

        class FakeArgs:
            fname = temp_file
            mountpoint = ''

        fly = Fly()
        fly.add_args(FakeArgs())
        fly.write('/new_file', b'new_file', 0)
        fly.write('/new_file', b'12345678', 8)

        file1 = fly.fs_structure.files_dict['new_file']
        assert file1.size == 16
        assert file1.offset == 22 + len(MAGIC_BYTES)
        # assert False, fly.fs_structure.files_dict
        assert fly.fs_structure.base_offset == 22 + len(MAGIC_BYTES) + file1.size + 8

    def test_add_two_files(self, tmp_path):
        temp_file = tmp_path / 'test_add_two_files'
        temp_file.write_bytes(b'this_is_sample_content')

        class FakeArgs:
            fname = temp_file
            mountpoint = ''

        fly = Fly()
        fly.add_args(FakeArgs())
        fly.write('/new_file', b'new_file', 0)
        fly.write('/new_file', b'12345678', 8)

        fly.write('/new_file2', b'new_file2', 0)
        fly.write('/new_file2', b'87654321', 8)

        file1 = fly.fs_structure.files_dict['new_file']
        file2 = fly.fs_structure.files_dict['new_file2']
        assert file2.size == 16
        assert file2.offset == 22 + len(MAGIC_BYTES) + file1.size
        assert fly.fs_structure.base_offset == 22 + len(MAGIC_BYTES) + file1.size + file2.size + 8
        assert fly.fs_structure.base_offset == file2.offset + file2.size + 8

        assert fly.file_wrapper.read(8, 22) == MAGIC_BYTES
        assert fly.read('/new_file', 8, 0) == b'new_file'
        assert fly.file_wrapper.read(8, file1.offset) == b'new_file'

        assert fly.read('/new_file2', 16, 0) == b'new_file87654321'
        assert fly.file_wrapper.read(16, file2.offset) == b'new_file87654321'

        fly = Fly()
        fly.add_args(FakeArgs())
        assert fly.read('/new_file', 8, 0) == b'new_file'
        assert fly.read('/new_file2', 16, 0) == b'new_file87654321'

    def test_remove_file(self, tmp_path):
        temp_file = tmp_path / 'test_remove'
        temp_file.write_bytes(b'this_is_sample_content')

        class FakeArgs:
            fname = temp_file
            mountpoint = ''

        fly = Fly()
        fly.add_args(FakeArgs())
        fly.write('/new_file', b'new_file', 0)
        fly.write('/new_file', b'12345678', 8)

        fly.write('/new_file2', b'new_file2', 0)
        fly.write('/new_file2', b'87654321', 8)

        file2 = fly.fs_structure.files_dict['new_file2']
        old_offset = file2.offset

        fly.unlink('/new_file')
        assert 'new_file' not in fly.fs_structure.files_dict

        assert old_offset != file2.offset
        assert fly.read('/new_file2', 16, 0) == b'new_file87654321'
        assert fly.file_wrapper.read(16, file2.offset) == b'new_file87654321'

        fly = Fly()
        fly.add_args(FakeArgs())

        fly.unlink('/new_file2')
        assert len(fly.fs_structure.files_list) == 0
        fly.write('/new_file', b'new_file', 0)
        fly.write('/new_file', b'12345678', 8)

        file1 = fly.fs_structure.files_dict['new_file']
        assert fly.file_wrapper.read(8, 22) == MAGIC_BYTES
        assert fly.read('/new_file', 16, 0) == b'new_file12345678'
        assert fly.file_wrapper.read(8, file1.offset) == b'new_file'


class TestFlyContract:
    """Behavioral tests that lock in the contract of touched Fly methods.

    These use the shared fixtures from conftest.py so adding more cases
    stays cheap.
    """

    def test_rename_returns_enoent(self, fly):
        """rename is currently a stub; it must return -ENOENT.

        This guards against accidental regressions when the duplicate
        definition of `rename` is removed (F811).
        """
        assert fly.rename('/a', '/b') == -errno.ENOENT

    def test_write_swallows_plain_exception_as_eio(self, fly, monkeypatch):
        """Plain exceptions inside write() must be mapped to -errno.EIO.

        FUSE callers expect integer errno-style returns, never Python
        exceptions, so Exception subclasses should be caught.
        """

        def boom(*_args, **_kwargs):
            raise RuntimeError('simulated IO failure')

        monkeypatch.setattr(fly.file_wrapper, 'write_end', boom)
        assert fly.write('/new_file', b'payload', 0) == -errno.EIO

    def test_write_propagates_keyboard_interrupt(self, fly, monkeypatch):
        """KeyboardInterrupt must NOT be swallowed by write().

        With a bare `except:` this test fails (red) because Ctrl+C gets
        converted into -EIO. With `except Exception:` the signal
        propagates, which is the behaviour we want.
        """

        def boom(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(fly.file_wrapper, 'write_end', boom)
        with pytest.raises(KeyboardInterrupt):
            fly.write('/new_file', b'payload', 0)

    def test_unlink_swallows_plain_exception_as_eio(self, fly, monkeypatch):
        """Plain exceptions inside unlink() must be mapped to -errno.EIO."""
        fly.write('/victim', b'data', 0)

        def boom(*_args, **_kwargs):
            raise RuntimeError('simulated IO failure')

        monkeypatch.setattr(fly.file_wrapper, 'reset_handlers', boom)
        assert fly.unlink('/victim') == -errno.EIO

    def test_unlink_propagates_keyboard_interrupt(self, fly, monkeypatch):
        """KeyboardInterrupt must NOT be swallowed by unlink().

        Red with bare `except:`; green with `except Exception:`.
        """
        fly.write('/victim', b'data', 0)

        def boom(*_args, **_kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr(fly.file_wrapper, 'reset_handlers', boom)
        with pytest.raises(KeyboardInterrupt):
            fly.unlink('/victim')


class TestFlyFixtures:
    """Smoke tests that confirm the shared fixtures wire things correctly.

    Keeps fixture regressions loud and obvious.
    """

    def test_make_fly_persists_across_reopen(self, make_fly):
        fly, _path, reopen = make_fly()
        fly.write('/persisted', b'abcdefgh', 0)

        fly2 = reopen()
        assert fly2.read('/persisted', 8, 0) == b'abcdefgh'

    def test_file_wrapper_fixture_is_usable(self, file_wrapper):
        file_wrapper.write(2, b'xy')
        assert file_wrapper.path.read_bytes()[2:4] == b'xy'
