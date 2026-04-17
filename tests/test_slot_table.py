"""Tests for ``fly.slot_table.SlotTable``.

Covers the lifecycle rules the user called out explicitly:

* Slot 0 is reserved for the empty password.
* Non-empty passwords only use slots 1..7.
* ``find_or_create`` returns the first occupied slot that unwraps, else
  the first free one, else raises ``PasswordDoesNotMatch``.
* A slot is only marked occupied when ``associate`` is called.
* ``free`` reverts the slot to a random-looking free state.
"""

from __future__ import annotations

import pytest

from fly.container import N_SLOTS, Container
from fly.crypto import KDF, KDFParams
from fly.slot_table import FLAG_FREE, FLAG_OCCUPIED, PasswordDoesNotMatch, SlotTable
from fly.storage import FileWrapper


@pytest.fixture
def kdf() -> KDF:
    return KDF(KDFParams.fast())


@pytest.fixture
def container(tmp_path) -> Container:
    return Container(FileWrapper(tmp_path / 'backing'))


def _mount(container: Container, kdf: KDF, password: str) -> SlotTable:
    return SlotTable(container, kdf, password)


class TestFreshContainer:
    def test_empty_password_returns_new_slot_0(self, container, kdf):
        st = _mount(container, kdf, '')
        info = st.find_or_create()
        assert info.index == 0
        assert info.is_new is True
        assert info.file_table_chunk_id is None
        assert len(info.volume_key) == 32
        # Nothing was written yet; slot 0 is still free on disk.
        assert container.read_slot(0)[0] == FLAG_FREE

    def test_non_empty_password_returns_first_free_slot(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        info = st.find_or_create()
        assert info.index == 1
        assert info.is_new is True
        assert info.file_table_chunk_id is None


class TestAssociate:
    def test_empty_password_writes_slot_0(self, container, kdf):
        st = _mount(container, kdf, '')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, file_table_chunk_id=7)
        assert container.read_slot(0)[0] == FLAG_OCCUPIED

        st2 = _mount(container, kdf, '')
        reloaded = st2.find_or_create()
        assert reloaded.index == 0
        assert reloaded.is_new is False
        assert reloaded.volume_key == info.volume_key
        assert reloaded.file_table_chunk_id == 7

    def test_first_password_takes_slot_1(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, file_table_chunk_id=42)
        assert info.index == 1
        assert container.read_slot(1)[0] == FLAG_OCCUPIED
        for i in range(2, N_SLOTS):
            assert container.read_slot(i)[0] == FLAG_FREE

    def test_second_distinct_password_takes_next_free(self, container, kdf):
        st_a = _mount(container, kdf, 'alpha')
        info_a = st_a.find_or_create()
        st_a.associate(info_a.index, info_a.volume_key, 1)

        st_b = _mount(container, kdf, 'beta')
        info_b = st_b.find_or_create()
        assert info_b.index == 2
        st_b.associate(info_b.index, info_b.volume_key, 2)
        assert container.read_slot(1)[0] == FLAG_OCCUPIED
        assert container.read_slot(2)[0] == FLAG_OCCUPIED

    def test_remount_finds_existing_slot(self, container, kdf):
        st_a = _mount(container, kdf, 'alpha')
        info_a = st_a.find_or_create()
        st_a.associate(info_a.index, info_a.volume_key, 10)

        st_b = _mount(container, kdf, 'beta')
        info_b = st_b.find_or_create()
        st_b.associate(info_b.index, info_b.volume_key, 20)

        again = _mount(container, kdf, 'alpha').find_or_create()
        assert again.index == 1
        assert again.is_new is False
        assert again.volume_key == info_a.volume_key
        assert again.file_table_chunk_id == 10

        again_b = _mount(container, kdf, 'beta').find_or_create()
        assert again_b.index == 2
        assert again_b.volume_key == info_b.volume_key
        assert again_b.file_table_chunk_id == 20

    def test_refuses_to_overwrite_occupied_slot(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, 1)
        with pytest.raises(RuntimeError):
            st.associate(info.index, info.volume_key, 2)

    def test_empty_password_rejects_non_zero_slot(self, container, kdf):
        st = _mount(container, kdf, '')
        with pytest.raises(ValueError, match='empty password'):
            st.associate(1, b'\x00' * 32, 0)

    def test_non_empty_password_rejects_slot_zero(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        with pytest.raises(ValueError, match='non-empty password'):
            st.associate(0, b'\x00' * 32, 0)


class TestUnknownPassword:
    def test_unknown_password_with_free_slots_returns_new_slot(self, container, kdf):
        st_a = _mount(container, kdf, 'alpha')
        info_a = st_a.find_or_create()
        st_a.associate(info_a.index, info_a.volume_key, 0)

        guess = _mount(container, kdf, 'nope').find_or_create()
        assert guess.is_new is True
        assert guess.index == 2  # slot 1 is taken by alpha

    def test_unknown_password_with_all_slots_full_raises(self, container, kdf):
        for p in (f'pw-{i}' for i in range(1, N_SLOTS)):  # 7 password slots
            st = _mount(container, kdf, p)
            info = st.find_or_create()
            st.associate(info.index, info.volume_key, 0)

        for i in range(1, N_SLOTS):
            assert container.read_slot(i)[0] == FLAG_OCCUPIED

        with pytest.raises(PasswordDoesNotMatch):
            _mount(container, kdf, 'stranger').find_or_create()

    def test_empty_password_never_scans_password_slots(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, 0)

        # slot 0 is still free; empty password returns a new-slot-0 info.
        empty = _mount(container, kdf, '').find_or_create()
        assert empty.index == 0
        assert empty.is_new is True


class TestFree:
    def test_free_marks_slot_free_and_new_password_reuses_it(self, container, kdf):
        st_a = _mount(container, kdf, 'alpha')
        info_a = st_a.find_or_create()
        st_a.associate(info_a.index, info_a.volume_key, 0)
        assert st_a.is_occupied(1)

        st_a.free(1)
        assert not st_a.is_occupied(1)

        gamma = _mount(container, kdf, 'gamma').find_or_create()
        assert gamma.index == 1
        assert gamma.is_new is True

    def test_free_empty_password_slot(self, container, kdf):
        st = _mount(container, kdf, '')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, 0)
        assert st.is_occupied(0)
        st.free(0)
        assert not st.is_occupied(0)

    def test_free_slot_contents_look_random(self, container, kdf):
        st = _mount(container, kdf, '')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, 0)
        occupied = container.read_slot(0)
        st.free(0)
        freed = container.read_slot(0)
        assert freed[0] == FLAG_FREE
        assert freed != occupied
        # The first free byte aside, the remainder is not all-zero.
        assert freed[1:] != b'\x00' * (len(freed) - 1)


class TestUpdate:
    def test_update_changes_chunk_id_and_is_remountable(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, 10)

        st.update(info.index, info.volume_key, 99)
        reloaded = _mount(container, kdf, 'alpha').find_or_create()
        assert reloaded.file_table_chunk_id == 99
        assert reloaded.volume_key == info.volume_key

    def test_update_on_free_slot_raises(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        with pytest.raises(RuntimeError):
            st.update(1, b'\x00' * 32, 0)

    def test_update_rewrites_nonce(self, container, kdf):
        st = _mount(container, kdf, 'alpha')
        info = st.find_or_create()
        st.associate(info.index, info.volume_key, 10)
        blob_a = container.read_slot(1)

        st.update(info.index, info.volume_key, 10)
        blob_b = container.read_slot(1)
        assert blob_a != blob_b
