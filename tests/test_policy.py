"""Tests for src.utils.policy — AAGUID attestation policy store."""

from __future__ import annotations

from pathlib import Path

from uon.utils.policy import PolicyStore, is_valid_aaguid

# ── is_valid_aaguid() ────────────────────────────────────────────────


class TestIsValidAaguid:
    def test_valid_lowercase(self) -> None:
        assert is_valid_aaguid("2fc0579f-8113-47ea-b116-bb5a8db9202a") is True

    def test_valid_uppercase(self) -> None:
        assert is_valid_aaguid("2FC0579F-8113-47EA-B116-BB5A8DB9202A") is True

    def test_no_hyphens(self) -> None:
        assert is_valid_aaguid("2fc0579f811347eab116bb5a8db9202a") is False

    def test_too_short(self) -> None:
        assert is_valid_aaguid("2fc0579f-8113-47ea-b116") is False

    def test_non_hex_chars(self) -> None:
        assert is_valid_aaguid("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz") is False

    def test_empty_string(self) -> None:
        assert is_valid_aaguid("") is False


# ── PolicyStore ──────────────────────────────────────────────────────


class TestPolicyStore:
    def test_empty_not_enforcing(self, policy_store: PolicyStore) -> None:
        assert policy_store.is_enforcing is False

    def test_add_makes_enforcing(self, policy_store: PolicyStore) -> None:
        assert policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a") is True
        assert policy_store.is_enforcing is True

    def test_add_duplicate_returns_false(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assert policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a") is False

    def test_add_normalises_to_lowercase(self, policy_store: PolicyStore) -> None:
        policy_store.add("2FC0579F-8113-47EA-B116-BB5A8DB9202A")
        assert "2fc0579f-8113-47ea-b116-bb5a8db9202a" in policy_store.list_aaguids()

    def test_remove_existing(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assert policy_store.remove("2fc0579f-8113-47ea-b116-bb5a8db9202a") is True
        assert policy_store.is_enforcing is False

    def test_remove_missing(self, policy_store: PolicyStore) -> None:
        assert policy_store.remove("2fc0579f-8113-47ea-b116-bb5a8db9202a") is False

    def test_clear_returns_count(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        policy_store.add("00000000-0000-0000-0000-000000000000")
        assert policy_store.clear() == 2
        assert policy_store.is_enforcing is False

    def test_clear_empty_returns_zero(self, policy_store: PolicyStore) -> None:
        assert policy_store.clear() == 0

    def test_list_returns_sorted(self, policy_store: PolicyStore) -> None:
        policy_store.add("ffffffff-ffff-ffff-ffff-ffffffffffff")
        policy_store.add("00000000-0000-0000-0000-000000000000")
        assert policy_store.list_aaguids() == [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ]

    def test_is_allowed_positive(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assert policy_store.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a") is True

    def test_is_allowed_negative(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assert policy_store.is_allowed("00000000-0000-0000-0000-000000000000") is False

    def test_is_allowed_case_insensitive(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assert policy_store.is_allowed("2FC0579F-8113-47EA-B116-BB5A8DB9202A") is True

    def test_persistence_round_trip(self, tmp_policy_file: Path) -> None:
        store1 = PolicyStore(path=tmp_policy_file)
        store1.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")

        store2 = PolicyStore(path=tmp_policy_file)
        assert store2.is_allowed("2fc0579f-8113-47ea-b116-bb5a8db9202a") is True

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        store = PolicyStore(path=tmp_path / "does_not_exist.json")
        assert store.is_enforcing is False
        assert store.list_aaguids() == []


# ── check_credential() ──────────────────────────────────────────────


class TestCheckCredential:
    def test_open_policy_allows_everything(self, policy_store: PolicyStore) -> None:
        assert policy_store.check_credential("2fc0579f-8113-47ea-b116-bb5a8db9202a", False) is None

    def test_open_policy_allows_backup_eligible(self, policy_store: PolicyStore) -> None:
        assert policy_store.check_credential("2fc0579f-8113-47ea-b116-bb5a8db9202a", True) is None

    def test_enforcing_allows_listed(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assert policy_store.check_credential("2fc0579f-8113-47ea-b116-bb5a8db9202a", False) is None

    def test_enforcing_rejects_unlisted(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        result = policy_store.check_credential("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", False)
        assert result is not None
        assert "not in the allowlist" in result

    def test_enforcing_rejects_backup_eligible(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        result = policy_store.check_credential("2fc0579f-8113-47ea-b116-bb5a8db9202a", True)
        assert result is not None
        assert "backup-eligible" in result

    def test_zero_aaguid_rejection_message(self, policy_store: PolicyStore) -> None:
        policy_store.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        result = policy_store.check_credential("00000000-0000-0000-0000-000000000000", False)
        assert result is not None
        assert "zero AAGUID" in result

    def test_zero_aaguid_allowed_when_listed(self, policy_store: PolicyStore) -> None:
        policy_store.add("00000000-0000-0000-0000-000000000000")
        assert policy_store.check_credential("00000000-0000-0000-0000-000000000000", False) is None
