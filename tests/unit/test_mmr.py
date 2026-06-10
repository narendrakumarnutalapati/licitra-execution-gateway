import pytest

from packages.mmr import (
    mmr_append,
    mmr_root,
    mmr_proof,
    mmr_verify_proof,
    mmr_detect_tampering,
    mmr_size,
    reset_mmr_for_testing,
    sha256_hex,
    canonical_json,
    mmr_leaves,
    mmr_peaks,
)


def test_single_leaf_append_changes_root():
    reset_mmr_for_testing()
    result = mmr_append({"event": "test1"})
    root = result["root_hash"]
    assert root != "0" * 64
    assert len(root) == 64
    assert all(c in "0123456789abcdef" for c in root)


def test_seven_leaves_produce_three_peaks():
    reset_mmr_for_testing()
    for i in range(7):
        mmr_append({"event": f"e{i}"})
    assert len(mmr_peaks) == 3
    heights = [p["height"] for p in mmr_peaks]
    assert heights == [2, 1, 0]


def test_proof_verification_passes_for_valid_leaf():
    reset_mmr_for_testing()
    for i in range(7):
        mmr_append({"event": f"e{i}"})
    proof = mmr_proof(3)
    root = mmr_root()
    leaf_hash = mmr_leaves[3]["leaf_hash"]
    assert mmr_verify_proof(leaf_hash, proof, root, 3) is True


def test_proof_fails_for_tampered_leaf_hash():
    reset_mmr_for_testing()
    for i in range(7):
        mmr_append({"event": f"e{i}"})
    proof = mmr_proof(3)
    root = mmr_root()
    assert mmr_verify_proof("a" * 64, proof, root, 3) is False


def test_proof_fails_for_wrong_root():
    reset_mmr_for_testing()
    for i in range(7):
        mmr_append({"event": f"e{i}"})
    proof = mmr_proof(3)
    leaf_hash = mmr_leaves[3]["leaf_hash"]
    assert mmr_verify_proof(leaf_hash, proof, "b" * 64, 3) is False


def test_detect_tampering_returns_intact_on_clean_chain():
    reset_mmr_for_testing()
    for i in range(5):
        mmr_append({"event": f"e{i}"})
    result = mmr_detect_tampering()
    assert result["intact"] is True
    assert result["tampered_leaf_index"] is None


def test_detect_tampering_finds_tampered_leaf():
    reset_mmr_for_testing()
    for i in range(5):
        mmr_append({"event": f"e{i}"})
    mmr_leaves[2]["event_data"] = {"tampered": True}
    result = mmr_detect_tampering()
    assert result["intact"] is False
    assert result["tampered_leaf_index"] == 2


def test_leaf_index_binding_prevents_position_swap():
    reset_mmr_for_testing()
    mmr_append({"event": "first"})
    mmr_append({"event": "second"})
    leaf0_hash = mmr_leaves[0]["leaf_hash"]
    leaf1_hash = mmr_leaves[1]["leaf_hash"]
    swapped = sha256_hex("1" + canonical_json(mmr_leaves[0]["event_data"]))
    assert swapped != leaf0_hash
    assert leaf0_hash != leaf1_hash
