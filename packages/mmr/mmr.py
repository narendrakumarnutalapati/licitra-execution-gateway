import hashlib
import json
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Module-level in-memory stores (replaced by DB in later days)
# ---------------------------------------------------------------------------
mmr_leaves: list = []   # [{leaf_index, leaf_hash, event_data, proof, created_at}]
mmr_peaks: list = []    # [{height, position, hash}]


def reset_mmr_for_testing():
    mmr_leaves.clear()
    mmr_peaks.clear()


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# MMR root
# ---------------------------------------------------------------------------

def mmr_root() -> str:
    if not mmr_peaks:
        return "0" * 64
    combined = "".join(p["hash"] for p in mmr_peaks)
    return sha256_hex(combined)


# ---------------------------------------------------------------------------
# Proof computation
# ---------------------------------------------------------------------------

def _find_peak_for_leaf(leaf_index: int):
    """
    Return (peak_start, peak_size) — the index of the first leaf in the
    power-of-2 subtree (peak) that contains leaf_index, and the size of
    that subtree.
    """
    n = len(mmr_leaves)
    # Walk peaks left-to-right; each peak covers 2^height leaves.
    pos = 0
    for peak in mmr_peaks:
        size = 1 << peak["height"]
        if pos <= leaf_index < pos + size:
            return pos, size
        pos += size
    raise ValueError(f"leaf_index {leaf_index} not found in any peak")


def _compute_proof(leaf_index: int) -> dict:
    """
    Returns {siblings: [...], peaks: [...]}.

    siblings: hashes needed to walk from the leaf up to its subtree root
              (intra-peak Merkle proof).
    peaks:    ordered list of all peak hashes with the leaf's own peak
              replaced by None (sentinel). The verifier substitutes the
              recomputed subtree root in its place, then bags all peaks
              to reproduce the MMR root.
    """
    n = len(mmr_leaves)
    if n == 1:
        # Only one peak — leaf IS the peak; bagging just hashes it alone.
        return {"siblings": [], "peaks": [None], "peak_index": 0}

    peak_start, peak_size = _find_peak_for_leaf(leaf_index)

    # Build intra-peak sibling proof.
    subtree_leaves = [mmr_leaves[peak_start + i]["leaf_hash"] for i in range(peak_size)]
    siblings = []
    idx = leaf_index - peak_start
    nodes = list(subtree_leaves)

    while len(nodes) > 1:
        next_level = []
        i = 0
        while i < len(nodes):
            if i + 1 < len(nodes):
                left, right = nodes[i], nodes[i + 1]
                merged = sha256_hex(left + right)
                if idx == i:
                    siblings.append(right)
                    idx = len(next_level)
                elif idx == i + 1:
                    siblings.append(left)
                    idx = len(next_level)
                next_level.append(merged)
                i += 2
            else:
                if idx == i:
                    idx = len(next_level)
                next_level.append(nodes[i])
                i += 1
        nodes = next_level

    # Record the position of this leaf's peak among all peaks, and the
    # hashes of the other peaks (None marks where the subtree root goes).
    pos = 0
    peak_hashes = []
    this_peak_index = None
    for pi, peak in enumerate(mmr_peaks):
        size = 1 << peak["height"]
        if pos == peak_start:
            peak_hashes.append(None)
            this_peak_index = pi
        else:
            peak_hashes.append(peak["hash"])
        pos += size

    return {"siblings": siblings, "peaks": peak_hashes, "peak_index": this_peak_index}


# ---------------------------------------------------------------------------
# Append
# ---------------------------------------------------------------------------

def mmr_append(event_data: dict) -> dict:
    leaf_index = len(mmr_leaves)
    leaf_hash = sha256_hex(str(leaf_index) + canonical_json(event_data))

    mmr_leaves.append({
        "leaf_index": leaf_index,
        "leaf_hash": leaf_hash,
        "event_data": event_data,
        "proof": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    # Peak merging
    new_peak = {"height": 0, "position": leaf_index, "hash": leaf_hash}
    while mmr_peaks and mmr_peaks[-1]["height"] == new_peak["height"]:
        popped = mmr_peaks.pop()
        merged_hash = sha256_hex(popped["hash"] + new_peak["hash"])
        new_peak = {
            "height": popped["height"] + 1,
            "position": len(mmr_leaves) - 1,
            "hash": merged_hash,
        }
    mmr_peaks.append(new_peak)

    root_hash = mmr_root()

    # Compute and store inclusion proof at INSERT time
    proof = _compute_proof(leaf_index)
    mmr_leaves[leaf_index]["proof"] = proof

    return {
        "leaf_index": leaf_index,
        "leaf_hash": leaf_hash,
        "root_hash": root_hash,
        "proof": proof,
    }


# ---------------------------------------------------------------------------
# Proof retrieval and verification
# ---------------------------------------------------------------------------

def mmr_proof(leaf_index: int) -> dict:
    if leaf_index < 0 or leaf_index >= len(mmr_leaves):
        raise IndexError(f"leaf_index {leaf_index} out of range")
    return _compute_proof(leaf_index)


def mmr_verify_proof(
    leaf_hash: str, proof: dict, root: str, leaf_index: int
) -> bool:
    try:
        siblings = proof["siblings"]
        peak_hashes = proof["peaks"]
        peak_index = proof["peak_index"]

        # Step 1: walk up the intra-peak subtree using siblings.
        current = leaf_hash
        for level, sibling in enumerate(siblings):
            if (leaf_index >> level) & 1 == 0:
                current = sha256_hex(current + sibling)
            else:
                current = sha256_hex(sibling + current)

        # Step 2: reconstruct full peak list and bag to get the MMR root.
        full_peaks = [current if h is None else h for h in peak_hashes]
        bagged = sha256_hex("".join(full_peaks))
        return bagged == root
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def mmr_detect_tampering() -> dict:
    for leaf in mmr_leaves:
        expected = sha256_hex(
            str(leaf["leaf_index"]) + canonical_json(leaf["event_data"])
        )
        if expected != leaf["leaf_hash"]:
            return {"intact": False, "tampered_leaf_index": leaf["leaf_index"]}
    return {"intact": True, "tampered_leaf_index": None}


# ---------------------------------------------------------------------------
# Size
# ---------------------------------------------------------------------------

def mmr_size() -> int:
    return len(mmr_leaves)
