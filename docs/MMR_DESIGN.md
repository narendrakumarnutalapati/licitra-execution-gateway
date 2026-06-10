# LICITRA-MMR Design Specification

## Why MMR Instead of Linked Hash Chain

| Log Size | Linked Chain Verify | MMR Inclusion Proof |
|---|---|---|
| 100 events | Instant | Instant — 7 hashes |
| 10,000 events | Noticeable | Instant — 14 hashes |
| 1,000,000 events | Minutes | Instant — 20 hashes |
| Third-party verify | Requires full log | Requires 4-27 hashes only |

## MMR Structure

A Merkle Mountain Range is an append-only sequence of perfect binary trees of decreasing height. Each tree produces a peak hash. All peaks are bagged into a root hash.

Example after 7 leaves:

Hash(0,1,2,3)        Hash(4,5)   Hash(6)
     /      \            /    \       |
Hash(0,1)  Hash(2,3)  Hash(4) Hash(5) Leaf6
 /    \     /    \

Leaf0  Leaf1 Leaf2 Leaf3  Leaf4  Leaf5
Peaks: [Hash(0,1,2,3), Hash(4,5), Hash(6)]
Root:  SHA-256(Hash(0,1,2,3) || Hash(4,5) || Hash(6))

## Leaf Hash Construction

CRITICAL: leaf_index MUST be bound into leaf_hash.
Without this, an attacker can reorder leaves while keeping individual hashes valid.

leaf_hash = SHA-256(
str(leaf_index)
+ canonical_json({
"event_type": "VERIFY_BLOCKED",
"agent_id": "...",
"action": "send_email",
"resource": "cfo@company.com",
"decision": "BLOCKED",
"payload_hash": "sha256:...",
"ticket_id": "...",
"timestamp": "2026-06-09T14:32:01Z"
})
)

Canonical JSON: keys sorted alphabetically, no whitespace, UTF-8 encoded.

## MMR Functions

### mmr_append(event_data_dict, db_session)
1. Get current leaf_count as new leaf_index
2. Compute leaf_hash = SHA-256(str(leaf_index) + canonical_json(event_data))
3. Insert into mmr_leaves
4. Peak merging: while last two peaks have equal height, pop both, push new peak with hash=SHA-256(left||right) and height=prev+1
5. Update mmr_peaks table
6. Compute root = SHA-256(all peak hashes concatenated in order)
7. Compute inclusion proof (sibling hashes) and store in mmr_leaves.proof at insert time
8. Return MMRResult(leaf_index, leaf_hash, root_hash, proof)

### mmr_root(db_session)
Fetch all peaks ordered by position.
Return SHA-256(peak1.hash || peak2.hash || ... || peakN.hash)
If zero peaks: return "0" * 64

### mmr_proof(leaf_index, db_session)
Fetch mmr_leaves row for leaf_index.
Return stored proof JSON array.
Proof computed at insert time — O(log N) length.

### mmr_verify_proof(leaf_hash, proof, root, leaf_index)
Pure computation. No database access.
Starting with leaf_hash, apply each sibling hash in proof.
Left or right position determined by leaf_index bit at each level.
Recompute up to root.
Return True if computed root == provided root, else False.

### mmr_detect_tampering(db_session)
Fetch all mmr_leaves ordered by leaf_index.
For each leaf: recompute SHA-256(str(leaf_index) + canonical_json(event_data))
Compare to stored leaf_hash.
Return TamperingResult(intact=True, tampered_leaf_index=None) if all match.
Return TamperingResult(intact=False, tampered_leaf_index=first_mismatch) if any mismatch.

## Evidence Record MMR Fields
Every evidence record includes:
- mmr_leaf_index: position in MMR
- mmr_leaf_hash: SHA-256 of leaf content
- mmr_root: root hash at time of append
- mmr_proof: list of sibling hashes
- mmr_proof_size: len(proof) — typically 4-27

## Independent Verification
A regulator calls:
1. GET /audit/root — gets current root hash
2. POST /audit/verify-proof with {leaf_hash, proof, root, leaf_index}
3. LICITRA returns valid: true or false

No database access required. Proof is self-contained.

