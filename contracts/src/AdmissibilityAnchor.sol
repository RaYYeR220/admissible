// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title  AdmissibilityAnchor
/// @notice Tamper-evident, time-anchored commitments to what an autonomous agent's memory
///         contained at a given moment, plus a public mirror of the counterparties it refuses.
///
/// @dev WHY THIS EXISTS
///
///      An agent that hires and pays other agents decides with its memory. A memory is only
///      allowed to move money if it is *admissible*: re-derivable from evidence, carrying a
///      provenance envelope whose keccak256 digest fixes the claim. That discipline is enforced
///      offchain. What cannot be enforced offchain is honesty about the past: nothing stops an
///      operator from editing the memory store after the fact and claiming the payment was
///      justified by something it "always knew".
///
///      This contract closes that hole and does nothing else. An agent periodically commits a
///      Merkle root over the digests of every admissible memory it holds, together with the
///      `asOf` watermark of the transaction time up to which that memory is complete. Afterwards
///      anyone - a counterparty, an arbiter, a judge - can ask two questions and get answers the
///      agent cannot retroactively influence:
///
///        1. "What did your memory commit to when you made that decision?"  -> `anchorAt`
///        2. "Was this specific memory in it?"                              -> `verifyMemory`
///
///      Anchors are append-only and their `asOf` watermarks must be non-decreasing. The
///      monotonicity rule is the whole guarantee: if an agent could anchor a root with an older
///      watermark, it could manufacture a more convenient version of what it knew at decision
///      time, and every point-in-time answer above would become worthless.
///
/// @dev GOVERNANCE - DELIBERATELY ABSENT
///
///      There is no owner, no admin, no upgrade path, no pause, no registry of blessed agents.
///      Every write is namespaced to `msg.sender`, so an agent can only ever append to its own
///      history and flag on its own behalf. Nothing here custodies value or arbitrates disputes,
///      so there is nothing that a privileged role could usefully do - while such a role could
///      censor anchors, rewrite the flag registry, or (via an upgrade) forge history. A
///      governance surface would be pure liability against a contract whose only product is the
///      credibility of its append-only log. Its absence is the feature.
///
/// @dev LEAF CONVENTION
///
///      A memory's identity is `digest = keccak256(canonical claim bytes)`, produced offchain by
///      the provenance envelope. The Merkle *leaf* is one further hash of that digest:
///
///          leaf = keccak256(abi.encodePacked(digest))     // see `leafOf`
///
///      The extra hash is not ceremony. Internal nodes of this tree are always keccak256 over a
///      64-byte preimage; leaves are keccak256 over a 32-byte preimage. Domain separation by
///      preimage length is what stops a second-preimage attack in which an attacker submits an
///      internal node as if it were a leaf and "proves" the inclusion of a memory that was never
///      written. Build the tree offchain over `leafOf(digest)` values, never over raw digests.
contract AdmissibilityAnchor {
    // -------------------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------------------

    /// @notice One immutable commitment to the contents of an agent's admissible memory.
    /// @param root      Merkle root over `leafOf(digest)` for every admissible memory held.
    ///                  `bytes32(0)` if and only if the agent held none.
    /// @param asOf      Agent-supplied transaction-time watermark: the memory is complete up to
    ///                  this instant. This, not `anchoredAt`, is what point-in-time queries use,
    ///                  because an agent's knowledge is dated by its data, not by when it got
    ///                  around to publishing a commitment to it.
    /// @param leafCount Number of leaves in the tree. Lets a reader detect a silently shrinking
    ///                  memory (evidence quietly dropped) without opening the tree itself.
    /// @param anchoredAt  `block.timestamp` of the anchoring transaction - the chain's own
    ///                  opinion of when this claim became unforgeable.
    /// @param blockNumber `block.number` of the anchoring transaction, for log replay and for
    ///                  citing an archive-node state at an exact height.
    /// @param agent     Author of the anchor (`msg.sender`). Redundant with the mapping key, and
    ///                  it does cost a third storage slot, but it makes a single struct read
    ///                  self-describing for an offchain indexer that never sees the key.
    struct Anchor {
        bytes32 root; //        slot 0
        uint64 asOf; //         slot 1 [ 0..8  )
        uint32 leafCount; //    slot 1 [ 8..12 )
        uint64 anchoredAt; //   slot 1 [12..20 )
        uint64 blockNumber; //  slot 1 [20..28 )
        address agent; //       slot 2
    }

    /// @notice An agent's public refusal record for one counterparty.
    /// @param evidenceDigest keccak256 of the evidence bundle that justifies the flag. The flag
    ///                       is a pointer, not an accusation: without a digest another agent
    ///                       cannot check the reasoning, so the digest is mandatory.
    /// @param flaggedAt      When suspicion began. Preserved across a re-flag with new evidence.
    /// @param unflaggedAt    When the flag was lifted, or 0 if it never was.
    /// @param active         Current state. Flags are marked, never deleted.
    /// @param reason         Human-readable justification for the flag.
    /// @param clearedReason  Human-readable justification for lifting it, empty while active.
    struct Flag {
        bytes32 evidenceDigest;
        uint64 flaggedAt;
        uint64 unflaggedAt;
        bool active;
        string reason;
        string clearedReason;
    }

    // -------------------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------------------

    /// @dev A tree with leaves needs a root, and a tree with no leaves must commit to
    ///      `bytes32(0)`. Any other combination is a bug in the caller's tree builder, and
    ///      accepting it would let `leafCount` drift away from the thing it is supposed to
    ///      describe.
    error RootLeafCountMismatch(bytes32 root, uint32 leafCount);

    /// @dev The submitted watermark predates the agent's last one. Rejected: see the
    ///      monotonicity note in the contract docs.
    error AsOfRegression(uint64 lastAsOf, uint64 submittedAsOf);

    /// @dev The agent has never anchored anything.
    error NoAnchors(address agent);

    /// @dev No anchor of `agent` carries a watermark at or before `whenAsOf`, so the agent's
    ///      memory at that moment is genuinely unknown. Returning a later anchor instead would
    ///      be a lie about what it knew; returning nothing at all is the honest answer.
    error NoAnchorAsOf(address agent, uint64 whenAsOf);

    /// @dev Index past the end of the agent's history. This reverts rather than returning
    ///      `false` from `verifyMemory`, because "you asked about an anchor that does not exist"
    ///      and "this memory was not in that anchor" are different answers and must not be
    ///      confusable by a caller that gates a payment on the result.
    error AnchorIndexOutOfRange(address agent, uint256 index, uint256 length);

    /// @dev Evidence digest omitted. A flag with no checkable evidence is a rumour.
    error EvidenceRequired();

    /// @dev `unflag` on an actor that is not currently flagged by this agent.
    error NotFlagged(address agent, bytes32 actorHash);

    // -------------------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------------------

    /// @notice Emitted on every anchor. Carries the full record so that an indexer can rebuild
    ///         an agent's entire history from logs alone, without a single archive call.
    event MemoryAnchored(
        address indexed agent,
        uint256 indexed anchorIndex,
        bytes32 indexed root,
        uint64 asOf,
        uint32 leafCount,
        uint64 anchoredAt,
        uint64 blockNumber
    );

    /// @notice Emitted when an agent flags a counterparty, including on re-flag with fresh
    ///         evidence. `firstTime` distinguishes a new refusal from a strengthened one.
    event ActorFlagged(
        address indexed agent,
        bytes32 indexed actorHash,
        bytes32 indexed evidenceDigest,
        uint64 flaggedAt,
        bool firstTime,
        string reason
    );

    /// @notice Emitted when an agent lifts a flag. The record survives in storage and in this
    ///         log, so a cleared counterparty can prove it was cleared and a careless flagger
    ///         cannot quietly erase a bad call.
    event ActorUnflagged(address indexed agent, bytes32 indexed actorHash, uint64 unflaggedAt, string reason);

    // -------------------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------------------

    /// @dev agent => append-only anchor history, ordered by non-decreasing `asOf`.
    mapping(address => Anchor[]) private _anchors;

    /// @dev agent => actorHash => that agent's refusal record for that counterparty.
    mapping(address => mapping(bytes32 => Flag)) private _flags;

    // -------------------------------------------------------------------------------------
    // Anchoring
    // -------------------------------------------------------------------------------------

    /// @notice Commit to the exact contents of your admissible memory as of a stated moment.
    /// @dev Called by the agent itself; the record is filed under `msg.sender` and no other
    ///      namespace is reachable. The entry is appended, never replaced, so an agent's history
    ///      only ever grows and a published anchor can never be walked back - which is precisely
    ///      what makes a later payment decision auditable rather than merely asserted.
    /// @param root      Merkle root over `leafOf(digest)` for every admissible memory, using
    ///                  sorted-pair keccak256 hashing. Pass `bytes32(0)` with `leafCount == 0`
    ///                  to state on the record that you hold no admissible memory at all - a
    ///                  meaningful claim, and the honest thing to publish before the first
    ///                  interaction rather than staying silent.
    /// @param asOf      Transaction-time watermark, in seconds. Must be >= your previous anchor's.
    /// @param leafCount Number of leaves in the tree.
    /// @return index    Position of the new anchor in your history.
    function anchor(bytes32 root, uint64 asOf, uint32 leafCount) external returns (uint256 index) {
        if ((root == bytes32(0)) != (leafCount == 0)) {
            revert RootLeafCountMismatch(root, leafCount);
        }

        Anchor[] storage history = _anchors[msg.sender];
        uint256 length = history.length;

        if (length != 0) {
            // Non-decreasing: re-anchoring at an unchanged watermark is legitimate (memory was
            // pruned or re-derived without new evidence arriving); moving backwards is not.
            uint64 lastAsOf = history[length - 1].asOf;
            if (asOf < lastAsOf) revert AsOfRegression(lastAsOf, asOf);
        }

        history.push(
            Anchor({
                root: root,
                asOf: asOf,
                leafCount: leafCount,
                anchoredAt: uint64(block.timestamp),
                blockNumber: uint64(block.number),
                agent: msg.sender
            })
        );

        index = length;

        emit MemoryAnchored(msg.sender, index, root, asOf, leafCount, uint64(block.timestamp), uint64(block.number));
    }

    /// @notice How many anchors an agent has published. The count itself is evidence: an agent
    ///         that anchors once and then goes quiet is making a much weaker claim than one that
    ///         anchors continuously.
    function anchorCount(address agent) external view returns (uint256) {
        return _anchors[agent].length;
    }

    /// @notice Read one anchor by position, for callers walking a history they already indexed.
    function getAnchor(address agent, uint256 index) external view returns (Anchor memory) {
        Anchor[] storage history = _anchors[agent];
        if (index >= history.length) revert AnchorIndexOutOfRange(agent, index, history.length);
        return history[index];
    }

    /// @notice The agent's most recent commitment - what it claims to know right now.
    function latestAnchor(address agent) external view returns (uint256 index, Anchor memory anchorRecord) {
        Anchor[] storage history = _anchors[agent];
        uint256 length = history.length;
        if (length == 0) revert NoAnchors(agent);
        unchecked {
            index = length - 1; // length != 0
        }
        anchorRecord = history[index];
    }

    /// @notice Answer "what did this agent's memory commit to at that moment?" for any moment.
    /// @dev This is the function that makes the whole scheme public rather than private. A
    ///      counterparty disputing a refusal, or an arbiter reviewing a payment, does not have to
    ///      trust our indexer or ask us for logs: given the timestamp of the decision they can
    ///      recover the root that was current then, and then demand inclusion proofs against it.
    ///
    ///      Returns the *latest* anchor whose watermark is at or before `whenAsOf`, found by
    ///      binary search over the non-decreasing `asOf` sequence. If several anchors share that
    ///      watermark the last one wins, which is the agent's most refined statement about that
    ///      instant. Reverts with `NoAnchorAsOf` when the moment predates the agent's first
    ///      anchor - the agent's memory then is unknowable, and any answer would be a fabrication.
    /// @param agent     Agent whose history to search.
    /// @param whenAsOf  The moment in question, in the same units as `asOf`.
    function anchorAt(address agent, uint64 whenAsOf)
        external
        view
        returns (uint256 index, bytes32 root, uint64 asOf, uint64 blockNumber)
    {
        Anchor[] storage history = _anchors[agent];
        uint256 upper = _upperBound(history, whenAsOf);
        if (upper == 0) revert NoAnchorAsOf(agent, whenAsOf);

        unchecked {
            index = upper - 1; // upper != 0
        }
        Anchor storage found = history[index];
        return (index, found.root, found.asOf, found.blockNumber);
    }

    // -------------------------------------------------------------------------------------
    // Inclusion proofs
    // -------------------------------------------------------------------------------------

    /// @notice Prove that a specific memory was inside a specific published commitment.
    /// @dev The counterpart to `anchorAt`: that one recovers *which* root was in force, this one
    ///      settles whether a given memory was under it. Together they turn "my memory said so"
    ///      into something a third party can check. Standard sorted-pair Merkle verification -
    ///      written out here rather than imported so the contract carries no external dependency
    ///      for a reviewer to audit alongside it.
    /// @param leaf  `leafOf(digest)`, not the raw memory digest. See the leaf convention above.
    /// @return True only if `leaf` is provably under the stored root.
    function verifyMemory(address agent, uint256 anchorIndex, bytes32 leaf, bytes32[] calldata proof)
        public
        view
        returns (bool)
    {
        Anchor[] storage history = _anchors[agent];
        if (anchorIndex >= history.length) {
            revert AnchorIndexOutOfRange(agent, anchorIndex, history.length);
        }

        Anchor storage target = history[anchorIndex];

        // An empty commitment contains nothing, and `bytes32(0)` is not a real keccak256 output.
        // Without these two guards, `leaf == 0` with an empty proof would verify against the
        // `root == 0` of an empty tree and let an agent "prove" a memory it never had.
        if (target.leafCount == 0 || leaf == bytes32(0)) return false;

        return _processProof(leaf, proof) == target.root;
    }

    /// @notice Inclusion proof against the agent's current commitment.
    /// @dev The convenience form for the live path: a paying agent checking a counterparty right
    ///      now cares about the newest root and should not have to fetch an index first.
    function verifyLatest(address agent, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        uint256 length = _anchors[agent].length;
        if (length == 0) revert NoAnchors(agent);
        unchecked {
            return verifyMemory(agent, length - 1, leaf, proof); // length != 0
        }
    }

    /// @notice Canonical leaf for a memory digest: `keccak256(abi.encodePacked(digest))`.
    /// @dev Exposed so the offchain tree builder and the onchain verifier can never disagree
    ///      about the convention. The second hash is a security requirement, not a formality -
    ///      it separates the 32-byte leaf preimage from the 64-byte internal-node preimage and
    ///      thereby blocks the classic second-preimage forgery. See the leaf convention above.
    function leafOf(bytes32 memoryDigest) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(memoryDigest));
    }

    // -------------------------------------------------------------------------------------
    // Flag registry mirror
    // -------------------------------------------------------------------------------------

    /// @notice Publish, onchain, that you refuse to deal with a counterparty - and why.
    /// @dev The onchain shadow of the offchain FLAGGED tier. A refusal that lives only in the
    ///      agent's private store is unfalsifiable and unusable by anyone else; mirrored here it
    ///      becomes checkable by the accused and reusable by other agents, at the price of the
    ///      flagger's own reputation if the evidence does not hold up.
    ///
    ///      Re-flagging an already-flagged actor updates the evidence and reason but preserves
    ///      the original `flaggedAt`, because the moment suspicion began is itself evidence and
    ///      must not be silently refreshed.
    /// @param actorHash      `keccak256(abi.encodePacked(lowercased address or handle))`. Hashed
    ///                       rather than stored plainly so the registry is checkable by anyone
    ///                       who already knows the counterparty, without publishing a scrapeable
    ///                       blacklist of identities to anyone who does not.
    /// @param evidenceDigest keccak256 of the evidence bundle behind the refusal. Required.
    /// @param reason         Short human-readable justification.
    function flag(bytes32 actorHash, bytes32 evidenceDigest, string calldata reason) external {
        if (evidenceDigest == bytes32(0)) revert EvidenceRequired();

        Flag storage record = _flags[msg.sender][actorHash];

        bool firstTime = !record.active;
        if (firstTime) {
            record.flaggedAt = uint64(block.timestamp);
            record.unflaggedAt = 0;
            record.active = true;
            if (bytes(record.clearedReason).length != 0) delete record.clearedReason;
        }

        record.evidenceDigest = evidenceDigest;
        record.reason = reason;

        emit ActorFlagged(msg.sender, actorHash, evidenceDigest, record.flaggedAt, firstTime, reason);
    }

    /// @notice Withdraw a refusal you previously published.
    /// @dev Marks, never deletes. The flag stays readable with `unflaggedAt` and the withdrawal
    ///      reason set, so the record of having accused someone survives the retraction: an agent
    ///      that flags carelessly cannot launder its history by cleaning up afterwards, and a
    ///      cleared counterparty keeps a citable proof that it was cleared.
    function unflag(bytes32 actorHash, string calldata reason) external {
        Flag storage record = _flags[msg.sender][actorHash];
        if (!record.active) revert NotFlagged(msg.sender, actorHash);

        record.active = false;
        record.unflaggedAt = uint64(block.timestamp);
        record.clearedReason = reason;

        emit ActorUnflagged(msg.sender, actorHash, uint64(block.timestamp), reason);
    }

    /// @notice Does `agent` currently refuse `actorHash`, and on what basis?
    /// @dev The read another agent performs before paying. Deliberately returns the evidence
    ///      digest alongside the boolean: a flag is only worth acting on if the caller can go and
    ///      check the evidence behind it, so the pointer travels with the verdict.
    /// @return flagged        True only while the flag is active.
    /// @return evidenceDigest Digest of the evidence bundle (retained after unflagging).
    /// @return flaggedAt      When the flag was first raised, 0 if it never was.
    /// @return reason         The stated reason for the flag.
    function isFlagged(address agent, bytes32 actorHash)
        external
        view
        returns (bool flagged, bytes32 evidenceDigest, uint64 flaggedAt, string memory reason)
    {
        Flag storage record = _flags[agent][actorHash];
        return (record.active, record.evidenceDigest, record.flaggedAt, record.reason);
    }

    /// @notice The full refusal record, including the withdrawal if there was one.
    /// @dev `isFlagged` answers the live question; this answers the historical one - whether an
    ///      agent ever flagged this counterparty and what it said when it backed down.
    function flagRecord(address agent, bytes32 actorHash) external view returns (Flag memory) {
        return _flags[agent][actorHash];
    }

    // -------------------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------------------

    /// @dev First index whose `asOf` is strictly greater than `whenAsOf`, by binary search over
    ///      the non-decreasing watermark sequence. `history.length` if there is none.
    function _upperBound(Anchor[] storage history, uint64 whenAsOf) private view returns (uint256) {
        uint256 low = 0;
        uint256 high = history.length;

        while (low < high) {
            uint256 mid;
            unchecked {
                // `low <= high <= history.length`, and an array of anchors cannot approach
                // 2**255 entries, so the sum cannot overflow.
                mid = (low + high) >> 1;
                if (history[mid].asOf <= whenAsOf) {
                    low = mid + 1; // mid < high <= length, so mid + 1 cannot overflow
                } else {
                    high = mid;
                }
            }
        }

        return low;
    }

    /// @dev Fold a sorted-pair Merkle proof from `leaf` up to a candidate root.
    function _processProof(bytes32 leaf, bytes32[] calldata proof) private pure returns (bytes32 computed) {
        computed = leaf;
        uint256 length = proof.length;

        for (uint256 i = 0; i < length;) {
            bytes32 sibling = proof[i];
            // Sorted pairs: the tree is order-independent at each node, so a proof does not need
            // to carry left/right positions and the verifier does not need an index.
            computed = computed < sibling ? _hashPair(computed, sibling) : _hashPair(sibling, computed);
            unchecked {
                ++i; // bounded by proof.length
            }
        }
    }

    /// @dev keccak256 of two words, using the reserved scratch space so no memory is allocated.
    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }
}
