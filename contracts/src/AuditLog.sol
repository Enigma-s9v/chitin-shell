// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title AuditLog
/// @notice Anchors Merkle roots of off-chain audit log batches on-chain,
///         providing tamper-proof auditability. Each commitment records a
///         Merkle root, entry count, time range, and submitter.
/// @dev Non-upgradeable. Merkle proof verification uses a standard sorted-pair
///      algorithm compatible with OpenZeppelin MerkleProof.
contract AuditLog {
    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// @notice A single anchored commitment
    struct Commitment {
        bytes32 merkleRoot;
        uint256 entryCount;
        uint256 fromTimestamp;
        uint256 toTimestamp;
        address submitter;
        uint256 blockNumber;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice Contract owner
    address public owner;

    /// @notice Addresses authorized to submit commitments
    mapping(address => bool) public authorizedSubmitters;

    /// @notice Array of all commitments (commitment ID = array index)
    Commitment[] public commitments;

    /// @notice Latest commitment index per agent DID hash
    mapping(bytes32 => uint256) public latestCommitmentByAgent;

    /// @dev Track whether an agent DID hash has any commitment
    mapping(bytes32 => bool) internal _hasCommitment;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event CommitmentAnchored(
        uint256 indexed commitmentId,
        bytes32 indexed merkleRoot,
        uint256 entryCount,
        uint256 fromTimestamp,
        uint256 toTimestamp,
        address submitter
    );
    event SubmitterAdded(address indexed submitter);
    event SubmitterRemoved(address indexed submitter);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error NotOwner();
    error NotAuthorized();
    error ZeroAddress();
    error InvalidTimeRange();
    error InvalidCommitmentId();
    error NoCommitmentForAgent();
    error AlreadySubmitter();
    error NotSubmitter();

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyAuthorized() {
        if (!authorizedSubmitters[msg.sender] && msg.sender != owner) revert NotAuthorized();
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @notice Deploy the audit log with an initial owner
    /// @param owner_ The contract owner
    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
    }

    // -----------------------------------------------------------------------
    // Commitment Anchoring
    // -----------------------------------------------------------------------

    /// @notice Anchor a new Merkle root commitment on-chain
    /// @param merkleRoot    Root hash of the Merkle tree of audit entries
    /// @param entryCount    Number of entries in this batch
    /// @param fromTimestamp  Earliest entry timestamp in the batch
    /// @param toTimestamp    Latest entry timestamp in the batch
    /// @param agentDidHash  keccak256 of the agent's DID string
    /// @return commitmentId Index of the new commitment
    function anchorCommitment(
        bytes32 merkleRoot,
        uint256 entryCount,
        uint256 fromTimestamp,
        uint256 toTimestamp,
        bytes32 agentDidHash
    ) external onlyAuthorized returns (uint256 commitmentId) {
        if (fromTimestamp > toTimestamp) revert InvalidTimeRange();

        commitmentId = commitments.length;

        commitments.push(Commitment({
            merkleRoot: merkleRoot,
            entryCount: entryCount,
            fromTimestamp: fromTimestamp,
            toTimestamp: toTimestamp,
            submitter: msg.sender,
            blockNumber: block.number
        }));

        latestCommitmentByAgent[agentDidHash] = commitmentId;
        _hasCommitment[agentDidHash] = true;

        emit CommitmentAnchored(
            commitmentId,
            merkleRoot,
            entryCount,
            fromTimestamp,
            toTimestamp,
            msg.sender
        );
    }

    // -----------------------------------------------------------------------
    // Merkle Verification
    // -----------------------------------------------------------------------

    /// @notice Verify that a leaf is included in a commitment's Merkle tree
    /// @param commitmentId The commitment to verify against
    /// @param leaf          The leaf hash to verify
    /// @param proof         Array of sibling hashes from leaf to root
    /// @param index         Leaf index (determines left/right ordering)
    /// @return valid        Whether the proof is valid
    function verifyInclusion(
        uint256 commitmentId,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) external view returns (bool valid) {
        if (commitmentId >= commitments.length) revert InvalidCommitmentId();

        bytes32 computedRoot = leaf;
        uint256 idx = index;

        for (uint256 i = 0; i < proof.length; i++) {
            if (idx % 2 == 0) {
                computedRoot = _hashPair(computedRoot, proof[i]);
            } else {
                computedRoot = _hashPair(proof[i], computedRoot);
            }
            idx /= 2;
        }

        return computedRoot == commitments[commitmentId].merkleRoot;
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    /// @notice Get the total number of commitments
    function getCommitmentCount() external view returns (uint256) {
        return commitments.length;
    }

    /// @notice Get a commitment by ID
    function getCommitment(uint256 id) external view returns (Commitment memory) {
        if (id >= commitments.length) revert InvalidCommitmentId();
        return commitments[id];
    }

    /// @notice Get the latest commitment for an agent
    function getLatestByAgent(bytes32 agentDidHash) external view returns (Commitment memory) {
        if (!_hasCommitment[agentDidHash]) revert NoCommitmentForAgent();
        return commitments[latestCommitmentByAgent[agentDidHash]];
    }

    // -----------------------------------------------------------------------
    // Submitter Management
    // -----------------------------------------------------------------------

    /// @notice Authorize an address to submit commitments
    function addSubmitter(address submitter) external onlyOwner {
        if (submitter == address(0)) revert ZeroAddress();
        if (authorizedSubmitters[submitter]) revert AlreadySubmitter();
        authorizedSubmitters[submitter] = true;
        emit SubmitterAdded(submitter);
    }

    /// @notice Remove an authorized submitter
    function removeSubmitter(address submitter) external onlyOwner {
        if (!authorizedSubmitters[submitter]) revert NotSubmitter();
        authorizedSubmitters[submitter] = false;
        emit SubmitterRemoved(submitter);
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    /// @dev Hash two nodes in sorted order (standard Merkle tree)
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(a, b));
    }
}
