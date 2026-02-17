// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title ProofVerifier
/// @notice On-chain verification of Chitin Shell ZKP proofs.
///         Verifies commitment openings, provenance bindings, non-leakage proofs,
///         and stores verification records for audit.
/// @dev Uses SHA-256 precompile for gas-efficient hashing. No upgradeable proxy
///      needed — this is a stateless verifier with optional record storage.
contract ProofVerifier {
    // -------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------

    enum ProofType { Provenance, NonLeakage, SkillSafety }

    struct VerificationRecord {
        bytes32 intentHash;
        ProofType proofType;
        bool verified;
        address submitter;
        uint256 timestamp;
        bytes32 proofHash;     // H(all proof data)
    }

    // -------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------

    address public owner;

    /// @notice Authorized submitters who can record proofs
    mapping(address => bool) public authorizedSubmitters;

    /// @notice All verification records
    VerificationRecord[] public records;

    /// @notice intentHash => latest record index (1-indexed, 0 = no record)
    mapping(bytes32 => uint256) public latestRecordByIntent;

    /// @notice Total verification count by type
    mapping(ProofType => uint256) public verificationCount;

    // -------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------

    event ProofVerified(
        bytes32 indexed intentHash,
        ProofType indexed proofType,
        bool verified,
        address submitter
    );
    event SubmitterAdded(address indexed submitter);
    event SubmitterRemoved(address indexed submitter);

    // -------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------

    error NotOwner();
    error NotAuthorized();
    error ZeroAddress();
    error AlreadySubmitter();
    error NotSubmitter();
    error LengthMismatch();

    // -------------------------------------------------------------------
    // Internal auth helpers (extracted from modifiers to reduce bytecode)
    // -------------------------------------------------------------------

    function _requireOwner() internal view {
        if (msg.sender != owner) revert NotOwner();
    }

    function _requireAuthorized() internal view {
        if (!authorizedSubmitters[msg.sender] && msg.sender != owner) revert NotAuthorized();
    }

    // -------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------

    modifier onlyOwner() {
        _requireOwner();
        _;
    }

    modifier onlyAuthorized() {
        _requireAuthorized();
        _;
    }

    // -------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------

    constructor(address owner_) {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        authorizedSubmitters[owner_] = true;
    }

    // -------------------------------------------------------------------
    // Pure Verification Functions (anyone can call)
    // -------------------------------------------------------------------

    /// @notice Verify a SHA-256 commitment opening
    /// @param commitment The commitment hash (SHA-256)
    /// @param value The committed value
    /// @param blindingFactor The random blinding factor
    /// @return valid Whether the opening is valid
    function verifyCommitment(
        bytes32 commitment,
        bytes calldata value,
        bytes32 blindingFactor
    ) external pure returns (bool valid) {
        bytes32 computed = sha256(abi.encodePacked(value, blindingFactor));
        return computed == commitment;
    }

    /// @notice Verify a provenance binding
    /// @param promptCommitment Commitment to the prompt
    /// @param intentHash Hash of the intent
    /// @param derivationBinding The binding hash to verify
    /// @param timestamp The timestamp used in binding
    /// @return valid Whether the binding is correct
    function verifyProvenance(
        bytes32 promptCommitment,
        bytes32 intentHash,
        bytes32 derivationBinding,
        uint256 timestamp
    ) external pure returns (bool valid) {
        bytes32 computed = sha256(
            abi.encodePacked(promptCommitment, intentHash, timestamp)
        );
        return computed == derivationBinding;
    }

    /// @notice Verify combined proof hash
    /// @param provenanceHash Hash of the provenance proof (or bytes32(0) if absent)
    /// @param nonLeakageHash Hash of the non-leakage proof (or bytes32(0) if absent)
    /// @param skillSafetyHash Hash of the skill safety proof (or bytes32(0) if absent)
    /// @param combinedHash The expected combined hash
    /// @return valid Whether the combined hash is correct
    function verifyCombinedHash(
        bytes32 provenanceHash,
        bytes32 nonLeakageHash,
        bytes32 skillSafetyHash,
        bytes32 combinedHash
    ) external pure returns (bool valid) {
        bytes32 computed = sha256(
            abi.encodePacked(provenanceHash, nonLeakageHash, skillSafetyHash)
        );
        return computed == combinedHash;
    }

    // -------------------------------------------------------------------
    // Record Functions (authorized submitters only)
    // -------------------------------------------------------------------

    /// @notice Record a verified proof on-chain
    function recordProof(
        bytes32 intentHash,
        ProofType proofType,
        bool verified,
        bytes32 proofHash
    ) external onlyAuthorized returns (uint256 recordId) {
        recordId = records.length;
        records.push(VerificationRecord({
            intentHash: intentHash,
            proofType: proofType,
            verified: verified,
            submitter: msg.sender,
            timestamp: block.timestamp,
            proofHash: proofHash
        }));

        latestRecordByIntent[intentHash] = recordId + 1; // 1-indexed
        verificationCount[proofType]++;

        emit ProofVerified(intentHash, proofType, verified, msg.sender);
    }

    /// @notice Record multiple proofs in a batch (gas efficient)
    function recordProofBatch(
        bytes32[] calldata intentHashes,
        ProofType[] calldata proofTypes,
        bool[] calldata verifiedFlags,
        bytes32[] calldata proofHashes
    ) external onlyAuthorized {
        uint256 len = intentHashes.length;
        if (len != proofTypes.length || len != verifiedFlags.length || len != proofHashes.length) {
            revert LengthMismatch();
        }

        for (uint256 i = 0; i < len; i++) {
            uint256 recordId = records.length;
            records.push(VerificationRecord({
                intentHash: intentHashes[i],
                proofType: proofTypes[i],
                verified: verifiedFlags[i],
                submitter: msg.sender,
                timestamp: block.timestamp,
                proofHash: proofHashes[i]
            }));

            latestRecordByIntent[intentHashes[i]] = recordId + 1;
            verificationCount[proofTypes[i]]++;

            emit ProofVerified(intentHashes[i], proofTypes[i], verifiedFlags[i], msg.sender);
        }
    }

    // -------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------

    /// @notice Get total number of records
    function getRecordCount() external view returns (uint256) {
        return records.length;
    }

    /// @notice Get the latest verification status for an intent
    function getLatestVerification(bytes32 intentHash)
        external view returns (bool exists, VerificationRecord memory record)
    {
        uint256 idx = latestRecordByIntent[intentHash];
        if (idx == 0) return (false, record);
        return (true, records[idx - 1]);
    }

    /// @notice Check if an intent has been verified with a specific proof type
    function isVerified(bytes32 intentHash, ProofType proofType)
        external view returns (bool)
    {
        uint256 idx = latestRecordByIntent[intentHash];
        if (idx == 0) return false;
        VerificationRecord storage rec = records[idx - 1];
        return rec.proofType == proofType && rec.verified;
    }

    // -------------------------------------------------------------------
    // Admin
    // -------------------------------------------------------------------

    function addSubmitter(address submitter) external onlyOwner {
        if (submitter == address(0)) revert ZeroAddress();
        if (authorizedSubmitters[submitter]) revert AlreadySubmitter();
        authorizedSubmitters[submitter] = true;
        emit SubmitterAdded(submitter);
    }

    function removeSubmitter(address submitter) external onlyOwner {
        if (!authorizedSubmitters[submitter]) revert NotSubmitter();
        authorizedSubmitters[submitter] = false;
        emit SubmitterRemoved(submitter);
    }
}
