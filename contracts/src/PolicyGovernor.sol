// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./AgentPolicy.sol";

/// @title PolicyGovernor
/// @notice Multisig + timelock governance for AgentPolicy mutations. All policy
///         changes must go through propose -> approve -> execute with a 24-hour
///         timelock and configurable approval threshold.
/// @dev Non-upgradeable. Designed as owner of the AgentPolicy proxy.
contract PolicyGovernor {
    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    struct ProposalCore {
        bytes32 id;
        address proposer;
        bytes callData;        // ABI-encoded call to AgentPolicy
        string description;
        uint256 createdAt;
        uint256 executesAt;    // createdAt + TIMELOCK
        uint8 approvals;
        bool executed;
        bool cancelled;
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /// @notice Timelock duration before a proposal can be executed
    uint256 public constant TIMELOCK = 24 hours;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice Reference to the AgentPolicy contract this governor manages
    AgentPolicy public policy;

    /// @notice Number of approvals required to execute a proposal
    uint8 public requiredApprovals;

    /// @notice Whether an address is a governor
    mapping(address => bool) public isGovernor;

    /// @notice Total number of active governors
    uint8 public governorCount;

    /// @dev Proposal id => core data
    mapping(bytes32 => ProposalCore) internal _proposals;

    /// @dev Proposal id => (governor => has approved)
    mapping(bytes32 => mapping(address => bool)) internal _hasApproved;

    /// @notice Ordered list of all proposal ids
    bytes32[] public proposalIds;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event ProposalCreated(bytes32 indexed id, address indexed proposer, string description);
    event ProposalApproved(bytes32 indexed id, address indexed approver, uint8 totalApprovals);
    event ProposalExecuted(bytes32 indexed id, address indexed executor);
    event ProposalCancelled(bytes32 indexed id, address indexed canceller);
    event GovernorAdded(address indexed governor);
    event GovernorRemoved(address indexed governor);

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error NotGovernor();
    error AlreadyGovernor();
    error NotAGovernor();
    error InvalidThreshold();
    error ProposalNotFound();
    error AlreadyApproved();
    error AlreadyExecuted();
    error AlreadyCancelled();
    error TimelockNotElapsed();
    error InsufficientApprovals();
    error ExecutionFailed();
    error ZeroAddress();
    error CannotRemoveLastGovernor();
    error OnlySelf();

    // -----------------------------------------------------------------------
    // Modifiers
    // -----------------------------------------------------------------------

    modifier onlyGovernor() {
        if (!isGovernor[msg.sender]) revert NotGovernor();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @notice Deploy the governor with initial governors and approval threshold
    /// @param policyAddress Address of the AgentPolicy proxy
    /// @param governors     Initial set of governor addresses
    /// @param required      Number of approvals required to execute proposals
    constructor(address policyAddress, address[] memory governors, uint8 required) {
        if (policyAddress == address(0)) revert ZeroAddress();
        if (governors.length == 0) revert InvalidThreshold();
        if (required == 0 || required > governors.length) revert InvalidThreshold();

        policy = AgentPolicy(policyAddress);
        requiredApprovals = required;

        for (uint256 i = 0; i < governors.length; i++) {
            if (governors[i] == address(0)) revert ZeroAddress();
            if (isGovernor[governors[i]]) revert AlreadyGovernor();
            isGovernor[governors[i]] = true;
            emit GovernorAdded(governors[i]);
        }
        governorCount = uint8(governors.length);
    }

    // -----------------------------------------------------------------------
    // Proposal Lifecycle
    // -----------------------------------------------------------------------

    /// @notice Create a new proposal
    /// @param callData    ABI-encoded function call to execute on AgentPolicy
    /// @param description Human-readable description of the proposal
    /// @return id         Unique proposal identifier
    function propose(
        bytes calldata callData,
        string calldata description
    ) external onlyGovernor returns (bytes32 id) {
        id = keccak256(abi.encodePacked(callData, block.timestamp, msg.sender));

        ProposalCore storage p = _proposals[id];
        p.id = id;
        p.proposer = msg.sender;
        p.callData = callData;
        p.description = description;
        p.createdAt = block.timestamp;
        p.executesAt = block.timestamp + TIMELOCK;
        p.approvals = 1; // Proposer auto-approves
        _hasApproved[id][msg.sender] = true;

        proposalIds.push(id);

        emit ProposalCreated(id, msg.sender, description);
        emit ProposalApproved(id, msg.sender, 1);

        return id;
    }

    /// @notice Approve a pending proposal
    /// @param proposalId The proposal to approve
    function approve(bytes32 proposalId) external onlyGovernor {
        ProposalCore storage p = _proposals[proposalId];
        if (p.createdAt == 0) revert ProposalNotFound();
        if (p.executed) revert AlreadyExecuted();
        if (p.cancelled) revert AlreadyCancelled();
        if (_hasApproved[proposalId][msg.sender]) revert AlreadyApproved();

        _hasApproved[proposalId][msg.sender] = true;
        p.approvals++;

        emit ProposalApproved(proposalId, msg.sender, p.approvals);
    }

    /// @notice Execute a proposal after timelock and sufficient approvals
    /// @param proposalId The proposal to execute
    function execute(bytes32 proposalId) external onlyGovernor {
        ProposalCore storage p = _proposals[proposalId];
        if (p.createdAt == 0) revert ProposalNotFound();
        if (p.executed) revert AlreadyExecuted();
        if (p.cancelled) revert AlreadyCancelled();
        if (block.timestamp < p.executesAt) revert TimelockNotElapsed();
        if (p.approvals < requiredApprovals) revert InsufficientApprovals();

        p.executed = true;

        (bool success,) = address(policy).call(p.callData);
        if (!success) revert ExecutionFailed();

        emit ProposalExecuted(proposalId, msg.sender);
    }

    /// @notice Cancel a pending proposal. Only the proposer or any governor
    ///         can cancel.
    /// @param proposalId The proposal to cancel
    function cancel(bytes32 proposalId) external onlyGovernor {
        ProposalCore storage p = _proposals[proposalId];
        if (p.createdAt == 0) revert ProposalNotFound();
        if (p.executed) revert AlreadyExecuted();
        if (p.cancelled) revert AlreadyCancelled();

        p.cancelled = true;

        emit ProposalCancelled(proposalId, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Governor Management (must go through proposal)
    // -----------------------------------------------------------------------

    /// @notice Add a new governor. Must be called via proposal execution.
    /// @param governor Address to add
    function addGovernor(address governor) external onlySelf {
        if (governor == address(0)) revert ZeroAddress();
        if (isGovernor[governor]) revert AlreadyGovernor();

        isGovernor[governor] = true;
        governorCount++;

        emit GovernorAdded(governor);
    }

    /// @notice Remove a governor. Must be called via proposal execution.
    /// @param governor Address to remove
    function removeGovernor(address governor) external onlySelf {
        if (!isGovernor[governor]) revert NotAGovernor();
        if (governorCount <= requiredApprovals) revert CannotRemoveLastGovernor();

        isGovernor[governor] = false;
        governorCount--;

        emit GovernorRemoved(governor);
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    /// @notice Get the core data for a proposal
    function getProposal(bytes32 proposalId)
        external
        view
        returns (ProposalCore memory)
    {
        return _proposals[proposalId];
    }

    /// @notice Check whether a governor has approved a proposal
    function hasApproved(bytes32 proposalId, address governor)
        external
        view
        returns (bool)
    {
        return _hasApproved[proposalId][governor];
    }

    /// @notice Total number of proposals created
    function proposalCount() external view returns (uint256) {
        return proposalIds.length;
    }
}
