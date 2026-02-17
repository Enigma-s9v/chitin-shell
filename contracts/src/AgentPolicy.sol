// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/// @title AgentPolicy
/// @notice On-chain security policy registry for AI agents. Stores tamper-proof
///         tier configurations, action mappings, whitelists, blacklists, and
///         rate limits. Deployed behind a UUPS proxy for upgradeability.
/// @dev Uses OpenZeppelin UUPS + OwnableUpgradeable. Tier 0 = auto-approve,
///      Tier 3 = requires human approval. Unknown actions default to Tier 3.
contract AgentPolicy is UUPSUpgradeable, OwnableUpgradeable {
    // -----------------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------------

    /// @notice Rate limit configuration for a tier
    struct RateLimit {
        uint32 max;            // Maximum calls allowed within the window
        uint32 windowSeconds;  // Rolling window in seconds
    }

    /// @notice Full configuration for a policy tier
    struct TierConfig {
        string description;
        string[] actions;
        uint8 verification;    // 0=none, 1=local, 2=on_chain, 3=human_approval
        RateLimit rateLimit;
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice Policy version, incremented on every mutation
    uint256 public policyVersion;

    /// @dev Tier number => config. Only tiers 0-3 are expected but not enforced.
    mapping(uint8 => TierConfig) internal _tiers;

    /// @notice Fast lookup: keccak256(action) => assigned tier
    mapping(bytes32 => uint8) public actionTier;

    /// @dev Track whether an action hash has been explicitly mapped
    mapping(bytes32 => bool) internal _actionMapped;

    /// @notice Whitelisted agent addresses (bypass rate-limit checks)
    mapping(address => bool) public whitelistedAgents;

    /// @notice Blacklisted action hashes (always rejected)
    mapping(bytes32 => bool) public blacklistedActions;

    /// @dev Rate limit history: keccak256(agentDid, actionHash) => timestamps
    mapping(bytes32 => uint256[]) private _rateHistory;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event PolicyUpdated(uint256 indexed version, address indexed updatedBy);
    event TierConfigSet(uint8 indexed tier, string description, uint8 verification);
    event ActionMapped(string action, uint8 tier);
    event AgentWhitelisted(address indexed agent, bool status);
    event ActionBlacklisted(string action, bool status);
    event ActionVerified(
        bytes32 indexed intentHash,
        string action,
        uint8 tier,
        bool approved,
        string reason
    );

    // -----------------------------------------------------------------------
    // Errors
    // -----------------------------------------------------------------------

    error InvalidVerificationLevel(uint8 level);

    // -----------------------------------------------------------------------
    // Initializer
    // -----------------------------------------------------------------------

    /// @notice Initializes the proxy state. Must be called exactly once.
    /// @param owner_ The initial owner (admin) of the policy contract
    function initialize(address owner_) public initializer {
        __Ownable_init(owner_);
        policyVersion = 1;
    }

    // -----------------------------------------------------------------------
    // Admin — Tier Config
    // -----------------------------------------------------------------------

    /// @notice Set the configuration for a given tier
    /// @param tier           Tier number (0-3 recommended)
    /// @param description    Human-readable description
    /// @param actions        List of action strings assigned to this tier
    /// @param verification   Verification level (0-3)
    /// @param rateLimitMax   Max calls within the rate window
    /// @param rateLimitWindow Rolling window in seconds
    function setTierConfig(
        uint8 tier,
        string calldata description,
        string[] calldata actions,
        uint8 verification,
        uint32 rateLimitMax,
        uint32 rateLimitWindow
    ) external onlyOwner {
        if (verification > 3) revert InvalidVerificationLevel(verification);

        TierConfig storage cfg = _tiers[tier];
        cfg.description = description;
        cfg.verification = verification;
        cfg.rateLimit = RateLimit(rateLimitMax, rateLimitWindow);

        // Clear old action mappings for this tier
        for (uint256 i = 0; i < cfg.actions.length; i++) {
            bytes32 h = keccak256(bytes(cfg.actions[i]));
            delete actionTier[h];
            delete _actionMapped[h];
        }

        // Set new actions
        delete cfg.actions;
        for (uint256 i = 0; i < actions.length; i++) {
            cfg.actions.push(actions[i]);
            bytes32 h = keccak256(bytes(actions[i]));
            actionTier[h] = tier;
            _actionMapped[h] = true;
        }

        unchecked { policyVersion++; }

        emit TierConfigSet(tier, description, verification);
        emit PolicyUpdated(policyVersion, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Admin — Action Mapping
    // -----------------------------------------------------------------------

    /// @notice Map a single action to a tier
    function mapAction(string calldata action, uint8 tier) external onlyOwner {
        bytes32 h = keccak256(bytes(action));
        actionTier[h] = tier;
        _actionMapped[h] = true;

        unchecked { policyVersion++; }

        emit ActionMapped(action, tier);
        emit PolicyUpdated(policyVersion, msg.sender);
    }

    /// @notice Batch map multiple actions to the same tier
    function mapActions(string[] calldata actions, uint8 tier) external onlyOwner {
        for (uint256 i = 0; i < actions.length; i++) {
            bytes32 h = keccak256(bytes(actions[i]));
            actionTier[h] = tier;
            _actionMapped[h] = true;
            emit ActionMapped(actions[i], tier);
        }

        unchecked { policyVersion++; }
        emit PolicyUpdated(policyVersion, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Admin — Whitelist / Blacklist
    // -----------------------------------------------------------------------

    /// @notice Whitelist or un-whitelist an agent address
    function setAgentWhitelist(address agent, bool status) external onlyOwner {
        whitelistedAgents[agent] = status;
        emit AgentWhitelisted(agent, status);
    }

    /// @notice Blacklist or un-blacklist an action string
    function setActionBlacklist(string calldata action, bool status) external onlyOwner {
        bytes32 h = keccak256(bytes(action));
        blacklistedActions[h] = status;
        emit ActionBlacklisted(action, status);
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    /// @notice Verify an action against the on-chain policy.
    /// @dev State-changing because it updates rate-limit history.
    /// @param agentDid   DID string of the agent
    /// @param action     Action string to verify
    /// @param intentHash Hash of the intent payload (for event correlation)
    /// @return approved  Whether the action is approved
    /// @return tier      Resolved tier number
    /// @return reason    Human-readable explanation
    function verifyAction(
        string calldata agentDid,
        string calldata action,
        bytes32 intentHash
    ) external returns (bool approved, uint8 tier, string memory reason) {
        bytes32 actionHash = keccak256(bytes(action));

        // 1. Blacklist check
        if (blacklistedActions[actionHash]) {
            emit ActionVerified(intentHash, action, 0, false, "action_blacklisted");
            return (false, 0, "action_blacklisted");
        }

        // 2. Resolve tier (unmapped => tier 3)
        if (_actionMapped[actionHash]) {
            tier = actionTier[actionHash];
        } else {
            tier = 3;
        }

        // 3. Rate limit check (skip for tier 0 or if no limit configured)
        TierConfig storage cfg = _tiers[tier];
        if (cfg.rateLimit.max > 0 && cfg.rateLimit.windowSeconds > 0) {
            bytes32 rlKey = keccak256(abi.encodePacked(agentDid, actionHash));
            uint256[] storage history = _rateHistory[rlKey];

            // Count recent calls within the window
            uint256 windowStart = block.timestamp > cfg.rateLimit.windowSeconds
                ? block.timestamp - cfg.rateLimit.windowSeconds
                : 0;
            uint256 recentCount;
            for (uint256 i = history.length; i > 0; i--) {
                if (history[i - 1] >= windowStart) {
                    recentCount++;
                } else {
                    break;
                }
            }

            if (recentCount >= cfg.rateLimit.max) {
                emit ActionVerified(intentHash, action, tier, false, "rate_limit_exceeded");
                return (false, tier, "rate_limit_exceeded");
            }

            // Record this call
            history.push(block.timestamp);
        }

        // 4. Tier 3 = human approval required (never auto-approve)
        if (tier == 3) {
            emit ActionVerified(intentHash, action, tier, false, "human_approval_required");
            return (false, tier, "human_approval_required");
        }

        // 5. Approved
        emit ActionVerified(intentHash, action, tier, true, "approved");
        return (true, tier, "approved");
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    /// @notice Get all actions assigned to a tier
    function getTierActions(uint8 tier) external view returns (string[] memory) {
        return _tiers[tier].actions;
    }

    /// @notice Get the tier for an action (returns 3 for unmapped)
    function getActionTier(string calldata action) external view returns (uint8) {
        bytes32 h = keccak256(bytes(action));
        if (_actionMapped[h]) {
            return actionTier[h];
        }
        return 3;
    }

    /// @notice Get the tier config description and verification level
    function getTierConfig(uint8 tier)
        external
        view
        returns (
            string memory description,
            uint8 verification,
            uint32 rateLimitMax,
            uint32 rateLimitWindow
        )
    {
        TierConfig storage cfg = _tiers[tier];
        return (cfg.description, cfg.verification, cfg.rateLimit.max, cfg.rateLimit.windowSeconds);
    }

    /// @notice Check rate limit for an agent + action combination
    /// @return allowed   Whether the agent can perform the action now
    /// @return remaining Number of calls remaining in the current window
    function checkRateLimit(
        string calldata agentDid,
        string calldata action
    ) external view returns (bool allowed, uint256 remaining) {
        bytes32 actionHash = keccak256(bytes(action));
        uint8 tier;
        if (_actionMapped[actionHash]) {
            tier = actionTier[actionHash];
        } else {
            tier = 3;
        }

        TierConfig storage cfg = _tiers[tier];
        if (cfg.rateLimit.max == 0 || cfg.rateLimit.windowSeconds == 0) {
            return (true, type(uint256).max);
        }

        bytes32 rlKey = keccak256(abi.encodePacked(agentDid, actionHash));
        uint256[] storage history = _rateHistory[rlKey];

        uint256 windowStart = block.timestamp > cfg.rateLimit.windowSeconds
            ? block.timestamp - cfg.rateLimit.windowSeconds
            : 0;
        uint256 recentCount;
        for (uint256 i = history.length; i > 0; i--) {
            if (history[i - 1] >= windowStart) {
                recentCount++;
            } else {
                break;
            }
        }

        uint256 rem = cfg.rateLimit.max > recentCount
            ? cfg.rateLimit.max - recentCount
            : 0;
        return (rem > 0, rem);
    }

    // -----------------------------------------------------------------------
    // UUPS
    // -----------------------------------------------------------------------

    /// @dev Only owner can authorize upgrades
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
