<h1 align="center">Chitin Shell</h1>

<p align="center">
  <strong>The missing security layer for AI agents.</strong><br/>
  Open-source middleware that separates LLMs from credentials using process isolation, policy enforcement, and verifiable execution.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-chitin-shell">Why?</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#ecosystem">Ecosystem</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/chitin-id/chitin-shell/actions"><img src="https://img.shields.io/github/actions/workflow/status/chitin-id/chitin-shell/ci.yml?branch=main&style=flat-square" alt="CI" /></a>
  <a href="https://github.com/chitin-id/chitin-shell/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License" /></a>
  <a href="https://chitin.id/shell"><img src="https://img.shields.io/badge/website-chitin.id%2Fshell-green?style=flat-square" alt="Website" /></a>
</p>

---

## The Problem

Every major AI agent framework stores API keys as environment variables in the same process as the LLM. When prompt injection tricks the LLM—and [it will](https://arxiv.org/abs/2503.18813)—the attacker gets everything.

```
┌─────────────────────────────────────────┐
│  Current AI Agent Architecture          │
│                                         │
│  LLM + API Keys + Untrusted Input       │
│  = All in the same process              │
│  = One prompt injection away from       │
│    leaking everything                   │
└─────────────────────────────────────────┘
```

This is not a bug in any specific framework. It's a **structural vulnerability**—the same class of problem as SQL injection before parameterized queries. In October 2025, researchers from OpenAI, Anthropic, and Google DeepMind confirmed that [all 12 published prompt injection defenses can be bypassed](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/) with >90% success. The UK NCSC warned it ["may never be fixed"](https://www.malwarebytes.com/blog/news/2025/12/prompt-injection-is-a-problem-that-may-never-be-fixed-warns-ncsc) at the model level. The only viable mitigation is **architectural separation**.

## The Solution

Chitin Shell wraps your AI agent in a hardened exoskeleton. The LLM never sees credentials. It can only produce structured **Intents**—requests that are verified against policies before a separate secure proxy executes them.

```
┌─────────────────────────────────────────┐
│  Chitin Shell Architecture              │
│                                         │
│  LLM (no secrets)                       │
│    ↓ Intent (structured request)        │
│  Policy Engine (verify)                 │
│    ↓ Approved token                     │
│  Secure Proxy (holds all credentials)   │
│    ↓ Sanitized result                   │
│  LLM receives result (secrets masked)   │
└─────────────────────────────────────────┘
```

Think of it like a restaurant: the **waiter** (LLM) takes orders but never enters the kitchen. The **chef** (Secure Proxy) has the knives, ingredients, and cash register. The waiter can only pass order slips. Even if a malicious customer tricks the waiter, the chef checks the rules posted on the wall before cooking—and those rules are carved in stone.

## Why Chitin Shell

| Problem | How frameworks handle it today | How Chitin Shell handles it |
|---|---|---|
| API key leakage | Environment variables in LLM process | Keys exist **only** in the Secure Proxy—physically inaccessible to the LLM |
| Prompt injection → unauthorized actions | Hope the LLM doesn't comply | LLM can only produce Intents. Policy Engine rejects unauthorized actions regardless of what the LLM "wants" |
| Data exfiltration | No output filtering | Network isolation + output sanitization. LLM can only communicate with the proxy |
| Malicious skills/plugins | Trust on first install | Sandboxed execution with scoped permissions. Skills never see raw credentials |
| No audit trail | Application-level logs (mutable) | Immutable on-chain audit log (optional) |
| Policy tampering | Config files editable by the agent | On-chain policies are immutable without multisig + timelock (optional) |

## Key Features

🔒 **Process Isolation** — LLM runs in a network-isolated container with zero access to credentials, keys, or tokens.

📋 **Structured Intents** — LLM output is constrained to typed, signed Intent structures instead of raw tool calls.

⚖️ **Tiered Policy Engine** — Four security tiers from no-check (read-only) to human-approval-required (fund transfers), configurable via JSON or on-chain.

🔑 **Secure Proxy** — Credential vault that executes verified Intents and returns sanitized results. Supports TEE-backed storage.

🪪 **Agent Identity** — Optional ERC-8004 / W3C DID-based decentralized identity for verifiable agent provenance.

🔗 **On-Chain Policies** — Optional immutable policy enforcement via smart contracts with multisig governance.

🛡️ **Output Sanitization** — Automatic detection and masking of secrets, PII, and sensitive data in proxy responses.

📊 **Audit Logging** — Every Intent, verification decision, and execution result is logged. Optionally anchored on-chain for tamper-proof auditability.

🔌 **Framework Agnostic** — Works as middleware for LangChain, CrewAI, AutoGPT, MCP servers, or any custom agent setup.

## Quick Start

### Prerequisites

- Node.js ≥ 20
- Zero external dependencies — uses only Node.js built-in modules

### Installation

```bash
npm install @chitin-id/shell-core
```

### Basic Usage

```typescript
import { ChitinShell } from '@chitin-id/shell-core';
import type { ActionMapper, PolicyConfig } from '@chitin-id/shell-core';

// 1. Define a policy — deterministic rules, no LLM involved
const policy: PolicyConfig = {
  version: '1.0',
  tiers: {
    tier_0: {
      description: 'Read-only (auto-approved)',
      actions: ['think', 'recall', 'summarize'],
      verification: 'none',
    },
    tier_1: {
      description: 'Low-risk writes (whitelisted contacts)',
      actions: ['send_message', 'reply_email'],
      verification: 'local',
      constraints: { recipient_whitelist: true },
    },
    tier_2: {
      description: 'Medium-risk operations',
      actions: ['api_call', 'send_email_new'],
      verification: 'local',
    },
    tier_3: {
      description: 'Critical — requires human approval',
      actions: ['transfer_funds', 'change_permissions'],
      verification: 'human_approval',
    },
  },
  whitelists: { contacts: ['alice@example.com'] },
};

// 2. Define an action mapper — bridges Intents to real-world side effects
class SlackMessenger implements ActionMapper {
  readonly action_type = 'send_message';
  async execute(params: Record<string, unknown>) {
    // In production, this calls Slack/Discord/email APIs
    return { sent: true, to: params.to, body: params.body };
  }
}

// 3. Create and configure the shell
const shell = await ChitinShell.create({ policy });
shell.registerMapper(new SlackMessenger());

// Store credentials in the vault — the LLM NEVER sees these
await shell.vault.set('slack-token', {
  type: 'bearer',
  value: 'xoxb-your-slack-bot-token',
});

// 4. The LLM produces an Intent — NOT a raw API call
const intent = shell.createIntent({
  action: 'send_message',
  params: { to: 'alice@example.com', body: 'Deploy complete!' },
});

// 5. Policy Engine verifies → Secure Proxy executes → sanitized result
const result = await shell.execute(intent);
// result.verification.approved: true
// result.verification.tier: 1
// result.execution.status: 'success'
// result.execution.data: { sent: true, to: 'alice@example.com', ... }
// result.execution.sanitized: false (no secrets in output)
```

### What Happens Under the Hood

```
  LLM output: "Send message to alice@example.com"
       │
       ▼
  Intent Layer: Converts to signed, structured Intent
       │
       ▼
  Policy Engine: "send_message" → Tier 1 → whitelist check → ✅ approved
       │
       ▼
  Secure Proxy: Executes via SlackMessenger → sanitizes output
       │
       ▼
  LLM receives: { sent: true, to: "alice@example.com" }
                 (no API keys, tokens, or raw headers exposed)
```

### Output Sanitization

Even if an API accidentally returns secrets, the Sanitizer catches them:

```typescript
// API response contains leaked credentials
{ data: "Key: sk-proj-ABC123...", auth: "Bearer eyJhbG..." }

// After sanitization — LLM receives:
{ data: "Key: [REDACTED:openai_key]", auth: "Bearer [REDACTED:jwt]" }
```

Detects: OpenAI/Anthropic keys, AWS keys, GitHub tokens, JWTs, Bearer tokens, connection strings, and more.

### Policy Configuration

Policies are defined in JSON (local) or on-chain (Solidity, coming in v0.2):

```json
{
  "version": "1.0",
  "tiers": {
    "tier_0": {
      "description": "No verification needed",
      "actions": ["think", "recall", "summarize"],
      "verification": "none"
    },
    "tier_1": {
      "description": "Local policy check",
      "actions": ["send_message", "reply_email"],
      "constraints": {
        "recipient_whitelist": true,
        "rate_limit": { "max": 30, "window": "1h" }
      },
      "verification": "local"
    },
    "tier_2": {
      "description": "Enhanced verification",
      "actions": ["send_email_new", "file_write", "api_call"],
      "verification": "local"
    },
    "tier_3": {
      "description": "Human approval required",
      "actions": ["transfer_funds", "change_permissions", "bulk_export"],
      "verification": "human_approval",
      "multisig": { "required": 1, "timeout": "1h" }
    }
  }
}
```

## Architecture

For a deep dive into the architecture, see the documentation on [**chitin.id/shell**](https://chitin.id/shell).

<p align="center">
  <img src="./docs/images/architecture.png" alt="Chitin Shell Architecture — Intent, Verify, Execute" width="800" />
</p>

```
 User Input
     │
     ▼
┌─────────┐     ┌──────────┐     ┌─────────────┐
│  Intent  │────▶│  Verify  │────▶│   Execute   │
│  Layer   │     │  Layer   │     │   Layer     │
│          │     │          │     │             │
│ LLM      │     │ Policy   │     │ Secure      │
│ (no keys)│     │ Engine   │     │ Proxy       │
│          │     │          │     │ (keys here) │
└─────────┘     └──────────┘     └─────────────┘
     ▲                                  │
     └──── sanitized result ────────────┘
```

### The Restaurant Analogy

<p align="center">
  <img src="./docs/images/restaurant.png" alt="Restaurant analogy — Dining Room (Intent), Kitchen Window (Verify), Kitchen (Execute)" width="800" />
</p>

The **waiter** (LLM) takes orders in the dining room but never enters the kitchen. The **chef** (Secure Proxy) has the knives, ingredients, and cash register behind a reinforced barrier. Orders pass through a kitchen window where **policy** is checked before cooking begins. Even if a malicious customer tricks the waiter, the chef verifies every order against the rules.

### Core Principles

1. **Zero-Knowledge Agent**: The LLM never has access to any secret material. Not temporarily, not through tokens, not through environment variables. Ever.
2. **Intent, Not Action**: The LLM produces structured requests, not raw API calls. The system decides what actually happens.
3. **Immutable Policy**: Security policies can be stored on-chain, making them tamper-proof even if the entire agent is compromised.
4. **Defense in Depth**: Process isolation + network isolation + policy enforcement + output sanitization + audit logging.
5. **Pragmatic Security**: Not everything needs blockchain. Tier 0–1 operations run locally with zero overhead. On-chain verification is reserved for high-risk actions.

## Ecosystem

Chitin Shell is part of the [**chitin.id**](https://chitin.id) ecosystem:

| Project | Description | Status |
|---|---|---|
| **Chitin ID** | Decentralized AI agent identity (ERC-8004) | Active |
| **Chitin Shell** | Secure agent middleware (this project) | v0.1.0 on npm |
| **Chitin Registry** | On-chain skill/plugin safety registry | Planned |

## Compatibility

Chitin Shell is designed to work as middleware with any agent framework:

| Framework | Integration | Status |
|---|---|---|
| LangChain | Callback handler + tool wrapper | ✅ v0.1.0 |
| CrewAI | Agent executor middleware | 📋 Planned |
| AutoGPT | Plugin system hook | 📋 Planned |
| MCP Servers | Proxy gateway | ✅ v0.1.0 |
| OpenClaw | Skill wrapper | 📋 Planned |
| Custom agents | SDK + REST API | ✅ v0.1.0 |

## Roadmap

### Phase 1: Core SDK (v0.1) ✅
- [x] Docker-based LLM sandbox with network isolation
- [x] Intent structure specification + Ed25519 signing
- [x] Local JSON policy engine (4-tier)
- [x] Secure Proxy with credential vault
- [x] Output sanitization (10 patterns)
- [x] LangChain integration (`@chitin-id/shell-langchain`)
- [x] MCP gateway mode (`@chitin-id/shell-mcp`)
- [x] CLI tool (`@chitin-id/shell-cli`)

### Phase 2: On-Chain Policy ✅
- [x] Solidity policy contracts (AgentPolicy UUPS + PolicyGovernor)
- [x] ERC-8004 DID integration (`did:chitin:<chainId>:<registry>:<agentId>`)
- [x] On-chain audit log anchoring (Merkle root)
- [x] Policy governance (multisig + 24h timelock)

### Phase 3: Zero-Knowledge Verification ✅
- [x] ZKP-based Intent provenance verification
- [x] Data non-leakage proofs for output sanitization
- [x] Skill safety proofs (ProofVerifier.sol)

### Phase 4: Advanced ✅
- [x] TEE abstraction (ITeeProvider interface + mock)
- [x] Multi-agent trust delegation (scoped tokens, chain verification)
- [x] A2A protocol integration (Ed25519 signed messages, registry, middleware)
- [ ] GPU TEE support (NVIDIA Confidential Compute)
- [ ] zkML inference verification (as technology matures)

## Research Foundation

Chitin Shell's architecture is grounded in peer-reviewed research:

| Paper | Relevance | Venue |
|---|---|---|
| [IsolateGPT](https://arxiv.org/abs/2403.04960) — Wu et al. | Process isolation for LLM agents | NDSS 2025 |
| [CaMeL](https://arxiv.org/abs/2503.18813) — Debenedetti et al. | Capability-based LLM security | Google DeepMind 2025 |
| [Design Patterns for Securing LLM Agents](https://arxiv.org/abs/2506.08837) — Beurer-Kellner et al. | Architectural defense patterns | arXiv 2025 |
| [Guardians of the Agents](https://queue.acm.org/detail.cfm?id=3762990) — Meijer | Formal verification of AI workflows | ACM Queue 2025 |
| [zkLLM](https://arxiv.org/abs/2404.16109) — Sun et al. | ZKP for LLM inference | ACM CCS 2024 |
| [ETHOS](https://arxiv.org/abs/2412.17114) — Chaffer et al. | Blockchain governance for AI agents | NeurIPS Workshops 2024 |
| [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) — De Rossi et al. | Trustless AI agent identity on Ethereum | EIP Draft 2025 |

## Standards Alignment

| Standard | Alignment |
|---|---|
| **OWASP Top 10 for Agentic Applications** (Dec 2025) | Addresses ASI01 (Goal Hijack), ASI02 (Tool Misuse), ASI03 (Identity & Privilege Abuse), ASI07 (Insecure Inter-Agent Comms) |
| **NIST AI RMF / IR 8596** | Maps to Govern, Map, Measure, Manage functions for AI-specific risks |
| **ERC-8004** | Native integration for agent identity and reputation |
| **MCP** (Model Context Protocol) | Compatible as a security gateway layer |
| **A2A** (Agent-to-Agent Protocol) | Planned integration for multi-agent trust |
| **W3C DID / VC** | Foundation for agent identity and credential delegation |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

### Priority Areas

- 🔌 **Framework integrations** — LangChain, CrewAI, MCP adapters
- 🧪 **Red team testing** — Try to break it. Prompt injection PoCs welcome
- 📄 **Policy templates** — Pre-built policies for common use cases
- 🌍 **Documentation translations** — Especially Japanese (日本語) and Chinese (中文)
- 🔐 **Security audits** — Formal analysis of the isolation model

### Development

```bash
# Install dependencies
npm install

# Run tests (561 tests across all packages + contracts)
cd packages/core && npm test

# Type check
cd packages/core && npx tsc --noEmit

# Run the basic example
npx tsx examples/basic/index.ts
```

## FAQ

**Q: Does this make AI agents completely safe?**
No. It makes credential theft impossible and limits the blast radius of prompt injection. The LLM can still be tricked into producing malicious Intents—but those Intents are verified before execution.

**Q: Do I need blockchain to use this?**
No. Phase 1 works entirely locally with Docker and JSON policies. Blockchain is optional for immutable policy enforcement and audit logging.

**Q: How much latency does this add?**
Tier 0 (read-only): 0ms. Tier 1 (local policy): 1–10ms. Tier 2 (on-chain): 1–15 seconds. Tier 3 (human approval): minutes to hours. Most agent operations fall into Tier 0–1.

**Q: Which LLMs does this support?**
Any. The Intent Layer is model-agnostic. If it can output JSON, it works with Chitin Shell.

**Q: How is this different from NeMo Guardrails / LLM Guard?**
Those tools filter LLM input/output (content safety). Chitin Shell provides **architectural separation**—the LLM literally cannot access credentials regardless of what it outputs. They're complementary: you can run NeMo Guardrails inside Chitin Shell's Intent Layer.

## License

Apache License 2.0 — See [LICENSE](./LICENSE)

## Links

- 🌐 [chitin.id/shell](https://chitin.id/shell) — Project page
- 📖 [Documentation](https://chitin.id/docs)
- 🐦 [Twitter/X](https://x.com/chitin_id)
- 📧 [security@chitin.id](mailto:security@chitin.id) — Responsible disclosure

---

<p align="center">
  Built by <a href="https://tiida.tech">Tiida Tech</a> · Part of the <a href="https://chitin.id">chitin.id</a> ecosystem
</p>
