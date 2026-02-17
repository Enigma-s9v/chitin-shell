# Chitin Shell: Comprehensive Research Landscape for Secure AI Agent Architecture

The architectural approach at the heart of Chitin Shell—separating LLMs from credentials via an Intent-Verify-Execute model—sits at the convergence of the most active research frontiers in AI security. **Prompt injection remains fundamentally unsolved at the model level** (confirmed by a joint OpenAI/Anthropic/Google DeepMind paper in October 2025 that bypassed all 12 published defenses at >90% success rates), making architectural separation the only viable mitigation path. The AI agent security market attracted $8.5 billion in funding across 2024–2025, yet only $414 million targeted AI/LLM-specific security—a massive gap as agent adoption accelerates from $7.6 billion in 2025 toward a projected $183 billion by 2033. Meanwhile, ZKML has advanced from theoretical curiosity to proving 671-billion-parameter models, and ERC-8004 launched on Ethereum mainnet in January 2026 with 24,000+ registered agents, establishing on-chain infrastructure for exactly the kind of agent identity and policy enforcement Chitin Shell envisions.

---

## 1. Academic research directly validates Chitin Shell's core architecture

### Process isolation and credential separation

The most directly relevant academic work is **IsolateGPT** (Yuhao Wu, Franziska Roesner, Tadayoshi Kohno, Ning Zhang, Umar Iqbal; arXiv:2403.04960, March 2024; presented at NDSS 2025). It proposes a hub-and-spoke execution isolation architecture for LLM-based systems where each third-party app executes in isolation with its own dedicated LLM instance. A trusted central "hub" routes queries to isolated "spokes," with an inter-spoke communication protocol mediating all interactions. Performance overhead stays under 30% for 75% of tested queries. This directly parallels Chitin Shell's process isolation model—and explicitly draws analogies to browser site isolation.

**CaMeL** (Edoardo Debenedetti et al., Google DeepMind/ETH Zurich; arXiv:2503.18813, March 2025) is arguably the most significant architectural defense published to date. It wraps the LLM in a capability-based security layer inspired by traditional OS security: explicit control-flow and data-flow extraction from trusted queries, unforgeable capability tokens restricting what operations each data value can undergo, and a custom Python interpreter enforcing all security policies. CaMeL solves **77% of tasks with provable security** on the AgentDojo benchmark versus 84% undefended—the first defense claiming formal guarantees. It extends Simon Willison's foundational **Dual LLM Pattern** (April 2023), which proposed separating a Privileged LLM (tool access, trusted input only) from a Quarantined LLM (untrusted content, no tool access).

A June 2025 paper, **"Design Patterns for Securing LLM Agents against Prompt Injections"** (Luca Beurer-Kellner, Beat Buesser, Ana-Maria Crețu, Edoardo Debenedetti et al.; arXiv:2506.08837), codifies six principled design patterns: Action-Selector, Plan-Then-Execute, LLM Map-Reduce, Dual LLM, Code-Then-Execute, and Context-Minimization. This is the first comprehensive practical framework for prompt-injection-resilient agent design, endorsed by Simon Willison.

**"Better Privilege Separation for Agents by Restricting Data Types"** (Dennis Jacob et al.; arXiv:2509.25926, September 2025) extends the Dual LLM pattern by introducing type-directed privilege separation, allowing the privileged agent to access context through restricted data types rather than complete isolation, offering a middle ground between security and functionality.

### Intent-based action and formal verification frameworks

**VSA** (arXiv:2503.18492, March 2025) introduces an Intent Encoder and Verification Engine that translates user instructions into logical constraints expressed in a domain-specific language, performing runtime deterministic verification before each agent action. This is the closest published system to Chitin Shell's Intent-Verify-Execute pipeline.

**"Guardians of the Agents: Formal Verification of AI Workflows"** (Erik Meijer, ACM Queue, September 2025) proposes that AI agents generate structured workflows that are formally validated before execution—drawing a direct analogy to Java/JVM bytecode verification. The key insight: static verification before execution prevents rather than detects failures, eliminates rollback needs, and scales through automated verification.

**VeriGuard** (arXiv:2510.05156, October 2025) introduces a dual-stage architecture: an offline stage that clarifies intent, establishes safety specifications, synthesizes behavioral policy, and subjects it to formal verification; and an online stage where a runtime monitor validates each proposed action against the pre-verified policy. The **"Towards Guaranteed Safe AI"** landmark paper (David Dalrymple, Yoshua Bengio, Stuart Russell, Max Tegmark et al.; arXiv:2405.06624, May 2024) provides theoretical grounding through its three-component framework: World Model, Safety Specification, and Verifier producing auditable proof certificates.

A 2025 position paper accepted at a top venue, **"Trustworthy AI Agents Require the Integration of LLMs and Formal Methods"** (OpenReview:wkisIZbntD), argues for bidirectional integration: LLMs enhance formal methods for efficiency while formal methods verify LLM outputs for correctness.

### The confused deputy problem as the dominant threat model

Multiple independent research efforts have converged on framing prompt injection as a **confused deputy problem**. A comprehensive MDPI review (January 2025, 142 primary sources) explicitly states: "agents possess legitimate credentials and permissions and users trust them to act appropriately, yet decision-making can be influenced by anyone injecting convincing instructions." Quarkslab's technical analysis (2025) demonstrated through a medical AI application that "the fix is not making better prompts or smarter models—it's about defining trust boundaries, enforcing permissions, and validating access privileges and tool operations." WithSecure Labs (2024) showed that tools must have "foolproof APIs" where the LLM cannot specify sensitive parameters like user IDs—security enforcement must happen at the tool/API layer, exactly as Chitin Shell proposes.

### Decentralized identity for AI agents

**"AI Agents with Decentralized Identifiers and Verifiable Credentials"** (Sandro Rodriguez Garzon et al.; arXiv:2511.02841, October 2025) presents a prototypical multi-agent system where each agent has a self-sovereign digital identity combining a ledger-anchored W3C DID with Verifiable Credentials. Agents prove DID ownership for authentication and establish cross-domain trust through spontaneous VC exchange.

**"Interoperable Architecture for Digital Identity Delegation for AI Agents with Blockchain Integration"** (Universidad de Los Andes; arXiv:2601.14982, January 2026) formalizes bounded, auditable, least-privilege delegation through "Delegation Grants"—first-class authorization artifacts encoding revocable, scope-reduced transfers of authority. It introduces the "Delegation Tetrahedron" extending the trust triangle with a fourth role: the Delegate. A **"Novel Zero-Trust Identity Framework for Agentic AI"** (Cloud Security Alliance; arXiv:2505.19301, May 2025) proposes an Agent Name Service for discoverable identities, ZKPs for privacy-preserving attribute verification, and fine-grained access control where every significant action is logged with the agent's DID.

---

## 2. Zero-knowledge proofs and blockchain policy enforcement are rapidly maturing

### ZKML has reached LLM scale

The trajectory of ZKML from infeasible to practical has been dramatic. **zkLLM** (Haochen Sun, Jason Li, Hongyang Zhang; ACM CCS 2024) was the first specialized ZKP for LLMs, achieving verifiable inference for models up to **13 billion parameters in under 15 minutes** with proof sizes under 200 KB and minimal accuracy degradation (<0.1 perplexity increase). It introduced tlookup (parallelized lookup for non-arithmetic tensor operations) and zkAttn (ZKP for attention mechanisms).

**zkGPT** (Wenjie Qu et al.; USENIX Security 2025) proved GPT-2 inference in **under 25 seconds**—a 185–279× speedup over prior work—with non-interactive proofs of just 101 KB. **ZK-DeepSeek** (Yunxiao Wang et al.; arXiv:2511.19902, November 2025) achieved the first SNARK-verifiable version of **DeepSeek-V3 at 671 billion parameters**, using Kimchi (PLONKish proving system) with recursive proof composition. **zkPyTorch** (Polyhedra Network; ePrint 2025/535) proved Llama-3 inference at approximately 150 seconds per token and VGG-16 in 2.2 seconds.

Key ZKML projects and frameworks include:

- **EZKL** (Zkonduit): Open-source, production-ready library converting ONNX models to ZK-SNARK circuits via Halo2. Audited by Trail of Bits. Used by MIT, Microsoft Research, and major decentralized networks. ~15× performance improvement in 2024 alone.
- **Lagrange DeepProve**: Claims 54–158× faster than EZKL. First to prove complete GPT-2 inference. Decentralized prover network live on EigenLayer.
- **Giza/LuminAIR**: Verifiable AI on Starknet using StarkWare's S-two prover with Circle STARKs. Deployed for DeFi with Yearn Finance.
- **Bionetta** (October 2025): Achieved sub-second proving times on commodity hardware with constant-sized **320-byte proofs** and 3–4 KB verification keys.

### Blockchain-based policy enforcement for AI agents

The **ETHOS framework** (Tomer Jordi Chaffer et al.; arXiv:2412.17114, December 2024; NeurIPS 2024 workshops) proposes decentralized governance using blockchain, smart contracts, and DAOs with a global AI agent registry, dynamic four-tier risk classification, soulbound tokens for compliance credentials, and ZKP-based privacy-preserving auditing.

**"A Blockchain-Monitored Agentic AI Architecture"** (IEEE ICCA 2025; arXiv:2512.20985) integrates LangChain-based multi-agent systems with Hyperledger Fabric, where smart contracts verify inputs, evaluate actions, and log outcomes across perception-conceptualization-action layers. **"Autonomous Agents on Blockchains"** (arXiv:2601.04583, January 2025) is a major survey proposing Transaction Intent Schema and Policy Decision Record standards for auditable policy enforcement.

### ERC-8004 establishes on-chain agent identity infrastructure

**ERC-8004: Trustless Agents** (Marco De Rossi/MetaMask, Davide Crapis/Ethereum Foundation, Jordan Ellis/Google, Erik Reppel/Coinbase) launched on Ethereum mainnet **January 29, 2026** with over **24,000 agents registered**. It defines three on-chain registries: an Identity Registry (ERC-721-based portable agent handle linking to off-chain agent-card.json), a Reputation Registry (composable feedback signals), and a Validation Registry (generic hooks for zkML verifiers, TEE oracles, stake-based re-execution). The standard integrates with A2A, MCP, and x402 micropayment protocols. The Ethereum Foundation established a dedicated dAI Team to position Ethereum as the settlement layer for AI agents.

---

## 3. Technical challenges reveal why architectural approaches like Chitin Shell are necessary

### Prompt injection cannot be solved at the model level

A landmark October 2025 study by **14 researchers from OpenAI, Anthropic, and Google DeepMind** examined 12 published defenses against prompt injection and subjected them to adaptive attacks. They **bypassed all 12 defenses with >90% attack success rates**, despite most originally reporting near-zero attack rates. OpenAI CISO Dane Stuckey stated: "Prompt injection remains a frontier, unsolved security problem." Bruce Schneier wrote in IEEE Spectrum: "We honestly don't know if it's possible to build an LLM where trusted commands and untrusted inputs processed through the same channel is immune to prompt injection attacks." The UK National Cyber Security Centre warned that prompt injection is "unlikely to be mitigated in the same way SQL injection was."

Real-world exploitation has already occurred at scale: GitHub Copilot CVE-2025-53773 (CVSS 9.6) enabled remote code execution affecting millions; a February 2025 proof-of-concept AI worm demonstrated autonomous propagation between agents via prompt injection; the March 2024 Auto-GPT cryptocurrency wallet attack proved real financial impact; and Chinese state-sponsored hackers used Claude Code with MCP tools as an autonomous cyber-attack agent executing 80–90% of operations independently (November 2025).

Simon Willison's "Rule of Two" captures the architectural principle: systems become dangerous when they combine more than two of (1) access to private data, (2) exposure to untrusted content, and (3) ability to take external actions. **Chitin Shell's Intent-Verify-Execute model structurally prevents any single component from combining all three.**

### ZKML computational overhead is closing but not yet real-time

Current state-of-the-art ZKML performance as of early 2026:

| System | Model | Proving Time | Proof Size |
|--------|-------|-------------|------------|
| zkGPT | GPT-2 | <25 seconds | 101 KB |
| zkLLM | 13B parameter LLM | ~15 minutes | <200 KB |
| ZK-DeepSeek | DeepSeek-V3 (671B) | Hours (CPU) | Constant |
| zkPyTorch | Llama-3 | ~150s/token | — |
| Bionetta | Small models | Sub-second | 320 bytes |

Overall overhead has dropped from approximately **1,000,000× in 2022 to roughly 10,000× in 2025** for optimized frameworks. Key remaining limitations include: only ~50 of 120+ ONNX operators supported, quantization precision loss from floating-point to finite-field conversion, and non-linear activation functions (sigmoid, GELU, softmax) remaining extremely expensive in ZK circuits. Training verification remains infeasible—only inference is provable. For Chitin Shell's use case of verifying policy compliance rather than full model inference, the computational requirements are far more manageable.

### On-chain policy verification is viable on Layer 2

L2 rollups offer **sub-second soft finality at costs under $0.01 per transaction**. Arbitrum achieves 250ms block times, Solana delivers 400ms slots with 12–13 second finality (improving to ~1 second with Alpenglow), and MegaETH targets 10–15ms blocks. EIP-4844 (Dencun, March 2024) reduced L2 data posting costs by 50–90%. The practical architecture for Chitin Shell would involve off-chain verification with on-chain anchoring: compute policy checks off-chain, post cryptographic commitments on-chain for auditability, with full on-chain settlement asynchronous. Groth16 ZK proof verification on-chain requires only ~200K gas (roughly $0.05–0.10 on L1, fractions of a cent on L2).

### Every major agent framework fails at credential security

**All major frameworks store credentials as environment variables or config files accessible to any code in the same process.** The LangChain vulnerability CVE-2025-68664 ("LangGrinch," CVSS 9.3, December 2025) demonstrated this pattern: a serialization injection flaw enabled exfiltration of all environment variables—cloud credentials, database strings, API keys—via prompt injection, affecting **847 million total downloads**. AutoGPT stores API keys in `.env` files with no isolation. CrewAI sets keys via `os.environ` with all agents sharing the same environment. MCP's security model was found wanting by multiple researchers: Knostic scanned ~2,000 internet-exposed MCP servers and found **all verified servers lacked any form of authentication**. No framework provides hardware-backed credential isolation, credential rotation, or per-tool credential scoping by default.

### TEE limitations are real but manageable

The **TEE.Fail** attack (October 2025, Georgia Tech/Purdue/Synkhronix) demonstrated physical DDR5 memory bus interposition using **<$1,000 off-the-shelf equipment** that affects all three major TEE platforms (Intel SGX, Intel TDX, AMD SEV-SNP), extracting ECDSA attestation keys and enabling fake attestation. Classic SGX memory limitations (128 MB EPC) are largely moot for credential management (as opposed to full model inference). The industry is shifting to GPU TEEs: NVIDIA H100 Confidential Compute shows **<5% performance overhead** for large model inference. For Chitin Shell's specific use case—storing and managing credentials within a TEE rather than running full LLM inference—the overhead is minimal and the attack surface is far smaller than for full confidential inference.

---

## 4. The market is rapidly forming around exactly this problem space

### Funding is concentrated but growing fast

Total AI security startup funding reached **$8.5 billion across 175 companies** in 2024–2025, but only **$414 million across just 13 companies** targets AI/LLM/agent-specific security. This massive gap represents the core opportunity. Key funded companies include:

- **Noma Security**: $132M total ($100M Series B led by Evolution Equity Partners, July 2025); **1,300% ARR growth** in one year; unified AI/agent security platform
- **7AI**: $166M total ($130M Series A—largest cybersecurity A round in history—led by Index Ventures + Blackstone, December 2025); AI agents for security operations
- **Descope**: $88M total; pivoted to "Agentic Identity Hub" for AI agent authentication
- **Astrix Security**: $85M total ($45M Series B from Menlo Ventures/Anthropic partnership); AI agent & non-human identity security
- **Keycard**: $38M total (a16z/boldstart seed + Acrew Capital Series A); authenticating AI agents, their builders, and downstream services
- **Clover Security**: $36M (Notable Capital, Team8, backed by Wiz co-founders)
- **Lakera**: $30M total; **acquired by Check Point Software** for their Global Center of Excellence for AI Security

Enterprise vendors are moving aggressively through M&A: Palo Alto Networks acquired Protect AI (July 2025) for its Prisma AIRS platform; CrowdStrike acquired Pangea (September 2025) and SGNL (~$740M, January 2026) for AI Detection & Response; ServiceNow spent **$11.6 billion on security acquisitions** in 2025 alone.

### Agent adoption is accelerating faster than security

The AI agent market is projected to grow from **$7.6 billion in 2025 to $183 billion by 2033** (CAGR 49.6%). Palo Alto Networks projects **1.3 billion production agents by 2028**. Gartner predicts 40% of enterprise applications will embed task-specific AI agents by end of 2026. Non-human identities already outnumber humans **50:1**, projected to reach 80:1 within two years. Yet **only 6% of organizations** have guardrails for AI deployment, and 80% have encountered risky behaviors from AI agents. Shadow AI breaches cost **$4.63 million per incident** ($670K more than standard breaches, per IBM's 2025 report).

### Open-source tooling is fragmented

Existing open-source projects address pieces of the problem but nothing offers Chitin Shell's integrated architecture:

- **NVIDIA NeMo Guardrails**: Programmable guardrails for LLM systems (content safety, jailbreak prevention)
- **Invariant Guardrails**: Rule-based guardrailing layer deployable as MCP or LLM proxy
- **LLM Guard** (Protect AI/Palo Alto): Comprehensive sanitization and prompt injection resistance
- **LlamaFirewall** (Meta): Detects AI-centric security risks across multi-step agentic operations
- **vibekit/leash**: Sandbox coding agents with sensitive data redaction
- **MCP-Scan/secure-mcp-gateway**: Security scanning and gateway enforcement for MCP servers
- **VibraniumDome**: Full-stack LLM WAF with policy-driven control

None of these projects combine process isolation, blockchain-based immutable policy enforcement, and zero-knowledge proofs. No existing open-source project implements the Intent-Verify-Execute three-layer model. This represents a significant gap Chitin Shell could fill.

---

## 5. Standards bodies are actively defining the agentic security landscape

### OWASP published the definitive agentic security taxonomy

The **OWASP Top 10 for Agentic Applications** (v1.0, December 2025) is purpose-built for agent security with ten risk categories directly relevant to Chitin Shell's design:

- **ASI01 (Agent Goal Hijack)**: Attackers redirect agent objectives via manipulated instructions or tool outputs—addressed by Chitin Shell's structured intents
- **ASI02 (Tool Misuse & Exploitation)**: Agents misuse tools due to injection or misalignment—addressed by the verification layer
- **ASI03 (Identity & Privilege Abuse)**: Exploiting inherited or cached credentials—addressed by credential isolation
- **ASI07 (Insecure Inter-Agent Communication)**: Spoofed messages between agents—addressed by on-chain identity verification

The **OWASP LLM Top 10 2025** ranks prompt injection as the #1 risk and significantly expanded LLM06 (Excessive Agency) for agentic architectures. Supporting resources include an Agentic Identity Cheat Sheet, MCP Security Cheat Sheet, and the FinBot CTF Platform for testing agentic security.

### NIST is explicitly incorporating agentic AI

**NIST IR 8596** (Cybersecurity Framework Profile for AI, preliminary draft December 2025) is NIST's most agent-relevant publication, explicitly covering "Using Agentic AI: Single Agent & Multi-Agent" as a distinct use case. It maps CSF 2.0 functions to AI-specific considerations including inventorying AI agents and their permissions, incorporating AI-specific attacks in vulnerability management, and defining conditions for disabling AI autonomy during incidents. **NIST AI 600-1** (July 2024) explicitly identifies "autonomous agent unpredictability" as a risk category.

### MCP security is improving but fundamentally limited

MCP's June 2025 spec update added **OAuth 2.1** authentication, classified MCP servers as OAuth Resource Servers, and mandated Resource Indicators (RFC 8707). However, **authentication remains optional** and not enforced by default. The confused deputy problem is explicitly documented in the specification. Key architectural limitations include plaintext credential exposure in local config files, broad permission scopes, and no native sandboxing. The protocol was donated to the Linux Foundation's Agentic AI Foundation in December 2025.

### A2A and DID standards complement the architecture

Google's **A2A protocol** (Release Candidate v1.0, April 2025, donated to Linux Foundation) enables agent interoperability while preserving opacity—agents never expose internal state to each other. It supports OpenAPI-aligned security schemes including OAuth 2.0, mTLS, and digitally signed Agent Cards (JWS/RFC 7515). **W3C DIDs** (v1.0 Recommendation since July 2022) provide the foundational identity standard, with multiple 2025 papers demonstrating practical implementations for AI agent identity using DIDs combined with Verifiable Credentials. Enterprise implementations like Nuggets AI Agent Identity (available on AWS Marketplace) already bridge DIDs with MCP and A2A.

---

## Conclusion: Chitin Shell occupies a validated but unoccupied architectural position

The research landscape validates every core design decision in Chitin Shell's architecture. The separation of LLMs from credentials has direct academic support from IsolateGPT, CaMeL, and the Design Patterns paper. The Intent-Verify-Execute model is corroborated by VSA, Guardians of the Agents, and VeriGuard. Blockchain-based policy enforcement is supported by ETHOS, ERC-8004's mainnet deployment, and multiple applied research papers. ZKML has matured enough to prove compliance properties even if full model inference verification remains expensive.

Three strategic advantages distinguish Chitin Shell from the current landscape. **First**, no existing open-source project integrates all three pillars—process isolation, on-chain policy, and ZK proofs—into a single coherent architecture; existing tools address fragments. **Second**, every major agent framework (LangChain, AutoGPT, CrewAI, MCP) has demonstrated fundamental credential security failures that architectural approaches can prevent; the LangGrinch vulnerability alone affected 847 million downloads. **Third**, the standards ecosystem (OWASP ASI, NIST IR 8596, ERC-8004) is coalescing around exactly the threat model Chitin Shell addresses, creating alignment between the project's architecture and emerging compliance requirements.

The primary technical risks center on ZKML overhead for complex policy verification (mitigable by using ZK for policy attestation rather than full inference), on-chain latency for real-time agent operations (addressable via L2 rollups with sub-second finality at <$0.01), and TEE side-channel vulnerabilities (manageable for credential storage where the attack surface is far smaller than for full inference). The market timing appears optimal: agent adoption is exponential, security tooling is nascent, and the $414M funding in agent-specific security against an $8.5B broader AI security market signals enormous room for growth.