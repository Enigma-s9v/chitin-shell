# Chitin Shell — Implementation Plan

> **Version:** 0.1.0
> **Date:** 2026-02-17
> **Status:** Draft

---

## 1. Guiding Principles

- **Code over docs** — 動くプロトタイプを最速で出す。完璧な仕様書より不完全な動くコードのほうが価値がある
- **Incremental hardening** — 最初はシングルプロセスで動かし、段階的にコンテナ分離・オンチェーン化していく
- **DX first** — `npm start` で 5 分以内に動く。Docker 必須にしない（開発時）
- **Framework agnostic** — 特定の LLM フレームワークに依存しない。SDK + REST API がコア
- **Honest security** — 各フェーズで何が守れて何が守れないかを明示する

---

## 2. Milestone Overview

```
v0.1-alpha  ─── "動く最小限"
│  Intent spec + Policy Engine (JSON) + Secure Proxy
│  シングルプロセスモード（開発用）
│  npm start で即動く
│
v0.1-beta   ─── "本物のプロセス分離"
│  Docker 3 コンテナ構成
│  ネットワーク隔離 (iptables)
│  Output sanitization
│
v0.2        ─── "フレームワーク統合"
│  LangChain adapter
│  MCP gateway mode
│  CLI ツール (chitin-shell init/policy/logs)
│
v0.3        ─── "オンチェーンポリシー"
│  Solidity policy contracts (Base L2)
│  ERC-8004 DID integration (Chitin ID)
│  On-chain audit log anchoring
│
v0.4        ─── "ZKP 統合"
│  Intent provenance proofs
│  Data non-leakage proofs
│  Skill safety analysis (zkVM)
│
v1.0        ─── "Production Ready"
   GPU TEE support
   Multi-agent trust delegation
   A2A protocol integration
```

---

## 3. Tech Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Language** | TypeScript (Node.js 20+) | Chitin エコシステムと統一。Web 開発者が多い agent 界隈に合わせる |
| **Runtime** | Node.js + Docker | Phase 1 は Node.js のみ。Phase 2 で Docker 分離 |
| **Policy Engine** | Pure TypeScript (deterministic) | LLM 不使用。JSON Schema validation + custom rule engine |
| **Credential Vault** | node-keytar → HashiCorp Vault (optional) | ローカルは OS keychain、本番は Vault/TEE |
| **Sanitization** | regex + pattern matching | dlp-toolkit 等のライブラリ活用 |
| **Testing** | Vitest | Chitin エコシステム統一 |
| **Packaging** | npm (`@chitin-id/shell`) | scoped package、ESM only |
| **Container** | Docker Compose | 開発・本番両方 |
| **Chain** | Base L2 (Phase 3〜) | 既存 Chitin 資産との整合性 |
| **Monorepo** | Chitin 本体の `shell/` ディレクトリ | 初期は同一リポ。成長したら分離 |

---

## 4. Project Structure

```
shell/
├── docs/                          # 仕様書（既存）
│   ├── ARCHITECTURE.md
│   ├── README.md
│   └── IMPLEMENTATION_PLAN.md     # ← this file
│
├── packages/
│   ├── core/                      # @chitin-id/shell-core
│   │   ├── src/
│   │   │   ├── intent/
│   │   │   │   ├── types.ts           # Intent 型定義
│   │   │   │   ├── builder.ts         # Intent 生成ヘルパー
│   │   │   │   ├── signer.ts          # Intent 署名 (DID key)
│   │   │   │   └── validator.ts       # Intent 構造バリデーション
│   │   │   ├── policy/
│   │   │   │   ├── types.ts           # Policy 型定義
│   │   │   │   ├── engine.ts          # ポリシーエンジン本体
│   │   │   │   ├── tier.ts            # ティア判定ロジック
│   │   │   │   ├── rate-limiter.ts    # レート制限
│   │   │   │   └── loader.ts          # JSON / on-chain ポリシー読込
│   │   │   ├── proxy/
│   │   │   │   ├── types.ts           # Proxy 型定義
│   │   │   │   ├── vault.ts           # Credential vault interface
│   │   │   │   ├── executor.ts        # Intent → API call 変換・実行
│   │   │   │   ├── sanitizer.ts       # Output sanitization
│   │   │   │   └── mappers/           # Action → API mapping
│   │   │   │       ├── email.ts
│   │   │   │       ├── slack.ts
│   │   │   │       └── generic-http.ts
│   │   │   ├── audit/
│   │   │   │   ├── types.ts           # Audit log 型定義
│   │   │   │   ├── logger.ts          # 監査ロガー interface
│   │   │   │   └── local-logger.ts    # ローカルファイルロガー
│   │   │   ├── shell.ts               # ChitinShell メインクラス
│   │   │   └── index.ts               # Public API exports
│   │   ├── test/
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── vault-local/               # @chitin-id/shell-vault-local
│   │   └── src/
│   │       └── keychain-vault.ts      # OS keychain ベース vault
│   │
│   └── vault-hashicorp/           # @chitin-id/shell-vault-hashicorp (後日)
│
├── docker/
│   ├── Dockerfile.agent           # Intent Layer コンテナ
│   ├── Dockerfile.policy          # Verify Layer コンテナ
│   ├── Dockerfile.proxy           # Execute Layer コンテナ
│   ├── docker-compose.yml         # 本番構成
│   └── docker-compose.dev.yml     # 開発構成
│
├── config/
│   ├── example.env                # 設定例
│   ├── default-policy.json        # デフォルトポリシー
│   └── schemas/
│       ├── intent.schema.json     # Intent JSON Schema
│       └── policy.schema.json     # Policy JSON Schema
│
├── examples/
│   ├── basic/                     # 最小限の使用例
│   ├── langchain/                 # LangChain 統合例 (v0.2)
│   └── mcp-gateway/              # MCP gateway 例 (v0.2)
│
├── contracts/                     # Solidity (v0.3〜)
│   ├── src/
│   │   └── AgentPolicy.sol
│   └── test/
│
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── README.md                      # → docs/README.md のシンボリックリンク or コピー
```

---

## 5. Phase 1: v0.1-alpha — "動く最小限"

### 5.1 Goal

`npm install @chitin-id/shell` → 5 行のコードで Intent-Verify-Execute パイプラインが動く。シングルプロセス。Docker 不要。

### 5.2 Deliverables

```
[Core]
 ├─ Intent 型定義 + builder + validator
 ├─ Policy Engine (JSON ベース、Tier 0-3 判定)
 ├─ Secure Proxy (in-process、credential vault interface)
 ├─ Output Sanitizer (regex パターンマッチ)
 ├─ Audit Logger (ローカルファイル)
 └─ ChitinShell 統合クラス

[Config]
 ├─ default-policy.json
 ├─ Intent JSON Schema
 └─ Policy JSON Schema

[DX]
 ├─ examples/basic/ (動作サンプル)
 ├─ README (Quick Start)
 └─ npm package (@chitin-id/shell-core)
```

### 5.3 Task Breakdown

#### A. Intent Layer (3-4 days)

| # | Task | Description | Output |
|---|---|---|---|
| A1 | Intent 型定義 | `IntentV1` type + action enum + params union | `intent/types.ts` |
| A2 | Intent Builder | `createIntent()` — action + params → signed Intent | `intent/builder.ts` |
| A3 | Intent Signer | Ed25519 署名。DID key pair 生成 + 署名 + 検証 | `intent/signer.ts` |
| A4 | Intent Validator | JSON Schema validation + signature verification | `intent/validator.ts` |
| A5 | JSON Schema | Intent の JSON Schema 定義 | `config/schemas/intent.schema.json` |
| A6 | テスト | Intent の生成・署名・検証の unit test | `test/intent/` |

#### B. Policy Engine (3-4 days)

| # | Task | Description | Output |
|---|---|---|---|
| B1 | Policy 型定義 | Tier enum, PolicyRule, RateLimit types | `policy/types.ts` |
| B2 | Tier 判定 | action.type → Tier 0-3 判定ロジック | `policy/tier.ts` |
| B3 | Policy Engine | verify(intent) → approve/reject + reason | `policy/engine.ts` |
| B4 | Rate Limiter | Per-agent, per-action sliding window | `policy/rate-limiter.ts` |
| B5 | Policy Loader | JSON ファイルからポリシー読込 | `policy/loader.ts` |
| B6 | Default Policy | デフォルトポリシー JSON | `config/default-policy.json` |
| B7 | JSON Schema | Policy の JSON Schema 定義 | `config/schemas/policy.schema.json` |
| B8 | テスト | 各ティアの判定・レート制限・拒否パターン | `test/policy/` |

#### C. Secure Proxy (4-5 days)

| # | Task | Description | Output |
|---|---|---|---|
| C1 | Vault Interface | `IVault` — get/set/delete/list | `proxy/vault.ts` |
| C2 | In-Memory Vault | 開発用の in-memory 実装 | `proxy/vault.ts` |
| C3 | Executor | Intent + approval token → API call → result | `proxy/executor.ts` |
| C4 | Action Mappers | `send_email`, `slack_message`, `generic_http` | `proxy/mappers/` |
| C5 | Output Sanitizer | API key / token / PII パターン検出 + マスキング | `proxy/sanitizer.ts` |
| C6 | Sanitizer Patterns | 検出パターン定義 (sk-*, AIza*, Bearer, etc.) | `proxy/sanitizer.ts` |
| C7 | テスト | 実行フロー + sanitization の unit test | `test/proxy/` |

#### D. Integration (2-3 days)

| # | Task | Description | Output |
|---|---|---|---|
| D1 | ChitinShell クラス | 3 層を統合するメインエントリーポイント | `shell.ts` |
| D2 | Public API | `index.ts` — 公開 API exports | `index.ts` |
| D3 | Audit Logger | ローカルファイルベースの監査ログ | `audit/local-logger.ts` |
| D4 | E2E テスト | Intent 生成 → Policy 検証 → 実行 → sanitized result | `test/e2e/` |
| D5 | Basic Example | 最小限の使用例 | `examples/basic/` |
| D6 | Package setup | package.json, tsconfig, vitest, build | root config |

#### E. Polish (1-2 days)

| # | Task | Description | Output |
|---|---|---|---|
| E1 | README | Quick Start + API リファレンス | shell/README.md |
| E2 | npm publish 準備 | scoped package, exports, types | package.json |
| E3 | CI | GitHub Actions (lint + test + build) | `.github/workflows/` |

### 5.4 Estimated Timeline

```
Week 1:  A1-A6 (Intent) + B1-B4 (Policy core)
Week 2:  B5-B8 (Policy polish) + C1-C4 (Proxy core)
Week 3:  C5-C7 (Sanitizer) + D1-D6 (Integration)
Week 4:  E1-E3 (Polish) + Buffer
```

**合計: 約 2-3 週間（集中開発時）**

### 5.5 Usage Example (v0.1-alpha target)

```typescript
import { ChitinShell } from '@chitin-id/shell-core';

// 1. Initialize
const shell = new ChitinShell({
  policy: './policies/my-policy.json',
  vault: { type: 'memory' },  // or 'keychain' for OS keychain
});

// Register credentials in the vault (NOT in env vars)
await shell.vault.set('gmail', {
  type: 'oauth',
  token: 'ya29.xxx',
});

// 2. Create an Intent (what the LLM produces)
const intent = await shell.createIntent({
  action: 'send_email',
  params: {
    to: 'alice@example.com',
    subject: 'Meeting tomorrow',
    body: 'Shall we meet at 3pm?',
  },
});

// 3. Verify + Execute (Intent → Policy → Proxy → sanitized result)
const result = await shell.execute(intent);
// { status: 'approved', data: { messageId: 'msg-123' } }

// 4. Check audit log
const logs = await shell.audit.query({ last: 10 });
```

### 5.6 Security Guarantees (v0.1-alpha)

| Guarantee | Status | Note |
|---|---|---|
| Credentials NOT in env vars | ✅ | Vault にのみ保管 |
| LLM output → structured Intent | ✅ | 型安全な Intent 構造体 |
| Policy-based verification | ✅ | JSON ポリシー (Tier 0-3) |
| Output sanitization | ✅ | パターンベースのマスキング |
| Audit logging | ✅ | ローカルファイル |
| Process isolation | ❌ | v0.1-beta で対応 |
| Network isolation | ❌ | v0.1-beta で対応 |
| On-chain policy | ❌ | v0.3 で対応 |

---

## 6. Phase 2: v0.1-beta — "本物のプロセス分離"

### 6.1 Goal

Docker 3 コンテナ構成で**物理的なプロセス分離**を実現。LLM プロセスから credential へのアクセスが不可能になる。

### 6.2 Deliverables

| # | Task | Description |
|---|---|---|
| F1 | Dockerfile.agent | LLM sandbox — ネットワーク制限、env vars なし、read-only fs |
| F2 | Dockerfile.policy | Policy Engine — internal network only |
| F3 | Dockerfile.proxy | Secure Proxy — external network access、credentials mount |
| F4 | docker-compose.yml | 3 コンテナ + 2 ネットワーク (isolated / proxy) |
| F5 | HTTP API: Intent Layer → Policy Engine | REST endpoint for intent submission |
| F6 | HTTP API: Policy Engine → Proxy | REST endpoint for approved intent execution |
| F7 | Network isolation | iptables rules — agent can only reach policy endpoint |
| F8 | Healthcheck + restart | 各コンテナの死活監視 |
| F9 | docker-compose.dev.yml | 開発用（ホットリロード、ログ表示） |
| F10 | Security test suite | プロセス分離の検証テスト（agent → proxy 直接通信が失敗することの確認等） |

### 6.3 Security Guarantees (v0.1-beta)

| Guarantee | Status |
|---|---|
| Process isolation | ✅ |
| Network isolation | ✅ |
| Credential non-exposure to LLM | ✅ (物理的に不可能) |
| Read-only filesystem (LLM) | ✅ |

---

## 7. Phase 3: v0.2 — "フレームワーク統合"

### 7.1 Deliverables

| # | Task | Description |
|---|---|---|
| G1 | LangChain Callback Handler | LangChain の tool call を Intent に変換するアダプター |
| G2 | MCP Gateway Mode | MCP server ↔ Chitin Shell ↔ MCP client のプロキシ |
| G3 | CLI: `chitin-shell init` | プロジェクト初期化（policy 生成、vault setup） |
| G4 | CLI: `chitin-shell policy` | ポリシーの表示・検証・テスト |
| G5 | CLI: `chitin-shell logs` | 監査ログの検索・表示 |
| G6 | CrewAI Adapter | Agent executor middleware |
| G7 | Custom Agent SDK | 任意のエージェントから使える REST API + SDK |

### 7.2 MCP Gateway Architecture

```
MCP Client (Claude, etc.)
     │
     ▼
┌─────────────────────────────┐
│ Chitin Shell MCP Gateway    │
│                             │
│  MCP Request               │
│    ↓ parse                 │
│  Intent creation           │
│    ↓                       │
│  Policy verification       │
│    ↓ approved              │
│  Credential injection      │
│    ↓                       │
│  Upstream MCP Server call  │
│    ↓                       │
│  Output sanitization       │
│    ↓                       │
│  MCP Response              │
└─────────────────────────────┘
     │
     ▼
Upstream MCP Server (GitHub, Slack, etc.)
```

---

## 8. Phase 4: v0.3 — "オンチェーンポリシー"

### 8.1 Deliverables

| # | Task | Description |
|---|---|---|
| H1 | AgentPolicy.sol | ポリシースマートコントラクト (UUPS Proxy) |
| H2 | PolicyGovernor.sol | マルチシグ + タイムロック (24h) |
| H3 | AuditLog.sol | ハッシュアンカリング (batch commitment) |
| H4 | On-chain policy loader | `policy/loader.ts` に on-chain source 追加 |
| H5 | Chitin ID integration | ERC-8004 DID → agent_did in Intent |
| H6 | On-chain audit anchoring | 定期的にログハッシュを Base L2 に書き込み |
| H7 | Web dashboard | ポリシー管理 UI (Next.js) |
| H8 | Foundry test suite | コントラクトのテスト |

### 8.2 Target Chain

- **Base L2** — 既存 Chitin エコシステムとの整合性
- Gas cost: < $0.01/tx
- Finality: ~1 min (L1), instant soft finality

---

## 9. Phase 5: v0.4 — "ZKP 統合"

### 9.1 Scope

| Proof Type | Circuit | Use Case |
|---|---|---|
| Intent Provenance | User prompt hash → Intent derivation | 高リスク操作の正当性証明 |
| Data Non-Leakage | Raw response → sanitized output | 出力にシークレットが含まれないことの証明 |
| Skill Safety | Code hash → static analysis result | スキルの安全性証明 |

### 9.2 Recommended Framework

- **EZKL**: Production-ready、ONNX → ZK-SNARK。Trail of Bits 監査済み
- **RISC Zero**: zkVM ベース。汎用的だが proving time が長い
- 最初は EZKL で Intent Provenance proof のみ実装

---

## 10. npm Package Strategy

### 10.1 Package Map

| Package | Scope | Phase |
|---|---|---|
| `@chitin-id/shell-core` | Intent + Policy + Proxy + Audit | v0.1-alpha |
| `@chitin-id/shell-vault-local` | OS keychain vault | v0.1-alpha |
| `@chitin-id/shell-vault-hashicorp` | HashiCorp Vault adapter | v0.2 |
| `@chitin-id/shell-langchain` | LangChain adapter | v0.2 |
| `@chitin-id/shell-mcp` | MCP gateway | v0.2 |
| `@chitin-id/shell-cli` | CLI tool | v0.2 |
| `@chitin-id/shell-contracts` | Solidity ABIs + TypeScript bindings | v0.3 |

### 10.2 Versioning

- Semver (`0.x.y` until v1.0)
- Breaking changes allowed in `0.x`
- Changelog は git-cliff or changelog-generator skill で自動生成

---

## 11. GitHub Repository Strategy

### 11.1 Initial Phase (v0.1)

```
chitin-id/chitin-shell  (新規リポジトリ)
├── packages/
├── docker/
├── config/
├── examples/
├── .github/workflows/ci.yml
├── README.md
├── LICENSE (Apache-2.0)
├── CONTRIBUTING.md
└── SECURITY.md
```

- Chitin 本体 (`chitin-id/chitin-contracts`) とは別リポ
- OSSとしての独立性を確保
- Chitin ID との連携は optional dependency

### 11.2 CI/CD

| Trigger | Action |
|---|---|
| PR | lint + test + build |
| Push to main | lint + test + build + npm publish (canary) |
| Git tag `v*` | npm publish (release) + GitHub Release + Docker image |

---

## 12. Competitive Positioning

### 12.1 Differentiation Matrix

```
                    Process    On-chain   ZKP    Framework   Open
                    Isolation  Policy     Proofs Agnostic    Source
─────────────────────────────────────────────────────────────────
Chitin Shell          ✅         ✅        ✅       ✅         ✅
NeMo Guardrails       ❌         ❌        ❌       ❌(NVIDIA)  ✅
LLM Guard             ❌         ❌        ❌       ✅         ✅
LlamaFirewall         ❌         ❌        ❌       ❌(Meta)    ✅
Invariant Guardrails  ❌         ❌        ❌       partial    ✅
MCP-Scan              ❌         ❌        ❌       ❌(MCP)     ✅
Noma Security         partial    ❌        ❌       ✅         ❌
Keycard               ❌         partial   ❌       ✅         ❌
```

### 12.2 One-liner Positioning

> **"NeMo Guardrails filters what the LLM says. Chitin Shell ensures it can't steal your keys even if it wanted to."**

---

## 13. Success Metrics

### v0.1-alpha Launch

- [ ] `npm install` → 動く demo が 5 分以内
- [ ] README に Quick Start + 完全な API ドキュメント
- [ ] テストカバレッジ 80%+
- [ ] GitHub Stars 100+ (launch week)

### v0.1-beta Launch

- [ ] `docker compose up` → 3 コンテナが起動
- [ ] Security test: agent → proxy 直接通信が失敗することを証明
- [ ] 1 つ以上の Red Team PoC (prompt injection → credential theft が失敗)

### v0.2 Launch

- [ ] LangChain integration が動く
- [ ] MCP gateway mode が動く
- [ ] 外部コントリビューター 5+

---

## 14. Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| スコープクリープ | High | High | Phase ごとのスコープを厳守。v0.1-alpha は core のみ |
| 競合の先行 | High | Medium | 最速で v0.1-alpha を公開。動くコードが最大の差別化 |
| Docker 依存の採用障壁 | Medium | Medium | Phase 1 は Docker 不要のシングルプロセスモード |
| On-chain latency | Medium | Low | Tier 0-1 はオフチェーン。90% の操作に影響なし |
| ZKP の実用性 | Medium | Medium | Phase 4 まで延期。EZKL の成熟を待つ |
| セキュリティ脆弱性の発見 | High | Medium | 早期に Red Team テスト。SECURITY.md で responsible disclosure |

---

## 15. Next Steps

1. **リポジトリ作成**: `chitin-id/chitin-shell` を GitHub に作成
2. **プロジェクト初期化**: monorepo setup (packages/core)
3. **Intent 型定義から着手**: A1 → A2 → A3 の順で実装開始
4. **並行**: default-policy.json の設計

---

*This plan is a living document. Updated as implementation progresses.*
