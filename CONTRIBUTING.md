# Contributing to Chitin Shell

Thank you for your interest in contributing to Chitin Shell! This project aims to be the security standard for AI agents, and we welcome contributions from the community.

## Getting Started

```bash
# Clone the repository
git clone https://github.com/chitin-id/chitin-shell.git
cd chitin-shell

# Install dependencies
npm install

# Run tests
cd packages/core && npm test

# Type check
cd packages/core && npx tsc --noEmit
```

## Project Structure

```
shell/
├── packages/
│   ├── core/          # @chitin-id/shell-core — Intent + Policy + Proxy + Audit
│   ├── langchain/     # @chitin-id/shell-langchain — LangChain adapter
│   ├── mcp/           # @chitin-id/shell-mcp — MCP gateway
│   └── cli/           # @chitin-id/shell-cli — CLI tool
├── examples/          # Usage examples
├── config/            # Default policy and schemas
└── docs/              # Documentation
```

## How to Contribute

### Bug Reports

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Node.js version, OS
- Relevant logs or error messages

### Feature Requests

Open an issue describing:
- The use case
- Proposed solution
- Alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`npm test`)
5. Ensure type checking passes (`npx tsc --noEmit`)
6. Commit with clear messages
7. Push and open a PR

### Code Style

- TypeScript, ESM only
- Zero external runtime dependencies for core package
- Node.js 20+ built-in modules only
- Use `vitest` for testing
- Follow existing patterns in the codebase

## Priority Areas

We especially welcome contributions in:

- **Framework integrations** — LangChain, CrewAI, AutoGPT, MCP adapters
- **Red team testing** — Try to break the isolation model. Prompt injection PoCs welcome
- **Policy templates** — Pre-built policies for common use cases (email bot, code assistant, trading bot)
- **Sanitization patterns** — Additional secret/PII detection patterns
- **Documentation** — Guides, tutorials, translations (Japanese, Chinese)
- **Security audits** — Formal analysis of the isolation model

## Security

If you discover a security vulnerability, please report it responsibly. See [SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
