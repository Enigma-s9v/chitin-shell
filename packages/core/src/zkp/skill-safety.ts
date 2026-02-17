/**
 * ZKP Skill Safety Proof — static analysis checks on skill code.
 *
 * Pure regex-based analysis (no external tools or AST parsers).
 * Generates a proof that the analysis was performed on specific code.
 *
 * Uses only node:crypto — zero external dependencies.
 */

import { createHash } from 'node:crypto';
import type { SkillSafetyCheck, SkillSafetyProof } from './types.js';

/**
 * Compute SHA-256 hash and return as 0x-prefixed hex string.
 */
function sha256(data: string): string {
  return '0x' + createHash('sha256').update(data).digest('hex');
}

/** A rule that checks code for dangerous patterns */
interface SafetyRule {
  name: string;
  pattern: RegExp;
  description: string;
  severity: 'error' | 'warning';
}

/**
 * Safety rules — order doesn't matter, all are checked independently.
 *
 * Each pattern is tested against the full source code.
 * A match means the check FAILS (the dangerous pattern was found).
 */
const SAFETY_RULES: SafetyRule[] = [
  {
    name: 'noEval',
    pattern: /\beval\s*\(|new\s+Function\s*\(|vm\.runInNewContext\s*\(/,
    description: 'No eval(), new Function(), or vm.runInNewContext',
    severity: 'error',
  },
  {
    name: 'noProcessEnv',
    pattern: /\bprocess\.env\b/,
    description: 'No process.env access',
    severity: 'error',
  },
  {
    name: 'noNetworkImport',
    pattern: /import\s*\(\s*['"`]https?:\/\//,
    description: 'No dynamic import from network URLs',
    severity: 'error',
  },
  {
    name: 'noFsWrite',
    pattern: /\bfs\s*\.\s*(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|rename|renameSync|unlink|unlinkSync|rmdir|rmdirSync|rm|rmSync)\b/,
    description: 'No filesystem write operations',
    severity: 'error',
  },
  {
    name: 'noDangerousGlobals',
    pattern: /__proto__|constructor\s*\.\s*constructor/,
    description: 'No __proto__ or constructor.constructor access',
    severity: 'error',
  },
  {
    name: 'noShellExec',
    pattern: /child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\b|\bexecSync\s*\(|\bspawn\s*\(/,
    description: 'No child_process.exec, execSync, spawn, etc.',
    severity: 'error',
  },
  {
    name: 'boundedLoops',
    pattern: /while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)|while\s*\(\s*1\s*\)/,
    description: 'No unbounded loops (while(true), for(;;), while(1))',
    severity: 'warning',
  },
  {
    name: 'noCredentialLiteral',
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9_-]{20,}|AIza[a-zA-Z0-9_-]{35}|AKIA[A-Z0-9]{16}|gh[pos]_[a-zA-Z0-9]{20,}|xox[bpras]-[a-zA-Z0-9-]+/,
    description: 'No hardcoded API keys or credentials',
    severity: 'error',
  },
];

/**
 * Analyze skill code for safety violations.
 *
 * @param code - The skill source code to analyze
 * @returns Array of check results (passed=true means the check passed, i.e. no violation)
 */
export function analyzeSkillSafety(code: string): SkillSafetyCheck[] {
  return SAFETY_RULES.map((rule) => {
    const match = rule.pattern.test(code);
    return {
      name: rule.name,
      passed: !match,
      details: match ? `Violation: ${rule.description}` : undefined,
    };
  });
}

/**
 * Generate a skill safety proof.
 *
 * @param code - The skill source code
 * @returns Proof containing code hash, analysis hash, and check results
 */
export function generateSkillSafetyProof(code: string): SkillSafetyProof {
  const checks = analyzeSkillSafety(code);
  const passed = checks.every((c) => c.passed);

  const codeHash = sha256(code);
  const analysisHash = sha256(JSON.stringify(checks));

  return {
    codeHash,
    analysisHash,
    checks,
    passed,
    timestamp: Date.now(),
    scheme: 'sha256-commit',
  };
}

/**
 * Verify a skill safety proof against the original code.
 *
 * Re-runs the analysis and compares hashes.
 *
 * @param proof - The proof to verify
 * @param code - The original source code
 * @returns true if the proof matches the code
 */
export function verifySkillSafetyProof(proof: SkillSafetyProof, code: string): boolean {
  // Verify code hash
  const expectedCodeHash = sha256(code);
  if (expectedCodeHash !== proof.codeHash) {
    return false;
  }

  // Re-run analysis and verify analysis hash
  const checks = analyzeSkillSafety(code);
  const expectedAnalysisHash = sha256(JSON.stringify(checks));
  if (expectedAnalysisHash !== proof.analysisHash) {
    return false;
  }

  // Verify the passed flag
  const expectedPassed = checks.every((c) => c.passed);
  if (expectedPassed !== proof.passed) {
    return false;
  }

  return true;
}
