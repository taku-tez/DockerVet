#!/usr/bin/env npx tsx
/**
 * DockerVet FP Triage Script
 *
 * Reads DockerVet JSON output and classifies findings as:
 * - "fp"        : Auto-classified false positive
 * - "candidate" : FP candidate (needs human review)
 * - "legitimate": Real finding
 */

import { readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────

export interface Finding {
  file: string;
  line: number;
  column: number;
  rule: string;
  severity: string;
  message: string;
}

export type Classification = 'fp' | 'candidate' | 'legitimate';

export interface ClassifiedFinding extends Finding {
  classification: Classification;
  reason: string;
}

interface DirectoryExclusion {
  description: string;
  directories: string[];
}

interface FilenameExclusion {
  description: string;
  exact: string[];
  suffixes: string[];
}

interface Condition {
  type: string;
  pattern: string;
  classification: 'fp' | 'candidate';
}

interface ContextualRule {
  description: string;
  conditions: Condition[];
}

export interface FPPatterns {
  version: string;
  patterns: {
    directoryExclusions: Record<string, DirectoryExclusion>;
    filenameExclusions: Record<string, FilenameExclusion>;
    contextualRules: Record<string, ContextualRule>;
  };
}

// ── Classification Logic ───────────────────────────────────────────────

export function matchesDirectoryPattern(
  filePath: string,
  directories: string[],
): boolean {
  // Normalise to forward-slash for cross-platform comparison
  const norm = filePath.replace(/\\/g, '/');
  return directories.some((dir) => {
    const d = dir.replace(/\/$/, ''); // strip trailing slash
    return norm.includes(`/${d}/`) || norm.startsWith(`${d}/`);
  });
}

export function matchesFilenamePattern(
  filePath: string,
  exact: string[],
  suffixes: string[],
): boolean {
  const name = basename(filePath);
  if (exact.includes(name)) return true;
  return suffixes.some((s) => name.endsWith(s));
}

export function matchesContextualRule(
  finding: Finding,
  conditions: Condition[],
): { matched: boolean; classification: Classification; reason: string } {
  for (const cond of conditions) {
    if (cond.type === 'messageMatch') {
      const re = new RegExp(cond.pattern, 'i');
      if (re.test(finding.message)) {
        return {
          matched: true,
          classification: cond.classification,
          reason: `message matches /${cond.pattern}/i`,
        };
      }
    }
  }
  return { matched: false, classification: 'legitimate', reason: '' };
}

export function classifyFinding(
  finding: Finding,
  patterns: FPPatterns,
): ClassifiedFinding {
  const { rule, file } = finding;
  const { directoryExclusions, filenameExclusions, contextualRules } =
    patterns.patterns;

  // 1. Directory exclusion check
  const dirExcl = directoryExclusions[rule];
  if (dirExcl && matchesDirectoryPattern(file, dirExcl.directories)) {
    const matchedDir = dirExcl.directories.find(
      (d) =>
        file.replace(/\\/g, '/').includes(`/${d.replace(/\/$/, '')}/`) ||
        file.replace(/\\/g, '/').startsWith(`${d.replace(/\/$/, '')}/`),
    );
    return {
      ...finding,
      classification: 'fp',
      reason: `directory: ${matchedDir}`,
    };
  }

  // 2. Filename exclusion check
  const fnExcl = filenameExclusions[rule];
  if (fnExcl && matchesFilenamePattern(file, fnExcl.exact, fnExcl.suffixes)) {
    return {
      ...finding,
      classification: 'fp',
      reason: `filename: ${basename(file)}`,
    };
  }

  // 3. Contextual rule check
  const ctxRule = contextualRules[rule];
  if (ctxRule) {
    const result = matchesContextualRule(finding, ctxRule.conditions);
    if (result.matched) {
      return { ...finding, classification: result.classification, reason: result.reason };
    }
  }

  return { ...finding, classification: 'legitimate', reason: '' };
}

export function classifyFindings(
  findings: Finding[],
  patterns: FPPatterns,
): ClassifiedFinding[] {
  return findings.map((f) => classifyFinding(f, patterns));
}

// ── Report Generation ──────────────────────────────────────────────────

export function generateReport(classified: ClassifiedFinding[]): string {
  const total = classified.length;
  const fps = classified.filter((c) => c.classification === 'fp');
  const candidates = classified.filter((c) => c.classification === 'candidate');
  const legit = classified.filter((c) => c.classification === 'legitimate');

  const pct = (n: number) => total === 0 ? '0.0' : ((n / total) * 100).toFixed(1);

  const lines: string[] = [];
  lines.push('# DockerVet FP Triage Report');
  lines.push('');
  lines.push('## Summary');
  lines.push(`- Total findings: ${total}`);
  lines.push(`- Auto-classified FP: ${fps.length} (${pct(fps.length)}%)`);
  lines.push(`- FP candidates (review needed): ${candidates.length} (${pct(candidates.length)}%)`);
  lines.push(`- Legitimate findings: ${legit.length} (${pct(legit.length)}%)`);
  lines.push('');

  // Group by rule
  const groupByRule = (items: ClassifiedFinding[]) => {
    const map = new Map<string, ClassifiedFinding[]>();
    for (const item of items) {
      const arr = map.get(item.rule) || [];
      arr.push(item);
      map.set(item.rule, arr);
    }
    return map;
  };

  if (fps.length > 0) {
    lines.push('## Auto-classified False Positives');
    lines.push('');
    for (const [rule, items] of groupByRule(fps)) {
      lines.push(`### ${rule} - ${items[0].message.slice(0, 60)}`);
      for (const item of items) {
        lines.push(`- ${item.file} (${item.reason})`);
      }
      lines.push('');
    }
  }

  if (candidates.length > 0) {
    lines.push('## FP Candidates (Review Needed)');
    lines.push('');
    for (const [rule, items] of groupByRule(candidates)) {
      lines.push(`### ${rule} - ${items[0].message.slice(0, 60)}`);
      for (const item of items) {
        lines.push(`- ${item.file} (${item.reason})`);
      }
      lines.push('');
    }
  }

  if (legit.length > 0) {
    lines.push('## Legitimate Findings');
    lines.push('');
    for (const [rule, items] of groupByRule(legit)) {
      lines.push(`### ${rule} - ${items[0].message.slice(0, 60)}`);
      for (const item of items) {
        lines.push(`- ${item.file}:${item.line}`);
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ── CLI Entry Point ────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Usage: npx tsx scripts/fp-triage.ts <dockervet-output.json> [fp-patterns.json]');
    process.exit(1);
  }

  const inputPath = resolve(args[0]);
  const patternsPath = resolve(args[1] || 'scripts/fp-patterns.json');

  const findings: Finding[] = JSON.parse(readFileSync(inputPath, 'utf-8'));
  const patterns: FPPatterns = JSON.parse(readFileSync(patternsPath, 'utf-8'));

  const classified = classifyFindings(findings, patterns);
  console.log(generateReport(classified));
}

// Only run main when executed directly
if (process.argv[1]?.endsWith('fp-triage.ts') || process.argv[1]?.includes('fp-triage')) {
  main();
}
