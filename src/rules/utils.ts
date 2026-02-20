/**
 * Shared utility functions for Dockerfile lint rules.
 */
import { RuleContext, Violation, Severity } from './types';
import { Stage, DockerfileInstruction } from '../parser/types';

/** Archive file extensions pattern */
// Docker's ADD only auto-extracts tar-based archives (not zip).
// .zip files should remain as COPY since ADD will NOT extract them.
export const ARCHIVE_PATTERN = /\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|tar\.zst)$/i;

/** URL prefix check */
export function isUrl(s: string): boolean {
  return s.startsWith('http://') || s.startsWith('https://');
}

/**
 * Iterate over all stages and instructions, calling the callback for each instruction.
 */
export function forEachInstruction(
  ctx: RuleContext,
  type: string,
  cb: (inst: DockerfileInstruction, stage: Stage) => void,
): void {
  for (const stage of ctx.ast.stages) {
    for (const inst of stage.instructions) {
      if (inst.type === type) {
        cb(inst, stage);
      }
    }
  }
}

/**
 * Simple RUN instruction check: flag if regex matches.
 */
export function runCheck(
  ctx: RuleContext,
  regex: RegExp,
  ruleId: string,
  severity: Severity,
  msg: string,
): Violation[] {
  const violations: Violation[] = [];
  forEachInstruction(ctx, 'RUN', (inst) => {
    if (regex.test(inst.arguments)) {
      violations.push({ rule: ruleId, severity, message: msg, line: inst.line });
    }
  });
  return violations;
}

/**
 * RUN instruction check: flag if triggerRegex matches but mustHaveRegex does not.
 */
export function runCheckNeg(
  ctx: RuleContext,
  triggerRegex: RegExp,
  mustHaveRegex: RegExp,
  ruleId: string,
  severity: Severity,
  msg: string,
): Violation[] {
  const violations: Violation[] = [];
  forEachInstruction(ctx, 'RUN', (inst) => {
    if (triggerRegex.test(inst.arguments) && !mustHaveRegex.test(inst.arguments)) {
      violations.push({ rule: ruleId, severity, message: msg, line: inst.line });
    }
  });
  return violations;
}

/**
 * Extract packages from a RUN instruction matching a package manager install pattern.
 * Returns parsed package names (excluding flags and variables).
 */
export function extractPackages(
  args: string,
  installPattern: RegExp,
  opts?: { excludeFlags?: boolean },
): string[] {
  const m = args.match(installPattern);
  if (!m) return [];
  return m[1]
    .split(/\s+/)
    .filter(p => p && !p.startsWith('-') && !p.startsWith('$') && p !== '\\' && !/^[<%>]+$/.test(p) && !p.startsWith('/dev/') && !/^[>|&]+$/.test(p));
}

/**
 * Check RUN instructions for a package manager install command
 * and flag packages that don't satisfy the version pin predicate.
 */
export function checkVersionPinning(
  ctx: RuleContext,
  installPattern: RegExp,
  isPinned: (pkg: string) => boolean,
  ruleId: string,
  severity: Severity,
  makeMsg: (pkg: string) => string,
  extraFilter?: (pkg: string) => boolean,
): Violation[] {
  const violations: Violation[] = [];
  forEachInstruction(ctx, 'RUN', (inst) => {
    const pkgs = extractPackages(inst.arguments, installPattern);
    for (const pkg of pkgs) {
      if (extraFilter && !extraFilter(pkg)) continue;
      if (!isPinned(pkg)) {
        violations.push({ rule: ruleId, severity, message: makeMsg(pkg), line: inst.line });
      }
    }
  });
  return violations;
}
