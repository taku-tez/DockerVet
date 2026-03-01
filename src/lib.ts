/**
 * DockerVet Programmatic API
 *
 * Exposes the core scan functionality for use by other tools (e.g. Securify CLI).
 *
 * @example
 * ```typescript
 * import { scanDockerfile, scanDockerfileContent } from 'dockervet';
 *
 * // Scan a file on disk
 * const result = scanDockerfile('./Dockerfile');
 * console.log(result.violations);
 * console.log(result.exitCode); // 0 | 1 | 2 | 3
 *
 * // Scan raw content
 * const result2 = scanDockerfileContent('FROM ubuntu:20.04\nRUN apt-get install curl', 'Dockerfile');
 * ```
 */

import * as fs from 'fs';
import { parse } from './parser/parser';
import { lint } from './engine/linter';
import { loadConfig, DockerVetConfig, getActiveIgnoreIds } from './engine/config';
import { Violation } from './rules/types';

export { DockerVetConfig, Violation };
export type { IgnoreEntry, SarifConfig } from './engine/config';
export { ALL_RULES, RULE_MAP } from './rules/index';

/**
 * Exit codes used by DockerVet:
 * - 0: No violations (or only info/style when threshold not reached)
 * - 1: Warnings found
 * - 2: Errors found (or fail-on threshold reached)
 * - 3: Execution failure (file not found, parse error)
 */
export const EXIT_CODES = {
  OK: 0,
  WARNINGS: 1,
  ERRORS: 2,
  FAILURE: 3,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export interface ScanOptions {
  /** Path to a config file (.dockervet.yaml or .dockervetrc.yaml) */
  configPath?: string;
  /** Config object (overrides configPath) */
  config?: DockerVetConfig;
  /** Additional trusted registries */
  trustedRegistries?: string[];
  /** Additional rules to ignore */
  ignoreRules?: string[];
  /** Logical file path (used in violation messages and SARIF output) */
  filePath?: string;
}

export interface ScanResult {
  /** Logical file path that was scanned */
  filePath: string;
  /** All violations found */
  violations: Violation[];
  /** Recommended process exit code */
  exitCode: ExitCode;
}

/**
 * Scan the content of a Dockerfile string.
 *
 * @param content  Raw Dockerfile text
 * @param filePath Logical path for reporting (e.g. "Dockerfile", "services/api/Dockerfile")
 * @param options  Optional scan configuration
 */
export function scanDockerfileContent(
  content: string,
  filePath: string = '<stdin>',
  options: ScanOptions = {},
): ScanResult {
  try {
    const config = resolveConfig(options);
    const ast = parse(content);
    const violations = lint(ast, {
      config,
      trustedRegistries: options.trustedRegistries,
      filePath,
    });

    return { filePath, violations, exitCode: computeExitCode(violations, config) };
  } catch (err) {
    // Parse or rule errors — return exit code 3
    const msg = err instanceof Error ? err.message : String(err);
    return {
      filePath,
      violations: [{
        rule: 'INTERNAL', severity: 'error',
        message: `DockerVet internal error: ${msg}`,
        line: 0,
      }],
      exitCode: EXIT_CODES.FAILURE,
    };
  }
}

/**
 * Scan a Dockerfile at the given path.
 *
 * @param dockerfilePath Absolute or relative path to the Dockerfile
 * @param options        Optional scan configuration
 */
export function scanDockerfile(
  dockerfilePath: string,
  options: ScanOptions = {},
): ScanResult {
  if (!fs.existsSync(dockerfilePath)) {
    return {
      filePath: dockerfilePath,
      violations: [{
        rule: 'INTERNAL', severity: 'error',
        message: `File not found: ${dockerfilePath}`,
        line: 0,
      }],
      exitCode: EXIT_CODES.FAILURE,
    };
  }

  const content = fs.readFileSync(dockerfilePath, 'utf-8');
  return scanDockerfileContent(content, dockerfilePath, options);
}

/**
 * Scan multiple Dockerfiles and return an array of results.
 *
 * @param paths   Array of Dockerfile paths
 * @param options Optional scan configuration (shared across all files)
 */
export function scanDockerfiles(
  paths: string[],
  options: ScanOptions = {},
): ScanResult[] {
  return paths.map(p => scanDockerfile(p, options));
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function resolveConfig(options: ScanOptions): DockerVetConfig {
  const base = options.config ?? loadConfig(options.configPath);

  if (options.ignoreRules && options.ignoreRules.length > 0) {
    base.ignore = [...base.ignore, ...options.ignoreRules];
  }

  if (options.trustedRegistries && options.trustedRegistries.length > 0) {
    base.trustedRegistries = [...(base.trustedRegistries || []), ...options.trustedRegistries];
  }

  return base;
}

const SEVERITY_ORDER = ['error', 'warning', 'info', 'style'] as const;

function computeExitCode(violations: Violation[], config: DockerVetConfig): ExitCode {
  const failOn: string[] = config.failOn ?? ['error'];
  const hasFail = violations.some(v => failOn.includes(v.severity));
  if (hasFail) return EXIT_CODES.ERRORS;

  const hasWarnings = violations.some(v => v.severity === 'warning');
  if (hasWarnings) return EXIT_CODES.WARNINGS;

  return EXIT_CODES.OK;
}
