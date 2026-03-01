import * as fs from 'fs';
import * as path from 'path';

export interface IgnoreEntry {
  id: string;
  reason?: string;
  expires?: string; // ISO date string e.g. "2026-12-31"
}

export interface SarifConfig {
  export?: boolean;
  outputFile?: string;
}

export interface DockerVetConfig {
  version?: number;
  ignore: (string | IgnoreEntry)[];
  trustedRegistries: string[];
  requiredLabels: string[];
  allowedLabels?: string[];
  override: Record<string, { severity?: string }>;
  /** Minimum severity that triggers a non-zero exit code (error|warning|info) */
  severityThreshold?: 'error' | 'warning' | 'info';
  /** Which severity levels cause CI failure (exit code 2). Defaults to ['error'] */
  failOn?: ('error' | 'warning' | 'info')[];
  sarif?: SarifConfig;
}

const DEFAULT_CONFIG: DockerVetConfig = {
  ignore: [],
  trustedRegistries: [],
  requiredLabels: [],
  override: {},
};

export function loadConfig(configPath?: string): DockerVetConfig {
  const searchPaths = configPath
    ? [configPath]
    : ['.dockervet.yaml', '.dockervet.yml', '.dockervetrc.yaml', '.dockervetrc.yml', '.dockervetrc.json', '.dockervetrc'];

  for (const p of searchPaths) {
    const resolved = path.resolve(p);
    if (!fs.existsSync(resolved)) continue;

    const content = fs.readFileSync(resolved, 'utf-8');

    if (p.endsWith('.json')) {
      return normalizeConfig({ ...DEFAULT_CONFIG, ...JSON.parse(content) });
    }

    return normalizeConfig({ ...DEFAULT_CONFIG, ...parseYaml(content) });
  }

  return { ...DEFAULT_CONFIG };
}

function normalizeConfig(cfg: DockerVetConfig): DockerVetConfig {
  // Normalize ignore to always be string | IgnoreEntry[]
  cfg.ignore = cfg.ignore || [];
  return cfg;
}

/**
 * Load config from a `.securify.yaml` file, reading the `securify.docker` section.
 * Falls back to `loadConfig()` when no securify file is found.
 */
export function loadSecurifyConfig(securifyPath?: string): DockerVetConfig {
  const candidates = securifyPath
    ? [securifyPath]
    : ['.securify.yaml', '.securify.yml'];

  for (const p of candidates) {
    const resolved = path.resolve(p);
    if (!fs.existsSync(resolved)) continue;

    // Use loadConfig to parse, which handles all YAML formats
    return loadConfig(resolved);
  }

  // Fall back to standard DockerVet config
  return loadConfig();
}

/**
 * Returns the set of currently active (non-expired) ignore rule IDs.
 */
export function getActiveIgnoreIds(config: DockerVetConfig): Set<string> {
  const now = new Date();
  const ids = new Set<string>();

  for (const entry of config.ignore) {
    if (typeof entry === 'string') {
      ids.add(entry);
    } else {
      if (entry.expires) {
        const expiry = new Date(entry.expires);
        if (expiry < now) {
          // Expired — skip (do not ignore this rule)
          continue;
        }
      }
      ids.add(entry.id);
    }
  }

  return ids;
}

/**
 * Parse a YAML config file, supporting the v2 format with structured ignore entries.
 *
 * Supports:
 *   version: 2
 *   severity-threshold: warning
 *   fail-on: [error, warning]
 *   ignore:
 *     - DL3008
 *     - id: DV1001
 *       reason: "Using vault at runtime"
 *       expires: "2026-12-31"
 *   sarif:
 *     export: true
 *     outputFile: results.sarif
 */
function parseYaml(content: string): Partial<DockerVetConfig> {
  const result: any = {};
  const lines = content.split('\n');

  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      i++;
      continue;
    }

    // Top-level key
    const kvMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_-]*):\s*(.*)?$/);
    if (!kvMatch) {
      i++;
      continue;
    }

    const rawKey = kvMatch[1];
    const key = camelCase(rawKey);
    const value = kvMatch[2]?.trim() ?? '';
    const indent = line.length - line.trimStart().length;

    if (value === '' || value === null) {
      // Block sequence or mapping
      const block = collectBlock(lines, i + 1, indent);
      i += block.linesConsumed + 1;

      if (key === 'ignore') {
        result[key] = parseIgnoreBlock(block.lines);
      } else if (key === 'sarif') {
        result[key] = parseMappingBlock(block.lines);
      } else if (key === 'failOn') {
        result[key] = parseSequenceBlock(block.lines);
      } else {
        // Generic array of strings
        result[key] = parseSequenceBlock(block.lines);
      }
    } else if (value === '[]') {
      result[key] = [];
      i++;
    } else if (value.startsWith('[')) {
      result[key] = value.replace(/[\[\]]/g, '').split(',').map((s: string) => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
      i++;
    } else {
      // Scalar
      result[key] = parseScalar(value);
      i++;
    }
  }

  return result;
}

function camelCase(s: string): string {
  return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

function parseScalar(value: string): any {
  const v = value.replace(/^["']|["']$/g, '');
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (/^\d+$/.test(v)) return parseInt(v, 10);
  return v;
}

interface BlockResult {
  lines: string[];
  linesConsumed: number;
}

function collectBlock(lines: string[], startIdx: number, parentIndent: number): BlockResult {
  const blockLines: string[] = [];
  let j = startIdx;

  while (j < lines.length) {
    const line = lines[j];
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      j++;
      continue;
    }

    const lineIndent = line.length - line.trimStart().length;
    if (lineIndent <= parentIndent) break;

    blockLines.push(line);
    j++;
  }

  return { lines: blockLines, linesConsumed: j - startIdx };
}

function parseSequenceBlock(lines: string[]): string[] {
  const result: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('- ')) {
      result.push(trimmed.slice(2).trim().replace(/^["']|["']$/g, ''));
    }
  }
  return result;
}

function parseMappingBlock(lines: string[]): Record<string, any> {
  const result: Record<string, any> = {};
  for (const line of lines) {
    const trimmed = line.trim();
    const m = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_-]*):\s*(.*)$/);
    if (m) {
      result[camelCase(m[1])] = parseScalar(m[2].trim());
    }
  }
  return result;
}

/**
 * Parse the ignore block, supporting both plain strings and structured entries.
 *
 * Plain:
 *   - DL3008
 *
 * Structured:
 *   - id: DV1001
 *     reason: "Using vault at runtime"
 *     expires: "2026-12-31"
 */
function parseIgnoreBlock(lines: string[]): (string | IgnoreEntry)[] {
  const result: (string | IgnoreEntry)[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      i++;
      continue;
    }

    if (trimmed.startsWith('- ')) {
      const rest = trimmed.slice(2).trim();

      if (rest.match(/^[A-Za-z][A-Za-z0-9]+$/)) {
        // Plain rule ID: - DL3008
        result.push(rest);
        i++;
      } else if (rest.match(/^id:\s*/)) {
        // Structured entry starting on the same line as `-`
        const entry: IgnoreEntry = { id: rest.replace(/^id:\s*/, '').replace(/^["']|["']$/g, '') };
        const entryIndent = line.length - line.trimStart().length;
        i++;

        while (i < lines.length) {
          const subLine = lines[i];
          const subTrimmed = subLine.trim();
          const subIndent = subLine.length - subLine.trimStart().length;

          if (!subTrimmed || subTrimmed.startsWith('#')) {
            i++;
            continue;
          }

          if (subIndent <= entryIndent || subTrimmed.startsWith('- ')) break;

          const m = subTrimmed.match(/^(reason|expires|id):\s*(.*)$/);
          if (m) {
            (entry as any)[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
          }
          i++;
        }

        result.push(entry);
      } else {
        // Fallback: treat as plain string
        result.push(rest.replace(/^["']|["']$/g, ''));
        i++;
      }
    } else {
      // Nested mapping line (part of previous entry)
      i++;
    }
  }

  return result;
}
