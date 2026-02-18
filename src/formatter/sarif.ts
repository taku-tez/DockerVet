import { Violation } from '../rules/types';
import { RULE_MAP } from '../rules/index';

const SEVERITY_MAP: Record<string, string> = {
  error: 'error',
  warning: 'warning',
  info: 'note',
  style: 'note',
};

interface ProcessResult {
  filename: string;
  violations: Violation[];
  exitCode: number;
}

export function formatSARIF(violations: Violation[], filename: string): string {
  const usedRules = new Set(violations.map(v => v.rule));
  const rules = Array.from(usedRules).map(id => {
    const rule = RULE_MAP.get(id);
    return {
      id,
      shortDescription: { text: rule?.description || id },
      defaultConfiguration: { level: SEVERITY_MAP[rule?.severity || 'info'] || 'note' },
    };
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dockervet',
          version: '0.1.0',
          informationUri: 'https://github.com/taku-tez/DockerVet',
          rules,
        },
      },
      results: violations.map(v => ({
        ruleId: v.rule,
        level: SEVERITY_MAP[v.severity] || 'note',
        message: { text: v.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: filename },
            region: { startLine: v.line, startColumn: v.column || 1 },
          },
        }],
      })),
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Format multiple file results as a single SARIF output.
 * This ensures valid JSON output when processing multiple files.
 */
export function formatSARIFBatch(results: ProcessResult[]): string {
  const allViolations: Violation[] = [];
  const usedRules = new Set<string>();
  
  for (const result of results) {
    for (const v of result.violations) {
      allViolations.push(v);
      usedRules.add(v.rule);
    }
  }

  const rules = Array.from(usedRules).map(id => {
    const rule = RULE_MAP.get(id);
    return {
      id,
      shortDescription: { text: rule?.description || id },
      defaultConfiguration: { level: SEVERITY_MAP[rule?.severity || 'info'] || 'note' },
    };
  });

  const sarifResults = results.flatMap(result =>
    result.violations.map(v => ({
      ruleId: v.rule,
      level: SEVERITY_MAP[v.severity] || 'note',
      message: { text: v.message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: result.filename },
          region: { startLine: v.line, startColumn: v.column || 1 },
        },
      }],
    }))
  );

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dockervet',
          version: '0.1.0',
          informationUri: 'https://github.com/taku-tez/DockerVet',
          rules,
        },
      },
      results: sarifResults,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
