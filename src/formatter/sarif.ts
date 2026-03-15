import { Violation } from '../rules/types';
import { RULE_MAP } from '../rules/index';

const SEVERITY_MAP: Record<string, string> = {
  error: 'error',
  warning: 'warning',
  info: 'note',
  style: 'note',
};

const PRECISION_MAP: Record<string, string> = {
  error: 'high',
  warning: 'medium',
  info: 'low',
  style: 'low',
};

const DOCS_BASE = 'https://github.com/taku-tez/DockerVet#rules';

interface ProcessResult {
  filename: string;
  violations: Violation[];
  exitCode: number;
}

function buildRuleEntry(id: string) {
  const rule = RULE_MAP.get(id);
  const severity = rule?.severity || 'info';
  const description = rule?.description || id;
  const ruleUrl = rule?.url || `${DOCS_BASE}`;
  const helpText = `${description}\n\nSee: ${ruleUrl}`;
  return {
    id,
    shortDescription: { text: description },
    fullDescription: { text: description },
    helpUri: ruleUrl,
    help: {
      text: helpText,
      markdown: `**${id}**: ${description}\n\nSee [DockerVet Rules](${ruleUrl})`,
    },
    defaultConfiguration: { level: SEVERITY_MAP[severity] || 'note' },
    properties: {
      precision: PRECISION_MAP[severity] || 'low',
      tags: ['security', 'dockerfile'],
    },
  };
}

export function formatSARIF(violations: Violation[], filename: string): string {
  const usedRules = new Set(violations.map(v => v.rule));
  const rules = Array.from(usedRules).map(id => buildRuleEntry(id));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dockervet',
          version: '0.1.0',
          informationUri: 'https://github.com/3-shake/DockerVet',
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
  const usedRules = new Set<string>();

  for (const result of results) {
    for (const v of result.violations) {
      usedRules.add(v.rule);
    }
  }

  const rules = Array.from(usedRules).map(id => buildRuleEntry(id));

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
          informationUri: 'https://github.com/3-shake/DockerVet',
          rules,
        },
      },
      results: sarifResults,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
