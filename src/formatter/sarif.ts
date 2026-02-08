import { Violation } from '../rules/types';
import { RULE_MAP } from '../rules/index';

const SEVERITY_MAP: Record<string, string> = {
  error: 'error',
  warning: 'warning',
  info: 'note',
  style: 'note',
};

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
          informationUri: 'https://github.com/tez-hub/dockervet',
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
