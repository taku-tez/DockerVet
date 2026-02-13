import { DockerfileAST } from '../parser/types';
import { ALL_RULES, RULE_MAP } from '../rules/index';
import { Rule, RuleContext, Violation } from '../rules/types';
import { DockerVetConfig } from './config';

export interface LintOptions {
  config: DockerVetConfig;
  trustedRegistries?: string[];
  filePath?: string;
}

export function lint(ast: DockerfileAST, options: LintOptions): Violation[] {
  const { config } = options;
  const ignoredRules = new Set(config.ignore || []);
  const trustedRegistries = options.trustedRegistries || config.trustedRegistries || [];

  const ctx: RuleContext = {
    ast,
    trustedRegistries,
    requiredLabels: config.requiredLabels || [],
    allowedLabels: config.allowedLabels,
    filePath: options.filePath,
  };

  const violations: Violation[] = [];

  for (const rule of ALL_RULES) {
    if (ignoredRules.has(rule.id)) continue;

    const ruleViolations = rule.check(ctx);

    for (const v of ruleViolations) {
      // Check inline ignores
      const lineIgnores = ast.inlineIgnores.get(v.line);
      if (lineIgnores && lineIgnores.includes(v.rule)) continue;

      // Apply severity override
      const override = config.override?.[v.rule];
      if (override?.severity) {
        v.severity = override.severity as any;
      }

      violations.push(v);
    }
  }

  // Sort by line number
  violations.sort((a, b) => a.line - b.line || a.rule.localeCompare(b.rule));

  return violations;
}
