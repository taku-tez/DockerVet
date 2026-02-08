import { Rule, Violation } from '../types';

export const DL3006: Rule = {
  id: 'DL3006',
  severity: 'warning',
  description: 'Always tag the version of an image explicitly',
  check(ctx) {
    const violations: Violation[] = [];
    // Collect stage aliases to avoid false positives on internal references
    const stageAliases = new Set<string>();
    for (const stage of ctx.ast.stages) {
      if (stage.from.alias) stageAliases.add(stage.from.alias.toLowerCase());
    }
    for (const stage of ctx.ast.stages) {
      const f = stage.from;
      if (f.image === 'scratch') continue;
      // Skip references to other build stages (e.g., FROM gobuild)
      if (stageAliases.has(f.image.toLowerCase())) continue;
      if (!f.tag && !f.digest) {
        violations.push({ rule: 'DL3006', severity: 'warning', message: `Always tag the version of an image explicitly. Tag "${f.image}" with a specific version.`, line: f.line });
      }
    }
    return violations;
  },
};
