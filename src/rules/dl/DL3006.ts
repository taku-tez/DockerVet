import { Rule, Violation } from '../types';

export const DL3006: Rule = {
  id: 'DL3006',
  severity: 'warning',
  description: 'Always tag the version of an image explicitly',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const f = stage.from;
      if (f.image === 'scratch') continue;
      if (!f.tag && !f.digest) {
        violations.push({ rule: 'DL3006', severity: 'warning', message: `Always tag the version of an image explicitly. Tag "${f.image}" with a specific version.`, line: f.line });
      }
    }
    return violations;
  },
};
