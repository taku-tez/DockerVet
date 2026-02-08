import { Rule, Violation } from '../types';

export const DL3007: Rule = {
  id: 'DL3007',
  severity: 'warning',
  description: 'Using latest is prone to errors if the image will ever update',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      if (stage.from.tag === 'latest') {
        violations.push({ rule: 'DL3007', severity: 'warning', message: 'Using latest is prone to errors. Pin the version explicitly.', line: stage.from.line });
      }
    }
    return violations;
  },
};
