import { Rule, Violation } from '../types';

export const DL3003: Rule = {
  id: 'DL3003',
  severity: 'warning',
  description: 'Use WORKDIR to switch to a directory',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /(?:^|[;&|]\s*)cd\s+/.test(inst.arguments)) {
          violations.push({ rule: 'DL3003', severity: 'warning', message: 'Use WORKDIR to switch to a directory', line: inst.line });
        }
      }
    }
    return violations;
  },
};
