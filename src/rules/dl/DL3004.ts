import { Rule, Violation } from '../types';

export const DL3004: Rule = {
  id: 'DL3004',
  severity: 'error',
  description: 'Do not use sudo as it leads to unpredictable behavior',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /\bsudo\b/.test(inst.arguments)) {
          violations.push({ rule: 'DL3004', severity: 'error', message: 'Do not use sudo as it leads to unpredictable behavior. Use the USER instruction instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};
