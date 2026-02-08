import { Rule, Violation } from '../types';
import { UserInstruction } from '../../parser/types';

export const DL3002: Rule = {
  id: 'DL3002',
  severity: 'warning',
  description: 'Last USER should not be root',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;

    const userInsts = lastStage.instructions.filter(i => i.type === 'USER');
    if (userInsts.length > 0) {
      const last = userInsts[userInsts.length - 1] as UserInstruction;
      if (last.user === 'root' || last.user === '0') {
        violations.push({ rule: 'DL3002', severity: 'warning', message: 'Last USER should not be root', line: last.line });
      }
    }
    return violations;
  },
};
