import { Rule, Violation } from '../types';
import { WorkdirInstruction } from '../../parser/types';

export const DL3000: Rule = {
  id: 'DL3000',
  severity: 'error',
  description: 'Use absolute WORKDIR',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'WORKDIR') {
          const w = inst as WorkdirInstruction;
          if (!w.path.startsWith('/') && !w.path.startsWith('$')) {
            violations.push({ rule: 'DL3000', severity: 'error', message: 'Use absolute WORKDIR', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};
