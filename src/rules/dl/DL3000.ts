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
          // Unix absolute paths start with /; Windows absolute paths start with drive letter (C:/ or C:\)
          if (!w.path.startsWith('/') && !w.path.startsWith('$') && !/^[A-Za-z]:[/\\]/.test(w.path)) {
            violations.push({ rule: 'DL3000', severity: 'error', message: 'Use absolute WORKDIR', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};
