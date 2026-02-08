import { Rule, Violation } from '../types';

const INAPPROPRIATE_COMMANDS = ['ssh', 'vim', 'shutdown', 'service', 'ps', 'free', 'top', 'kill', 'mount', 'ifconfig', 'nano'];

export const DL3001: Rule = {
  id: 'DL3001',
  severity: 'info',
  description: 'For some bash commands it makes no sense running them in a Docker container like ssh, vim, shutdown, service, ps, free, top, kill, mount, ifconfig',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN') {
          for (const cmd of INAPPROPRIATE_COMMANDS) {
            const regex = new RegExp(`(?:^|[;&|]|\\b)${cmd}\\b`);
            if (regex.test(inst.arguments)) {
              violations.push({ rule: 'DL3001', severity: 'info', message: `Avoid using ${cmd} in RUN. It does not make sense in a Docker container`, line: inst.line });
            }
          }
        }
      }
    }
    return violations;
  },
};
