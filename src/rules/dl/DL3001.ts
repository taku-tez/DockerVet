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
          // Strip BuildKit --mount flags before checking
          const argsWithoutMount = inst.arguments.replace(/--mount=\S+/g, '');

          // Split into individual shell commands on ;, &&, ||, |, newlines
          const shellCmds = argsWithoutMount.split(/[;&|\n]+/).map(s => s.trim()).filter(Boolean);

          for (const cmd of INAPPROPRIATE_COMMANDS) {
            for (const shellCmd of shellCmds) {
              // Skip package install lines (apt-get install, apk add, etc.)
              if (/^\s*(apt-get|apt|apk|yum|dnf|microdnf|zypper|pacman|pip3?|npm|gem|go)\s+(install|add|get)\b/.test(shellCmd)) continue;

              // Match only as a standalone command at the start of the shell command
              // Not as a flag (--service, -kill) or part of another word
              const regex = new RegExp(`(?:^|\\s)${cmd}(?:\\s|$)`);
              // Also ensure it's not preceded by a dash (flag like --service)
              const flagRegex = new RegExp(`-\\w*${cmd}\\b`);
              if (regex.test(shellCmd) && !flagRegex.test(shellCmd)) {
                violations.push({ rule: 'DL3001', severity: 'info', message: `Avoid using ${cmd} in RUN. It does not make sense in a Docker container`, line: inst.line });
                break; // one violation per command per instruction
              }
            }
          }
        }
      }
    }
    return violations;
  },
};
