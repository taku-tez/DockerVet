import { Rule, Violation } from '../types';

/** Check if 'sudo' only appears as a package name in install commands, not as an actual command */
function isOnlyPackageInstall(args: string): boolean {
  // Remove all occurrences of sudo that are part of package install commands
  // e.g., apt-get install sudo, apk add sudo, yum install sudo
  const withoutPkgInstall = args.replace(/\b(?:apt-get|apt|apk|yum|dnf|zypper|pacman|microdnf)\b[^|;&]*/g, '');
  return !/\bsudo\b/.test(withoutPkgInstall);
}

export const DL3004: Rule = {
  id: 'DL3004',
  severity: 'error',
  description: 'Do not use sudo as it leads to unpredictable behavior',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /\bsudo\b/.test(inst.arguments) && !isOnlyPackageInstall(inst.arguments)) {
          violations.push({ rule: 'DL3004', severity: 'error', message: 'Do not use sudo as it leads to unpredictable behavior. Use the USER instruction instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};
