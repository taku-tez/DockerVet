import { Rule, Violation } from '../types';
import { EnvInstruction, UserInstruction } from '../../parser/types';

// ---------------------------------------------------------------------------
// DV7xxx: Runtime Hardening
// ---------------------------------------------------------------------------

// DV7001: ENV LD_PRELOAD or LD_LIBRARY_PATH set — shared library injection risk
export const DV7001: Rule = {
  id: 'DV7001', severity: 'warning',
  description: 'Avoid setting LD_PRELOAD or LD_LIBRARY_PATH in ENV. These enable shared library injection attacks.',
  check(ctx) {
    const dangerous = /^(LD_PRELOAD|LD_LIBRARY_PATH)$/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV') {
          const e = inst as EnvInstruction;
          for (const pair of e.pairs) {
            if (dangerous.test(pair.key)) {
              violations.push({
                rule: 'DV7001', severity: 'warning',
                message: `Setting ${pair.key} in ENV enables shared library injection. Remove it unless absolutely required and document the justification.`,
                line: inst.line,
              });
            }
          }
        }
        // Also catch ARG with these names that are then used in ENV
        if (inst.type === 'ARG' && dangerous.test(inst.arguments.split('=')[0].trim())) {
          violations.push({
            rule: 'DV7001', severity: 'warning',
            message: `ARG ${inst.arguments.split('=')[0].trim()} can be used for shared library injection. Avoid exposing LD_PRELOAD/LD_LIBRARY_PATH as build arguments.`,
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV7002: nsenter / mount --bind / unshare in RUN — container escape risk
export const DV7002: Rule = {
  id: 'DV7002', severity: 'error',
  description: 'Avoid nsenter, mount --bind, or unshare in RUN instructions. These can facilitate container escapes.',
  check(ctx) {
    const escapePatterns = [
      /\bnsenter\b/,
      /\bmount\s+--bind\b/,
      /\bmount\s+-o\s+bind\b/,
      /\bunshare\b/,
    ];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        for (const pat of escapePatterns) {
          if (pat.test(inst.arguments)) {
            const match = inst.arguments.match(pat)?.[0] || 'command';
            violations.push({
              rule: 'DV7002', severity: 'error',
              message: `"${match}" in RUN instruction can facilitate container escapes. Remove unless required for build and document justification.`,
              line: inst.line,
            });
            break;
          }
        }
      }
    }
    return violations;
  },
};

// DV7003: useradd without --no-log-init creates huge sparse lastlog files
export const DV7003: Rule = {
  id: 'DV7003', severity: 'info',
  description: 'useradd without --no-log-init can create huge sparse files in /var/log/lastlog.',
  check(ctx) {
    const useradd = /\buseradd\b/;
    const noLogInit = /--no-log-init/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (useradd.test(inst.arguments) && !noLogInit.test(inst.arguments)) {
          violations.push({
            rule: 'DV7003', severity: 'info',
            message: 'useradd without --no-log-init can create huge sparse files in /var/log/lastlog. Add --no-log-init flag.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV7005: USER switches back to root in the final stage after setting non-root user
export const DV7005: Rule = {
  id: 'DV7005', severity: 'warning',
  description: 'USER switches back to root after setting a non-root user in the final stage.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;

    // Track USER instructions in the final stage
    const userInstructions: Array<{ user: string; line: number }> = [];
    for (const inst of lastStage.instructions) {
      if (inst.type !== 'USER') continue;
      const u = inst as UserInstruction;
      const userName = u.user || inst.arguments.trim().split(/[:\s]/)[0];
      userInstructions.push({ user: userName, line: inst.line });
    }

    // Look for pattern: non-root user followed by root user (privilege re-escalation)
    // We only flag if the LAST USER instruction is root — if it's non-root, the container
    // ultimately runs as non-root which is fine (intermediate root for setup is acceptable).
    if (userInstructions.length < 2) return violations;
    const lastUser = userInstructions[userInstructions.length - 1];
    const hasNonRoot = userInstructions.slice(0, -1).some(u =>
      u.user !== 'root' && u.user !== '0'
    );
    if (hasNonRoot && (lastUser.user === 'root' || lastUser.user === '0')) {
      violations.push({
        rule: 'DV7005', severity: 'warning',
        message: 'USER switches back to root after setting a non-root user. The container will run as root, defeating the purpose of the earlier USER instruction. Move root-required operations before the final USER instruction.',
        line: lastUser.line,
      });
    }
    return violations;
  },
};

// DV7004: chmod +s / chmod u+s / chmod g+s / chmod 4xxx / chmod 2xxx adding setuid/setgid bits
export const DV7004: Rule = {
  id: 'DV7004', severity: 'warning',
  description: 'Avoid adding setuid/setgid bits with chmod. These enable privilege escalation.',
  check(ctx) {
    // Matches chmod with setuid/setgid symbolic or octal modes
    const setuidSymbolic = /\bchmod\s+[^\s]*[uago]*\+[^\s]*s/;
    const setuidOctal = /\bchmod\s+[2467][0-7]{3}\b/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (setuidSymbolic.test(inst.arguments) || setuidOctal.test(inst.arguments)) {
          violations.push({
            rule: 'DV7004', severity: 'warning',
            message: 'chmod with setuid/setgid bits enables privilege escalation. Avoid adding SUID/SGID bits unless absolutely necessary.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};
