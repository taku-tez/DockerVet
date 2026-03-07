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

// DV7006: Kernel parameter manipulation via /proc/sys/ writes or sysctl
// Writing to /proc/sys/ or using sysctl in containers is a security concern:
// - Requires privileged mode or specific capabilities (CAP_SYS_ADMIN)
// - Can weaken host kernel security settings (ip_forward, randomize_va_space, etc.)
// - Indicates the container expects elevated privileges
export const DV7006: Rule = {
  id: 'DV7006', severity: 'warning',
  description: 'Avoid kernel parameter manipulation in containers.',
  check(ctx) {
    // Match writing to /proc/sys/ paths (echo/tee/printf to /proc/sys/...)
    const procSysWrite = /(?:echo|printf|tee)\s+.*?\/proc\/sys\//;
    // Also match direct sysctl commands
    const sysctlCmd = /\bsysctl\s+(?:-w\s+)?[a-zA-Z0-9_.]+\s*=/;
    // Match reading /proc/sys is fine; only flag writes
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (procSysWrite.test(inst.arguments)) {
          violations.push({
            rule: 'DV7006', severity: 'warning',
            message: 'Writing to /proc/sys/ manipulates kernel parameters. This requires privileged mode and can weaken host security. Use kernel tuning at the host/orchestrator level instead.',
            line: inst.line,
          });
        } else if (sysctlCmd.test(inst.arguments)) {
          violations.push({
            rule: 'DV7006', severity: 'warning',
            message: 'sysctl modifies kernel parameters at runtime. This requires privileged containers and affects host security. Configure kernel parameters via pod securityContext or host-level tuning.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV7007: Process supervisor / multi-service container anti-pattern
// Running multiple services in a single container violates the one-process-per-container principle.
// Process supervisors (supervisord, s6-overlay, runit, monit) indicate multi-service design
// which complicates health checks, logging, scaling, and crash recovery.
export const DV7007: Rule = {
  id: 'DV7007', severity: 'info',
  description: 'Avoid running multiple services in a single container.',
  check(ctx) {
    const supervisorInstall = /(?:pip3?\s+install\s+[^&|;]*\bsupervisor\b|apt-get\s+install\s+[^&|;]*\bsupervisor\b|apk\s+add\s+[^&|;]*\bsupervisor\b|yum\s+install\s+[^&|;]*\bsupervisord?\b)/i;
    const s6Install = /(?:s6-overlay|s6-svscan|s6-supervise)/i;
    const runitInstall = /(?:apt-get\s+install\s+[^&|;]*\brunit\b|apk\s+add\s+[^&|;]*\brunit\b)/i;
    const monitInstall = /(?:apt-get\s+install\s+[^&|;]*\bmonit\b|apk\s+add\s+[^&|;]*\bmonit\b)/i;
    // Also detect cron daemon installation (should use orchestrator scheduling)
    const cronInstall = /(?:apt-get\s+install\s+[^&|;]*\bcron\b|apk\s+add\s+[^&|;]*\bdcron\b|yum\s+install\s+[^&|;]*\bcronie?\b)/i;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (supervisorInstall.test(args)) {
          violations.push({
            rule: 'DV7007', severity: 'info',
            message: 'supervisord detected. Running multiple services in one container complicates health checks, logging, and scaling. Consider splitting into separate containers.',
            line: inst.line,
          });
        } else if (s6Install.test(args)) {
          violations.push({
            rule: 'DV7007', severity: 'info',
            message: 's6-overlay process supervisor detected. Consider whether multiple services can be split into separate containers for better orchestration.',
            line: inst.line,
          });
        } else if (runitInstall.test(args)) {
          violations.push({
            rule: 'DV7007', severity: 'info',
            message: 'runit process supervisor detected. Consider splitting services into separate containers for better isolation and scaling.',
            line: inst.line,
          });
        } else if (monitInstall.test(args)) {
          violations.push({
            rule: 'DV7007', severity: 'info',
            message: 'monit process monitor detected. Container orchestrators (Kubernetes, Docker Compose) handle process monitoring. Consider using orchestrator-level health checks instead.',
            line: inst.line,
          });
        } else if (cronInstall.test(args)) {
          violations.push({
            rule: 'DV7007', severity: 'info',
            message: 'cron daemon detected in container. Use orchestrator-level scheduling (Kubernetes CronJob, ECS Scheduled Tasks) instead of in-container cron.',
            line: inst.line,
          });
        }
      }
    }
    // Also check ENTRYPOINT/CMD for supervisor
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'CMD' && inst.type !== 'ENTRYPOINT') continue;
        if (/supervisord/i.test(inst.arguments)) {
          violations.push({
            rule: 'DV7007', severity: 'info',
            message: 'Container entrypoint uses supervisord. Running multiple services in one container complicates health checks, logging, and scaling. Consider splitting into separate containers.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};
