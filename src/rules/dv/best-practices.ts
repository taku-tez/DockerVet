import { Rule, Violation } from '../types';
import { CopyInstruction, EnvInstruction, ExposeInstruction } from '../../parser/types';

// DV4001: Multiple package install in separate RUNs
export const DV4001: Rule = {
  id: 'DV4001', severity: 'info',
  description: 'Consider combining multiple package install commands with && in a single RUN.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const installRuns = stage.instructions.filter(i =>
        i.type === 'RUN' && /(?:apt-get|yum|dnf|apk)\s+(?:install|add)/.test(i.arguments)
      );
      if (installRuns.length > 1) {
        for (const r of installRuns.slice(1)) {
          violations.push({ rule: 'DV4001', severity: 'info', message: 'Multiple package install RUN instructions detected. Consider combining them with && to reduce layers.', line: r.line });
        }
      }
    }
    return violations;
  },
};

// DV4002: Consecutive RUN instructions
export const DV4002: Rule = {
  id: 'DV4002', severity: 'info',
  description: 'Consecutive RUN instructions can be combined to reduce layers.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      let consecutiveCount = 0;
      let firstLine = 0;
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN') {
          consecutiveCount++;
          if (consecutiveCount === 1) firstLine = inst.line;
          if (consecutiveCount >= 3) {
            violations.push({ rule: 'DV4002', severity: 'info', message: `${consecutiveCount} consecutive RUN instructions detected. Consider combining with && to reduce layers.`, line: firstLine });
            break;
          }
        } else {
          consecutiveCount = 0;
        }
      }
    }
    return violations;
  },
};

// DV4003: WORKDIR not set before RUN
export const DV4003: Rule = {
  id: 'DV4003', severity: 'info',
  description: 'No WORKDIR set before RUN instructions.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const hasWorkdir = stage.instructions.some(i => i.type === 'WORKDIR');
      const hasRun = stage.instructions.some(i => i.type === 'RUN');
      if (hasRun && !hasWorkdir) {
        violations.push({ rule: 'DV4003', severity: 'info', message: 'No WORKDIR set. Use WORKDIR to define the working directory explicitly.', line: stage.from.line });
      }
    }
    return violations;
  },
};

// DV4004: ARG defined before ENV (build cache)
export const DV4004: Rule = {
  id: 'DV4004', severity: 'info',
  description: 'ENV referencing an ARG should have the ARG defined before it for proper cache utilization.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const envIndices: number[] = [];
      const argIndices: number[] = [];
      stage.instructions.forEach((inst, idx) => {
        if (inst.type === 'ENV') envIndices.push(idx);
        if (inst.type === 'ARG') argIndices.push(idx);
      });
      // Flag if ARG comes after ENV in same stage
      for (const ai of argIndices) {
        for (const ei of envIndices) {
          if (ai > ei) {
            const argInst = stage.instructions[ai];
            violations.push({ rule: 'DV4004', severity: 'info', message: 'ARG defined after ENV. Define ARG before ENV for better build cache utilization.', line: argInst.line });
            return violations;
          }
        }
      }
    }
    return violations;
  },
};

// DV4005: No ENTRYPOINT or CMD
export const DV4005: Rule = {
  id: 'DV4005', severity: 'info',
  description: 'No CMD or ENTRYPOINT found in the final stage.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    const hasCmdOrEp = lastStage.instructions.some(i => i.type === 'CMD' || i.type === 'ENTRYPOINT');
    if (!hasCmdOrEp) {
      violations.push({ rule: 'DV4005', severity: 'info', message: 'No CMD or ENTRYPOINT instruction found in the final stage.', line: lastStage.from.line });
    }
    return violations;
  },
};

// DV4006: Large EXPOSE port range
export const DV4006: Rule = {
  id: 'DV4006', severity: 'warning',
  description: 'Exposing a large range of ports is usually unnecessary.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'EXPOSE') continue;
        // Check for range syntax like 8000-9000
        const rangeMatch = inst.arguments.match(/(\d+)-(\d+)/);
        if (rangeMatch) {
          const start = parseInt(rangeMatch[1]);
          const end = parseInt(rangeMatch[2]);
          if (end - start > 100) {
            violations.push({ rule: 'DV4006', severity: 'warning', message: `Large port range exposed (${start}-${end}). Consider exposing only necessary ports.`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV4007: DEBIAN_FRONTEND=noninteractive as global ENV
export const DV4007: Rule = {
  id: 'DV4007', severity: 'info',
  description: 'DEBIAN_FRONTEND=noninteractive should be set via ARG, not ENV.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'ENV') continue;
        const e = inst as EnvInstruction;
        if (e.pairs.some(p => p.key === 'DEBIAN_FRONTEND' && p.value === 'noninteractive')) {
          violations.push({ rule: 'DV4007', severity: 'info', message: 'DEBIAN_FRONTEND=noninteractive is set as ENV. Use ARG instead to avoid persisting in the final image.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4008: TODO/FIXME/HACK comments
export const DV4008: Rule = {
  id: 'DV4008', severity: 'info',
  description: 'TODO/FIXME/HACK comment found in Dockerfile.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const comment of ctx.ast.comments) {
      if (/\b(TODO|FIXME|HACK|XXX)\b/i.test(comment.arguments)) {
        violations.push({ rule: 'DV4008', severity: 'info', message: 'TODO/FIXME/HACK comment found. Resolve before production use.', line: comment.line });
      }
    }
    return violations;
  },
};

// DV4009: chmod 777
export const DV4009: Rule = {
  id: 'DV4009', severity: 'warning',
  description: 'Avoid chmod 777. Use more restrictive permissions.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /chmod\s+777/.test(inst.arguments)) {
          violations.push({ rule: 'DV4009', severity: 'warning', message: 'chmod 777 grants excessive permissions. Use more restrictive permissions.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4010: chown -R (recursive, increases layer size)
export const DV4010: Rule = {
  id: 'DV4010', severity: 'info',
  description: 'Recursive chown increases layer size. Use --chown flag on COPY instead.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /chown\s+-R/.test(inst.arguments)) {
          violations.push({ rule: 'DV4010', severity: 'info', message: 'Recursive chown -R increases layer size. Consider using COPY --chown instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4011: WORKDIR should use absolute paths
export const DV4011: Rule = {
  id: 'DV4011', severity: 'warning',
  description: 'WORKDIR should use an absolute path.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'WORKDIR') continue;
        let dir = inst.arguments.trim();
        // Strip surrounding quotes (single or double)
        if ((dir.startsWith('"') && dir.endsWith('"')) || (dir.startsWith("'") && dir.endsWith("'"))) {
          dir = dir.slice(1, -1);
        }
        // Allow variable references like $HOME or ${APP_DIR}
        if (dir.startsWith('$') || dir.startsWith('/')) continue;
        violations.push({ rule: 'DV4011', severity: 'warning', message: `WORKDIR "${dir}" is a relative path. Use an absolute path for predictable behavior.`, line: inst.line });
      }
    }
    return violations;
  },
};

// DV4012: Multiple consecutive COPY instructions that could be combined
export const DV4012: Rule = {
  id: 'DV4012', severity: 'style',
  description: 'Multiple consecutive COPY instructions with same --from could be combined.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      let prevCopy: { from?: string; line: number } | null = null;
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          const curFrom = c.from || '';
          if (prevCopy && prevCopy.from === curFrom) {
            violations.push({ rule: 'DV4012', severity: 'style', message: 'Multiple consecutive COPY instructions with same source could potentially be combined.', line: inst.line });
          }
          prevCopy = { from: curFrom, line: inst.line };
        } else {
          prevCopy = null;
        }
      }
    }
    return violations;
  },
};
