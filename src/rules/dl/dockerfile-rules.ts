import { Rule, Violation } from '../types';
import {
  FromInstruction, CopyInstruction, ExposeInstruction, HealthcheckInstruction,
  EnvInstruction, LabelInstruction, WorkdirInstruction,
} from '../../parser/types';

// DL3010: Use ADD for extracting archives
export const DL3010: Rule = {
  id: 'DL3010', severity: 'info',
  description: 'Use ADD for extracting archives into an image',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          if (c.sources.some(s => /\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$/i.test(s))) {
            violations.push({ rule: 'DL3010', severity: 'info', message: 'Use ADD for extracting archives into an image', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3011: Valid UNIX ports
export const DL3011: Rule = {
  id: 'DL3011', severity: 'error',
  description: 'Valid UNIX ports range from 0 to 65535',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'EXPOSE') {
          const e = inst as ExposeInstruction;
          for (const p of e.ports) {
            if (p.port < 0 || p.port > 65535) {
              violations.push({ rule: 'DL3011', severity: 'error', message: `Valid UNIX ports range from 0 to 65535. Port ${p.port} is invalid.`, line: inst.line });
            }
          }
        }
      }
    }
    return violations;
  },
};

// DL3012: Multiple HEALTHCHECK
export const DL3012: Rule = {
  id: 'DL3012', severity: 'error',
  description: 'Provide only one HEALTHCHECK instruction per stage',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const hcs = stage.instructions.filter(i => i.type === 'HEALTHCHECK');
      if (hcs.length > 1) {
        for (const hc of hcs.slice(1)) {
          violations.push({ rule: 'DL3012', severity: 'error', message: 'Provide only one HEALTHCHECK instruction per stage', line: hc.line });
        }
      }
    }
    return violations;
  },
};

// DL3020: Use COPY instead of ADD for files/folders
export const DL3020: Rule = {
  id: 'DL3020', severity: 'error',
  description: 'Use COPY instead of ADD for files and folders',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ADD') {
          const a = inst as CopyInstruction;
          const hasUrl = a.sources.some(s => s.startsWith('http://') || s.startsWith('https://'));
          const hasArchive = a.sources.some(s => /\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$/i.test(s));
          if (!hasUrl && !hasArchive) {
            violations.push({ rule: 'DL3020', severity: 'error', message: 'Use COPY instead of ADD for files and folders', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3021: COPY with more than 2 arguments requires destination ending with /
export const DL3021: Rule = {
  id: 'DL3021', severity: 'error',
  description: 'COPY with more than 2 arguments requires the last argument to end with /',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY' || inst.type === 'ADD') {
          const c = inst as CopyInstruction;
          if (c.sources.length > 1 && !c.destination.endsWith('/')) {
            violations.push({ rule: 'DL3021', severity: 'error', message: 'COPY with more than 2 arguments requires the last argument to end with /', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3022: COPY --from should reference a previously defined FROM alias
export const DL3022: Rule = {
  id: 'DL3022', severity: 'warning',
  description: 'COPY --from should reference a previously defined FROM alias',
  check(ctx) {
    const violations: Violation[] = [];
    const aliases = new Set<string>();
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          if (c.from && !/^\d+$/.test(c.from) && !aliases.has(c.from)) {
            violations.push({ rule: 'DL3022', severity: 'warning', message: `COPY --from=${c.from} references an undefined FROM alias`, line: inst.line });
          }
        }
      }
      if (stage.from.alias) aliases.add(stage.from.alias);
    }
    return violations;
  },
};

// DL3023: COPY --from cannot reference its own FROM alias
export const DL3023: Rule = {
  id: 'DL3023', severity: 'error',
  description: 'COPY --from should not reference its own FROM alias',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          if (c.from && stage.from.alias && c.from === stage.from.alias) {
            violations.push({ rule: 'DL3023', severity: 'error', message: `COPY --from=${c.from} references its own FROM alias`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3024: FROM aliases must be unique
export const DL3024: Rule = {
  id: 'DL3024', severity: 'error',
  description: 'FROM aliases (stage names) must be unique',
  check(ctx) {
    const violations: Violation[] = [];
    const seen = new Map<string, number>();
    for (const stage of ctx.ast.stages) {
      if (stage.from.alias) {
        const lower = stage.from.alias.toLowerCase();
        if (seen.has(lower)) {
          violations.push({ rule: 'DL3024', severity: 'error', message: `FROM alias "${stage.from.alias}" is not unique`, line: stage.from.line });
        }
        seen.set(lower, stage.from.line);
      }
    }
    return violations;
  },
};

// DL3025: Use JSON notation for CMD and ENTRYPOINT
export const DL3025: Rule = {
  id: 'DL3025', severity: 'warning',
  description: 'Use arguments JSON notation for CMD and ENTRYPOINT arguments',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if ((inst.type === 'CMD' || inst.type === 'ENTRYPOINT') && !inst.arguments.trim().startsWith('[')) {
          violations.push({ rule: 'DL3025', severity: 'warning', message: `Use arguments JSON notation for ${inst.type} arguments`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DL3026: Use only allowed registries
export const DL3026: Rule = {
  id: 'DL3026', severity: 'error',
  description: 'Use only an allowed registry in the FROM image',
  check(ctx) {
    if (ctx.trustedRegistries.length === 0) return [];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const img = stage.from.image;
      if (img === 'scratch') continue;
      const hasRegistry = img.includes('/') && (img.includes('.') || img.includes(':'));
      const registry = hasRegistry ? img.split('/')[0] : 'docker.io';
      if (!ctx.trustedRegistries.some(r => registry === r || registry.endsWith('.' + r))) {
        violations.push({ rule: 'DL3026', severity: 'error', message: `Use only an allowed registry in the FROM image. Registry "${registry}" is not allowed.`, line: stage.from.line });
      }
    }
    return violations;
  },
};

// DL3029: Do not use --platform flag with FROM
export const DL3029: Rule = {
  id: 'DL3029', severity: 'warning',
  description: 'Do not use --platform flag with FROM',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      if (stage.from.platform) {
        violations.push({ rule: 'DL3029', severity: 'warning', message: 'Do not use --platform flag with FROM', line: stage.from.line });
      }
    }
    return violations;
  },
};

// DL3043: ONBUILD cannot contain FROM or MAINTAINER
export const DL3043: Rule = {
  id: 'DL3043', severity: 'error',
  description: 'ONBUILD should not contain FROM or MAINTAINER',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ONBUILD' && inst.innerInstruction) {
          const inner = inst.innerInstruction.type;
          if (inner === 'FROM' || inner === 'MAINTAINER') {
            violations.push({ rule: 'DL3043', severity: 'error', message: `ONBUILD should not contain ${inner}`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3044: Do not refer to environment variable within same ENV statement
export const DL3044: Rule = {
  id: 'DL3044', severity: 'error',
  description: 'Do not refer to an environment variable within the same ENV statement where it is defined',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV') {
          const env = inst as EnvInstruction;
          if (env.pairs.length > 1) {
            const definedKeys = new Set<string>();
            for (const pair of env.pairs) {
              // Check if value references a key defined in this same statement
              for (const k of definedKeys) {
                if (pair.value.includes(`$${k}`) || pair.value.includes(`\${${k}}`)) {
                  violations.push({ rule: 'DL3044', severity: 'error', message: `Do not refer to an environment variable within the same ENV statement where it is defined (${k})`, line: inst.line });
                }
              }
              definedKeys.add(pair.key);
            }
          }
        }
      }
    }
    return violations;
  },
};

// DL3045: COPY to relative destination without WORKDIR set
export const DL3045: Rule = {
  id: 'DL3045', severity: 'warning',
  description: 'COPY to a relative destination without WORKDIR set',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      let hasWorkdir = false;
      for (const inst of stage.instructions) {
        if (inst.type === 'WORKDIR') hasWorkdir = true;
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          if (!hasWorkdir && c.destination && !c.destination.startsWith('/') && !c.destination.startsWith('$')) {
            violations.push({ rule: 'DL3045', severity: 'warning', message: 'COPY to a relative destination without WORKDIR set. Use absolute paths or set WORKDIR.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3046: useradd without -l flag and high UID warning
export const DL3046: Rule = {
  id: 'DL3046', severity: 'warning',
  description: 'useradd without flag -l and target UID set to high value may cause performance issues',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /useradd\b/.test(inst.arguments)) {
          const hasL = /-l\b/.test(inst.arguments);
          const uidMatch = inst.arguments.match(/--uid\s+(\d+)|-u\s+(\d+)/);
          if (!hasL && uidMatch) {
            const uid = parseInt(uidMatch[1] ?? uidMatch[2], 10);
            if (uid > 65534) {
              violations.push({ rule: 'DL3046', severity: 'warning', message: 'useradd without flag -l and target UID set to high value causes performance issues with large lastlog files', line: inst.line });
            }
          }
        }
      }
    }
    return violations;
  },
};

// DL3047: wget without --progress
export const DL3047: Rule = {
  id: 'DL3047', severity: 'info',
  description: 'Avoid use of wget without progress bar. Use wget --progress=dot:giga <url>',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /\bwget\b/.test(inst.arguments) && !/--progress/.test(inst.arguments)) {
          violations.push({ rule: 'DL3047', severity: 'info', message: 'Avoid use of wget without progress bar. Use `wget --progress=dot:giga <url>`', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DL3048: Invalid label key
export const DL3048: Rule = {
  id: 'DL3048', severity: 'info',
  description: 'Invalid label key',
  check(ctx) {
    const violations: Violation[] = [];
    const validKeyRegex = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'LABEL') {
          const l = inst as LabelInstruction;
          for (const pair of l.pairs) {
            if (!validKeyRegex.test(pair.key)) {
              violations.push({ rule: 'DL3048', severity: 'info', message: `Invalid label key "${pair.key}"`, line: inst.line });
            }
          }
        }
      }
    }
    return violations;
  },
};

// DL3049: Label missing
export const DL3049: Rule = {
  id: 'DL3049', severity: 'info',
  description: 'Label is missing',
  check(ctx) {
    if (!ctx.requiredLabels || ctx.requiredLabels.length === 0) return [];
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    const existingLabels = new Set<string>();
    for (const inst of lastStage.instructions) {
      if (inst.type === 'LABEL') {
        const l = inst as LabelInstruction;
        for (const pair of l.pairs) existingLabels.add(pair.key);
      }
    }
    for (const req of ctx.requiredLabels) {
      if (!existingLabels.has(req)) {
        violations.push({ rule: 'DL3049', severity: 'info', message: `Label "${req}" is missing`, line: lastStage.from.line });
      }
    }
    return violations;
  },
};

// DL3050: Superfluous label present
export const DL3050: Rule = {
  id: 'DL3050', severity: 'info',
  description: 'Superfluous label present',
  check(ctx) {
    if (!ctx.allowedLabels || ctx.allowedLabels.length === 0) return [];
    const violations: Violation[] = [];
    const allowed = new Set(ctx.allowedLabels);
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'LABEL') {
          const l = inst as LabelInstruction;
          for (const pair of l.pairs) {
            if (!allowed.has(pair.key)) {
              violations.push({ rule: 'DL3050', severity: 'info', message: `Superfluous label "${pair.key}" present`, line: inst.line });
            }
          }
        }
      }
    }
    return violations;
  },
};

// DL3057: HEALTHCHECK instruction missing
export const DL3057: Rule = {
  id: 'DL3057', severity: 'info',
  description: 'HEALTHCHECK instruction missing',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    const hasHC = lastStage.instructions.some(i => i.type === 'HEALTHCHECK');
    if (!hasHC) {
      violations.push({ rule: 'DL3057', severity: 'info', message: 'HEALTHCHECK instruction missing', line: lastStage.from.line });
    }
    return violations;
  },
};
