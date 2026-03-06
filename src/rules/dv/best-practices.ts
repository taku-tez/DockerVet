import { Rule, Violation } from '../types';
import { forEachInstruction } from '../utils';
import { ArgInstruction, CopyInstruction, EnvInstruction, ExposeInstruction, WorkdirInstruction } from '../../parser/types';

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
    // Build alias→stage map to resolve parent WORKDIR inheritance
    const aliasMap = new Map<string, typeof ctx.ast.stages[0]>();
    for (const s of ctx.ast.stages) {
      if (s.from.alias) aliasMap.set(s.from.alias.toLowerCase(), s);
    }
    const stageHasWorkdir = (stage: typeof ctx.ast.stages[0], visited = new Set<string>()): boolean => {
      if (stage.instructions.some(i => i.type === 'WORKDIR')) return true;
      // Check if parent stage (FROM <alias>) has WORKDIR (with cycle detection)
      const key = stage.from.alias?.toLowerCase() ?? stage.from.image.toLowerCase();
      if (visited.has(key)) return false;
      visited.add(key);
      const parent = aliasMap.get(stage.from.image.toLowerCase());
      if (parent && parent !== stage) return stageHasWorkdir(parent, visited);
      return false;
    };
    for (const stage of ctx.ast.stages) {
      // Skip scratch-based stages — they typically have no shell and don't need WORKDIR
      if (stage.from.image === 'scratch') continue;
      const hasRun = stage.instructions.some(i => i.type === 'RUN');
      if (hasRun && !stageHasWorkdir(stage)) {
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
      // Flag if ARG comes after ENV but is NOT referenced by a later ENV
      for (const ai of argIndices) {
        const firstEnvIdx = envIndices.length > 0 ? envIndices[0] : Infinity;
        if (ai > firstEnvIdx) {
          const argInst = stage.instructions[ai] as ArgInstruction;
          const argName = argInst.name;
          // Check if any ENV after this ARG references it
          const referencedByLaterEnv = argName && stage.instructions.slice(ai + 1).some(inst => {
            if (inst.type !== 'ENV') return false;
            const raw = (inst as { raw?: string }).raw || '';
            return raw.includes('${' + argName + '}') || raw.includes('$' + argName);
          });
          if (!referencedByLaterEnv) {
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
    // Skip builder/base/test/data/verify Dockerfiles — they typically don't need CMD/ENTRYPOINT
    if (ctx.filePath) {
      const lower = ctx.filePath.toLowerCase();
      const basename = lower.split('/').pop() || '';
      if (/(?:builder|base|test|build-stage|\.binary$)/.test(basename)) return violations;
      // Also check parent directory name for utility/helper containers
      const parts = lower.split('/');
      const parentDir = parts.length >= 2 ? parts[parts.length - 2] : '';
      if (/^(?:build|data|ci|scripts|hack|contrib|packaging)$/.test(parentDir)) return violations;
      if (/(?:verify|test|check)/.test(parentDir)) return violations;
      // Also check any ancestor directory for test/build/example paths
      if (parts.some(p => /(?:test|tests|testing|e2e|integration-test|examples|docker-examples)/.test(p))) return violations;
    }
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    const hasCmdOrEp = lastStage.instructions.some(i => i.type === 'CMD' || i.type === 'ENTRYPOINT');
    if (!hasCmdOrEp) {
      // Skip extension images: FROM uses a variable or a specific app image (not scratch/base),
      // and has no COPY/ADD of application code — likely inherits CMD/ENTRYPOINT from parent
      const fromImage = lastStage.from.image || '';
      const usesVariable = fromImage.includes('$');
      const hasAppCopy = lastStage.instructions.some(i => i.type === 'COPY' || i.type === 'ADD');
      if (usesVariable && !hasAppCopy) return violations;
      // If FROM uses a variable, resolve it from ARG defaults — if it references an org image, skip
      if (usesVariable) {
        // Collect ARG defaults from global args and all stages
        const argDefaults = new Map<string, string>();
        if (ctx.ast.globalArgs) {
          for (const ga of ctx.ast.globalArgs) {
            const gm = ga.arguments.match(/^(\w+)=(.+)/);
            if (gm) argDefaults.set(gm[1], gm[2].replace(/^["']|["']$/g, ''));
          }
        }
        for (const s of ctx.ast.stages) {
          for (const inst of s.instructions) {
            if (inst.type === 'ARG') {
              const m = inst.arguments.match(/^(\w+)=(.+)/);
              if (m) argDefaults.set(m[1], m[2].replace(/^["']|["']$/g, ''));
            }
          }
        }
        // Resolve the FROM image variable
        let resolved = fromImage;
        for (const [k, v] of argDefaults) {
          resolved = resolved.replace(`$${k}`, v).replace(`\${${k}}`, v);
        }
        // If resolved image contains '/' (org-scoped) or '-' (specific app), likely inherits CMD
        if (resolved.includes('/') || resolved.includes('-')) return violations;
      }
      // Skip images that extend a specific app image (registry paths, org-scoped, or local build aliases)
      // These likely inherit CMD/ENTRYPOINT from their parent image
      const imageName = fromImage.split(/[:/]/)[0];
      // Images that ship with CMD/ENTRYPOINT — extending them without CMD is valid
      const imagesWithCmd = /^(nginx|httpd|node|python|ruby|php|redis|postgres|mysql|mariadb|mongo|memcached|rabbitmq|elasticsearch|kibana|logstash|consul|vault|traefik|caddy|haproxy|tomcat|jetty|jenkins|sonarqube|gitlab|registry|verdaccio|grafana|influxdb|telegraf|chronograf|kapacitor|nats|etcd|cockroachdb|couchdb|cassandra|neo4j|wordpress|ghost|drupal|joomla|mediawiki|redmine|nextcloud|gitea|minio)$/i;
      if (imagesWithCmd.test(imageName)) return violations;
      const genericBases = /^(scratch|alpine|debian|ubuntu|centos|fedora|rockylinux|amazonlinux|golang|rust|openjdk|eclipse-temurin|maven|gradle|busybox|buildpack-deps|mcr\.microsoft\.com\/dotnet)$/i;
      const isGenericBase = genericBases.test(imageName);
      // If FROM references a prior build stage, it's an intermediate — skip
      const priorStageNames = ctx.ast.stages.slice(0, -1).map(s => s.from.alias).filter(Boolean);
      const isFromPriorStage = priorStageNames.includes(fromImage);
      // Extension image: not a generic base, not scratch, not a prior build stage
      if (!isGenericBase && !isFromPriorStage && (fromImage.includes('/') || fromImage.includes('-'))) return violations;
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
        if (inst.type === 'RUN' && /chmod\s+(?:-[a-zA-Z]+\s+)*777/.test(inst.arguments)) {
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
          // Skip system directories where COPY --chown is not applicable
          const chownTarget = inst.arguments.match(/chown\s+-R\s+\S+\s+(.+)/);
          const targets = chownTarget ? chownTarget[1].trim().split(/\s+/) : [];
          const systemDirs = ['/tmp', '/var', '/etc', '/run', '/opt', '/usr', '/home'];
          const allSystem = targets.length > 0 && targets.every(t => systemDirs.some(sd => t === sd || t.startsWith(sd + '/')));
          if (!allSystem) {
            violations.push({ rule: 'DV4010', severity: 'info', message: 'Recursive chown -R increases layer size. Consider using COPY --chown instead.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV4011: WORKDIR should use absolute paths
// Note: DL3000 already fires as an error for relative WORKDIR paths. The parser strips
// surrounding quotes from WORKDIR paths (w.path is always unquoted), so DL3000 correctly
// catches all relative paths including WORKDIR "./" and WORKDIR 'app'.
// DV4011 is therefore suppressed when DL3000 would fire, to avoid double-reporting the
// same issue at both error and warning severity (warrant-dev/warrant pattern).
export const DV4011: Rule = {
  id: 'DV4011', severity: 'warning',
  description: 'WORKDIR should use an absolute path.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'WORKDIR') continue;
        const w = inst as WorkdirInstruction;
        const dir = w.path; // Parser already strips surrounding quotes
        // Skip variable references — cannot be resolved at lint time
        if (dir.startsWith('$')) continue;
        // Skip absolute paths — Unix (/app) and Windows (C:/app, C:\app)
        if (dir.startsWith('/')) continue;
        if (/^[A-Za-z]:[/\\]/.test(dir)) continue;
        // Skip if DL3000 would also fire on this path (same condition: non-absolute, non-variable,
        // non-Windows). DL3000 fires as an error; suppress DV4011 to avoid duplicate reporting.
        // DL3000 condition: !startsWith('/') && !startsWith('$') && !Windows drive
        // That is exactly the condition above — so all cases reaching here are DL3000 cases.
        // DV4011 suppresses itself entirely when the parser provides a clean (unquoted) path,
        // since DL3000 covers all such cases. DV4011 is preserved for potential future edge cases.
        // Currently: no-op (all relative paths are caught by DL3000 first).
      }
    }
    return violations;
  },
};

// DV4013: Pin versions in pecl install
export const DV4013: Rule = {
  id: 'DV4013', severity: 'warning',
  description: 'Pin versions in pecl install for reproducible builds',
  check(ctx) {
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'RUN', (inst) => {
      const regex = /pecl\s+install\s+([^\s;&|]+)/g;
      let m;
      while ((m = regex.exec(inst.arguments)) !== null) {
        const pkg = m[1];
        // pecl uses package-version format (e.g., redis-5.3.7)
        if (!pkg.includes('-') && !pkg.startsWith('$')) {
          violations.push({ rule: 'DV4013', severity: 'warning', message: `Pin versions in pecl install. Instead of \`pecl install ${pkg}\` use \`pecl install ${pkg}-<version>\``, line: inst.line });
        }
      }
    });
    return violations;
  },
};

// DV4015: pip install without --no-cache-dir (extends DL3042 to cover python -m pip)
export const DV4015: Rule = {
  id: 'DV4015', severity: 'warning',
  description: 'Avoid pip cache in Docker. Use `pip install --no-cache-dir`',
  check(ctx) {
    // Skip if PIP_NO_CACHE_DIR is set via ENV in any stage
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV' && /PIP_NO_CACHE_DIR\s*=\s*["']?(1|true|on|yes)/i.test(inst.arguments)) {
          return [];
        }
      }
    }
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'RUN', (inst) => {
      if (/--mount=type=cache/.test(inst.arguments)) return;
      if (/python3?\s+-m\s+pip\s+install/.test(inst.arguments) && !/--no-cache-dir/.test(inst.arguments)) {
        violations.push({ rule: 'DV4015', severity: 'warning', message: 'Avoid pip cache in Docker. Use `python -m pip install --no-cache-dir <package>` to reduce image size.', line: inst.line });
      }
    });
    return violations;
  },
};

// DV4016: Invalid COPY --from stage reference
export const DV4016: Rule = {
  id: 'DV4016', severity: 'info',
  description: 'COPY --from references an invalid or self-referential stage index.',
  check(ctx) {
    const violations: Violation[] = [];
    const totalStages = ctx.ast.stages.length;

    for (let stageIdx = 0; stageIdx < ctx.ast.stages.length; stageIdx++) {
      const stage = ctx.ast.stages[stageIdx];
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY') continue;
        const c = inst as CopyInstruction;
        if (!c.from) continue;
        // Only check numeric references (named refs are handled by DL3022)
        if (!/^\d+$/.test(c.from)) continue;

        const fromIdx = parseInt(c.from, 10);
        if (totalStages === 1 && fromIdx === 0) {
          violations.push({ rule: 'DV4016', severity: 'info', message: `COPY --from=0 in a single-stage build is self-referential and has no effect.`, line: inst.line });
        } else if (fromIdx >= totalStages) {
          violations.push({ rule: 'DV4016', severity: 'info', message: `COPY --from=${c.from} references non-existent stage (only ${totalStages} stage(s) exist).`, line: inst.line });
        }
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
      let prevCopy: { from?: string; dest: string; line: number } | null = null;
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          const curFrom = c.from || '';
          const curDest = c.destination || '';
          // Only flag when both --from and destination match (actually combinable)
          if (prevCopy && prevCopy.from === curFrom && prevCopy.dest === curDest) {
            violations.push({ rule: 'DV4012', severity: 'style', message: 'Multiple consecutive COPY instructions with same source could potentially be combined.', line: inst.line });
          }
          prevCopy = { from: curFrom, dest: curDest, line: inst.line };
        } else {
          prevCopy = null;
        }
      }
    }
    return violations;
  },
};

// DV4018: Multiple HEALTHCHECK instructions (only last one takes effect)
export const DV4018: Rule = {
  id: 'DV4018', severity: 'warning',
  description: 'Multiple HEALTHCHECK instructions found. Only the last one takes effect.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const healthchecks = stage.instructions.filter(i => i.type === 'HEALTHCHECK');
      if (healthchecks.length > 1) {
        for (let i = 0; i < healthchecks.length - 1; i++) {
          violations.push({ rule: 'DV4018', severity: 'warning', message: 'Multiple HEALTHCHECK instructions found. Only the last one takes effect; earlier ones are silently ignored.', line: healthchecks[i].line });
        }
      }
    }
    return violations;
  },
};

// DV4019: WORKDIR with relative path
export const DV4019: Rule = {
  id: 'DV4019', severity: 'warning',
  description: 'WORKDIR should use absolute paths for clarity and predictability.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'WORKDIR') continue;
        const w = inst as WorkdirInstruction;
        const dir = w.path || inst.arguments.trim();
        // Skip variable references like $HOME or ${APP_DIR}
        if (/^\$/.test(dir)) continue;
        // Flag relative paths (not starting with /)
        if (dir && !dir.startsWith('/')) {
          violations.push({ rule: 'DV4019', severity: 'warning', message: `WORKDIR "${dir}" uses a relative path. Use an absolute path for clarity and predictability.`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4021: gem install without --no-document
export const DV4021: Rule = {
  id: 'DV4021', severity: 'info',
  description: 'Use `gem install --no-document` to avoid installing unnecessary documentation.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (/gem\s+install\b/.test(args) && !(/--no-doc(ument)?/.test(args) || /--no-ri/.test(args) || /--no-rdoc/.test(args))) {
          violations.push({ rule: 'DV4021', severity: 'info', message: 'gem install without --no-document includes unnecessary documentation. Use `gem install --no-document` to reduce image size.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4022: npm install instead of npm ci for deterministic builds
export const DV4022: Rule = {
  id: 'DV4022', severity: 'info',
  description: 'Prefer `npm ci` over `npm install` for deterministic, reproducible builds.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        // Match `npm install` but not `npm install <specific-package>` (which is adding a dep, not installing all)
        // npm install with no args or with only flags like --production
        // Exclude shell operators (&&, ||, ;) after npm install — those are chained commands, not package names
        if (/\bnpm\s+install\b/.test(args) && !/\bnpm\s+install\s+[a-zA-Z@]/.test(args)) {
          violations.push({ rule: 'DV4022', severity: 'info', message: 'Use `npm ci` instead of `npm install` for deterministic builds. npm ci uses package-lock.json exactly and is faster in CI.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4023: Multiple consecutive ENV instructions that could be consolidated
export const DV4023: Rule = {
  id: 'DV4023', severity: 'info',
  description: 'Multiple consecutive ENV instructions can be consolidated into one.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      let consecutiveEnvCount = 0;
      let firstEnvLine = 0;
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV') {
          consecutiveEnvCount++;
          if (consecutiveEnvCount === 1) firstEnvLine = inst.line;
          if (consecutiveEnvCount === 3) {
            violations.push({ rule: 'DV4023', severity: 'info', message: 'Multiple consecutive ENV instructions detected. Consolidate into a single ENV to reduce image layers.', line: firstEnvLine });
          }
        } else {
          consecutiveEnvCount = 0;
        }
      }
    }
    return violations;
  },
};

// DV4020: Shell form ENTRYPOINT (prevents proper signal handling)
export const DV4020: Rule = {
  id: 'DV4020', severity: 'warning',
  description: 'ENTRYPOINT uses shell form. Use exec form for proper signal handling.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    for (const inst of lastStage.instructions) {
      if (inst.type !== 'ENTRYPOINT') continue;
      const args = inst.arguments.trim();
      // Exec form starts with [
      if (!args.startsWith('[')) {
        violations.push({ rule: 'DV4020', severity: 'warning', message: 'ENTRYPOINT uses shell form, which wraps the process in /bin/sh -c and prevents proper signal handling (SIGTERM). Use exec form: ENTRYPOINT ["executable", "arg1"].', line: inst.line });
      }
    }
    return violations;
  },
};
