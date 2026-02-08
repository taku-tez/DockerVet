import { Rule, Violation } from '../types';
import { EnvInstruction, ArgInstruction, CopyInstruction, UserInstruction } from '../../parser/types';

const SECRET_PATTERNS = /(password|passwd|secret|api_key|apikey|api_secret|access_key|access_token|auth_token|token|private_key|credentials?)/i;
// Docker secrets convention: ENV vars ending in _FILE point to file paths, not actual secrets
const FILE_PATH_SUFFIX = /_FILE$/i;

// DV1001: Hardcoded secrets in ENV/ARG
export const DV1001: Rule = {
  id: 'DV1001', severity: 'error',
  description: 'Secrets should not be hardcoded in ENV or ARG instructions',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV') {
          const e = inst as EnvInstruction;
          for (const pair of e.pairs) {
            if (SECRET_PATTERNS.test(pair.key) && !FILE_PATH_SUFFIX.test(pair.key) && pair.value && pair.value !== '' && !pair.value.startsWith('$')) {
              violations.push({ rule: 'DV1001', severity: 'error', message: `Possible secret hardcoded in ENV: "${pair.key}". Use build secrets or runtime environment variables instead.`, line: inst.line });
            }
          }
        }
        if (inst.type === 'ARG') {
          const a = inst as ArgInstruction;
          if (SECRET_PATTERNS.test(a.name) && !FILE_PATH_SUFFIX.test(a.name) && a.defaultValue && a.defaultValue !== '' && !a.defaultValue.startsWith('$')) {
            violations.push({ rule: 'DV1001', severity: 'error', message: `Possible secret hardcoded in ARG: "${a.name}". Use --build-arg at build time without default values.`, line: inst.line });
          }
        }
      }
    }
    // Check global args too
    for (const arg of ctx.ast.globalArgs) {
      if (SECRET_PATTERNS.test(arg.name) && !FILE_PATH_SUFFIX.test(arg.name) && arg.defaultValue && arg.defaultValue !== '' && !arg.defaultValue.startsWith('$')) {
        violations.push({ rule: 'DV1001', severity: 'error', message: `Possible secret hardcoded in ARG: "${arg.name}". Use --build-arg at build time without default values.`, line: arg.line });
      }
    }
    return violations;
  },
};

// DV1002: Privileged operations
export const DV1002: Rule = {
  id: 'DV1002', severity: 'warning',
  description: 'Avoid privileged operations in Dockerfile',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN') {
          if (/--privileged/.test(inst.arguments)) {
            violations.push({ rule: 'DV1002', severity: 'warning', message: 'Avoid --privileged flag in RUN instructions', line: inst.line });
          }
          if (/--cap-add/.test(inst.arguments)) {
            violations.push({ rule: 'DV1002', severity: 'warning', message: 'Avoid --cap-add flag. Follow principle of least privilege.', line: inst.line });
          }
          if (/--security-opt\s+(apparmor|seccomp)=unconfined/.test(inst.arguments)) {
            violations.push({ rule: 'DV1002', severity: 'warning', message: 'Avoid disabling security profiles (apparmor/seccomp)', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV1003: Unsafe curl pipe
export const DV1003: Rule = {
  id: 'DV1003', severity: 'error',
  description: 'Avoid piping curl/wget output to shell',
  check(ctx) {
    const violations: Violation[] = [];
    const unsafePipe = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|ksh|dash|source\s)/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && unsafePipe.test(inst.arguments)) {
          violations.push({ rule: 'DV1003', severity: 'error', message: 'Avoid piping curl/wget output directly to a shell. Download first, verify, then execute.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV1004: Multi-stage build not used for large base images
export const DV1004: Rule = {
  id: 'DV1004', severity: 'info',
  description: 'Consider using multi-stage builds to reduce image size',
  check(ctx) {
    if (ctx.ast.stages.length > 1) return [];
    const violations: Violation[] = [];
    const stage = ctx.ast.stages[0];
    if (!stage) return violations;
    const hasCompiler = stage.instructions.some(i =>
      i.type === 'RUN' && /(gcc|g\+\+|make|cargo|go\s+build|javac|mvn|gradle|dotnet\s+build|npm\s+run\s+build)/.test(i.arguments)
    );
    if (hasCompiler) {
      violations.push({ rule: 'DV1004', severity: 'info', message: 'Consider using multi-stage builds to reduce final image size. Build tools detected but only one stage is used.', line: stage.from.line });
    }
    return violations;
  },
};

// DV1005: .dockerignore recommended
export const DV1005: Rule = {
  id: 'DV1005', severity: 'info',
  description: 'Consider using a .dockerignore file',
  check(ctx) {
    // This is a meta-rule; we always suggest it if COPY . is used
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          if (c.sources.includes('.') || c.sources.includes('./')) {
            violations.push({ rule: 'DV1005', severity: 'info', message: 'When using COPY with broad sources, ensure a .dockerignore file exists to exclude unnecessary files.', line: inst.line });
            return violations;
          }
        }
      }
    }
    return violations;
  },
};

// DV1006: No non-root user set
export const DV1006: Rule = {
  id: 'DV1006', severity: 'warning',
  description: 'No USER instruction found. Container will run as root.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    const hasUser = lastStage.instructions.some(i => i.type === 'USER');
    if (!hasUser) {
      // Skip if base image is known to run as non-root (e.g., distroless nonroot variants, chainguard static)
      let fromImage = lastStage.from.image.toLowerCase();
      let fromTag = (lastStage.from.tag || '').toLowerCase();
      // Resolve stage alias to original base image
      if (!fromImage.includes('/') && !fromImage.includes('.')) {
        const aliasStage = ctx.ast.stages.find(s => s.from.alias?.toLowerCase() === fromImage);
        if (aliasStage) {
          fromImage = aliasStage.from.image.toLowerCase();
          fromTag = (aliasStage.from.tag || '').toLowerCase();
        }
      }
      const isNonRootBase =
        /nonroot/.test(fromTag) ||
        /nonroot/.test(fromImage) ||
        (/distroless/.test(fromImage) && /nonroot/.test(fromTag)) ||
        /cgr\.dev\/chainguard\/static/.test(fromImage);
      if (!isNonRootBase) {
        violations.push({ rule: 'DV1006', severity: 'warning', message: 'No USER instruction found. Container will run as root by default.', line: lastStage.from.line });
      }
    }
    return violations;
  },
};

// DV1007: Package manager cache not cleaned
export const DV1007: Rule = {
  id: 'DV1007', severity: 'warning',
  description: 'Package manager cache not cleaned in same RUN instruction',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const a = inst.arguments;
        // apt-get
        if (/apt-get\s+install/.test(a) && !/rm\s+(-rf?\s+)?\/var\/lib\/apt\/lists/.test(a)) {
          violations.push({ rule: 'DV1007', severity: 'warning', message: 'apt-get cache not cleaned. Add `rm -rf /var/lib/apt/lists/*` in the same RUN instruction.', line: inst.line });
        }
        // yum
        if (/yum\s+install/.test(a) && !/yum\s+clean\s+all/.test(a)) {
          violations.push({ rule: 'DV1007', severity: 'warning', message: 'yum cache not cleaned. Add `yum clean all` in the same RUN instruction.', line: inst.line });
        }
        // dnf
        if (/dnf\s+install/.test(a) && !/dnf\s+clean\s+all/.test(a)) {
          violations.push({ rule: 'DV1007', severity: 'warning', message: 'dnf cache not cleaned. Add `dnf clean all` in the same RUN instruction.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV1008: COPY . . (too broad)
export const DV1008: Rule = {
  id: 'DV1008', severity: 'warning',
  description: 'COPY . . copies the entire build context. Consider copying only needed files.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'COPY') {
          const c = inst as CopyInstruction;
          if (c.sources.length === 1 && (c.sources[0] === '.' || c.sources[0] === './') && !c.from) {
            violations.push({ rule: 'DV1008', severity: 'warning', message: 'COPY . copies the entire build context. Consider copying only needed files for better cache utilization.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV1009: Unpinned base image digest
export const DV1009: Rule = {
  id: 'DV1009', severity: 'info',
  description: 'Consider pinning base image with digest for reproducible builds',
  check(ctx) {
    const violations: Violation[] = [];
    // Collect stage aliases to skip (can't pin stage references with digests)
    const stageAliases = new Set<string>();
    for (const stage of ctx.ast.stages) {
      if (stage.from.alias) stageAliases.add(stage.from.alias.toLowerCase());
    }
    for (const stage of ctx.ast.stages) {
      const f = stage.from;
      if (f.image === 'scratch') continue;
      if (f.digest) continue;
      // Skip stage aliases (e.g., FROM builder, FROM docs-base)
      if (stageAliases.has(f.image.toLowerCase())) continue;
      // Skip ARG variable references (e.g., ${GOLANG_IMAGE}, $BASE_IMAGE)
      if (/\$\{?[A-Za-z_]/.test(f.image)) continue;
      violations.push({ rule: 'DV1009', severity: 'info', message: `Consider pinning "${f.image}" with a digest (e.g., image@sha256:...) for reproducible builds.`, line: f.line });
    }
    return violations;
  },
};
