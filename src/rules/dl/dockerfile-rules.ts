/**
 * General Dockerfile DL rules (DL3010-DL3057).
 *
 * Uses shared utilities from ../utils.ts for common iteration patterns.
 */
import { Rule, Violation } from '../types';
import { forEachInstruction, ARCHIVE_PATTERN, isUrl } from '../utils';
import {
  ArgInstruction, CopyInstruction, ExposeInstruction,
  EnvInstruction, LabelInstruction,
} from '../../parser/types';

// DL3010: Use ADD for extracting archives
export const DL3010: Rule = {
  id: 'DL3010', severity: 'info',
  description: 'Use ADD for extracting archives into an image',
  check(ctx) {
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'COPY', (inst) => {
      const c = inst as CopyInstruction;
      if (c.sources.some(s => ARCHIVE_PATTERN.test(s))) {
        violations.push({ rule: 'DL3010', severity: 'info', message: 'Use ADD for extracting archives into an image', line: inst.line });
      }
    });
    return violations;
  },
};

// DL3011: Valid UNIX ports
export const DL3011: Rule = {
  id: 'DL3011', severity: 'error',
  description: 'Valid UNIX ports range from 0 to 65535',
  check(ctx) {
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'EXPOSE', (inst) => {
      const e = inst as ExposeInstruction;
      for (const p of e.ports) {
        if (p.port < 0 || p.port > 65535) {
          violations.push({ rule: 'DL3011', severity: 'error', message: `Valid UNIX ports range from 0 to 65535. Port ${p.port} is invalid.`, line: inst.line });
        }
      }
    });
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
    // Build ARG default lookup for variable resolution
    const argDefaults = new Map<string, string>();
    for (const a of ctx.ast.globalArgs) argDefaults.set(a.name, a.defaultValue || '');
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ARG') {
          const ai = inst as import('../../parser/types').ArgInstruction;
          argDefaults.set(ai.name, ai.defaultValue || '');
        }
      }
    }
    const resolveVar = (s: string): string => {
      const m = s.match(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/);
      return m ? (argDefaults.get(m[1]) || s) : s;
    };
    forEachInstruction(ctx, 'ADD', (inst) => {
      const a = inst as CopyInstruction;
      const hasUrlSrc = a.sources.some(s => isUrl(s) || isUrl(resolveVar(s)));
      const hasArchive = a.sources.some(s => {
        const resolved = resolveVar(s);
        return ARCHIVE_PATTERN.test(s) || ARCHIVE_PATTERN.test(resolved);
      });
      if (!hasUrlSrc && !hasArchive) {
        violations.push({ rule: 'DL3020', severity: 'error', message: 'Use COPY instead of ADD for files and folders', line: inst.line });
      }
    });
    return violations;
  },
};

// DL3021: COPY with more than 2 arguments requires destination ending with /
export const DL3021: Rule = {
  id: 'DL3021', severity: 'error',
  description: 'COPY with more than 2 arguments requires the last argument to end with /',
  check(ctx) {
    const violations: Violation[] = [];
    for (const type of ['COPY', 'ADD'] as const) {
      forEachInstruction(ctx, type, (inst) => {
        const c = inst as CopyInstruction;
        // Skip check when destination contains a shell variable (e.g. $DEPLOYDIR, ${DIR},
        // or /path/${VAR}) — the variable's value cannot be determined at lint time, so we
        // cannot know if it will expand to a path ending with '/' or to an existing directory.
        const destIsVar = c.destination.includes('$');
        // Skip check when any argument contains a template variable ({{ .Var }} syntax) —
        // template files (Go, Jinja2, etc.) may have {{ .AppName }} in paths which the
        // parser splits on spaces, causing spurious multi-source counts (konveyor/move2kube pattern).
        const hasTemplateVar = c.sources.some(s => s.includes('{{')) || c.destination.includes('{{');
        if (c.sources.length > 1 && !destIsVar && !hasTemplateVar && !c.destination.endsWith('/') && c.destination !== '.' && c.destination !== './') {
          violations.push({ rule: 'DL3021', severity: 'error', message: 'COPY with more than 2 arguments requires the last argument to end with /', line: inst.line });
        }
      });
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
          if (c.from && !/^\d+$/.test(c.from) && !aliases.has(c.from) && !c.from.includes('/') && !c.from.includes('.') && !c.from.includes(':')) {
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
// Skip BuildKit automatic platform ARGs ($BUILDPLATFORM, $TARGETPLATFORM, etc.)
const BUILDKIT_PLATFORM_ARGS = /^\$\{?(BUILDPLATFORM|TARGETPLATFORM|BUILDOS|TARGETOS|BUILDARCH|TARGETARCH|BUILDVARIANT|TARGETVARIANT)\}?$/i;
export const DL3029: Rule = {
  id: 'DL3029', severity: 'warning',
  description: 'Do not use --platform flag with FROM',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      // Allow BuildKit automatic vars, pure variable refs ($VAR), and composite platform strings containing variables (linux/${ARCH})
      if (stage.from.platform && !BUILDKIT_PLATFORM_ARGS.test(stage.from.platform) && !/\$/.test(stage.from.platform)) {
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
    forEachInstruction(ctx, 'ONBUILD', (inst) => {
      if (inst.innerInstruction) {
        const inner = inst.innerInstruction.type;
        if (inner === 'FROM' || inner === 'MAINTAINER') {
          violations.push({ rule: 'DL3043', severity: 'error', message: `ONBUILD should not contain ${inner}`, line: inst.line });
        }
      }
    });
    return violations;
  },
};

// DL3044: Do not refer to environment variable within same ENV statement
export const DL3044: Rule = {
  id: 'DL3044', severity: 'error',
  description: 'Do not refer to an environment variable within the same ENV statement where it is defined',
  check(ctx) {
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'ENV', (inst) => {
      const env = inst as EnvInstruction;
      if (env.pairs.length > 1) {
        const definedKeys = new Set<string>();
        for (const pair of env.pairs) {
          for (const k of definedKeys) {
            if (pair.value.includes(`$${k}`) || pair.value.includes(`\${${k}}`)) {
              violations.push({ rule: 'DL3044', severity: 'error', message: `Do not refer to an environment variable within the same ENV statement where it is defined (${k})`, line: inst.line });
            }
          }
          definedKeys.add(pair.key);
        }
      }
    });
    return violations;
  },
};

// DL3045: COPY to relative destination without WORKDIR set
export const DL3045: Rule = {
  id: 'DL3045', severity: 'warning',
  description: 'COPY to a relative destination without WORKDIR set',
  check(ctx) {
    const violations: Violation[] = [];
    // Build map of stage alias -> whether it has WORKDIR (directly or inherited)
    const stageHasWorkdir = new Map<string, boolean>();
    const stageParent = new Map<string, string | undefined>();
    for (const stage of ctx.ast.stages) {
      const alias = stage.from.alias?.toLowerCase();
      const has = stage.instructions.some(i => i.type === 'WORKDIR');
      const parent = stage.from.image?.toLowerCase();
      if (alias) {
        stageParent.set(alias, parent);
        stageHasWorkdir.set(alias, has);
      }
    }
    // Resolve transitive WORKDIR inheritance (with cycle detection)
    const resolvedWorkdir = (alias: string | undefined, visited = new Set<string>()): boolean => {
      if (!alias) return false;
      if (stageHasWorkdir.get(alias)) return true;
      if (visited.has(alias)) return false;
      visited.add(alias);
      const parent = stageParent.get(alias);
      return parent ? resolvedWorkdir(parent, visited) : false;
    };
    for (const [alias] of stageHasWorkdir) {
      if (resolvedWorkdir(alias)) stageHasWorkdir.set(alias, true);
    }

    for (const stage of ctx.ast.stages) {
      // Check if this stage inherits WORKDIR from a parent stage
      const parentAlias = stage.from.image?.toLowerCase();
      let hasWorkdir = parentAlias ? (stageHasWorkdir.get(parentAlias) ?? false) : false;
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
    forEachInstruction(ctx, 'RUN', (inst) => {
      if (/useradd\b/.test(inst.arguments)) {
        const hasL = /-l\b/.test(inst.arguments);
        const uidMatch = inst.arguments.match(/--uid\s+(\d+)|-u\s+(\d+)/);
        if (!hasL && uidMatch) {
          const uid = parseInt(uidMatch[1] ?? uidMatch[2], 10);
          if (uid > 65534) {
            violations.push({ rule: 'DL3046', severity: 'warning', message: 'useradd without flag -l and target UID set to high value causes performance issues with large lastlog files', line: inst.line });
          }
        }
      }
    });
    return violations;
  },
};

// DL3047: wget without --progress
export const DL3047: Rule = {
  id: 'DL3047', severity: 'info',
  description: 'Avoid use of wget without progress bar. Use wget --progress=dot:giga <url>',
  check(ctx) {
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'RUN', (inst) => {
      if (/\bwget\b/.test(inst.arguments) && !/--progress/.test(inst.arguments) && !/\bwget\s+(-\w*q|-\w*\s+--quiet|--quiet)\b/.test(inst.arguments) && !/\bwget\b.*\s-q\b/.test(inst.arguments) && !/\bapt-get\b.*\binstall\b.*\bwget\b/.test(inst.arguments) && !/\bapk\b.*\badd\b.*\bwget\b/.test(inst.arguments)) {
        violations.push({ rule: 'DL3047', severity: 'info', message: 'Avoid use of wget without progress bar. Use `wget --progress=dot:giga <url>`', line: inst.line });
      }
    });
    return violations;
  },
};

// DL3048: Invalid label key
const VALID_LABEL_KEY = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

export const DL3048: Rule = {
  id: 'DL3048', severity: 'info',
  description: 'Invalid label key',
  check(ctx) {
    const violations: Violation[] = [];
    forEachInstruction(ctx, 'LABEL', (inst) => {
      const l = inst as LabelInstruction;
      for (const pair of l.pairs) {
        if (!VALID_LABEL_KEY.test(pair.key)) {
          violations.push({ rule: 'DL3048', severity: 'info', message: `Invalid label key "${pair.key}"`, line: inst.line });
        }
      }
    });
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
    forEachInstruction(ctx, 'LABEL', (inst) => {
      const l = inst as LabelInstruction;
      for (const pair of l.pairs) {
        if (!allowed.has(pair.key)) {
          violations.push({ rule: 'DL3050', severity: 'info', message: `Superfluous label "${pair.key}" present`, line: inst.line });
        }
      }
    });
    return violations;
  },
};

// DL3051: Empty LABEL value for required labels
export const DL3051: Rule = {
  id: 'DL3051', severity: 'warning',
  description: 'LABEL value should not be empty',
  check(ctx) {
    if (!ctx.requiredLabels || ctx.requiredLabels.length === 0) return [];
    const violations: Violation[] = [];
    const requiredSet = new Set(ctx.requiredLabels);
    forEachInstruction(ctx, 'LABEL', (inst) => {
      const l = inst as LabelInstruction;
      for (const pair of l.pairs) {
        if (requiredSet.has(pair.key) && pair.value.trim() === '') {
          violations.push({ rule: 'DL3051', severity: 'warning', message: `LABEL "${pair.key}" is present but empty. Provide a meaningful value.`, line: inst.line });
        }
      }
    });
    return violations;
  },
};

// DL3052: ARG declared but not referenced
// Well-known ARGs that are implicitly consumed by Docker BuildKit or system tools
// and don't need explicit $VAR references in the Dockerfile.
const IMPLICIT_ARGS = new Set([
  // BuildKit automatic platform ARGs (https://docs.docker.com/build/building/variables/#pre-defined-build-arguments)
  'TARGETOS', 'TARGETARCH', 'TARGETPLATFORM', 'TARGETVARIANT',
  'BUILDOS', 'BUILDARCH', 'BUILDPLATFORM', 'BUILDVARIANT',
  // BuildKit SBOM attestation ARGs (https://docs.docker.com/build/metadata/attestations/sbom/)
  'BUILDKIT_SBOM_SCAN_CONTEXT', 'BUILDKIT_SBOM_SCAN_STAGE',
  // Debian/Ubuntu dpkg/apt env vars consumed implicitly by package tools
  'DEBIAN_FRONTEND', 'DEBCONF_NOWARNINGS', 'DEBCONF_NONINTERACTIVE_SEEN',
  // pip/uv env vars — ARG declarations make these available as env vars during build,
  // pip and uv read them implicitly without explicit $VAR references
  'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_TRUSTED_HOST',
  'PIP_NO_CACHE_DIR', 'PIP_DISABLE_PIP_VERSION_CHECK', 'PIP_DEFAULT_TIMEOUT',
  'PIP_KEYRING_PROVIDER', 'PIP_CERT', 'PIP_CLIENT_CERT',
  'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL', 'UV_KEYRING_PROVIDER',
  'UV_CACHE_DIR', 'UV_NO_CACHE', 'UV_SYSTEM_PYTHON', 'UV_COMPILE_BYTECODE',
  // Network proxy env vars consumed implicitly by curl, wget, pip, apt, etc.
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
  'http_proxy', 'https_proxy', 'no_proxy', 'FTP_PROXY', 'ALL_PROXY',
  // Go env vars consumed implicitly by go build/install
  'GOFLAGS', 'GOPROXY', 'GONOSUMCHECK', 'GONOSUMDB', 'GOPRIVATE',
  // npm/yarn env vars
  'NPM_CONFIG_REGISTRY', 'NPM_TOKEN', 'YARN_CACHE_FOLDER',
  // Rust env vars consumed implicitly by cargo/rustc during RUN cargo build
  'CARGO_REGISTRIES_CRATES_IO_PROTOCOL', 'CARGO_NET_GIT_FETCH_WITH_CLI',
  'RUSTUP_HOME', 'CARGO_HOME',
  'CARGO_BUILD_INCREMENTAL', 'CARGO_BUILD_TARGET', 'CARGO_BUILD_JOBS',
  'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTDOCFLAGS',
  'CARGO_PROFILE_RELEASE_LTO', 'CARGO_PROFILE_RELEASE_STRIP',
  'CARGO_PROFILE_RELEASE_CODEGEN_UNITS', 'CARGO_PROFILE_RELEASE_OPT_LEVEL',
  'RUSTFLAGS', 'RUSTDOCFLAGS',
  // C/C++ compiler env vars consumed by cc/cmake/make during RUN
  'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'AR', 'RANLIB',
  'PKG_CONFIG_PATH', 'PKG_CONFIG_SYSROOT_DIR',
  // OpenSSL/static linking env vars consumed by Rust *-sys crates via pkg-config
  'OPENSSL_DIR', 'OPENSSL_LIB_DIR', 'OPENSSL_INCLUDE_DIR',
  'OPENSSL_STATIC', 'OPENSSL_NO_VENDOR',
  'PKG_CONFIG_ALL_STATIC', 'PKG_CONFIG_ALLOW_CROSS',
]);

// Additional implicit ARG patterns (prefix matches) — these are consumed as env vars
// by build tools without explicit $VAR reference in Dockerfile instructions.
const IMPLICIT_ARG_PREFIXES = [
  'CARGO_BUILD_',     // cargo build configuration
  'CARGO_PROFILE_',   // cargo profile overrides
  'CARGO_TARGET_',    // cargo target-specific config
  'CMAKE_',           // CMake configuration
  'OPENSSL_',         // OpenSSL build config
  'LIBGIT2_',         // libgit2 sys crate
  'LIBSSH2_',         // libssh2 sys crate
  'LIBZ_SYS_',        // libz-sys crate
  'ZSTD_SYS_',        // zstd-sys crate
];

export const DL3052: Rule = {
  id: 'DL3052', severity: 'style',
  description: 'ARG is declared but never referenced',
  check(ctx) {
    const violations: Violation[] = [];
    // Collect all text where variables can be referenced (including FROM directives)
    const allText: string[] = [];
    for (const stage of ctx.ast.stages) {
      allText.push(stage.from.raw || stage.from.arguments);
      for (const inst of stage.instructions) {
        allText.push(inst.raw || inst.arguments);
      }
    }
    const combined = allText.join('\n');

    // Check global args (before any FROM)
    for (const arg of ctx.ast.globalArgs) {
      const name = arg.name;
      if (!name) continue;
      if (IMPLICIT_ARGS.has(name)) continue;
      if (IMPLICIT_ARG_PREFIXES.some(p => name.startsWith(p))) continue;
      const re = new RegExp(`\\$\\{?${name}\\}?`);
      if (!re.test(combined)) {
        violations.push({ rule: 'DL3052', severity: 'style', message: `ARG ${name} is declared but never referenced in the Dockerfile.`, line: arg.line });
      }
    }

    // Check per-stage args
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'ARG') continue;
        const ai = inst as ArgInstruction;
        const name = ai.name;
        if (!name) continue;
        if (IMPLICIT_ARGS.has(name)) continue;
        if (IMPLICIT_ARG_PREFIXES.some(p => name.startsWith(p))) continue;
        const re = new RegExp(`\\$\\{?${name}\\}?`);
        if (!re.test(combined)) {
          violations.push({ rule: 'DL3052', severity: 'style', message: `ARG ${name} is declared but never referenced in the Dockerfile.`, line: ai.line });
        }
      }
    }
    return violations;
  },
};

// DL3053: ENV overrides ARG with same name
export const DL3053: Rule = {
  id: 'DL3053', severity: 'warning',
  description: 'ENV variable overrides ARG with the same name, preventing build-arg injection',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const argDefaults = new Map<string, boolean>(); // name -> has default value
      for (const inst of stage.instructions) {
        if (inst.type === 'ARG') {
          const ai = inst as ArgInstruction;
          if (ai.name) {
            argDefaults.set(ai.name, ai.defaultValue !== undefined);
          }
        } else if (inst.type === 'ENV') {
          const env = inst as EnvInstruction;
          for (const pair of env.pairs) {
            // Only flag when ARG has a default value (without default, there's nothing to shadow)
            if (argDefaults.has(pair.key) && argDefaults.get(pair.key)) {
              // Skip if ENV value references the ARG variable (e.g., ENV FOO $FOO or ENV FOO ${FOO})
              // This is the correct pattern to pass ARG values to runtime ENV
              const val = pair.value.trim();
              const isArgRef = val === `$${pair.key}` || val === `\${${pair.key}}`;
              if (!isArgRef) {
                violations.push({ rule: 'DL3053', severity: 'warning', message: `ENV ${pair.key} overrides ARG with the same name. --build-arg ${pair.key} will have no effect.`, line: inst.line });
              }
            }
          }
        }
      }
    }
    return violations;
  },
};

// DL3057: HEALTHCHECK instruction missing
// Skip for non-service Dockerfiles (devcontainer, releasing, CI, test utilities)
const DL3057_SKIP_DIRS = /(?:^|[/\\])(?:\.devcontainer|RELEASING|releasing|hack|contrib|packaging|benchmarks?|examples?|tools|testdata|test-framework|e2e-tests?|scripts)(?:[/\\]|$)/i;
export const DL3057: Rule = {
  id: 'DL3057', severity: 'info',
  description: 'HEALTHCHECK instruction missing',
  check(ctx) {
    const violations: Violation[] = [];
    // Skip non-service Dockerfiles by path or filename pattern
    if (ctx.filePath && DL3057_SKIP_DIRS.test(ctx.filePath)) return violations;
    // Skip build/CI-oriented Dockerfiles by filename (e.g., Dockerfile.make, Dockerfile.ci)
    if (ctx.filePath) {
      const fname = ctx.filePath.replace(/^.*[/\\]/, '').toLowerCase();
      if (/^dockerfile\.(make|ci|build|lint|test|dev|(.+\.)?tilt)$/i.test(fname)) return violations;
      if (/^(dev|build|ci|test|lint)\.dockerfile$/i.test(fname)) return violations;
    }
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;

    // Skip scratch and distroless/chainguard images (no processes to health-check)
    const image = lastStage.from.image.toLowerCase();
    if (image === 'scratch') return violations;
    if (image.includes('distroless') || image.includes('chainguard')) return violations;

    // Skip utility images without CMD/ENTRYPOINT (they don't serve requests)
    const hasCmdOrEp = lastStage.instructions.some(i => i.type === 'CMD' || i.type === 'ENTRYPOINT');
    if (!hasCmdOrEp) return violations;

    const hasHC = lastStage.instructions.some(i => i.type === 'HEALTHCHECK');
    if (!hasHC) {
      violations.push({ rule: 'DL3057', severity: 'info', message: 'HEALTHCHECK instruction missing', line: lastStage.from.line });
    }
    return violations;
  },
};

// DL4006: Set SHELL to pipefail-enabled bash when using pipes in RUN
// Without pipefail, only the exit code of the last command in a pipe is checked.
// e.g., `RUN curl http://example.com | tar xz` — if curl fails, the build continues.
export const DL4006: Rule = {
  id: 'DL4006', severity: 'warning',
  description: 'Set the SHELL option -o pipefail before RUN with a pipe in.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      let hasPipefail = false;
      for (const inst of stage.instructions) {
        // Track SHELL instructions that enable pipefail
        if (inst.type === 'SHELL') {
          const shellArgs = inst.arguments.toLowerCase();
          if (shellArgs.includes('pipefail')) {
            hasPipefail = true;
          }
          continue;
        }

        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;

        // Check if this RUN uses an inline "set -o pipefail" or "set -euo pipefail"
        if (/\bset\s+[^;|&]*pipefail/.test(args)) continue;

        // Check if RUN uses bash -c with pipefail inline
        if (/\bbash\s+-[a-zA-Z]*o\s+pipefail\b/.test(args)) continue;
        if (/\bbash\s+[^;|&]*-o\s+pipefail\b/.test(args)) continue;

        // Check for pipes (but not || which is logical OR, or |& for stderr redirect)
        // Also skip heredoc bodies and strings that contain | inside quotes
        const stripped = args
          .replace(/\\\n/g, ' ')           // join continuations
          .replace(/"[^"]*"/g, '""')       // strip double-quoted strings
          .replace(/'[^']*'/g, "''")       // strip single-quoted strings
          .replace(/\|\|/g, '  ')          // remove logical OR
          .replace(/\|&/g, '  ');          // remove |& (bash stderr redirect)

        if (/\|/.test(stripped) && !hasPipefail) {
          violations.push({
            rule: 'DL4006', severity: 'warning',
            message: 'Set the SHELL option -o pipefail before RUN with a pipe in. If any command in a pipe fails, the whole pipe succeeds regardless. Use `SHELL ["/bin/bash", "-o", "pipefail", "-c"]` or add `set -o pipefail &&` before the pipe.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};
