import { Rule, Violation } from '../types';
import { CopyInstruction, WorkdirInstruction } from '../../parser/types';

// ---------------------------------------------------------------------------
// DV6xxx: Supply Chain & Runtime Hardening
// ---------------------------------------------------------------------------

// DV6001: Insecure pip install (--trusted-host or http:// index)
export const DV6001: Rule = {
  id: 'DV6001', severity: 'warning',
  description: 'Avoid bypassing TLS verification for Python package installation.',
  check(ctx) {
    const violations: Violation[] = [];
    const trustedHost = /pip\s+install\b[^&|;]*--trusted-host/;
    const httpIndex = /pip\s+install\b[^&|;]*(?:-i|--index-url|--extra-index-url)\s+http:\/\//;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (trustedHost.test(inst.arguments)) {
          violations.push({ rule: 'DV6001', severity: 'warning', message: 'pip install uses --trusted-host, bypassing TLS certificate verification. Use HTTPS package indexes instead.', line: inst.line });
        } else if (httpIndex.test(inst.arguments)) {
          violations.push({ rule: 'DV6001', severity: 'warning', message: 'pip install uses an HTTP (non-TLS) package index. Use HTTPS to prevent man-in-the-middle attacks.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6002: STOPSIGNAL SIGKILL prevents graceful shutdown
export const DV6002: Rule = {
  id: 'DV6002', severity: 'warning',
  description: 'STOPSIGNAL SIGKILL prevents graceful shutdown of the container process.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'STOPSIGNAL') continue;
        const sig = inst.arguments.trim().toUpperCase();
        if (sig === 'SIGKILL' || sig === '9') {
          violations.push({ rule: 'DV6002', severity: 'warning', message: 'STOPSIGNAL SIGKILL prevents graceful shutdown. The process cannot catch or handle SIGKILL, so cleanup code will not run. Use SIGTERM (default) or SIGQUIT instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6003: Installing network debugging tools increases attack surface
export const DV6003: Rule = {
  id: 'DV6003', severity: 'info',
  description: 'Avoid installing network debugging tools in production images.',
  check(ctx) {
    const violations: Violation[] = [];
    // Match package names in apt-get install, apk add, yum/dnf install
    const installCmd = /(?:apt-get\s+install|apk\s+add|yum\s+install|dnf\s+install)\b/;
    const debugTools = /\b(netcat|netcat-openbsd|netcat-traditional|ncat|nmap|socat|telnet|tcpdump|wireshark|tshark|ettercap|hping3)\b/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (!installCmd.test(inst.arguments)) continue;
        const match = inst.arguments.match(debugTools);
        if (match) {
          violations.push({ rule: 'DV6003', severity: 'info', message: `Installing network debugging tool '${match[1]}' increases attack surface. Remove it from production images or use a multi-stage build.`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6004: RUN with full output suppression (> /dev/null 2>&1)
export const DV6004: Rule = {
  id: 'DV6004', severity: 'info',
  description: 'Avoid suppressing all output in RUN instructions, which hides build errors.',
  check(ctx) {
    const violations: Violation[] = [];
    // Match patterns like > /dev/null 2>&1, &> /dev/null, 2>&1 >/dev/null
    const fullSuppression = /(?:>\s*\/dev\/null\s+2>&1|2>&1\s*>\s*\/dev\/null|&>\s*\/dev\/null)/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (fullSuppression.test(inst.arguments)) {
          violations.push({ rule: 'DV6004', severity: 'info', message: 'RUN command suppresses all output (> /dev/null 2>&1). This hides errors during build. Redirect only stdout if needed, or remove the suppression.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6005: npm install with --unsafe-perm allows lifecycle scripts to run as root
export const DV6005: Rule = {
  id: 'DV6005', severity: 'warning',
  description: 'Avoid npm install --unsafe-perm, which allows lifecycle scripts to run as root.',
  check(ctx) {
    const violations: Violation[] = [];
    const unsafePerm = /npm\s+install\b[^&|;]*--unsafe-perm/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (unsafePerm.test(inst.arguments)) {
          violations.push({ rule: 'DV6005', severity: 'warning', message: 'npm install with --unsafe-perm allows lifecycle scripts to execute as root. This enables malicious packages to run arbitrary code with elevated privileges. Remove --unsafe-perm or run as a non-root user.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6006: npm/yarn configured with HTTP (non-TLS) registry
export const DV6006: Rule = {
  id: 'DV6006', severity: 'warning',
  description: 'Avoid configuring npm/yarn with an HTTP (non-TLS) registry URL.',
  check(ctx) {
    const violations: Violation[] = [];
    // npm config set registry http://... or npm install --registry http://...
    const npmHttpRegistry = /npm\s+(?:config\s+set\s+registry|install\b[^&|;]*--registry)\s+http:\/\//;
    // yarn config set registry http://...
    const yarnHttpRegistry = /yarn\s+config\s+set\s+registry\s+http:\/\//;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (npmHttpRegistry.test(inst.arguments)) {
          violations.push({ rule: 'DV6006', severity: 'warning', message: 'npm registry configured with HTTP (non-TLS). Use HTTPS to prevent man-in-the-middle attacks on package downloads.', line: inst.line });
        } else if (yarnHttpRegistry.test(inst.arguments)) {
          violations.push({ rule: 'DV6006', severity: 'warning', message: 'yarn registry configured with HTTP (non-TLS). Use HTTPS to prevent man-in-the-middle attacks on package downloads.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6007: apt-key usage is deprecated and insecure
export const DV6007: Rule = {
  id: 'DV6007', severity: 'warning',
  description: 'apt-key is deprecated. Use signed-by in sources list instead.',
  check(ctx) {
    const violations: Violation[] = [];
    const aptKey = /apt-key\s+(?:add|adv)/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (aptKey.test(inst.arguments)) {
          violations.push({ rule: 'DV6007', severity: 'warning', message: 'apt-key is deprecated and adds keys to the global trusted keyring, allowing them to authenticate any repository. Use [signed-by=/path/to/key.gpg] in sources.list.d instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6009: pip install --break-system-packages bypasses PEP 668 protection
export const DV6009: Rule = {
  id: 'DV6009', severity: 'warning',
  description: 'Avoid pip install --break-system-packages. Use a virtual environment instead.',
  check(ctx) {
    const violations: Violation[] = [];
    const breakSysPkg = /pip3?\s+install\b[^&|;]*--break-system-packages/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (breakSysPkg.test(inst.arguments)) {
          violations.push({ rule: 'DV6009', severity: 'warning', message: 'pip install --break-system-packages bypasses PEP 668 environment isolation. Use a virtual environment (python -m venv) or --user install to avoid corrupting system Python packages.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6010: yarn/npm install without lockfile (non-deterministic builds)
export const DV6010: Rule = {
  id: 'DV6010', severity: 'info',
  description: 'Package install without frozen lockfile may produce non-deterministic builds.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        // yarn install without --frozen-lockfile or --immutable
        if (/\byarn\s+install\b/.test(args) && !/--frozen-lockfile|--immutable/.test(args)) {
          violations.push({ rule: 'DV6010', severity: 'info', message: 'yarn install without --frozen-lockfile or --immutable may produce non-deterministic builds. Use `yarn install --frozen-lockfile` (v1) or `yarn install --immutable` (v2+).', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6008: COPY or ADD of .git directory leaks repository history
export const DV6008: Rule = {
  id: 'DV6008', severity: 'warning',
  description: 'Avoid copying .git directory into the image.',
  check(ctx) {
    const violations: Violation[] = [];
    const gitDir = /(?:^|[/\\])\.git(?:[/\\]|$)/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => gitDir.test(s) || s === '.git')) {
          violations.push({ rule: 'DV6008', severity: 'warning', message: 'Copying .git directory into the image leaks repository history, credentials, and metadata. Add .git to .dockerignore or copy only the needed files.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6011: curl/wget downloading from http:// (non-TLS) URLs in RUN — MITM risk
export const DV6011: Rule = {
  id: 'DV6011', severity: 'warning',
  description: 'Avoid downloading files over plain HTTP. Use HTTPS to prevent man-in-the-middle attacks.',
  check(ctx) {
    const violations: Violation[] = [];
    // Match curl/wget with an http:// URL (not https://)
    // Exclude localhost/127.0.0.1 — local downloads are safe
    const httpDownload = /(?:curl|wget)\s+[^;|&]*\bhttp:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[\/:)}\s])/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (httpDownload.test(inst.arguments)) {
          violations.push({ rule: 'DV6011', severity: 'warning', message: 'Downloading files over plain HTTP is vulnerable to man-in-the-middle attacks. Use HTTPS URLs instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6012: WORKDIR set to sensitive system directory
export const DV6012: Rule = {
  id: 'DV6012', severity: 'warning',
  description: 'Avoid using sensitive system directories as WORKDIR.',
  check(ctx) {
    const violations: Violation[] = [];
    const sensitiveDirs: Record<string, string> = {
      '/': 'filesystem root',
      '/etc': 'system configuration',
      '/var': 'system variable data',
      '/usr': 'system programs',
      '/bin': 'system binaries',
      '/sbin': 'system administration binaries',
      '/lib': 'system libraries',
      '/dev': 'device files',
      '/proc': 'process information',
      '/sys': 'system information',
      '/boot': 'boot loader files',
    };
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'WORKDIR') continue;
        const dir = inst.arguments.trim().replace(/\/+$/, '') || '/';
        const info = sensitiveDirs[dir];
        if (info) {
          violations.push({ rule: 'DV6012', severity: 'warning', message: `WORKDIR set to "${dir}" (${info}). Use a dedicated application directory like /app or /opt/app instead.`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6013: curl/wget download without --fail flag
export const DV6013: Rule = {
  id: 'DV6013', severity: 'warning',
  description: 'curl/wget used without failure flags. HTTP errors produce silent bad downloads.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        // Check curl without --fail or -f (ignore -fsSL etc. which includes f)
        if (/\bcurl\b/.test(args) && !/\bcurl\b[^|;]*\s(?:--fail\b|-[a-zA-Z]*f)/.test(args)) {
          violations.push({ rule: 'DV6013', severity: 'warning', message: 'curl used without --fail/-f flag. HTTP error responses (4xx/5xx) will be silently saved instead of failing the build. Use `curl -fsSL` or `curl --fail`.', line: inst.line });
        }
        // Check wget without --tries or specific failure handling isn't the concern;
        // wget fails on HTTP errors by default, but not with -q which hides errors
      }
    }
    return violations;
  },
};

// DV6014: HEALTHCHECK with too-short interval (< 5s)
export const DV6014: Rule = {
  id: 'DV6014', severity: 'info',
  description: 'HEALTHCHECK interval too short, causing unnecessary resource consumption.',
  check(ctx) {
    const violations: Violation[] = [];
    const intervalRe = /--interval=(\d+)(s|ms|m)?/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'HEALTHCHECK') continue;
        const match = inst.arguments.match(intervalRe);
        if (match) {
          const val = parseInt(match[1], 10);
          const unit = match[2] || 's';
          let seconds = val;
          if (unit === 'ms') seconds = val / 1000;
          else if (unit === 'm') seconds = val * 60;
          if (seconds < 5) {
            violations.push({ rule: 'DV6014', severity: 'info', message: `HEALTHCHECK interval is ${match[0]} (< 5s). Very frequent health checks waste CPU and network resources. Use at least 10s.`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV6015: git clone without --depth (full history wastes space and may leak info)
export const DV6015: Rule = {
  id: 'DV6015', severity: 'info',
  description: 'git clone without --depth fetches full history, wasting image space.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        // Find git clone commands without --depth or --single-branch
        if (/\bgit\s+clone\b/.test(args) && !/--depth\b/.test(args) && !/--single-branch\b/.test(args)) {
          violations.push({ rule: 'DV6015', severity: 'info', message: 'git clone without --depth fetches full repository history, increasing image size and potentially exposing sensitive historical data. Use `git clone --depth 1` for smaller images.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6017: HEALTHCHECK NONE explicitly disables health monitoring
export const DV6017: Rule = {
  id: 'DV6017', severity: 'info',
  description: 'HEALTHCHECK NONE disables container health monitoring.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    for (const inst of lastStage.instructions) {
      if (inst.type !== 'HEALTHCHECK') continue;
      const args = inst.arguments.trim().toUpperCase();
      if (args === 'NONE') {
        violations.push({ rule: 'DV6017', severity: 'info', message: 'HEALTHCHECK NONE explicitly disables health monitoring. Orchestrators (Kubernetes, Docker Swarm) rely on health checks for automated recovery. Remove HEALTHCHECK NONE or add a proper health check.', line: inst.line });
      }
    }
    return violations;
  },
};

// DV6018: pip install from VCS URL (git+https/git+ssh) without version pin
export const DV6018: Rule = {
  id: 'DV6018', severity: 'warning',
  description: 'pip install from VCS URL without version pin is a supply chain risk.',
  check(ctx) {
    const violations: Violation[] = [];
    // Match pip install git+https://... or git+ssh://... without @<commit/tag>
    // Pinned: git+https://github.com/org/repo@v1.0.0 or @abc123
    // Unpinned: git+https://github.com/org/repo (defaults to HEAD)
    const pipVcs = /pip3?\s+install\b[^;|&]*\bgit\+(?:https?|ssh):\/\/[^\s]+/g;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        let match: RegExpExecArray | null;
        const re = new RegExp(pipVcs.source, pipVcs.flags);
        while ((match = re.exec(args)) !== null) {
          // Extract the VCS URL from the match
          const urlMatch = /git\+(?:https?|ssh):\/\/[^\s]+/.exec(match[0]);
          if (!urlMatch) continue;
          const url = urlMatch[0];
          // Check if the URL has a pin (@commit, @tag, @branch) after the repo path
          // git+https://github.com/org/repo.git@v1.0 or @abc123def
          // Exclude @user in git+ssh://user@host (authentication, not pinning)
          // The pin @ appears after the path component (after .git or after /repo)
          const pathPart = url.replace(/^git\+(?:https?|ssh):\/\/[^/]*/, ''); // strip scheme+host
          if (!/@[a-zA-Z0-9]/.test(pathPart)) {
            violations.push({ rule: 'DV6018', severity: 'warning', message: 'pip install from VCS URL without version pin (e.g., @tag or @commit). This fetches HEAD, making builds non-reproducible and vulnerable to supply chain attacks. Pin with @<tag> or @<commit-hash>.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV6019: Shell form CMD prevents proper signal handling
export const DV6019: Rule = {
  id: 'DV6019', severity: 'info',
  description: 'CMD uses shell form. Use exec form for proper signal handling.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;
    // Only check the last CMD (earlier ones are overridden)
    const cmdInstructions = lastStage.instructions.filter(i => i.type === 'CMD');
    if (cmdInstructions.length === 0) return violations;
    const lastCmd = cmdInstructions[cmdInstructions.length - 1];
    const args = lastCmd.arguments.trim();
    // Exec form starts with [
    if (!args.startsWith('[')) {
      // Skip if ENTRYPOINT is set (CMD in shell form with ENTRYPOINT is a common pattern for default args)
      const hasEntrypoint = lastStage.instructions.some(i => i.type === 'ENTRYPOINT');
      if (hasEntrypoint) return violations;
      violations.push({ rule: 'DV6019', severity: 'info', message: 'CMD uses shell form, which wraps the process in /bin/sh -c and prevents proper signal handling (SIGTERM). Use exec form: CMD ["executable", "arg1"]. This ensures PID 1 receives signals correctly.', line: lastCmd.line });
    }
    return violations;
  },
};

// DV6020: COPY --chmod or ADD --chmod with overly permissive modes
export const DV6020: Rule = {
  id: 'DV6020', severity: 'warning',
  description: 'COPY/ADD --chmod with overly permissive file modes (777/666).',
  check(ctx) {
    const violations: Violation[] = [];
    const dangerousModes = /--chmod=(?:777|776|666|o\+w|a\+w)/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const raw = inst.raw || inst.arguments || '';
        if (dangerousModes.test(raw)) {
          violations.push({ rule: 'DV6020', severity: 'warning', message: `${inst.type} with overly permissive --chmod detected. Avoid 777/666/world-writable modes. Use the minimum required permissions.`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6016: npm install with --force or --legacy-peer-deps bypasses dependency safety
export const DV6016: Rule = {
  id: 'DV6016', severity: 'warning',
  description: 'npm install with --force/--legacy-peer-deps bypasses dependency safety checks.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (/\bnpm\s+(?:install|i|ci)\b/.test(args)) {
          if (/--force\b/.test(args)) {
            violations.push({ rule: 'DV6016', severity: 'warning', message: 'npm install with --force bypasses peer dependency checks and overrides protections. This can introduce incompatible or vulnerable transitive dependencies.', line: inst.line });
          } else if (/--legacy-peer-deps\b/.test(args)) {
            violations.push({ rule: 'DV6016', severity: 'warning', message: 'npm install with --legacy-peer-deps ignores peer dependency conflicts. This may allow incompatible or vulnerable dependency versions.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV6021: pip install --extra-index-url is a dependency confusion attack vector.
// When --extra-index-url is used alongside the default PyPI index, an attacker can
// register a higher-version package on PyPI with the same name as an internal package,
// causing pip to prefer the malicious public version. Use --index-url (replaces default)
// instead, or use --no-deps with a lock file.
export const DV6021: Rule = {
  id: 'DV6021', severity: 'warning',
  description: 'pip install with --extra-index-url enables dependency confusion attacks.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (/\bpip3?\s+install\b/.test(args) && /--extra-index-url\b/.test(args)) {
          violations.push({ rule: 'DV6021', severity: 'warning', message: 'pip install with --extra-index-url enables dependency confusion attacks. An attacker can publish a higher-version package on PyPI with the same name as your internal package. Use --index-url (replaces default PyPI) instead, or use a lock file with hash checking.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV6022: go install/get with GOPROXY=direct or GONOSUMDB bypasses Go module proxy security.
// The Go module proxy (proxy.golang.org) and checksum database (sum.golang.org) protect
// against tampered modules. Bypassing them removes a critical supply chain security layer.
export const DV6022: Rule = {
  id: 'DV6022', severity: 'warning',
  description: 'Go module proxy or checksum database bypassed, reducing supply chain security.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV') {
          const envInst = inst as import('../../parser/types').EnvInstruction;
          for (const pair of envInst.pairs) {
            if (/^GOPROXY$/i.test(pair.key) && /\bdirect\b/.test(pair.value) && !/proxy\.golang\.org/.test(pair.value)) {
              violations.push({ rule: 'DV6022', severity: 'warning', message: 'GOPROXY=direct bypasses the Go module proxy, removing a supply chain security layer. The module proxy caches and verifies modules; bypassing it allows fetching tampered code directly from VCS.', line: inst.line });
            }
            if (/^GONOSUMDB$/i.test(pair.key) && pair.value && pair.value !== '') {
              violations.push({ rule: 'DV6022', severity: 'warning', message: `GONOSUMDB=${pair.value} disables checksum verification for matching modules. This allows tampered dependencies to be used without detection. Remove GONOSUMDB or restrict its scope.`, line: inst.line });
            }
          }
        }
        if (inst.type === 'RUN') {
          const args = inst.arguments;
          // Inline GOPROXY=direct before go install/get
          if (/\bGOPROXY=direct\b/.test(args) && /\bgo\s+(?:install|get|mod)\b/.test(args) && !/proxy\.golang\.org/.test(args)) {
            violations.push({ rule: 'DV6022', severity: 'warning', message: 'GOPROXY=direct in RUN bypasses the Go module proxy. The proxy caches and verifies modules; bypassing it allows fetching tampered code directly from VCS.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV6023: COPY --from referencing external image without digest pin
// When COPY --from=<image> references an external image (not a build stage alias),
// using a mutable tag like :latest or no tag at all means the source content can change
// between builds, breaking supply chain integrity and reproducibility.
export const DV6023: Rule = {
  id: 'DV6023', severity: 'warning',
  description: 'COPY --from references external image without digest pin.',
  check(ctx) {
    const violations: Violation[] = [];
    // Collect all stage aliases and numeric indices
    const stageAliases = new Set<string>();
    ctx.ast.stages.forEach((stage, idx) => {
      stageAliases.add(String(idx));
      if (stage.from.alias) {
        stageAliases.add(stage.from.alias.toLowerCase());
      }
    });

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY') continue;
        const copy = inst as import('../../parser/types').CopyInstruction;
        if (!copy.from) continue;

        const fromRef = copy.from.trim();

        // Skip numeric indices and stage aliases — those reference build stages, not external images
        if (stageAliases.has(fromRef.toLowerCase())) continue;
        // Pure numeric references are stage indices
        if (/^\d+$/.test(fromRef)) continue;

        // This is an external image reference (e.g., COPY --from=nginx:latest /etc/nginx .)
        // Check if it has a digest pin (@sha256:...)
        if (fromRef.includes('@sha256:') || fromRef.includes('@sha384:') || fromRef.includes('@sha512:')) {
          continue; // Properly pinned by digest
        }

        // Flag: external image without digest
        const hasTag = /:/.test(fromRef) && !fromRef.startsWith('localhost');
        const tagPart = hasTag ? fromRef.split(':').pop() : 'latest (implicit)';
        violations.push({
          rule: 'DV6023', severity: 'warning',
          message: `COPY --from=${fromRef} references an external image with mutable tag "${tagPart}". Pin to a digest (@sha256:...) for reproducible builds and supply chain security.`,
          line: inst.line,
        });
      }
    }
    return violations;
  },
};
