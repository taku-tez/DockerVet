import { Rule, Violation } from '../types';
import { CopyInstruction } from '../../parser/types';

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
