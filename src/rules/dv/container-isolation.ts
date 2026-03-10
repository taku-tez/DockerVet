import { Rule, Violation } from '../types';

// ---------------------------------------------------------------------------
// DV8xxx: Container Isolation & Escape Prevention
// ---------------------------------------------------------------------------

// DV8001: setcap granting dangerous Linux capabilities
export const DV8001: Rule = {
  id: 'DV8001', severity: 'warning',
  description: 'Avoid granting dangerous Linux capabilities via setcap.',
  check(ctx) {
    const violations: Violation[] = [];
    const dangerousCaps = /cap_sys_admin|cap_sys_ptrace|cap_net_raw|cap_dac_override|cap_fowner|cap_setuid|cap_setgid|cap_sys_module|cap_sys_rawio|cap_mknod/i;
    const setcapPattern = /\bsetcap\b/i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (!setcapPattern.test(inst.arguments)) continue;
        if (dangerousCaps.test(inst.arguments)) {
          violations.push({
            rule: 'DV8001', severity: 'warning',
            message: 'setcap grants a dangerous Linux capability. Capabilities like CAP_SYS_ADMIN, CAP_SYS_PTRACE, and CAP_NET_RAW can facilitate container escapes or network attacks.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV8002: Adding third-party APT repositories without GPG verification
export const DV8002: Rule = {
  id: 'DV8002', severity: 'warning',
  description: 'Adding third-party APT/YUM repositories without proper GPG key verification.',
  check(ctx) {
    const violations: Violation[] = [];
    // Patterns: add-apt-repository without signed-by, or echo > sources.list without signed-by
    const addAptRepo = /\badd-apt-repository\b/i;
    const signedBy = /signed-by/i;
    // curl/wget piped to apt-key add (deprecated and insecure)
    const aptKeyPipe = /(?:curl|wget)\s[^|]*\|\s*(?:sudo\s+)?apt-key\s+add/i;
    const aptKeyAdd = /\bapt-key\s+add\b/i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (aptKeyPipe.test(args) || aptKeyAdd.test(args)) {
          violations.push({
            rule: 'DV8002', severity: 'warning',
            message: 'apt-key is deprecated and insecure. Use signed-by in /etc/apt/sources.list.d/ with a keyring file instead.',
            line: inst.line,
          });
        } else if (addAptRepo.test(args) && !signedBy.test(args)) {
          // add-apt-repository without signed-by might add unverified repos
          violations.push({
            rule: 'DV8002', severity: 'warning',
            message: 'add-apt-repository adds a third-party repository. Consider using signed-by for GPG key verification to prevent supply chain attacks.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV8003: Direct manipulation of /etc/passwd, /etc/shadow, or /etc/group
export const DV8003: Rule = {
  id: 'DV8003', severity: 'warning',
  description: 'Avoid directly editing /etc/passwd, /etc/shadow, or /etc/group. Use useradd/usermod instead.',
  check(ctx) {
    const violations: Violation[] = [];
    // Detect echo/sed/tee writing to passwd/shadow/group files
    const directEdit = /(?:echo|sed|tee|cat)\s[^&|;]*(?:\/etc\/passwd|\/etc\/shadow|\/etc\/group)/i;
    // Also detect redirect to these files
    const redirect = />\s*(?:\/etc\/passwd|\/etc\/shadow|\/etc\/group)/i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (directEdit.test(args) || redirect.test(args)) {
          violations.push({
            rule: 'DV8003', severity: 'warning',
            message: 'Direct manipulation of /etc/passwd, /etc/shadow, or /etc/group is error-prone and can create security holes. Use useradd/usermod/groupadd instead.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV8005: Security-disabling commands in RUN instructions
export const DV8005: Rule = {
  id: 'DV8005', severity: 'warning',
  description: 'Avoid disabling TLS/SSL verification or security features in RUN commands.',
  check(ctx) {
    const violations: Violation[] = [];
    const dangerousCommands: Array<{ pattern: RegExp; msg: string }> = [
      { pattern: /\bnpm\s+(?:config\s+)?set\s+strict-ssl\s+false/i, msg: 'npm config set strict-ssl false disables TLS certificate verification for npm registry connections.' },
      { pattern: /\byarn\s+config\s+set\s+strict-ssl\s+false/i, msg: 'yarn config set strict-ssl false disables TLS certificate verification for Yarn registry connections.' },
      { pattern: /\bpip\s+install\s+[^&|;]*--trusted-host\b/i, msg: 'pip install --trusted-host bypasses TLS verification for the specified host, enabling man-in-the-middle attacks.' },
      { pattern: /\bgit\s+config\s+[^&|;]*(?:http\.sslVerify|https\.sslVerify)\s+false/i, msg: 'git config http.sslVerify false disables TLS verification for Git operations.' },
      { pattern: /\bcomposer\s+config\s+[^&|;]*disable-tls\s+true/i, msg: 'composer config disable-tls true disables TLS for all Composer downloads.' },
      { pattern: /\bgem\s+(?:install|fetch)\s+[^&|;]*--no-verify/i, msg: 'gem --no-verify skips signature verification for RubyGems packages.' },
      { pattern: /\bconda\s+config\s+[^&|;]*ssl_verify\s+(?:false|0|no)/i, msg: 'conda config ssl_verify false disables TLS verification for Conda package downloads.' },
    ];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        for (const { pattern, msg } of dangerousCommands) {
          if (pattern.test(inst.arguments)) {
            violations.push({ rule: 'DV8005', severity: 'warning', message: msg, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV8004: Disabling security features via environment variables
export const DV8004: Rule = {
  id: 'DV8004', severity: 'warning',
  description: 'Avoid disabling language/runtime security features via environment variables.',
  check(ctx) {
    const violations: Violation[] = [];
    // Dangerous env vars that disable security features
    const dangerousEnvs: Array<{ pattern: RegExp; msg: string }> = [
      { pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/i, msg: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification for all Node.js HTTPS requests.' },
      { pattern: /PYTHONHTTPSVERIFY\s*=\s*["']?0["']?/i, msg: 'PYTHONHTTPSVERIFY=0 disables TLS certificate verification for Python HTTPS requests.' },
      { pattern: /GIT_SSL_NO_VERIFY\s*=\s*["']?(?:true|1)["']?/i, msg: 'GIT_SSL_NO_VERIFY disables TLS verification for Git operations, enabling man-in-the-middle attacks.' },
      { pattern: /GONOSUMCHECK\s*=\s*/i, msg: 'GONOSUMCHECK disables Go module checksum verification, weakening supply chain integrity.' },
      { pattern: /GONOSUMDB\s*=\s*/i, msg: 'GONOSUMDB disables Go checksum database lookups for specified modules, weakening supply chain verification.' },
      { pattern: /GOFLAGS\s*=\s*[^&|;]*-insecure/i, msg: 'GOFLAGS=-insecure disables security checks for Go module downloads.' },
      { pattern: /CURL_SSL_BACKEND\s*=\s*["']?insecure/i, msg: 'CURL_SSL_BACKEND=insecure disables TLS verification for curl.' },
      { pattern: /NPM_CONFIG_STRICT_SSL\s*=\s*["']?false["']?/i, msg: 'NPM_CONFIG_STRICT_SSL=false disables TLS certificate verification for npm registry connections.' },
      { pattern: /YARN_STRICT_SSL\s*=\s*["']?false["']?/i, msg: 'YARN_STRICT_SSL=false disables TLS certificate verification for Yarn registry connections.' },
      { pattern: /PIP_TRUSTED_HOST\s*=\s*/i, msg: 'PIP_TRUSTED_HOST bypasses TLS verification for the specified pip hosts, enabling man-in-the-middle attacks.' },
      { pattern: /REQUESTS_CA_BUNDLE\s*=\s*["']?\s*["']?$/i, msg: 'REQUESTS_CA_BUNDLE set to empty disables CA certificate verification for Python requests library.' },
      { pattern: /SSL_CERT_FILE\s*=\s*["']?\/dev\/null["']?/i, msg: 'SSL_CERT_FILE=/dev/null disables TLS certificate verification system-wide.' },
    ];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'ENV' && inst.type !== 'ARG') continue;
        for (const { pattern, msg } of dangerousEnvs) {
          if (pattern.test(inst.arguments) || pattern.test(inst.raw)) {
            violations.push({ rule: 'DV8004', severity: 'warning', message: msg, line: inst.line });
            break;
          }
        }
      }
    }
    return violations;
  },
};

// DV8006: Multi-stage build - final stage copies build tool directories
// Detects when the final stage copies broad directories from a builder stage
// that likely contain compilers, build tools, and development headers.
// These bloat the final image and increase attack surface.
import { CopyInstruction } from '../../parser/types';
const BUILD_TOOL_PATHS = /^(?:\/usr\/(?:local\/)?(?:include|src|share\/(?:man|doc|info|gcc))|\/usr\/lib\/gcc|\/opt\/(?:gcc|build)|\/root\/\.cache\/(?:go-build|pip))(?:\/|$)/;
const BUILD_TOOL_BROAD = /^(?:\/usr\/local\/?|\/usr\/?)$/;
export const DV8006: Rule = {
  id: 'DV8006', severity: 'warning',
  description: 'Final stage copies build tool directories from builder stage, increasing image size and attack surface.',
  check(ctx) {
    const violations: Violation[] = [];
    const stages = ctx.ast.stages;
    if (stages.length < 2) return violations;
    const finalStage = stages[stages.length - 1];
    for (const inst of finalStage.instructions) {
      if (inst.type !== 'COPY') continue;
      const c = inst as CopyInstruction;
      if (!c.from) continue;
      for (const src of c.sources) {
        if (BUILD_TOOL_PATHS.test(src)) {
          violations.push({
            rule: 'DV8006', severity: 'warning',
            message: `COPY --from=${c.from} copies build tool path "${src}" into the final stage. This likely includes compilers, headers, and dev files that increase image size and attack surface. Copy only the specific build artifacts you need.`,
            line: inst.line,
          });
        } else if (BUILD_TOOL_BROAD.test(src)) {
          violations.push({
            rule: 'DV8006', severity: 'warning',
            message: `COPY --from=${c.from} copies broad directory "${src}" into the final stage. This likely includes build tools, compilers, and development files. Copy only specific artifacts (e.g., compiled binaries) instead.`,
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};
