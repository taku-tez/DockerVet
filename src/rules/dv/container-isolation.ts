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
      { pattern: /GOFLAGS\s*=\s*[^&|;]*-insecure/i, msg: 'GOFLAGS=-insecure disables security checks for Go module downloads.' },
      { pattern: /CURL_SSL_BACKEND\s*=\s*["']?insecure/i, msg: 'CURL_SSL_BACKEND=insecure disables TLS verification for curl.' },
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
