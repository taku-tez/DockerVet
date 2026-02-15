import { Rule, Violation } from '../types';
import { ExposeInstruction } from '../../parser/types';

// DV2001: apt-get update used alone (should be combined with install)
export const DV2001: Rule = {
  id: 'DV2001', severity: 'warning',
  description: 'apt-get update should not be used alone. Combine with apt-get install in the same RUN instruction.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const a = inst.arguments;
        if (/apt-get\s+update/.test(a) && !/(?:apt-get|apt)\s+install/.test(a)) {
          violations.push({ rule: 'DV2001', severity: 'warning', message: 'apt-get update should be combined with apt-get install in the same RUN instruction to avoid cache issues.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV2002: apt-get dist-upgrade should be avoided
export const DV2002: Rule = {
  id: 'DV2002', severity: 'warning',
  description: 'Avoid apt-get dist-upgrade in Dockerfiles.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /apt-get\s+dist-upgrade/.test(inst.arguments)) {
          violations.push({ rule: 'DV2002', severity: 'warning', message: 'Avoid apt-get dist-upgrade. Pin specific package versions instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV2003: Sensitive directories should not be mounted as VOLUME
export const DV2003: Rule = {
  id: 'DV2003', severity: 'error',
  description: 'Do not mount sensitive system directories as VOLUME.',
  check(ctx) {
    const sensitive = ['/etc', '/var/run', '/var/lib', '/usr', '/bin', '/sbin', '/dev', '/sys', '/proc', '/boot'];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'VOLUME') continue;
        for (const dir of sensitive) {
          const re = new RegExp(`(?:^|[\\s,\\["])${dir.replace('/', '\\/')}(?:[\\s,\\]"]|$)`);
          if (re.test(inst.arguments)) {
            violations.push({ rule: 'DV2003', severity: 'error', message: `Sensitive directory "${dir}" should not be defined as a VOLUME.`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV2004: apt-get install without --no-install-recommends
export const DV2004: Rule = {
  id: 'DV2004', severity: 'info',
  description: 'Use --no-install-recommends with apt-get install to avoid unnecessary packages.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (/(?:apt-get|apt)\s+install/.test(inst.arguments) && !inst.arguments.includes('--no-install-recommends')) {
          violations.push({ rule: 'DV2004', severity: 'info', message: 'Consider using --no-install-recommends with apt-get install to minimize image size.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV2005: MAINTAINER is deprecated
export const DV2005: Rule = {
  id: 'DV2005', severity: 'warning',
  description: 'MAINTAINER is deprecated. Use LABEL maintainer="..." instead.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'MAINTAINER') {
          violations.push({ rule: 'DV2005', severity: 'warning', message: 'MAINTAINER is deprecated. Use LABEL maintainer="name" instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV2006: Multiple ENTRYPOINT instructions
export const DV2006: Rule = {
  id: 'DV2006', severity: 'warning',
  description: 'Multiple ENTRYPOINT instructions found. Only the last one takes effect.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const eps = stage.instructions.filter(i => i.type === 'ENTRYPOINT');
      if (eps.length > 1) {
        for (const ep of eps.slice(0, -1)) {
          violations.push({ rule: 'DV2006', severity: 'warning', message: 'Multiple ENTRYPOINT instructions found. Only the last one takes effect.', line: ep.line });
        }
      }
    }
    return violations;
  },
};

// DV2007: Multiple CMD instructions
export const DV2007: Rule = {
  id: 'DV2007', severity: 'warning',
  description: 'Multiple CMD instructions found. Only the last one takes effect.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const cmds = stage.instructions.filter(i => i.type === 'CMD');
      if (cmds.length > 1) {
        for (const cmd of cmds.slice(0, -1)) {
          violations.push({ rule: 'DV2007', severity: 'warning', message: 'Multiple CMD instructions found. Only the last one takes effect.', line: cmd.line });
        }
      }
    }
    return violations;
  },
};

// DV2008: apt-get update without apt-get install (whole Dockerfile scope)
export const DV2008: Rule = {
  id: 'DV2008', severity: 'warning',
  description: 'RUN apt-get update without a subsequent apt-get install in the same RUN.',
  check(ctx) {
    // DV2001 checks per-RUN; DV2008 also flags when update is in one RUN and install in another
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const runs = stage.instructions.filter(i => i.type === 'RUN');
      for (let i = 0; i < runs.length; i++) {
        const a = runs[i].arguments;
        if (/apt-get\s+update/.test(a) && !/(?:apt-get|apt)\s+install/.test(a)) {
          // Check if next RUN has install without update
          const next = runs[i + 1];
          if (next && /(?:apt-get|apt)\s+install/.test(next.arguments) && !/apt-get\s+update/.test(next.arguments)) {
            violations.push({ rule: 'DV2008', severity: 'warning', message: 'apt-get update and apt-get install should be in the same RUN instruction to prevent stale cache.', line: runs[i].line });
          }
        }
      }
    }
    return violations;
  },
};

// DV2009: Unsafe shell in SHELL instruction
export const DV2009: Rule = {
  id: 'DV2009', severity: 'warning',
  description: 'SHELL instruction uses a potentially unsafe shell.',
  check(ctx) {
    const violations: Violation[] = [];
    const safeShells = ['/bin/sh', '/bin/bash', '/bin/dash', '/bin/ash', '/usr/bin/bash', '/usr/bin/sh', 'cmd', 'powershell', 'pwsh'];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'SHELL') continue;
        const shellMatch = inst.arguments.match(/\[\s*"([^"]+)"/);
        if (shellMatch) {
          const shell = shellMatch[1];
          const base = shell.split('/').pop() || shell;
          if (!safeShells.includes(shell) && !safeShells.includes(base)) {
            violations.push({ rule: 'DV2009', severity: 'warning', message: `SHELL uses "${shell}" which may be unsafe. Use standard shells like /bin/bash or /bin/sh.`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV2010: apk upgrade in Dockerfile
export const DV2010: Rule = {
  id: 'DV2010', severity: 'warning',
  description: 'Avoid apk upgrade in Dockerfiles for reproducible builds.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && /\bapk\s+(--[a-z-]+\s+)*upgrade\b/.test(inst.arguments)) {
          violations.push({ rule: 'DV2010', severity: 'warning', message: 'Avoid apk upgrade in Dockerfiles. It makes builds non-reproducible. Pin specific package versions instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV2011: apk update is redundant when apk add --no-cache is used
export const DV2011: Rule = {
  id: 'DV2011', severity: 'info',
  description: 'apk update is redundant when apk add --no-cache is used in the same RUN instruction.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const cmd = inst.arguments;
        if (cmd.includes('apk update') && cmd.includes('apk add') && cmd.includes('--no-cache')) {
          violations.push({ rule: 'DV2011', severity: 'info', message: 'apk update is redundant when using apk add --no-cache. The --no-cache flag already fetches the latest index.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV2012: Silent error suppression with || true
export const DV2012: Rule = {
  id: 'DV2012', severity: 'info',
  description: 'RUN command uses || true to suppress errors, which can mask build failures.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const cmd = inst.arguments;
        // Match || true, || :, or || exit 0 at end of command/subshell
        if (/\|\|\s*(?:true|:|exit\s+0)\s*(?:$|;|\))/.test(cmd)) {
          violations.push({
            rule: 'DV2012', severity: 'info',
            message: 'RUN uses "|| true" to suppress errors. This can mask build failures. Consider handling errors explicitly or documenting why suppression is needed.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};
