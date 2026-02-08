// Shared helpers for package manager rules
import { Rule, Violation } from '../types';

function runCheck(ctx: any, regex: RegExp, ruleId: string, severity: any, msg: string): Violation[] {
  const violations: Violation[] = [];
  for (const stage of ctx.ast.stages) {
    for (const inst of stage.instructions) {
      if (inst.type === 'RUN' && regex.test(inst.arguments)) {
        violations.push({ rule: ruleId, severity, message: msg, line: inst.line });
      }
    }
  }
  return violations;
}

function runCheckNeg(ctx: any, triggerRegex: RegExp, mustHaveRegex: RegExp, ruleId: string, severity: any, msg: string): Violation[] {
  const violations: Violation[] = [];
  for (const stage of ctx.ast.stages) {
    for (const inst of stage.instructions) {
      if (inst.type === 'RUN' && triggerRegex.test(inst.arguments) && !mustHaveRegex.test(inst.arguments)) {
        violations.push({ rule: ruleId, severity, message: msg, line: inst.line });
      }
    }
  }
  return violations;
}

// DL3008: Pin versions in apt-get install
export const DL3008: Rule = {
  id: 'DL3008', severity: 'warning',
  description: 'Pin versions in apt-get install',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/apt-get\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].replace(/-y|--yes|--no-install-recommends|--quiet|-q/g, '').trim().split(/\s+/).filter(p => p && !p.startsWith('-'));
        for (const pkg of pkgs) {
          if (!pkg.includes('=') && !pkg.startsWith('$')) {
            violations.push({ rule: 'DL3008', severity: 'warning', message: `Pin versions in apt-get install. Instead of \`apt-get install ${pkg}\` use \`apt-get install ${pkg}=<version>\``, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3009: Delete apt-get lists
export const DL3009: Rule = {
  id: 'DL3009', severity: 'info',
  description: 'Delete the apt-get lists after installing something',
  check(ctx) {
    return runCheckNeg(ctx, /apt-get\s+install/, /rm\s+(-rf?\s+)?\/var\/lib\/apt\/lists/, 'DL3009', 'info', 'Delete the apt-get lists after installing something');
  },
};

// DL3013: Pin versions in pip install
export const DL3013: Rule = {
  id: 'DL3013', severity: 'warning',
  description: 'Pin versions in pip install',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/pip3?\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].split(/\s+/).filter(p => p && !p.startsWith('-') && !p.startsWith('--'));
        for (const pkg of pkgs) {
          if (!pkg.includes('==') && !pkg.includes('>=') && !pkg.includes('.txt') && !pkg.includes('.whl') && !pkg.includes('/') && !pkg.startsWith('.') && !pkg.startsWith('$')) {
            violations.push({ rule: 'DL3013', severity: 'warning', message: `Pin versions in pip. Instead of \`pip install ${pkg}\` use \`pip install ${pkg}==<version>\``, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3014: Use -y switch with apt-get
export const DL3014: Rule = {
  id: 'DL3014', severity: 'warning',
  description: 'Use the -y switch to avoid manual input `apt-get -y install <package>`',
  check(ctx) { return runCheckNeg(ctx, /apt-get\s+install/, /(-y|--yes|--assume-yes)/, 'DL3014', 'warning', 'Use the -y switch to avoid manual input `apt-get -y install <package>`'); },
};

// DL3015: Avoid additional packages with apt-get
export const DL3015: Rule = {
  id: 'DL3015', severity: 'info',
  description: 'Avoid additional packages by specifying --no-install-recommends',
  check(ctx) { return runCheckNeg(ctx, /apt-get\s+install/, /--no-install-recommends/, 'DL3015', 'info', 'Avoid additional packages by specifying --no-install-recommends'); },
};

// DL3016: Pin versions in npm install
export const DL3016: Rule = {
  id: 'DL3016', severity: 'warning',
  description: 'Pin versions in npm',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/npm\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].split(/\s+/).filter(p => p && !p.startsWith('-'));
        for (const pkg of pkgs) {
          if (!pkg.includes('@') && !pkg.startsWith('.') && !pkg.startsWith('/') && !pkg.startsWith('$')) {
            violations.push({ rule: 'DL3016', severity: 'warning', message: `Pin versions in npm. Instead of \`npm install ${pkg}\` use \`npm install ${pkg}@<version>\``, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3018: Pin versions in apk add
export const DL3018: Rule = {
  id: 'DL3018', severity: 'warning',
  description: 'Pin versions in apk add',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/apk\s+(?:--[^\s]+\s+)*add\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].split(/\s+/).filter(p => p && !p.startsWith('-') && !p.startsWith('$'));
        for (const pkg of pkgs) {
          if (!pkg.includes('=')) {
            violations.push({ rule: 'DL3018', severity: 'warning', message: `Pin versions in apk add. Instead of \`apk add ${pkg}\` use \`apk add ${pkg}=<version>\``, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3019: Use --no-cache switch with apk
export const DL3019: Rule = {
  id: 'DL3019', severity: 'info',
  description: 'Use the --no-cache switch to avoid the need to use --update and remove /var/cache/apk/*',
  check(ctx) { return runCheckNeg(ctx, /apk\s+(?:--[^\s]+\s+)*add/, /--no-cache/, 'DL3019', 'info', 'Use the --no-cache switch to avoid the need to use --update and remove /var/cache/apk/*'); },
};

// DL3027: Do not use apt as it is meant to be an end-user tool
export const DL3027: Rule = {
  id: 'DL3027', severity: 'warning',
  description: 'Do not use apt as it is meant to be an end-user tool, use apt-get or apt-cache instead',
  check(ctx) { return runCheck(ctx, /(?:^|[;&|]\s*)\bapt\s+(install|update|upgrade|remove|purge)/, 'DL3027', 'warning', 'Do not use apt as it is meant to be an end-user tool, use apt-get or apt-cache instead'); },
};

// DL3028: Pin versions in gem install
export const DL3028: Rule = {
  id: 'DL3028', severity: 'warning',
  description: 'Pin versions in gem install',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/gem\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const parts = m[1].split(/\s+/).filter(p => p && !p.startsWith('-'));
        for (let i = 0; i < parts.length; i++) {
          const pkg = parts[i];
          const nextIsVersion = parts[i + 1] === '-v' || parts[i + 1] === '--version';
          if (!nextIsVersion && !pkg.startsWith('$') && !pkg.includes(':')) {
            violations.push({ rule: 'DL3028', severity: 'warning', message: `Pin versions in gem install. Instead of \`gem install ${pkg}\` use \`gem install ${pkg}:<version>\``, line: inst.line });
          }
          if (nextIsVersion) i += 2;
        }
      }
    }
    return violations;
  },
};

// DL3030: Use -y switch with yum
export const DL3030: Rule = {
  id: 'DL3030', severity: 'warning',
  description: 'Use the -y switch to avoid manual input `yum install -y <package>`',
  check(ctx) { return runCheckNeg(ctx, /yum\s+install/, /-y|--assumeyes/, 'DL3030', 'warning', 'Use the -y switch to avoid manual input `yum install -y <package>`'); },
};

// DL3032: yum clean all
export const DL3032: Rule = {
  id: 'DL3032', severity: 'warning',
  description: 'yum clean all missing after yum command',
  check(ctx) { return runCheckNeg(ctx, /yum\s+(install|update)/, /yum\s+clean\s+all/, 'DL3032', 'warning', 'yum clean all missing after yum command'); },
};

// DL3033: Pin versions in yum install
export const DL3033: Rule = {
  id: 'DL3033', severity: 'warning',
  description: 'Specify version with yum install -y <package>-<version>',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/yum\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].split(/\s+/).filter(p => p && !p.startsWith('-') && !p.startsWith('$'));
        for (const pkg of pkgs) {
          if (!pkg.includes('-') || pkg.split('-').every(p => !/^\d/.test(p))) {
            violations.push({ rule: 'DL3033', severity: 'warning', message: `Specify version with yum install -y ${pkg}-<version>`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3034-DL3037: zypper rules
export const DL3034: Rule = {
  id: 'DL3034', severity: 'warning',
  description: 'Non-interactive switch missing from zypper command: zypper install -y',
  check(ctx) { return runCheckNeg(ctx, /zypper\s+install/, /-y|--non-interactive/, 'DL3034', 'warning', 'Non-interactive switch missing from zypper command: zypper install -y'); },
};

export const DL3035: Rule = {
  id: 'DL3035', severity: 'warning',
  description: 'Do not use zypper dist-upgrade',
  check(ctx) { return runCheck(ctx, /zypper\s+dist-upgrade/, 'DL3035', 'warning', 'Do not use zypper dist-upgrade'); },
};

export const DL3036: Rule = {
  id: 'DL3036', severity: 'warning',
  description: 'zypper clean missing after zypper use',
  check(ctx) { return runCheckNeg(ctx, /zypper\s+(install|update)/, /zypper\s+clean/, 'DL3036', 'warning', 'zypper clean missing after zypper use'); },
};

export const DL3037: Rule = {
  id: 'DL3037', severity: 'warning',
  description: 'Specify version with zypper install -y <package>=<version>',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/zypper\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].split(/\s+/).filter(p => p && !p.startsWith('-') && !p.startsWith('$'));
        for (const pkg of pkgs) {
          if (!pkg.includes('=') && !pkg.includes('>')) {
            violations.push({ rule: 'DL3037', severity: 'warning', message: `Specify version with zypper install -y ${pkg}=<version>`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3038-DL3041: dnf rules
export const DL3038: Rule = {
  id: 'DL3038', severity: 'warning',
  description: 'Use the -y switch to avoid manual input `dnf install -y <package>`',
  check(ctx) { return runCheckNeg(ctx, /dnf\s+install/, /-y|--assumeyes/, 'DL3038', 'warning', 'Use the -y switch to avoid manual input `dnf install -y <package>`'); },
};

export const DL3040: Rule = {
  id: 'DL3040', severity: 'warning',
  description: 'dnf clean all missing after dnf command',
  check(ctx) { return runCheckNeg(ctx, /dnf\s+(install|update)/, /dnf\s+clean\s+all/, 'DL3040', 'warning', 'dnf clean all missing after dnf command'); },
};

export const DL3041: Rule = {
  id: 'DL3041', severity: 'warning',
  description: 'Specify version with dnf install -y <package>-<version>',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const m = inst.arguments.match(/dnf\s+install\s+(.+?)(?:[;&|]|$)/s);
        if (!m) continue;
        const pkgs = m[1].split(/\s+/).filter(p => p && !p.startsWith('-') && !p.startsWith('$'));
        for (const pkg of pkgs) {
          if (!pkg.includes('-') || pkg.split('-').every(p => !/^\d/.test(p))) {
            violations.push({ rule: 'DL3041', severity: 'warning', message: `Specify version with dnf install -y ${pkg}-<version>`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DL3042: pip --no-cache-dir
export const DL3042: Rule = {
  id: 'DL3042', severity: 'warning',
  description: 'Avoid use of cache directory with pip. Use `pip install --no-cache-dir <package>`',
  check(ctx) { return runCheckNeg(ctx, /pip3?\s+install/, /--no-cache-dir/, 'DL3042', 'warning', 'Avoid use of cache directory with pip. Use `pip install --no-cache-dir <package>`'); },
};
