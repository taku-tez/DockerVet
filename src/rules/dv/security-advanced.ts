import { Rule, Violation } from '../types';
import { CopyInstruction, ExposeInstruction } from '../../parser/types';

// DV3001: AWS/GCP credential patterns in ENV/ARG/RUN
export const DV3001: Rule = {
  id: 'DV3001', severity: 'error',
  description: 'Possible cloud credential detected.',
  check(ctx) {
    const patterns = [
      /AKIA[0-9A-Z]{16}/,
      /projects\/[^/]+\/secrets\//,
      /GOOG[\w]{10,}/,
      /AIza[0-9A-Za-z_-]{35}/,
    ];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (!['ENV', 'ARG', 'RUN', 'LABEL'].includes(inst.type)) continue;
        for (const pat of patterns) {
          if (pat.test(inst.arguments) || pat.test(inst.raw)) {
            violations.push({ rule: 'DV3001', severity: 'error', message: 'Possible cloud credential pattern detected. Use secrets management instead.', line: inst.line });
            break;
          }
        }
      }
    }
    return violations;
  },
};

// DV3002: SSH private key COPY/ADD
export const DV3002: Rule = {
  id: 'DV3002', severity: 'error',
  description: 'Do not COPY/ADD SSH private keys into the image.',
  check(ctx) {
    const sshKeys = /(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|\.ssh\/)/i;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => sshKeys.test(s))) {
          violations.push({ rule: 'DV3002', severity: 'error', message: 'Do not COPY/ADD SSH private keys. Use SSH mount or build secrets.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3003: .env file COPY/ADD
export const DV3003: Rule = {
  id: 'DV3003', severity: 'warning',
  description: 'Avoid copying .env files into the image.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => /(?:^|[/\\])\.env(?:\.|$)/i.test(s) || s === '.env')) {
          violations.push({ rule: 'DV3003', severity: 'warning', message: 'Avoid copying .env files into the image. Use runtime environment variables.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3004: Certificate/private key COPY
export const DV3004: Rule = {
  id: 'DV3004', severity: 'warning',
  description: 'Avoid copying certificates or private keys into the image.',
  check(ctx) {
    const certPatterns = /\.(pem|key|p12|pfx|jks|keystore)$/i;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => certPatterns.test(s))) {
          violations.push({ rule: 'DV3004', severity: 'warning', message: 'Avoid copying certificate/private key files into the image. Use secrets management.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3005: GPG private key COPY
export const DV3005: Rule = {
  id: 'DV3005', severity: 'error',
  description: 'Do not COPY/ADD GPG private keys.',
  check(ctx) {
    const gpgPattern = /(?:\.gpg|\.pgp|secring|private-keys)/i;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => gpgPattern.test(s))) {
          violations.push({ rule: 'DV3005', severity: 'error', message: 'Do not COPY/ADD GPG private keys. Use build secrets.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3006: Unauthenticated package install
export const DV3006: Rule = {
  id: 'DV3006', severity: 'error',
  description: 'Avoid unauthenticated package installation.',
  check(ctx) {
    const unsafeFlags = /--allow-unauthenticated|--force-yes|--no-gpg-check|--nogpgcheck/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN' && unsafeFlags.test(inst.arguments)) {
          violations.push({ rule: 'DV3006', severity: 'error', message: 'Avoid unauthenticated package installation flags. Verify package authenticity.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3007: TLS verification disabled
export const DV3007: Rule = {
  id: 'DV3007', severity: 'warning',
  description: 'Avoid disabling TLS certificate verification.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (/wget\s+.*--no-check-certificate/.test(inst.arguments) || /curl\s+.*\s-k[\s$]/.test(inst.arguments) || /curl\s+.*--insecure/.test(inst.arguments)) {
          violations.push({ rule: 'DV3007', severity: 'warning', message: 'Avoid disabling TLS certificate verification (--no-check-certificate / -k / --insecure).', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3008: git clone with credentials in URL
export const DV3008: Rule = {
  id: 'DV3008', severity: 'warning',
  description: 'Avoid git clone in RUN instructions, especially with embedded credentials.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (/git\s+clone\s+https?:\/\/[^@]+@/.test(inst.arguments)) {
          violations.push({ rule: 'DV3008', severity: 'warning', message: 'git clone with embedded credentials detected. Use SSH keys or build secrets instead.', line: inst.line });
        } else if (/git\s+clone/.test(inst.arguments)) {
          violations.push({ rule: 'DV3008', severity: 'info', message: 'git clone in RUN may embed credentials in the image layer. Consider alternatives.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3009: EXPOSE 22 (SSH)
export const DV3009: Rule = {
  id: 'DV3009', severity: 'warning',
  description: 'Exposing SSH port 22 is usually unnecessary in containers.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'EXPOSE') continue;
        const e = inst as ExposeInstruction;
        if (e.ports.some(p => p.port === 22)) {
          violations.push({ rule: 'DV3009', severity: 'warning', message: 'EXPOSE 22 (SSH) is usually unnecessary in containers. Use docker exec instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3011: sudo usage in RUN
export const DV3011: Rule = {
  id: 'DV3011', severity: 'warning',
  description: 'Avoid using sudo in Dockerfiles. RUN instructions already execute as root.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        // Match sudo but not "apt-get install sudo" or "apk add sudo"
        if (/(?:^|&&|\|\||;)\s*sudo\s/.test(inst.arguments) || /^\s*sudo\s/.test(inst.arguments)) {
          violations.push({ rule: 'DV3011', severity: 'warning', message: 'Avoid using sudo in Dockerfiles. RUN instructions run as root by default. sudo adds unnecessary attack surface.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3012: Hardcoded tokens/passwords in RUN
export const DV3012: Rule = {
  id: 'DV3012', severity: 'error',
  description: 'Possible hardcoded token or password detected in RUN instruction.',
  check(ctx) {
    const patterns = [
      /npm\s+.*(?:_authToken|\/\/[^/]+\/:_auth)\s*=\s*\S+/,        // npm token
      /pip\s+install\s+.*--extra-index-url\s+https?:\/\/[^@]+@/,    // pip with credentials
      /(?:BUNDLE_|GEM_)(?:GITHUB__COM|RUBYGEMS__PKG__GITHUB__COM)\s*=\s*\S+/, // bundler credentials
      /\bnuget\s+.*-k(?:ey)?\s+[A-Za-z0-9]{20,}/,                  // NuGet API key
      /composer\s+config\s+.*(?:http-basic|bearer)\s+\S+\s+\S+/,    // Composer auth
      /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/,                // GitHub token
      /\bglpat-[A-Za-z0-9_-]{20,}/,                                  // GitLab PAT
      /\bnpm_[A-Za-z0-9]{36}/,                                       // npm automation token
      /\bpypi-[A-Za-z0-9_-]{50,}/,                                   // PyPI API token
    ];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        for (const pat of patterns) {
          if (pat.test(inst.arguments)) {
            violations.push({ rule: 'DV3012', severity: 'error', message: 'Possible hardcoded token or password in RUN instruction. Use --mount=type=secret or build args.', line: inst.line });
            break;
          }
        }
      }
    }
    return violations;
  },
};

// DV3013: setuid/setgid binaries not stripped
export const DV3013: Rule = {
  id: 'DV3013', severity: 'info',
  description: 'Consider stripping setuid/setgid bits to reduce privilege escalation risk.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      // Only check final stage
      if (stage !== ctx.ast.stages[ctx.ast.stages.length - 1]) continue;
      const hasChmodSuid = stage.instructions.some(i =>
        i.type === 'RUN' && /chmod\s+[ugo]*\+s/.test(i.arguments)
      );
      if (hasChmodSuid) {
        const inst = stage.instructions.find(i =>
          i.type === 'RUN' && /chmod\s+[ugo]*\+s/.test(i.arguments)
        )!;
        violations.push({ rule: 'DV3013', severity: 'info', message: 'Setting setuid/setgid bit detected. This can enable privilege escalation. Consider if this is necessary.', line: inst.line });
      }
    }
    return violations;
  },
};

// DV3014: Hardcoded database connection strings
export const DV3014: Rule = {
  id: 'DV3014', severity: 'error',
  description: 'Hardcoded database connection string detected.',
  check(ctx) {
    const dbPatterns = [
      /(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^${\s]+@[^\s]+/i,
      /jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb):\/\/[^\s]+/i,
      /Server\s*=\s*[^;]+;\s*(?:Database|Initial Catalog)\s*=\s*[^;]+;\s*(?:User\s*Id|Uid)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^${\s;]+/i,
    ];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (!['ENV', 'ARG', 'RUN', 'LABEL'].includes(inst.type)) continue;
        const text = inst.arguments || inst.raw;
        for (const pat of dbPatterns) {
          if (pat.test(text)) {
            violations.push({ rule: 'DV3014', severity: 'error', message: 'Hardcoded database connection string detected. Use runtime environment variables or secrets.', line: inst.line });
            break;
          }
        }
      }
    }
    return violations;
  },
};

// DV3015: Downloading scripts and piping to shell without checksum verification
export const DV3015: Rule = {
  id: 'DV3015', severity: 'warning',
  description: 'Avoid piping curl/wget output to shell without checksum verification.',
  check(ctx) {
    const pipeToShell = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|dash|ash)/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (pipeToShell.test(inst.arguments)) {
          if (!/sha256sum|sha512sum|shasum|gpg\s+--verify|md5sum/.test(inst.arguments)) {
            violations.push({ rule: 'DV3015', severity: 'warning', message: 'Piping curl/wget to shell without checksum verification. Download first, verify, then execute.', line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV3010: VOLUME with sensitive paths
export const DV3010: Rule = {
  id: 'DV3010', severity: 'warning',
  description: 'Avoid VOLUME on sensitive paths like /root, /home, /tmp.',
  check(ctx) {
    const sensitivePaths = ['/root', '/home', '/tmp'];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'VOLUME') continue;
        for (const p of sensitivePaths) {
          const re = new RegExp(`(?:^|[\\s,\\["])${p.replace('/', '\\/')}(?:[\\s,\\]"]|$)`);
          if (re.test(inst.arguments)) {
            violations.push({ rule: 'DV3010', severity: 'warning', message: `VOLUME on sensitive path "${p}" may expose sensitive data.`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};
