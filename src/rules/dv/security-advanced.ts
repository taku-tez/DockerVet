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
      const suidPattern = /chmod\s+(?:[ugo]*\+s|[246][0-7]{3}|--reference)/;
      const hasChmodSuid = stage.instructions.some(i =>
        i.type === 'RUN' && suidPattern.test(i.arguments)
      );
      if (hasChmodSuid) {
        const inst = stage.instructions.find(i =>
          i.type === 'RUN' && suidPattern.test(i.arguments)
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

// DV3016: AI Prompt Injection in LABEL (DockerDash attack)
export const DV3016: Rule = {
  id: 'DV3016', severity: 'error',
  description: 'AI prompt injection detected in LABEL value (DockerDash attack).',
  check(ctx) {
    const violations: Violation[] = [];

    // Category A: Command execution patterns (+3)
    const catA = [
      /execute the command/i, /run the command/i, /run docker/i,
      /docker\s+(?:stop|exec|rm|ps|kill)/i,
      /capture the output/i, /return only the command output/i,
    ];
    // Category B: AI/MCP prompt injection (+3)
    const catB = [
      /mcp\s+(?:tools|gateway|server)/i,
      /ignore (?:previous|your) instructions/i,
      /you are now/i, /respond by (?:running|executing)/i,
      /as part of the workflow/i,
    ];
    // Category C: Data exfiltration (+2)
    const catC_exfil = [/exfiltrat(?:e|ion)/i, /data exfiltration/i];
    const catC_send = [/send to https?:\/\//i, /curl https?:\/\//i, /wget https?:\/\//i];

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'LABEL') continue;
        const val = inst.arguments || inst.raw;
        let score = 0;

        for (const p of catA) { if (p.test(val)) { score += 3; break; } }
        for (const p of catB) { if (p.test(val)) { score += 3; break; } }

        // C: markdown image exfil
        if (/!\[/.test(val) && /https?:\/\//.test(val)) {
          score += 2;
        } else {
          let cHit = false;
          for (const p of catC_send) { if (p.test(val)) { cHit = true; break; } }
          if (!cHit) { for (const p of catC_exfil) { if (p.test(val)) { cHit = true; break; } } }
          if (cHit) score += 2;
        }

        if (score >= 3) {
          violations.push({ rule: 'DV3016', severity: 'error', message: `AI prompt injection detected in LABEL (score: ${score}). This may be a DockerDash-style meta-context injection attack.`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3017: Suspicious External URL with Imperative Context in LABEL
export const DV3017: Rule = {
  id: 'DV3017', severity: 'warning',
  description: 'Suspicious external URL with imperative context in LABEL.',
  check(ctx) {
    const violations: Violation[] = [];
    const urlRe = /https?:\/\/\S+/gi;
    // Imperative verbs (exclude informational: visit, see, check, refer, read, view, go)
    const imperativeRe = /\b(?:run|execute|send|forward|render|call|fetch|post|submit|invoke|dispatch|transmit|upload|push|pipe|redirect|exfiltrate|curl|wget)\b/i;

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'LABEL') continue;
        const val = inst.arguments || inst.raw;
        if (!urlRe.test(val)) continue;
        urlRe.lastIndex = 0;

        // Skip if the value is essentially just a URL (key=url pattern)
        // Extract label values: handle key=value or key="value" pairs
        const stripped = val.replace(/https?:\/\/\S+/gi, '').replace(/['"]/g, '');
        if (!imperativeRe.test(stripped)) continue;

        violations.push({ rule: 'DV3017', severity: 'warning', message: 'Suspicious external URL with imperative context in LABEL. This may indicate a prompt injection or data exfiltration attempt.', line: inst.line });
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
    const warningPaths = ['/root', '/home'];
    const infoPaths = ['/tmp'];
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'VOLUME') continue;
        for (const p of warningPaths) {
          const re = new RegExp(`(?:^|[\\s,\\["])${p.replace('/', '\\/')}(?:[\\s,\\]"]|$)`);
          if (re.test(inst.arguments)) {
            violations.push({ rule: 'DV3010', severity: 'warning', message: `VOLUME on sensitive path "${p}" may expose sensitive data.`, line: inst.line });
          }
        }
        for (const p of infoPaths) {
          const re = new RegExp(`(?:^|[\\s,\\["])${p.replace('/', '\\/')}(?:[\\s,\\]"]|$)`);
          if (re.test(inst.arguments)) {
            violations.push({ rule: 'DV3010', severity: 'info', message: `VOLUME on "${p}" is common but may expose ephemeral data. Ensure no secrets are written there.`, line: inst.line });
          }
        }
      }
    }
    return violations;
  },
};

// DV3018: Plaintext password via chpasswd without -e
export const DV3018: Rule = {
  id: 'DV3018', severity: 'error',
  description: 'chpasswd used without -e flag may set plaintext passwords in build history.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        // Match chpasswd calls that don't have -e flag
        if (/chpasswd/.test(inst.arguments) && !/chpasswd\s+-e|chpasswd\s+--encrypted/.test(inst.arguments)) {
          violations.push({ rule: 'DV3018', severity: 'error', message: 'chpasswd without -e flag sets plaintext passwords, which are stored in image layers.', line: inst.line });
        }
      }
    }
    return violations;
  },
};
