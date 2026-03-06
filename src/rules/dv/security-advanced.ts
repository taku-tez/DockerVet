import { Rule, Violation } from '../types';
import { ArgInstruction, CopyInstruction, EnvInstruction, ExposeInstruction } from '../../parser/types';
import { isUrl } from '../utils';

// DV3001: AWS/GCP credential patterns in ENV/ARG/RUN
export const DV3001: Rule = {
  id: 'DV3001', severity: 'error',
  description: 'Possible cloud credential detected.',
  check(ctx) {
    const patterns = [
      /AKIA[0-9A-Z]{16}/,                  // AWS access key ID
      /projects\/[^/]+\/secrets\//,          // GCP Secret Manager path
      /AIza[0-9A-Za-z_-]{35}/,             // Google API key
      /ya29\.[0-9A-Za-z_-]{50,}/,           // Google OAuth2 access token
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
// Note: .pub files (public keys like id_rsa.pub) are explicitly excluded — copying a
// public key into authorized_keys is a legitimate pattern for test SSH servers.
export const DV3002: Rule = {
  id: 'DV3002', severity: 'error',
  description: 'Do not COPY/ADD SSH private keys into the image.',
  check(ctx) {
    // Match private key filenames but NOT .pub files (public keys are safe to copy)
    const sshPrivateKey = /(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?!\.pub\b)/i;
    // Also match .ssh/ directory copies (entire directory likely contains private keys/config)
    const sshDir = /\.ssh\//i;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => sshPrivateKey.test(s) || sshDir.test(s))) {
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
    const lastStageIndex = ctx.ast.stages.length - 1;
    for (const stage of ctx.ast.stages) {
      // Skip non-final stages — cert files in build stages are discarded
      if (stage.index !== lastStageIndex) continue;
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
    // Match private key indicators; plain .gpg/.pgp files are commonly public verification keyrings
    // Flag: secring, private-keys, secret*.gpg, *.sec.gpg
    // Skip: docker.gpg, hashicorp.gpg, nodesource.gpg etc. (public keyrings for package verification)
    const gpgPattern = /(?:secring|private-keys|secret[^/]*\.(?:gpg|pgp)|\.sec\.(?:gpg|pgp))/i;
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
// Note: This complements DL3004 (error) for sudo usage. Both may fire on the same line;
// DL3004 fires for all contexts, DV3011 is user-context-aware (only fires for root).
// Non-root USER context using sudo is considered a legitimate pattern (e.g., makepkg,
// gitpod devcontainers) — DL3004 already handles the error-level finding for those cases.
export const DV3011: Rule = {
  id: 'DV3011', severity: 'warning',
  description: 'Avoid using sudo in Dockerfiles. RUN instructions already execute as root.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      let currentUser = 'root';
      for (const inst of stage.instructions) {
        if (inst.type === 'USER') {
          currentUser = inst.arguments.trim().split(/[:\s]/)[0];
        }
        if (inst.type !== 'RUN') continue;
        // Match sudo but not "apt-get install sudo" or "apk add sudo"
        if (/(?:^|&&|\|\||;)\s*sudo\s/.test(inst.arguments) || /^\s*sudo\s/.test(inst.arguments)) {
          // If running as non-root user, sudo is legitimate (e.g., makepkg, devcontainer patterns)
          // DL3004 already fires as an error for these cases
          if (currentUser !== 'root' && currentUser !== '0') continue;
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
      // URI with embedded credentials: scheme://user:pass@host or scheme://user@host
      /(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^${\s]+@[^\s]+/i,
      // JDBC URL with embedded credentials (@ syntax) or password in query string.
      // Bare JDBC URLs like jdbc:postgresql://localhost:5432/db (no credentials) are NOT flagged.
      /jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb):\/\/[^${\s]*(?:@[^\s]+|[?&](?:password|passwd|pwd|secret)=[^&\s]+)/i,
      // ADO.NET / SQL Server connection string with password field
      /Server\s*=\s*[^;]+;\s*(?:Database|Initial Catalog)\s*=\s*[^;]+;\s*(?:User\s*Id|Uid)\s*=\s*[^;]+;\s*(?:Password|Pwd)\s*=\s*[^${\s;]+/i,
    ];

    // Return true if the userinfo component of a URI contains only obvious placeholder values.
    // Handles: scheme://user:pass@host and scheme://user@host patterns.
    // Only suppresses when BOTH user AND password are clearly placeholder tokens.
    // We intentionally do NOT treat "user"/"username"/"pass"/"password" as placeholders
    // because they're too generic and often used as real credentials in examples.
    // Strong placeholder indicators: the literal word "placeholder", angle/curly bracket vars,
    // or both fields being identical non-meaningful tokens.
    const STRONG_PLACEHOLDER = /^(?:placeholder|<[^>]+>|\{[^}]+\}|\[[^\]]+\])$/i;
    function hasPlaceholderCreds(match: string): boolean {
      // Extract userinfo from URI (everything between :// and @host)
      const uriUserinfo = /:[/]{2}([^@\s]+)@/.exec(match);
      if (uriUserinfo) {
        const userinfo = uriUserinfo[1];
        const colonIdx = userinfo.indexOf(':');
        const user = colonIdx >= 0 ? userinfo.slice(0, colonIdx) : userinfo;
        const pass = colonIdx >= 0 ? userinfo.slice(colonIdx + 1) : '';
        // Suppress only when BOTH credentials are strong placeholder tokens
        if (STRONG_PLACEHOLDER.test(user) && (pass === '' || STRONG_PLACEHOLDER.test(pass))) return true;
      }
      return false;
    }

    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (!['ENV', 'ARG', 'RUN', 'LABEL'].includes(inst.type)) continue;
        const text = inst.arguments || inst.raw;
        for (const pat of dbPatterns) {
          const m = pat.exec(text);
          if (m && !hasPlaceholderCreds(m[0])) {
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
// Note: DV1003 already fires as an error for the same curl|sh patterns (sh/bash/zsh/ksh/dash/source).
// DV3015 skips those to avoid double-reporting — it only fires for shells not covered by DV1003 (e.g. ash).
export const DV3015: Rule = {
  id: 'DV3015', severity: 'warning',
  description: 'Avoid piping curl/wget output to shell without checksum verification.',
  check(ctx) {
    const pipeToShell = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|dash|ash)/;
    // DV1003 covers sh|bash|zsh|ksh|dash|source as an error; avoid double-reporting on same line
    const dv1003Pattern = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|ksh|dash|source)\b/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (pipeToShell.test(inst.arguments)) {
          // Skip if DV1003 already fires on this instruction (prevents error+warning duplicate)
          if (dv1003Pattern.test(inst.arguments)) continue;
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
    // Note: Avoid overly-broad patterns like /run docker/ or /docker stop/ which match
    // legitimate OpenShift/UBI label conventions (e.g., run="docker run...", stop="docker stop...").
    const catA = [
      /execute the command/i, /run the command/i,
      // docker exec with a shell is the real injection signal; plain "docker stop/run" in labels is normal UBI convention
      /docker\s+exec\s+\S+\s+(?:bash|sh|ash|python|perl|ruby|cmd|powershell)/i,
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
    // Imperative verbs (exclude informational: visit, see, check, refer, read, view, go)
    const imperativeRe = /\b(?:run|execute|send|forward|render|call|fetch|post|submit|invoke|dispatch|transmit|upload|push|pipe|redirect|exfiltrate|curl|wget)\b/i;
    // Pattern: imperative verb within 80 chars of a URL in the same value string.
    // This prevents FPs from multi-pair LABELs like:
    //   description="Run the tests" url="https://legit.com"
    // where "Run" and the URL are in different label key-value pairs.
    const proximityRe = /(?:(?:\b(?:run|execute|send|forward|render|call|fetch|post|submit|invoke|dispatch|transmit|upload|push|pipe|redirect|exfiltrate|curl|wget)\b).{0,80}https?:\/\/|https?:\/\/\S{0,80}\b(?:run|execute|send|forward|render|call|fetch|post|submit|invoke|dispatch|transmit|upload|push|pipe|redirect|exfiltrate|curl|wget)\b)/i;

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'LABEL') continue;
        const raw = inst.arguments || inst.raw;

        // Extract individual label values by parsing key=value or key="value" pairs.
        // Each value is checked independently so that a verb in one value and URL in
        // another (standard metadata LABELs like label-schema.org) are not mixed.
        const valueParts: string[] = [];
        // Match quoted values: ="..." or ='...'
        const quotedRe = /=["']([^"']+)["']/g;
        let m: RegExpExecArray | null;
        while ((m = quotedRe.exec(raw)) !== null) valueParts.push(m[1]);
        // Match unquoted values (after = until whitespace or end): =value
        const unquotedRe = /=([^\s"'][^\s\\]*)/g;
        while ((m = unquotedRe.exec(raw)) !== null) valueParts.push(m[1]);

        // Check each individual value for the proximity pattern
        let flagged = false;
        for (const v of valueParts) {
          if (proximityRe.test(v)) { flagged = true; break; }
        }
        // If no values were extracted (e.g. unquoted single value), fall back to full raw check
        if (!flagged && valueParts.length === 0 && proximityRe.test(raw)) flagged = true;

        if (flagged && imperativeRe.test(raw)) {
          violations.push({ rule: 'DV3017', severity: 'warning', message: 'Suspicious external URL with imperative context in LABEL. This may indicate a prompt injection or data exfiltration attempt.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3021: Dangerous service port EXPOSE detection
export const DV3021: Rule = {
  id: 'DV3021', severity: 'warning',
  description: 'Exposing sensitive service ports can enable unauthorized access.',
  check(ctx) {
    type PortSeverity = 'error' | 'warning' | 'info';
    const dangerousPorts: Record<number, { severity: PortSeverity; name: string }> = {
      2375: { severity: 'error', name: 'Docker API (unencrypted)' },
      2376: { severity: 'error', name: 'Docker API (TLS)' },
      6379: { severity: 'warning', name: 'Redis' },
      27017: { severity: 'warning', name: 'MongoDB' },
      5432: { severity: 'warning', name: 'PostgreSQL' },
      3306: { severity: 'warning', name: 'MySQL/MariaDB' },
      11211: { severity: 'warning', name: 'Memcached' },
      9200: { severity: 'warning', name: 'Elasticsearch HTTP' },
      9300: { severity: 'warning', name: 'Elasticsearch Transport' },
      4444: { severity: 'warning', name: 'Selenium Grid Hub' },
      4445: { severity: 'warning', name: 'Selenium Grid' },
      4446: { severity: 'warning', name: 'Selenium Grid' },
      5000: { severity: 'info', name: 'Docker Registry / common web app port (Flask, etc.)' },
      // 8080 removed: too common as standard web app port (Java/Tomcat, Spring Boot, Node.js, etc.) to be meaningful
      8443: { severity: 'info', name: 'HTTPS alternate (admin UI)' },
    };

    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'EXPOSE') continue;
        const e = inst as ExposeInstruction;

        // Check parsed ports (handles single ports; NaN ports are variable references, skipped)
        for (const portEntry of e.ports) {
          if (isNaN(portEntry.port)) continue;
          const info = dangerousPorts[portEntry.port];
          if (info) {
            violations.push({ rule: 'DV3021', severity: info.severity, message: `EXPOSE ${portEntry.port} (${info.name}) may expose a sensitive service. Avoid publishing service ports directly.`, line: inst.line });
          }
        }

        // Also check port ranges in arguments (e.g., EXPOSE 6379-6380)
        const rangeMatch = inst.arguments.match(/(\d+)-(\d+)/);
        if (rangeMatch) {
          const start = parseInt(rangeMatch[1], 10);
          const end = parseInt(rangeMatch[2], 10);
          for (const [portStr, info] of Object.entries(dangerousPorts)) {
            const portNum = parseInt(portStr, 10);
            if (portNum >= start && portNum <= end) {
              // Avoid double-reporting if already caught by individual port check
              if (!e.ports.some(p => p.port === portNum)) {
                violations.push({ rule: 'DV3021', severity: info.severity, message: `Port range includes ${portNum} (${info.name}) which may expose a sensitive service.`, line: inst.line });
              }
            }
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

// DV3022: Sensitive operation without BuildKit secret mount
export const DV3022: Rule = {
  id: 'DV3022', severity: 'warning',
  description: 'Sensitive credential operation without BuildKit --mount=type=secret.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (/--mount=type=secret/.test(args)) continue;

        // 1. Authentication file generation (.netrc or /etc/apt/auth.conf)
        if ((/echo\b/.test(args) || /tee\b/.test(args) || />/.test(args)) &&
            (/\.netrc/.test(args) || /\/etc\/apt\/auth\.conf/.test(args))) {
          violations.push({ rule: 'DV3022', severity: 'warning', message: 'Generating authentication file in RUN. Use --mount=type=secret to avoid storing credentials in image layers.', line: inst.line });
          continue;
        }

        // 2. pip with authenticated --extra-index-url
        if (/pip3?\s+install.*--extra-index-url\s+https?:\/\/[^@\s]+@/.test(args)) {
          violations.push({ rule: 'DV3022', severity: 'warning', message: 'pip install with authenticated --extra-index-url. Use --mount=type=secret for credentials.', line: inst.line });
          continue;
        }

        // 3. npm with authenticated --registry
        if (/npm\s+install.*--registry\s+https?:\/\/[^@\s]+@/.test(args) ||
            /npm\s+config.*registry\s+https?:\/\/[^@\s]+@/.test(args)) {
          violations.push({ rule: 'DV3022', severity: 'warning', message: 'npm with authenticated --registry. Use --mount=type=secret for credentials.', line: inst.line });
          continue;
        }

        // 4. git clone with credentials in URL (when not caught by DV3008 at error level)
        if (/git\s+clone\s+https?:\/\/[^@\s]+:[^@\s]+@/.test(args)) {
          violations.push({ rule: 'DV3022', severity: 'warning', message: 'git clone with embedded credentials. Use --mount=type=secret or SSH keys instead.', line: inst.line });
          continue;
        }
      }
    }
    return violations;
  },
};

// DV3023: Shell variable expansion injection risk in RUN
export const DV3023: Rule = {
  id: 'DV3023', severity: 'warning',
  description: 'Unquoted ARG variable in shell execution context enables injection via --build-arg.',
  check(ctx) {
    const violations: Violation[] = [];

    for (const stage of ctx.ast.stages) {
      // Collect ARG names (injectable via --build-arg)
      const argNames = new Set<string>();
      for (const globalArg of ctx.ast.globalArgs) {
        if (globalArg.name) argNames.add(globalArg.name);
      }
      for (const inst of stage.instructions) {
        if (inst.type === 'ARG') {
          const ai = inst as ArgInstruction;
          if (ai.name) argNames.add(ai.name);
        }
      }

      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (/--mount=type=secret/.test(args)) continue;

        let flagged = false;
        for (const name of argNames) {
          // Pattern 1: unquoted ARG in eval/sh -c/bash -c context
          const evalRe = new RegExp(`(?:eval|sh\\s+-c|bash\\s+-c|sh\\s+-s)\\s+\\$(?:\\{${name}\\}|${name})(?!["\\'\\w])`);
          if (evalRe.test(args)) {
            violations.push({ rule: 'DV3023', severity: 'warning', message: `Unquoted ARG $${name} in shell execution context. This may allow command injection via --build-arg.`, line: inst.line });
            flagged = true;
            break;
          }

          // Pattern 2: unquoted ARG variable in wget/curl URL
          // Only flag if the variable appears in the URL argument position (not in --output/-o/-d/etc.)
          const urlRe = new RegExp(`(?:wget|curl)\\s+(?:[^"]*?)\\$(?:\\{${name}\\}|${name})(?!["\\'\\w])`);
          if (urlRe.test(args)) {
            // Check if ALL occurrences of this variable are in non-URL argument positions
            // (e.g., --output, -o, -O, --data, -d, --header, etc.)
            const nonUrlFlagRe = new RegExp(
              `(?:--output|--data|--header|--user|--form|--upload-file|--cookie|--cacert|--key|--cert|--capath|--proxy|--range|--referer|-[oOdHuFTb])(?:[= ]\\S*)?[= ]\\S*\\$(?:\\{${name}\\}|${name})`,
              'g'
            );
            const varRe = new RegExp(`\\$(?:\\{${name}\\}|${name})`, 'g');
            const allCount = (args.match(varRe) || []).length;
            const nonUrlCount = (args.match(nonUrlFlagRe) || []).length;
            if (allCount > nonUrlCount) {
              violations.push({ rule: 'DV3023', severity: 'warning', message: `Unquoted ARG $${name} in download URL. URL injection possible via --build-arg.`, line: inst.line });
              flagged = true;
              break;
            }
          }

          // Pattern 3: unquoted ARG in find -exec path
          const findRe = new RegExp(`find\\s+.*\\$(?:\\{${name}\\}|${name}).*-exec`);
          if (findRe.test(args)) {
            violations.push({ rule: 'DV3023', severity: 'warning', message: `Unquoted ARG $${name} in find -exec. Path traversal possible via --build-arg.`, line: inst.line });
            flagged = true;
            break;
          }
        }
        if (flagged) continue;
      }
    }
    return violations;
  },
};

// DV3024: Downloaded file executed without checksum verification
export const DV3024: Rule = {
  id: 'DV3024', severity: 'error',
  description: 'Downloaded file executed without checksum verification.',
  check(ctx) {
    const checksumPattern = /(?:sha256sum|sha512sum|sha384sum|md5sum|shasum|gpg\s+--verify|cosign\s+verify)/;
    // Patterns already covered by DV1003 (pipe to shell) — skip to avoid duplicate
    const dv1003Pattern = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|ksh|dash|source|ash)\b/;
    const violations: Violation[] = [];

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (checksumPattern.test(args)) continue;
        if (dv1003Pattern.test(args)) continue;

        // Pattern 1: download → chmod +x → execute chain
        if (/(?:curl|wget)\b/.test(args) && /chmod\s+\+x\b/.test(args) && /(?:\.\s*\/|\bexec\s+\.\/)/.test(args)) {
          violations.push({ rule: 'DV3024', severity: 'error', message: 'Downloaded file made executable and run without checksum verification. Verify file integrity before execution.', line: inst.line });
          continue;
        }

        // Pattern 2: download + extract tarball without verification
        if (/(?:curl|wget)\b[^;]*(?:&&|;)\s*tar\s/.test(args)) {
          violations.push({ rule: 'DV3024', severity: 'error', message: 'Tarball downloaded and extracted without checksum verification. Verify integrity before extraction.', line: inst.line });
          continue;
        }
      }
    }
    return violations;
  },
};

// DV3025: git credential configuration stores credentials in plaintext
export const DV3025: Rule = {
  id: 'DV3025', severity: 'error',
  description: 'git credential configuration stores credentials in plaintext in image layers.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;

        // credential.helper store (plaintext file storage)
        if (/git\s+config.*credential\.helper\s+store/.test(args)) {
          violations.push({ rule: 'DV3025', severity: 'error', message: 'git credential.helper store saves credentials as plaintext. Use --mount=type=secret instead.', line: inst.line });
          continue;
        }

        // Writing to ~/.git-credentials
        if (/(?:echo|printf|tee)\b.*(?:>>?)\s*~?\/?(root|home\/[^/]+)?\/\.git-credentials/.test(args) ||
            /~?\/\.git-credentials/.test(args) && /(?:echo|printf|tee|>)/.test(args)) {
          violations.push({ rule: 'DV3025', severity: 'error', message: 'Writing credentials to .git-credentials stores them in the image layer. Use --mount=type=secret instead.', line: inst.line });
          continue;
        }

        // git config with embedded token/password value
        if (/git\s+config\s+.*(?:password|token|pat|secret)\s+\S{8,}/.test(args)) {
          violations.push({ rule: 'DV3025', severity: 'error', message: 'git config with embedded credentials stores them in image layer history. Use --mount=type=secret instead.', line: inst.line });
          continue;
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

// DV3019: Downloaded script executed without checksum verification
export const DV3019: Rule = {
  id: 'DV3019', severity: 'info',
  description: 'Downloaded script executed without checksum verification.',
  check(ctx) {
    // Detect pattern: curl/wget downloading files and then executing or extracting
    // but NOT when sha256sum/md5sum/gpg verify is present in the same RUN
    const checksumPattern = /(?:sha256sum|sha512sum|md5sum|gpg\s+--verify|cosign\s+verify)/;
    // Pattern 1: download + execute (sh/bash/chmod/source)
    const downloadAndExec = /(?:curl|wget)\s+[^|]*?(?:-[^\s]*[oO]\s+\S+|--output\s+\S+|>\s*\S+).*?(?:&&|;)\s*(?:sh\s|bash\s|chmod\s+(?:\+x|[0-7]{3,4}|[a-z]+=[a-z]*x[a-z]*)[\s]|\.\/)(?!.*(?:sha256sum|sha512sum|md5sum|gpg\s+--verify))/;
    // Pattern 2: download + extract (tar/unzip/gunzip) without checksum
    const downloadAndExtract = /(?:curl|wget)\s+[^|]*?(?:-[^\s]*[oO]\s+\S+|--output\s+\S+|>\s*\S+).*?(?:&&|;)\s*(?:tar\s|unzip\s|gunzip\s)/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (checksumPattern.test(args)) continue;
        if (downloadAndExec.test(args) || downloadAndExtract.test(args)) {
          violations.push({ rule: 'DV3019', severity: 'info', message: 'Downloaded script executed without checksum verification. Consider adding sha256sum/gpg verification before execution.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3020: ADD with remote URL without checksum
export const DV3020: Rule = {
  id: 'DV3020', severity: 'warning',
  description: 'ADD with remote URL lacks integrity verification.',
  check(ctx) {
    const violations: Violation[] = [];
    const argDefaults = new Map<string, string>();
    for (const a of ctx.ast.globalArgs) argDefaults.set(a.name, a.defaultValue || '');
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ARG') {
          const ai = inst as import('../../parser/types').ArgInstruction;
          argDefaults.set(ai.name, ai.defaultValue || '');
        }
        if (inst.type === 'ADD') {
          const a = inst as CopyInstruction;
          const resolveVar = (s: string): string => {
            const m = s.match(/^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/);
            return m ? (argDefaults.get(m[1]) || s) : s;
          };
          const hasUrlSrc = a.sources.some(s => isUrl(s) || isUrl(resolveVar(s)));
          if (hasUrlSrc) {
            // Check if --checksum flag is used (Docker 24+ syntax)
            const raw = inst.raw || '';
            if (!/--checksum[= ]/i.test(raw)) {
              violations.push({
                rule: 'DV3020', severity: 'warning',
                message: 'ADD with remote URL lacks integrity verification. Use ADD --checksum=<digest> (Docker 24+) or download with curl/wget and verify checksum.',
                line: inst.line,
              });
            }
          }
        }
      }
    }
    return violations;
  },
};

// DV3026: chmod 777 or overly permissive file permissions
export const DV3026: Rule = {
  id: 'DV3026', severity: 'warning',
  description: 'Avoid overly permissive file permissions (chmod 777/666).',
  check(ctx) {
    const violations: Violation[] = [];
    // Match chmod with dangerous permission modes: 777, 776, 666, etc.
    // Also match o+w (other writable), a+w (all writable)
    const dangerousChmod = /chmod\s+(?:-[Rrf]+\s+)*(?:777|776|775|666|o\+w|a\+w)\b/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (dangerousChmod.test(inst.arguments)) {
          violations.push({ rule: 'DV3026', severity: 'warning', message: 'Overly permissive file permissions detected. Avoid chmod 777/666/o+w. Use the minimum required permissions.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3027: apt-get upgrade / apk upgrade / yum update in Dockerfile
export const DV3027: Rule = {
  id: 'DV3027', severity: 'warning',
  description: 'Avoid running dist-upgrade/upgrade in Dockerfiles. Update the base image instead.',
  check(ctx) {
    const violations: Violation[] = [];
    const upgradePatterns = /(?:apt-get|apt)\s+(?:dist-)?upgrade|apk\s+upgrade|yum\s+update\b(?!\s+--)|dnf\s+upgrade/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (upgradePatterns.test(inst.arguments)) {
          violations.push({ rule: 'DV3027', severity: 'warning', message: 'Avoid running upgrade/dist-upgrade in Dockerfiles. This creates non-reproducible builds. Update the base image tag instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV4017: PATH contains writable directory (PATH pollution attack)
export const DV4017: Rule = {
  id: 'DV4017', severity: 'warning',
  description: 'PATH contains a writable directory, enabling PATH pollution attacks.',
  check(ctx) {
    const dangerousPaths = ['/tmp', '/var/tmp', '/dev/shm'];
    const dangerousPatterns = [/^\/home\//, /^\/root\//];
    const violations: Violation[] = [];

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'ENV') continue;
        const env = inst as EnvInstruction;
        for (const pair of env.pairs) {
          if (pair.key !== 'PATH') continue;
          const pathValue = pair.value;
          // Skip pure variable references like PATH=$PATH:/usr/local/bin (these are fine)
          const paths = pathValue.split(':');
          for (const p of paths) {
            const trimmed = p.trim().replace(/["']/g, '');
            // Skip variable references in individual components
            if (trimmed.startsWith('$')) continue;
            if (trimmed === '') continue;
            if (dangerousPaths.some(dp => trimmed === dp || trimmed.startsWith(dp + '/'))) {
              violations.push({ rule: 'DV4017', severity: 'warning', message: `PATH contains writable directory "${trimmed}" which can enable PATH pollution attacks.`, line: inst.line });
              break;
            }
            if (dangerousPatterns.some(dp => dp.test(trimmed))) {
              violations.push({ rule: 'DV4017', severity: 'warning', message: `PATH contains potentially writable directory "${trimmed}" which can enable PATH pollution attacks.`, line: inst.line });
              break;
            }
          }
        }
      }
    }
    return violations;
  },
};

// DV3029: Cloud credential directory COPY/ADD (~/.aws, ~/.config/gcloud, ~/.azure, ~/.kube)
export const DV3029: Rule = {
  id: 'DV3029', severity: 'error',
  description: 'Do not COPY/ADD cloud credential directories into the image.',
  check(ctx) {
    const cloudCredDirs = /(?:\.aws|\.config\/gcloud|\.azure|\.kube)(?:\/|$)/i;
    const cloudCredFiles = /(?:\.aws\/credentials|\.aws\/config|\.boto|\.config\/gcloud\/credentials\.db|kubeconfig|\.kube\/config)$/i;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => cloudCredDirs.test(s) || cloudCredFiles.test(s))) {
          violations.push({ rule: 'DV3029', severity: 'error', message: 'Do not COPY/ADD cloud credential directories (~/.aws, ~/.kube, ~/.azure, ~/.config/gcloud). Use runtime credential injection (IAM roles, workload identity, mounted secrets).', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3030: Docker socket exposed via VOLUME
export const DV3030: Rule = {
  id: 'DV3030', severity: 'error',
  description: 'Avoid exposing the Docker socket via VOLUME.',
  check(ctx) {
    const dockerSocket = /\/var\/run\/docker\.sock/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'VOLUME' && dockerSocket.test(inst.arguments)) {
          violations.push({ rule: 'DV3030', severity: 'error', message: 'VOLUME /var/run/docker.sock exposes the Docker daemon socket, enabling full host compromise. Avoid mounting the Docker socket in images.', line: inst.line });
        }
        // Also check COPY/ADD of docker.sock
        if ((inst.type === 'COPY' || inst.type === 'ADD') && dockerSocket.test(inst.arguments)) {
          violations.push({ rule: 'DV3030', severity: 'error', message: 'COPY/ADD of Docker socket path detected. This enables container escape and full host compromise.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3028: useradd without --no-log-init (large sparse lastlog file risk)
export const DV3028: Rule = {
  id: 'DV3028', severity: 'info',
  description: 'useradd without --no-log-init can create a huge sparse lastlog file.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (/\buseradd\b/.test(args) && !/--no-log-init/.test(args)) {
          violations.push({ rule: 'DV3028', severity: 'info', message: 'useradd without --no-log-init can create a huge sparse lastlog file. Use `useradd --no-log-init` or `adduser` instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};
