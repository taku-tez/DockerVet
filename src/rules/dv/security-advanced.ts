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
    // Public GPG keys (e.g., .gpg.key, gpgkey/) are not private keys
    const publicKeyExclusion = /\.gpg\.key$|gpg(?:key)?/i;
    const violations: Violation[] = [];
    const lastStageIndex = ctx.ast.stages.length - 1;
    for (const stage of ctx.ast.stages) {
      // Skip non-final stages — cert files in build stages are discarded
      if (stage.index !== lastStageIndex) continue;
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const c = inst as CopyInstruction;
        if (c.sources.some(s => certPatterns.test(s) && !publicKeyExclusion.test(s))) {
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
// TLS-disabling environment variable patterns (checked in ENV instructions by DV3007)
const TLS_DISABLE_ENV_PATTERNS: Array<{ key: RegExp; value: RegExp; description: string }> = [
  { key: /^NODE_TLS_REJECT_UNAUTHORIZED$/i, value: /^0$/, description: 'NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate verification for all Node.js HTTPS requests.' },
  { key: /^PYTHONHTTPSVERIFY$/i, value: /^0$/, description: 'PYTHONHTTPSVERIFY=0 disables TLS certificate verification for Python urllib/requests.' },
  { key: /^GIT_SSL_NO_VERIFY$/i, value: /^(true|1)$/i, description: 'GIT_SSL_NO_VERIFY disables TLS certificate verification for all Git operations.' },
  { key: /^CURL_CA_BUNDLE$/i, value: /^$/, description: 'CURL_CA_BUNDLE="" disables curl certificate verification by clearing the CA bundle path.' },
  { key: /^SSL_CERT_FILE$/i, value: /^\/dev\/null$/i, description: 'SSL_CERT_FILE=/dev/null disables TLS certificate verification by pointing to an empty CA file.' },
  { key: /^REQUESTS_CA_BUNDLE$/i, value: /^(\/dev\/null|)$/i, description: 'REQUESTS_CA_BUNDLE set to /dev/null or empty disables TLS certificate verification for Python requests library.' },
  { key: /^GONOSUMCHECK$/i, value: /./,  description: 'GONOSUMCHECK disables Go module checksum verification, allowing tampered dependencies.' },
  { key: /^GOFLAGS$/i, value: /-insecure/, description: 'GOFLAGS=-insecure disables TLS verification for Go module downloads.' },
];

export const DV3007: Rule = {
  id: 'DV3007', severity: 'warning',
  description: 'Avoid disabling TLS certificate verification.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'RUN') {
          const args = inst.arguments;
          // curl/wget TLS bypass
          if (/wget\s+.*--no-check-certificate/.test(args) || /curl\s+.*\s-k[\s$]/.test(args) || /curl\s+.*--insecure/.test(args)) {
            violations.push({ rule: 'DV3007', severity: 'warning', message: 'Avoid disabling TLS certificate verification (--no-check-certificate / -k / --insecure).', line: inst.line });
          }
          // pip --trusted-host bypasses TLS verification for package downloads
          if (/pip3?\s+install\s+.*--trusted-host/.test(args)) {
            violations.push({ rule: 'DV3007', severity: 'warning', message: 'pip install --trusted-host bypasses TLS certificate verification for package downloads. Use a properly configured package index with valid TLS.', line: inst.line });
          }
          // git config http.sslVerify false
          if (/git\s+config\s+.*http\.sslVerify\s+false/i.test(args)) {
            violations.push({ rule: 'DV3007', severity: 'warning', message: 'git config http.sslVerify false disables TLS verification for Git operations, enabling man-in-the-middle attacks.', line: inst.line });
          }
          // npm config set strict-ssl false
          if (/npm\s+config\s+set\s+strict-ssl\s+false/i.test(args)) {
            violations.push({ rule: 'DV3007', severity: 'warning', message: 'npm config set strict-ssl false disables TLS certificate verification for npm registry connections.', line: inst.line });
          }
        }
        // ENV-based TLS disabling patterns
        if (inst.type === 'ENV') {
          const env = inst as EnvInstruction;
          for (const pair of env.pairs) {
            for (const tlsPattern of TLS_DISABLE_ENV_PATTERNS) {
              if (tlsPattern.key.test(pair.key) && tlsPattern.value.test(pair.value)) {
                violations.push({ rule: 'DV3007', severity: 'warning', message: tlsPattern.description, line: inst.line });
              }
            }
          }
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
      /\bhvs\.[A-Za-z0-9_-]{24,}/,                                    // HashiCorp Vault service token
      /\bhvb\.[A-Za-z0-9_-]{24,}/,                                    // HashiCorp Vault batch token
      /\bdckr_pat_[A-Za-z0-9_-]{20,}/,                                // Docker Hub PAT
      /\bAIza[0-9A-Za-z_-]{35}\b/,                                    // Google API key
      /\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/,               // OpenAI API key
      /\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{40,}/,                     // OpenAI project/service key
      /\bsk-ant-(?:api\d{2}|admin\d{2}|key\d{2})-[A-Za-z0-9_-]{20,}/, // Anthropic API key
      /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/,                // Stripe API key
      /\bxox[bpas]-[0-9]+-[A-Za-z0-9-]+/,                             // Slack bot/user/app token
      /\bhooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, // Slack webhook URL
      /\bvcel_[A-Za-z0-9_-]{20,}/,                                    // Vercel token
      /\batlasv1-[A-Za-z0-9_-]{20,}/,                                 // Terraform Cloud token
      /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}/,                // SendGrid API key
      /\bSK[0-9a-f]{32}/,                                              // Twilio API key
      /\bdapi[0-9a-f]{32,}/,                                           // Databricks PAT
      /\bAKCp[A-Za-z0-9]{10,}/,                                       // JFrog Artifactory token
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
    const pipeToShell = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|dash|ash|python3?|perl|ruby|node)/;
    // DV1003 covers sh|bash|zsh|ksh|dash|source|python3?|perl|ruby|node as an error; avoid double-reporting on same line
    const dv1003Pattern = /(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash|zsh|ksh|dash|source|python3?|perl|ruby|node)\b/;
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
          // Require curl/wget to be in command position (after &&, ||, ;, |, or start of line)
          // to avoid matching package names like "apk add curl"
          const urlRe = new RegExp(`(?:^|&&|\\|\\||;|\\|)\\s*(?:wget|curl)\\s+(?:[^"]*?)\\$(?:\\{${name}\\}|${name})(?!["\\'\\w])`);
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

// DV3031: Modifying /etc/sudoers or /etc/sudoers.d/ — privilege escalation risk
export const DV3031: Rule = {
  id: 'DV3031', severity: 'warning',
  description: 'Modifying sudoers grants privilege escalation paths in the container.',
  check(ctx) {
    const violations: Violation[] = [];
    const sudoersWrite = /(?:echo|printf|tee|cat|sed|>>?)\s*[^;|&]*\/etc\/sudoers(?:\.d\/)?/;
    const visudo = /\bvisudo\b/;
    const nopasswd = /NOPASSWD/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (sudoersWrite.test(args) || visudo.test(args)) {
          const hasNopasswd = nopasswd.test(args);
          const severity = hasNopasswd ? 'error' as const : 'warning' as const;
          violations.push({
            rule: 'DV3031', severity,
            message: hasNopasswd
              ? 'Modifying /etc/sudoers with NOPASSWD grants passwordless root access. This is a privilege escalation risk. Avoid sudo in containers; use USER instruction instead.'
              : 'Modifying /etc/sudoers grants privilege escalation paths. Prefer using the USER instruction to switch to a non-root user.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV3032: CMD/ENTRYPOINT running sshd — SSH daemon is a container anti-pattern
export const DV3032: Rule = {
  id: 'DV3032', severity: 'warning',
  description: 'Running SSH daemon in a container is an anti-pattern. Use docker exec instead.',
  check(ctx) {
    const violations: Violation[] = [];
    const sshdPattern = /\bsshd\b|\/usr\/sbin\/sshd/;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'CMD' && inst.type !== 'ENTRYPOINT') continue;
        if (sshdPattern.test(inst.arguments)) {
          violations.push({ rule: 'DV3032', severity: 'warning', message: 'Running sshd in a container is an anti-pattern. It increases attack surface and adds unnecessary complexity. Use `docker exec` or `kubectl exec` for debugging access.', line: inst.line });
        }
      }
    }
    // Also check RUN starting sshd as a daemon (service/systemctl patterns)
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (/(?:service\s+ssh(?:d)?\s+start|systemctl\s+(?:start|enable)\s+ssh(?:d)?)\b/.test(inst.arguments)) {
          violations.push({ rule: 'DV3032', severity: 'warning', message: 'Starting SSH service in RUN instruction. SSH daemons in containers increase attack surface. Use `docker exec` instead.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3033: HTTP (non-HTTPS) URLs in ADD or RUN download commands
// Downloading over plaintext HTTP is vulnerable to man-in-the-middle attacks and content tampering.
export const DV3033: Rule = {
  id: 'DV3033', severity: 'warning',
  description: 'Downloading over HTTP (non-HTTPS) is vulnerable to man-in-the-middle attacks.',
  check(ctx) {
    const violations: Violation[] = [];
    // Well-known localhost / internal-only URLs are acceptable over HTTP
    const localhostPattern = /^http:\/\/(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0|[a-z0-9.-]+\.svc\.cluster\.local)[\/:]/i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ADD') {
          const add = inst as CopyInstruction;
          for (const src of add.sources) {
            if (/^http:\/\//i.test(src) && !localhostPattern.test(src)) {
              violations.push({
                rule: 'DV3033', severity: 'warning',
                message: `ADD uses HTTP URL "${src}". Use HTTPS to prevent man-in-the-middle attacks and content tampering.`,
                line: inst.line,
              });
            }
          }
        }
        if (inst.type === 'RUN') {
          // Strip echo/printf string content to avoid flagging URLs in config output
          const argsStripped = inst.arguments
            .replace(/\b(?:echo|printf)\s+(?:-[enE]+\s+)*(?:'[^']*'|"[^"]*")/g, '')
            .replace(/\b(?:echo|printf)\s+(?:-[enE]+\s+)*[^|;&\n]*/g, '');
          // Detect curl/wget with http:// URLs
          const httpUrls = argsStripped.match(/\bhttps?:\/\/\S+/g);
          if (httpUrls) {
            for (const url of httpUrls) {
              if (/^http:\/\//i.test(url) && !localhostPattern.test(url)) {
                violations.push({
                  rule: 'DV3033', severity: 'warning',
                  message: `RUN downloads from HTTP URL "${url}". Use HTTPS to prevent man-in-the-middle attacks.`,
                  line: inst.line,
                });
                break; // one per instruction to avoid noise
              }
            }
          }
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

// DV3034: Unsafe package manager configurations that weaken supply chain security
export const DV3034: Rule = {
  id: 'DV3034', severity: 'warning',
  description: 'Avoid disabling package manager security checks (npm audit signatures, yarn integrity, etc.).',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        // npm config set ignore-scripts true (globally disables lifecycle scripts verification)
        // Note: --ignore-scripts on install is a SECURITY feature, but setting it globally via config is suspicious
        if (/npm\s+config\s+set\s+audit\s+false/i.test(args)) {
          violations.push({ rule: 'DV3034', severity: 'warning', message: 'npm config set audit false disables npm audit checks. Vulnerabilities in dependencies will not be reported.', line: inst.line });
        }
        // npm config set fund false is fine (just hides funding messages), skip it
        // npm install --force bypasses peer dependency checks and integrity verification
        if (/npm\s+install\s+.*--force\b/.test(args) && !/--force\s+.*--audit/.test(args)) {
          violations.push({ rule: 'DV3034', severity: 'warning', message: 'npm install --force bypasses peer dependency and integrity checks. Use --legacy-peer-deps for peer dep issues only.', line: inst.line });
        }
        // yarn install --no-verify (skip integrity verification)
        // Note: --skip-integrity-check is yarn v1, --no-immutable is yarn v2+
        if (/yarn\s+(?:install\s+)?.*--skip-integrity-check/.test(args)) {
          violations.push({ rule: 'DV3034', severity: 'warning', message: 'yarn --skip-integrity-check disables package integrity verification, allowing tampered packages.', line: inst.line });
        }
        // pip install --no-verify (not an actual pip flag but related: --no-deps --no-build-isolation)
        // pip install from HTTP (non-HTTPS) index
        if (/pip3?\s+install\s+.*--index-url\s+http:\/\//.test(args) || /pip3?\s+install\s+.*-i\s+http:\/\//.test(args)) {
          violations.push({ rule: 'DV3034', severity: 'warning', message: 'pip install with HTTP (non-HTTPS) index URL. Use HTTPS to prevent package tampering.', line: inst.line });
        }
        // gem install --no-verify (skip SSL verification)
        if (/gem\s+(?:install|sources)\s+.*--no-verify/.test(args) || /gem\s+sources\s+.*-a\s+http:\/\//.test(args)) {
          violations.push({ rule: 'DV3034', severity: 'warning', message: 'gem with --no-verify or HTTP source disables integrity/TLS verification for Ruby package downloads.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3035: JWT token hardcoded in RUN instruction
// JWT tokens (eyJhbG...) in RUN commands indicate hardcoded authentication tokens.
// These tokens may grant access to APIs/services and should never be baked into image layers.
export const DV3035: Rule = {
  id: 'DV3035', severity: 'error',
  description: 'Hardcoded JWT token detected in RUN instruction.',
  check(ctx) {
    // Match JWT: base64url-encoded header.payload.signature (3 dot-separated parts)
    // Header always starts with eyJ (base64 of '{"')
    const jwtPattern = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        if (jwtPattern.test(inst.arguments)) {
          violations.push({ rule: 'DV3035', severity: 'error', message: 'Hardcoded JWT token detected in RUN instruction. JWT tokens should be provided via --mount=type=secret or runtime environment variables.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3037: GPG key or signing key fetched over plain HTTP
// Fetching GPG keys over HTTP is a supply chain risk: an attacker performing MITM can inject
// a malicious key, allowing them to sign tampered packages that appear trusted.
export const DV3037: Rule = {
  id: 'DV3037', severity: 'warning',
  description: 'GPG key or signing key fetched over plain HTTP instead of HTTPS.',
  check(ctx) {
    const violations: Violation[] = [];
    // Patterns: curl/wget fetching a key over http:// and piping to apt-key/gpg/keyring
    const gpgFetchHttp = /(?:curl|wget)\s[^|;&&]*http:\/\/[^|;&&]*(?:\|\s*(?:apt-key\s+add|gpg\s+--dearmor|gpg\s+--import|tee\s+\S*\.gpg|tee\s+\S*keyring))/i;
    // Direct http:// URL in apt-key adv --keyserver
    const keyserverHttp = /apt-key\s+adv\s+[^|;&&]*--keyserver\s+http:\/\//i;
    // Fetching .asc/.gpg/.key files over http://
    const gpgFileHttp = /(?:curl|wget)\s[^|;&&]*http:\/\/\S+\.(?:asc|gpg|key|pub)\b/i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (gpgFetchHttp.test(args) || keyserverHttp.test(args) || gpgFileHttp.test(args)) {
          violations.push({
            rule: 'DV3037', severity: 'warning',
            message: 'GPG/signing key fetched over plain HTTP. Use HTTPS to prevent man-in-the-middle substitution of the key, which would allow an attacker to sign malicious packages.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV3038: Package repository configured with HTTP instead of HTTPS
// Adding APT/YUM/DNF repositories using http:// URLs makes the entire package download
// path vulnerable to MITM attacks, even if individual packages are signed.
export const DV3038: Rule = {
  id: 'DV3038', severity: 'warning',
  description: 'Package repository configured with plain HTTP instead of HTTPS.',
  check(ctx) {
    const violations: Violation[] = [];
    // Detect echo/tee writing to sources.list with http:// URLs
    const sourcesListHttp = /(?:echo|tee|cat)\s[^|;]*http:\/\/[^|;]*(?:sources\.list|\.list|\.repo)/i;
    // Detect add-apt-repository with http://
    const addAptRepoHttp = /\badd-apt-repository\b[^|;&&]*['"]?\s*(?:deb\s+)?http:\/\//i;
    // Detect yum-config-manager --add-repo with http://
    const yumRepoHttp = /\byum-config-manager\s+--add-repo\s+http:\/\//i;
    // Detect direct write to /etc/yum.repos.d/ with http:// baseurl
    const yumRepoFileHttp = /baseurl\s*=\s*http:\/\//i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (sourcesListHttp.test(args) || addAptRepoHttp.test(args) || yumRepoHttp.test(args) || yumRepoFileHttp.test(args)) {
          violations.push({
            rule: 'DV3038', severity: 'warning',
            message: 'Package repository uses plain HTTP. Use HTTPS to prevent man-in-the-middle attacks on package downloads. Even with signed packages, HTTP metadata can be manipulated.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV3036: Azure SAS token in URL
// Azure Shared Access Signatures contain sig= parameter with sensitive signing key material.
// These should use BuildKit secrets or runtime environment injection.
export const DV3036: Rule = {
  id: 'DV3036', severity: 'error',
  description: 'Azure SAS token detected in URL.',
  check(ctx) {
    // Match Azure blob/file/queue/table storage URLs with SAS token parameters (sig=)
    const sasPattern = /(?:blob|file|queue|table|dfs)\.core\.windows\.net\/[^"'\s]*[?&]sig=[A-Za-z0-9%+/=]+/;
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN' && inst.type !== 'ADD') continue;
        const text = inst.type === 'ADD' ? inst.raw : inst.arguments;
        if (sasPattern.test(text)) {
          violations.push({ rule: 'DV3036', severity: 'error', message: 'Azure SAS token detected in URL. SAS tokens contain signing key material and should not be hardcoded. Use --mount=type=secret or runtime environment variables.', line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3039: Hardcoded credentials in HEALTHCHECK commands
// HEALTHCHECK CMD may contain URLs or credentials visible in image metadata (docker inspect).
// Unlike RUN, HEALTHCHECK is stored in the image config, not just build layers.
export const DV3039: Rule = {
  id: 'DV3039', severity: 'error',
  description: 'Hardcoded credentials detected in HEALTHCHECK command.',
  check(ctx) {
    const violations: Violation[] = [];
    // Patterns for credentials in HEALTHCHECK commands
    const credentialPatterns = [
      // URLs with embedded credentials: http://user:pass@host
      { pattern: /https?:\/\/[^:@\s]+:[^@\s]+@/i, msg: 'HEALTHCHECK contains a URL with embedded credentials (user:pass@host). These are visible via `docker inspect`. Use environment variables or a healthcheck script instead.' },
      // Authorization headers with tokens
      { pattern: /(?:Authorization[:\s]+Bearer|Bearer|Token)\s+[A-Za-z0-9_.\-+/=]{20,}/i, msg: 'HEALTHCHECK contains an authorization header or token. HEALTHCHECK commands are visible via `docker inspect`. Use environment variables or a healthcheck script instead.' },
      // Explicit password/secret flags
      { pattern: /(?:--password|--secret|--token|-p)\s+["']?[^\s"']{8,}/i, msg: 'HEALTHCHECK contains a password/secret/token flag. HEALTHCHECK commands are visible via `docker inspect`. Use environment variables or a healthcheck script instead.' },
    ];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'HEALTHCHECK') continue;
        const args = inst.arguments;
        if (/^\s*NONE\s*$/i.test(args)) continue;
        for (const { pattern, msg } of credentialPatterns) {
          if (pattern.test(args)) {
            violations.push({ rule: 'DV3039', severity: 'error', message: msg, line: inst.line });
            break; // One violation per HEALTHCHECK instruction
          }
        }
      }
    }
    return violations;
  },
};

// DV3040: npmrc/pypirc/pip.conf COPY leaks credentials
// Copying .npmrc, .pypirc, or pip.conf into images may leak registry authentication tokens.
// These files often contain _authToken, password, or HTTP basic auth credentials.
export const DV3040: Rule = {
  id: 'DV3040', severity: 'warning',
  description: 'Avoid copying package manager config files that may contain registry credentials.',
  check(ctx) {
    const violations: Violation[] = [];
    // Match common package manager config files that store credentials
    const sensitiveConfigs = /(?:^|\/)(?:\.npmrc|\.pypirc|pip\.conf|\.yarnrc\.yml|\.yarnrc|\.cargo\/credentials|\.nuget\/NuGet\.Config|\.docker\/config\.json|\.gem\/credentials)(?:$|["'\s])/i;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const raw = inst.raw || inst.arguments;
        if (sensitiveConfigs.test(raw)) {
          const match = raw.match(sensitiveConfigs);
          const filename = match ? match[0].trim().replace(/^\//, '') : 'config file';
          violations.push({ rule: 'DV3040', severity: 'warning', message: `Copying "${filename}" may leak registry credentials (auth tokens, passwords). Use BuildKit --mount=type=secret or multi-stage builds to avoid persisting credentials in image layers.`, line: inst.line });
        }
      }
    }
    return violations;
  },
};

// DV3041: Installation of insecure network protocol packages
// Packages like telnet, rsh, ftp transmit data (including credentials) in plaintext.
// Their presence in a container image is a security risk and often indicates poor practices.
const INSECURE_PROTOCOL_PACKAGES: Array<{ pattern: RegExp; pkg: string; alternative: string }> = [
  { pattern: /\btelnet\b/, pkg: 'telnet', alternative: 'Use SSH or encrypted protocols instead' },
  { pattern: /\btelnetd\b/, pkg: 'telnetd', alternative: 'Use SSH for remote access instead' },
  { pattern: /\brsh-client\b/, pkg: 'rsh-client', alternative: 'Use SSH instead of rsh' },
  { pattern: /\brsh-server\b/, pkg: 'rsh-server', alternative: 'Use SSH server instead of rsh' },
  { pattern: /\brlogin\b/, pkg: 'rlogin', alternative: 'Use SSH instead of rlogin' },
  { pattern: /\bvsftpd\b/, pkg: 'vsftpd', alternative: 'Use SFTP or SCP for file transfer' },
  { pattern: /\bproftpd(?:-basic)?\b/, pkg: 'proftpd', alternative: 'Use SFTP or SCP for file transfer' },
  { pattern: /\bftpd?\b/, pkg: 'ftp', alternative: 'Use sftp or scp for secure file transfer' },
  { pattern: /\binetutils-telnet\b/, pkg: 'inetutils-telnet', alternative: 'Use SSH or encrypted protocols instead' },
  { pattern: /\binetutils-ftp\b/, pkg: 'inetutils-ftp', alternative: 'Use sftp or scp for secure file transfer' },
];
// Package-install commands: apt-get install, apk add, yum/dnf install, etc.
const PKG_INSTALL_CMD = /(?:apt-get\s+install|apt\s+install|apk\s+add|yum\s+install|dnf\s+install|zypper\s+install|pacman\s+-S)/i;
export const DV3041: Rule = {
  id: 'DV3041', severity: 'warning',
  description: 'Avoid installing packages for insecure network protocols (telnet, rsh, ftp).',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;
        if (!PKG_INSTALL_CMD.test(args)) continue;
        for (const { pattern, pkg, alternative } of INSECURE_PROTOCOL_PACKAGES) {
          if (pattern.test(args)) {
            violations.push({
              rule: 'DV3041', severity: 'warning',
              message: `Installing "${pkg}" introduces an insecure plaintext protocol. ${alternative}.`,
              line: inst.line,
            });
          }
        }
      }
    }
    return violations;
  },
};

// DV3042: Running sshd as container's main process
// Running an SSH server in a container is an anti-pattern that increases attack surface,
// bypasses container orchestration logging, and enables unauthorized access.
// Use `docker exec` or `kubectl exec` for container debugging instead.
export const DV3042: Rule = {
  id: 'DV3042', severity: 'warning',
  description: 'Avoid running sshd as the container main process.',
  check(ctx) {
    const violations: Violation[] = [];
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;

    for (const inst of lastStage.instructions) {
      // Check CMD and ENTRYPOINT for sshd
      if (inst.type === 'CMD' || inst.type === 'ENTRYPOINT') {
        const args = inst.arguments;
        if (/\bsshd\b/.test(args) || /\/usr\/sbin\/sshd/.test(args)) {
          violations.push({
            rule: 'DV3042', severity: 'warning',
            message: 'Running sshd as the container main process increases attack surface and bypasses container orchestration logging. Use `docker exec` or `kubectl exec` for debugging instead.',
            line: inst.line,
          });
        }
      }
      // Also detect openssh-server installation (in last stage = likely intended for runtime)
      if (inst.type === 'RUN') {
        const args = inst.arguments;
        if (PKG_INSTALL_CMD.test(args) && /\bopenssh-server\b/.test(args)) {
          violations.push({
            rule: 'DV3042', severity: 'info',
            message: 'Installing openssh-server in a container is usually unnecessary. Use `docker exec` or `kubectl exec` for container access. If SSH is required for the application (e.g., git server), consider using a dedicated SSH image.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV3043: ENV/ARG values with embedded credentials in URLs
// Detects patterns like https://user:token@registry.example.com in ENV/ARG values.
// These persist in image layers and are visible via `docker history` / `docker inspect`.
const EMBEDDED_CRED_URL = /https?:\/\/[^:@\s]+:[^@\s]+@[^/\s]+/;
// Exclude common false positives: proxy placeholders, Docker Hub auth examples, localhost
const EMBEDDED_CRED_FP = /(?:username:password|user:pass(?:word)?|YOUR_|CHANGE_ME|@(?:[a-z0-9-]+\.)*example\.com|@localhost|@127\.0\.0\.1|@::1)/i;
// Variable references like $VAR or ${VAR} are not actual credentials
const VARIABLE_REF_IN_CRED = /https?:\/\/[^:@\s]*\$[\{(]?\w+[\})]?:[^@\s]*@|https?:\/\/[^:@\s]+:\$[\{(]?\w+[\})]?@/;
export const DV3043: Rule = {
  id: 'DV3043', severity: 'warning',
  description: 'ENV or ARG contains a URL with embedded credentials (user:password@host). These persist in image history.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'ENV') {
          const env = inst as import('../../parser/types').EnvInstruction;
          for (const pair of env.pairs) {
            if (EMBEDDED_CRED_URL.test(pair.value) && !EMBEDDED_CRED_FP.test(pair.value) && !VARIABLE_REF_IN_CRED.test(pair.value)) {
              violations.push({
                rule: 'DV3043', severity: 'warning',
                message: `ENV "${pair.key}" contains a URL with embedded credentials. These are visible in image history via \`docker history\`. Use --mount=type=secret or runtime environment variables instead.`,
                line: inst.line,
              });
            }
          }
        }
        if (inst.type === 'ARG') {
          const arg = inst as import('../../parser/types').ArgInstruction;
          if (arg.defaultValue && EMBEDDED_CRED_URL.test(arg.defaultValue) && !EMBEDDED_CRED_FP.test(arg.defaultValue) && !VARIABLE_REF_IN_CRED.test(arg.defaultValue)) {
            violations.push({
              rule: 'DV3043', severity: 'warning',
              message: `ARG "${arg.name}" default value contains a URL with embedded credentials. ARG values are visible in image history via \`docker history\`. Use --mount=type=secret instead.`,
              line: inst.line,
            });
          }
        }
      }
    }
    // Also check global args
    for (const arg of ctx.ast.globalArgs) {
      if (arg.defaultValue && EMBEDDED_CRED_URL.test(arg.defaultValue) && !EMBEDDED_CRED_FP.test(arg.defaultValue) && !VARIABLE_REF_IN_CRED.test(arg.defaultValue)) {
        violations.push({
          rule: 'DV3043', severity: 'warning',
          message: `Global ARG "${arg.name}" default value contains a URL with embedded credentials. ARG values are visible in image history. Use --mount=type=secret instead.`,
          line: arg.line,
        });
      }
    }
    return violations;
  },
};
