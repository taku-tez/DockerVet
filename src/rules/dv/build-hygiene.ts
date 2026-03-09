import { Rule, Violation } from '../types';
import { CopyInstruction } from '../../parser/types';

// ---------------------------------------------------------------------------
// DV9xxx: Build Hygiene & Layer Optimization
// ---------------------------------------------------------------------------

// DV9001: COPY or ADD of sensitive files (.env, .git, id_rsa, etc.)
export const DV9001: Rule = {
  id: 'DV9001', severity: 'error',
  description: 'Avoid copying sensitive files into the image. Use .dockerignore instead.',
  check(ctx) {
    const violations: Violation[] = [];
    const sensitivePatterns = [
      { pattern: /(?:^|\/)\.env(?:\.[^/]*)?$/i, name: '.env file' },
      { pattern: /(?:^|\/)\.git(?:\/|$)/i, name: '.git directory' },
      { pattern: /(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)(?!\.pub\b)/i, name: 'SSH private key' },
      { pattern: /(?<!\.crt|\.cert|\.ca|\.pub)\.pem$|(?<!public|\.gpg|\.asc|\.pub)\.key$/i, name: 'private key file' },
      { pattern: /\.pfx$|\.p12$/i, name: 'certificate bundle' },
      { pattern: /(?:^|\/)\.aws(?:\/|$)/i, name: '.aws credentials directory' },
      { pattern: /(?:^|\/)\.kube(?:\/|$)/i, name: '.kube config directory' },
      { pattern: /(?:^|\/)\.docker\/config\.json/i, name: 'Docker config (may contain registry credentials)' },
      { pattern: /(?:^|\/)\.npmrc$/i, name: '.npmrc (may contain auth tokens)' },
      { pattern: /(?:^|\/)\.pypirc$/i, name: '.pypirc (may contain auth tokens)' },
    ];

    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const copy = inst as CopyInstruction;
        // Skip COPY --from (multi-stage copies)
        if (copy.from) continue;
        for (const src of copy.sources) {
          // Skip wildcard-only patterns like "." or "./" (too broad to analyze)
          if (src === '.' || src === './') continue;
          for (const { pattern, name } of sensitivePatterns) {
            if (pattern.test(src)) {
              // Skip .env template/sample files — they contain placeholders, not real secrets
              if (name === '.env file' && /\.(?:sample|example|template|dist|defaults)$/i.test(src)) {
                continue;
              }
              // Skip public GPG key URLs (e.g., https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key)
              if (name === 'private key file' && /gpg(?:key)?/i.test(src)) {
                continue;
              }
              // Skip DH parameter files (e.g., ffdhe2048.pem, ffdhe4096.pem, dhparam.pem) — these are public parameters, not private keys
              if (name === 'private key file' && /(?:ffdhe\d+|dhparam|dh\d+)\.pem$/i.test(src)) {
                continue;
              }
              violations.push({
                rule: 'DV9001', severity: 'error',
                message: `Copying ${name} ("${src}") into the image exposes sensitive data. Use .dockerignore to exclude it, or use BuildKit secrets (--mount=type=secret).`,
                line: inst.line,
              });
              break;
            }
          }
        }
      }
    }
    return violations;
  },
};

// DV9002: COPY/ADD with overly broad source (copying entire build context)
export const DV9002: Rule = {
  id: 'DV9002', severity: 'info',
  description: 'Copying the entire build context may include unnecessary files. Be more specific.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'COPY' && inst.type !== 'ADD') continue;
        const copy = inst as CopyInstruction;
        if (copy.from) continue;
        for (const src of copy.sources) {
          if (src === '.' || src === './') {
            // Only flag if there's no .dockerignore indication and the destination is root-ish
            violations.push({
              rule: 'DV9002', severity: 'info',
              message: `COPY "${src}" copies the entire build context. Consider copying only needed files/directories to reduce image size and avoid leaking files. Ensure .dockerignore is configured.`,
              line: inst.line,
            });
            break;
          }
        }
      }
    }
    return violations;
  },
};

// DV9003: Using ADD when COPY would suffice (ADD has implicit tar extraction & URL fetch)
export const DV9003: Rule = {
  id: 'DV9003', severity: 'info',
  description: 'Use COPY instead of ADD for simple file copies. ADD has implicit tar extraction and URL fetch behavior.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'ADD') continue;
        const add = inst as CopyInstruction;
        // ADD is appropriate for URLs and tar files
        const hasUrl = add.sources.some(s => /^https?:\/\//.test(s));
        const hasTar = add.sources.some(s => /\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz)$/i.test(s));
        if (!hasUrl && !hasTar) {
          violations.push({
            rule: 'DV9003', severity: 'info',
            message: 'Use COPY instead of ADD for copying local files. ADD implicitly extracts tar archives and can fetch URLs, which may cause unexpected behavior.',
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};

// DV9004: Missing LABEL for image metadata (maintainer, version, description)
export const DV9004: Rule = {
  id: 'DV9004', severity: 'info',
  description: 'Consider adding OCI-standard LABELs for image metadata (maintainer, version, description).',
  check(ctx) {
    const violations: Violation[] = [];
    // Only check if there are no LABEL instructions at all
    let hasLabel = false;
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type === 'LABEL') {
          hasLabel = true;
          break;
        }
      }
      if (hasLabel) break;
    }
    // Skip scratch-based images (minimal binary containers often don't need labels)
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!hasLabel && ctx.ast.stages.length > 0 && lastStage.from.image !== 'scratch') {
      violations.push({
        rule: 'DV9004', severity: 'info',
        message: 'No LABEL instructions found. Consider adding OCI-standard labels (org.opencontainers.image.authors, org.opencontainers.image.version, org.opencontainers.image.description) for better image management.',
        line: lastStage.from.line,
      });
    }
    return violations;
  },
};

// DV9005: apt-get/apk without --no-cache or rm of cache in the same RUN
export const DV9005: Rule = {
  id: 'DV9005', severity: 'warning',
  description: 'Package manager cache not cleaned in the same RUN layer, increasing image size.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      for (const inst of stage.instructions) {
        if (inst.type !== 'RUN') continue;
        const args = inst.arguments;

        // BuildKit --mount=type=cache manages the cache externally; cleanup is unnecessary
        if (/--mount=type=cache/.test(args)) continue;

        // apt-get install without cleanup
        if (/\bapt-get\s+install\b/.test(args)) {
          const hasClean = /\bapt-get\s+clean\b/.test(args) ||
            /\brm\s+-rf?\s+\/var\/lib\/apt\/lists/.test(args);
          if (!hasClean) {
            violations.push({
              rule: 'DV9005', severity: 'warning',
              message: 'apt-get install without cache cleanup in the same RUN layer. Add "apt-get clean && rm -rf /var/lib/apt/lists/*" to reduce image size.',
              line: inst.line,
            });
          }
        }

        // yum/dnf install without cleanup
        if (/\b(?:yum|dnf)\s+install\b/.test(args)) {
          const hasClean = /\b(?:yum|dnf)\s+clean\s+all\b/.test(args) ||
            /\brm\s+-rf?\s+\/var\/cache\/(?:yum|dnf)/.test(args);
          if (!hasClean) {
            violations.push({
              rule: 'DV9005', severity: 'warning',
              message: 'yum/dnf install without cache cleanup in the same RUN layer. Add "yum clean all" or "dnf clean all" to reduce image size.',
              line: inst.line,
            });
          }
        }

        // Note: apk add --no-cache is already covered by DL3018
      }
    }
    return violations;
  },
};

// DV9006: Multiple FROM without clear multi-stage pattern (potential image bloat)
export const DV9006: Rule = {
  id: 'DV9006', severity: 'info',
  description: 'Multi-stage build detected but final stage copies from no prior stage. Consider using COPY --from to leverage multi-stage builds.',
  check(ctx) {
    const violations: Violation[] = [];
    if (ctx.ast.stages.length < 2) return violations;

    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    const hasCopyFrom = lastStage.instructions.some(inst => {
      if (inst.type !== 'COPY') return false;
      return !!(inst as CopyInstruction).from;
    });

    // If the last stage FROM references another stage alias, it's fine
    const stageAliases = new Set(
      ctx.ast.stages.slice(0, -1).map(s => s.from.alias).filter(Boolean)
    );
    const lastFromImage = lastStage.from.image;
    const referencesStage = stageAliases.has(lastFromImage);

    if (!hasCopyFrom && !referencesStage) {
      violations.push({
        rule: 'DV9006', severity: 'info',
        message: 'Multi-stage Dockerfile detected but the final stage does not COPY --from any prior stage. If prior stages are build-only, use COPY --from=<stage> to copy only needed artifacts.',
        line: lastStage.from.line,
      });
    }
    return violations;
  },
};

// DV9007: VOLUME in non-final build stage (silently ignored)
export const DV9007: Rule = {
  id: 'DV9007', severity: 'warning',
  description: 'VOLUME instruction in a non-final build stage has no effect on the final image.',
  check(ctx) {
    const violations: Violation[] = [];
    if (ctx.ast.stages.length < 2) return violations;

    // Check all stages except the last one
    for (let i = 0; i < ctx.ast.stages.length - 1; i++) {
      const stage = ctx.ast.stages[i];
      for (const inst of stage.instructions) {
        if (inst.type === 'VOLUME') {
          violations.push({
            rule: 'DV9007', severity: 'warning',
            message: `VOLUME instruction in build stage ${i} (${stage.from.alias || stage.from.image}) has no effect on the final image. VOLUME in non-final stages is silently ignored. Move it to the final stage if needed.`,
            line: inst.line,
          });
        }
      }
    }
    return violations;
  },
};
