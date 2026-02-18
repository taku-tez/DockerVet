import { Rule, Violation } from '../types';

// Docker's automatic platform ARGs (available without explicit ARG declaration in multi-arch builds)
// See: https://docs.docker.com/reference/dockerfile/#automatic-platform-args-in-the-global-scope
const PLATFORM_ARG_VALUES: Record<string, string[]> = {
  TARGETARCH:     ['amd64', 'arm64', 'arm', 'armv7', '386', 's390x', 'ppc64le', 'riscv64'],
  TARGETOS:       ['linux', 'darwin', 'windows', 'freebsd'],
  TARGETPLATFORM: ['linux/amd64', 'linux/arm64', 'linux/arm/v7'],
  TARGETVARIANT:  ['v7', 'v6', ''],
  BUILDARCH:      ['amd64', 'arm64'],
  BUILDOS:        ['linux'],
};

/**
 * Given a template string with ${VAR} placeholders, generate all possible
 * substitutions using known platform ARG values and check if any matches
 * a stage alias. Used to handle patterns like FROM init-build-${TARGETARCH}.
 */
function matchesPlatformVariantAlias(template: string, stageAliases: Set<string>): boolean {
  // Find all remaining unresolved variable names in the template
  const varNames = [...new Set([...template.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g)].map(m => m[1]))];
  // Only handle patterns where all vars are known platform ARGs
  if (varNames.some(v => !PLATFORM_ARG_VALUES[v])) return false;

  // Generate all combinations and check each against stage aliases
  function expand(s: string, vars: string[]): boolean {
    if (vars.length === 0) return stageAliases.has(s.toLowerCase());
    const [head, ...rest] = vars;
    const values = PLATFORM_ARG_VALUES[head] || [];
    return values.some(val => expand(s.replace(new RegExp(`\\$\\{?${head}\\}?`, 'g'), val), rest));
  }
  return expand(template, varNames);
}

export const DL3006: Rule = {
  id: 'DL3006',
  severity: 'warning',
  description: 'Always tag the version of an image explicitly',
  check(ctx) {
    const violations: Violation[] = [];
    // Collect stage aliases to avoid false positives on internal references
    const stageAliases = new Set<string>();
    for (const stage of ctx.ast.stages) {
      if (stage.from.alias) stageAliases.add(stage.from.alias.toLowerCase());
    }
    for (const stage of ctx.ast.stages) {
      const f = stage.from;
      if (f.image === 'scratch') continue;
      // Skip references to other build stages (e.g., FROM gobuild)
      if (stageAliases.has(f.image.toLowerCase())) continue;
      if (!f.tag && !f.digest) {
        // If image is a variable reference (e.g., ${BASEIMG} or base-${BUILD_TYPE}),
        // resolve from global ARGs to check if the default value already contains a tag/digest,
        // or if the fully-substituted name resolves to a stage alias.
        if (f.image.includes('$')) {
          const varMatch = f.image.match(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/);
          if (varMatch) {
            const argName = varMatch[1];
            const argDef = ctx.ast.globalArgs.find(a => a.name === argName);
            if (argDef && (argDef as any).defaultValue) {
              const defaultVal = (argDef as any).defaultValue;
              if (defaultVal.includes('@') || defaultVal.includes(':')) continue;
              // Skip if default value is the special 'scratch' base image
              if (defaultVal.toLowerCase() === 'scratch') continue;
              // Skip if default value (alone) references a stage alias
              if (stageAliases.has(defaultVal.toLowerCase())) continue;
            }
          }
          // Try substituting ALL variables in the image string with their ARG defaults;
          // if the fully-resolved name is a known stage alias, skip (e.g. FROM base-${BUILD_TYPE})
          // Unknown variables are kept in ${VAR} form so platform alias matching can handle them.
          const resolved = f.image.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (match, v) => {
            const arg = ctx.ast.globalArgs.find(a => a.name === v);
            return (arg && (arg as any).defaultValue) ? (arg as any).defaultValue : `\${${v}}`;
          });
          if (stageAliases.has(resolved.toLowerCase())) continue;
          // Skip if fully-resolved image name is 'scratch'
          if (resolved.toLowerCase() === 'scratch') continue;
          // Handle Docker automatic platform ARGs (TARGETARCH, TARGETOS, etc.)
          // e.g. FROM init-build-${TARGETARCH} where init-build-amd64 is a stage alias
          if (matchesPlatformVariantAlias(resolved, stageAliases)) continue;
        }
        violations.push({ rule: 'DL3006', severity: 'warning', message: `Always tag the version of an image explicitly. Tag "${f.image}" with a specific version.`, line: f.line });
      }
    }
    return violations;
  },
};
