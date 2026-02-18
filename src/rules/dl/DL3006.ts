import { Rule, Violation } from '../types';

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
              // Skip if default value (alone) references a stage alias
              if (stageAliases.has(defaultVal.toLowerCase())) continue;
            }
          }
          // Try substituting ALL variables in the image string with their ARG defaults;
          // if the fully-resolved name is a known stage alias, skip (e.g. FROM base-${BUILD_TYPE})
          const resolved = f.image.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (_, v) => {
            const arg = ctx.ast.globalArgs.find(a => a.name === v);
            return (arg && (arg as any).defaultValue) ? (arg as any).defaultValue : v;
          });
          if (stageAliases.has(resolved.toLowerCase())) continue;
        }
        violations.push({ rule: 'DL3006', severity: 'warning', message: `Always tag the version of an image explicitly. Tag "${f.image}" with a specific version.`, line: f.line });
      }
    }
    return violations;
  },
};
