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
        // If image is a variable reference (e.g., ${BASEIMG}), resolve from global ARGs
        // to check if the default value already contains a tag or digest
        if (f.image.includes('$')) {
          const varMatch = f.image.match(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/);
          if (varMatch) {
            const argName = varMatch[1];
            const argDef = ctx.ast.globalArgs.find(a => a.name === argName);
            if (argDef && (argDef as any).defaultValue) {
              const defaultVal = (argDef as any).defaultValue;
              if (defaultVal.includes('@') || defaultVal.includes(':')) continue;
              // Skip if default value references a stage alias
              if (stageAliases.has(defaultVal.toLowerCase())) continue;
            }
          }
        }
        violations.push({ rule: 'DL3006', severity: 'warning', message: `Always tag the version of an image explicitly. Tag "${f.image}" with a specific version.`, line: f.line });
      }
    }
    return violations;
  },
};
