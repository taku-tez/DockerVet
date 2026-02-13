import { parse } from '../src/parser/parser';
import { lint } from '../src/engine/linter';
import { Violation } from '../src/rules/types';

export const defaultConfig = { ignore: [] as string[], trustedRegistries: [] as string[], requiredLabels: [] as string[], override: {} as Record<string, any> };

export function lintDockerfile(content: string, config = defaultConfig, filePath?: string): Violation[] {
  const ast = parse(content);
  return lint(ast, { config, filePath });
}

export function hasRule(violations: Violation[], rule: string): boolean {
  return violations.some(v => v.rule === rule);
}
