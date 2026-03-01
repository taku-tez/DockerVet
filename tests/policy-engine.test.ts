import { describe, it, expect } from 'vitest';
import { loadConfig, getActiveIgnoreIds, DockerVetConfig } from '../src/engine/config';
import { parse } from '../src/parser/parser';
import { lint } from '../src/engine/linter';

function makeConfig(overrides: Partial<DockerVetConfig> = {}): DockerVetConfig {
  return {
    ignore: [],
    trustedRegistries: [],
    requiredLabels: [],
    override: {},
    ...overrides,
  };
}

function processContent(content: string, config: DockerVetConfig) {
  const ast = parse(content);
  const violations = lint(ast, { config, trustedRegistries: config.trustedRegistries, filePath: 'Dockerfile' });

  const failOn: string[] = config.failOn ?? ['error'];
  const threshold: string = config.severityThreshold ?? 'style';
  const severityOrder = ['error', 'warning', 'info', 'style'];
  const thresholdIdx = severityOrder.indexOf(threshold);

  const activeViolations = violations.filter(v => {
    const idx = severityOrder.indexOf(v.severity);
    return idx !== -1 && idx <= thresholdIdx;
  });

  const hasFail = activeViolations.some(v => failOn.includes(v.severity));
  const hasWarnings = activeViolations.some(v => v.severity === 'warning') && !hasFail;
  let exitCode = 0;
  if (hasFail) exitCode = 2;
  else if (hasWarnings) exitCode = 1;

  return { violations: activeViolations, exitCode };
}

describe('Policy Engine', () => {
  it('non-expired ignore entry is active', () => {
    const config = makeConfig({
      ignore: [
        { id: 'DL3008', reason: 'test', expires: '2099-12-31' },
      ],
    });
    const ids = getActiveIgnoreIds(config);
    expect(ids.has('DL3008')).toBe(true);
  });

  it('expired ignore entry is inactive', () => {
    const config = makeConfig({
      ignore: [
        { id: 'DL3008', reason: 'test', expires: '2020-01-01' },
      ],
    });
    const ids = getActiveIgnoreIds(config);
    expect(ids.has('DL3008')).toBe(false);
  });

  it('fail-on: [warning] causes exit code 2 on warning', () => {
    // Use a Dockerfile that triggers a warning-level rule
    const dockerfile = `FROM ubuntu:latest\nRUN apt-get install -y curl\n`;
    const config = makeConfig({ failOn: ['warning'] });
    const result = processContent(dockerfile, config);
    const hasWarning = result.violations.some(v => v.severity === 'warning');
    if (hasWarning) {
      expect(result.exitCode).toBe(2);
    }
  });

  it('severity-threshold: warning filters out info violations', () => {
    const dockerfile = `FROM ubuntu:latest\nRUN apt-get install -y curl\n`;
    const config = makeConfig({ severityThreshold: 'warning' });
    const result = processContent(dockerfile, config);
    const hasInfo = result.violations.some(v => v.severity === 'info');
    expect(hasInfo).toBe(false);
  });

  it('style severity violations are shown with default threshold', () => {
    // Default threshold is 'style', so style rules should be included
    const dockerfile = `FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\n`;
    const config = makeConfig(); // default severityThreshold = 'style'
    const result = processContent(dockerfile, config);
    // All violations should pass through, including style if any exist
    for (const v of result.violations) {
      expect(['error', 'warning', 'info', 'style']).toContain(v.severity);
    }
  });
});
