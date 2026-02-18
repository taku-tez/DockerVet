import { describe, it, expect } from 'vitest';
import {
  matchesDirectoryPattern,
  matchesFilenamePattern,
  matchesContextualRule,
  classifyFinding,
  classifyFindings,
  generateReport,
  type Finding,
  type FPPatterns,
} from '../scripts/fp-triage';

// ── Minimal patterns fixture ───────────────────────────────────────────

const patterns: FPPatterns = {
  version: '1.0.0',
  patterns: {
    directoryExclusions: {
      DL3057: {
        description: 'HEALTHCHECK missing',
        directories: ['testdata/', 'devenv/', 'examples/'],
      },
      DV4005: {
        description: 'No CMD/ENTRYPOINT',
        directories: ['build/', 'ci/'],
      },
      DV1001: {
        description: 'Hardcoded secrets',
        directories: ['testdata/', 'fixtures/'],
      },
    },
    filenameExclusions: {
      DL3057: {
        description: 'HEALTHCHECK missing',
        exact: ['Dockerfile.ci', 'Dockerfile.test', 'dev.Dockerfile'],
        suffixes: ['.binary'],
      },
      DV4005: {
        description: 'No CMD/ENTRYPOINT',
        exact: [],
        suffixes: ['.binary'],
      },
    },
    contextualRules: {
      DV1006: {
        description: 'Distroless/chainguard FP',
        conditions: [
          { type: 'messageMatch', pattern: 'distroless|chainguard', classification: 'fp' as const },
          { type: 'messageMatch', pattern: 'stage alias', classification: 'candidate' as const },
        ],
      },
      DL3001: {
        description: 'BuildKit mount FP',
        conditions: [
          { type: 'messageMatch', pattern: '--mount=type=cache', classification: 'fp' as const },
        ],
      },
    },
  },
};

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    file: 'repo/Dockerfile',
    line: 1,
    column: 1,
    rule: 'DL3057',
    severity: 'warning',
    message: 'HEALTHCHECK missing',
    ...overrides,
  };
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('matchesDirectoryPattern', () => {
  it('matches directory in middle of path', () => {
    expect(matchesDirectoryPattern('repo/testdata/Dockerfile', ['testdata/'])).toBe(true);
  });

  it('matches directory at start of path', () => {
    expect(matchesDirectoryPattern('devenv/data/Dockerfile', ['devenv/'])).toBe(true);
  });

  it('does not match unrelated path', () => {
    expect(matchesDirectoryPattern('src/main/Dockerfile', ['testdata/'])).toBe(false);
  });

  it('does not partial-match directory names', () => {
    expect(matchesDirectoryPattern('repo/testdata-extra/Dockerfile', ['testdata/'])).toBe(false);
  });
});

describe('matchesFilenamePattern', () => {
  it('matches exact filename', () => {
    expect(matchesFilenamePattern('repo/Dockerfile.ci', ['Dockerfile.ci'], [])).toBe(true);
  });

  it('matches suffix', () => {
    expect(matchesFilenamePattern('repo/Dockerfile.binary', [], ['.binary'])).toBe(true);
  });

  it('does not match unrelated filename', () => {
    expect(matchesFilenamePattern('repo/Dockerfile', ['Dockerfile.ci'], ['.binary'])).toBe(false);
  });
});

describe('matchesContextualRule', () => {
  it('matches message pattern and returns correct classification', () => {
    const finding = mkFinding({ rule: 'DV1006', message: 'Using distroless base image' });
    const result = matchesContextualRule(finding, patterns.patterns.contextualRules.DV1006.conditions);
    expect(result.matched).toBe(true);
    expect(result.classification).toBe('fp');
  });

  it('returns candidate for weaker match', () => {
    const finding = mkFinding({ rule: 'DV1006', message: 'References stage alias' });
    const result = matchesContextualRule(finding, patterns.patterns.contextualRules.DV1006.conditions);
    expect(result.matched).toBe(true);
    expect(result.classification).toBe('candidate');
  });

  it('returns no match for unrelated message', () => {
    const finding = mkFinding({ rule: 'DV1006', message: 'Something unrelated' });
    const result = matchesContextualRule(finding, patterns.patterns.contextualRules.DV1006.conditions);
    expect(result.matched).toBe(false);
  });
});

describe('classifyFinding', () => {
  it('classifies directory-based FP', () => {
    const f = mkFinding({ file: 'grafana/grafana/devenv/data/Dockerfile' });
    const result = classifyFinding(f, patterns);
    expect(result.classification).toBe('fp');
    expect(result.reason).toContain('devenv');
  });

  it('classifies filename-based FP', () => {
    const f = mkFinding({ file: 'repo/Dockerfile.ci' });
    const result = classifyFinding(f, patterns);
    expect(result.classification).toBe('fp');
    expect(result.reason).toContain('Dockerfile.ci');
  });

  it('classifies contextual FP', () => {
    const f = mkFinding({ rule: 'DL3001', message: 'Uses --mount=type=cache in RUN' });
    const result = classifyFinding(f, patterns);
    expect(result.classification).toBe('fp');
  });

  it('classifies legitimate finding', () => {
    const f = mkFinding({ file: 'production/Dockerfile', rule: 'DL3057', message: 'HEALTHCHECK missing' });
    const result = classifyFinding(f, patterns);
    expect(result.classification).toBe('legitimate');
  });

  it('directory check takes priority over filename', () => {
    const f = mkFinding({ file: 'testdata/Dockerfile.ci' });
    const result = classifyFinding(f, patterns);
    expect(result.classification).toBe('fp');
    expect(result.reason).toContain('testdata');
  });
});

describe('classifyFindings', () => {
  it('classifies a batch of findings', () => {
    const findings = [
      mkFinding({ file: 'repo/testdata/Dockerfile' }),
      mkFinding({ file: 'repo/src/Dockerfile', rule: 'DL3057' }),
      mkFinding({ file: 'repo/Dockerfile.binary' }),
    ];
    const results = classifyFindings(findings, patterns);
    expect(results).toHaveLength(3);
    expect(results[0].classification).toBe('fp');
    expect(results[1].classification).toBe('legitimate');
    expect(results[2].classification).toBe('fp');
  });
});

describe('generateReport', () => {
  it('generates markdown report with correct structure', () => {
    const findings = [
      mkFinding({ file: 'repo/testdata/Dockerfile' }),
      mkFinding({ file: 'repo/src/Dockerfile' }),
      mkFinding({ rule: 'DV1006', message: 'Uses distroless image', file: 'repo/Dockerfile' }),
      mkFinding({ rule: 'DV1006', message: 'References stage alias', file: 'repo/build/Dockerfile' }),
    ];
    const classified = classifyFindings(findings, patterns);
    const report = generateReport(classified);

    expect(report).toContain('# DockerVet FP Triage Report');
    expect(report).toContain('## Summary');
    expect(report).toContain('Total findings: 4');
    expect(report).toContain('Auto-classified FP:');
    expect(report).toContain('Legitimate findings:');
  });

  it('handles empty findings', () => {
    const report = generateReport([]);
    expect(report).toContain('Total findings: 0');
  });
});
