import { describe, it, expect } from 'vitest';
import { parse } from '../src/parser/parser';
import { lint } from '../src/engine/linter';
import { loadConfig } from '../src/engine/config';
import { formatTTY } from '../src/formatter/tty';
import { formatJSON } from '../src/formatter/json';
import { formatSARIF } from '../src/formatter/sarif';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };

describe('Integration - Full Dockerfile lint', () => {
  it('lints a good Dockerfile with few issues', () => {
    const content = `FROM node:18-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY package.json package-lock.json ./
RUN npm ci --production
USER node
HEALTHCHECK CMD ["node", "-e", "require('http').get('http://localhost:3000')"]
CMD ["node", "dist/index.js"]
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    // Should not have critical issues
    const errors = violations.filter(v => v.severity === 'error');
    expect(errors.length).toBe(0);
  });

  it('lints a bad Dockerfile with many issues', () => {
    const content = `FROM ubuntu
RUN sudo apt install curl
RUN cd /tmp && wget http://example.com/file
WORKDIR tmp
ENV DB_PASSWORD=secret123
EXPOSE 70000
COPY . .
CMD node app.js
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    expect(violations.length).toBeGreaterThan(5);
  });

  it('respects inline ignores', () => {
    const content = `FROM ubuntu:20.04
# dockervet ignore=DL3004
RUN sudo echo hello
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    expect(violations.some(v => v.rule === 'DL3004')).toBe(false);
  });

  it('respects config ignore', () => {
    const content = `FROM ubuntu
RUN sudo echo hello
`;
    const config = { ...defaultConfig, ignore: ['DL3004', 'DL3006', 'DV1006', 'DV1009', 'DL3057'] };
    const ast = parse(content);
    const violations = lint(ast, { config });
    expect(violations.some(v => v.rule === 'DL3004')).toBe(false);
    expect(violations.some(v => v.rule === 'DL3006')).toBe(false);
  });

  it('respects hadolint inline ignores', () => {
    const content = `FROM ubuntu:20.04
# hadolint ignore=DL3004
RUN sudo echo hello
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    expect(violations.some(v => v.rule === 'DL3004')).toBe(false);
  });
});

describe('Formatters', () => {
  const violations = [
    { rule: 'DL3006', severity: 'warning' as const, message: 'Tag version explicitly', line: 1 },
    { rule: 'DL3004', severity: 'error' as const, message: 'Do not use sudo', line: 2 },
  ];

  it('formats TTY output', () => {
    const output = formatTTY(violations, 'Dockerfile', false);
    expect(output).toContain('Dockerfile');
    expect(output).toContain('DL3006');
    expect(output).toContain('DL3004');
    expect(output).toContain('1 error(s)');
    expect(output).toContain('1 warning(s)');
  });

  it('formats TTY with no issues', () => {
    const output = formatTTY([], 'Dockerfile', false);
    expect(output).toContain('No issues found');
  });

  it('formats TTY with color', () => {
    const output = formatTTY(violations, 'Dockerfile', true);
    expect(output).toContain('\x1b[');
  });

  it('formats JSON output', () => {
    const output = formatJSON(violations, 'Dockerfile');
    const parsed = JSON.parse(output);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].file).toBe('Dockerfile');
    expect(parsed[0].rule).toBe('DL3006');
  });

  it('formats SARIF output', () => {
    const output = formatSARIF(violations, 'Dockerfile');
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].tool.driver.name).toBe('dockervet');
    expect(parsed.runs[0].results).toHaveLength(2);
  });

  it('SARIF has correct structure', () => {
    const output = formatSARIF(violations, 'Dockerfile');
    const parsed = JSON.parse(output);
    expect(parsed.$schema).toContain('sarif');
    const result = parsed.runs[0].results[0];
    expect(result.ruleId).toBe('DL3006');
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('Dockerfile');
    expect(result.locations[0].physicalLocation.region.startLine).toBe(1);
  });
});

describe('Config', () => {
  it('returns default config when no file exists', () => {
    const config = loadConfig('/nonexistent/path');
    expect(config.ignore).toEqual([]);
    expect(config.trustedRegistries).toEqual([]);
  });
});

describe('Exit code logic', () => {
  it('returns 0 for no violations', () => {
    const content = `FROM scratch
WORKDIR /app
COPY app /app
USER nobody
HEALTHCHECK CMD ["/app"]
CMD ["/app"]
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    const hasErrors = violations.some(v => v.severity === 'error');
    const hasWarnings = violations.some(v => v.severity === 'warning');
    expect(hasErrors).toBe(false);
    expect(hasWarnings).toBe(false);
  });
});

describe('Multi-stage builds', () => {
  it('correctly handles COPY --from with numeric index', () => {
    const content = `FROM node:18 AS builder
RUN echo build
FROM nginx:alpine
COPY --from=0 /app/dist /usr/share/nginx/html
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    // --from=0 is valid numeric index, should not trigger DL3022
    expect(violations.some(v => v.rule === 'DL3022')).toBe(false);
  });

  it('flags COPY --from with unknown alias', () => {
    const content = `FROM node:18
COPY --from=nonexistent /a /b
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    expect(violations.some(v => v.rule === 'DL3022')).toBe(true);
  });
});

describe('Edge cases', () => {
  it('handles empty Dockerfile', () => {
    const ast = parse('');
    const violations = lint(ast, { config: defaultConfig });
    expect(violations).toEqual([]);
  });

  it('handles Dockerfile with only comments', () => {
    const ast = parse('# Just a comment\n# Another comment');
    const violations = lint(ast, { config: defaultConfig });
    expect(violations).toEqual([]);
  });

  it('handles multiple inline ignores', () => {
    const content = `FROM ubuntu:20.04
# dockervet ignore=DL3004,DL3003
RUN sudo cd /tmp && echo hi
`;
    const ast = parse(content);
    const violations = lint(ast, { config: defaultConfig });
    expect(violations.some(v => v.rule === 'DL3004')).toBe(false);
    expect(violations.some(v => v.rule === 'DL3003')).toBe(false);
  });
});
