import { describe, it, expect } from 'vitest';
import { ALL_RULES } from '../../src/rules';
import { parse } from '../../src/parser/parser';
import { Violation } from '../../src/rules/types';

function lint(dockerfile: string): Violation[] {
  const ast = parse(dockerfile);
  const ctx = { ast, trustedRegistries: [] as string[], requiredLabels: [] as string[] };
  return ALL_RULES.flatMap(r => r.check(ctx));
}

function hasRule(violations: Violation[], ruleId: string): boolean {
  return violations.some(v => v.rule === ruleId);
}

// ===========================================================================
// DV4014: ONBUILD with dangerous instructions
// ===========================================================================
describe('DV4014: ONBUILD with dangerous instructions', () => {
  it('should flag ONBUILD RUN', () => {
    const violations = lint(`
FROM node:18
ONBUILD RUN npm install
`);
    expect(hasRule(violations, 'DV4014')).toBe(true);
    const v = violations.find(v => v.rule === 'DV4014')!;
    expect(v.message).toContain('ONBUILD RUN');
  });

  it('should flag ONBUILD ADD', () => {
    const violations = lint(`
FROM node:18
ONBUILD ADD . /app
`);
    expect(hasRule(violations, 'DV4014')).toBe(true);
    const v = violations.find(v => v.rule === 'DV4014')!;
    expect(v.message).toContain('ONBUILD ADD');
  });

  it('should flag ONBUILD COPY', () => {
    const violations = lint(`
FROM node:18
ONBUILD COPY package.json /app/
`);
    expect(hasRule(violations, 'DV4014')).toBe(true);
    const v = violations.find(v => v.rule === 'DV4014')!;
    expect(v.message).toContain('ONBUILD COPY');
  });

  it('should not flag ONBUILD ENV', () => {
    const violations = lint(`
FROM node:18
ONBUILD ENV NODE_ENV=production
`);
    expect(hasRule(violations, 'DV4014')).toBe(false);
  });

  it('should not flag ONBUILD WORKDIR', () => {
    const violations = lint(`
FROM node:18
ONBUILD WORKDIR /app
`);
    expect(hasRule(violations, 'DV4014')).toBe(false);
  });

  it('should not flag ONBUILD EXPOSE', () => {
    const violations = lint(`
FROM node:18
ONBUILD EXPOSE 3000
`);
    expect(hasRule(violations, 'DV4014')).toBe(false);
  });

  it('should flag multiple ONBUILD RUN in same Dockerfile', () => {
    const violations = lint(`
FROM node:18
ONBUILD RUN echo step1
ONBUILD RUN echo step2
`);
    const dv4014 = violations.filter(v => v.rule === 'DV4014');
    expect(dv4014.length).toBe(2);
  });

  it('should not flag regular RUN/COPY/ADD without ONBUILD', () => {
    const violations = lint(`
FROM node:18
RUN npm install
COPY . /app
ADD file.tar.gz /app
`);
    expect(hasRule(violations, 'DV4014')).toBe(false);
  });
});

// ===========================================================================
// DV9009: chmod 777 or world-writable permissions in RUN
// ===========================================================================
describe('DV9009: chmod 777 / world-writable permissions', () => {
  it('should flag chmod 777', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod 777 /tmp/app
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod 0777', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod 0777 /var/data
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod a+w', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod a+w /tmp/shared
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod o+w', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod o+w /opt/data
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod a=rwx', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod a=rwx /tmp/dir
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod ugo+w', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod ugo+w /tmp/dir
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod 777 in chained commands', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN mkdir -p /app && chmod 777 /app && echo done
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should flag chmod -R 777', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod -R 777 /app
`);
    expect(hasRule(violations, 'DV9009')).toBe(true);
  });

  it('should not flag chmod 755', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod 755 /usr/local/bin/app
`);
    expect(hasRule(violations, 'DV9009')).toBe(false);
  });

  it('should not flag chmod 644', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod 644 /etc/config.conf
`);
    expect(hasRule(violations, 'DV9009')).toBe(false);
  });

  it('should not flag chmod u+w', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN chmod u+w /app/data
`);
    expect(hasRule(violations, 'DV9009')).toBe(false);
  });

  it('should not flag COPY --chmod (not a RUN instruction)', () => {
    const violations = lint(`
FROM ubuntu:22.04
COPY --chmod=777 file.txt /app/
`);
    expect(hasRule(violations, 'DV9009')).toBe(false);
  });
});

// ===========================================================================
// DV3044: CI/CD token in ENV/ARG
// ===========================================================================
describe('DV3044: CI/CD token in ENV/ARG', () => {
  it('should flag ENV GITHUB_TOKEN with literal value', () => {
    const violations = lint(`
FROM node:18
ENV GITHUB_TOKEN=ghp_abc123def456
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
    const v = violations.find(v => v.rule === 'DV3044')!;
    expect(v.severity).toBe('error');
    expect(v.message).toContain('GITHUB_TOKEN');
  });

  it('should flag ENV GH_TOKEN', () => {
    const violations = lint(`
FROM node:18
ENV GH_TOKEN=ghp_secretvalue
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
  });

  it('should flag ENV NPM_TOKEN', () => {
    const violations = lint(`
FROM node:18
ENV NPM_TOKEN=npm_1234567890abcdef
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
  });

  it('should flag ARG GITLAB_TOKEN with default', () => {
    const violations = lint(`
FROM node:18
ARG GITLAB_TOKEN=glpat-secret123
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
  });

  it('should flag ENV AWS_SECRET_ACCESS_KEY', () => {
    const violations = lint(`
FROM python:3.12
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
  });

  it('should flag ENV SNYK_TOKEN', () => {
    const violations = lint(`
FROM node:18
ENV SNYK_TOKEN=12345678-abcd-efgh
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
  });

  it('should not flag ARG GITHUB_TOKEN without default', () => {
    const violations = lint(`
FROM node:18
ARG GITHUB_TOKEN
`);
    expect(hasRule(violations, 'DV3044')).toBe(false);
  });

  it('should not flag ENV with variable reference', () => {
    const violations = lint(`
FROM node:18
ARG GH_TOKEN
ENV GH_TOKEN=$GH_TOKEN
`);
    expect(hasRule(violations, 'DV3044')).toBe(false);
  });

  it('should not flag ENV with ${VAR} reference', () => {
    const violations = lint(`
FROM node:18
ARG NPM_TOKEN
ENV NPM_TOKEN=\${NPM_TOKEN}
`);
    expect(hasRule(violations, 'DV3044')).toBe(false);
  });

  it('should not flag unrelated ENV variable', () => {
    const violations = lint(`
FROM node:18
ENV NODE_ENV=production
ENV APP_PORT=3000
`);
    expect(hasRule(violations, 'DV3044')).toBe(false);
  });

  it('should flag global ARG with CI/CD token default', () => {
    const violations = lint(`
ARG GITHUB_TOKEN=ghp_leaked123
FROM node:18
RUN echo build
`);
    expect(hasRule(violations, 'DV3044')).toBe(true);
  });

  it('should not flag global ARG without default', () => {
    const violations = lint(`
ARG GITHUB_TOKEN
FROM node:18
RUN echo build
`);
    expect(hasRule(violations, 'DV3044')).toBe(false);
  });
});
