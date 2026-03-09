import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/parser';

function makeCtx(dockerfile: string) {
  return {
    ast: parse(dockerfile),
    trustedRegistries: [] as string[],
    requiredLabels: [] as string[],
  };
}

import { DV9007 } from '../../src/rules/dv/build-hygiene';
import { DV3043 } from '../../src/rules/dv/security-advanced';

// ---------------------------------------------------------------------------
// DV9007: VOLUME in non-final build stage
// ---------------------------------------------------------------------------
describe('DV9007: VOLUME in non-final build stage', () => {
  it('should flag VOLUME in intermediate stage', () => {
    const ctx = makeCtx([
      'FROM node:18 AS builder',
      'VOLUME /data',
      'RUN echo build',
      'FROM node:18-slim',
      'COPY --from=builder /app /app',
    ].join('\n'));
    const violations = DV9007.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].rule).toBe('DV9007');
    expect(violations[0].message).toContain('non-final');
  });

  it('should NOT flag VOLUME in final stage', () => {
    const ctx = makeCtx([
      'FROM node:18 AS builder',
      'RUN echo build',
      'FROM node:18-slim',
      'VOLUME /data',
    ].join('\n'));
    const violations = DV9007.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should NOT flag VOLUME in single-stage Dockerfile', () => {
    const ctx = makeCtx([
      'FROM node:18',
      'VOLUME /data',
    ].join('\n'));
    const violations = DV9007.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should flag multiple VOLUME instructions in different non-final stages', () => {
    const ctx = makeCtx([
      'FROM node:18 AS stage1',
      'VOLUME /data1',
      'FROM node:18 AS stage2',
      'VOLUME /data2',
      'FROM node:18-slim',
      'COPY --from=stage1 /app /app',
    ].join('\n'));
    const violations = DV9007.check(ctx);
    expect(violations.length).toBe(2);
  });

  it('should include stage alias in message when available', () => {
    const ctx = makeCtx([
      'FROM node:18 AS build-deps',
      'VOLUME /cache',
      'FROM node:18-slim',
      'CMD ["node", "app.js"]',
    ].join('\n'));
    const violations = DV9007.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].message).toContain('build-deps');
  });
});

// ---------------------------------------------------------------------------
// DV3043: ENV/ARG with embedded credentials in URLs
// ---------------------------------------------------------------------------
describe('DV3043: ENV/ARG with embedded credentials in URLs', () => {
  it('should flag ENV with URL containing embedded credentials', () => {
    const ctx = makeCtx([
      'FROM node:18',
      'ENV NPM_REGISTRY=https://deploy-token:glpat-xxxx1234@gitlab.corp.internal/api/v4/packages/npm/',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].rule).toBe('DV3043');
    expect(violations[0].message).toContain('NPM_REGISTRY');
    expect(violations[0].message).toContain('embedded credentials');
  });

  it('should flag ARG with default URL containing embedded credentials', () => {
    const ctx = makeCtx([
      'FROM python:3.11',
      'ARG PIP_INDEX=https://admin:s3cret@pypi.internal.com/simple/',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].rule).toBe('DV3043');
    expect(violations[0].message).toContain('PIP_INDEX');
  });

  it('should flag global ARG with embedded credentials', () => {
    const ctx = makeCtx([
      'ARG REGISTRY_URL=https://ci-user:token123@registry.corp.internal/',
      'FROM node:18',
      'RUN echo hello',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].message).toContain('Global ARG');
  });

  it('should NOT flag ENV with URL without credentials', () => {
    const ctx = makeCtx([
      'FROM node:18',
      'ENV NPM_REGISTRY=https://registry.npmjs.org/',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should NOT flag placeholder/example credentials', () => {
    const ctx = makeCtx([
      'FROM node:18',
      'ENV REGISTRY=https://username:password@registry.example.com/',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should NOT flag URLs with variable references as credentials', () => {
    const ctx = makeCtx([
      'FROM node:18',
      'ARG TOKEN',
      'ENV REGISTRY=https://user:${TOKEN}@registry.example.com/',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should NOT flag ARG without default value', () => {
    const ctx = makeCtx([
      'FROM node:18',
      'ARG REGISTRY_URL',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should flag HTTP URL with embedded credentials', () => {
    const ctx = makeCtx([
      'FROM python:3.11',
      'ENV PIP_INDEX_URL=http://deploy:abc123xyz@pypi.corp.internal/simple/',
    ].join('\n'));
    const violations = DV3043.check(ctx);
    expect(violations.length).toBe(1);
  });
});
