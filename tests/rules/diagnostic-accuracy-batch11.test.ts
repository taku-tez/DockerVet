import { describe, it, expect } from 'vitest';
import { ALL_RULES } from '../../src/rules';
import { parse } from '../../src/parser/parser';
import { Violation } from '../../src/rules/types';

function lint(dockerfile: string): Violation[] {
  const ast = parse(dockerfile);
  const ctx = { ast, trustedRegistries: [], requiredLabels: [] };
  return ALL_RULES.flatMap(r => r.check(ctx));
}

function hasRule(violations: Violation[], ruleId: string): boolean {
  return violations.some(v => v.rule === ruleId);
}

// ===========================================================================
// DV9008: RUN cd <dir> instead of WORKDIR
// ===========================================================================
describe('DV9008: RUN cd instead of WORKDIR', () => {
  it('should flag RUN cd <dir> && at start of command', () => {
    const violations = lint(`
FROM node:18
RUN cd /app && npm install
`);
    expect(hasRule(violations, 'DV9008')).toBe(true);
  });

  it('should flag RUN cd with longer path', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN cd /opt/myapp && ./configure && make install
`);
    expect(hasRule(violations, 'DV9008')).toBe(true);
  });

  it('should NOT flag WORKDIR usage (correct pattern)', () => {
    const violations = lint(`
FROM node:18
WORKDIR /app
RUN npm install
`);
    expect(hasRule(violations, 'DV9008')).toBe(false);
  });

  it('should NOT flag cd within a subshell or unrelated context', () => {
    const violations = lint(`
FROM node:18
RUN echo "cd /app is a command"
`);
    expect(hasRule(violations, 'DV9008')).toBe(false);
  });

  it('should flag cd after && in a chain', () => {
    const violations = lint(`
FROM ubuntu:22.04
RUN apt-get update && cd /src && make
`);
    expect(hasRule(violations, 'DV9008')).toBe(true);
  });
});

// ===========================================================================
// DV4029: ARG before FROM not re-declared in stage
// ===========================================================================
describe('DV4029: ARG before FROM scope loss', () => {
  it('should flag ARG used in RUN but only defined before FROM', () => {
    const violations = lint(`
ARG APP_VERSION=1.0
FROM ubuntu:22.04
RUN echo $APP_VERSION
`);
    expect(hasRule(violations, 'DV4029')).toBe(true);
  });

  it('should NOT flag when ARG is re-declared after FROM', () => {
    const violations = lint(`
ARG APP_VERSION=1.0
FROM ubuntu:22.04
ARG APP_VERSION
RUN echo $APP_VERSION
`);
    expect(hasRule(violations, 'DV4029')).toBe(false);
  });

  it('should NOT flag ARG used only in FROM instruction', () => {
    const violations = lint(`
ARG BASE_TAG=22.04
FROM ubuntu:$BASE_TAG
RUN echo hello
`);
    // The ARG is used in FROM, not in stage instructions — no violation
    expect(hasRule(violations, 'DV4029')).toBe(false);
  });

  it('should NOT flag automatic platform ARGs like TARGETARCH', () => {
    const violations = lint(`
ARG TARGETARCH
FROM ubuntu:22.04
RUN echo $TARGETARCH
`);
    expect(hasRule(violations, 'DV4029')).toBe(false);
  });

  it('should flag in multi-stage builds for unreferenced global ARG', () => {
    const violations = lint(`
ARG MY_VAR=test
FROM node:18 AS builder
RUN echo $MY_VAR
FROM node:18-slim
COPY --from=builder /app /app
RUN echo $MY_VAR
`);
    // Should flag in both stages
    const dv4029 = violations.filter(v => v.rule === 'DV4029');
    expect(dv4029.length).toBeGreaterThanOrEqual(2);
  });

  it('should NOT flag when variable is set as ENV', () => {
    const violations = lint(`
ARG APP_VERSION=1.0
FROM ubuntu:22.04
ENV APP_VERSION=2.0
RUN echo $APP_VERSION
`);
    expect(hasRule(violations, 'DV4029')).toBe(false);
  });
});
