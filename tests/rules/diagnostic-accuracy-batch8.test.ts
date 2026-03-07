import { describe, it, expect } from 'vitest';
import { lint } from '../../src/engine/linter';
import { parse } from '../../src/parser/parser';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };

function lintDockerfile(content: string, filePath?: string) {
  const ast = parse(content);
  return lint(ast, { config: defaultConfig, filePath });
}

function hasRule(violations: any[], ruleId: string): boolean {
  return violations.some(v => v.rule === ruleId);
}

describe('DV7006: Kernel parameter manipulation', () => {
  it('should flag echo to /proc/sys/', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN echo 1 > /proc/sys/net/ipv4/ip_forward
`);
    expect(hasRule(violations, 'DV7006')).toBe(true);
  });

  it('should flag tee to /proc/sys/', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN echo 0 | tee /proc/sys/kernel/randomize_va_space
`);
    expect(hasRule(violations, 'DV7006')).toBe(true);
  });

  it('should flag sysctl -w', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN sysctl -w net.ipv4.ip_forward=1
`);
    expect(hasRule(violations, 'DV7006')).toBe(true);
  });

  it('should flag sysctl without -w', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN sysctl net.core.somaxconn=65535
`);
    expect(hasRule(violations, 'DV7006')).toBe(true);
  });

  it('should NOT flag reading /proc/sys/ (cat)', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN cat /proc/sys/kernel/hostname
`);
    expect(hasRule(violations, 'DV7006')).toBe(false);
  });

  it('should NOT flag normal echo commands', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN echo "hello world"
`);
    expect(hasRule(violations, 'DV7006')).toBe(false);
  });

  it('should flag printf to /proc/sys/', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN printf "1" > /proc/sys/net/ipv4/ip_forward
`);
    expect(hasRule(violations, 'DV7006')).toBe(true);
  });
});

describe('DV7007: Process supervisor / multi-service container', () => {
  it('should flag supervisord installation via pip', () => {
    const violations = lintDockerfile(`
FROM python:3.11
RUN pip install supervisor
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag supervisord installation via apt', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN apt-get install -y supervisor
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag s6-overlay', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN apt-get install -y s6-overlay
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag runit installation', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN apt-get install -y runit
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag monit installation', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN apt-get install -y monit
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag cron daemon installation', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN apt-get install -y cron
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag dcron on Alpine', () => {
    const violations = lintDockerfile(`
FROM alpine:3.18
RUN apk add dcron
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag supervisord in CMD', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should flag supervisord in ENTRYPOINT', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
ENTRYPOINT ["/usr/bin/supervisord"]
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });

  it('should NOT flag normal apt-get install', () => {
    const violations = lintDockerfile(`
FROM ubuntu:22.04
RUN apt-get install -y curl nginx
`);
    expect(hasRule(violations, 'DV7007')).toBe(false);
  });

  it('should NOT flag normal CMD', () => {
    const violations = lintDockerfile(`
FROM node:18
CMD ["node", "server.js"]
`);
    expect(hasRule(violations, 'DV7007')).toBe(false);
  });

  it('should flag cronie on RHEL/CentOS', () => {
    const violations = lintDockerfile(`
FROM centos:8
RUN yum install -y cronie
`);
    expect(hasRule(violations, 'DV7007')).toBe(true);
  });
});
