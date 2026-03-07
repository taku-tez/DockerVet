import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';

// ============================================================================
// Diagnostic accuracy improvements batch 2 (2026-03-07)
// ============================================================================

// ---------------------------------------------------------------------------
// DV1001: False positive reduction for secret-management config variables
// ---------------------------------------------------------------------------
describe('DV1001 - Secret management config suffix FP reduction', () => {
  it('does NOT flag CREDENTIAL_STORE_TYPE=vault', () => {
    const df = `FROM ubuntu:22.04
ENV CREDENTIAL_STORE_TYPE=vault`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag SECRET_BACKEND=aws', () => {
    const df = `FROM ubuntu:22.04
ENV SECRET_BACKEND=aws`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag CREDENTIAL_PROVIDER=gcp', () => {
    const df = `FROM ubuntu:22.04
ENV CREDENTIAL_PROVIDER=gcp`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag PASSWORD_ENCODING=sha256', () => {
    const df = `FROM ubuntu:22.04
ENV PASSWORD_ENCODING=sha256`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag CREDENTIAL_HELPER=osxkeychain', () => {
    const df = `FROM ubuntu:22.04
ENV CREDENTIAL_HELPER=osxkeychain`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag TOKEN_STORE=redis', () => {
    const df = `FROM ubuntu:22.04
ENV TOKEN_STORE=redis`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag SECRET_ENGINE=transit', () => {
    const df = `FROM ubuntu:22.04
ENV SECRET_ENGINE=transit`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag AUTH_TOKEN_HANDLER=jwt', () => {
    const df = `FROM ubuntu:22.04
ENV AUTH_TOKEN_HANDLER=jwt`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag CREDENTIAL_MANAGER=keepass', () => {
    const df = `FROM ubuntu:22.04
ARG CREDENTIAL_MANAGER=keepass`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('does NOT flag PASSWORD_POLICY=strict', () => {
    const df = `FROM ubuntu:22.04
ENV PASSWORD_POLICY=strict`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(false);
  });

  it('still flags actual secrets like API_KEY=sk-12345abcdef', () => {
    const df = `FROM ubuntu:22.04
ENV API_KEY=sk-12345abcdef`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(true);
  });

  it('still flags PASSWORD=hunter2', () => {
    const df = `FROM ubuntu:22.04
ENV PASSWORD=hunter2`;
    expect(hasRule(lintDockerfile(df), 'DV1001')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3007: ENV-based TLS disabling detection
// ---------------------------------------------------------------------------
describe('DV3007 - ENV-based TLS disabling', () => {
  it('flags NODE_TLS_REJECT_UNAUTHORIZED=0', () => {
    const df = `FROM node:20
ENV NODE_TLS_REJECT_UNAUTHORIZED=0`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags PYTHONHTTPSVERIFY=0', () => {
    const df = `FROM python:3.11
ENV PYTHONHTTPSVERIFY=0`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags GIT_SSL_NO_VERIFY=true', () => {
    const df = `FROM ubuntu:22.04
ENV GIT_SSL_NO_VERIFY=true`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags GIT_SSL_NO_VERIFY=1', () => {
    const df = `FROM ubuntu:22.04
ENV GIT_SSL_NO_VERIFY=1`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags SSL_CERT_FILE=/dev/null', () => {
    const df = `FROM ubuntu:22.04
ENV SSL_CERT_FILE=/dev/null`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags REQUESTS_CA_BUNDLE=/dev/null', () => {
    const df = `FROM python:3.11
ENV REQUESTS_CA_BUNDLE=/dev/null`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags GONOSUMCHECK=*', () => {
    const df = `FROM golang:1.21
ENV GONOSUMCHECK=*`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('flags GOFLAGS with -insecure', () => {
    const df = `FROM golang:1.21
ENV GOFLAGS=-insecure`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(true);
  });

  it('does NOT flag NODE_TLS_REJECT_UNAUTHORIZED=1 (valid)', () => {
    const df = `FROM node:20
ENV NODE_TLS_REJECT_UNAUTHORIZED=1`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(false);
  });

  it('does NOT flag GIT_SSL_NO_VERIFY=false', () => {
    const df = `FROM ubuntu:22.04
ENV GIT_SSL_NO_VERIFY=false`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(false);
  });

  it('does NOT flag SSL_CERT_FILE with a real path', () => {
    const df = `FROM ubuntu:22.04
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(false);
  });

  it('does NOT flag GOFLAGS without -insecure', () => {
    const df = `FROM golang:1.21
ENV GOFLAGS=-mod=vendor`;
    expect(hasRule(lintDockerfile(df), 'DV3007')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV3034: Unsafe package manager configurations
// ---------------------------------------------------------------------------
describe('DV3034 - Unsafe package manager configurations', () => {
  it('flags npm config set audit false', () => {
    const df = `FROM node:20
RUN npm config set audit false && npm install`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(true);
  });

  it('flags npm install --force', () => {
    const df = `FROM node:20
RUN npm install --force`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(true);
  });

  it('flags yarn --skip-integrity-check', () => {
    const df = `FROM node:20
RUN yarn install --skip-integrity-check`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(true);
  });

  it('flags pip install with HTTP index URL', () => {
    const df = `FROM python:3.11
RUN pip install --index-url http://pypi.internal.com/simple/ requests`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(true);
  });

  it('flags pip install with -i HTTP URL', () => {
    const df = `FROM python:3.11
RUN pip install -i http://pypi.internal.com/simple/ requests`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(true);
  });

  it('flags gem sources -a http://', () => {
    const df = `FROM ruby:3.2
RUN gem sources -a http://rubygems.internal.com/`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(true);
  });

  it('does NOT flag normal npm install', () => {
    const df = `FROM node:20
RUN npm install`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(false);
  });

  it('does NOT flag pip install with HTTPS index', () => {
    const df = `FROM python:3.11
RUN pip install --index-url https://pypi.internal.com/simple/ requests`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(false);
  });

  it('does NOT flag yarn install without flags', () => {
    const df = `FROM node:20
RUN yarn install --frozen-lockfile`;
    expect(hasRule(lintDockerfile(df), 'DV3034')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV4026: Shell-form ENTRYPOINT detection
// ---------------------------------------------------------------------------
describe('DV4026 - Shell form ENTRYPOINT', () => {
  it('flags shell-form ENTRYPOINT', () => {
    const df = `FROM node:20
ENTRYPOINT node server.js`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(true);
  });

  it('flags shell-form ENTRYPOINT with path', () => {
    const df = `FROM ubuntu:22.04
ENTRYPOINT /usr/bin/my-app --config /etc/app.conf`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(true);
  });

  it('does NOT flag exec-form ENTRYPOINT', () => {
    const df = `FROM node:20
ENTRYPOINT ["node", "server.js"]`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(false);
  });

  it('does NOT flag shell-form ENTRYPOINT with exec prefix', () => {
    const df = `FROM node:20
ENTRYPOINT exec node server.js`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(false);
  });

  it('does NOT flag shell-form ENTRYPOINT with tini', () => {
    const df = `FROM node:20
ENTRYPOINT tini -- node server.js`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(false);
  });

  it('does NOT flag shell-form ENTRYPOINT with dumb-init', () => {
    const df = `FROM node:20
ENTRYPOINT dumb-init node server.js`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(false);
  });

  it('only checks last stage', () => {
    const df = `FROM node:20 AS builder
ENTRYPOINT node build.js
FROM node:20-slim
ENTRYPOINT ["node", "server.js"]`;
    expect(hasRule(lintDockerfile(df), 'DV4026')).toBe(false);
  });
});
