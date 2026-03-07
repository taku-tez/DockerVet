import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';

// ============================================================================
// Tests for diagnostic accuracy improvements (batch 2026-03-07)
// ============================================================================

// ---------------------------------------------------------------------------
// DV1007: BuildKit --mount=type=cache false positive fix
// ---------------------------------------------------------------------------
describe('DV1007 - BuildKit cache mount awareness', () => {
  it('does NOT flag apt-get install with --mount=type=cache', () => {
    const df = `FROM ubuntu:22.04
RUN --mount=type=cache,target=/var/cache/apt apt-get update && apt-get install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
  });

  it('does NOT flag yum install with --mount=type=cache', () => {
    const df = `FROM centos:7
RUN --mount=type=cache,target=/var/cache/yum yum install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
  });

  it('still flags apt-get install without cache cleanup or mount', () => {
    const df = `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV1007: zypper and tdnf support
// ---------------------------------------------------------------------------
describe('DV1007 - zypper/tdnf support', () => {
  it('flags zypper install without cleanup', () => {
    const df = `FROM opensuse/leap:15.5
RUN zypper install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(true);
  });

  it('does NOT flag zypper install with zypper clean', () => {
    const df = `FROM opensuse/leap:15.5
RUN zypper install -y curl && zypper clean --all`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
  });

  it('does NOT flag zypper install with rm /var/cache/zypp', () => {
    const df = `FROM opensuse/leap:15.5
RUN zypper install -y curl && rm -rf /var/cache/zypp`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
  });

  it('flags tdnf install without cleanup', () => {
    const df = `FROM photon:4.0
RUN tdnf install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(true);
  });

  it('does NOT flag tdnf install with tdnf clean all', () => {
    const df = `FROM photon:4.0
RUN tdnf install -y curl && tdnf clean all`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
  });

  it('does NOT flag zypper with --mount=type=cache', () => {
    const df = `FROM opensuse/leap:15.5
RUN --mount=type=cache,target=/var/cache/zypp zypper install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV1007')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV9005: BuildKit cache mount awareness
// ---------------------------------------------------------------------------
describe('DV9005 - BuildKit cache mount awareness', () => {
  it('does NOT flag apt-get install with --mount=type=cache', () => {
    const df = `FROM ubuntu:22.04
RUN --mount=type=cache,target=/var/cache/apt apt-get update && apt-get install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV9005')).toBe(false);
  });

  it('still flags apt-get install without cache cleanup', () => {
    const df = `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV9005')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV1003: Extended curl-pipe-to-shell detection
// ---------------------------------------------------------------------------
describe('DV1003 - Extended curl pipe detection', () => {
  it('flags curl | sudo bash', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/install.sh | sudo bash`;
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(true);
  });

  it('flags curl | sudo -E sh', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/install.sh | sudo -E sh`;
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(true);
  });

  it('flags curl | ENV=val bash', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/install.sh | INSTALL_DIR=/opt bash`;
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(true);
  });

  it('flags bash <(curl ...)', () => {
    const df = `FROM ubuntu:22.04
RUN bash <(curl -fsSL https://example.com/install.sh)`;
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(true);
  });

  it('flags bash -c "$(curl ...)"', () => {
    const df = `FROM ubuntu:22.04
RUN bash -c "$(curl -fsSL https://example.com/install.sh)"`;
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(true);
  });

  it('does NOT flag curl with no pipe to shell', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz`;
    expect(hasRule(lintDockerfile(df), 'DV1003')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV3012: New token patterns
// ---------------------------------------------------------------------------
describe('DV3012 - Expanded token pattern detection', () => {
  it('flags HashiCorp Vault service token', () => {
    const df = `FROM ubuntu:22.04
RUN curl -H "X-Vault-Token: hvs.CAESIJlFrKRdXg1234567890abcdefghijklmnopqrstuvwxyz" https://vault.example.com/v1/secret/data`;
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags Docker Hub PAT', () => {
    const df = `FROM ubuntu:22.04
RUN echo dckr_pat_abcdefghijklmnopqrstuvwxyz | docker login --username user --password-stdin`;
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags Google API key', () => {
    const df = `FROM ubuntu:22.04
RUN curl https://maps.googleapis.com/maps/api?key=AIzaSyAbcdefghij1234567890abcdefghijklm`;
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags OpenAI project API key', () => {
    const df = `FROM python:3.11
RUN pip install openai && echo sk-proj-abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrs > /tmp/key`;
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3033: HTTP URL detection (non-HTTPS downloads)
// ---------------------------------------------------------------------------
describe('DV3033 - HTTP URL detection', () => {
  it('flags ADD with HTTP URL', () => {
    const df = `FROM ubuntu:22.04
ADD http://example.com/package.tar.gz /tmp/`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(true);
  });

  it('does NOT flag ADD with HTTPS URL', () => {
    const df = `FROM ubuntu:22.04
ADD https://example.com/package.tar.gz /tmp/`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(false);
  });

  it('flags curl with HTTP URL in RUN', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL http://example.com/install.sh -o /tmp/install.sh`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(true);
  });

  it('flags wget with HTTP URL in RUN', () => {
    const df = `FROM ubuntu:22.04
RUN wget http://example.com/package.deb -O /tmp/package.deb`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(true);
  });

  it('does NOT flag localhost HTTP URLs', () => {
    const df = `FROM ubuntu:22.04
RUN curl http://localhost:8080/healthz`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(false);
  });

  it('does NOT flag 127.0.0.1 HTTP URLs', () => {
    const df = `FROM ubuntu:22.04
RUN curl http://127.0.0.1:3000/api/status`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(false);
  });

  it('does NOT flag RUN without HTTP URLs', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(false);
  });

  it('does NOT flag ADD with local file sources', () => {
    const df = `FROM ubuntu:22.04
COPY package.json /app/`;
    expect(hasRule(lintDockerfile(df), 'DV3033')).toBe(false);
  });
});
