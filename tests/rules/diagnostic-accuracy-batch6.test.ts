import { describe, it, expect } from 'vitest';
import { scanDockerfileContent } from '../../src/lib';

// ---------------------------------------------------------------------------
// DV3039: Hardcoded credentials in HEALTHCHECK commands
// ---------------------------------------------------------------------------
describe('DV3039 - HEALTHCHECK credentials', () => {
  it('detects URL with embedded credentials in HEALTHCHECK', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nHEALTHCHECK CMD curl http://admin:secret123@localhost:8080/health\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3039');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('embedded credentials');
  });

  it('detects Authorization header in HEALTHCHECK', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nHEALTHCHECK CMD curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbiI6InRlc3QifQ" http://localhost:8080/health\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3039');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('authorization');
  });

  it('detects --password flag in HEALTHCHECK', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nHEALTHCHECK CMD mysqladmin ping --password supersecretpassword\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3039');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('password');
  });

  it('does not flag clean HEALTHCHECK without credentials', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nHEALTHCHECK CMD curl -f http://localhost:8080/health\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3039');
    expect(v.length).toBe(0);
  });

  it('does not flag HEALTHCHECK NONE', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nHEALTHCHECK NONE\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3039');
    expect(v.length).toBe(0);
  });

  it('detects credentials in HEALTHCHECK with --interval flags', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nHEALTHCHECK --interval=30s --timeout=5s CMD curl http://user:pass@localhost/health\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3039');
    expect(v.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// DV3040: Package manager config file COPY leaks credentials
// ---------------------------------------------------------------------------
describe('DV3040 - Package manager config COPY', () => {
  it('detects COPY .npmrc', () => {
    const result = scanDockerfileContent(
      'FROM node:18\nCOPY .npmrc /app/.npmrc\nRUN npm install',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.npmrc');
  });

  it('detects COPY .pypirc', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nCOPY .pypirc /root/.pypirc\nRUN pip install mypackage',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.pypirc');
  });

  it('detects COPY pip.conf', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nCOPY pip.conf /etc/pip.conf\nRUN pip install mypackage',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('pip.conf');
  });

  it('detects COPY .docker/config.json', () => {
    const result = scanDockerfileContent(
      'FROM ubuntu:22.04\nCOPY .docker/config.json /root/.docker/config.json\nUSER nobody',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('config.json');
  });

  it('detects COPY .cargo/credentials', () => {
    const result = scanDockerfileContent(
      'FROM rust:1.77\nCOPY .cargo/credentials /root/.cargo/credentials\nRUN cargo publish',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('credentials');
  });

  it('does not flag normal COPY commands', () => {
    const result = scanDockerfileContent(
      'FROM node:18\nCOPY package.json /app/\nCOPY src/ /app/src/\nRUN npm install',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(0);
  });

  it('detects ADD .npmrc', () => {
    const result = scanDockerfileContent(
      'FROM node:18\nADD .npmrc /app/.npmrc\nRUN npm install',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
  });

  it('detects .yarnrc.yml', () => {
    const result = scanDockerfileContent(
      'FROM node:18\nCOPY .yarnrc.yml /app/.yarnrc.yml\nRUN yarn install',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.yarnrc.yml');
  });

  it('detects .gem/credentials', () => {
    const result = scanDockerfileContent(
      'FROM ruby:3.2\nCOPY .gem/credentials /root/.gem/credentials\nRUN gem push my-gem.gem',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
  });

  it('detects .nuget/NuGet.Config', () => {
    const result = scanDockerfileContent(
      'FROM mcr.microsoft.com/dotnet/sdk:8.0\nCOPY .nuget/NuGet.Config /root/.nuget/NuGet.Config\nRUN dotnet restore',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV3040');
    expect(v.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// DV6021: pip --extra-index-url dependency confusion
// ---------------------------------------------------------------------------
describe('DV6021 - pip --extra-index-url dependency confusion', () => {
  it('detects pip install --extra-index-url', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nRUN pip install --extra-index-url https://pypi.internal.corp/simple my-internal-package',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6021');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('dependency confusion');
  });

  it('detects pip3 install --extra-index-url', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nRUN pip3 install --extra-index-url https://private.repo/simple pkg',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6021');
    expect(v.length).toBe(1);
  });

  it('does not flag pip install --index-url (safe replacement)', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nRUN pip install --index-url https://pypi.internal.corp/simple my-internal-package',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6021');
    expect(v.length).toBe(0);
  });

  it('does not flag pip install without extra index', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nRUN pip install flask==2.0.0',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6021');
    expect(v.length).toBe(0);
  });

  it('detects --extra-index-url in multi-command RUN', () => {
    const result = scanDockerfileContent(
      'FROM python:3.12\nRUN apt-get update && pip install --extra-index-url https://corp/simple pkg && apt-get clean',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6021');
    expect(v.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// DV6022: Go module proxy/checksum bypass
// ---------------------------------------------------------------------------
describe('DV6022 - Go module proxy bypass', () => {
  it('detects GOPROXY=direct in ENV', () => {
    const result = scanDockerfileContent(
      'FROM golang:1.22\nENV GOPROXY=direct\nRUN go build .',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6022');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('GOPROXY=direct');
  });

  it('does not flag GOPROXY with proxy.golang.org included', () => {
    const result = scanDockerfileContent(
      'FROM golang:1.22\nENV GOPROXY=https://proxy.golang.org,direct\nRUN go build .',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6022');
    expect(v.length).toBe(0);
  });

  it('detects GONOSUMDB in ENV', () => {
    const result = scanDockerfileContent(
      'FROM golang:1.22\nENV GONOSUMDB=github.com/internal/*\nRUN go build .',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6022');
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('GONOSUMDB');
  });

  it('detects inline GOPROXY=direct in RUN', () => {
    const result = scanDockerfileContent(
      'FROM golang:1.22\nRUN GOPROXY=direct go install github.com/some/tool@latest',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6022');
    expect(v.length).toBe(1);
  });

  it('does not flag normal go build without proxy bypass', () => {
    const result = scanDockerfileContent(
      'FROM golang:1.22\nRUN go build -o /app .',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6022');
    expect(v.length).toBe(0);
  });

  it('does not flag GOPROXY=off (explicit rejection, not bypass)', () => {
    const result = scanDockerfileContent(
      'FROM golang:1.22\nENV GOPROXY=off\nRUN go build .',
      'Dockerfile',
    );
    const v = result.violations.filter(v => v.rule === 'DV6022');
    expect(v.length).toBe(0);
  });
});
