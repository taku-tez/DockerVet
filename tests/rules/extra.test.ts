import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';
import { parse } from '../../src/parser/parser';

describe('DL3033 - yum version pinning', () => {
  it('flags unpinned yum package', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install curl'), 'DL3033')).toBe(true);
  });
});

describe('DL3037 - zypper version pinning', () => {
  it('flags unpinned zypper package', () => {
    expect(hasRule(lintDockerfile('FROM opensuse:42\nRUN zypper install -y curl'), 'DL3037')).toBe(true);
  });
  it('passes pinned', () => {
    expect(hasRule(lintDockerfile('FROM opensuse:42\nRUN zypper install -y curl=7.0'), 'DL3037')).toBe(false);
  });
});

describe('DL3041 - dnf version pinning', () => {
  it('flags unpinned dnf package', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN dnf install -y curl'), 'DL3041')).toBe(true);
  });
  it('does not flag microdnf packages', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN microdnf install -y curl'), 'DL3041')).toBe(false);
  });
  it('does not flag backslash line continuations as packages', () => {
    const df = 'FROM fedora:35\nRUN dnf install -y \\\n  curl-7.79.1 \\\n  wget-1.21';
    expect(hasRule(lintDockerfile(df), 'DL3041')).toBe(false);
  });
  it('does not flag tdnf packages (Photon OS)', () => {
    expect(hasRule(lintDockerfile('FROM photon:5.0\nRUN tdnf install -y nginx shadow'), 'DL3041')).toBe(false);
  });
  it('does not flag /dev/null as a package (shell redirection)', () => {
    const df = 'FROM fedora:35\nRUN dnf install -y curl-7.79.1 >> /dev/null';
    expect(hasRule(lintDockerfile(df), 'DL3041')).toBe(false);
  });
});

describe('DL3050 - Superfluous labels', () => {
  it('flags extra labels', () => {
    const v = lintDockerfile('FROM ubuntu:20.04\nLABEL foo="bar"', { ...defaultConfig, allowedLabels: ['maintainer'] });
    expect(hasRule(v, 'DL3050')).toBe(true);
  });
  it('passes allowed labels', () => {
    const v = lintDockerfile('FROM ubuntu:20.04\nLABEL maintainer="test"', { ...defaultConfig, allowedLabels: ['maintainer'] });
    expect(hasRule(v, 'DL3050')).toBe(false);
  });
});

describe('Additional parser tests', () => {
  it('handles COPY with chown', () => {
    const ast = parse('FROM ubuntu:20.04\nCOPY --chown=1000:1000 app.js /app/');
    const inst = ast.stages[0].instructions[0] as any;
    expect(inst.chown).toBe('1000:1000');
  });

  it('handles multiple FROM stages', () => {
    const ast = parse('FROM node:18 AS a\nFROM node:18 AS b\nFROM node:18 AS c');
    expect(ast.stages.length).toBe(3);
  });

  it('parses complex RUN with continuation', () => {
    const ast = parse('FROM ubuntu:20.04\nRUN apt-get update \\\n    && apt-get install -y curl \\\n    && rm -rf /var/lib/apt/lists/*');
    expect(ast.stages[0].instructions[0].arguments).toContain('apt-get update');
    expect(ast.stages[0].instructions[0].arguments).toContain('rm -rf');
  });

  it('handles LABEL with multiple pairs', () => {
    const ast = parse('FROM ubuntu:20.04\nLABEL a="1" b="2" c="3"');
    const inst = ast.stages[0].instructions[0] as any;
    expect(inst.pairs.length).toBe(3);
  });

  it('handles EXPOSE multiple ports', () => {
    const ast = parse('FROM ubuntu:20.04\nEXPOSE 80 443 8080');
    const inst = ast.stages[0].instructions[0] as any;
    expect(inst.ports.length).toBe(3);
  });
});

describe('Additional rule edge cases', () => {
  it('DL3001 does not flag openssh-server install', () => {
    // "ssh" in "openssh-server" should not trigger
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install openssh-client'), 'DL3001')).toBe(false);
  });

  it('DL3003 does not flag cd inside commands', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN echo "cd /tmp"'), 'DL3003')).toBe(false);
  });

  it('DV1001 does not flag empty password', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV DB_PASSWORD='), 'DV1001')).toBe(false);
  });

  it('DL3025 passes JSON ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENTRYPOINT ["node"]'), 'DL3025')).toBe(false);
  });

  it('DV1003 does not flag curl without pipe', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN curl -LO https://example.com/file'), 'DV1003')).toBe(false);
  });

  it('DL3007 does not flag non-latest tags', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:focal'), 'DL3007')).toBe(false);
  });

  it('DL3000 allows variable WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nWORKDIR ${APP_DIR}'), 'DL3000')).toBe(false);
  });

  it('DL3020 flags ADD for non-archive files', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nADD config.json /etc/'), 'DL3020')).toBe(true);
  });

  it('DL3022 passes COPY --from with numeric', () => {
    expect(hasRule(lintDockerfile('FROM node:18\nRUN echo\nFROM ubuntu:20.04\nCOPY --from=0 /a /b'), 'DL3022')).toBe(false);
  });

  it('DV1006 does not flag multi-stage intermediate stages', () => {
    // Only last stage matters
    const v = lintDockerfile('FROM node:18 AS builder\nRUN echo\nFROM nginx:alpine\nUSER nginx');
    expect(hasRule(v, 'DV1006')).toBe(false);
  });

  it('DV1008 does not flag COPY --from=stage .', () => {
    expect(hasRule(lintDockerfile('FROM node:18 AS b\nRUN echo\nFROM ubuntu:20.04\nCOPY --from=b . /app'), 'DV1008')).toBe(false);
  });

  it('DL3013 passes pip install with whl file', () => {
    expect(hasRule(lintDockerfile('FROM python:3\nRUN pip install package.whl'), 'DL3013')).toBe(false);
  });

  it('DL3016 passes npm install with local path', () => {
    expect(hasRule(lintDockerfile('FROM node:18\nRUN npm install ./local-pkg'), 'DL3016')).toBe(false);
  });

  it('DL3018 with --no-cache and unpinned still triggers DL3018', () => {
    expect(hasRule(lintDockerfile('FROM alpine:3\nRUN apk add --no-cache curl'), 'DL3018')).toBe(true);
  });

  it('DV1009 flags untagged image without digest', () => {
    expect(hasRule(lintDockerfile('FROM node'), 'DV1009')).toBe(true);
  });

  it('DL3044 does not flag single ENV pair', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV A=$B'), 'DL3044')).toBe(false);
  });

  it('DL3043 passes ONBUILD RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nONBUILD RUN echo'), 'DL3043')).toBe(false);
  });

  it('DL3012 passes single HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD true'), 'DL3012')).toBe(false);
  });

  it('DV1010 flags curl -k in HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD curl -k https://localhost/health'), 'DV1010')).toBe(true);
  });

  it('DV1010 flags curl --insecure in HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD curl --insecure https://localhost/health'), 'DV1010')).toBe(true);
  });

  it('DV1010 passes curl without -k in HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD curl http://localhost/health'), 'DV1010')).toBe(false);
  });

  it('DL3047 does not flag apt-get install wget', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get update && apt-get install -y wget'), 'DL3047')).toBe(false);
  });

  it('DL3047 flags wget usage without --progress', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN wget https://example.com/file.tar.gz'), 'DL3047')).toBe(true);
  });
});
