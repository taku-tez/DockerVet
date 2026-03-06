import { describe, it, expect } from 'vitest';
import { DV9001, DV9002, DV9003, DV9004, DV9005, DV9006 } from '../../src/rules/dv/build-hygiene';
import { parse } from '../../src/parser/parser';
import { RuleContext } from '../../src/rules/types';

function ctx(dockerfile: string, filePath = 'Dockerfile'): RuleContext {
  return { ast: parse(dockerfile), filePath };
}

describe('DV9001: Sensitive file COPY', () => {
  it('detects COPY .env', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY .env /app/.env'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.env file');
  });

  it('detects COPY .env.production', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY .env.production /app/'));
    expect(v.length).toBe(1);
  });

  it('detects COPY .git/', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY .git/ /app/.git/'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.git directory');
  });

  it('detects COPY id_rsa', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY id_rsa /root/.ssh/id_rsa'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('SSH private key');
  });

  it('detects COPY of .npmrc', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY .npmrc /app/.npmrc'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.npmrc');
  });

  it('does not flag COPY --from (multi-stage)', () => {
    const v = DV9001.check(ctx('FROM node:22 AS build\nRUN echo hi\nFROM node:22\nCOPY --from=build /app/.env /app/.env'));
    expect(v.length).toBe(0);
  });

  it('does not flag COPY of non-sensitive files', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY package.json /app/'));
    expect(v.length).toBe(0);
  });

  it('does not flag COPY . (broad copy)', () => {
    // DV9001 skips "." because it's too broad to classify as sensitive
    const v = DV9001.check(ctx('FROM node:22\nCOPY . /app/'));
    expect(v.length).toBe(0);
  });

  it('detects COPY of .pem files', () => {
    const v = DV9001.check(ctx('FROM node:22\nCOPY server.pem /etc/ssl/'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('private key file');
  });

  it('detects ADD of sensitive files too', () => {
    const v = DV9001.check(ctx('FROM node:22\nADD .aws/ /root/.aws/'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('.aws');
  });
});

describe('DV9002: Broad context COPY', () => {
  it('detects COPY . /app', () => {
    const v = DV9002.check(ctx('FROM node:22\nCOPY . /app/'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('entire build context');
  });

  it('detects COPY ./ /app', () => {
    const v = DV9002.check(ctx('FROM node:22\nCOPY ./ /app/'));
    expect(v.length).toBe(1);
  });

  it('does not flag specific copies', () => {
    const v = DV9002.check(ctx('FROM node:22\nCOPY package.json /app/'));
    expect(v.length).toBe(0);
  });

  it('does not flag COPY --from', () => {
    const v = DV9002.check(ctx('FROM node:22 AS build\nRUN echo hi\nFROM node:22\nCOPY --from=build . /app/'));
    expect(v.length).toBe(0);
  });
});

describe('DV9003: ADD vs COPY', () => {
  it('flags ADD for local files', () => {
    const v = DV9003.check(ctx('FROM node:22\nADD package.json /app/'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('Use COPY instead of ADD');
  });

  it('does not flag ADD for URLs', () => {
    const v = DV9003.check(ctx('FROM node:22\nADD https://example.com/file.tar.gz /tmp/'));
    expect(v.length).toBe(0);
  });

  it('does not flag ADD for tar files', () => {
    const v = DV9003.check(ctx('FROM node:22\nADD archive.tar.gz /app/'));
    expect(v.length).toBe(0);
  });

  it('flags ADD for non-tar, non-URL files', () => {
    const v = DV9003.check(ctx('FROM node:22\nADD config.yaml /app/'));
    expect(v.length).toBe(1);
  });
});

describe('DV9004: Missing LABEL', () => {
  it('flags when no LABEL instructions exist', () => {
    const v = DV9004.check(ctx('FROM node:22\nRUN echo hi'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('No LABEL');
  });

  it('does not flag when LABEL exists', () => {
    const v = DV9004.check(ctx('FROM node:22\nLABEL maintainer="test"'));
    expect(v.length).toBe(0);
  });
});

describe('DV9005: Package cache not cleaned', () => {
  it('flags apt-get install without cleanup', () => {
    const v = DV9005.check(ctx('FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y curl'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('apt-get install');
  });

  it('does not flag apt-get install with apt-get clean', () => {
    const v = DV9005.check(ctx('FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*'));
    expect(v.length).toBe(0);
  });

  it('does not flag apt-get install with rm of lists', () => {
    const v = DV9005.check(ctx('FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*'));
    expect(v.length).toBe(0);
  });

  it('flags yum install without cleanup', () => {
    const v = DV9005.check(ctx('FROM centos:7\nRUN yum install -y curl'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('yum/dnf install');
  });

  it('does not flag yum install with clean', () => {
    const v = DV9005.check(ctx('FROM centos:7\nRUN yum install -y curl && yum clean all'));
    expect(v.length).toBe(0);
  });

  it('flags dnf install without cleanup', () => {
    const v = DV9005.check(ctx('FROM fedora:39\nRUN dnf install -y curl'));
    expect(v.length).toBe(1);
  });
});

describe('DV9006: Multi-stage without COPY --from', () => {
  it('flags multi-stage without COPY --from in final stage', () => {
    const v = DV9006.check(ctx('FROM node:22 AS build\nRUN npm build\nFROM nginx:1.27\nCOPY nginx.conf /etc/nginx/'));
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('does not COPY --from');
  });

  it('does not flag multi-stage with COPY --from', () => {
    const v = DV9006.check(ctx('FROM node:22 AS build\nRUN npm build\nFROM nginx:1.27\nCOPY --from=build /app/dist /usr/share/nginx/html'));
    expect(v.length).toBe(0);
  });

  it('does not flag single-stage', () => {
    const v = DV9006.check(ctx('FROM node:22\nRUN npm build'));
    expect(v.length).toBe(0);
  });

  it('does not flag when final FROM references a stage alias', () => {
    const v = DV9006.check(ctx('FROM node:22 AS base\nRUN echo hi\nFROM base\nRUN echo done'));
    expect(v.length).toBe(0);
  });
});
