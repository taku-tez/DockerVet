import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/parser';
import { lint } from '../../src/engine/linter';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };
const lintDockerfile = (content: string, config = defaultConfig) => {
  const ast = parse(content);
  return lint(ast, { config });
};
const hasRule = (violations: any[], rule: string) => violations.some(v => v.rule === rule);

describe('DL3000 - Absolute WORKDIR', () => {
  it('flags relative WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR app'), 'DL3000')).toBe(true);
  });
  it('passes absolute WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /app'), 'DL3000')).toBe(false);
  });
  it('allows variable WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR $HOME'), 'DL3000')).toBe(false);
  });
});

describe('DL3001 - Inappropriate commands', () => {
  it('flags ssh', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN ssh localhost'), 'DL3001')).toBe(true);
  });
  it('flags vim', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN vim file.txt'), 'DL3001')).toBe(true);
  });
  it('passes normal commands', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hello'), 'DL3001')).toBe(false);
  });
  it('does not flag BuildKit --mount syntax', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN --mount=type=cache,target=/root/.cache pip install -r requirements.txt'), 'DL3001')).toBe(false);
  });
  it('does not flag BuildKit --mount=type=bind', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN --mount=type=bind,source=.,target=/app make build'), 'DL3001')).toBe(false);
  });
  it('still flags mount command alongside --mount', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN --mount=type=cache,target=/tmp mount /dev/sda1 /mnt'), 'DL3001')).toBe(true);
  });
});

describe('DL3002 - Last USER not root', () => {
  it('flags root user', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nUSER root'), 'DL3002')).toBe(true);
  });
  it('flags UID 0', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nUSER 0'), 'DL3002')).toBe(true);
  });
  it('passes non-root', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nUSER nobody'), 'DL3002')).toBe(false);
  });
  it('passes when no USER', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DL3002')).toBe(false);
  });
});

describe('DL3003 - Use WORKDIR instead of cd', () => {
  it('flags cd usage', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN cd /app && make'), 'DL3003')).toBe(true);
  });
  it('passes without cd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN make'), 'DL3003')).toBe(false);
  });
});

describe('DL3004 - No sudo', () => {
  it('flags sudo', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN sudo apt-get update'), 'DL3004')).toBe(true);
  });
  it('passes without sudo', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update'), 'DL3004')).toBe(false);
  });
});

describe('DL3006 - Tag version explicitly', () => {
  it('flags untagged image', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu'), 'DL3006')).toBe(true);
  });
  it('passes tagged image', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04'), 'DL3006')).toBe(false);
  });
  it('passes digest', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu@sha256:abc'), 'DL3006')).toBe(false);
  });
  it('skips scratch', () => {
    expect(hasRule(lintDockerfile('FROM scratch'), 'DL3006')).toBe(false);
  });
  it('skips internal stage aliases', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.21 AS gobuild\nRUN go build\nFROM gobuild\nRUN echo hi'), 'DL3006')).toBe(false);
  });
});

describe('DL3007 - No latest tag', () => {
  it('flags latest', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:latest'), 'DL3007')).toBe(true);
  });
  it('passes specific tag', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04'), 'DL3007')).toBe(false);
  });
});

describe('DL3008 - Pin versions in apt-get', () => {
  it('flags unpinned apt-get install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install curl'), 'DL3008')).toBe(true);
  });
  it('passes pinned', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install curl=7.68.0'), 'DL3008')).toBe(false);
  });
});

describe('DL3009 - Delete apt-get lists', () => {
  it('flags missing rm', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y curl'), 'DL3009')).toBe(true);
  });
  it('passes with rm', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*'), 'DL3009')).toBe(false);
  });
});

describe('DL3010 - Use ADD for archives', () => {
  it('flags COPY of archive', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY archive.tar.gz /opt/'), 'DL3010')).toBe(true);
  });
  it('passes COPY of regular file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY app.js /opt/'), 'DL3010')).toBe(false);
  });
});

describe('DL3011 - Valid UNIX ports', () => {
  it('flags invalid port', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nEXPOSE 70000'), 'DL3011')).toBe(true);
  });
  it('passes valid port', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nEXPOSE 8080'), 'DL3011')).toBe(false);
  });
});

describe('DL3012 - Multiple HEALTHCHECK', () => {
  it('flags multiple', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD curl localhost\nHEALTHCHECK CMD wget localhost'), 'DL3012')).toBe(true);
  });
  it('passes single', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD curl localhost'), 'DL3012')).toBe(false);
  });
});

describe('DL3013 - Pin pip versions', () => {
  it('flags unpinned pip', () => {
    expect(hasRule(lintDockerfile('FROM python:3\nRUN pip install flask'), 'DL3013')).toBe(true);
  });
  it('passes pinned', () => {
    expect(hasRule(lintDockerfile('FROM python:3\nRUN pip install flask==2.0'), 'DL3013')).toBe(false);
  });
  it('passes requirements file', () => {
    expect(hasRule(lintDockerfile('FROM python:3\nRUN pip install -r requirements.txt'), 'DL3013')).toBe(false);
  });
});

describe('DL3014 - apt-get -y', () => {
  it('flags missing -y', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install curl'), 'DL3014')).toBe(true);
  });
  it('passes with -y', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y curl'), 'DL3014')).toBe(false);
  });
});

describe('DL3015 - --no-install-recommends', () => {
  it('flags missing flag', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y curl'), 'DL3015')).toBe(true);
  });
  it('passes with flag', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install -y --no-install-recommends curl'), 'DL3015')).toBe(false);
  });
});

describe('DL3016 - Pin npm versions', () => {
  it('flags unpinned npm', () => {
    expect(hasRule(lintDockerfile('FROM node:18\nRUN npm install express'), 'DL3016')).toBe(true);
  });
  it('passes pinned', () => {
    expect(hasRule(lintDockerfile('FROM node:18\nRUN npm install express@4.18.0'), 'DL3016')).toBe(false);
  });
});

describe('DL3018 - Pin apk versions', () => {
  it('flags unpinned apk', () => {
    expect(hasRule(lintDockerfile('FROM alpine:3\nRUN apk add curl'), 'DL3018')).toBe(true);
  });
  it('passes pinned', () => {
    expect(hasRule(lintDockerfile('FROM alpine:3\nRUN apk add curl=7.80.0-r0'), 'DL3018')).toBe(false);
  });
});

describe('DL3019 - apk --no-cache', () => {
  it('flags missing --no-cache', () => {
    expect(hasRule(lintDockerfile('FROM alpine:3\nRUN apk add curl=1.0'), 'DL3019')).toBe(true);
  });
  it('passes with --no-cache', () => {
    expect(hasRule(lintDockerfile('FROM alpine:3\nRUN apk add --no-cache curl=1.0'), 'DL3019')).toBe(false);
  });
});

describe('DL3020 - Use COPY instead of ADD', () => {
  it('flags ADD for regular files', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nADD app.js /opt/'), 'DL3020')).toBe(true);
  });
  it('passes ADD with URL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nADD https://example.com/file /opt/'), 'DL3020')).toBe(false);
  });
  it('passes ADD with archive', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nADD archive.tar.gz /opt/'), 'DL3020')).toBe(false);
  });
});

describe('DL3021 - COPY multiple sources needs / dest', () => {
  it('flags missing /', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY a.txt b.txt dest'), 'DL3021')).toBe(true);
  });
  it('passes with /', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY a.txt b.txt dest/'), 'DL3021')).toBe(false);
  });
});

describe('DL3023 - COPY --from self-reference', () => {
  it('flags self-reference', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04 AS builder\nCOPY --from=builder /a /b'), 'DL3023')).toBe(true);
  });
});

describe('DL3024 - Unique FROM aliases', () => {
  it('flags duplicate alias', () => {
    expect(hasRule(lintDockerfile('FROM node:18 AS builder\nRUN echo\nFROM ubuntu:20.04 AS builder'), 'DL3024')).toBe(true);
  });
  it('passes unique aliases', () => {
    expect(hasRule(lintDockerfile('FROM node:18 AS builder\nRUN echo\nFROM ubuntu:20.04 AS runner'), 'DL3024')).toBe(false);
  });
});

describe('DL3025 - JSON notation for CMD/ENTRYPOINT', () => {
  it('flags shell form CMD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCMD node app.js'), 'DL3025')).toBe(true);
  });
  it('passes JSON CMD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCMD ["node", "app.js"]'), 'DL3025')).toBe(false);
  });
  it('flags shell form ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENTRYPOINT node app.js'), 'DL3025')).toBe(true);
  });
});

describe('DL3026 - Allowed registries', () => {
  it('flags disallowed registry', () => {
    const v = lintDockerfile('FROM docker.io/ubuntu:20.04', { ...defaultConfig, trustedRegistries: ['gcr.io'] });
    expect(hasRule(v, 'DL3026')).toBe(true);
  });
  it('passes allowed registry', () => {
    const v = lintDockerfile('FROM gcr.io/myproject/myimage:1.0', { ...defaultConfig, trustedRegistries: ['gcr.io'] });
    expect(hasRule(v, 'DL3026')).toBe(false);
  });
  it('skips when no registries configured', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04'), 'DL3026')).toBe(false);
  });
});

describe('DL3027 - Use apt-get not apt', () => {
  it('flags apt install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt install curl'), 'DL3027')).toBe(true);
  });
  it('passes apt-get', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN apt-get install curl'), 'DL3027')).toBe(false);
  });
});

describe('DL3028 - Pin gem versions', () => {
  it('flags unpinned gem', () => {
    expect(hasRule(lintDockerfile('FROM ruby:3\nRUN gem install rails'), 'DL3028')).toBe(true);
  });
  it('does not flag gem with -v version', () => {
    const result = lintDockerfile('FROM ruby:3\nRUN gem install nokogiri -v 1.18.6');
    const dl3028 = result.filter(v => v.rule === 'DL3028');
    // Should flag nokogiri (unpinned name) but NOT 1.18.6
    expect(dl3028.some(v => v.message.includes('1.18.6'))).toBe(false);
  });
});

describe('DL3029 - No --platform with FROM', () => {
  it('flags --platform', () => {
    expect(hasRule(lintDockerfile('FROM --platform=linux/amd64 ubuntu:20.04'), 'DL3029')).toBe(true);
  });
  it('passes without --platform', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04'), 'DL3029')).toBe(false);
  });
});

describe('DL3030 - yum -y', () => {
  it('flags missing -y', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install curl'), 'DL3030')).toBe(true);
  });
  it('passes with -y', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install -y curl'), 'DL3030')).toBe(false);
  });
});

describe('DL3032 - yum clean all', () => {
  it('flags missing clean', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install -y curl'), 'DL3032')).toBe(true);
  });
  it('passes with clean', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install -y curl && yum clean all'), 'DL3032')).toBe(false);
  });
});

describe('DL3034 - zypper -y', () => {
  it('flags missing -y', () => {
    expect(hasRule(lintDockerfile('FROM opensuse:42\nRUN zypper install curl'), 'DL3034')).toBe(true);
  });
});

describe('DL3035 - No zypper dist-upgrade', () => {
  it('flags dist-upgrade', () => {
    expect(hasRule(lintDockerfile('FROM opensuse:42\nRUN zypper dist-upgrade'), 'DL3035')).toBe(true);
  });
});

describe('DL3036 - zypper clean', () => {
  it('flags missing clean', () => {
    expect(hasRule(lintDockerfile('FROM opensuse:42\nRUN zypper install -y curl'), 'DL3036')).toBe(true);
  });
});

describe('DL3038 - dnf -y', () => {
  it('flags missing -y', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN dnf install curl'), 'DL3038')).toBe(true);
  });
  it('passes with -y', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN dnf install -y curl'), 'DL3038')).toBe(false);
  });
});

describe('DL3040 - dnf clean all', () => {
  it('flags missing clean', () => {
    expect(hasRule(lintDockerfile('FROM fedora:35\nRUN dnf install -y curl'), 'DL3040')).toBe(true);
  });
});

describe('DL3042 - pip --no-cache-dir', () => {
  it('flags missing --no-cache-dir', () => {
    expect(hasRule(lintDockerfile('FROM python:3\nRUN pip install flask==2.0'), 'DL3042')).toBe(true);
  });
  it('passes with --no-cache-dir', () => {
    expect(hasRule(lintDockerfile('FROM python:3\nRUN pip install --no-cache-dir flask==2.0'), 'DL3042')).toBe(false);
  });
});

describe('DL3043 - ONBUILD FROM/MAINTAINER', () => {
  it('flags ONBUILD FROM', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nONBUILD FROM alpine'), 'DL3043')).toBe(true);
  });
  it('flags ONBUILD MAINTAINER', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nONBUILD MAINTAINER test'), 'DL3043')).toBe(true);
  });
  it('passes ONBUILD RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nONBUILD RUN echo hi'), 'DL3043')).toBe(false);
  });
});

describe('DL3044 - ENV self-reference', () => {
  it('flags self-reference', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV A=1 B=$A'), 'DL3044')).toBe(true);
  });
  it('passes independent vars', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nENV A=1 B=2'), 'DL3044')).toBe(false);
  });
});

describe('DL3045 - COPY relative without WORKDIR', () => {
  it('flags relative COPY without WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY app.js app/'), 'DL3045')).toBe(true);
  });
  it('passes with WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nWORKDIR /app\nCOPY app.js app/'), 'DL3045')).toBe(false);
  });
  it('passes absolute destination', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nCOPY app.js /app/'), 'DL3045')).toBe(false);
  });
});

describe('DL3046 - useradd without -l', () => {
  it('flags high UID without -l', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN useradd --uid 100000 testuser'), 'DL3046')).toBe(true);
  });
  it('passes normal UID', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN useradd --uid 1000 testuser'), 'DL3046')).toBe(false);
  });
});

describe('DL3047 - wget --progress', () => {
  it('flags wget without progress', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN wget http://example.com'), 'DL3047')).toBe(true);
  });
  it('passes with --progress', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN wget --progress=dot:giga http://example.com'), 'DL3047')).toBe(false);
  });
});

describe('DL3048 - Invalid label key', () => {
  it('flags invalid key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nLABEL -invalid="test"'), 'DL3048')).toBe(true);
  });
  it('passes valid key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nLABEL maintainer="test"'), 'DL3048')).toBe(false);
  });
});

describe('DL3049 - Label missing', () => {
  it('flags missing required label', () => {
    const v = lintDockerfile('FROM ubuntu:20.04\nLABEL version="1.0"', { ...defaultConfig, requiredLabels: ['maintainer'] });
    expect(hasRule(v, 'DL3049')).toBe(true);
  });
  it('passes when label present', () => {
    const v = lintDockerfile('FROM ubuntu:20.04\nLABEL maintainer="test"', { ...defaultConfig, requiredLabels: ['maintainer'] });
    expect(hasRule(v, 'DL3049')).toBe(false);
  });
});

describe('DL3057 - HEALTHCHECK missing', () => {
  it('flags missing HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nRUN echo'), 'DL3057')).toBe(true);
  });
  it('passes with HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:20.04\nHEALTHCHECK CMD curl localhost'), 'DL3057')).toBe(false);
  });
});
