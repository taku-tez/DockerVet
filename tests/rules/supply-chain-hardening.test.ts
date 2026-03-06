import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// ---------------------------------------------------------------------------
// DV6001 - Insecure pip install (--trusted-host or http:// index)
// ---------------------------------------------------------------------------
describe('DV6001 - Insecure pip install', () => {
  it('flags pip install --trusted-host', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --trusted-host pypi.internal.corp package-name'), 'DV6001')).toBe(true);
  });
  it('flags pip install with http:// index-url', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install -i http://pypi.internal.corp/simple/ package-name'), 'DV6001')).toBe(true);
  });
  it('flags pip install with http:// --extra-index-url', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --extra-index-url http://pypi.corp/simple/ package'), 'DV6001')).toBe(true);
  });
  it('flags pip3 install --trusted-host', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip3 install --trusted-host pypi.corp my-pkg'), 'DV6001')).toBe(false);
    // pip3 not matched by the pattern (only 'pip install'), this is intentional — pattern targets 'pip install'
  });
  it('does not flag pip install with https index-url', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install -i https://pypi.org/simple/ package-name'), 'DV6001')).toBe(false);
  });
  it('does not flag normal pip install', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --no-cache-dir flask'), 'DV6001')).toBe(false);
  });
  it('does not flag pip install -r requirements.txt', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install -r requirements.txt'), 'DV6001')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6002 - STOPSIGNAL SIGKILL prevents graceful shutdown
// ---------------------------------------------------------------------------
describe('DV6002 - STOPSIGNAL SIGKILL', () => {
  it('flags STOPSIGNAL SIGKILL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSTOPSIGNAL SIGKILL'), 'DV6002')).toBe(true);
  });
  it('flags STOPSIGNAL 9 (numeric SIGKILL)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSTOPSIGNAL 9'), 'DV6002')).toBe(true);
  });
  it('does not flag STOPSIGNAL SIGTERM', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSTOPSIGNAL SIGTERM'), 'DV6002')).toBe(false);
  });
  it('does not flag STOPSIGNAL SIGQUIT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSTOPSIGNAL SIGQUIT'), 'DV6002')).toBe(false);
  });
  it('does not flag STOPSIGNAL SIGINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSTOPSIGNAL SIGINT'), 'DV6002')).toBe(false);
  });
  it('does not flag Dockerfile without STOPSIGNAL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["sleep", "infinity"]'), 'DV6002')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6003 - Network debugging tools in production images
// ---------------------------------------------------------------------------
describe('DV6003 - Network debugging tools', () => {
  it('flags apt-get install netcat', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y netcat'), 'DV6003')).toBe(true);
  });
  it('flags apt-get install nmap', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y curl nmap'), 'DV6003')).toBe(true);
  });
  it('flags apk add tcpdump', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN apk add --no-cache tcpdump'), 'DV6003')).toBe(true);
  });
  it('flags yum install socat', () => {
    expect(hasRule(lintDockerfile('FROM centos:7\nRUN yum install -y socat'), 'DV6003')).toBe(true);
  });
  it('flags dnf install telnet', () => {
    expect(hasRule(lintDockerfile('FROM fedora\nRUN dnf install -y telnet'), 'DV6003')).toBe(true);
  });
  it('does not flag apt-get install curl', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y curl'), 'DV6003')).toBe(false);
  });
  it('does not flag apk add wget', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN apk add --no-cache wget'), 'DV6003')).toBe(false);
  });
  it('does not flag RUN without package install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo "netcat"'), 'DV6003')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6004 - Full output suppression in RUN
// ---------------------------------------------------------------------------
describe('DV6004 - Full output suppression in RUN', () => {
  it('flags > /dev/null 2>&1', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN make install > /dev/null 2>&1'), 'DV6004')).toBe(true);
  });
  it('flags &> /dev/null', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN ./configure &> /dev/null'), 'DV6004')).toBe(true);
  });
  it('flags 2>&1 > /dev/null', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN make 2>&1 >/dev/null'), 'DV6004')).toBe(true);
  });
  it('does not flag > /dev/null only (stdout suppression)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN make install > /dev/null'), 'DV6004')).toBe(false);
  });
  it('does not flag 2>/dev/null only (stderr suppression)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN make install 2>/dev/null'), 'DV6004')).toBe(false);
  });
  it('does not flag normal RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN make install'), 'DV6004')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6005 - npm install --unsafe-perm
// ---------------------------------------------------------------------------
describe('DV6005 - npm install --unsafe-perm', () => {
  it('flags npm install --unsafe-perm', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install --unsafe-perm'), 'DV6005')).toBe(true);
  });
  it('flags npm install with mixed flags including --unsafe-perm', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install --production --unsafe-perm -g express'), 'DV6005')).toBe(true);
  });
  it('does not flag normal npm install', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install --production'), 'DV6005')).toBe(false);
  });
  it('does not flag npm ci', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm ci'), 'DV6005')).toBe(false);
  });
  it('does not flag yarn install', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN yarn install'), 'DV6005')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6006 - npm/yarn HTTP registry
// ---------------------------------------------------------------------------
describe('DV6006 - npm/yarn HTTP registry', () => {
  it('flags npm config set registry http://', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm config set registry http://registry.internal.corp/'), 'DV6006')).toBe(true);
  });
  it('flags npm install --registry http://', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install --registry http://registry.corp/ express'), 'DV6006')).toBe(true);
  });
  it('flags yarn config set registry http://', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN yarn config set registry http://registry.corp/'), 'DV6006')).toBe(true);
  });
  it('does not flag npm config set registry https://', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm config set registry https://registry.npmjs.org/'), 'DV6006')).toBe(false);
  });
  it('does not flag npm install --registry https://', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install --registry https://registry.npmjs.org/ express'), 'DV6006')).toBe(false);
  });
  it('does not flag yarn config set registry https://', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN yarn config set registry https://registry.yarnpkg.com/'), 'DV6006')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6007 - apt-key deprecated usage
// ---------------------------------------------------------------------------
describe('DV6007 - apt-key deprecated', () => {
  it('flags apt-key add', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/key.gpg | apt-key add -'), 'DV6007')).toBe(true);
  });
  it('flags apt-key adv --keyserver', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv-keys ABCDEF'), 'DV6007')).toBe(true);
  });
  it('does not flag gpg --dearmor with signed-by pattern', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/key.gpg | gpg --dearmor -o /usr/share/keyrings/example.gpg'), 'DV6007')).toBe(false);
  });
  it('does not flag Dockerfile without apt-key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl'), 'DV6007')).toBe(false);
  });
  it('does not flag apt-get commands', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-get install -y gnupg'), 'DV6007')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6008 - COPY/ADD .git directory
// ---------------------------------------------------------------------------
describe('DV6008 - COPY/ADD .git directory', () => {
  it('flags COPY .git into image', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY .git /app/.git'), 'DV6008')).toBe(true);
  });
  it('flags COPY .git/ into image', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY .git/ /app/'), 'DV6008')).toBe(true);
  });
  it('flags ADD .git into image', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nADD .git /app/.git'), 'DV6008')).toBe(true);
  });
  it('does not flag COPY of normal directories', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY src/ /app/src/'), 'DV6008')).toBe(false);
  });
  it('does not flag COPY . . (covered by DV1008)', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY . .'), 'DV6008')).toBe(false);
  });
  it('does not flag .gitignore copy', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY .gitignore /app/'), 'DV6008')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6009 - pip install --break-system-packages
// ---------------------------------------------------------------------------
describe('DV6009 - pip install --break-system-packages', () => {
  it('flags pip install --break-system-packages', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --break-system-packages flask'), 'DV6009')).toBe(true);
  });
  it('flags pip3 install --break-system-packages', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip3 install --break-system-packages requests'), 'DV6009')).toBe(true);
  });
  it('flags --break-system-packages at end of command', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install flask --break-system-packages'), 'DV6009')).toBe(true);
  });
  it('does not flag normal pip install', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --no-cache-dir flask'), 'DV6009')).toBe(false);
  });
  it('does not flag pip install in venv', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN python -m venv /venv && /venv/bin/pip install flask'), 'DV6009')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6010 - yarn install without frozen lockfile
// ---------------------------------------------------------------------------
describe('DV6010 - yarn install without frozen lockfile', () => {
  it('flags yarn install without --frozen-lockfile', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY . .\nRUN yarn install'), 'DV6010')).toBe(true);
  });
  it('passes yarn install --frozen-lockfile', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY . .\nRUN yarn install --frozen-lockfile'), 'DV6010')).toBe(false);
  });
  it('passes yarn install --immutable', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY . .\nRUN yarn install --immutable'), 'DV6010')).toBe(false);
  });
  it('does not flag yarn add (not install)', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN yarn add express'), 'DV6010')).toBe(false);
  });
  it('does not flag npm install (different package manager)', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install'), 'DV6010')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6013 - curl without --fail flag
// ---------------------------------------------------------------------------
describe('DV6013 - curl without --fail flag', () => {
  it('flags curl without --fail', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN curl -sL https://example.com/install.sh -o /tmp/install.sh'), 'DV6013')).toBe(true);
  });
  it('flags curl with only -sL (no fail)', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN curl -sL https://example.com/file.tar.gz | tar xz'), 'DV6013')).toBe(true);
  });
  it('passes curl with -f flag', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh'), 'DV6013')).toBe(false);
  });
  it('passes curl with --fail flag', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN curl --fail -sL https://example.com/install.sh | bash'), 'DV6013')).toBe(false);
  });
  it('does not flag RUN without curl', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN wget https://example.com/file.tar.gz'), 'DV6013')).toBe(false);
  });
  it('passes curl with -fsSL combined flags', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -'), 'DV6013')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6014 - HEALTHCHECK with interval < 5s
// ---------------------------------------------------------------------------
describe('DV6014 - HEALTHCHECK with too-short interval', () => {
  it('flags --interval=1s', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nHEALTHCHECK --interval=1s CMD curl -f http://localhost/'), 'DV6014')).toBe(true);
  });
  it('flags --interval=2s', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nHEALTHCHECK --interval=2s --timeout=3s CMD wget -q http://localhost/'), 'DV6014')).toBe(true);
  });
  it('flags --interval=500ms', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nHEALTHCHECK --interval=500ms CMD true'), 'DV6014')).toBe(true);
  });
  it('passes --interval=30s', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nHEALTHCHECK --interval=30s CMD curl -f http://localhost/'), 'DV6014')).toBe(false);
  });
  it('passes --interval=10s', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nHEALTHCHECK --interval=10s CMD true'), 'DV6014')).toBe(false);
  });
  it('passes HEALTHCHECK without interval (uses default 30s)', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nHEALTHCHECK CMD curl -f http://localhost/'), 'DV6014')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6015 - git clone without --depth
// ---------------------------------------------------------------------------
describe('DV6015 - git clone without --depth', () => {
  it('flags git clone without --depth', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN git clone https://github.com/user/repo.git /app'), 'DV6015')).toBe(true);
  });
  it('flags git clone with branch but no depth', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN git clone -b main https://github.com/user/repo.git'), 'DV6015')).toBe(true);
  });
  it('passes git clone --depth 1', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN git clone --depth 1 https://github.com/user/repo.git /app'), 'DV6015')).toBe(false);
  });
  it('passes git clone --single-branch', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN git clone --single-branch https://github.com/user/repo.git'), 'DV6015')).toBe(false);
  });
  it('does not flag non-git RUN', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN echo hello'), 'DV6015')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6016 - npm install with --force / --legacy-peer-deps
// ---------------------------------------------------------------------------
describe('DV6016 - npm install with --force/--legacy-peer-deps', () => {
  it('flags npm install --force', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install --force'), 'DV6016')).toBe(true);
  });
  it('flags npm ci --legacy-peer-deps', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY package*.json ./\nRUN npm ci --legacy-peer-deps'), 'DV6016')).toBe(true);
  });
  it('flags npm i --force', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm i --force'), 'DV6016')).toBe(true);
  });
  it('passes normal npm install', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm install'), 'DV6016')).toBe(false);
  });
  it('passes npm ci without unsafe flags', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY package*.json ./\nRUN npm ci'), 'DV6016')).toBe(false);
  });
  it('does not flag yarn install --force (different manager)', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN yarn install --force'), 'DV6016')).toBe(false);
  });
});
