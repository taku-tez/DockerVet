import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// ---------------------------------------------------------------------------
// DV8001 - setcap granting dangerous Linux capabilities
// ---------------------------------------------------------------------------
describe('DV8001 - dangerous setcap', () => {
  it('flags setcap cap_sys_admin', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN setcap cap_sys_admin+ep /usr/bin/myapp'), 'DV8001')).toBe(true);
  });
  it('flags setcap cap_net_raw', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN setcap cap_net_raw+ep /usr/bin/ping'), 'DV8001')).toBe(true);
  });
  it('flags setcap cap_sys_ptrace', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN setcap cap_sys_ptrace+ep /usr/bin/strace'), 'DV8001')).toBe(true);
  });
  it('flags setcap cap_setuid', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN setcap cap_setuid+ep /usr/bin/newuidmap'), 'DV8001')).toBe(true);
  });
  it('does not flag setcap with safe capabilities', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN setcap cap_net_bind_service+ep /usr/bin/myapp'), 'DV8001')).toBe(false);
  });
  it('does not flag RUN without setcap', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-get install -y curl'), 'DV8001')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV8002 - Adding third-party APT repos without GPG verification
// ---------------------------------------------------------------------------
describe('DV8002 - untrusted APT repository', () => {
  it('flags curl piped to apt-key add', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/key.gpg | apt-key add -'), 'DV8002')).toBe(true);
  });
  it('flags wget piped to apt-key add', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN wget -qO- https://example.com/key.gpg | sudo apt-key add -'), 'DV8002')).toBe(true);
  });
  it('flags apt-key add directly', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-key add /tmp/key.gpg'), 'DV8002')).toBe(true);
  });
  it('flags add-apt-repository without signed-by', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN add-apt-repository ppa:deadsnakes/ppa'), 'DV8002')).toBe(true);
  });
  it('does not flag add-apt-repository with signed-by', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list'), 'DV8002')).toBe(false);
  });
  it('does not flag normal apt-get install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl'), 'DV8002')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV8003 - Direct /etc/passwd, /etc/shadow, /etc/group manipulation
// ---------------------------------------------------------------------------
describe('DV8003 - direct passwd/shadow manipulation', () => {
  it('flags echo to /etc/passwd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN echo "myuser:x:1000:1000::/home/myuser:/bin/bash" >> /etc/passwd'), 'DV8003')).toBe(true);
  });
  it('flags sed on /etc/shadow', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN sed -i "s/root:!/root:/" /etc/shadow'), 'DV8003')).toBe(true);
  });
  it('flags tee to /etc/group', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN echo "docker:x:999:" | tee -a /etc/group'), 'DV8003')).toBe(true);
  });
  it('flags redirect to /etc/passwd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN cat users.txt > /etc/passwd'), 'DV8003')).toBe(true);
  });
  it('does not flag useradd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN useradd --no-log-init -r -g appgroup appuser'), 'DV8003')).toBe(false);
  });
  it('does not flag reading /etc/passwd (cat without redirect)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN grep appuser /etc/passwd || true'), 'DV8003')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV8004 - Disabling security features via ENV
// ---------------------------------------------------------------------------
describe('DV8004 - security-disabling ENV vars', () => {
  it('flags NODE_TLS_REJECT_UNAUTHORIZED=0', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENV NODE_TLS_REJECT_UNAUTHORIZED=0'), 'DV8004')).toBe(true);
  });
  it('flags PYTHONHTTPSVERIFY=0', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nENV PYTHONHTTPSVERIFY=0'), 'DV8004')).toBe(true);
  });
  it('flags GIT_SSL_NO_VERIFY=true', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV GIT_SSL_NO_VERIFY=true'), 'DV8004')).toBe(true);
  });
  it('flags GIT_SSL_NO_VERIFY=1', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV GIT_SSL_NO_VERIFY=1'), 'DV8004')).toBe(true);
  });
  it('flags GONOSUMCHECK', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.22\nENV GONOSUMCHECK=*'), 'DV8004')).toBe(true);
  });
  it('flags GOFLAGS with -insecure', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.22\nENV GOFLAGS=-insecure'), 'DV8004')).toBe(true);
  });
  it('does not flag safe ENV vars', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENV NODE_ENV=production'), 'DV8004')).toBe(false);
  });
  it('does not flag unrelated Go ENV', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.22\nENV GOPATH=/go'), 'DV8004')).toBe(false);
  });
  it('flags GONOSUMDB', () => {
    expect(hasRule(lintDockerfile('FROM golang:1.22\nENV GONOSUMDB=github.com/private/*'), 'DV8004')).toBe(true);
  });
  it('flags NPM_CONFIG_STRICT_SSL=false', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENV NPM_CONFIG_STRICT_SSL=false'), 'DV8004')).toBe(true);
  });
  it('flags YARN_STRICT_SSL=false', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENV YARN_STRICT_SSL=false'), 'DV8004')).toBe(true);
  });
  it('flags PIP_TRUSTED_HOST', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nENV PIP_TRUSTED_HOST=pypi.internal.example.com'), 'DV8004')).toBe(true);
  });
  it('flags SSL_CERT_FILE=/dev/null', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV SSL_CERT_FILE=/dev/null'), 'DV8004')).toBe(true);
  });
  it('does not flag NPM_CONFIG_STRICT_SSL=true', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENV NPM_CONFIG_STRICT_SSL=true'), 'DV8004')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV8005 - Security-disabling commands in RUN
// ---------------------------------------------------------------------------
describe('DV8005 - security-disabling RUN commands', () => {
  it('flags npm config set strict-ssl false', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm config set strict-ssl false'), 'DV8005')).toBe(true);
  });
  it('flags npm set strict-ssl false', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm set strict-ssl false'), 'DV8005')).toBe(true);
  });
  it('flags yarn config set strict-ssl false', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN yarn config set strict-ssl false'), 'DV8005')).toBe(true);
  });
  it('flags pip install --trusted-host', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --trusted-host pypi.internal.com -r requirements.txt'), 'DV8005')).toBe(true);
  });
  it('flags git config http.sslVerify false', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN git config --global http.sslVerify false'), 'DV8005')).toBe(true);
  });
  it('flags composer config disable-tls true', () => {
    expect(hasRule(lintDockerfile('FROM php:8.2\nRUN composer config --global disable-tls true'), 'DV8005')).toBe(true);
  });
  it('flags conda config ssl_verify false', () => {
    expect(hasRule(lintDockerfile('FROM continuumio/miniconda3\nRUN conda config --set ssl_verify false'), 'DV8005')).toBe(true);
  });
  it('does not flag normal npm install', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nRUN npm ci --production'), 'DV8005')).toBe(false);
  });
  it('does not flag normal pip install', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install --no-cache-dir -r requirements.txt'), 'DV8005')).toBe(false);
  });
  it('does not flag git config user.name', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN git config --global user.name "builder"'), 'DV8005')).toBe(false);
  });
});
