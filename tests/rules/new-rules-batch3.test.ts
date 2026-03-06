import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// ---------------------------------------------------------------------------
// DV6017 - HEALTHCHECK NONE disables health monitoring
// ---------------------------------------------------------------------------
describe('DV6017 - HEALTHCHECK NONE', () => {
  it('flags HEALTHCHECK NONE in final stage', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nHEALTHCHECK NONE\nCMD ["node", "app.js"]'), 'DV6017')).toBe(true);
  });
  it('flags HEALTHCHECK NONE (lowercase)', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nHEALTHCHECK none\nCMD ["node", "app.js"]'), 'DV6017')).toBe(true);
  });
  it('does not flag proper HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nHEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1'), 'DV6017')).toBe(false);
  });
  it('does not flag Dockerfile without HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCMD ["node", "app.js"]'), 'DV6017')).toBe(false);
  });
  it('does not flag HEALTHCHECK NONE in non-final build stage', () => {
    expect(hasRule(lintDockerfile('FROM node:20 AS builder\nHEALTHCHECK NONE\nRUN npm run build\nFROM node:20-slim\nCOPY --from=builder /app/dist /app\nCMD ["node", "/app/index.js"]'), 'DV6017')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6018 - pip install from VCS URL without version pin
// ---------------------------------------------------------------------------
describe('DV6018 - pip install from VCS', () => {
  it('flags pip install git+https without pin', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install git+https://github.com/org/repo.git'), 'DV6018')).toBe(true);
  });
  it('flags pip3 install git+https without pin', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip3 install git+https://github.com/org/repo.git'), 'DV6018')).toBe(true);
  });
  it('flags pip install git+ssh without pin', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install git+ssh://git@github.com/org/repo.git'), 'DV6018')).toBe(true);
  });
  it('does not flag pip install git+https with @tag pin', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install git+https://github.com/org/repo.git@v1.0.0'), 'DV6018')).toBe(false);
  });
  it('does not flag pip install git+https with @commit pin', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install git+https://github.com/org/repo.git@abc123def'), 'DV6018')).toBe(false);
  });
  it('does not flag normal pip install', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install flask==2.3.0'), 'DV6018')).toBe(false);
  });
  it('does not flag pip install from requirements.txt', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nRUN pip install -r requirements.txt'), 'DV6018')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6019 - Shell form CMD
// ---------------------------------------------------------------------------
describe('DV6019 - Shell form CMD', () => {
  it('flags CMD in shell form', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCMD node app.js'), 'DV6019')).toBe(true);
  });
  it('flags CMD with shell string', () => {
    expect(hasRule(lintDockerfile('FROM python:3.12\nCMD python main.py --port 8080'), 'DV6019')).toBe(true);
  });
  it('does not flag CMD in exec form', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCMD ["node", "app.js"]'), 'DV6019')).toBe(false);
  });
  it('does not flag shell form CMD when ENTRYPOINT is set', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENTRYPOINT ["node"]\nCMD app.js'), 'DV6019')).toBe(false);
  });
  it('does not flag Dockerfile without CMD', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nENTRYPOINT ["node", "app.js"]'), 'DV6019')).toBe(false);
  });
  it('only checks CMD in final stage', () => {
    expect(hasRule(lintDockerfile('FROM node:20 AS builder\nCMD echo build\nFROM node:20-slim\nCMD ["node", "app.js"]'), 'DV6019')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV6020 - COPY/ADD --chmod with overly permissive modes
// ---------------------------------------------------------------------------
describe('DV6020 - COPY/ADD --chmod overly permissive', () => {
  it('flags COPY --chmod=777', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY --chmod=777 app.js /app/'), 'DV6020')).toBe(true);
  });
  it('flags ADD --chmod=666', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nADD --chmod=666 config.json /app/'), 'DV6020')).toBe(true);
  });
  it('flags COPY --chmod=776', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY --chmod=776 script.sh /app/'), 'DV6020')).toBe(true);
  });
  it('does not flag COPY --chmod=755', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY --chmod=755 entrypoint.sh /app/'), 'DV6020')).toBe(false);
  });
  it('does not flag COPY --chmod=644', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY --chmod=644 config.json /app/'), 'DV6020')).toBe(false);
  });
  it('does not flag COPY without --chmod', () => {
    expect(hasRule(lintDockerfile('FROM node:20\nCOPY app.js /app/'), 'DV6020')).toBe(false);
  });
});
