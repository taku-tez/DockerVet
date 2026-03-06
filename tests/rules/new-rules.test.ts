import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// DV3026 - chmod 777 / overly permissive permissions
describe('DV3026 - Overly permissive file permissions', () => {
  it('flags chmod 777', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod 777 /app'), 'DV3026')).toBe(true);
  });
  it('flags chmod -R 777', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod -R 777 /data'), 'DV3026')).toBe(true);
  });
  it('flags chmod 666', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod 666 /tmp/file'), 'DV3026')).toBe(true);
  });
  it('flags chmod o+w', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod o+w /app/config'), 'DV3026')).toBe(true);
  });
  it('flags chmod a+w', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod a+w /data'), 'DV3026')).toBe(true);
  });
  it('does not flag chmod 755', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod 755 /app/start.sh'), 'DV3026')).toBe(false);
  });
  it('does not flag chmod 644', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod 644 /etc/config'), 'DV3026')).toBe(false);
  });
  it('does not flag chmod +x', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod +x /app/run.sh'), 'DV3026')).toBe(false);
  });
});

// DV3027 - apt-get upgrade / apk upgrade
describe('DV3027 - Package manager upgrade in Dockerfile', () => {
  it('flags apt-get upgrade', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get upgrade -y'), 'DV3027')).toBe(true);
  });
  it('flags apt-get dist-upgrade', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get dist-upgrade'), 'DV3027')).toBe(true);
  });
  it('flags apk upgrade', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN apk upgrade'), 'DV3027')).toBe(true);
  });
  it('flags dnf upgrade', () => {
    expect(hasRule(lintDockerfile('FROM fedora\nRUN dnf upgrade -y'), 'DV3027')).toBe(true);
  });
  it('does not flag apt-get install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y curl'), 'DV3027')).toBe(false);
  });
  it('does not flag apk add', () => {
    expect(hasRule(lintDockerfile('FROM alpine\nRUN apk add --no-cache curl'), 'DV3027')).toBe(false);
  });
});

// DV4018 - Multiple HEALTHCHECK instructions
describe('DV4018 - Multiple HEALTHCHECK instructions', () => {
  it('flags multiple HEALTHCHECKs', () => {
    const df = `FROM ubuntu
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1`;
    const violations = lintDockerfile(df);
    expect(hasRule(violations, 'DV4018')).toBe(true);
  });
  it('does not flag single HEALTHCHECK', () => {
    const df = `FROM ubuntu
HEALTHCHECK CMD curl -f http://localhost/ || exit 1`;
    expect(hasRule(lintDockerfile(df), 'DV4018')).toBe(false);
  });
  it('does not flag no HEALTHCHECK', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hello'), 'DV4018')).toBe(false);
  });
});

// DV4019 - WORKDIR with relative path
describe('DV4019 - WORKDIR with relative path', () => {
  it('flags relative WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR app'), 'DV4019')).toBe(true);
  });
  it('flags relative WORKDIR with subdirectory', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR src/app'), 'DV4019')).toBe(true);
  });
  it('does not flag absolute WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /app'), 'DV4019')).toBe(false);
  });
  it('does not flag variable WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nARG APP_DIR=/app\nWORKDIR $APP_DIR'), 'DV4019')).toBe(false);
  });
});

// DV4020 - Shell form ENTRYPOINT
describe('DV4020 - Shell form ENTRYPOINT', () => {
  it('flags shell form ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT /app/start.sh'), 'DV4020')).toBe(true);
  });
  it('flags shell form ENTRYPOINT with arguments', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT python app.py --port 8080'), 'DV4020')).toBe(true);
  });
  it('does not flag exec form ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT ["/app/start.sh"]'), 'DV4020')).toBe(false);
  });
  it('does not flag exec form with args', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT ["python", "app.py", "--port", "8080"]'), 'DV4020')).toBe(false);
  });
  it('only checks final stage', () => {
    const df = `FROM ubuntu AS builder
ENTRYPOINT /build.sh
FROM alpine
ENTRYPOINT ["/app/start.sh"]`;
    expect(hasRule(lintDockerfile(df), 'DV4020')).toBe(false);
  });
});

// DV4021 - gem install without --no-document
describe('DV4021 - gem install without --no-document', () => {
  it('flags gem install without --no-document', () => {
    expect(hasRule(lintDockerfile('FROM ruby\nRUN gem install bundler'), 'DV4021')).toBe(true);
  });
  it('flags gem install with multiple gems', () => {
    expect(hasRule(lintDockerfile('FROM ruby\nRUN gem install rails sinatra'), 'DV4021')).toBe(true);
  });
  it('does not flag gem install with --no-document', () => {
    expect(hasRule(lintDockerfile('FROM ruby\nRUN gem install --no-document bundler'), 'DV4021')).toBe(false);
  });
  it('does not flag gem install with --no-doc', () => {
    expect(hasRule(lintDockerfile('FROM ruby\nRUN gem install --no-doc bundler'), 'DV4021')).toBe(false);
  });
  it('does not flag gem install with --no-ri --no-rdoc (legacy)', () => {
    expect(hasRule(lintDockerfile('FROM ruby\nRUN gem install --no-ri --no-rdoc bundler'), 'DV4021')).toBe(false);
  });
  it('flags gem install in multi-command RUN', () => {
    expect(hasRule(lintDockerfile('FROM ruby\nRUN apt-get update && gem install puma'), 'DV4021')).toBe(true);
  });
});

// DV4022 - npm install instead of npm ci
describe('DV4022 - npm install instead of npm ci', () => {
  it('flags bare npm install', () => {
    expect(hasRule(lintDockerfile('FROM node\nRUN npm install'), 'DV4022')).toBe(true);
  });
  it('flags npm install --production', () => {
    expect(hasRule(lintDockerfile('FROM node\nRUN npm install --production'), 'DV4022')).toBe(true);
  });
  it('does not flag npm install <specific-package>', () => {
    expect(hasRule(lintDockerfile('FROM node\nRUN npm install express'), 'DV4022')).toBe(false);
  });
  it('does not flag npm ci', () => {
    expect(hasRule(lintDockerfile('FROM node\nRUN npm ci'), 'DV4022')).toBe(false);
  });
  it('does not flag npm ci --production', () => {
    expect(hasRule(lintDockerfile('FROM node\nRUN npm ci --production'), 'DV4022')).toBe(false);
  });
  it('flags npm install in chained commands', () => {
    expect(hasRule(lintDockerfile('FROM node\nCOPY package*.json ./\nRUN npm install && npm run build'), 'DV4022')).toBe(true);
  });
});

// DV4023 - Multiple consecutive ENV instructions
describe('DV4023 - Multiple consecutive ENV instructions', () => {
  it('flags 3 consecutive ENV instructions', () => {
    const df = `FROM ubuntu
ENV FOO=bar
ENV BAZ=qux
ENV HELLO=world`;
    expect(hasRule(lintDockerfile(df), 'DV4023')).toBe(true);
  });
  it('flags 4 consecutive ENV instructions', () => {
    const df = `FROM ubuntu
ENV A=1
ENV B=2
ENV C=3
ENV D=4`;
    expect(hasRule(lintDockerfile(df), 'DV4023')).toBe(true);
  });
  it('does not flag 2 consecutive ENV instructions', () => {
    const df = `FROM ubuntu
ENV FOO=bar
ENV BAZ=qux`;
    expect(hasRule(lintDockerfile(df), 'DV4023')).toBe(false);
  });
  it('does not flag ENV instructions separated by other instructions', () => {
    const df = `FROM ubuntu
ENV FOO=bar
RUN echo hi
ENV BAZ=qux
COPY . .
ENV HELLO=world`;
    expect(hasRule(lintDockerfile(df), 'DV4023')).toBe(false);
  });
  it('does not flag single ENV with multiple vars', () => {
    const df = `FROM ubuntu
ENV FOO=bar BAZ=qux HELLO=world`;
    expect(hasRule(lintDockerfile(df), 'DV4023')).toBe(false);
  });
});

// DV3028 - useradd without --no-log-init
describe('DV3028 - useradd without --no-log-init', () => {
  it('flags useradd without --no-log-init', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN useradd appuser'), 'DV3028')).toBe(true);
  });
  it('flags useradd with other flags but not --no-log-init', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN useradd -m -s /bin/bash appuser'), 'DV3028')).toBe(true);
  });
  it('does not flag useradd with --no-log-init', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN useradd --no-log-init appuser'), 'DV3028')).toBe(false);
  });
  it('does not flag useradd with --no-log-init and other flags', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN useradd --no-log-init -m -s /bin/bash appuser'), 'DV3028')).toBe(false);
  });
  it('does not flag adduser (which does not have this issue)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN adduser --disabled-password appuser'), 'DV3028')).toBe(false);
  });
  it('flags useradd in chained command', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN groupadd app && useradd -g app appuser'), 'DV3028')).toBe(true);
  });
});
