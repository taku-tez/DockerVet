import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/parser';
import { lint } from '../../src/engine/linter';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };
const lintDockerfile = (content: string, config = defaultConfig) => {
  const ast = parse(content);
  return lint(ast, { config });
};
const hasRule = (violations: any[], rule: string) => violations.some(v => v.rule === rule);

describe('DV3001 - Cloud credentials', () => {
  it('flags AWS access key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV AWS_KEY=AKIAIOSFODNN7EXAMPLE'), 'DV3001')).toBe(true);
  });
  it('flags GCP secret path', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo projects/myproj/secrets/mysecret'), 'DV3001')).toBe(true);
  });
  it('passes normal env', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV NODE_ENV=production'), 'DV3001')).toBe(false);
  });
});

describe('DV3002 - SSH keys', () => {
  it('flags COPY id_rsa', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY id_rsa /root/.ssh/id_rsa'), 'DV3002')).toBe(true);
  });
  it('flags COPY .ssh/', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY .ssh/ /root/.ssh/'), 'DV3002')).toBe(true);
  });
  it('flags ADD id_ed25519', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nADD id_ed25519 /root/.ssh/'), 'DV3002')).toBe(true);
  });
  it('passes normal COPY', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY app.js /app/'), 'DV3002')).toBe(false);
  });
});

describe('DV3003 - .env file', () => {
  it('flags COPY .env', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY .env /app/'), 'DV3003')).toBe(true);
  });
  it('flags COPY .env.local', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY .env.local /app/'), 'DV3003')).toBe(true);
  });
  it('passes normal file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY package.json /app/'), 'DV3003')).toBe(false);
  });
});

describe('DV3004 - Certificate/key files', () => {
  it('flags .pem file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY server.pem /etc/ssl/'), 'DV3004')).toBe(true);
  });
  it('flags .key file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY private.key /etc/ssl/'), 'DV3004')).toBe(true);
  });
  it('flags .p12 file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY cert.p12 /app/'), 'DV3004')).toBe(true);
  });
  it('passes normal file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY app.js /app/'), 'DV3004')).toBe(false);
  });
});

describe('DV3005 - GPG keys', () => {
  it('flags .gpg file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY secret.gpg /app/'), 'DV3005')).toBe(true);
  });
  it('flags secring file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY secring.gpg /app/'), 'DV3005')).toBe(true);
  });
  it('passes normal file', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY app.js /app/'), 'DV3005')).toBe(false);
  });
});

describe('DV3006 - Unauthenticated install', () => {
  it('flags --allow-unauthenticated', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install --allow-unauthenticated -y pkg'), 'DV3006')).toBe(true);
  });
  it('flags --force-yes', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install --force-yes pkg'), 'DV3006')).toBe(true);
  });
  it('flags --no-gpg-check', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN yum install --no-gpg-check pkg'), 'DV3006')).toBe(true);
  });
  it('passes normal install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y curl'), 'DV3006')).toBe(false);
  });
});

describe('DV3007 - TLS verification disabled', () => {
  it('flags wget --no-check-certificate', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN wget --no-check-certificate https://example.com'), 'DV3007')).toBe(true);
  });
  it('flags curl --insecure', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN curl --insecure https://example.com'), 'DV3007')).toBe(true);
  });
  it('passes normal wget', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN wget https://example.com'), 'DV3007')).toBe(false);
  });
});

describe('DV3008 - git clone', () => {
  it('flags git clone with credentials', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN git clone https://user:pass@github.com/repo'), 'DV3008')).toBe(true);
  });
  it('flags plain git clone as info', () => {
    const v = lintDockerfile('FROM ubuntu\nRUN git clone https://github.com/repo');
    expect(v.some(x => x.rule === 'DV3008')).toBe(true);
  });
  it('passes no git clone', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV3008')).toBe(false);
  });
});

describe('DV3009 - EXPOSE 22', () => {
  it('flags EXPOSE 22', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nEXPOSE 22'), 'DV3009')).toBe(true);
  });
  it('passes EXPOSE 80', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nEXPOSE 80'), 'DV3009')).toBe(false);
  });
  it('passes EXPOSE 443', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nEXPOSE 443'), 'DV3009')).toBe(false);
  });
});

describe('DV3010 - VOLUME sensitive paths', () => {
  it('flags VOLUME /root', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /root'), 'DV3010')).toBe(true);
  });
  it('flags VOLUME /home', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /home'), 'DV3010')).toBe(true);
  });
  it('flags VOLUME /tmp', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /tmp'), 'DV3010')).toBe(true);
  });
  it('passes VOLUME /data', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /data'), 'DV3010')).toBe(false);
  });
});
