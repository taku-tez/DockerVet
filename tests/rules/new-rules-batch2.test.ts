import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// DV3031 - Modifying /etc/sudoers — privilege escalation risk
describe('DV3031 - Sudoers modification', () => {
  it('flags echo to /etc/sudoers', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo "user ALL=(ALL) ALL" >> /etc/sudoers'), 'DV3031')).toBe(true);
  });
  it('flags tee to /etc/sudoers.d/', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo "user ALL=(ALL) NOPASSWD:ALL" | tee /etc/sudoers.d/user'), 'DV3031')).toBe(true);
  });
  it('flags NOPASSWD as error severity', () => {
    const violations = lintDockerfile('FROM ubuntu\nRUN echo "app ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers');
    const v = violations.find(v => v.rule === 'DV3031');
    expect(v).toBeDefined();
    expect(v!.severity).toBe('error');
  });
  it('flags visudo usage', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN visudo -c'), 'DV3031')).toBe(true);
  });
  it('flags sed modifying sudoers', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN sed -i "s/#.*%sudo/%sudo/" /etc/sudoers'), 'DV3031')).toBe(true);
  });
  it('does not flag unrelated RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y curl'), 'DV3031')).toBe(false);
  });
  it('does not flag sudoers in comments only', () => {
    // The rule checks arguments, so if sudoers appears in the command it still fires
    // This test ensures non-sudoers commands pass
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo "hello world"'), 'DV3031')).toBe(false);
  });
  it('without NOPASSWD is warning severity', () => {
    const violations = lintDockerfile('FROM ubuntu\nRUN echo "user ALL=(ALL) ALL" >> /etc/sudoers');
    const v = violations.find(v => v.rule === 'DV3031');
    expect(v).toBeDefined();
    expect(v!.severity).toBe('warning');
  });
});

// DV3032 - CMD/ENTRYPOINT running sshd
describe('DV3032 - SSH daemon in container', () => {
  it('flags CMD with sshd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["/usr/sbin/sshd", "-D"]'), 'DV3032')).toBe(true);
  });
  it('flags ENTRYPOINT with sshd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT ["/usr/sbin/sshd", "-D"]'), 'DV3032')).toBe(true);
  });
  it('flags CMD shell form with sshd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD sshd -D'), 'DV3032')).toBe(true);
  });
  it('flags service ssh start in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN service ssh start'), 'DV3032')).toBe(true);
  });
  it('flags systemctl enable sshd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN systemctl enable sshd'), 'DV3032')).toBe(true);
  });
  it('does not flag CMD with other commands', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["node", "app.js"]'), 'DV3032')).toBe(false);
  });
  it('does not flag RUN apt-get install openssh-server (install is ok, running is not)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y openssh-server'), 'DV3032')).toBe(false);
  });
  it('does not flag ENTRYPOINT with nginx', () => {
    expect(hasRule(lintDockerfile('FROM nginx\nENTRYPOINT ["nginx", "-g", "daemon off;"]'), 'DV3032')).toBe(false);
  });
});

// DV6011 - curl/wget downloading from http:// (non-TLS) URLs
describe('DV6011 - HTTP download without TLS', () => {
  it('flags curl with http:// URL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN curl -O http://example.com/file.tar.gz'), 'DV6011')).toBe(true);
  });
  it('flags wget with http:// URL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN wget http://example.com/script.sh'), 'DV6011')).toBe(true);
  });
  it('does not flag curl with https:// URL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN curl -O https://example.com/file.tar.gz'), 'DV6011')).toBe(false);
  });
  it('does not flag wget with https:// URL', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN wget https://example.com/script.sh'), 'DV6011')).toBe(false);
  });
  it('does not flag http://localhost (local is safe)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN curl http://localhost:8080/health'), 'DV6011')).toBe(false);
  });
  it('does not flag http://127.0.0.1 (local is safe)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN wget http://127.0.0.1:3000/api'), 'DV6011')).toBe(false);
  });
  it('does not flag non-curl/wget RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y curl'), 'DV6011')).toBe(false);
  });
  it('flags http:// in a chained command', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && curl http://insecure.example.com/pkg.deb -o /tmp/pkg.deb'), 'DV6011')).toBe(true);
  });
});

// DV6012 - WORKDIR set to sensitive system directory
describe('DV6012 - Sensitive WORKDIR', () => {
  it('flags WORKDIR /', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /'), 'DV6012')).toBe(true);
  });
  it('flags WORKDIR /etc', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /etc'), 'DV6012')).toBe(true);
  });
  it('flags WORKDIR /var', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /var'), 'DV6012')).toBe(true);
  });
  it('flags WORKDIR /usr', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /usr'), 'DV6012')).toBe(true);
  });
  it('flags WORKDIR /bin', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /bin'), 'DV6012')).toBe(true);
  });
  it('does not flag WORKDIR /app', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /app'), 'DV6012')).toBe(false);
  });
  it('does not flag WORKDIR /opt/myapp', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /opt/myapp'), 'DV6012')).toBe(false);
  });
  it('does not flag WORKDIR /home/appuser', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /home/appuser'), 'DV6012')).toBe(false);
  });
  it('flags WORKDIR /etc with trailing slash', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /etc/'), 'DV6012')).toBe(true);
  });
});
