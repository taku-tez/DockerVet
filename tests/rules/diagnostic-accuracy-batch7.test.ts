import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/parser';
import { lint } from '../../src/engine/linter';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };

function lintContent(content: string, filePath?: string) {
  const ast = parse(content);
  return lint(ast, { config: defaultConfig, filePath });
}

// ── DV3041: Insecure network protocol packages ─────────────────────────

describe('DV3041: insecure network protocol packages', () => {
  // True positives - should fire
  it('detects telnet installation via apt-get', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y telnet\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects rsh-client installation', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y rsh-client\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects rsh-server installation', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y rsh-server\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects ftp package installation', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y ftp\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects vsftpd installation', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y vsftpd\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects proftpd installation', () => {
    const v = lintContent('FROM debian:12\nRUN apt-get install -y proftpd-basic\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects telnetd installation', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y telnetd\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects rlogin installation', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN yum install -y rlogin\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects inetutils-telnet via apk add', () => {
    const v = lintContent('FROM alpine:3.19\nRUN apk add inetutils-telnet\nCMD ["sh"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects inetutils-ftp via dnf install', () => {
    const v = lintContent('FROM fedora:39\nRUN dnf install -y inetutils-ftp\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(true);
  });

  it('detects multiple insecure packages in one RUN', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y telnet ftp rsh-client\nCMD ["bash"]');
    const dv3041 = v.filter(v => v.rule === 'DV3041');
    expect(dv3041.length).toBeGreaterThanOrEqual(3);
  });

  // False positive guards - should NOT fire
  it('does not fire on sftp packages', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y openssh-sftp-server\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(false);
  });

  it('does not fire on curl/wget (secure alternatives)', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y curl wget\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(false);
  });

  it('does not fire on openssh-client (SSH is secure)', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y openssh-client\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(false);
  });

  it('does not fire on non-install RUN commands mentioning telnet', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN echo "telnet is disabled"\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(false);
  });

  it('does not fire on python-ftplib or similar library names', () => {
    const v = lintContent('FROM python:3.12\nRUN pip install pyftpdlib\nCMD ["python"]');
    expect(v.some(v => v.rule === 'DV3041')).toBe(false);
  });
});

// ── DV3042: sshd as container main process ──────────────────────────────

describe('DV3042: sshd as container main process', () => {
  // True positives - should fire
  it('detects sshd in CMD', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y openssh-server\nCMD ["/usr/sbin/sshd", "-D"]');
    expect(v.some(v => v.rule === 'DV3042' && v.severity === 'warning')).toBe(true);
  });

  it('detects sshd in ENTRYPOINT', () => {
    const v = lintContent('FROM ubuntu:22.04\nENTRYPOINT ["/usr/sbin/sshd", "-D"]');
    expect(v.some(v => v.rule === 'DV3042' && v.severity === 'warning')).toBe(true);
  });

  it('detects sshd in shell-form CMD', () => {
    const v = lintContent('FROM ubuntu:22.04\nCMD sshd -D');
    expect(v.some(v => v.rule === 'DV3042' && v.severity === 'warning')).toBe(true);
  });

  it('detects openssh-server installation in final stage', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y openssh-server\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3042' && v.severity === 'info')).toBe(true);
  });

  it('detects sshd in multi-stage final stage', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
RUN go build -o /app

FROM ubuntu:22.04
COPY --from=builder /app /app
RUN apt-get install -y openssh-server
CMD ["/usr/sbin/sshd", "-D"]`);
    expect(v.some(v => v.rule === 'DV3042' && v.severity === 'warning')).toBe(true);
  });

  // False positive guards - should NOT fire
  it('does not fire on openssh-server in builder stage only', () => {
    const v = lintContent(`FROM ubuntu:22.04 AS builder
RUN apt-get install -y openssh-server git
RUN git clone git@github.com:org/repo.git

FROM alpine:3.19
COPY --from=builder /repo /app
CMD ["/app/server"]`);
    // Builder stage openssh install should not trigger DV3042
    expect(v.some(v => v.rule === 'DV3042')).toBe(false);
  });

  it('does not fire on normal CMD', () => {
    const v = lintContent('FROM ubuntu:22.04\nCMD ["node", "server.js"]');
    expect(v.some(v => v.rule === 'DV3042')).toBe(false);
  });

  it('does not fire on openssh-client', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN apt-get install -y openssh-client\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3042')).toBe(false);
  });

  it('detects /usr/sbin/sshd path in ENTRYPOINT', () => {
    const v = lintContent('FROM debian:12\nENTRYPOINT /usr/sbin/sshd -D -e');
    expect(v.some(v => v.rule === 'DV3042' && v.severity === 'warning')).toBe(true);
  });
});

// ── DV3031: Re-verify sudoers detection works (was stale build) ─────────

describe('DV3031: sudoers modification detection', () => {
  it('detects NOPASSWD ALL in sudoers', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3031')).toBe(true);
  });

  it('detects NOPASSWD with error severity', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers\nCMD ["bash"]');
    const dv3031 = v.find(v => v.rule === 'DV3031');
    expect(dv3031?.severity).toBe('error');
  });

  it('detects tee to sudoers.d', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN echo "appuser ALL=(ALL:ALL) ALL" | tee /etc/sudoers.d/appuser\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3031')).toBe(true);
  });

  it('detects visudo usage', () => {
    const v = lintContent('FROM ubuntu:22.04\nRUN visudo -c\nCMD ["bash"]');
    expect(v.some(v => v.rule === 'DV3031')).toBe(true);
  });
});
