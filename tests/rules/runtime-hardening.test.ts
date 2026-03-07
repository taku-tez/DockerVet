import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// ---------------------------------------------------------------------------
// DV7001 - LD_PRELOAD / LD_LIBRARY_PATH in ENV or ARG
// ---------------------------------------------------------------------------
describe('DV7001 - LD_PRELOAD / LD_LIBRARY_PATH', () => {
  it('flags ENV LD_PRELOAD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV LD_PRELOAD=/usr/lib/libfoo.so'), 'DV7001')).toBe(true);
  });
  it('flags ENV LD_LIBRARY_PATH', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV LD_LIBRARY_PATH=/custom/lib'), 'DV7001')).toBe(true);
  });
  it('flags ARG LD_PRELOAD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nARG LD_PRELOAD=/usr/lib/libfoo.so'), 'DV7001')).toBe(true);
  });
  it('flags ARG LD_LIBRARY_PATH', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nARG LD_LIBRARY_PATH=/custom/lib'), 'DV7001')).toBe(true);
  });
  it('does not flag normal ENV variables', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV PATH=/usr/local/bin:$PATH'), 'DV7001')).toBe(false);
  });
  it('does not flag ENV with LD in value but not key', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nENV MY_VAR=LD_PRELOAD_test'), 'DV7001')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV7002 - nsenter / mount --bind / unshare in RUN
// ---------------------------------------------------------------------------
describe('DV7002 - Container escape commands', () => {
  it('flags nsenter in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN nsenter --target 1 --mount --uts --ipc --net --pid'), 'DV7002')).toBe(true);
  });
  it('flags mount --bind in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN mount --bind /host /container'), 'DV7002')).toBe(true);
  });
  it('flags mount -o bind in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN mount -o bind /src /dst'), 'DV7002')).toBe(true);
  });
  it('flags unshare in RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN unshare --mount --pid --fork /bin/sh'), 'DV7002')).toBe(true);
  });
  it('does not flag normal mount command', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN mount -t tmpfs tmpfs /tmp'), 'DV7002')).toBe(false);
  });
  it('does not flag normal RUN commands', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl'), 'DV7002')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV7003 - useradd without --no-log-init
// ---------------------------------------------------------------------------
describe('DV7003 - useradd without --no-log-init', () => {
  it('flags useradd without --no-log-init', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN useradd -m appuser'), 'DV7003')).toBe(true);
  });
  it('flags useradd with other flags but no --no-log-init', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN useradd -r -s /bin/false myuser'), 'DV7003')).toBe(true);
  });
  it('does not flag useradd with --no-log-init', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN useradd --no-log-init -m appuser'), 'DV7003')).toBe(false);
  });
  it('does not flag adduser (different command)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN adduser --disabled-password appuser'), 'DV7003')).toBe(false);
  });
  it('does not flag RUN without useradd', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN apt-get install -y vim'), 'DV7003')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV7004 - chmod adding setuid/setgid bits
// ---------------------------------------------------------------------------
describe('DV7004 - chmod setuid/setgid', () => {
  it('flags chmod u+s', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod u+s /usr/bin/myapp'), 'DV7004')).toBe(true);
  });
  it('flags chmod +s', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod +s /usr/bin/myapp'), 'DV7004')).toBe(true);
  });
  it('flags chmod 4755 (setuid octal)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod 4755 /usr/bin/myapp'), 'DV7004')).toBe(true);
  });
  it('flags chmod 2755 (setgid octal)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod 2755 /usr/bin/myapp'), 'DV7004')).toBe(true);
  });
  it('flags chmod 6755 (both setuid+setgid)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod 6755 /usr/bin/myapp'), 'DV7004')).toBe(true);
  });
  it('does not flag chmod 755 (no setuid/setgid)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod 755 /usr/bin/myapp'), 'DV7004')).toBe(false);
  });
  it('does not flag chmod 644', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod 644 /etc/config'), 'DV7004')).toBe(false);
  });
  it('does not flag chmod without setuid patterns', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu:22.04\nRUN chmod +x /entrypoint.sh'), 'DV7004')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV7005 - USER switches back to root after non-root
// ---------------------------------------------------------------------------
describe('DV7005 - USER root re-escalation', () => {
  it('flags USER root after USER nonroot in final stage', () => {
    const df = 'FROM ubuntu:22.04\nUSER appuser\nRUN echo hello\nUSER root';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(true);
  });
  it('flags USER 0 after USER appuser in final stage', () => {
    const df = 'FROM ubuntu:22.04\nUSER appuser\nUSER 0';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(true);
  });
  it('does not flag single USER root', () => {
    const df = 'FROM ubuntu:22.04\nUSER root';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(false);
  });
  it('does not flag USER root then USER appuser (ends non-root)', () => {
    const df = 'FROM ubuntu:22.04\nUSER root\nRUN apt-get install -y curl\nUSER appuser';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(false);
  });
  it('does not flag single non-root USER', () => {
    const df = 'FROM ubuntu:22.04\nUSER nobody';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(false);
  });
  it('does not flag non-final stage USER re-escalation', () => {
    const df = 'FROM ubuntu:22.04 AS build\nUSER appuser\nUSER root\nFROM alpine:3.18\nUSER nobody';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(false);
  });
  it('flags in final stage of multi-stage build', () => {
    const df = 'FROM ubuntu:22.04 AS build\nRUN make\nFROM alpine:3.18\nUSER appuser\nRUN echo hello\nUSER root';
    expect(hasRule(lintDockerfile(df), 'DV7005')).toBe(true);
  });
});
