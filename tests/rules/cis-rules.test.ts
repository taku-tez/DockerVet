import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';

describe('DV2001 - apt-get update alone', () => {
  it('flags apt-get update without install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update'), 'DV2001')).toBe(true);
  });
  it('passes apt-get update with install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y curl'), 'DV2001')).toBe(false);
  });
  it('passes no apt-get', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hello'), 'DV2001')).toBe(false);
  });
});

describe('DV2002 - apt-get dist-upgrade', () => {
  it('flags dist-upgrade', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get dist-upgrade'), 'DV2002')).toBe(true);
  });
  it('passes normal upgrade', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get upgrade'), 'DV2002')).toBe(false);
  });
  it('passes install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y curl'), 'DV2002')).toBe(false);
  });
});

describe('DV2003 - Sensitive VOLUME', () => {
  it('flags VOLUME /etc', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /etc'), 'DV2003')).toBe(true);
  });
  it('flags VOLUME /var/run', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /var/run'), 'DV2003')).toBe(true);
  });
  it('passes VOLUME /data', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME /data'), 'DV2003')).toBe(false);
  });
  it('flags JSON array format', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nVOLUME ["/etc"]'), 'DV2003')).toBe(true);
  });
});

describe('DV2004 - no-install-recommends', () => {
  it('flags apt-get install without --no-install-recommends', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y curl'), 'DV2004')).toBe(true);
  });
  it('passes with --no-install-recommends', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install --no-install-recommends -y curl'), 'DV2004')).toBe(false);
  });
  it('passes no apt-get', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV2004')).toBe(false);
  });
});

describe('DV2005 - MAINTAINER deprecated', () => {
  it('flags MAINTAINER', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nMAINTAINER test@test.com'), 'DV2005')).toBe(true);
  });
  it('passes LABEL maintainer', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nLABEL maintainer="test@test.com"'), 'DV2005')).toBe(false);
  });
  it('passes no maintainer', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV2005')).toBe(false);
  });
});

describe('DV2006 - Multiple ENTRYPOINT', () => {
  it('flags multiple ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT ["sh"]\nENTRYPOINT ["bash"]'), 'DV2006')).toBe(true);
  });
  it('passes single ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT ["sh"]'), 'DV2006')).toBe(false);
  });
  it('passes no ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["sh"]'), 'DV2006')).toBe(false);
  });
});

describe('DV2007 - Multiple CMD', () => {
  it('flags multiple CMD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["echo", "1"]\nCMD ["echo", "2"]'), 'DV2007')).toBe(true);
  });
  it('passes single CMD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["echo", "1"]'), 'DV2007')).toBe(false);
  });
  it('passes no CMD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV2007')).toBe(false);
  });
});

describe('DV2008 - apt-get update/install in separate RUNs', () => {
  it('flags split update and install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update\nRUN apt-get install -y curl'), 'DV2008')).toBe(true);
  });
  it('passes combined update and install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update && apt-get install -y curl'), 'DV2008')).toBe(false);
  });
  it('passes standalone update only', () => {
    // DV2008 specifically checks update followed by install in next RUN
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get update\nRUN echo hi'), 'DV2008')).toBe(false);
  });
});

describe('DV2009 - Unsafe SHELL', () => {
  it('flags unusual shell', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSHELL ["/bin/nc"]'), 'DV2009')).toBe(true);
  });
  it('passes /bin/bash', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSHELL ["/bin/bash", "-c"]'), 'DV2009')).toBe(false);
  });
  it('passes /bin/sh', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nSHELL ["/bin/sh", "-c"]'), 'DV2009')).toBe(false);
  });
});
