import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';

describe('DV4001 - Multiple package install RUNs', () => {
  it('flags multiple apt-get install RUNs', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y curl\nRUN apt-get install -y wget'), 'DV4001')).toBe(true);
  });
  it('passes single install RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN apt-get install -y curl wget'), 'DV4001')).toBe(false);
  });
  it('passes no install', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV4001')).toBe(false);
  });
});

describe('DV4002 - Consecutive RUN instructions', () => {
  it('flags 3+ consecutive RUNs', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo 1\nRUN echo 2\nRUN echo 3'), 'DV4002')).toBe(true);
  });
  it('passes 2 consecutive RUNs', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo 1\nRUN echo 2'), 'DV4002')).toBe(false);
  });
  it('passes interrupted RUNs', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo 1\nENV A=1\nRUN echo 2\nENV B=2\nRUN echo 3'), 'DV4002')).toBe(false);
  });
});

describe('DV4003 - No WORKDIR before RUN', () => {
  it('flags RUN without WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV4003')).toBe(true);
  });
  it('passes with WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /app\nRUN echo hi'), 'DV4003')).toBe(false);
  });
  it('passes no RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["echo"]'), 'DV4003')).toBe(false);
  });
});

describe('DV4004 - ARG after ENV', () => {
  it('flags ARG after ENV', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV FOO=bar\nARG BAZ'), 'DV4004')).toBe(true);
  });
  it('passes ARG before ENV', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nARG BAZ\nENV FOO=bar'), 'DV4004')).toBe(false);
  });
  it('passes no ARG or ENV', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV4004')).toBe(false);
  });
});

describe('DV4005 - No CMD or ENTRYPOINT', () => {
  it('flags no CMD or ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV4005')).toBe(true);
  });
  it('passes with CMD', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCMD ["echo"]'), 'DV4005')).toBe(false);
  });
  it('passes with ENTRYPOINT', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENTRYPOINT ["echo"]'), 'DV4005')).toBe(false);
  });
});

describe('DV4006 - Large port range', () => {
  it('flags large range', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nEXPOSE 8000-9000'), 'DV4006')).toBe(true);
  });
  it('passes single port', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nEXPOSE 80'), 'DV4006')).toBe(false);
  });
  it('passes small range', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nEXPOSE 8080-8085'), 'DV4006')).toBe(false);
  });
});

describe('DV4007 - DEBIAN_FRONTEND as ENV', () => {
  it('flags ENV DEBIAN_FRONTEND=noninteractive', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV DEBIAN_FRONTEND=noninteractive'), 'DV4007')).toBe(true);
  });
  it('passes ARG DEBIAN_FRONTEND', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nARG DEBIAN_FRONTEND=noninteractive'), 'DV4007')).toBe(false);
  });
  it('passes other ENV', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nENV NODE_ENV=production'), 'DV4007')).toBe(false);
  });
});

describe('DV4008 - TODO/FIXME comments', () => {
  it('flags TODO comment', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\n# TODO: fix this'), 'DV4008')).toBe(true);
  });
  it('flags FIXME comment', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\n# FIXME: broken'), 'DV4008')).toBe(true);
  });
  it('flags HACK comment', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\n# HACK: workaround'), 'DV4008')).toBe(true);
  });
  it('passes normal comment', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\n# Install dependencies'), 'DV4008')).toBe(false);
  });
});

describe('DV4009 - chmod 777', () => {
  it('flags chmod 777', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod 777 /app'), 'DV4009')).toBe(true);
  });
  it('passes chmod 755', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod 755 /app'), 'DV4009')).toBe(false);
  });
  it('passes no chmod', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV4009')).toBe(false);
  });
  it('flags chmod -R 777', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod -R 777 /usr/bin'), 'DV4009')).toBe(true);
  });
  it('flags chmod -fR 777', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chmod -fR 777 /app'), 'DV4009')).toBe(true);
  });
});

describe('DV4010 - chown -R', () => {
  it('flags chown -R', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chown -R app:app /app'), 'DV4010')).toBe(true);
  });
  it('passes chown without -R', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chown app:app /app/file.txt'), 'DV4010')).toBe(false);
  });
  it('passes no chown', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN echo hi'), 'DV4010')).toBe(false);
  });
  it('skips system directories like /tmp', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chown -R 65532:65532 /tmp'), 'DV4010')).toBe(false);
  });
  it('skips /home directory', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chown -R nonroot:nonroot /home/nonroot/.yarn/berry'), 'DV4010')).toBe(false);
  });
  it('still flags app directories', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nRUN chown -R app:app /app'), 'DV4010')).toBe(true);
  });
});

describe('DV4011 - WORKDIR relative path', () => {
  it('flags relative WORKDIR', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR src'), 'DV4011')).toBe(true);
  });
  it('flags relative path with subdirectory', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR app/src'), 'DV4011')).toBe(true);
  });
  it('passes absolute path', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR /app'), 'DV4011')).toBe(false);
  });
  it('passes variable reference', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nARG APP_DIR=/app\nWORKDIR $APP_DIR'), 'DV4011')).toBe(false);
  });
  it('passes quoted absolute path (double quotes)', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nWORKDIR "/app"'), 'DV4011')).toBe(false);
  });
  it('passes quoted absolute path (single quotes)', () => {
    expect(hasRule(lintDockerfile("FROM ubuntu\nWORKDIR '/app'"), 'DV4011')).toBe(false);
  });
});

describe('DV4012 - consecutive COPY instructions', () => {
  it('flags consecutive COPY without --from', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY package.json .\nCOPY tsconfig.json .'), 'DV4012')).toBe(true);
  });
  it('passes COPY separated by RUN', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY package.json .\nRUN npm install\nCOPY . .'), 'DV4012')).toBe(false);
  });
  it('passes single COPY', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY . .'), 'DV4012')).toBe(false);
  });
  it('passes consecutive COPY with different destinations (Go monorepo pattern)', () => {
    expect(hasRule(lintDockerfile('FROM golang\nCOPY pkg/util pkg/util\nCOPY pkg/api pkg/api\nCOPY pkg/build pkg/build'), 'DV4012')).toBe(false);
  });
  it('flags consecutive COPY with same destination', () => {
    expect(hasRule(lintDockerfile('FROM ubuntu\nCOPY file1.txt /app/\nCOPY file2.txt /app/'), 'DV4012')).toBe(true);
  });
});
