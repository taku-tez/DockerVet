import { describe, it, expect } from 'vitest';
import { lint } from '../../src/engine/linter';
import { parse } from '../../src/parser/parser';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };

function makeCtx(dockerfile: string) {
  return {
    ast: parse(dockerfile),
    trustedRegistries: [] as string[],
    requiredLabels: [] as string[],
  };
}

// Import rules directly for unit testing
import { DV7008 } from '../../src/rules/dv/runtime-hardening';
import { DV6023 } from '../../src/rules/dv/supply-chain-hardening';

describe('DV7008: useradd/groupadd without explicit UID/GID', () => {
  it('should flag useradd without --uid', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN useradd appuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].rule).toBe('DV7008');
    expect(violations[0].message).toContain('useradd without --uid');
  });

  it('should flag groupadd without --gid', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN groupadd appgroup');
    const violations = DV6023.check(makeCtx('FROM ubuntu\nRUN echo hello'));
    // Test groupadd
    const v = DV7008.check(ctx);
    expect(v.length).toBe(1);
    expect(v[0].message).toContain('groupadd without --gid');
  });

  it('should not flag useradd with --uid', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN useradd --uid 1001 appuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag useradd with -u', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN useradd -u 1001 appuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag groupadd with --gid', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN groupadd --gid 1001 appgroup');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag groupadd with -g', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN groupadd -g 1001 appgroup');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag useradd --system (system user gets system UID)', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN useradd --system sysuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag useradd -r (system user shorthand)', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN useradd -r sysuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag groupadd --system', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN groupadd --system sysgroup');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should flag both useradd and groupadd without IDs in chained commands', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN groupadd appgroup && useradd -g appgroup appuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(2);
  });

  it('should flag useradd without --uid even with other flags', () => {
    const ctx = makeCtx('FROM ubuntu\nRUN useradd -m -s /bin/bash -d /home/app appuser');
    const violations = DV7008.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].message).toContain('useradd without --uid');
  });
});

describe('DV6023: COPY --from external image without digest pin', () => {
  it('should flag COPY --from with external image using :latest', () => {
    const ctx = makeCtx('FROM ubuntu\nCOPY --from=nginx:latest /etc/nginx/nginx.conf /etc/nginx/');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].rule).toBe('DV6023');
    expect(violations[0].message).toContain('mutable tag');
  });

  it('should flag COPY --from with external image without tag (implicit latest)', () => {
    const ctx = makeCtx('FROM ubuntu\nCOPY --from=nginx /etc/nginx/nginx.conf /etc/nginx/');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(1);
    expect(violations[0].message).toContain('latest (implicit)');
  });

  it('should flag COPY --from with external image using specific but mutable tag', () => {
    const ctx = makeCtx('FROM ubuntu\nCOPY --from=golang:1.21 /usr/local/go /usr/local/go');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(1);
  });

  it('should not flag COPY --from with digest-pinned external image', () => {
    const ctx = makeCtx('FROM ubuntu\nCOPY --from=nginx@sha256:abc123def456 /etc/nginx/nginx.conf /etc/nginx/');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag COPY --from referencing build stage by alias', () => {
    const ctx = makeCtx('FROM golang:1.21 AS builder\nRUN go build -o /app\nFROM alpine\nCOPY --from=builder /app /app');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should not flag COPY --from referencing build stage by index', () => {
    const ctx = makeCtx('FROM golang:1.21 AS builder\nRUN go build -o /app\nFROM alpine\nCOPY --from=0 /app /app');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(0);
  });

  it('should flag COPY --from with registry-prefixed external image without digest', () => {
    const ctx = makeCtx('FROM ubuntu\nCOPY --from=gcr.io/distroless/static:nonroot /etc/passwd /etc/passwd');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(1);
  });

  it('should not flag COPY --from with registry-prefixed image with digest', () => {
    const ctx = makeCtx('FROM ubuntu\nCOPY --from=gcr.io/distroless/static@sha256:abc123 /etc/passwd /etc/passwd');
    const violations = DV6023.check(ctx);
    expect(violations.length).toBe(0);
  });
});
