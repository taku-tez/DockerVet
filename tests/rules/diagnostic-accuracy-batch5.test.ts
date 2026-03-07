import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/parser';
import { ALL_RULES, RULE_MAP } from '../../src/rules';
import { RuleContext } from '../../src/rules/types';

function makeCtx(dockerfile: string, filePath?: string): RuleContext {
  return {
    ast: parse(dockerfile),
    trustedRegistries: [],
    requiredLabels: [],
    filePath,
  };
}

function rulesFor(dockerfile: string, filePath?: string) {
  const ctx = makeCtx(dockerfile, filePath);
  return ALL_RULES.flatMap(r => r.check(ctx));
}

function ruleCheck(ruleId: string, dockerfile: string, filePath?: string) {
  const ctx = makeCtx(dockerfile, filePath);
  const rule = RULE_MAP.get(ruleId)!;
  return rule.check(ctx);
}

// ===========================================================================
// DV9001: Fix false positive on SSH public key files (.pub)
// ===========================================================================
describe('DV9001: SSH public key FP fix', () => {
  it('should NOT flag id_rsa.pub (public key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY id_rsa.pub /root/.ssh/authorized_keys\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(0);
  });

  it('should NOT flag id_ed25519.pub (public key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY id_ed25519.pub /root/.ssh/authorized_keys\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(0);
  });

  it('should NOT flag id_ecdsa.pub (public key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY id_ecdsa.pub /app/\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(0);
  });

  it('should NOT flag path with id_rsa.pub', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY ./test/fixture/testrepos/id_rsa.pub /app/\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(0);
  });

  it('should still flag id_rsa (private key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY id_rsa /root/.ssh/\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(1);
  });

  it('should still flag id_ed25519 (private key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY id_ed25519 /root/.ssh/\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(1);
  });

  it('should still flag path containing id_rsa (private key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY ./keys/id_rsa /root/.ssh/\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(1);
  });

  it('should still flag id_dsa (private key)', () => {
    const v = ruleCheck('DV9001', 'FROM ubuntu\nCOPY id_dsa /root/.ssh/\n');
    expect(v.filter(v => v.rule === 'DV9001')).toHaveLength(1);
  });
});

// ===========================================================================
// DL4006: Set SHELL -o pipefail before RUN with pipe
// ===========================================================================
describe('DL4006: pipefail for RUN with pipes', () => {
  it('should flag RUN with pipe without pipefail', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN curl http://example.com | tar xz\n');
    expect(v).toHaveLength(1);
    expect(v[0].rule).toBe('DL4006');
  });

  it('should flag RUN with pipe in multi-command', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN apt-get update && curl http://example.com | bash\n');
    expect(v).toHaveLength(1);
  });

  it('should NOT flag when SHELL sets pipefail', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nSHELL ["/bin/bash", "-o", "pipefail", "-c"]\nRUN curl http://example.com | tar xz\n');
    expect(v).toHaveLength(0);
  });

  it('should NOT flag when inline set -o pipefail', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN set -o pipefail && curl http://example.com | tar xz\n');
    expect(v).toHaveLength(0);
  });

  it('should NOT flag when bash -o pipefail -c is used inline', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN bash -o pipefail -c "curl http://example.com | tar xz"\n');
    expect(v).toHaveLength(0);
  });

  it('should NOT flag RUN without pipes', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN apt-get update && apt-get install -y curl\n');
    expect(v).toHaveLength(0);
  });

  it('should NOT flag || (logical OR)', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN test -f /tmp/foo || echo "not found"\n');
    expect(v).toHaveLength(0);
  });

  it('should NOT flag pipes inside quoted strings', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN echo "hello | world"\n');
    expect(v).toHaveLength(0);
  });

  it('should NOT flag pipes inside single-quoted strings', () => {
    const v = ruleCheck('DL4006', "FROM ubuntu\nRUN echo 'hello | world'\n");
    expect(v).toHaveLength(0);
  });

  it('should reset pipefail tracking per stage', () => {
    const v = ruleCheck('DL4006', [
      'FROM ubuntu AS builder',
      'SHELL ["/bin/bash", "-o", "pipefail", "-c"]',
      'RUN curl http://example.com | tar xz',
      'FROM alpine',
      'RUN wget http://example.com | tar xz',
    ].join('\n'));
    // Stage 1 has SHELL pipefail so no warning
    // Stage 2 does NOT have pipefail so should warn
    expect(v).toHaveLength(1);
    expect(v[0].line).toBeGreaterThan(3);
  });

  it('should flag multiple RUN pipes without pipefail', () => {
    const v = ruleCheck('DL4006', [
      'FROM ubuntu',
      'RUN curl http://a.com | tar xz',
      'RUN wget http://b.com | gunzip > /tmp/out',
    ].join('\n'));
    expect(v).toHaveLength(2);
  });

  it('should handle set -euo pipefail', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN set -euo pipefail && curl http://example.com | tar xz\n');
    expect(v).toHaveLength(0);
  });

  it('should handle continuation lines with pipes', () => {
    const v = ruleCheck('DL4006', 'FROM ubuntu\nRUN curl http://example.com \\\n  | tar xz\n');
    expect(v).toHaveLength(1);
  });
});
