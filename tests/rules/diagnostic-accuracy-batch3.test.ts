import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule, defaultConfig } from '../helpers';

// ============================================================================
// Diagnostic accuracy improvements batch 3 (2026-03-07)
// Focus: Extended token pattern detection + new rules DV3035, DV3036
//
// NOTE: Some test token values are constructed dynamically (string concat)
// to avoid triggering GitHub push protection / secret scanning.
// ============================================================================

// Helper to build Dockerfile strings with token patterns without
// the literal token appearing as a static string in source code.
function mkDf(lines: string[]): string {
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// DV3012: New token patterns - Anthropic API key
// ---------------------------------------------------------------------------
describe('DV3012 - Anthropic API key detection', () => {
  it('flags Anthropic API key (sk-ant-api03-...)', () => {
    const token = 'sk-ant-api' + '03-FAKE_TEST_VALUE_NOT_REAL_abcdef1234567890';
    const df = mkDf(['FROM python:3.12', `RUN echo ${token} > /tmp/key`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags Anthropic admin key (sk-ant-admin01-...)', () => {
    const token = 'sk-ant-admin' + '01-FAKE_TEST_VALUE_NOT_REAL_12345';
    const df = mkDf(['FROM python:3.12', `RUN curl -H "x-api-key: ${token}" https://api.anthropic.com/v1/messages`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: Stripe API key detection
// ---------------------------------------------------------------------------
describe('DV3012 - Stripe API key detection', () => {
  it('flags Stripe secret key', () => {
    // Build token dynamically to bypass GitHub secret scanning
    const token = ['sk', 'live', '00FAKE00notreal1234567890'].join('_');
    const df = mkDf(['FROM node:20', `RUN echo 'export KEY=${token}' > /tmp/env`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags Stripe restricted key', () => {
    const token = ['rk', 'live', '00FAKE00notreal1234567890'].join('_');
    const df = mkDf(['FROM node:20', `RUN echo 'export RK=${token}' > /tmp/env`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags Stripe test key', () => {
    const token = ['sk', 'test', '00FAKE00notreal1234567890'].join('_');
    const df = mkDf(['FROM node:20', `RUN echo 'export KEY=${token}' > /tmp/env`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: Slack token detection
// ---------------------------------------------------------------------------
describe('DV3012 - Slack token detection', () => {
  it('flags Slack bot token', () => {
    // Build xoxb token dynamically
    const token = 'xox' + 'b-000000000000-0000000000000-FAKENOTREAL12345678901';
    const df = mkDf(['FROM ubuntu:22.04', `RUN curl -H "Authorization: Bearer ${token}" https://slack.com/api/chat.postMessage`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });

  it('flags Slack webhook URL', () => {
    const url = 'https://hooks.slack' + '.com/services/T0000FAKE0/B0000FAKE0/FAKE00NOTREAL00VALUE0';
    const df = mkDf(['FROM ubuntu:22.04', `RUN curl -X POST ${url}`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: Vercel token detection
// ---------------------------------------------------------------------------
describe('DV3012 - Vercel token detection', () => {
  it('flags Vercel token', () => {
    const token = 'vcel' + '_FAKE00NOTREAL00VALUE0012345678901234567890';
    const df = mkDf(['FROM node:20', `RUN npx vercel --token=${token} deploy`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: Terraform Cloud token detection
// ---------------------------------------------------------------------------
describe('DV3012 - Terraform Cloud token detection', () => {
  it('flags Terraform Cloud token (atlasv1-...)', () => {
    const token = 'atlas' + 'v1-FAKE00NOTREAL00VALUE0012345678901234567890';
    const df = mkDf(['FROM hashicorp/terraform:1.6', `RUN terraform login -token=${token}`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: SendGrid API key detection
// ---------------------------------------------------------------------------
describe('DV3012 - SendGrid API key detection', () => {
  it('flags SendGrid API key (SG.xxx.yyy)', () => {
    const token = 'SG.FAKE00NOTREAL00VALUE00123.FAKE00NOTREAL00VALUE00456';
    const df = mkDf(['FROM python:3.12', `RUN echo ${token} > /tmp/key`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: Twilio API key detection
// ---------------------------------------------------------------------------
describe('DV3012 - Twilio API key detection', () => {
  it('flags Twilio API key (SK + 32 hex)', () => {
    // Build SK token dynamically
    const token = 'SK' + '00000000000000000000000000000000';
    const df = mkDf(['FROM node:20', `RUN echo 'TWILIO=${token}' > /tmp/env`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: Databricks PAT detection
// ---------------------------------------------------------------------------
describe('DV3012 - Databricks PAT detection', () => {
  it('flags Databricks PAT (dapi + hex)', () => {
    const token = 'dapi' + '00000000000000000000000000000000000000';
    const df = mkDf(['FROM python:3.12', `RUN echo ${token} > /tmp/dbr`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: JFrog Artifactory token detection
// ---------------------------------------------------------------------------
describe('DV3012 - JFrog Artifactory token detection', () => {
  it('flags JFrog Artifactory token (AKCp...)', () => {
    const token = 'AKCp' + '00FAKE00NOT00REAL';
    const df = mkDf(['FROM maven:3.9', `RUN curl -H "X-JFrog-Art-Api: ${token}" https://artifactory.example.com/api/system/ping`]);
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DV3012: No false positives for common patterns
// ---------------------------------------------------------------------------
describe('DV3012 - No false positives', () => {
  it('does NOT flag plain curl commands', () => {
    const df = `FROM ubuntu:22.04
RUN curl -fsSL https://example.com/file.tar.gz -o /tmp/file.tar.gz`;
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(false);
  });

  it('does NOT flag npm install without tokens', () => {
    const df = `FROM node:20
RUN npm ci --production`;
    expect(hasRule(lintDockerfile(df), 'DV3012')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV3035: JWT token detection in RUN
// ---------------------------------------------------------------------------
describe('DV3035 - JWT token in RUN detection', () => {
  it('flags hardcoded JWT token in curl header', () => {
    // Construct a structurally valid JWT with "alg":"none" header (not a real secret)
    const jwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ0ZXN0IjoiZmFrZSJ9.fakesignaturevalue';
    const df = mkDf(['FROM ubuntu:22.04', `RUN curl -H "Authorization: Bearer ${jwt}" https://api.example.com/data`]);
    expect(hasRule(lintDockerfile(df), 'DV3035')).toBe(true);
  });

  it('flags JWT token echoed to file', () => {
    const jwt = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJ0ZXN0IiwiZmFrZSI6dHJ1ZX0.not_a_real_signature_1234';
    const df = mkDf(['FROM python:3.12', `RUN echo ${jwt} > /tmp/token`]);
    expect(hasRule(lintDockerfile(df), 'DV3035')).toBe(true);
  });

  it('does NOT flag RUN without JWT', () => {
    const df = `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl`;
    expect(hasRule(lintDockerfile(df), 'DV3035')).toBe(false);
  });

  it('does NOT flag ENV with JWT-like prefix (only targets RUN)', () => {
    const df = `FROM ubuntu:22.04
ENV TOKEN=some_value`;
    expect(hasRule(lintDockerfile(df), 'DV3035')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DV3036: Azure SAS token detection
// ---------------------------------------------------------------------------
describe('DV3036 - Azure SAS token detection', () => {
  it('flags Azure blob storage URL with SAS token in RUN', () => {
    const df = `FROM ubuntu:22.04
RUN curl "https://fakeaccount.blob.core.windows.net/container/blob?sv=2021-06-08&sig=FAKE00NOTREAL00SIGNATURE"`;
    expect(hasRule(lintDockerfile(df), 'DV3036')).toBe(true);
  });

  it('flags Azure file storage URL with SAS token in ADD', () => {
    const df = `FROM ubuntu:22.04
ADD https://fakeaccount.file.core.windows.net/share/file.tar.gz?sv=2021-06-08&sig=FAKE00TEST /tmp/`;
    expect(hasRule(lintDockerfile(df), 'DV3036')).toBe(true);
  });

  it('flags Azure dfs (Data Lake) storage URL with SAS token', () => {
    const df = `FROM ubuntu:22.04
RUN curl "https://fakedatalake.dfs.core.windows.net/filesystem/path?sig=FAKE00TEST&sv=2021-06-08"`;
    expect(hasRule(lintDockerfile(df), 'DV3036')).toBe(true);
  });

  it('does NOT flag Azure storage URL without SAS token', () => {
    const df = `FROM ubuntu:22.04
RUN curl https://fakeaccount.blob.core.windows.net/container/blob`;
    expect(hasRule(lintDockerfile(df), 'DV3036')).toBe(false);
  });

  it('does NOT flag non-Azure URLs', () => {
    const df = `FROM ubuntu:22.04
RUN curl https://example.com/file.tar.gz`;
    expect(hasRule(lintDockerfile(df), 'DV3036')).toBe(false);
  });
});
