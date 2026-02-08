import { describe, it, expect } from 'vitest';
import { parse } from '../src/parser/parser';
import { FromInstruction, CopyInstruction, EnvInstruction, ArgInstruction, ExposeInstruction, HealthcheckInstruction, LabelInstruction, UserInstruction, WorkdirInstruction } from '../src/parser/types';
import { tokenize } from '../src/parser/lexer';

describe('Lexer', () => {
  it('tokenizes empty lines', () => {
    const tokens = tokenize('\n\n');
    expect(tokens.filter(t => t.type === 'EMPTY').length).toBe(3);
  });

  it('tokenizes comments', () => {
    const tokens = tokenize('# This is a comment');
    expect(tokens[0].type).toBe('COMMENT');
  });

  it('tokenizes instructions', () => {
    const tokens = tokenize('FROM ubuntu:20.04');
    expect(tokens[0].type).toBe('INSTRUCTION');
    expect(tokens[0].value).toBe('FROM ubuntu:20.04');
  });

  it('handles line continuations', () => {
    const tokens = tokenize('RUN apt-get update \\\n  && apt-get install -y curl');
    expect(tokens[0].type).toBe('INSTRUCTION');
    expect(tokens[0].value).toContain('apt-get update');
    expect(tokens[0].value).toContain('apt-get install');
  });

  it('strips comments within line continuations', () => {
    const tokens = tokenize('RUN apk add --no-cache \\\n  # This is a comment\n  bash \\\n  curl');
    expect(tokens[0].type).toBe('INSTRUCTION');
    expect(tokens[0].value).not.toContain('comment');
    expect(tokens[0].value).toContain('bash');
    expect(tokens[0].value).toContain('curl');
  });
});

describe('Parser', () => {
  it('parses FROM instruction', () => {
    const ast = parse('FROM ubuntu:20.04');
    expect(ast.stages.length).toBe(1);
    const from = ast.stages[0].from;
    expect(from.image).toBe('ubuntu');
    expect(from.tag).toBe('20.04');
  });

  it('parses FROM with alias', () => {
    const ast = parse('FROM node:18 AS builder');
    expect(ast.stages[0].from.alias).toBe('builder');
  });

  it('parses FROM with digest', () => {
    const ast = parse('FROM ubuntu@sha256:abc123');
    expect(ast.stages[0].from.image).toBe('ubuntu');
    expect(ast.stages[0].from.digest).toBe('sha256:abc123');
  });

  it('parses FROM with platform', () => {
    const ast = parse('FROM --platform=linux/amd64 ubuntu:20.04');
    expect(ast.stages[0].from.platform).toBe('linux/amd64');
  });

  it('parses FROM scratch', () => {
    const ast = parse('FROM scratch');
    expect(ast.stages[0].from.image).toBe('scratch');
  });

  it('parses multi-stage builds', () => {
    const ast = parse('FROM node:18 AS builder\nRUN npm build\nFROM nginx:alpine\nCOPY --from=builder /app /usr/share/nginx/html');
    expect(ast.stages.length).toBe(2);
  });

  it('parses COPY instruction', () => {
    const ast = parse('FROM ubuntu\nCOPY src/ dest/');
    const inst = ast.stages[0].instructions[0] as CopyInstruction;
    expect(inst.type).toBe('COPY');
    expect(inst.sources).toEqual(['src/']);
    expect(inst.destination).toBe('dest/');
  });

  it('parses COPY --from', () => {
    const ast = parse('FROM ubuntu\nCOPY --from=builder /app /opt');
    const inst = ast.stages[0].instructions[0] as CopyInstruction;
    expect(inst.from).toBe('builder');
  });

  it('parses ADD instruction', () => {
    const ast = parse('FROM ubuntu\nADD archive.tar.gz /opt/');
    const inst = ast.stages[0].instructions[0] as CopyInstruction;
    expect(inst.type).toBe('ADD');
  });

  it('parses ENV with key=value', () => {
    const ast = parse('FROM ubuntu\nENV NODE_ENV=production');
    const inst = ast.stages[0].instructions[0] as EnvInstruction;
    expect(inst.pairs[0].key).toBe('NODE_ENV');
    expect(inst.pairs[0].value).toBe('production');
  });

  it('parses ENV with old form', () => {
    const ast = parse('FROM ubuntu\nENV NODE_ENV production');
    const inst = ast.stages[0].instructions[0] as EnvInstruction;
    expect(inst.pairs[0].key).toBe('NODE_ENV');
    expect(inst.pairs[0].value).toBe('production');
  });

  it('parses multiple ENV pairs', () => {
    const ast = parse('FROM ubuntu\nENV A=1 B=2');
    const inst = ast.stages[0].instructions[0] as EnvInstruction;
    expect(inst.pairs.length).toBe(2);
  });

  it('parses ARG', () => {
    const ast = parse('ARG VERSION=1.0\nFROM ubuntu');
    expect(ast.globalArgs[0].name).toBe('VERSION');
    expect(ast.globalArgs[0].defaultValue).toBe('1.0');
  });

  it('parses ARG without default', () => {
    const ast = parse('ARG VERSION\nFROM ubuntu');
    expect(ast.globalArgs[0].name).toBe('VERSION');
    expect(ast.globalArgs[0].defaultValue).toBeUndefined();
  });

  it('parses EXPOSE', () => {
    const ast = parse('FROM ubuntu\nEXPOSE 8080 443/tcp');
    const inst = ast.stages[0].instructions[0] as ExposeInstruction;
    expect(inst.ports.length).toBe(2);
    expect(inst.ports[0].port).toBe(8080);
    expect(inst.ports[1].port).toBe(443);
    expect(inst.ports[1].protocol).toBe('tcp');
  });

  it('parses HEALTHCHECK CMD', () => {
    const ast = parse('FROM ubuntu\nHEALTHCHECK CMD curl -f http://localhost/');
    const inst = ast.stages[0].instructions[0] as HealthcheckInstruction;
    expect(inst.none).toBe(false);
    expect(inst.cmd).toContain('curl');
  });

  it('parses HEALTHCHECK NONE', () => {
    const ast = parse('FROM ubuntu\nHEALTHCHECK NONE');
    const inst = ast.stages[0].instructions[0] as HealthcheckInstruction;
    expect(inst.none).toBe(true);
  });

  it('parses LABEL', () => {
    const ast = parse('FROM ubuntu\nLABEL maintainer="test"');
    const inst = ast.stages[0].instructions[0] as LabelInstruction;
    expect(inst.pairs[0].key).toBe('maintainer');
    expect(inst.pairs[0].value).toBe('test');
  });

  it('parses USER', () => {
    const ast = parse('FROM ubuntu\nUSER nobody');
    const inst = ast.stages[0].instructions[0] as UserInstruction;
    expect(inst.user).toBe('nobody');
  });

  it('parses WORKDIR', () => {
    const ast = parse('FROM ubuntu\nWORKDIR /app');
    const inst = ast.stages[0].instructions[0] as WorkdirInstruction;
    expect(inst.path).toBe('/app');
  });

  it('parses ONBUILD', () => {
    const ast = parse('FROM ubuntu\nONBUILD RUN echo hello');
    const inst = ast.stages[0].instructions[0];
    expect(inst.type).toBe('ONBUILD');
    expect(inst.innerInstruction?.type).toBe('RUN');
  });

  it('parses inline ignores (dockervet)', () => {
    const ast = parse('FROM ubuntu\n# dockervet ignore=DL3008,DV1001\nRUN apt-get install curl');
    expect(ast.inlineIgnores.get(3)).toEqual(['DL3008', 'DV1001']);
  });

  it('parses inline ignores (hadolint)', () => {
    const ast = parse('FROM ubuntu\n# hadolint ignore=DL3008\nRUN apt-get install curl');
    expect(ast.inlineIgnores.get(3)).toEqual(['DL3008']);
  });

  it('parses RUN instruction', () => {
    const ast = parse('FROM ubuntu\nRUN echo hello');
    expect(ast.stages[0].instructions[0].type).toBe('RUN');
    expect(ast.stages[0].instructions[0].arguments).toBe('echo hello');
  });

  it('parses CMD instruction', () => {
    const ast = parse('FROM ubuntu\nCMD ["node", "app.js"]');
    expect(ast.stages[0].instructions[0].type).toBe('CMD');
  });

  it('parses ENTRYPOINT', () => {
    const ast = parse('FROM ubuntu\nENTRYPOINT ["node"]');
    expect(ast.stages[0].instructions[0].type).toBe('ENTRYPOINT');
  });

  it('parses VOLUME', () => {
    const ast = parse('FROM ubuntu\nVOLUME /data');
    expect(ast.stages[0].instructions[0].type).toBe('VOLUME');
  });

  it('parses SHELL', () => {
    const ast = parse('FROM ubuntu\nSHELL ["/bin/bash", "-c"]');
    expect(ast.stages[0].instructions[0].type).toBe('SHELL');
  });

  it('parses STOPSIGNAL', () => {
    const ast = parse('FROM ubuntu\nSTOPSIGNAL SIGTERM');
    expect(ast.stages[0].instructions[0].type).toBe('STOPSIGNAL');
  });

  it('handles empty Dockerfile', () => {
    const ast = parse('');
    expect(ast.stages.length).toBe(0);
  });

  it('handles comments-only Dockerfile', () => {
    const ast = parse('# just a comment');
    expect(ast.stages.length).toBe(0);
    expect(ast.comments.length).toBe(1);
  });
});
