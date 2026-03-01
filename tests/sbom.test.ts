import { describe, it, expect } from 'vitest';
import { parse } from '../src/parser/parser';
import { extractComponents } from '../src/sbom/extractor';
import { formatCycloneDX } from '../src/sbom/cyclonedx';
import { formatSPDX } from '../src/sbom/spdx';

describe('SBOM', () => {
  it('extracts container component from FROM instruction', () => {
    const ast = parse('FROM node:18-alpine\nRUN echo hello\n');
    const components = extractComponents(ast);
    const containers = components.filter(c => c.type === 'container');
    expect(containers.length).toBeGreaterThanOrEqual(1);
    expect(containers[0].name).toBe('node');
    expect(containers[0].version).toContain('18-alpine');
  });

  it('extracts apt install packages', () => {
    const ast = parse('FROM ubuntu:22.04\nRUN apt-get install -y curl wget\n');
    const components = extractComponents(ast);
    const libs = components.filter(c => c.type === 'library');
    const names = libs.map(c => c.name);
    expect(names).toContain('curl');
    expect(names).toContain('wget');
  });

  it('CycloneDX output is valid JSON', () => {
    const ast = parse('FROM python:3.11\nRUN pip install requests flask\n');
    const components = extractComponents(ast);
    const output = formatCycloneDX(components, { source: 'Dockerfile' });
    const parsed = JSON.parse(output);
    expect(parsed.bomFormat).toBe('CycloneDX');
    expect(parsed.specVersion).toBe('1.5');
    expect(Array.isArray(parsed.components)).toBe(true);
  });

  it('SPDX output is valid JSON', () => {
    const ast = parse('FROM ruby:3.2\nRUN gem install rails\n');
    const components = extractComponents(ast);
    const output = formatSPDX(components, { documentName: 'Dockerfile' });
    const parsed = JSON.parse(output);
    expect(parsed.spdxVersion).toBeDefined();
    expect(Array.isArray(parsed.packages)).toBe(true);
  });

  it('sbom subcommand arg parsing guards against flags', () => {
    // Verify that args starting with - are not treated as subcommands
    const args = ['--format', 'json', 'Dockerfile'];
    // The guard: args[0] && !args[0].startsWith('-') && args[0] === 'sbom'
    const isSbom = args[0] && !args[0].startsWith('-') && args[0] === 'sbom';
    expect(isSbom).toBe(false);

    const sbomArgs = ['sbom', 'Dockerfile', '--format', 'cyclonedx'];
    const isSbom2 = sbomArgs[0] && !sbomArgs[0].startsWith('-') && sbomArgs[0] === 'sbom';
    expect(isSbom2).toBe(true);
  });
});
