/**
 * SBOM Component Extractor
 *
 * Extracts software components from a parsed Dockerfile AST:
 * - Base images (FROM instructions)
 * - Package manager installs (apt/apk/dnf/pip/npm/gem)
 * - Copied binaries (estimated from COPY/ADD of known binary paths)
 */

import { DockerfileAST } from '../parser/types';
import { EnvInstruction, ArgInstruction, CopyInstruction } from '../parser/types';

export type ComponentType = 'container' | 'library' | 'framework' | 'operating-system' | 'file';

export interface SbomComponent {
  type: ComponentType;
  name: string;
  version?: string;
  /** Package URL (https://github.com/package-url/purl-spec) */
  purl?: string;
  /** Source instruction (e.g. "FROM", "RUN apt-get install") */
  source: string;
  /** Line number in the Dockerfile */
  line: number;
}

// ---------------------------------------------------------------------------
// Package extraction regexes
// ---------------------------------------------------------------------------

interface PkgPattern {
  manager: string;
  purlType: string;
  installCmd: RegExp;
  pkgExtractor: (args: string) => string[];
}

const PKG_MANAGERS: PkgPattern[] = [
  {
    manager: 'apt',
    purlType: 'deb',
    installCmd: /\bapt(?:-get)?\s+install\b/,
    pkgExtractor: extractAptPackages,
  },
  {
    manager: 'apk',
    purlType: 'apk',
    installCmd: /\bapk\s+add\b/,
    pkgExtractor: extractApkPackages,
  },
  {
    manager: 'dnf',
    purlType: 'rpm',
    installCmd: /\b(?:dnf|yum|microdnf)\s+install\b/,
    pkgExtractor: extractDnfPackages,
  },
  {
    manager: 'pip',
    purlType: 'pypi',
    installCmd: /\bpip(?:3)?\s+install\b/,
    pkgExtractor: extractPipPackages,
  },
  {
    manager: 'npm',
    purlType: 'npm',
    installCmd: /\bnpm\s+install\b/,
    pkgExtractor: extractNpmPackages,
  },
  {
    manager: 'gem',
    purlType: 'gem',
    installCmd: /\bgem\s+install\b/,
    pkgExtractor: extractGemPackages,
  },
];

// ---------------------------------------------------------------------------
// Package name / version parsing helpers
// ---------------------------------------------------------------------------

function parseNameVersion(pkg: string): { name: string; version?: string } {
  // apt: curl=7.68.0 or curl
  // apk: curl==7.80 or curl=7.80 or curl
  // rpm: curl-7.68 or curl
  // pip: requests==2.28 or requests>=2.0 or requests
  const m = pkg.match(/^([a-zA-Z0-9._-]+?)(?:[=<>!~]{1,2}(.+))?$/);
  if (m) return { name: m[1], version: m[2] };
  return { name: pkg };
}

function extractAptPackages(args: string): string[] {
  // Strip install flags and command prefix
  const clean = args
    .replace(/apt(?:-get)?\s+install/, '')
    .replace(/-y\b|--yes\b|--no-install-recommends\b|--fix-missing\b/g, '')
    .replace(/&&.*/s, ''); // stop at next command
  return clean.split(/\s+/).map(s => s.trim()).filter(s => s && !s.startsWith('-'));
}

function extractApkPackages(args: string): string[] {
  const clean = args
    .replace(/apk\s+add/, '')
    .replace(/--no-cache\b|--update\b|-U\b/g, '')
    .replace(/&&.*/s, '');
  return clean.split(/\s+/).map(s => s.trim()).filter(s => s && !s.startsWith('-'));
}

function extractDnfPackages(args: string): string[] {
  const clean = args
    .replace(/(?:dnf|yum|microdnf)\s+install/, '')
    .replace(/-y\b|--assumeyes\b|--setopt\S*/g, '')
    .replace(/&&.*/s, '');
  return clean.split(/\s+/).map(s => s.trim()).filter(s => s && !s.startsWith('-'));
}

function extractPipPackages(args: string): string[] {
  const clean = args
    .replace(/pip(?:3)?\s+install/, '')
    .replace(/--no-cache-dir\b|--upgrade\b|-U\b|--user\b|-r\s+\S+/g, '')
    .replace(/&&.*/s, '');
  return clean.split(/[\s,]+/).map(s => s.trim()).filter(s => s && !s.startsWith('-'));
}

function extractNpmPackages(args: string): string[] {
  const clean = args
    .replace(/npm\s+install/, '')
    .replace(/-g\b|--global\b|--save-dev\b|-D\b|--save\b|-S\b|--production\b/g, '')
    .replace(/&&.*/s, '');
  return clean.split(/\s+/).map(s => s.trim()).filter(s => s && !s.startsWith('-'));
}

function extractGemPackages(args: string): string[] {
  const clean = args
    .replace(/gem\s+install/, '')
    .replace(/--no-document\b|--no-rdoc\b|--no-ri\b|-v\s+\S+/g, '')
    .replace(/&&.*/s, '');
  return clean.split(/\s+/).map(s => s.trim()).filter(s => s && !s.startsWith('-'));
}

function buildPurl(type: string, name: string, version?: string): string {
  const v = version ? `@${version}` : '';
  return `pkg:${type}/${encodeURIComponent(name)}${v}`;
}

// ---------------------------------------------------------------------------
// Main extraction function
// ---------------------------------------------------------------------------

export function extractComponents(ast: DockerfileAST): SbomComponent[] {
  const components: SbomComponent[] = [];

  for (const stage of ast.stages) {
    const f = stage.from;

    // Base image component
    if (f.image !== 'scratch') {
      const imageName = f.image;
      const tag = f.tag;
      const digest = f.digest;
      const version = digest ? `${tag}@${digest}` : tag;

      components.push({
        type: 'container',
        name: imageName,
        version,
        purl: `pkg:oci/${encodeURIComponent(imageName)}${version ? `@${version}` : ''}`,
        source: 'FROM',
        line: f.line,
      });
    }

    for (const inst of stage.instructions) {
      if (inst.type !== 'RUN') continue;

      const args = inst.arguments;

      for (const pm of PKG_MANAGERS) {
        if (!pm.installCmd.test(args)) continue;

        const pkgs = pm.pkgExtractor(args);
        for (const rawPkg of pkgs) {
          if (!rawPkg) continue;
          const { name, version } = parseNameVersion(rawPkg);
          if (!name || name.length < 2) continue;
          components.push({
            type: 'library',
            name,
            version,
            purl: buildPurl(pm.purlType, name, version),
            source: `RUN ${pm.manager} install`,
            line: inst.line,
          });
        }
      }
    }
  }

  return components;
}
