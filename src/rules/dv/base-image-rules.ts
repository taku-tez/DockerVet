import { Rule, Violation } from '../types';

// ---------------------------------------------------------------------------
// DV5xxx: Base Image Recommendation & Update Detection
// ---------------------------------------------------------------------------

/**
 * Known LTS / recommended upgrade paths for popular base images.
 * Format: { image: string, eolVersions: string[], latestLTS: string }
 */
interface ImageVersion {
  /** Image tags or version prefixes that are outdated */
  outdated: string[];
  /** Recommended replacement tag */
  recommended: string;
  /** Human-readable note */
  note: string;
}

const OUTDATED_IMAGE_MAP: Record<string, ImageVersion> = {
  ubuntu: {
    outdated: ['14.04', '16.04', '18.04', '20.04', '21.04', '21.10', '22.10', '23.04', '23.10'],
    recommended: 'ubuntu:24.04',
    note: 'Ubuntu 24.04 LTS (Noble Numbat)',
  },
  debian: {
    outdated: ['7', '8', '9', '10', 'wheezy', 'jessie', 'stretch', 'buster'],
    recommended: 'debian:12',
    note: 'Debian 12 (Bookworm)',
  },
  node: {
    outdated: ['8', '10', '12', '14', '16', '17', '18', '19', '20', '21'],
    recommended: 'node:22',
    note: 'Node.js 22 LTS (Iron)',
  },
  python: {
    outdated: ['2', '2.7', '3.6', '3.7', '3.8', '3.9', '3.10'],
    recommended: 'python:3.12',
    note: 'Python 3.12',
  },
  alpine: {
    outdated: ['3.14', '3.15', '3.16', '3.17', '3.18'],
    recommended: 'alpine:3.20',
    note: 'Alpine 3.20',
  },
  golang: {
    outdated: ['1.17', '1.18', '1.19', '1.20', '1.21'],
    recommended: 'golang:1.23',
    note: 'Go 1.23',
  },
  openjdk: {
    outdated: ['8', '11', '13', '14', '15', '16', '17', '18', '19', '20'],
    recommended: 'eclipse-temurin:21',
    note: 'Eclipse Temurin 21 LTS',
  },
  maven: {
    outdated: ['3.6', '3.7', '3.8'],
    recommended: 'maven:3.9',
    note: 'Maven 3.9',
  },
  nginx: {
    outdated: ['1.18', '1.19', '1.20', '1.21', '1.22', '1.23', '1.24'],
    recommended: 'nginx:1.27',
    note: 'nginx 1.27',
  },
  php: {
    outdated: ['7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1'],
    recommended: 'php:8.3',
    note: 'PHP 8.3',
  },
  ruby: {
    outdated: ['2.6', '2.7', '3.0', '3.1'],
    recommended: 'ruby:3.3',
    note: 'Ruby 3.3',
  },
  rust: {
    outdated: ['1.65', '1.66', '1.67', '1.68', '1.69', '1.70', '1.71', '1.72', '1.73', '1.74', '1.75'],
    recommended: 'rust:1.80',
    note: 'Rust 1.80',
  },
};

/**
 * End-of-life image database.
 * Format: imageWithTag → { eolDate: ISO date string, note: string }
 */
interface EolInfo {
  eolDate: string;
  note: string;
}

const EOL_IMAGE_DB: Record<string, EolInfo> = {
  // Ubuntu
  'ubuntu:14.04': { eolDate: '2019-04-25', note: 'Ubuntu 14.04 LTS EOL' },
  'ubuntu:16.04': { eolDate: '2021-04-30', note: 'Ubuntu 16.04 LTS EOL' },
  'ubuntu:18.04': { eolDate: '2023-04-30', note: 'Ubuntu 18.04 LTS EOL' },
  'ubuntu:20.04': { eolDate: '2025-04-30', note: 'Ubuntu 20.04 LTS EOL' },
  // Debian
  'debian:7':      { eolDate: '2018-05-31', note: 'Debian 7 (Wheezy) EOL' },
  'debian:8':      { eolDate: '2020-06-30', note: 'Debian 8 (Jessie) EOL' },
  'debian:9':      { eolDate: '2022-06-30', note: 'Debian 9 (Stretch) EOL' },
  'debian:10':     { eolDate: '2024-06-30', note: 'Debian 10 (Buster) EOL' },
  'debian:wheezy': { eolDate: '2018-05-31', note: 'Debian 7 (Wheezy) EOL' },
  'debian:jessie': { eolDate: '2020-06-30', note: 'Debian 8 (Jessie) EOL' },
  'debian:stretch':{ eolDate: '2022-06-30', note: 'Debian 9 (Stretch) EOL' },
  'debian:buster': { eolDate: '2024-06-30', note: 'Debian 10 (Buster) EOL' },
  // Node.js
  'node:8':  { eolDate: '2019-12-31', note: 'Node.js 8 EOL' },
  'node:10': { eolDate: '2021-04-30', note: 'Node.js 10 EOL' },
  'node:12': { eolDate: '2022-04-30', note: 'Node.js 12 EOL' },
  'node:14': { eolDate: '2023-04-30', note: 'Node.js 14 EOL' },
  'node:16': { eolDate: '2023-09-11', note: 'Node.js 16 EOL' },
  'node:18': { eolDate: '2025-04-30', note: 'Node.js 18 EOL' },
  'node:20': { eolDate: '2026-04-30', note: 'Node.js 20 EOL' },
  // Python
  'python:2.7': { eolDate: '2020-01-01', note: 'Python 2.7 EOL' },
  'python:3.6': { eolDate: '2021-12-23', note: 'Python 3.6 EOL' },
  'python:3.7': { eolDate: '2023-06-27', note: 'Python 3.7 EOL' },
  'python:3.8': { eolDate: '2024-10-31', note: 'Python 3.8 EOL' },
  // Alpine
  'alpine:3.14': { eolDate: '2023-05-01', note: 'Alpine 3.14 EOL' },
  'alpine:3.15': { eolDate: '2023-11-01', note: 'Alpine 3.15 EOL' },
  'alpine:3.16': { eolDate: '2024-05-23', note: 'Alpine 3.16 EOL' },
  'alpine:3.17': { eolDate: '2024-11-22', note: 'Alpine 3.17 EOL' },
  // OpenJDK
  'openjdk:8':  { eolDate: '2022-05-01', note: 'OpenJDK 8 (community) EOL' },
  'openjdk:11': { eolDate: '2024-10-31', note: 'OpenJDK 11 EOL' },
};

/**
 * Distroless / slim alternatives for common base images.
 */
interface BaseImageAlternative {
  alternative: string;
  reason: string;
}

const SAFER_ALTERNATIVES: Record<string, BaseImageAlternative> = {
  ubuntu:   { alternative: 'gcr.io/distroless/base-debian12', reason: 'Distroless image has no shell, reducing attack surface' },
  debian:   { alternative: 'gcr.io/distroless/base-debian12', reason: 'Distroless image has no shell, reducing attack surface' },
  node:     { alternative: 'gcr.io/distroless/nodejs22-debian12', reason: 'Distroless Node image has no shell or package manager' },
  python:   { alternative: 'gcr.io/distroless/python3-debian12', reason: 'Distroless Python image has no shell' },
  openjdk:  { alternative: 'gcr.io/distroless/java21-debian12', reason: 'Distroless Java image reduces attack surface' },
  golang:   { alternative: 'gcr.io/distroless/static-debian12', reason: 'Use distroless/static as final stage for Go binaries' },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseImageName(fullImage: string): { name: string; tag: string } {
  // Handle registry prefix: e.g. docker.io/library/node:18 → node:18
  let image = fullImage;
  const lastSlash = image.lastIndexOf('/');
  if (lastSlash !== -1) image = image.slice(lastSlash + 1);

  const colonIdx = image.indexOf(':');
  if (colonIdx === -1) return { name: image, tag: 'latest' };
  return { name: image.slice(0, colonIdx), tag: image.slice(colonIdx + 1) };
}

function isVersionOutdated(tag: string, outdatedList: string[]): boolean {
  return outdatedList.some(v => tag === v || tag.startsWith(v + '-') || tag.startsWith(v + '.'));
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

/** DV5001: Outdated Base Image */
export const DV5001: Rule = {
  id: 'DV5001', severity: 'warning',
  description: 'Outdated base image detected. Consider upgrading to a newer version.',
  check(ctx) {
    const violations: Violation[] = [];
    for (const stage of ctx.ast.stages) {
      const f = stage.from;
      if (f.image === 'scratch') continue;
      if (/\$/.test(f.image)) continue; // variable reference

      const { name, tag } = parseImageName(f.image);
      const info = OUTDATED_IMAGE_MAP[name.toLowerCase()];
      if (!info) continue;
      if (tag === 'latest') continue; // skip :latest — handled by DL3007

      if (isVersionOutdated(tag, info.outdated)) {
        violations.push({
          rule: 'DV5001', severity: 'warning',
          message: `Base image "${f.image}" is outdated. Recommended: ${info.recommended} (${info.note}).`,
          line: f.line,
        });
      }
    }
    return violations;
  },
};

/** DV5002: EOL Base Image */
export const DV5002: Rule = {
  id: 'DV5002', severity: 'error',
  description: 'End-of-life base image detected. No security patches are available.',
  check(ctx) {
    const violations: Violation[] = [];
    const now = new Date();

    for (const stage of ctx.ast.stages) {
      const f = stage.from;
      if (f.image === 'scratch') continue;
      if (/\$/.test(f.image)) continue;

      // Try exact match first, then name:tag
      const { name, tag } = parseImageName(f.image);
      const key = `${name.toLowerCase()}:${tag}`;
      const eolInfo = EOL_IMAGE_DB[key];

      if (eolInfo) {
        const eolDate = new Date(eolInfo.eolDate);
        if (eolDate <= now) {
          violations.push({
            rule: 'DV5002', severity: 'error',
            message: `Base image "${f.image}" reached end-of-life on ${eolInfo.eolDate} (${eolInfo.note}). No security updates are available. Please upgrade immediately.`,
            line: f.line,
          });
        }
      }
    }
    return violations;
  },
};

/** DV5003: Safer Base Image Alternative Available */
export const DV5003: Rule = {
  id: 'DV5003', severity: 'info',
  description: 'A more secure base image alternative is available (distroless / Alpine).',
  check(ctx) {
    const violations: Violation[] = [];

    // Only check the final stage (the shipped image)
    const lastStage = ctx.ast.stages[ctx.ast.stages.length - 1];
    if (!lastStage) return violations;

    const f = lastStage.from;
    if (f.image === 'scratch') return violations;
    if (/\$/.test(f.image)) return violations;

    const { name, tag } = parseImageName(f.image);

    // Skip if already using distroless, Alpine, or slim
    if (/distroless|alpine|slim|chainguard|cgr\.dev/.test(f.image)) return violations;

    const alt = SAFER_ALTERNATIVES[name.toLowerCase()];
    if (alt) {
      violations.push({
        rule: 'DV5003', severity: 'info',
        message: `Consider using "${alt.alternative}" instead of "${f.image}" for the final stage. ${alt.reason}.`,
        line: f.line,
      });
    }

    return violations;
  },
};
