#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import { parse } from './parser/parser';
import { lint } from './engine/linter';
import { loadConfig } from './engine/config';
import { formatTTY } from './formatter/tty';
import { formatJSON } from './formatter/json';
import { formatSARIF } from './formatter/sarif';
import { fetchDockerfiles } from './github';

function printUsage(): void {
  console.log(`
dockervet - Dockerfile security linter

Usage:
  dockervet [options] <Dockerfile> [Dockerfile...]
  dockervet --stdin
  dockervet --github <owner/repo or URL> [--branch <branch>]

Options:
  --format <tty|json|sarif>    Output format (default: tty)
  --config <path>              Config file path
  --trusted-registry <reg>     Trusted registry (repeatable)
  --ignore <rule>              Ignore rule (repeatable)
  --no-color                   Disable colored output
  --stdin                      Read Dockerfile from stdin
  --github <ref>               GitHub repo (owner/repo, URL, or blob URL)
  --branch <branch>            Branch for --github (default: repo default)
  -h, --help                   Show this help
  -v, --version                Show version
`);
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('dockervet 0.1.0');
    process.exit(0);
  }

  let format = 'tty';
  let configPath: string | undefined;
  const trustedRegistries: string[] = [];
  const ignoreRules: string[] = [];
  let noColor = false;
  let useStdin = false;
  let githubRef: string | undefined;
  let githubBranch: string | undefined;
  const files: string[] = [];

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--format':
        format = args[++i] || 'tty';
        break;
      case '--config':
        configPath = args[++i];
        break;
      case '--trusted-registry':
        trustedRegistries.push(args[++i]);
        break;
      case '--ignore':
        ignoreRules.push(args[++i]);
        break;
      case '--no-color':
        noColor = true;
        break;
      case '--stdin':
        useStdin = true;
        break;
      case '--github':
        githubRef = args[++i];
        break;
      case '--branch':
        githubBranch = args[++i];
        break;
      default:
        if (!args[i].startsWith('-')) {
          files.push(args[i]);
        }
        break;
    }
  }

  const config = loadConfig(configPath);
  config.ignore = [...config.ignore, ...ignoreRules];
  if (trustedRegistries.length > 0) {
    config.trustedRegistries = [...config.trustedRegistries, ...trustedRegistries];
  }

  if (githubRef) {
    handleGitHub(githubRef, githubBranch, format, noColor, config, trustedRegistries).then(
      (code) => process.exit(code),
      (err) => {
        console.error(`Error: ${(err as Error).message}`);
        process.exit(2);
      }
    );
    return;
  }

  if (useStdin) {
    const content = fs.readFileSync(0, 'utf-8');
    const result = processContent(content, '<stdin>', format, noColor, config, trustedRegistries);
    process.exit(result);
  }

  if (files.length === 0) {
    console.error('Error: No Dockerfile specified. Use --stdin or provide file paths.');
    process.exit(2);
  }

  let maxExit = 0;
  for (const file of files) {
    if (!fs.existsSync(file)) {
      console.error(`Error: File not found: ${file}`);
      maxExit = 2;
      continue;
    }
    const content = fs.readFileSync(file, 'utf-8');
    const result = processContent(content, file, format, noColor, config, trustedRegistries);
    maxExit = Math.max(maxExit, result);
  }

  process.exit(maxExit);
}

function processContent(
  content: string, filename: string, format: string,
  noColor: boolean, config: any, trustedRegistries: string[]
): number {
  const ast = parse(content);
  const violations = lint(ast, { config, trustedRegistries });

  switch (format) {
    case 'json':
      console.log(formatJSON(violations, filename));
      break;
    case 'sarif':
      console.log(formatSARIF(violations, filename));
      break;
    default:
      console.log(formatTTY(violations, filename, !noColor && process.stdout.isTTY !== false));
      break;
  }

  const hasErrors = violations.some(v => v.severity === 'error');
  const hasWarnings = violations.some(v => v.severity === 'warning');
  if (hasErrors) return 2;
  if (hasWarnings) return 1;
  return 0;
}

async function handleGitHub(
  ref: string, branch: string | undefined, format: string,
  noColor: boolean, config: any, trustedRegistries: string[]
): Promise<number> {
  const entries = await fetchDockerfiles(ref, branch);
  let maxExit = 0;
  for (const entry of entries) {
    const filename = `github:${ref}/${entry.path}`;
    const result = processContent(entry.content, filename, format, noColor, config, trustedRegistries);
    maxExit = Math.max(maxExit, result);
  }
  return maxExit;
}

main();
