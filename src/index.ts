#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import { parse } from './parser/parser';
import { lint } from './engine/linter';
import { loadConfig } from './engine/config';
import { formatTTY } from './formatter/tty';
import { formatJSON } from './formatter/json';
import { formatSARIF } from './formatter/sarif';

function printUsage(): void {
  console.log(`
dockervet - Dockerfile security linter

Usage:
  dockervet [options] <Dockerfile> [Dockerfile...]
  dockervet --stdin

Options:
  --format <tty|json|sarif>    Output format (default: tty)
  --config <path>              Config file path
  --trusted-registry <reg>     Trusted registry (repeatable)
  --ignore <rule>              Ignore rule (repeatable)
  --no-color                   Disable colored output
  --stdin                      Read Dockerfile from stdin
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

main();
