#!/usr/bin/env node

import * as fs from 'fs';
import { parse } from './parser/parser';
import { lint } from './engine/linter';
import { loadConfig } from './engine/config';
import { formatTTY } from './formatter/tty';
import { formatJSON, formatJSONBatch } from './formatter/json';
import { formatSARIF, formatSARIFBatch } from './formatter/sarif';
import { fetchDockerfiles } from './github';
import { Violation } from './rules/types';

const VERSION = '0.1.0';

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

interface CLIOptions {
  format: string;
  configPath?: string;
  trustedRegistries: string[];
  ignoreRules: string[];
  noColor: boolean;
  useStdin: boolean;
  githubRef?: string;
  githubBranch?: string;
  files: string[];
}

interface ProcessResult {
  filename: string;
  violations: Violation[];
  exitCode: number;
}

function parseArgs(args: string[]): CLIOptions {
  const opts: CLIOptions = {
    format: 'tty',
    trustedRegistries: [],
    ignoreRules: [],
    noColor: false,
    useStdin: false,
    files: [],
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--format':
        opts.format = args[++i] || 'tty';
        break;
      case '--config':
        opts.configPath = args[++i];
        break;
      case '--trusted-registry':
        opts.trustedRegistries.push(args[++i]);
        break;
      case '--ignore':
        opts.ignoreRules.push(args[++i]);
        break;
      case '--no-color':
        opts.noColor = true;
        break;
      case '--stdin':
        opts.useStdin = true;
        break;
      case '--github':
        opts.githubRef = args[++i];
        break;
      case '--branch':
        opts.githubBranch = args[++i];
        break;
      default:
        if (!args[i].startsWith('-')) {
          opts.files.push(args[i]);
        }
        break;
    }
  }

  return opts;
}

function processContent(
  content: string, filename: string, config: any, trustedRegistries: string[]
): ProcessResult {
  const ast = parse(content);
  const violations = lint(ast, { config, trustedRegistries, filePath: filename });

  const hasErrors = violations.some(v => v.severity === 'error');
  const hasWarnings = violations.some(v => v.severity === 'warning');
  let exitCode = 0;
  if (hasErrors) exitCode = 2;
  else if (hasWarnings) exitCode = 1;

  return { filename, violations, exitCode };
}

function outputResults(
  results: ProcessResult[], format: string, noColor: boolean
): void {
  switch (format) {
    case 'json':
      console.log(formatJSONBatch(results));
      break;
    case 'sarif':
      console.log(formatSARIFBatch(results));
      break;
    default:
      for (const result of results) {
        console.log(formatTTY(result.violations, result.filename, !noColor && process.stdout.isTTY !== false));
      }
      break;
  }
}

async function handleGitHub(
  ref: string, branch: string | undefined, format: string,
  noColor: boolean, config: any, trustedRegistries: string[]
): Promise<number> {
  const entries = await fetchDockerfiles(ref, branch);
  const results: ProcessResult[] = [];
  
  for (const entry of entries) {
    const filename = `github:${ref}/${entry.path}`;
    const result = processContent(entry.content, filename, config, trustedRegistries);
    results.push(result);
  }
  
  outputResults(results, format, noColor);
  return Math.max(...results.map(r => r.exitCode), 0);
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    printUsage();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log(`dockervet ${VERSION}`);
    process.exit(0);
  }

  const opts = parseArgs(args);
  const config = loadConfig(opts.configPath);
  config.ignore = [...config.ignore, ...opts.ignoreRules];
  if (opts.trustedRegistries.length > 0) {
    config.trustedRegistries = [...config.trustedRegistries, ...opts.trustedRegistries];
  }

  if (opts.githubRef) {
    handleGitHub(opts.githubRef, opts.githubBranch, opts.format, opts.noColor, config, opts.trustedRegistries).then(
      (code) => process.exit(code),
      (err) => {
        console.error(`Error: ${(err as Error).message}`);
        process.exit(2);
      }
    );
    return;
  }

  if (opts.useStdin) {
    const content = fs.readFileSync(0, 'utf-8');
    const result = processContent(content, '<stdin>', config, opts.trustedRegistries);
    outputResults([result], opts.format, opts.noColor);
    process.exit(result.exitCode);
  }

  if (opts.files.length === 0) {
    console.error('Error: No Dockerfile specified. Use --stdin or provide file paths.');
    process.exit(2);
  }

  const results: ProcessResult[] = [];
  let maxExit = 0;
  
  for (const file of opts.files) {
    if (!fs.existsSync(file)) {
      console.error(`Error: File not found: ${file}`);
      maxExit = 2;
      continue;
    }
    const content = fs.readFileSync(file, 'utf-8');
    const result = processContent(content, file, config, opts.trustedRegistries);
    results.push(result);
    maxExit = Math.max(maxExit, result.exitCode);
  }
  
  outputResults(results, opts.format, opts.noColor);
  process.exit(maxExit);
}

main();
