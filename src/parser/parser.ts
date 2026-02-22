import { tokenize } from './lexer';
import {
  DockerfileAST, DockerfileInstruction, FromInstruction, CopyInstruction,
  ExposeInstruction, HealthcheckInstruction, EnvInstruction, ArgInstruction,
  LabelInstruction, UserInstruction, WorkdirInstruction, Stage, InstructionType,
} from './types';

const VALID_INSTRUCTIONS = new Set<string>([
  'FROM', 'RUN', 'CMD', 'LABEL', 'EXPOSE', 'ENV', 'ADD', 'COPY',
  'ENTRYPOINT', 'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD',
  'STOPSIGNAL', 'HEALTHCHECK', 'SHELL', 'MAINTAINER',
]);

function parseFlags(args: string): { flags: Record<string, string>; rest: string } {
  const flags: Record<string, string> = {};
  let rest = args;
  // Do not capture space-separated value if next token starts with '[' (JSON array)
  // since COPY/ADD flags like --link, --mount use no value or use =value syntax
  const flagRegex = /^--([a-zA-Z][a-zA-Z0-9-]*)(?:=(\S+)|\s+(?!--|\[)(\S+))?/;

  while (rest.trim().startsWith('--')) {
    const m = rest.trim().match(flagRegex);
    if (!m) break;
    flags[m[1]] = m[2] ?? m[3] ?? 'true';
    rest = rest.trim().slice(m[0].length).trim();
  }
  return { flags, rest };
}

function parseFromArgs(args: string, line: number): FromInstruction {
  const { flags, rest } = parseFlags(args);
  const parts = rest.trim().split(/\s+/);
  let imageSpec = parts[0] || '';
  let alias: string | undefined;

  if (parts.length >= 3 && parts[1].toUpperCase() === 'AS') {
    alias = parts[2];
  }

  let image = imageSpec;
  let tag: string | undefined;
  let digest: string | undefined;

  if (imageSpec.includes('@')) {
    const [img, d] = imageSpec.split('@', 2);
    image = img;
    digest = d;
  } else if (imageSpec.includes(':')) {
    const [img, t] = imageSpec.split(':', 2);
    image = img;
    tag = t;
  }

  return {
    type: 'FROM', raw: `FROM ${args}`, line, arguments: args, flags,
    image, tag, digest, alias, platform: flags['platform'],
  };
}

function parseJsonArray(s: string): string[] | null {
  const trimmed = s.trim();
  if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed) && parsed.every((x: unknown) => typeof x === 'string')) return parsed;
  } catch { /* not valid JSON */ }
  return null;
}

function parseCopyArgs(type: 'COPY' | 'ADD', args: string, line: number): CopyInstruction {
  const { flags, rest } = parseFlags(args);
  const jsonArr = parseJsonArray(rest.trim());
  const parts = jsonArr ?? parseShellWords(rest.trim());
  const destination = parts.length > 0 ? parts[parts.length - 1] : '';
  const sources = parts.slice(0, -1);

  return {
    type, raw: `${type} ${args}`, line, arguments: args, flags,
    from: flags['from'], sources, destination,
    chown: flags['chown'], chmod: flags['chmod'],
  };
}

function parseShellWords(s: string): string[] {
  const words: string[] = [];
  let current = '';
  let inQuote: string | null = null;
  let escape = false;

  for (const ch of s) {
    if (escape) { current += ch; escape = false; continue; }
    if (ch === '\\' && !inQuote) { escape = true; continue; }
    if (ch === inQuote) { inQuote = null; continue; }
    if (!inQuote && (ch === '"' || ch === "'")) { inQuote = ch; continue; }
    if (!inQuote && /\s/.test(ch)) {
      if (current) { words.push(current); current = ''; }
      continue;
    }
    current += ch;
  }
  if (current) words.push(current);
  return words;
}

function parseExposeArgs(args: string, line: number): ExposeInstruction {
  const ports: Array<{ port: number; protocol?: string }> = [];
  for (const part of args.trim().split(/\s+/)) {
    const m = part.match(/^(\d+)(?:\/(tcp|udp))?$/i);
    if (m) {
      ports.push({ port: parseInt(m[1], 10), protocol: m[2]?.toLowerCase() });
    }
  }
  return { type: 'EXPOSE', raw: `EXPOSE ${args}`, line, arguments: args, flags: {}, ports };
}

function parseEnvArgs(args: string, line: number): EnvInstruction {
  const pairs: Array<{ key: string; value: string }> = [];
  const trimmed = args.trim();

  // New form: ENV KEY=VALUE KEY2=VALUE2
  if (trimmed.includes('=')) {
    const regex = /([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*?)"|'([^']*?)'|(\S*))/g;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(trimmed)) !== null) {
      pairs.push({ key: m[1], value: m[2] ?? m[3] ?? m[4] ?? '' });
    }
    if (pairs.length === 0) {
      // Fallback: single key=value
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        pairs.push({ key: trimmed.slice(0, eqIdx), value: trimmed.slice(eqIdx + 1) });
      }
    }
  } else {
    // Old form: ENV KEY VALUE
    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx > 0) {
      let val = trimmed.slice(spaceIdx + 1).trim();
      // Strip surrounding quotes (e.g. ENV API_TOKEN "" should yield empty string)
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      pairs.push({ key: trimmed.slice(0, spaceIdx), value: val });
    }
  }
  return { type: 'ENV', raw: `ENV ${args}`, line, arguments: args, flags: {}, pairs };
}

function parseArgArgs(args: string, line: number): ArgInstruction {
  const trimmed = args.trim();
  const eqIdx = trimmed.indexOf('=');
  if (eqIdx > 0) {
    let defaultValue = trimmed.slice(eqIdx + 1);
    // Strip surrounding quotes (e.g. ARG FOO="" or ARG FOO='bar') so rules see the actual value
    if (
      (defaultValue.startsWith('"') && defaultValue.endsWith('"')) ||
      (defaultValue.startsWith("'") && defaultValue.endsWith("'"))
    ) {
      defaultValue = defaultValue.slice(1, -1);
    }
    return {
      type: 'ARG', raw: `ARG ${args}`, line, arguments: args, flags: {},
      name: trimmed.slice(0, eqIdx), defaultValue,
    };
  }
  return { type: 'ARG', raw: `ARG ${args}`, line, arguments: args, flags: {}, name: trimmed };
}

function parseLabelArgs(args: string, line: number): LabelInstruction {
  const pairs: Array<{ key: string; value: string }> = [];
  const regex = /([^\s=]+)=(?:"((?:[^"\\]|\\.)*)"|'([^']*?)'|(\S*))/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(args)) !== null) {
    const key = m[1].replace(/^["']|["']$/g, '');
    pairs.push({ key, value: m[2] ?? m[3] ?? m[4] ?? '' });
  }
  return { type: 'LABEL', raw: `LABEL ${args}`, line, arguments: args, flags: {}, pairs };
}

function parseHealthcheckArgs(args: string, line: number): HealthcheckInstruction {
  const trimmed = args.trim();
  if (trimmed.toUpperCase() === 'NONE') {
    return { type: 'HEALTHCHECK', raw: `HEALTHCHECK ${args}`, line, arguments: args, flags: {}, none: true };
  }
  const cmdIdx = trimmed.toUpperCase().indexOf('CMD');
  const cmd = cmdIdx >= 0 ? trimmed.slice(cmdIdx + 3).trim() : trimmed;
  return { type: 'HEALTHCHECK', raw: `HEALTHCHECK ${args}`, line, arguments: args, flags: {}, none: false, cmd };
}

function parseInstruction(value: string, line: number): DockerfileInstruction {
  const spaceIdx = value.indexOf(' ');
  const keyword = (spaceIdx > 0 ? value.slice(0, spaceIdx) : value).toUpperCase();
  const args = spaceIdx > 0 ? value.slice(spaceIdx + 1) : '';

  if (!VALID_INSTRUCTIONS.has(keyword)) {
    return { type: 'RUN' as InstructionType, raw: value, line, arguments: value, flags: {} };
  }

  const type = keyword as InstructionType;

  switch (type) {
    case 'FROM': return parseFromArgs(args, line);
    case 'COPY': return parseCopyArgs('COPY', args, line);
    case 'ADD': return parseCopyArgs('ADD', args, line);
    case 'EXPOSE': return parseExposeArgs(args, line);
    case 'HEALTHCHECK': return parseHealthcheckArgs(args, line);
    case 'ENV': return parseEnvArgs(args, line);
    case 'ARG': return parseArgArgs(args, line);
    case 'LABEL': return parseLabelArgs(args, line);
    case 'USER': return { type, raw: `USER ${args}`, line, arguments: args, flags: {}, user: args.trim() } as UserInstruction;
    case 'WORKDIR': {
      // Strip surrounding quotes from the path (e.g. WORKDIR "/app" -> /app)
      const rawPath = args.trim();
      const unquotedPath = /^["'](.+)["']$/.test(rawPath) ? rawPath.slice(1, -1) : rawPath;
      return { type, raw: `WORKDIR ${args}`, line, arguments: args, flags: {}, path: unquotedPath } as WorkdirInstruction;
    }
    case 'ONBUILD': {
      const inner = parseInstruction(args.trim(), line);
      return { type: 'ONBUILD', raw: value, line, arguments: args, flags: {}, innerInstruction: inner };
    }
    default:
      return { type, raw: value, line, arguments: args, flags: {} };
  }
}

export function parse(content: string): DockerfileAST {
  const tokens = tokenize(content);
  const stages: Stage[] = [];
  const globalArgs: ArgInstruction[] = [];
  const comments: DockerfileInstruction[] = [];
  const inlineIgnores = new Map<number, string[]>();
  let currentStage: Stage | null = null;

  for (const token of tokens) {
    if (token.type === 'EMPTY') continue;

    if (token.type === 'COMMENT') {
      comments.push({ type: 'COMMENT', raw: token.value, line: token.line, arguments: token.value, flags: {} });

      // Parse inline ignores: # dockervet ignore=RULE1,RULE2 or # hadolint ignore=RULE1,RULE2
      const ignoreMatch = token.value.match(/^#\s*(?:dockervet|hadolint)\s+ignore\s*=\s*(.+)$/i);
      if (ignoreMatch) {
        const rules = ignoreMatch[1].split(',').map(r => r.trim());
        // Apply to next instruction line
        inlineIgnores.set(token.line, rules);
      }
      continue;
    }

    const instruction = parseInstruction(token.value, token.line);

    if (instruction.type === 'FROM') {
      currentStage = { from: instruction as FromInstruction, instructions: [], index: stages.length };
      stages.push(currentStage);
    } else if (instruction.type === 'ARG' && !currentStage) {
      globalArgs.push(instruction as ArgInstruction);
    } else if (currentStage) {
      currentStage.instructions.push(instruction);
    }
  }

  // Resolve inline ignores: map comment line -> next instruction line
  const resolvedIgnores = new Map<number, string[]>();
  for (const [commentLine, rules] of inlineIgnores) {
    // Find next instruction after this comment
    for (const stage of stages) {
      if (stage.from.line === commentLine + 1) {
        resolvedIgnores.set(stage.from.line, rules);
        break;
      }
      for (const inst of stage.instructions) {
        if (inst.line === commentLine + 1) {
          resolvedIgnores.set(inst.line, rules);
          break;
        }
      }
    }
    // Also support same-line comments (not common in Dockerfile but handle it)
    if (!resolvedIgnores.has(commentLine + 1)) {
      resolvedIgnores.set(commentLine + 1, rules);
    }
  }

  return { stages, globalArgs, comments, inlineIgnores: resolvedIgnores };
}
