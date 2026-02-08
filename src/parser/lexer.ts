export interface Token {
  type: 'INSTRUCTION' | 'COMMENT' | 'EMPTY' | 'CONTINUATION';
  line: number;
  value: string;
  raw: string;
}

export function tokenize(content: string): Token[] {
  const lines = content.split('\n');
  const tokens: Token[] = [];
  let i = 0;

  while (i < lines.length) {
    const raw = lines[i];
    const trimmed = raw.trim();

    if (trimmed === '') {
      tokens.push({ type: 'EMPTY', line: i + 1, value: '', raw });
      i++;
      continue;
    }

    if (trimmed.startsWith('#')) {
      tokens.push({ type: 'COMMENT', line: i + 1, value: trimmed, raw });
      i++;
      continue;
    }

    // Handle line continuations
    let fullLine = raw;
    const startLine = i + 1;
    while (fullLine.trimEnd().endsWith('\\') && i + 1 < lines.length) {
      i++;
      const nextTrimmed = lines[i].trim();
      // Skip comment lines within continuations (e.g., `apk add --no-cache \ \n # comment \n pkg`)
      if (nextTrimmed.startsWith('#')) {
        fullLine = fullLine.trimEnd().slice(0, -1) + ' \\';
        continue;
      }
      fullLine = fullLine.trimEnd().slice(0, -1) + ' ' + nextTrimmed;
    }

    tokens.push({ type: 'INSTRUCTION', line: startLine, value: fullLine.trim(), raw: fullLine });
    i++;
  }

  return tokens;
}
