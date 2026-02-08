export interface Token {
  type: 'INSTRUCTION' | 'COMMENT' | 'EMPTY' | 'CONTINUATION';
  line: number;
  value: string;
  raw: string;
}

/**
 * Extract heredoc delimiter names from a Dockerfile instruction.
 * Supports: <<EOF, <<"EOF", <<'EOF', <<-EOF, <<-"EOF", <<-'EOF'
 * Returns array of delimiter names (without quotes/dash).
 */
function extractHeredocDelimiters(line: string): string[] {
  const delimiters: string[] = [];
  // Match <<[-]?["']?WORD["']? patterns
  const regex = /<<-?\s*(?:"([^"]+)"|'([^']+)'|([A-Za-z_][A-Za-z0-9_]*))/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(line)) !== null) {
    delimiters.push(m[1] ?? m[2] ?? m[3]);
  }
  return delimiters;
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

    // Handle heredoc syntax (BuildKit feature): COPY/RUN/ADD with <<DELIMITER
    // Collect all heredoc delimiters from the instruction, then skip until all are closed
    const heredocDelimiters = extractHeredocDelimiters(fullLine.trim());
    if (heredocDelimiters.length > 0) {
      let delimIdx = 0;
      i++;
      while (i < lines.length && delimIdx < heredocDelimiters.length) {
        if (lines[i].trim() === heredocDelimiters[delimIdx]) {
          delimIdx++;
        }
        i++;
      }
      tokens.push({ type: 'INSTRUCTION', line: startLine, value: fullLine.trim(), raw: fullLine });
      continue;
    }

    tokens.push({ type: 'INSTRUCTION', line: startLine, value: fullLine.trim(), raw: fullLine });
    i++;
  }

  return tokens;
}
