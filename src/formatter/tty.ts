import { Violation } from '../rules/types';

const COLORS = {
  error: '\x1b[31m',
  warning: '\x1b[33m',
  info: '\x1b[36m',
  style: '\x1b[90m',
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
};

export function formatTTY(violations: Violation[], filename: string, useColor = true): string {
  if (violations.length === 0) {
    return useColor
      ? `${COLORS.bold}${filename}${COLORS.reset}: ${COLORS.dim}No issues found ✓${COLORS.reset}\n`
      : `${filename}: No issues found\n`;
  }

  const lines: string[] = [];
  if (useColor) {
    lines.push(`${COLORS.bold}${filename}${COLORS.reset}`);
  } else {
    lines.push(filename);
  }

  for (const v of violations) {
    if (useColor) {
      const color = COLORS[v.severity] || COLORS.info;
      lines.push(`  ${COLORS.dim}${v.line}${COLORS.reset} ${color}${v.severity}${COLORS.reset} ${COLORS.dim}${v.rule}${COLORS.reset} ${v.message}`);
    } else {
      lines.push(`  ${v.line} ${v.severity} ${v.rule} ${v.message}`);
    }
  }

  const errors = violations.filter(v => v.severity === 'error').length;
  const warnings = violations.filter(v => v.severity === 'warning').length;
  const infos = violations.filter(v => v.severity === 'info' || v.severity === 'style').length;

  const summary = `\n  ${errors} error(s), ${warnings} warning(s), ${infos} info(s)\n`;
  if (useColor) {
    lines.push(`${COLORS.dim}${summary}${COLORS.reset}`);
  } else {
    lines.push(summary);
  }

  return lines.join('\n');
}
