import { Violation } from '../rules/types';

export interface ViolationEntry {
  file: string;
  line: number;
  column: number;
  rule: string;
  severity: 'error' | 'warning' | 'info' | 'style';
  message: string;
}

export function formatJSON(violations: Violation[], filename: string): string {
  return JSON.stringify(violations.map(v => ({
    file: filename,
    line: v.line,
    column: v.column || 1,
    rule: v.rule,
    severity: v.severity,
    message: v.message,
  })), null, 2);
}

interface ProcessResult {
  filename: string;
  violations: Violation[];
  exitCode: number;
}

/**
 * Format multiple file results as a single JSON array.
 * This ensures valid JSON output when processing multiple files.
 */
export function formatJSONBatch(results: ProcessResult[]): string {
  const allViolations: ViolationEntry[] = [];
  
  for (const result of results) {
    for (const v of result.violations) {
      allViolations.push({
        file: result.filename,
        line: v.line,
        column: v.column || 1,
        rule: v.rule,
        severity: v.severity,
        message: v.message,
      });
    }
  }
  
  return JSON.stringify(allViolations, null, 2);
}
