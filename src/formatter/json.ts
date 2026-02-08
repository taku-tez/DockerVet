import { Violation } from '../rules/types';

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
