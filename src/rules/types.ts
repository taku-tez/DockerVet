import { DockerfileAST, DockerfileInstruction, Stage } from '../parser/types';

export type Severity = 'error' | 'warning' | 'info' | 'style';

export interface Violation {
  rule: string;
  severity: Severity;
  message: string;
  line: number;
  column?: number;
  instruction?: string;
}

export interface RuleContext {
  ast: DockerfileAST;
  trustedRegistries: string[];
  requiredLabels: string[];
  allowedLabels?: string[];
  filePath?: string;
}

export interface Rule {
  id: string;
  severity: Severity;
  description: string;
  url?: string;
  check(ctx: RuleContext): Violation[];
}
