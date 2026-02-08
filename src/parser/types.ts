export type InstructionType =
  | 'FROM' | 'RUN' | 'CMD' | 'LABEL' | 'EXPOSE' | 'ENV' | 'ADD' | 'COPY'
  | 'ENTRYPOINT' | 'VOLUME' | 'USER' | 'WORKDIR' | 'ARG' | 'ONBUILD'
  | 'STOPSIGNAL' | 'HEALTHCHECK' | 'SHELL' | 'MAINTAINER' | 'COMMENT';

export interface DockerfileInstruction {
  type: InstructionType;
  raw: string;
  line: number;
  arguments: string;
  flags: Record<string, string>;
  /** For ONBUILD, the inner instruction */
  innerInstruction?: DockerfileInstruction;
}

export interface FromInstruction extends DockerfileInstruction {
  type: 'FROM';
  image: string;
  tag?: string;
  digest?: string;
  alias?: string;
  platform?: string;
}

export interface CopyInstruction extends DockerfileInstruction {
  type: 'COPY' | 'ADD';
  from?: string;
  sources: string[];
  destination: string;
  chown?: string;
  chmod?: string;
}

export interface ExposeInstruction extends DockerfileInstruction {
  type: 'EXPOSE';
  ports: Array<{ port: number; protocol?: string }>;
}

export interface HealthcheckInstruction extends DockerfileInstruction {
  type: 'HEALTHCHECK';
  none: boolean;
  cmd?: string;
}

export interface EnvInstruction extends DockerfileInstruction {
  type: 'ENV';
  pairs: Array<{ key: string; value: string }>;
}

export interface ArgInstruction extends DockerfileInstruction {
  type: 'ARG';
  name: string;
  defaultValue?: string;
}

export interface LabelInstruction extends DockerfileInstruction {
  type: 'LABEL';
  pairs: Array<{ key: string; value: string }>;
}

export interface UserInstruction extends DockerfileInstruction {
  type: 'USER';
  user: string;
}

export interface WorkdirInstruction extends DockerfileInstruction {
  type: 'WORKDIR';
  path: string;
}

export interface Stage {
  from: FromInstruction;
  instructions: DockerfileInstruction[];
  index: number;
}

export interface DockerfileAST {
  stages: Stage[];
  globalArgs: ArgInstruction[];
  comments: DockerfileInstruction[];
  inlineIgnores: Map<number, string[]>;
}
