import * as fs from 'fs';
import * as path from 'path';

export interface DockerVetConfig {
  ignore: string[];
  trustedRegistries: string[];
  requiredLabels: string[];
  allowedLabels?: string[];
  override: Record<string, { severity?: string }>;
}

const DEFAULT_CONFIG: DockerVetConfig = {
  ignore: [],
  trustedRegistries: [],
  requiredLabels: [],
  override: {},
};

export function loadConfig(configPath?: string): DockerVetConfig {
  const searchPaths = configPath
    ? [configPath]
    : ['.dockervetrc.yaml', '.dockervetrc.yml', '.dockervetrc.json', '.dockervetrc'];

  for (const p of searchPaths) {
    const resolved = path.resolve(p);
    if (!fs.existsSync(resolved)) continue;

    const content = fs.readFileSync(resolved, 'utf-8');

    // Simple YAML parser for our config format (no dependency needed)
    if (p.endsWith('.json')) {
      return { ...DEFAULT_CONFIG, ...JSON.parse(content) };
    }

    return { ...DEFAULT_CONFIG, ...parseSimpleYaml(content) };
  }

  return { ...DEFAULT_CONFIG };
}

function parseSimpleYaml(content: string): Partial<DockerVetConfig> {
  const result: any = {};
  const lines = content.split('\n');
  let currentKey: string | null = null;
  let currentArray: string[] | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Array item
    if (trimmed.startsWith('- ') && currentKey && currentArray) {
      currentArray.push(trimmed.slice(2).trim().replace(/^["']|["']$/g, ''));
      continue;
    }

    // Key: value or Key:
    const kvMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*):\s*(.*)?$/);
    if (kvMatch) {
      if (currentKey && currentArray) {
        result[currentKey] = currentArray;
      }

      const key = kvMatch[1];
      const value = kvMatch[2]?.trim();

      if (!value) {
        currentKey = key;
        currentArray = [];
      } else if (value === '[]') {
        result[key] = [];
        currentKey = null;
        currentArray = null;
      } else if (value.startsWith('[')) {
        // Inline array
        result[key] = value.replace(/[\[\]]/g, '').split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean);
        currentKey = null;
        currentArray = null;
      } else {
        result[key] = value.replace(/^["']|["']$/g, '');
        currentKey = null;
        currentArray = null;
      }
    }
  }

  if (currentKey && currentArray) {
    result[currentKey] = currentArray;
  }

  return result;
}
