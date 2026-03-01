/**
 * CycloneDX 1.5 SBOM formatter
 * Specification: https://cyclonedx.org/specification/overview/
 */

import { SbomComponent } from './extractor';

export interface CycloneDxOptions {
  /** Tool version to embed in metadata */
  toolVersion?: string;
  /** Document metadata — source file name */
  source?: string;
}

export function formatCycloneDX(
  components: SbomComponent[],
  options: CycloneDxOptions = {},
): string {
  const now = new Date().toISOString();
  const serialNumber = `urn:uuid:${generateUUID()}`;

  const cdxComponents = components.map((c, idx) => {
    const comp: any = {
      type: c.type,
      'bom-ref': `${c.name}@${c.version ?? 'unknown'}-${idx}`,
      name: c.name,
    };

    if (c.version) comp.version = c.version;
    if (c.purl) comp.purl = c.purl;

    return comp;
  });

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [
        {
          vendor: 'DockerVet',
          name: 'dockervet',
          version: options.toolVersion ?? '0.1.0',
        },
      ],
      component: options.source
        ? { type: 'file', name: options.source }
        : undefined,
    },
    components: cdxComponents,
  };

  return JSON.stringify(bom, null, 2);
}

// Minimal UUID v4 generator (no crypto dependency for compatibility)
function generateUUID(): string {
  const hex = () => Math.floor(Math.random() * 16).toString(16);
  const s4 = () => Array.from({ length: 4 }, hex).join('');
  return `${s4()}${s4()}-${s4()}-4${s4().slice(1)}-${['8', '9', 'a', 'b'][Math.floor(Math.random() * 4)]}${s4().slice(1)}-${s4()}${s4()}${s4()}`;
}
