/**
 * SPDX 2.3 SBOM formatter
 * Specification: https://spdx.github.io/spdx-spec/v2.3/
 */

import { SbomComponent } from './extractor';

export interface SpdxOptions {
  /** Document name */
  documentName?: string;
  /** Tool version */
  toolVersion?: string;
  /** Creator organisation */
  organization?: string;
}

export function formatSPDX(
  components: SbomComponent[],
  options: SpdxOptions = {},
): string {
  const now = new Date().toISOString();
  const docName = options.documentName ?? 'DockerVet-SBOM';
  const ns = `https://dockervet.io/spdxdoc/${docName}-${Date.now()}`;

  const packages = components.map((c, idx) => {
    const spdxId = `SPDXRef-${sanitizeSpdxId(c.name)}-${idx}`;
    const pkg: any = {
      SPDXID: spdxId,
      name: c.name,
      versionInfo: c.version ?? 'NOASSERTION',
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      packageSourceInfo: `Extracted from Dockerfile line ${c.line} (${c.source})`,
    };

    if (c.purl) {
      pkg.externalRefs = [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: c.purl,
        },
      ];
    }

    return pkg;
  });

  const spdx = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: docName,
    documentNamespace: ns,
    creationInfo: {
      created: now,
      creators: [
        `Tool: dockervet-${options.toolVersion ?? '0.1.0'}`,
        ...(options.organization ? [`Organization: ${options.organization}`] : []),
      ],
    },
    packages,
    relationships: packages.map(p => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: p.SPDXID,
    })),
  };

  return JSON.stringify(spdx, null, 2);
}

function sanitizeSpdxId(name: string): string {
  return name.replace(/[^a-zA-Z0-9.-]/g, '-').replace(/^-+|-+$/g, '');
}
