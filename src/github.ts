import * as https from 'https';

export interface GitHubRef {
  owner: string;
  repo: string;
  branch?: string;
  path?: string;
}

export interface DockerfileEntry {
  path: string;
  content: string;
}

/**
 * Parse a GitHub URL or owner/repo shorthand into structured components.
 */
export function parseGitHubURL(input: string): GitHubRef {
  // owner/repo shorthand
  const shorthand = /^([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)$/;
  const m = input.match(shorthand);
  if (m) {
    return { owner: m[1], repo: m[2] };
  }

  // Full URL: https://github.com/owner/repo[/blob/branch/path]
  const urlPattern = /^https?:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?(?:\/(?:blob|tree)\/([^/]+)\/(.+))?$/;
  const um = input.match(urlPattern);
  if (um) {
    return {
      owner: um[1],
      repo: um[2],
      branch: um[3] || undefined,
      path: um[4] || undefined,
    };
  }

  throw new Error(`Invalid GitHub reference: ${input}`);
}

/**
 * Template file extensions that indicate the file is a template
 * requiring preprocessing before it can be parsed as a Dockerfile.
 * These files often contain placeholder values (e.g., ALPINE_BASEIMAGE)
 * or template syntax (e.g., ERB, Jinja2) that cause false positives.
 */
const TEMPLATE_EXTENSIONS = /\.(erb|j2|jinja|jinja2|tmpl|tpl|template)$/i;

/**
 * Check if a file path matches Dockerfile patterns.
 */
export function isDockerfile(filePath: string): boolean {
  const basename = filePath.split('/').pop() || '';
  // Skip template files (ERB, Jinja2, Go templates, generic .template)
  if (TEMPLATE_EXTENSIONS.test(basename)) return false;
  if (basename === 'Dockerfile') return true;
  if (basename.endsWith('.Dockerfile') || basename.endsWith('.dockerfile')) return true;
  if (/^Dockerfile\..+/.test(basename)) return true;
  return false;
}

function githubRequest(urlPath: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {
      'User-Agent': 'dockervet',
      'Accept': 'application/vnd.github.v3+json',
    };
    const token = process.env.GITHUB_TOKEN;
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request(
      {
        hostname: 'api.github.com',
        path: urlPath,
        method: 'GET',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
        res.on('end', () => {
          if (res.statusCode === 404) {
            reject(new Error(`GitHub API 404: ${urlPath}`));
            return;
          }
          if (res.statusCode === 403) {
            reject(new Error('GitHub API rate limit exceeded. Set GITHUB_TOKEN to increase limit.'));
            return;
          }
          if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
            reject(new Error(`GitHub API error ${res.statusCode}: ${data}`));
            return;
          }
          try {
            resolve(JSON.parse(data));
          } catch {
            reject(new Error(`Failed to parse GitHub API response: ${data.slice(0, 200)}`));
          }
        });
      }
    );
    req.on('error', (err: Error) => reject(new Error(`Network error: ${err.message}`)));
    req.end();
  });
}

/**
 * Get the default branch of a repository.
 */
async function getDefaultBranch(owner: string, repo: string): Promise<string> {
  const data = await githubRequest(`/repos/${owner}/${repo}`);
  return data.default_branch;
}

/**
 * Paths that indicate vendored/third-party code which should not be scanned.
 * Findings in these directories reflect upstream projects, not the repo under review.
 */
const VENDOR_PATH_PATTERN = /(?:^|\/)(vendor|node_modules)(?:\/|$)/i;

/**
 * Find Dockerfiles in a repository.
 */
async function findDockerfiles(owner: string, repo: string, branch: string): Promise<string[]> {
  const data = await githubRequest(`/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`);
  if (!data.tree || !Array.isArray(data.tree)) {
    throw new Error('Unexpected response from GitHub tree API');
  }
  return data.tree
    .filter((entry: any) =>
      entry.type === 'blob' &&
      isDockerfile(entry.path) &&
      !VENDOR_PATH_PATTERN.test(entry.path)
    )
    .map((entry: any) => entry.path);
}

/**
 * Fetch file content from a repository.
 */
async function fetchFileContent(owner: string, repo: string, filePath: string): Promise<string> {
  const data = await githubRequest(`/repos/${owner}/${repo}/contents/${filePath}`);
  if (data.encoding === 'base64') {
    // content may be empty string for zero-byte files; that's valid
    return data.content ? Buffer.from(data.content, 'base64').toString('utf-8') : '';
  }
  throw new Error(`Unexpected encoding for ${filePath}: ${data.encoding}`);
}

/**
 * Fetch Dockerfiles from a GitHub repository or specific file.
 */
export async function fetchDockerfiles(
  input: string,
  branch?: string
): Promise<DockerfileEntry[]> {
  const ref = parseGitHubURL(input);
  const effectiveBranch = branch || ref.branch || await getDefaultBranch(ref.owner, ref.repo);

  // If a specific path is given, fetch just that file
  if (ref.path) {
    const content = await fetchFileContent(ref.owner, ref.repo, ref.path);
    return [{ path: ref.path, content }];
  }

  // Otherwise, find all Dockerfiles
  const paths = await findDockerfiles(ref.owner, ref.repo, effectiveBranch);
  if (paths.length === 0) {
    throw new Error(`No Dockerfiles found in ${ref.owner}/${ref.repo}`);
  }

  const results: DockerfileEntry[] = [];
  for (const p of paths) {
    const content = await fetchFileContent(ref.owner, ref.repo, p);
    results.push({ path: p, content });
  }
  return results;
}
