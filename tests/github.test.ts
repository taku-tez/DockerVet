import { describe, it, expect } from 'vitest';
import { parseGitHubURL, isDockerfile } from '../src/github';

describe('parseGitHubURL', () => {
  it('parses owner/repo shorthand', () => {
    const r = parseGitHubURL('nginx/nginx');
    expect(r).toEqual({ owner: 'nginx', repo: 'nginx' });
  });

  it('parses full HTTPS URL', () => {
    const r = parseGitHubURL('https://github.com/moby/moby');
    expect(r).toEqual({ owner: 'moby', repo: 'moby', branch: undefined, path: undefined });
  });

  it('parses URL with .git suffix', () => {
    const r = parseGitHubURL('https://github.com/moby/moby.git');
    expect(r).toEqual({ owner: 'moby', repo: 'moby', branch: undefined, path: undefined });
  });

  it('parses blob URL with branch and path', () => {
    const r = parseGitHubURL('https://github.com/nginx/nginx/blob/main/Dockerfile');
    expect(r).toEqual({ owner: 'nginx', repo: 'nginx', branch: 'main', path: 'Dockerfile' });
  });

  it('parses blob URL with nested path', () => {
    const r = parseGitHubURL('https://github.com/owner/repo/blob/develop/docker/app/Dockerfile');
    expect(r).toEqual({ owner: 'owner', repo: 'repo', branch: 'develop', path: 'docker/app/Dockerfile' });
  });

  it('parses tree URL', () => {
    const r = parseGitHubURL('https://github.com/owner/repo/tree/v2/subdir/Dockerfile.prod');
    expect(r).toEqual({ owner: 'owner', repo: 'repo', branch: 'v2', path: 'subdir/Dockerfile.prod' });
  });

  it('parses HTTP URL', () => {
    const r = parseGitHubURL('http://github.com/a/b');
    expect(r).toEqual({ owner: 'a', repo: 'b', branch: undefined, path: undefined });
  });

  it('throws on invalid input', () => {
    expect(() => parseGitHubURL('not-valid')).toThrow('Invalid GitHub reference');
  });

  it('throws on random URL', () => {
    expect(() => parseGitHubURL('https://gitlab.com/a/b')).toThrow('Invalid GitHub reference');
  });

  it('parses owner/repo with dots and hyphens', () => {
    const r = parseGitHubURL('my-org/my.repo');
    expect(r).toEqual({ owner: 'my-org', repo: 'my.repo' });
  });
});

describe('isDockerfile', () => {
  it('matches Dockerfile', () => {
    expect(isDockerfile('Dockerfile')).toBe(true);
  });

  it('matches nested Dockerfile', () => {
    expect(isDockerfile('docker/Dockerfile')).toBe(true);
  });

  it('matches Dockerfile.prod', () => {
    expect(isDockerfile('Dockerfile.prod')).toBe(true);
  });

  it('matches app.Dockerfile', () => {
    expect(isDockerfile('app.Dockerfile')).toBe(true);
  });

  it('matches deeply nested', () => {
    expect(isDockerfile('a/b/c/Dockerfile')).toBe(true);
  });

  it('rejects README.md', () => {
    expect(isDockerfile('README.md')).toBe(false);
  });

  it('rejects docker-compose.yml', () => {
    expect(isDockerfile('docker-compose.yml')).toBe(false);
  });

  it('matches case-sensitive .dockerfile', () => {
    expect(isDockerfile('test.dockerfile')).toBe(true);
  });

  it('rejects Dockerfile substring in name', () => {
    expect(isDockerfile('notDockerfile')).toBe(false);
  });

  it('rejects ERB template files', () => {
    expect(isDockerfile('Dockerfile.template.erb')).toBe(false);
    expect(isDockerfile('Dockerfile.erb')).toBe(false);
  });

  it('rejects Jinja2 template files', () => {
    expect(isDockerfile('Dockerfile.j2')).toBe(false);
    expect(isDockerfile('Dockerfile.jinja2')).toBe(false);
    expect(isDockerfile('Dockerfile.jinja')).toBe(false);
  });

  it('rejects Go/Helm template files', () => {
    expect(isDockerfile('Dockerfile.tmpl')).toBe(false);
    expect(isDockerfile('Dockerfile.tpl')).toBe(false);
  });

  it('rejects generic .template files', () => {
    expect(isDockerfile('Dockerfile.template')).toBe(false);
    expect(isDockerfile('weave-kube/Dockerfile.template')).toBe(false);
  });

  it('rejects documentation files (man pages, markdown, etc.)', () => {
    // Dockerfile.5.md is the Dockerfile man page, not an actual Dockerfile
    expect(isDockerfile('Dockerfile.5.md')).toBe(false);
    expect(isDockerfile('man/Dockerfile.5.md')).toBe(false);
    expect(isDockerfile('Dockerfile.md')).toBe(false);
    expect(isDockerfile('Dockerfile.rst')).toBe(false);
    expect(isDockerfile('Dockerfile.txt')).toBe(false);
    expect(isDockerfile('Dockerfile.adoc')).toBe(false);
  });

  it('rejects data/config files that start with Dockerfile.', () => {
    expect(isDockerfile('Dockerfile.yaml')).toBe(false);
    expect(isDockerfile('Dockerfile.json')).toBe(false);
  });
});

// Note: vendor/ and node_modules/ path filtering is tested via VENDOR_PATH_PATTERN
// in findDockerfiles() rather than isDockerfile() since it's a path-level filter.
// The unit tests for that logic are covered by integration scan behavior.
