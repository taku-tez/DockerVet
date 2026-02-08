# DockerVet 🐳🔍

Dockerfile security linter — Hadolint-compatible rules + security-focused DockerVet rules.

**Zero runtime dependencies.** Written in TypeScript.

## Installation

```bash
npm install -g dockervet
```

## Usage

```bash
# Lint a Dockerfile
dockervet Dockerfile

# Read from stdin
cat Dockerfile | dockervet --stdin

# JSON output
dockervet Dockerfile --format json

# SARIF output (for GitHub Code Scanning)
dockervet Dockerfile --format sarif

# Ignore specific rules
dockervet Dockerfile --ignore DL3008 --ignore DV1009

# Trusted registries
dockervet Dockerfile --trusted-registry gcr.io --trusted-registry docker.io
```

## Rules

### Hadolint-Compatible (DL3xxx)

DockerVet implements all major Hadolint rules:

| Rule | Severity | Description |
|------|----------|-------------|
| DL3000 | error | Use absolute WORKDIR |
| DL3001 | info | Avoid inappropriate commands (ssh, vim, etc.) |
| DL3002 | warning | Last USER should not be root |
| DL3003 | warning | Use WORKDIR instead of cd |
| DL3004 | error | Do not use sudo |
| DL3006 | warning | Always tag image version |
| DL3007 | warning | Do not use :latest tag |
| DL3008 | warning | Pin versions in apt-get install |
| DL3009 | info | Delete apt-get lists |
| DL3010 | info | Use ADD for extracting archives |
| DL3011 | error | Valid UNIX ports (0-65535) |
| DL3012 | error | Only one HEALTHCHECK per stage |
| DL3013 | warning | Pin versions in pip |
| DL3014 | warning | Use -y with apt-get |
| DL3015 | info | Use --no-install-recommends |
| DL3016 | warning | Pin versions in npm |
| DL3018 | warning | Pin versions in apk |
| DL3019 | info | Use --no-cache with apk |
| DL3020 | error | Use COPY instead of ADD for files |
| DL3021 | error | COPY with 3+ args needs / destination |
| DL3022 | warning | COPY --from must reference defined alias |
| DL3023 | error | COPY --from cannot self-reference |
| DL3024 | error | FROM aliases must be unique |
| DL3025 | warning | Use JSON notation for CMD/ENTRYPOINT |
| DL3026 | error | Use only allowed registries |
| DL3027 | warning | Use apt-get, not apt |
| DL3028 | warning | Pin versions in gem |
| DL3029 | warning | Do not use --platform with FROM |
| DL3030 | warning | Use -y with yum |
| DL3032 | warning | yum clean all after yum |
| DL3033 | warning | Pin versions in yum |
| DL3034 | warning | Use -y with zypper |
| DL3035 | warning | Do not use zypper dist-upgrade |
| DL3036 | warning | zypper clean after zypper |
| DL3037 | warning | Pin versions in zypper |
| DL3038 | warning | Use -y with dnf |
| DL3040 | warning | dnf clean all after dnf |
| DL3041 | warning | Pin versions in dnf |
| DL3042 | warning | Use --no-cache-dir with pip |
| DL3043 | error | ONBUILD cannot contain FROM/MAINTAINER |
| DL3044 | error | No self-reference in same ENV statement |
| DL3045 | warning | COPY relative dest without WORKDIR |
| DL3046 | warning | useradd without -l + high UID |
| DL3047 | info | wget --progress recommended |
| DL3048 | info | Invalid label key |
| DL3049 | info | Required label missing |
| DL3050 | info | Superfluous label |
| DL3057 | info | HEALTHCHECK missing |

### DockerVet Security Rules (DV1xxx)

| Rule | Severity | Description |
|------|----------|-------------|
| DV1001 | error | Hardcoded secrets in ENV/ARG |
| DV1002 | warning | Privileged operations |
| DV1003 | error | Unsafe curl/wget pipe to shell |
| DV1004 | info | Multi-stage build recommended |
| DV1005 | info | .dockerignore recommended |
| DV1006 | warning | No non-root USER set |
| DV1007 | warning | Package manager cache not cleaned |
| DV1008 | warning | COPY . . too broad |
| DV1009 | info | Base image not pinned by digest |

### CIS Docker Benchmark Rules (DV2xxx)

| Rule | Severity | Description |
|------|----------|-------------|
| DV2001 | warning | apt-get update used alone without install |
| DV2002 | warning | apt-get dist-upgrade should be avoided |
| DV2003 | error | Sensitive system directories as VOLUME |
| DV2004 | info | Missing --no-install-recommends |
| DV2005 | warning | MAINTAINER is deprecated |
| DV2006 | warning | Multiple ENTRYPOINT instructions |
| DV2007 | warning | Multiple CMD instructions |
| DV2008 | warning | apt-get update/install in separate RUNs |
| DV2009 | warning | Unsafe shell in SHELL instruction |

### Security Advanced Rules (DV3xxx)

| Rule | Severity | Description |
|------|----------|-------------|
| DV3001 | error | Cloud credential patterns (AWS/GCP) |
| DV3002 | error | SSH private key COPY/ADD |
| DV3003 | warning | .env file COPY/ADD |
| DV3004 | warning | Certificate/private key COPY |
| DV3005 | error | GPG private key COPY |
| DV3006 | error | Unauthenticated package install |
| DV3007 | warning | TLS verification disabled |
| DV3008 | warning | git clone with possible credentials |
| DV3009 | warning | EXPOSE 22 (SSH) |
| DV3010 | warning | VOLUME on sensitive paths |

### Best Practices Rules (DV4xxx)

| Rule | Severity | Description |
|------|----------|-------------|
| DV4001 | info | Multiple package install RUNs |
| DV4002 | info | Consecutive RUN instructions (3+) |
| DV4003 | info | No WORKDIR before RUN |
| DV4004 | info | ARG defined after ENV |
| DV4005 | info | No CMD or ENTRYPOINT in final stage |
| DV4006 | warning | Large EXPOSE port range |
| DV4007 | info | DEBIAN_FRONTEND as global ENV |
| DV4008 | info | TODO/FIXME/HACK comments |
| DV4009 | warning | chmod 777 excessive permissions |
| DV4010 | info | Recursive chown -R increases layer size |

## Configuration

Create `.dockervetrc.yaml`:

```yaml
ignore:
  - DV1009
  - DL3057

trustedRegistries:
  - docker.io
  - gcr.io

requiredLabels:
  - maintainer
  - version
```

## Inline Ignores

```dockerfile
# dockervet ignore=DL3008,DV1001
RUN apt-get install curl

# hadolint ignore=DL3008
RUN apt-get install wget
```

Both `dockervet` and `hadolint` inline ignore formats are supported.

## Output Formats

- **tty** (default): Colored terminal output
- **json**: Machine-readable JSON array
- **sarif**: SARIF 2.1.0 for GitHub Code Scanning / VS Code

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues (or only info/style) |
| 1 | Warnings found |
| 2 | Errors found |

## GitHub Actions

```yaml
- name: Lint Dockerfile
  run: |
    npx dockervet Dockerfile --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Part of the xxVet Series

- **[ApiVet](https://github.com/tez-hub/apivet)** — OpenAPI linter
- **[WpVet](https://github.com/tez-hub/wpvet)** — WordPress security scanner
- **DockerVet** — Dockerfile security linter

## License

MIT
