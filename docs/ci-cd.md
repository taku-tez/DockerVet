# CI/CD Integration Guide

DockerVet integrates with all major CI/CD platforms via its SARIF output format and exit codes.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Warnings only |
| 2 | Errors found (or `fail-on` threshold reached) |
| 3 | Execution error (file not found, parse failure) |

## GitHub Actions

### Code Scanning Integration (Recommended)

Upload results to [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning) for inline PR annotations:

```yaml
name: DockerVet Scan

on: [push, pull_request]

jobs:
  dockervet:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Run DockerVet
        run: |
          npx dockervet Dockerfile --format sarif > results.sarif || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Simple Fail-on-Error

```yaml
- name: Lint Dockerfile
  run: npx dockervet Dockerfile
```

### Multiple Dockerfiles

```yaml
- name: Lint all Dockerfiles
  run: |
    find . -name 'Dockerfile*' -not -path '*/node_modules/*' | \
      xargs npx dockervet --format sarif > results.sarif || true
```

### With Policy File

```yaml
- name: Lint Dockerfile with policy
  run: npx dockervet Dockerfile --config .dockervet.yaml
```

## GitLab CI

```yaml
dockervet:
  stage: test
  image: node:22-alpine
  script:
    - npx --yes dockervet Dockerfile --format sarif > gl-sast-report.sarif || true
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    when: always
```

### With severity threshold

```yaml
dockervet:
  stage: test
  image: node:22-alpine
  script:
    - npx --yes dockervet Dockerfile --format tty
  allow_failure: false  # fail pipeline on errors
```

## CircleCI

```yaml
version: 2.1

jobs:
  dockervet:
    docker:
      - image: cimg/node:22.0
    steps:
      - checkout
      - run:
          name: Install DockerVet
          command: npm install -g dockervet
      - run:
          name: Lint Dockerfile
          command: dockervet Dockerfile --format json | tee dockervet-report.json
      - store_artifacts:
          path: dockervet-report.json
          destination: dockervet-report

workflows:
  version: 2
  lint:
    jobs:
      - dockervet
```

## Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Dockerfile Lint') {
            steps {
                sh 'npx --yes dockervet Dockerfile --format sarif > dockervet-results.sarif || true'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'dockervet-results.sarif'
                    // If you use Jenkins SARIF plugin:
                    // recordIssues(tools: [sarif(pattern: 'dockervet-results.sarif')])
                }
            }
        }
    }
}
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '22.x'

  - script: npx --yes dockervet Dockerfile --format sarif > $(Build.ArtifactStagingDirectory)/dockervet.sarif || true
    displayName: 'Run DockerVet'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'dockervet-results'
    condition: always()
```

## Configuration with `.dockervet.yaml`

Place a `.dockervet.yaml` in your repository root to configure DockerVet for CI:

```yaml
version: 2

# Fail CI when these severities are found
fail-on:
  - error
  - warning

# Ignore specific rules with expiry dates
ignore:
  - id: DV1009
    reason: "Base image digest pinning deferred to Q3 2026"
    expires: "2026-09-30"

# Auto-export SARIF alongside normal output
sarif:
  export: true
  outputFile: dockervet-results.sarif
```
