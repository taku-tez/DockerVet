import { describe, it, expect } from 'vitest';
import { parse } from '../../src/parser/parser';
import { lint } from '../../src/engine/linter';

const defaultConfig = { ignore: [], trustedRegistries: [], requiredLabels: [], override: {} };

function lintContent(content: string, filePath?: string) {
  const ast = parse(content);
  return lint(ast, { config: defaultConfig, filePath });
}

function ruleSet(violations: ReturnType<typeof lintContent>) {
  return [...new Set(violations.map(v => v.rule))].sort();
}

// ── prometheus/prometheus patterns ──────────────────────────────────────

describe('OSS: prometheus/prometheus patterns', () => {
  it('.gitpod.Dockerfile: untagged image, sudo usage, no user', () => {
    const v = lintContent(`FROM gitpod/workspace-full
RUN sudo apt-get update && sudo apt-get install -y build-essential
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3004')).toBe(true);  // sudo usage
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('Dockerfile: multi-stage with :latest tag, no healthcheck', () => {
    const v = lintContent(`FROM prom/busybox:latest AS builder
COPY . /app

FROM quay.io/prometheus/busybox:latest
LABEL maintainer="The Prometheus Authors"
COPY --from=builder /app/prometheus /bin/prometheus
EXPOSE 9090
VOLUME ["/prometheus"]
WORKDIR /prometheus
ENTRYPOINT ["/bin/prometheus"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);
  });

  it('Dockerfile.distroless: pinned with digest does not trigger DL3006', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12@sha256:abc123
COPY prometheus /bin/prometheus
ENTRYPOINT ["/bin/prometheus"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
  });
});

// ── containerd/containerd patterns ─────────────────────────────────────

describe('OSS: containerd/containerd patterns', () => {
  it('.devcontainer: unpinned apt, no user, single-stage build', () => {
    const v = lintContent(`FROM mcr.microsoft.com/devcontainers/go:1-1.22-bookworm
RUN apt-get update && apt-get install -y btrfs-progs gcc make
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
COPY . /workspace
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);
  });

  it('release Dockerfile: missing CMD/ENTRYPOINT, unpinned apt', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
RUN apt-get update && apt-get install -y git make
WORKDIR /go/src/github.com/containerd/containerd
COPY . .
RUN make build

FROM scratch
COPY --from=builder /go/src/github.com/containerd/containerd/bin/ /bin/
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
  });

  it('integration test: untagged busybox, no user', () => {
    const v = lintContent(`FROM busybox
VOLUME /vol
CMD ["cat", "/vol/file"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('test Dockerfile: ADD with URL, broad COPY', () => {
    const v = lintContent(`FROM debian:bullseye
RUN apt-get update && apt-get install -y wget git
ADD https://example.com/file.tar.gz /tmp/
COPY . /src
RUN make && make install
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV3020')).toBe(true);
  });
});

// ── aquasecurity/trivy patterns ────────────────────────────────────────

describe('OSS: aquasecurity/trivy patterns', () => {
  it('main Dockerfile: alpine with apk, no USER', () => {
    const v = lintContent(`FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY trivy /usr/local/bin/trivy
COPY contrib/*.tpl contrib/
ENTRYPOINT ["trivy"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);
  });

  it('docs build: pip install without version', () => {
    const v = lintContent(`FROM python:3.12
RUN pip install mkdocs mkdocs-material
COPY docs/ /docs/
WORKDIR /docs
RUN mkdocs build
`);
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('testdata: minimal ubuntu', () => {
    const v = lintContent(`FROM ubuntu
RUN echo hello
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('java testdata: gradle single stage', () => {
    const v = lintContent(`FROM gradle:7-jdk17
COPY build.gradle settings.gradle /app/
COPY src/ /app/src/
WORKDIR /app
RUN gradle build
`);
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });
});

// ── open-policy-agent/opa patterns ─────────────────────────────────────

describe('OSS: open-policy-agent/opa patterns', () => {
  it('main Dockerfile: well-structured with USER', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
WORKDIR /opa
COPY . .
RUN CGO_ENABLED=0 go build -o /go/bin/opa ./cmd/opa

FROM gcr.io/distroless/static-debian12
COPY --from=builder /go/bin/opa /opa
USER nonroot:nonroot
ENTRYPOINT ["/opa"]
`);
    const rs = ruleSet(v);
    expect(rs).not.toContain('DV1006');
  });

  it('wasm Dockerfile: curl pipe to bash', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl git make gcc g++ python3
RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y nodejs
WORKDIR /build
COPY . .
RUN make build-wasm
`);
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);
  });

  it('opa: no healthcheck with USER set', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /opa

FROM alpine:3.19
COPY --from=builder /opa /usr/local/bin/opa
EXPOSE 8181
USER 1000
CMD ["opa", "run", "--server"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });
});

// ── google/gvisor patterns ─────────────────────────────────────────────

describe('OSS: google/gvisor patterns', () => {
  it('agent: cd command in RUN', () => {
    const v = lintContent(`FROM ubuntu:20.04
RUN apt-get update && apt-get install -y wget
RUN cd /tmp && wget https://example.com/agent.tar.gz && tar xzf agent.tar.gz
`);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('arm-qemu: DEBIAN_FRONTEND as ARG, separate apt-get update', () => {
    const v = lintContent(`FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y qemu-system-x86 qemu-utils
RUN apt-get install -y cloud-image-utils
COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DV1007')).toBe(true);
    expect(v.some(v => v.rule === 'DV2001')).toBe(true);
  });

  it('basic/alpine: minimal no CMD', () => {
    const v = lintContent(`FROM alpine:3.18
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
  });

  it('benchmark: complex build with pip, no pin', () => {
    const v = lintContent(`FROM nvidia/cuda:12.0-devel
RUN apt-get update && apt-get install -y python3-pip git
RUN pip3 install torch torchvision
RUN cd /workspace && git clone https://github.com/example/bench.git && cd bench && python3 setup.py install
COPY benchmark.py /
CMD ["python3", "/benchmark.py"]
`);
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('runtime: typical multi-stage with unpinned apt', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
RUN apt-get update && apt-get install -y build-essential
WORKDIR /src
COPY . .
RUN go build -o /app

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app /usr/local/bin/app
CMD ["/usr/local/bin/app"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('iptables: unpinned apt, no USER, no WORKDIR', () => {
    const v = lintContent(`FROM debian:bullseye
RUN apt-get update && apt-get install -y iptables nftables
RUN iptables --version
COPY rules.sh /
ENTRYPOINT ["/rules.sh"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);
  });

  it('images/default: multi-stage with broad COPY', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
RUN apt-get update && apt-get install -y git protobuf-compiler
WORKDIR /gvisor
COPY . .
RUN make runsc

FROM scratch
COPY --from=builder /gvisor/bazel-bin/runsc/runsc /runsc
ENTRYPOINT ["/runsc"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);
  });

  it('gpu/cuda-tests: complex CUDA build', () => {
    const v = lintContent(`FROM nvidia/cuda:12.0-devel AS base
RUN apt-get update && apt-get install -y git cmake build-essential
RUN cd /opt && git clone https://github.com/example/tests.git
WORKDIR /opt/tests
RUN cmake . && make

FROM nvidia/cuda:12.0-runtime
COPY --from=base /opt/tests/bin /usr/local/bin/
CMD ["/usr/local/bin/run_tests"]
`);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });
});

// ── DV1012: COPY --from sensitive paths ────────────────────────────────

describe('DV1012: COPY --from sensitive paths', () => {
  it('detects COPY --from with /etc/shadow', () => {
    const v = lintContent(`FROM ubuntu:22.04 AS builder
RUN echo test

FROM alpine:3.19
COPY --from=builder /etc/shadow /tmp/shadow
CMD ["cat", "/tmp/shadow"]
`);
    expect(v.some(v => v.rule === 'DV1012')).toBe(true);
  });

  it('detects COPY --from with .ssh directory', () => {
    const v = lintContent(`FROM node:18 AS builder
WORKDIR /app
COPY . .
RUN npm ci

FROM node:18-slim
COPY --from=builder /root/.ssh /root/.ssh
COPY --from=builder /app/dist /app/dist
CMD ["node", "/app/dist/index.js"]
`);
    expect(v.some(v => v.rule === 'DV1012')).toBe(true);
  });

  it('detects COPY --from with .pem file', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
COPY . .
RUN go build

FROM alpine:3.19
COPY --from=builder /certs/server.pem /etc/ssl/server.pem
CMD ["/app"]
`);
    expect(v.some(v => v.rule === 'DV1012')).toBe(true);
  });

  it('detects COPY --from with id_rsa', () => {
    const v = lintContent(`FROM ubuntu:22.04 AS build
RUN ssh-keygen -t rsa -f /root/.ssh/id_rsa -N ""

FROM alpine:3.19
COPY --from=build /root/.ssh/id_rsa /keys/id_rsa
CMD ["cat", "/keys/id_rsa"]
`);
    expect(v.some(v => v.rule === 'DV1012')).toBe(true);
  });

  it('does not flag COPY --from with normal paths', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
COPY . .
RUN go build -o /app

FROM alpine:3.19
COPY --from=builder /app /usr/local/bin/app
CMD ["/usr/local/bin/app"]
`);
    expect(v.some(v => v.rule === 'DV1012')).toBe(false);
  });

  it('does not flag COPY without --from', () => {
    const v = lintContent(`FROM ubuntu:22.04
COPY /etc/shadow /tmp/
CMD ["cat", "/tmp/shadow"]
`);
    expect(v.some(v => v.rule === 'DV1012')).toBe(false);
  });
});

// ── DV1013: ARG secret leaks to ENV ────────────────────────────────────

describe('DV1013: ARG secret leaks to ENV', () => {
  it('detects ARG password exposed via ENV', () => {
    const v = lintContent(`FROM node:18
ARG DB_PASSWORD
ENV DB_PASSWORD=\${DB_PASSWORD}
COPY . /app
CMD ["node", "app.js"]
`);
    expect(v.some(v => v.rule === 'DV1013')).toBe(true);
  });

  it('detects ARG api_key exposed via ENV', () => {
    const v = lintContent(`FROM python:3.12
ARG API_KEY
ENV MY_API_KEY=\$API_KEY
RUN pip install flask
CMD ["python", "app.py"]
`);
    expect(v.some(v => v.rule === 'DV1013')).toBe(true);
  });

  it('detects global ARG secret leaking to ENV', () => {
    const v = lintContent(`ARG SECRET_TOKEN
FROM node:18
ENV APP_TOKEN=\${SECRET_TOKEN}
CMD ["node", "app.js"]
`);
    expect(v.some(v => v.rule === 'DV1013')).toBe(true);
  });

  it('does not flag non-secret ARG in ENV', () => {
    const v = lintContent(`FROM node:18
ARG NODE_ENV=production
ENV NODE_ENV=\${NODE_ENV}
CMD ["node", "app.js"]
`);
    expect(v.some(v => v.rule === 'DV1013')).toBe(false);
  });

  it('does not flag ARG secret not used in ENV', () => {
    const v = lintContent(`FROM node:18
ARG DB_PASSWORD
RUN --mount=type=secret,id=db_pass echo "using secret"
CMD ["node", "app.js"]
`);
    expect(v.some(v => v.rule === 'DV1013')).toBe(false);
  });

  it('detects ARG with access_token in ENV', () => {
    const v = lintContent(`FROM alpine:3.19
ARG GITHUB_ACCESS_TOKEN
ENV GH_TOKEN=\${GITHUB_ACCESS_TOKEN}
RUN apk add --no-cache git
`);
    expect(v.some(v => v.rule === 'DV1013')).toBe(true);
  });
});

// ── Cross-repo rule coverage ───────────────────────────────────────────

describe('OSS scan: cross-repo rule coverage', () => {
  it('DL3008 (unpinned apt) in CI Dockerfiles', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl git gcc
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
  });

  it('DV2004 (apt cache not cleaned) in build stages', () => {
    const v = lintContent(`FROM debian:bookworm
RUN apt-get update && apt-get install -y build-essential
COPY . /src
RUN make -C /src
`);
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);
  });

  it('DV4003 (no WORKDIR) across OSS projects', () => {
    const v = lintContent(`FROM alpine:3.19
RUN apk add --no-cache curl
CMD ["curl", "--version"]
`);
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);
  });

  it('DV1009 (no digest pin) for undigested images', () => {
    const v = lintContent(`FROM python:3.12-slim
COPY app.py /
CMD ["python", "/app.py"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
  });

  it('DV3020 (ADD remote URL) in build Dockerfiles', () => {
    const v = lintContent(`FROM ubuntu:22.04
ADD https://example.com/binary /usr/local/bin/binary
RUN chmod +x /usr/local/bin/binary
`);
    expect(v.some(v => v.rule === 'DV3020')).toBe(true);
  });

  it('DV3019 (curl download then execute) in runtime Dockerfiles', () => {
    const v = lintContent(`FROM debian:bookworm
RUN curl -o /tmp/installer.sh https://example.com/install.sh && chmod +x /tmp/installer.sh && /tmp/installer.sh
`);
    expect(v.some(v => v.rule === 'DV3019')).toBe(true);
  });

  it('DV1003 (curl pipe to shell) in benchmark Dockerfiles', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN curl -sL https://example.com/setup.sh | bash
`);
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);
  });

  it('Multiple rules on poorly-written Dockerfile', () => {
    const v = lintContent(`FROM ubuntu
RUN apt-get update
RUN apt-get install -y curl wget git
RUN curl https://raw.githubusercontent.com/example/install.sh | bash
ENV API_KEY=mysecret123
COPY . .
EXPOSE 8080
CMD node server.js
`);
    const rs = ruleSet(v);
    expect(rs.length).toBeGreaterThan(8);
    expect(rs).toContain('DL3006');
    expect(rs).toContain('DV1001');
    expect(rs).toContain('DV1003');
    expect(rs).toContain('DV1006');
  });
});
