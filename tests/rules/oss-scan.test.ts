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

// ── kubernetes/kubernetes patterns ─────────────────────────────────────

describe('OSS: kubernetes/kubernetes patterns', () => {
  it('build/pause: ARG base, USER set, minimal image', () => {
    const v = lintContent(`ARG BASE
FROM \${BASE}
ARG ARCH
ADD bin/pause-linux-\${ARCH} /pause
USER 65535:65535
ENTRYPOINT ["/pause"]
`);
    // Has USER so DV1006 should not fire
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    // Single stage with no healthcheck
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('build/server-image: ARG base, COPY with --chmod, no USER', () => {
    const v = lintContent(`ARG BASEIMAGE
ARG BINARY

FROM "\${BASEIMAGE}"
COPY --chmod=755 \${BINARY} /usr/local/bin/\${BINARY}
COPY --chmod=755 kube-log-runner /go-runner
ENTRYPOINT ["/go-runner"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('kube-apiserver: multi-stage with --platform, COPY --from numeric', () => {
    const v = lintContent(`ARG BASEIMAGE
ARG SETCAP_IMAGE

FROM \${SETCAP_IMAGE}
ARG BINARY
COPY --chmod=755 \${BINARY} /\${BINARY}
RUN setcap cap_net_bind_service=+ep /\${BINARY}

FROM \${BASEIMAGE}
ARG BINARY
COPY --from=0 /\${BINARY} /usr/local/bin/\${BINARY}
COPY --chmod=755 kube-log-runner /go-runner
ENTRYPOINT ["/go-runner"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('cluster/gce/mounter: ubuntu:xenial, unpinned apt, no USER', () => {
    const v = lintContent(`FROM ubuntu:xenial
RUN apt-get update && apt-get install -y netbase nfs-common=1:1.2.8-9ubuntu12
ENTRYPOINT ["/bin/mount"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('addon-manager: ADD instead of COPY, no USER', () => {
    const v = lintContent(`ARG BASEIMAGE
FROM \${BASEIMAGE}
RUN clean-install bash
ADD kube-addons.sh /opt/
ADD kube-addons-main.sh /opt/
ADD kubectl /usr/local/bin/
CMD ["/opt/kube-addons-main.sh"]
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('sample-apiserver: untagged fedora, ADD binary', () => {
    const v = lintContent(`FROM fedora
ADD kube-sample-apiserver /
ENTRYPOINT ["/kube-sample-apiserver"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
  });

  it('conformance: ARG runner, multiple ENV, ENTRYPOINT', () => {
    const v = lintContent(`ARG RUNNERIMAGE
FROM \${RUNNERIMAGE}
COPY cluster /kubernetes/cluster
COPY ginkgo /usr/local/bin/
COPY e2e.test /usr/local/bin/
ENV E2E_FOCUS="\\[Conformance\\]"
ENV E2E_SKIP=""
ENV E2E_PROVIDER="local"
ENV RESULTS_DIR="/tmp/results"
ENTRYPOINT ["kubeconformance"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('test/nginx: mirror image, ARG base only — no USER', () => {
    const v = lintContent(`ARG BASEIMAGE
FROM \$BASEIMAGE
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    // DV4005 not triggered: ARG-only FROM with no instructions
  });

  it('test/webserver: ARG base, CMD only, no healthcheck', () => {
    const v = lintContent(`ARG BASEIMAGE
FROM \$BASEIMAGE
COPY html/nautilus.jpg nautilus.jpg
COPY html/data.json data.json
CMD ["test-webserver"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });
});

// ── istio/istio patterns ───────────────────────────────────────────────

describe('OSS: istio/istio patterns', () => {
  it('Dockerfile.base: ubuntu:noble, unpinned apt, sudo, useradd', () => {
    const v = lintContent(`FROM ubuntu:noble
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \\
  apt-get install --no-install-recommends -y \\
  ca-certificates \\
  curl \\
  iptables \\
  iproute2 \\
  sudo \\
  && apt-get clean \\
  && rm -rf /var/lib/apt/lists/*
RUN useradd -m --uid 1337 istio-proxy && \\
  echo "istio-proxy ALL=NOPASSWD: ALL" >> /etc/sudoers
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('Dockerfile.distroless: digest-pinned chainguard, multi-stage', () => {
    const v = lintContent(`FROM cgr.dev/chainguard/static@sha256:a301031ffd4ed67f35ca7fa6cf3dad9937b5fa47d7493955a18d9b4ca5412d1a AS distroless_source

FROM ubuntu:noble AS ubuntu_source
COPY --from=distroless_source /etc/ /home/etc
COPY --from=distroless_source /home/nonroot /home/nonroot
RUN echo istio-proxy:x:1337: >> /home/etc/group
RUN echo istio-proxy:x:1337:1337:istio-proxy:/nonexistent:/sbin/nologin >> /home/etc/passwd

FROM distroless_source
COPY --from=ubuntu_source /home/etc/passwd /etc/passwd
COPY --from=ubuntu_source /home/etc/group /etc/group
COPY --from=ubuntu_source /home/nonroot /home/nonroot
`);
    // Digest-pinned images should not trigger DL3006
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    // Final stage has no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
  });

  it('istioctl: USER set, ARG base, minimal', () => {
    const v = lintContent(`ARG BASE_VERSION=latest
ARG ISTIO_BASE_REGISTRY=gcr.io/istio-release
FROM \${ISTIO_BASE_REGISTRY}/base:\${BASE_VERSION}
USER 1000:1000
ARG TARGETARCH
COPY \${TARGETARCH:-amd64}/istioctl /usr/local/bin/istioctl
ENTRYPOINT ["/usr/local/bin/istioctl"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('pilot: multi-stage ARG switching, USER 1337', () => {
    const v = lintContent(`ARG BASE_DISTRIBUTION=debug
ARG BASE_VERSION=latest
ARG ISTIO_BASE_REGISTRY=gcr.io/istio-release

FROM \${ISTIO_BASE_REGISTRY}/base:\${BASE_VERSION} AS debug
FROM \${ISTIO_BASE_REGISTRY}/distroless:\${BASE_VERSION} AS distroless
FROM \${BASE_DISTRIBUTION:-debug}

ARG TARGETARCH
COPY \${TARGETARCH:-amd64}/pilot-discovery /usr/local/bin/pilot-discovery
USER 1337:1337
ENTRYPOINT ["/usr/local/bin/pilot-discovery"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });

  it('CNI install: multi-stage with LABEL, ENV PATH, WORKDIR', () => {
    const v = lintContent(`ARG BASE_DISTRIBUTION=debug
ARG BASE_VERSION=latest
ARG ISTIO_BASE_REGISTRY=gcr.io/istio-release

FROM \${ISTIO_BASE_REGISTRY}/base:\${BASE_VERSION} AS debug
FROM \${ISTIO_BASE_REGISTRY}/iptables:\${BASE_VERSION} AS distroless
FROM \${BASE_DISTRIBUTION:-debug}

LABEL description="Istio CNI plugin installer."
ARG TARGETARCH
COPY \${TARGETARCH:-amd64}/istio-cni /opt/cni/bin/istio-cni
COPY \${TARGETARCH:-amd64}/install-cni /usr/local/bin/install-cni
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/cni/bin
WORKDIR /opt/cni/bin
CMD ["/usr/local/bin/install-cni"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('agentgateway: single FROM, untagged image, no USER', () => {
    const v = lintContent(`ARG AGENTGATEWAY_IMAGE=cr.agentgateway.dev/agentgateway
FROM \${AGENTGATEWAY_IMAGE}
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });
});

// ── etcd-io/etcd patterns ──────────────────────────────────────────────

describe('OSS: etcd-io/etcd patterns', () => {
  it('main Dockerfile: distroless with digest, ADD binaries, WORKDIR, CMD', () => {
    const v = lintContent(`ARG ARCH=amd64
FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
ADD etcd /usr/local/bin/
ADD etcdctl /usr/local/bin/
ADD etcdutl /usr/local/bin/
WORKDIR /var/etcd/
WORKDIR /var/lib/etcd/
EXPOSE 2379 2380
CMD ["/usr/local/bin/etcd"]
`);
    // Digest-pinned, should not fire DL3006
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    // ADD for local files
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);
    // No USER in distroless
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('antithesis/config: multi-stage, go install, scratch final', () => {
    const v = lintContent(`ARG GO_VERSION=1.25.5
FROM golang:\$GO_VERSION AS build
RUN go install github.com/a8m/envsubst/cmd/envsubst@v1.4.3
COPY docker-compose.yml.template /docker-compose.yml.template
RUN cat /docker-compose.yml.template | envsubst > /docker-compose.yml

FROM scratch
COPY --from=build /docker-compose.yml /docker-compose.yml
`);
    // scratch final: no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
  });

  it('antithesis/server: complex build with git clone, ubuntu final', () => {
    const v = lintContent(`ARG GO_IMAGE_TAG
FROM golang:\$GO_IMAGE_TAG AS build
ARG REF=main
RUN git clone --depth=1 https://github.com/etcd-io/etcd.git --branch=\${REF} /etcd
WORKDIR /etcd/server
RUN go install golang.org/x/tools/cmd/goimports@latest
RUN go mod tidy
WORKDIR /etcd
RUN go mod download
RUN make build

FROM ubuntu:24.04
COPY --from=build /go/bin/dlv /bin/dlv
COPY --from=build /etcd /etcd
EXPOSE 2379 2380
CMD ["/etcd/customer/bin/etcd"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('antithesis/test-template: multi-stage, race flag, ubuntu final', () => {
    const v = lintContent(`ARG GO_IMAGE_TAG
ARG ARCH=amd64
FROM golang:\$GO_IMAGE_TAG AS build
WORKDIR /build
COPY . .
WORKDIR /build/tests
RUN go build -o /opt/entrypoint -race ./main.go

FROM ubuntu:24.04
COPY --from=build /opt/ /opt/
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);
  });
});

// ── cilium/cilium patterns ─────────────────────────────────────────────

describe('OSS: cilium/cilium patterns', () => {
  it('Documentation: python alpine, apk add, pip install without pin', () => {
    const v = lintContent(`FROM docker.io/library/python:3.11-alpine3.17 AS docs-base
LABEL maintainer="maintainer@cilium.io"
RUN apk add --no-cache --virtual --update \\
    aspell-en \\
    nodejs \\
    npm \\
    bash \\
    gcc \\
    musl-dev \\
    && true

FROM docs-base AS docs-builder
ADD ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
`);
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('cilium-cli: digest-pinned distroless, ENTRYPOINT []', () => {
    const v = lintContent(`ARG BASE_IMAGE=gcr.io/distroless/static:latest@sha256:28efbe90d0b2f2a3ee465cc5b44f3f2cf5533514cf4d51447a977a5dc8e526d0
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.0@sha256:9edf71320ef8a791c4c33ec79f90496d641f306a91fb112d3d060d5c1cee4e20
FROM \${GOLANG_IMAGE} AS builder
WORKDIR /go/src/github.com/cilium/cilium
RUN make install

FROM \${BASE_IMAGE} AS release
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /usr/local/bin/cilium /usr/local/bin/cilium
ENTRYPOINT []
`);
    // No USER
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('backporting: ubuntu, unpinned apt, curl+tar, USER set', () => {
    const v = lintContent(`ARG GOLANG_IMAGE=docker.io/library/golang:1.20.2@sha256:5990c4fbb1ab074b4be7bcc9ee3b8bd2888a1d4f9572fc7d63b804ea5da54e73
FROM \$GOLANG_IMAGE AS golang

FROM ubuntu:20.04
COPY --from=golang /usr/local/go /usr/local/go
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y \\
  git \\
  jq \\
  python3 \\
  python3-pip \\
  curl \\
  vim
ARG GH_VERSION=2.49.0
RUN curl -L -o gh.tar.gz https://github.com/cli/cli/releases/download/v\${GH_VERSION}/gh_\${GH_VERSION}_linux_amd64.tar.gz \\
  && tar xfz gh.tar.gz \\
  && cp gh/bin/gh /usr/sbin/ \\
  && rm -rf /hub
RUN useradd -m user
USER user
ENV PATH=/usr/local/go/bin:\$PATH
RUN pip3 install --user PyGithub
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false); // USER is set
    expect(v.some(v => v.rule === 'DL3013')).toBe(true); // pip without version
  });

  it('coccinelle: alpine with digest, curl pipe to tar, apk', () => {
    const v = lintContent(`FROM docker.io/library/alpine:3.16.0@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c
LABEL maintainer="maintainer@cilium.io"
ENV COCCINELLE_VERSION=1.1.1
RUN apk add -t .build_apks curl autoconf automake gcc libc-dev ocaml ocaml-dev && \\
    apk add make python3 bash && \\
    curl -sS -L https://github.com/coccinelle/coccinelle/archive/\$COCCINELLE_VERSION.tar.gz -o coccinelle.tar.gz && \\
    tar xvzf coccinelle.tar.gz && rm coccinelle.tar.gz && \\
    cd coccinelle-\$COCCINELLE_VERSION && \\
    make && make install-spatch install-python && \\
    cd .. && rm -r coccinelle-\$COCCINELLE_VERSION && \\
    apk del .build_apks
`);
    // digest-pinned should not fire DL3006
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true); // cd in RUN
  });

  it('kubernetes-grpc example: ubuntu, unpinned apt, pip install, git clone', () => {
    const v = lintContent(`FROM docker.io/library/ubuntu:20.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \\
    software-properties-common \\
    curl \\
    git \\
    python3-pip
RUN pip3 install grpcio grpcio-tools
WORKDIR /tmp
RUN git clone -b v1.7.0 https://github.com/grpc/grpc

FROM docker.io/library/ubuntu:20.04
RUN apt-get update \\
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
    python3 \\
    python3-pip \\
    && pip3 install grpcio grpcio-tools \\
    && apt-get clean \\
    && rm -rf /var/lib/apt/lists/*
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DL3013')).toBe(true); // pip without version
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4003')).toBe(true); // No WORKDIR in final stage
  });

  it('hubble-relay: distroless nonroot, USER 65532, CMD', () => {
    const v = lintContent(`ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:f512d819b8f109f2375e8b51d8cfd8aafe81034bc3e319740128b7d7f70d5036
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.0@sha256:9edf71320ef8a791c4c33ec79f90496d641f306a91fb112d3d060d5c1cee4e20

FROM \${GOLANG_IMAGE} AS builder
WORKDIR /go/src
RUN make build

FROM \${GOLANG_IMAGE} AS gops
RUN go install github.com/google/gops@latest

FROM \${BASE_IMAGE} AS release
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /go/bin/gops /usr/local/bin/gops
COPY --from=builder /usr/bin/hubble-relay /usr/bin/hubble-relay
USER 65532:65532
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });

  it('runtime: multi-stage ubuntu, apt-get upgrade, scratch final', () => {
    const v = lintContent(`ARG GOLANG_IMAGE=docker.io/library/golang:1.26.0@sha256:abc123
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:24.04@sha256:def456

FROM \${GOLANG_IMAGE} AS go-builder
WORKDIR /build
RUN go install github.com/google/gops@latest

FROM \${UBUNTU_IMAGE} AS rootfs
RUN apt-get update && \\
    apt-get upgrade -y && \\
    apt-get install -y jq
COPY --from=go-builder /go/bin/gops /usr/local/bin/gops

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
  });

  it('operator: complex multi-stage, ARG-based naming, scratch base', () => {
    const v = lintContent(`ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=docker.io/library/golang:1.26.0@sha256:abc123
ARG ALPINE_IMAGE=docker.io/library/alpine:3.23.3@sha256:def456

FROM \${GOLANG_IMAGE} AS builder
WORKDIR /go/src
RUN make build

FROM \${ALPINE_IMAGE} AS certs
RUN apk --update add ca-certificates

FROM \${BASE_IMAGE} AS release
ARG OPERATOR_VARIANT
LABEL maintainer="maintainer@cilium.io"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/bin/cilium-operator /usr/bin/cilium-operator
WORKDIR /
CMD ["/usr/bin/cilium-operator"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });
});

// ── Cross-repo K8s ecosystem rule coverage ─────────────────────────────

describe('OSS scan: K8s ecosystem cross-repo patterns', () => {
  it('ADD local files (DL3020) common in kubernetes images', () => {
    const v = lintContent(`ARG BASEIMAGE
FROM \${BASEIMAGE}
ADD kube-addons.sh /opt/
ADD kubectl /usr/local/bin/
CMD ["/opt/kube-addons.sh"]
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);
  });

  it('DEBIAN_FRONTEND as ENV (DV1007) in istio/cilium builds', () => {
    const v = lintContent(`FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl
`);
    expect(v.some(v => v.rule === 'DV1007')).toBe(true);
  });

  it('No USER (DV1006) in mirror/config images', () => {
    const v = lintContent(`ARG BASEIMAGE
FROM \$BASEIMAGE
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('Multi-stage with scratch final and no CMD', () => {
    const v = lintContent(`FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /app

FROM scratch
COPY --from=build /app /app
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);
  });

  it('Complex etcd-style build with git clone and multiple WORKDIR', () => {
    const v = lintContent(`FROM golang:1.22 AS build
RUN git clone --depth=1 https://github.com/example/project.git /src
WORKDIR /src
RUN go mod download
RUN go build -o /bin/server

FROM ubuntu:22.04
COPY --from=build /bin/server /usr/local/bin/
EXPOSE 2379
CMD ["/usr/local/bin/server"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('Digest-pinned images should not trigger DL3006 or DV1009', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
COPY app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    expect(v.some(v => v.rule === 'DV1009')).toBe(false);
  });

  it('pip install without version pin in CI builds (cilium/istio)', () => {
    const v = lintContent(`FROM python:3.11
RUN pip install mkdocs PyGithub grpcio
COPY docs/ /docs/
WORKDIR /docs
CMD ["mkdocs", "serve"]
`);
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);
  });

  it('useradd pattern from istio/cilium (proper USER after useradd)', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates
RUN useradd -m --uid 1337 istio-proxy
USER istio-proxy
ENTRYPOINT ["/usr/local/bin/pilot-discovery"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
  });

  it('ENV with hardcoded path override (cilium pattern)', () => {
    const v = lintContent(`FROM ubuntu:22.04
ENV HUBBLE_SERVER=unix:///var/run/cilium/hubble.sock
ENV INITSYSTEM="SYSTEMD"
COPY cilium-agent /usr/bin/cilium-agent
WORKDIR /home/cilium
CMD ["/usr/bin/cilium-agent"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);
  });

  it('apk add in alpine builds (cilium docs, coccinelle)', () => {
    const v = lintContent(`FROM alpine:3.19
RUN apk add --no-cache curl git gcc musl-dev make
WORKDIR /build
COPY . .
RUN make install
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);
  });
});

// ── argoproj/argo-cd patterns ──────────────────────────────────────────

describe('OSS: argoproj/argo-cd patterns', () => {
  it('main Dockerfile: multi-stage with unpinned apt, dist-upgrade, DEBIAN_FRONTEND as ENV', () => {
    const v = lintContent(`FROM docker.io/library/golang:1.26.0@sha256:abc123 AS builder
WORKDIR /tmp
RUN apt-get update && apt-get install --no-install-recommends -y \
    openssh-server nginx unzip fcgiwrap git make wget gcc sudo zip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
FROM docker.io/library/ubuntu:25.10@sha256:def456
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get dist-upgrade -y && apt-get install -y git tini ca-certificates gpg
COPY --from=builder /tmp/argocd /usr/local/bin/argocd
ENTRYPOINT ["argocd"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3005')).toBe(true);   // dist-upgrade
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);   // DEBIAN_FRONTEND as ENV
    expect(v.some(v => v.rule === 'DV2002')).toBe(true);   // dist-upgrade warning
  });

  it('Dockerfile.dev: FROM internal stage alias without tag triggers DL3006', () => {
    const v = lintContent(`FROM argocd-base
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
  });

  it('Dockerfile.tilt: single-stage Go build, no USER, no apt cleanup', () => {
    const v = lintContent(`FROM docker.io/library/golang:1.26.0
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y curl openssh-server nginx
RUN make build
COPY argocd-server /usr/local/bin/
`);
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);   // apt lists not deleted
  });

  it('gitops-engine Dockerfile: COPY . broad context, no CMD/ENTRYPOINT', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
WORKDIR /src
COPY go.mod /src/go.mod
COPY go.sum /src/go.sum
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /dist/gitops ./agent

FROM alpine/git:v2.45.2
COPY --from=builder /dist/gitops /usr/local/bin/gitops
`);
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);   // COPY . broad context
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT in final stage
  });

  it('test/e2e Dockerfile: CMD with double quotes triggers DL3025', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y git ssh
CMD "start.sh"
`);
    expect(v.some(v => v.rule === 'DL3025')).toBe(true);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('ui-test Dockerfile: npm install with sudo, ADD for URL', () => {
    const v = lintContent(`FROM node:20
ADD https://example.com/test-runner.tar.gz /tmp/
RUN npm install -g yarn
RUN yarn install
COPY . /app
CMD ["yarn", "test"]
`);
    expect(v.some(v => v.rule === 'DV3023')).toBe(false);  // no ARG in URL
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });
});

// ── fluxcd/flux2 patterns ──────────────────────────────────────────────

describe('OSS: fluxcd/flux2 patterns', () => {
  it('main Dockerfile: multi-stage alpine, unpinned apk, curl download without checksum', () => {
    const v = lintContent(`FROM alpine:3.23 AS builder
RUN apk add --no-cache ca-certificates curl
ARG ARCH=linux/amd64
ARG KUBECTL_VER=1.35.0
RUN curl -sL https://dl.k8s.io/release/v\${KUBECTL_VER}/bin/\${ARCH}/kubectl \
    -o /usr/local/bin/kubectl && chmod +x /usr/local/bin/kubectl

FROM alpine:3.23 AS flux-cli
RUN apk add --no-cache ca-certificates
COPY --from=builder /usr/local/bin/kubectl /usr/local/bin/
COPY --chmod=755 flux /usr/local/bin/
USER 65534:65534
ENTRYPOINT [ "flux" ]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV3019')).toBe(true);   // download without checksum
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('flux2: unquoted ARG in download URL triggers DV3023', () => {
    const v = lintContent(`FROM alpine:3.23
ARG ARCH=linux/amd64
RUN curl -sL https://example.com/bin/$ARCH/tool -o /usr/local/bin/tool
`);
    expect(v.some(v => v.rule === 'DV3023')).toBe(true);
  });

  it('flux2: proper USER 65534 does not trigger DV1006', () => {
    const v = lintContent(`FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY flux /usr/local/bin/
USER 65534:65534
ENTRYPOINT ["flux"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });
});

// ── jaegertracing/jaeger patterns ──────────────────────────────────────

describe('OSS: jaegertracing/jaeger patterns', () => {
  it('cmd/jaeger Dockerfile: ARG base_image, multiple EXPOSE, proper USER', () => {
    const v = lintContent(`ARG base_image
FROM $base_image AS release
ARG TARGETARCH
ARG USER_UID=10001
ENV JAEGER_LISTEN_HOST=0.0.0.0
EXPOSE 4317
EXPOSE 4318
EXPOSE 16686
COPY jaeger-linux-$TARGETARCH /cmd/jaeger/jaeger-linux
VOLUME ["/tmp"]
ENTRYPOINT ["/cmd/jaeger/jaeger-linux"]
USER \${USER_UID}
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is set
    expect(v.some(v => v.rule === 'DV3010')).toBe(true);   // ENV with listen address
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('hotrod example: multi-stage with pinned digest, scratch final', () => {
    const v = lintContent(`FROM alpine:3.23.0@sha256:abc123 AS cert
RUN apk add --update --no-cache ca-certificates

FROM scratch
ARG TARGETARCH
EXPOSE 8080 8081 8082 8083
COPY --from=cert /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY hotrod-linux-$TARGETARCH /go/bin/hotrod-linux
ENTRYPOINT ["/go/bin/hotrod-linux"]
CMD ["all"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk (--update --no-cache but no version)
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);  // digest-pinned
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // scratch is acceptable
  });

  it('base Dockerfile: alpine multi-stage, no CMD/ENTRYPOINT in final', () => {
    const v = lintContent(`FROM alpine:3.23.3@sha256:abc123 AS cert
RUN apk add --update --no-cache ca-certificates mailcap

FROM alpine:3.23.3@sha256:abc123
COPY --from=cert /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=cert /etc/mime.types /etc/mime.types
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
  });

  it('es-index-cleaner/es-rollover: minimal scratch images (no violations)', () => {
    const v = lintContent(`FROM scratch
ARG TARGETARCH
COPY es-index-cleaner-linux-$TARGETARCH /go/bin/es-index-cleaner-linux
EXPOSE 8080
ENTRYPOINT ["/go/bin/es-index-cleaner-linux"]
`);
    // scratch images are minimal — no apt/apk, no USER needed
    expect(v.length).toBe(0);
  });

  it('remote-storage: VOLUME with missing HEALTHCHECK and no USER', () => {
    const v = lintContent(`ARG base_image
FROM $base_image
VOLUME ["/data"]
COPY config.yaml /etc/config.yaml
ENTRYPOINT ["/bin/remote-storage"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });
});

// ── open-telemetry/opentelemetry-collector-contrib patterns ────────────

describe('OSS: open-telemetry/opentelemetry-collector-contrib patterns', () => {
  it('otelcontribcol: multi-stage with scratch final, USER set, apk unpinned', () => {
    const v = lintContent(`FROM alpine:latest@sha256:abc123 AS prep
RUN apk --update add ca-certificates

FROM scratch
ARG USER_UID=10001
ARG USER_GID=10001
USER \${USER_UID}:\${USER_GID}
COPY --from=prep /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY otelcontribcol /
EXPOSE 4317 55680 55679
ENTRYPOINT ["/otelcontribcol"]
CMD ["--config", "/etc/otel/config.yaml"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DL3019')).toBe(true);   // apk --update without --no-cache
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is set
  });

  it('golden cmd: alpine with apk add and no version pin', () => {
    const v = lintContent(`FROM alpine:latest@sha256:abc123
RUN apk --update add ca-certificates
COPY golden /
ENTRYPOINT ["/golden"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);
    expect(v.some(v => v.rule === 'DL3019')).toBe(true);
  });

  it('mongodb receiver test: COPY script with chmod, no USER', () => {
    const v = lintContent(`FROM mongo:4.0
COPY scripts/setup.sh /setup.sh
RUN chmod +x /setup.sh
EXPOSE 27017
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV3021')).toBe(true);   // chmod on COPY (use --chmod)
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('redis cluster test: apt install with pipe, no cleanup', () => {
    const v = lintContent(`FROM debian:bullseye
RUN apt-get update && apt-get install -y redis-server ruby
RUN gem install redis
RUN chmod +x /setup.sh
COPY setup.sh /setup.sh
EXPOSE 6379
CMD ["/setup.sh"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1007')).toBe(true);   // apt cache not cleaned
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('simpleprometheus example: double-quote CMD, COPY . broad context', () => {
    const v = lintContent(`FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o /counter

FROM scratch
COPY --from=builder /counter /counter
CMD "/counter"
`);
    expect(v.some(v => v.rule === 'DL3025')).toBe(true);   // CMD double-quoted string
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);   // COPY . broad context
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY without .dockerignore
  });

  it('journald receiver: apt without recommends flag, wget usage', () => {
    const v = lintContent(`FROM debian:bullseye
RUN apt-get update && apt-get install -y systemd journalctl wget
RUN wget https://example.com/otel-collector -O /usr/local/bin/otelcol
ENTRYPOINT ["/usr/local/bin/otelcol"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);   // --no-install-recommends missing
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);   // wget usage (use curl/ADD)
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('snmp agent test: DL3013 pip without version, DL3042 --no-cache-dir', () => {
    const v = lintContent(`FROM python:3.11-slim
RUN pip install pysnmp
COPY snmp_agent.py /
CMD ["python", "/snmp_agent.py"]
`);
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);   // pip without version
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);   // pip --no-cache-dir
  });
});

// ── grafana/grafana patterns ───────────────────────────────────────────

describe('OSS: grafana/grafana patterns', () => {
  it('main Dockerfile: complex multi-stage, alpine + node + golang', () => {
    const v = lintContent(`FROM alpine:3.23.3 AS alpine-base
FROM golang:1.25.7-alpine AS go-builder-base
FROM node:24-alpine AS js-builder-base

FROM js-builder-base AS js-builder
WORKDIR /tmp/grafana
RUN apk add --no-cache make build-base python3
COPY package.json yarn.lock ./
COPY packages packages
RUN yarn install --immutable

FROM go-builder-base AS go-builder
WORKDIR /tmp/grafana
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM alpine-base
RUN apk add --no-cache ca-certificates tzdata musl
COPY --from=go-builder /tmp/grafana/bin/grafana /usr/share/grafana/bin/
COPY --from=js-builder /tmp/grafana/public /usr/share/grafana/public/
EXPOSE 3000
USER 472
ENTRYPOINT ["/usr/share/grafana/bin/grafana"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is set
  });

  it('devenv smtp: centos with yum, no version pin', () => {
    const v = lintContent(`FROM centos:centos7
LABEL maintainer="test@example.com"
RUN yum update -y && yum install -y net-snmp net-snmp-utils && yum clean all
COPY bootstrap.sh /tmp/bootstrap.sh
EXPOSE 161
ENTRYPOINT ["/tmp/bootstrap.sh"]
`);
    expect(v.some(v => v.rule === 'DL3033')).toBe(true);   // unpinned yum
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('devenv debtest: DL3015 --no-install-recommends missing, apt lists not deleted', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y wget adduser libfontconfig1
COPY grafana.deb /tmp/
RUN dpkg -i /tmp/grafana.deb
CMD ["grafana-server"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);   // --no-install-recommends
    expect(v.some(v => v.rule === 'DV1007')).toBe(true);   // apt cache not cleaned
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
  });

  it('devenv buildcontainer: centos with yum, single-stage build, COPY .', () => {
    const v = lintContent(`FROM centos:7
RUN yum install -y gcc gcc-c++ make git rpm-build
RUN yum install -y epel-release
WORKDIR /build
COPY . .
RUN make rpm
`);
    expect(v.some(v => v.rule === 'DL3033')).toBe(true);   // unpinned yum
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);   // COPY . broad context
  });

  it('packaging/docker/custom: :latest tag, ARG after ENV, VOLUME before COPY', () => {
    const v = lintContent(`FROM grafana/grafana:latest
ENV GF_INSTALL_PLUGINS=""
ARG GF_UID="472"
COPY custom.ini /etc/grafana/custom.ini
CMD ["grafana-server"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest tag
    expect(v.some(v => v.rule === 'DV4004')).toBe(true);   // ARG after ENV
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('devenv prometheus block: ADD with URL (DV3020), :latest tag (DL3007)', () => {
    const v = lintContent(`FROM prom/prometheus:latest
ADD https://example.com/prometheus.yml /etc/prometheus/prometheus.yml
CMD ["--config.file=/etc/prometheus/prometheus.yml"]
`);
    expect(v.some(v => v.rule === 'DV3020')).toBe(true);   // ADD for URL
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest tag
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('frontend-service proxy: alpine with consecutive RUN, unpinned apk', () => {
    const v = lintContent(`FROM nginx:alpine
RUN apk add --no-cache openssl
RUN mkdir -p /etc/nginx/ssl
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 -subj "/CN=localhost" -keyout /etc/nginx/ssl/key.pem -out /etc/nginx/ssl/cert.pem
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
`);
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('ha-test: ADD URL (DV3020) + no USER with grafana image', () => {
    const v = lintContent(`FROM grafana/grafana:10.0.0
ADD https://example.com/provisioning.tar.gz /etc/grafana/
COPY datasources.yaml /etc/grafana/provisioning/datasources/
ENTRYPOINT ["/run.sh"]
`);
    expect(v.some(v => v.rule === 'DV3020')).toBe(true);   // ADD with URL
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('verify-repo-update deb: DL3015 --no-install-recommends missing, consecutive RUN', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y wget apt-transport-https software-properties-common
RUN wget -q -O /tmp/grafana.deb https://example.com/grafana.deb
RUN dpkg -i /tmp/grafana.deb || apt-get install -f -y
`);
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);   // --no-install-recommends missing
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
  });

  it('verify-repo-update rpm: yum install without version pin', () => {
    const v = lintContent(`FROM centos:7
RUN yum install -y yum-utils
RUN yum-config-manager --add-repo https://example.com/grafana.repo
RUN yum install -y grafana
CMD ["grafana-server"]
`);
    expect(v.some(v => v.rule === 'DL3033')).toBe(true);
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);
  });
});

// ── open-telemetry/opentelemetry-collector note ────────────────────────
// open-telemetry/opentelemetry-collector has no Dockerfiles (uses contrib repo).
// Tests above cover opentelemetry-collector-contrib patterns.

// ── helm/helm note ─────────────────────────────────────────────────────
// helm/helm has no Dockerfiles in the repository (binary distributed via GitHub releases).
// Tests for Helm-like patterns (Go binary distribution without Docker) are not applicable.

// ── vitessio/vitess patterns ───────────────────────────────────────────

describe('OSS: vitessio/vitess patterns', () => {
  it('main Dockerfile: complex multi-stage with digest-pinned images, USER vitess', () => {
    const v = lintContent(`FROM golang:1.26.0-trixie@sha256:4e603da0ea8df4a8ab10cbf0b3061f7823d277e82ea210a47c32a5fafb43cc43 AS go-builder
WORKDIR /vt/src/vitess.io/vitess
RUN groupadd -r vitess && useradd -r -g vitess vitess
RUN mkdir -p /vt/vtdataroot /home/vitess
RUN chown -R vitess:vitess /vt /home/vitess
USER vitess
COPY --chown=vitess:vitess go.mod go.sum /vt/src/vitess.io/vitess/
RUN go mod download
COPY --chown=vitess:vitess . /vt/src/vitess.io/vitess
RUN make install PREFIX=/vt/install

FROM debian:trixie-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430
RUN apt-get update && apt-get install -y locales tar
RUN groupadd -r vitess && useradd -r -g vitess vitess
RUN mkdir -p /vt/vtdataroot /home/vitess && chown -R vitess:vitess /vt /home/vitess
ENV VTROOT=/vt
ENV VTDATAROOT=/vt/vtdataroot
ENV PATH=$VTROOT/bin:$PATH
COPY --from=go-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-builder --chown=vitess:vitess /vt/install /vt
VOLUME /vt/vtdataroot
USER vitess
`);
    // Digest-pinned should not fire DL3006
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    // USER is set
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    // Unpinned apt
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);
    // Consecutive RUN in builder
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);
  });

  it('binary images: debian with apt-get upgrade, COPY --from lite, no CMD', () => {
    const v = lintContent(`ARG VT_BASE_VER=latest@sha256:06084c171907baf470d80729c6ef6dbefaad6356777689577e9f6aada1279128
ARG DEBIAN_VER=stable-slim@sha256:ed542b2d269ff08139fc5ab8c762efe8c8986b564a423d5241a5ce9fb09b6c08
FROM vitess/lite:\${VT_BASE_VER} AS lite
FROM debian:\${DEBIAN_VER}
RUN apt-get update && apt-get upgrade -qq && apt-get clean && rm -rf /var/lib/apt/lists/*
ENV VTROOT /vt
RUN mkdir -p /vt/bin && mkdir -p /vtdataroot
COPY --from=lite /vt/bin/vtgate /vt/bin/
COPY --from=lite /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN groupadd -r --gid 2000 vitess && useradd -r -g vitess --uid 1000 vitess && chown -R vitess:vitess /vt && chown -R vitess:vitess /vtdataroot
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
    expect(v.some(v => v.rule === 'DV2001')).toBe(true);   // apt-get upgrade
  });

  it('vtctlclient: debian with curl jq, unpinned apt, CMD set', () => {
    const v = lintContent(`ARG DEBIAN_VER=stable-slim@sha256:abc123
FROM debian:\${DEBIAN_VER}
RUN apt-get update && apt-get upgrade -qq && apt-get install jq curl -qq --no-install-recommends && apt-get autoremove && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY vtctlclient /usr/bin/
RUN groupadd -r --gid 2000 vitess && useradd -r -g vitess --uid 1000 vitess
CMD ["/usr/bin/vtctlclient"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('logrotate: debian with apt-get upgrade, ENTRYPOINT, no USER', () => {
    const v = lintContent(`ARG DEBIAN_VER=stable-slim@sha256:abc123
FROM debian:\${DEBIAN_VER}
COPY logrotate.conf /vt/logrotate.conf
COPY rotate.sh /vt/rotate.sh
RUN mkdir -p /vt && apt-get update && apt-get upgrade -qq && apt-get install logrotate -qq --no-install-recommends && apt-get autoremove -qq && apt-get clean && rm -rf /var/lib/apt/lists/* && groupadd -r --gid 2000 vitess && useradd -r -g vitess --uid 1000 vitess && chown -R vitess:vitess /vt && chmod +x /vt/rotate.sh
ENTRYPOINT [ "/vt/rotate.sh" ]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('bootstrap common: golang with DEBIAN_FRONTEND in RUN, apt install, USER vitess', () => {
    const v = lintContent(`ARG image=golang:1.26.0-bookworm@sha256:abc123
FROM $image
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && apt-get install -y --no-install-recommends ant ca-certificates curl default-jdk-headless g++ git gnupg make unzip zip && rm -rf /var/lib/apt/lists/*
ENV VTROOT=/vt/src/vitess.io/vitess
RUN groupadd -r -g 1000 vitess && useradd -r -u 1000 -g 1000 vitess && mkdir -p /vt/vtdataroot /home/vitess && chown -R vitess:vitess /vt /home/vitess
VOLUME /vt/vtdataroot
WORKDIR /vt/src/vitess.io/vitess
USER vitess
RUN BUILD_CONSUL=0 ./bootstrap.sh
CMD ["/bin/bash"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is set
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
  });

  it('colldump: debian with curl, cmake build, ADD remote URL, cd in RUN', () => {
    const v = lintContent(`FROM debian:latest@sha256:abc123
ARG MYSQL_VERSION=8.0.34
RUN apt-get update && apt-get -y install curl cmake build-essential libssl-dev libncurses5-dev pkg-config rapidjson-dev
RUN cd /tmp && curl -OL https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-\${MYSQL_VERSION}.tar.gz && tar zxvf mysql-\${MYSQL_VERSION}.tar.gz
ADD https://gist.githubusercontent.com/example/raw/colldump.cc /tmp/mysql-\${MYSQL_VERSION}/strings/colldump.cc
RUN cd /tmp/mysql-\${MYSQL_VERSION} && mkdir build && cd build && cmake -DDOWNLOAD_BOOST=1 -DWITH_BOOST=dist/boost .. && make colldump
`);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);   // cd in RUN
    expect(v.some(v => v.rule === 'DV3020')).toBe(true);   // ADD remote URL
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('vtadmin: multi-stage node+nginx, USER nginx set, no CMD (base image provides)', () => {
    const v = lintContent(`ARG NODE_DIGEST=sha256:abc123
ARG NGINX_DIGEST=sha256:def456
ARG DEBIAN_VER=bookworm-slim
FROM node:22-\${DEBIAN_VER}@\${NODE_DIGEST} AS node
WORKDIR /vt/web/vtadmin
COPY /vt/web/vtadmin /vt/web/vtadmin
RUN npm ci && npm run build

FROM nginxinc/nginx-unprivileged:1.29@\${NGINX_DIGEST} AS nginx
USER root
RUN apt-get update && apt-get upgrade -qq && apt-get clean && rm -rf /var/lib/apt/lists/*
USER nginx
ENV VTADMIN_WEB_PORT=14201
COPY --from=node /vt/web/vtadmin/build /var/www/
COPY default.conf /etc/nginx/templates/default.conf.template
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER nginx is set
    expect(v.some(v => v.rule === 'DV2001')).toBe(true);   // apt-get upgrade
  });

  it('mysql bootstrap: FROM $image, USER root then USER vitess, apt install mysql', () => {
    const v = lintContent(`ARG bootstrap_version
ARG image="vitess/bootstrap:\${bootstrap_version}-common"
FROM $image
USER root
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server libmysqlclient-dev libdbd-mysql-perl rsync libev4 && rm -rf /var/lib/apt/lists/*
USER vitess
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER vitess at end
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
  });
});

// ── apache/kafka patterns ──────────────────────────────────────────────

describe('OSS: apache/kafka patterns', () => {
  it('jvm Dockerfile: alpine multi-stage, wget downloads, USER appuser', () => {
    const v = lintContent(`FROM eclipse-temurin:21-jre-alpine AS build-jsa
USER root
RUN apk update && apk upgrade && apk add --no-cache wget gcompat gpg gpg-agent procps bash
RUN mkdir opt/kafka && wget -nv -O kafka.tgz "https://archive.apache.org/dist/kafka/3.7.0/kafka.tgz"

FROM eclipse-temurin:21-jre-alpine
EXPOSE 9092
USER root
RUN apk update && apk upgrade && apk add --no-cache wget gcompat gpg gpg-agent procps bash
RUN mkdir opt/kafka && wget -nv -O kafka.tgz "https://archive.apache.org/dist/kafka/3.7.0/kafka.tgz"
RUN adduser -h /home/appuser -D --shell /bin/bash appuser && chown appuser:appuser -R /usr/logs
USER appuser
VOLUME ["/etc/kafka/secrets", "/var/lib/kafka/data"]
CMD ["/etc/kafka/docker/run"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);   // wget usage
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is set
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
  });

  it('native Dockerfile: graalvm build + alpine final, :latest tag', () => {
    const v = lintContent(`FROM ghcr.io/graalvm/graalvm-community:21 AS build-native-image
ARG kafka_url
WORKDIR /app
COPY native-image-configs /app/native-image-configs
COPY native_command.sh native_command.sh
RUN mkdir /app/kafka && tar xfz kafka.tgz -C /app/kafka --strip-components 1

FROM alpine:latest
EXPOSE 9092
RUN apk update && apk add --no-cache gcompat bash
RUN mkdir -p /etc/kafka/docker /opt/kafka/config /etc/kafka/secrets
RUN adduser -h /home/appuser -D --shell /bin/bash appuser
RUN chown appuser:root -R /etc/kafka /opt/kafka
USER appuser
VOLUME ["/etc/kafka/secrets"]
CMD ["/etc/kafka/docker/run"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest tag
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER appuser set
  });

  it('tests/docker: massive apt install, pip install, ssh keygen, no USER', () => {
    const v = lintContent(`ARG jdk_version
FROM $jdk_version
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y sudo git netcat iptables rsync unzip wget curl jq coreutils openssh-server net-tools vim python3-pip python3-dev libffi-dev libssl-dev cmake pkg-config
RUN python3 -m pip install -U pip==21.1.1
RUN pip3 install --upgrade -r requirements.txt
RUN ssh-keygen -m PEM -q -t rsa -N '' -f /root/.ssh/id_rsa && cp -f /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys
RUN mkdir -p "/opt/kafka-2.1.1" && curl -s "https://s3.amazonaws.com/kafka-packages/kafka_2.12-2.1.1.tgz" | tar xz --strip-components=1 -C "/opt/kafka-2.1.1"
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);   // wget in apt install
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);   // DEBIAN_FRONTEND as ENV
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
  });

  it('official 3.7.0: ENV for kafka_url (hardcoded URL in ENV), apk with wget', () => {
    const v = lintContent(`FROM eclipse-temurin:21-jre-alpine
EXPOSE 9092
USER root
ENV kafka_url https://archive.apache.org/dist/kafka/3.7.0/kafka_2.13-3.7.0.tgz
ENV build_date 2024-06-11
RUN apk update && apk upgrade && apk add --no-cache wget gcompat gpg gpg-agent procps bash
RUN mkdir opt/kafka && wget -nv -O kafka.tgz "$kafka_url"
USER appuser
CMD ["/etc/kafka/docker/run"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);   // wget usage
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER appuser
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
  });
});

// ── vectordotdev/vector patterns ───────────────────────────────────────

describe('OSS: vectordotdev/vector patterns', () => {
  it('alpine Dockerfile: multi-stage, apk unpinned, smoke test RUN, no USER', () => {
    const v = lintContent(`FROM docker.io/alpine:3.23 AS builder
WORKDIR /vector
COPY vector-*.tar.gz ./
RUN tar -xvf vector-0*-unknown-linux-musl*.tar.gz --strip-components=2
RUN mkdir -p /var/lib/vector

FROM docker.io/alpine:3.23
RUN apk --no-cache add ca-certificates tzdata
COPY --from=builder /vector/bin/* /usr/local/bin/
COPY --from=builder /vector/config/vector.yaml /etc/vector/vector.yaml
RUN ["vector", "--version"]
ENTRYPOINT ["/usr/local/bin/vector"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR in final
  });

  it('debian Dockerfile: multi-stage dpkg install, unpinned apt, no USER', () => {
    const v = lintContent(`FROM docker.io/debian:trixie-slim AS builder
WORKDIR /vector
COPY vector_*.deb ./
RUN dpkg -i vector_*_"$(dpkg --print-architecture)".deb
RUN mkdir -p /var/lib/vector

FROM docker.io/debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata systemd && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/bin/vector /usr/bin/vector
RUN ["vector", "--version"]
ENTRYPOINT ["/usr/bin/vector"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR in final
  });

  it('distroless-static: :latest tag on distroless, no USER', () => {
    const v = lintContent(`FROM docker.io/alpine:3.23 AS builder
WORKDIR /vector
COPY vector-*.tar.gz ./
RUN tar -xvf vector-0*-unknown-linux-musl*.tar.gz --strip-components=2
RUN mkdir -p /var/lib/vector

FROM gcr.io/distroless/static:latest
COPY --from=builder /vector/bin/* /usr/local/bin/
COPY --from=builder /vector/config/vector.yaml /etc/vector/vector.yaml
RUN ["vector", "--version"]
ENTRYPOINT ["/usr/local/bin/vector"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest tag
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('regression: :latest builder, dist-upgrade, broad COPY .', () => {
    const v = lintContent(`FROM docker.io/timberio/vector-dev:latest AS builder
WORKDIR /vector
COPY . .
RUN cargo build --bin vector --release && cp target/release/vector .

FROM docker.io/debian:trixie-slim@sha256:abc123
RUN apt-get update && apt-get dist-upgrade -y && apt-get -y --no-install-recommends install zlib1g ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /vector/vector /usr/bin/vector
RUN ["/usr/bin/vector", "--version"]
ENTRYPOINT ["/usr/bin/vector"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest in builder
    expect(v.some(v => v.rule === 'DL3005')).toBe(true);   // dist-upgrade
    expect(v.some(v => v.rule === 'DV2002')).toBe(true);   // dist-upgrade warning
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);   // COPY . broad context
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('environment: ubuntu with DEBIAN_FRONTEND as ENV, unpinned apt, VOLUME', () => {
    const v = lintContent(`FROM docker.io/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git
WORKDIR /git/vectordotdev/vector
COPY scripts/environment/*.sh scripts/environment/
RUN ./scripts/environment/bootstrap-ubuntu-24.04.sh
VOLUME /vector
ENTRYPOINT ["/entrypoint.sh"]
CMD ["bash"]
`);
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);   // DEBIAN_FRONTEND as ENV
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
  });

  it('e2e tests: rust slim, unpinned apt, COPY . broad, no CMD', () => {
    const v = lintContent(`ARG RUST_VERSION=1
FROM docker.io/rust:\${RUST_VERSION}-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake curl git clang libclang-dev libsasl2-dev libssl-dev zlib1g-dev zlib1g unzip mold && rm -rf /var/lib/apt/lists/*
WORKDIR /vector
COPY . .
ARG FEATURES
ARG BUILD
RUN if [ "$BUILD" = "true" ]; then cargo build --tests --lib --bin vector; fi
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);   // COPY . broad context
  });

  it('e2e dogstatsd: python alpine, pip install, no version pin', () => {
    const v = lintContent(`FROM python:3.7-alpine
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD [ "python3", "./client.py"]
`);
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);   // pip --no-cache-dir
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY
  });

  it('e2e otel collector: alpine with apk, USER root explicit', () => {
    const v = lintContent(`ARG CONFIG_COLLECTOR_VERSION=latest
FROM otel/opentelemetry-collector-contrib:\${CONFIG_COLLECTOR_VERSION} AS upstream

FROM alpine:3.20 AS base
COPY --from=upstream /otelcol-contrib /otelcol-contrib
COPY --from=upstream /etc/otelcol-contrib/config.yaml /etc/otelcol-contrib/config.yaml
USER root
ENTRYPOINT ["/otelcol-contrib"]
CMD ["--config", "/etc/otelcol-contrib/config.yaml"]
`);
    // DL3002: last USER should not be root (detected by some linters)
    expect(v.some(v => v.rule === 'DL3002')).toBe(true);   // USER root
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
  });

  it('tilt: complex multi-stage rust build, git clone, dist-upgrade in final', () => {
    const v = lintContent(`ARG RUST_VERSION=1.85
FROM docker.io/rust:\${RUST_VERSION}-trixie AS builder
RUN apt-get update && apt-get -y --no-install-recommends install build-essential git clang cmake libclang-dev libsasl2-dev libssl-dev zlib1g-dev zlib1g
RUN git clone https://github.com/rui314/mold.git && mkdir mold/build && cd mold/build && cmake .. && cmake --build . && cmake --install .
WORKDIR /vector
COPY . .
RUN cargo build --bin vector

FROM docker.io/debian:trixie-slim
RUN apt-get update && apt-get -y --no-install-recommends install zlib1g && rm -rf /var/lib/apt/lists/*
COPY --from=builder /vector/vector /usr/bin/vector
RUN ["vector", "--version"]
ENTRYPOINT ["/usr/bin/vector"]
`);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);   // cd in RUN
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY . in builder
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR in final
  });

  it('cross build: ARG-based FROM, bootstrap script', () => {
    const v = lintContent(`ARG CROSS_VERSION=0.2.5
ARG TARGET=x86_64-unknown-linux-musl
FROM ghcr.io/cross-rs/\${TARGET}:\${CROSS_VERSION}
COPY scripts/cross/bootstrap-ubuntu.sh /
COPY scripts/environment/install-protoc.sh /
RUN /bootstrap-ubuntu.sh && bash /install-protoc.sh
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
    expect(v.some(v => v.rule === 'DV4012')).toBe(true);   // no CMD/ENTRYPOINT
  });

  it('dnstap integration test: debian with bind9, DEBIAN_FRONTEND as ENV', () => {
    const v = lintContent(`FROM docker.io/library/debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y --no-install-recommends install bind9 bind9utils dnsutils && rm -rf /var/lib/apt/lists/*
COPY named.conf.local /etc/bind/
COPY configure_bind.sh run_bind.sh /etc/bind/
RUN chmod +x /etc/bind/configure_bind.sh /etc/bind/run_bind.sh
RUN /etc/bind/configure_bind.sh
CMD ["/etc/bind/run_bind.sh"]
`);
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);   // DEBIAN_FRONTEND as ENV
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });
});

// ── temporalio/temporal patterns ───────────────────────────────────────

describe('OSS: temporalio/temporal patterns', () => {
  it('server.Dockerfile: alpine with unpinned apk, USER temporal, WORKDIR', () => {
    const v = lintContent(`ARG ALPINE_TAG=3.23.3
FROM alpine:\${ALPINE_TAG}
ARG TARGETARCH
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 1000 temporal && adduser -u 1000 -G temporal -D temporal
COPY --chmod=755 ./build/\${TARGETARCH}/temporal-server /usr/local/bin/
COPY --chmod=755 ./scripts/sh/entrypoint.sh /etc/temporal/entrypoint.sh
WORKDIR /etc/temporal
USER temporal
CMD [ "/etc/temporal/entrypoint.sh" ]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER temporal is set
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('admin-tools.Dockerfile: alpine with multiple COPY --chmod, USER, trap CMD', () => {
    const v = lintContent(`ARG ALPINE_TAG=3.23.3
FROM alpine:\${ALPINE_TAG}
ARG TARGETARCH
ARG USER_UID=10001
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 1000 temporal && adduser -u 1000 -G temporal -D temporal
COPY --chmod=755 ./build/\${TARGETARCH}/temporal ./build/\${TARGETARCH}/temporal-cassandra-tool ./build/\${TARGETARCH}/temporal-sql-tool ./build/\${TARGETARCH}/tdbg /usr/local/bin/
COPY ./build/temporal/schema /etc/temporal/schema
USER temporal
CMD ["sh", "-c", "trap exit INT HUP TERM; sleep infinity"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER temporal set
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('temporal: well-structured with USER should not trigger DV1006', () => {
    const v = lintContent(`FROM alpine:3.23
RUN apk add --no-cache ca-certificates
RUN addgroup -g 1000 temporal && adduser -u 1000 -G temporal -D temporal
COPY temporal-server /usr/local/bin/
WORKDIR /etc/temporal
USER temporal
ENTRYPOINT ["/usr/local/bin/temporal-server"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
  });
});

// ── hashicorp/vault patterns ───────────────────────────────────────────

describe('OSS: hashicorp/vault patterns', () => {
  it('main Dockerfile (alpine): unpinned alpine:3, apk add, VOLUME, no USER in default stage', () => {
    const v = lintContent(`FROM alpine:3 AS default
ARG BIN_NAME
ARG NAME=vault
RUN addgroup \${NAME} && adduser -S -G \${NAME} \${NAME}
RUN apk add --no-cache libcap su-exec dumb-init tzdata
COPY dist/linux/amd64/vault /bin/
RUN mkdir -p /vault/logs && mkdir -p /vault/file && mkdir -p /vault/config && chown -R vault:vault /vault
VOLUME /vault/logs
VOLUME /vault/file
EXPOSE 8200
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-dev"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin (alpine:3)
    expect(v.some(v => v.rule === 'DL3052')).toBe(true);   // imprecise tag
  });

  it('UBI Dockerfile: microdnf install, groupadd, USER vault', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi10/ubi-minimal AS ubi
ARG NAME=vault
ARG PRODUCT_VERSION
ENV NAME=$NAME
RUN microdnf install -y ca-certificates gnupg openssl libcap tzdata procps shadow-utils util-linux tar
RUN groupadd --gid 1000 vault && adduser --uid 100 --system -g vault vault && usermod -a -G root vault
COPY dist/linux/amd64/vault /bin/
ENV HOME=/home/vault
RUN mkdir -p /vault/logs && mkdir -p /vault/file && mkdir -p /vault/config && mkdir -p $HOME
VOLUME /vault/logs
VOLUME /vault/file
EXPOSE 8200
COPY ubi-docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
USER vault
CMD ["server", "-dev"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER vault set
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('cross build: debian buster, curl pipe to bash, multiple consecutive RUN', () => {
    const v = lintContent(`FROM debian:buster
RUN apt-get update -y && apt-get install --no-install-recommends -y -q curl zip build-essential gcc-multilib g++-multilib ca-certificates git gnupg libltdl-dev libltdl7
RUN curl -sL https://deb.nodesource.com/setup_20.x | bash -
RUN curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
RUN apt-get update -y && apt-get install -y -q nodejs yarn
RUN rm -rf /var/lib/apt/lists/*
ENV GOVERSION 1.13.8
RUN mkdir /goroot && mkdir /gopath
RUN curl https://storage.googleapis.com/golang/go\${GOVERSION}.linux-amd64.tar.gz | tar xvzf - -C /goroot --strip-components=1
ENV GOPATH /gopath
ENV GOROOT /goroot
CMD make static-dist bin
`);
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);   // curl pipe to bash
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single-stage with build tools
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
    expect(v.some(v => v.rule === 'DL3025')).toBe(true);   // CMD not in exec form
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('scripts/docker: multi-stage Go build, alpine final, no USER', () => {
    const v = lintContent(`ARG VERSION
FROM golang:\${VERSION} AS builder
ARG CGO_ENABLED=0
WORKDIR /go/src/github.com/hashicorp/vault
COPY . .
RUN make bootstrap && CGO_ENABLED=0 sh -c "./scripts/build.sh"

FROM alpine:3.13
RUN addgroup vault && adduser -S -G vault vault
RUN apk add --no-cache ca-certificates libcap su-exec dumb-init tzdata
COPY --from=builder /go/src/github.com/hashicorp/vault/bin/vault /bin/vault
RUN mkdir -p /vault/logs && mkdir -p /vault/file && mkdir -p /vault/config && chown -R vault:vault /vault
VOLUME /vault/logs
VOLUME /vault/file
EXPOSE 8200
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-dev"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY . in builder
  });

  it('Dockerfile.ui: debian buster builder, curl pipe bash, complex build', () => {
    const v = lintContent(`FROM debian:buster AS builder
ARG VERSION
RUN apt-get update -y && apt-get install --no-install-recommends -y -q curl zip build-essential gcc-multilib g++-multilib ca-certificates git gnupg libltdl-dev libltdl7
RUN curl -sL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get update -y && apt-get install -y -q nodejs yarn
ENV GOPATH /go
ENV GOROOT /goroot
RUN mkdir /goroot && mkdir /go
RUN curl https://storage.googleapis.com/golang/go\${VERSION}.linux-amd64.tar.gz | tar xvzf - -C /goroot --strip-components=1
WORKDIR /go/src/github.com/hashicorp/vault
COPY . .
RUN make bootstrap static-dist

FROM alpine:3.13
RUN addgroup vault && adduser -S -G vault vault
RUN apk add --no-cache ca-certificates libcap su-exec dumb-init tzdata
COPY --from=builder /go/src/github.com/hashicorp/vault/bin/vault /bin/vault
EXPOSE 8200
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-dev"]
`);
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);   // curl pipe to bash
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER in final
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
  });

  it('testdata: ubuntu with groupadd, USER nonroot, proper structure', () => {
    const v = lintContent(`FROM docker.mirror.hashicorp.services/ubuntu:22.04
ARG plugin
RUN groupadd nonroot && useradd -g nonroot nonroot
USER nonroot
COPY \${plugin} /bin/plugin
ENTRYPOINT [ "/bin/plugin" ]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER nonroot set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('builder: ubuntu focal, consecutive RUN with chmod, ENTRYPOINT', () => {
    const v = lintContent(`FROM ubuntu:focal AS builder
ARG GO_VERSION
ENV PATH="/root/go/bin:/opt/go/bin:/opt/tools/bin:$PATH"
ENV GOPRIVATE='github.com/hashicorp/*'
COPY system.sh .
RUN chmod +x system.sh && ./system.sh && rm -rf system.sh
COPY go.sh .
RUN chmod +x go.sh && ./go.sh && rm -rf go.sh
COPY tools.sh .
RUN chmod +x tools.sh
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // no digest pin
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });
});

// ── Cross-repo patterns: vitess/kafka/vector/temporal/vault ────────────

describe('OSS scan: infrastructure tool cross-repo patterns', () => {
  it('Alpine with adduser/addgroup pattern (temporal, kafka, vault)', () => {
    const v = lintContent(`FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1000 appgroup && adduser -u 1000 -G appgroup -D appuser
COPY app /usr/local/bin/
USER appuser
ENTRYPOINT ["/usr/local/bin/app"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER set
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('Debian binary image pattern (vitess): apt-get upgrade, COPY --from, no CMD', () => {
    const v = lintContent(`FROM myapp/base:latest@sha256:abc123 AS base
FROM debian:stable-slim@sha256:def456
RUN apt-get update && apt-get upgrade -qq && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=base /app/bin /usr/local/bin/
RUN groupadd -r --gid 2000 app && useradd -r -g app --uid 1000 app && chown -R app:app /usr/local/bin
`);
    expect(v.some(v => v.rule === 'DV2001')).toBe(true);   // apt-get upgrade
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('wget usage pattern (kafka): DL3047 detected', () => {
    const v = lintContent(`FROM alpine:3.23
RUN apk add --no-cache wget bash
RUN wget -nv -O /tmp/app.tgz "https://example.com/app.tgz"
RUN tar xfz /tmp/app.tgz -C /opt/
CMD ["/opt/app/run"]
`);
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);   // wget usage
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
  });

  it('COPY --chmod pattern (temporal, vitess): accepted without DV3021', () => {
    const v = lintContent(`FROM alpine:3.23
COPY --chmod=755 app /usr/local/bin/app
COPY --chmod=755 entrypoint.sh /entrypoint.sh
USER 1000
ENTRYPOINT ["/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DV3021')).toBe(false);  // --chmod is proper
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER set
  });

  it('curl pipe to bash in build images (vault cross build)', () => {
    const v = lintContent(`FROM debian:bookworm
RUN apt-get update && apt-get install -y curl gnupg
RUN curl -sL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get install -y nodejs
`);
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);   // curl pipe to bash
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
  });

  it('microdnf pattern (vault UBI): no apt/apk rules fire', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi10/ubi-minimal
RUN microdnf install -y ca-certificates openssl tzdata
COPY vault /bin/vault
EXPOSE 8200
ENTRYPOINT ["vault"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(false);  // not apt
    expect(v.some(v => v.rule === 'DL3018')).toBe(false);  // not apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('smoke test RUN pattern (vector): RUN ["binary", "--version"]', () => {
    const v = lintContent(`FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY vector /usr/bin/vector
RUN ["vector", "--version"]
ENTRYPOINT ["/usr/bin/vector"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('graalvm native image build (kafka): complex multi-stage', () => {
    const v = lintContent(`FROM ghcr.io/graalvm/graalvm-community:21 AS build
ARG kafka_url
WORKDIR /app
RUN if [ -n "$kafka_url" ]; then microdnf install wget; wget -nv -O kafka.tgz "$kafka_url"; fi
RUN mkdir /app/kafka && tar xfz kafka.tgz -C /app/kafka --strip-components 1

FROM alpine:3.23
RUN apk update && apk add --no-cache gcompat bash
RUN adduser -h /home/appuser -D --shell /bin/bash appuser
USER appuser
CMD ["/opt/kafka/run"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // unpinned apk
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER appuser
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR in final
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);   // wget usage
  });
});

// ── redis/redis patterns ───────────────────────────────────────────────

describe('OSS: redis/redis patterns', () => {
  it('official redis image: build from source with gosu', () => {
    const v = lintContent(`FROM debian:bookworm-slim
RUN groupadd -r -g 999 redis && useradd -r -g redis -u 999 redis
RUN set -eux; savedAptMark="$(apt-mark showmanual)"; apt-get update; apt-get install -y --no-install-recommends ca-certificates wget gnupg dirmngr; rm -rf /var/lib/apt/lists/*; wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/1.17/gosu-amd64"; chmod +x /usr/local/bin/gosu; gosu nobody true
ENV REDIS_VERSION 7.2.4
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends ca-certificates wget gcc libc6-dev make; wget -O redis.tar.gz "https://download.redis.io/releases/redis-$REDIS_VERSION.tar.gz"; mkdir -p /usr/src/redis; tar -xzf redis.tar.gz -C /usr/src/redis --strip-components=1; rm redis.tar.gz; make -C /usr/src/redis -j; make -C /usr/src/redis install; rm -r /usr/src/redis; apt-get purge -y --auto-remove gcc libc6-dev make; rm -rf /var/lib/apt/lists/*
RUN mkdir /data && chown redis:redis /data
VOLUME /data
WORKDIR /data
COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]
EXPOSE 6379
CMD ["redis-server"]
USER redis
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // no multi-stage
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // missing .dockerignore hint
  });

  it('redis sentinel pattern: config-only with USER', () => {
    const v = lintContent(`FROM redis:7.2-alpine
COPY sentinel.conf /etc/redis/sentinel.conf
USER redis
EXPOSE 26379
CMD ["redis-sentinel", "/etc/redis/sentinel.conf"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER is present
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('redis test harness: multi-stage with build deps', () => {
    const v = lintContent(`FROM debian:bookworm AS builder
RUN apt-get update && apt-get install -y gcc make libc6-dev
COPY . /src
WORKDIR /src
RUN make -j$(nproc)

FROM debian:bookworm-slim
COPY --from=builder /src/src/redis-server /usr/local/bin/
COPY --from=builder /src/src/redis-cli /usr/local/bin/
USER nobody
EXPOSE 6379
CMD ["redis-server"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER nobody set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('redis cluster setup: multiple EXPOSE, no HEALTHCHECK', () => {
    const v = lintContent(`FROM redis:7.2-alpine
COPY redis.conf /usr/local/etc/redis/redis.conf
EXPOSE 6379 16379
HEALTHCHECK --interval=30s CMD redis-cli ping
CMD ["redis-server", "/usr/local/etc/redis/redis.conf", "--cluster-enabled", "yes"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(false);  // HEALTHCHECK present
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });
});

// ── mongodb/mongo patterns ─────────────────────────────────────────────

describe('OSS: mongodb/mongo patterns', () => {
  it('mongo build from source: heavy build deps, no USER', () => {
    const v = lintContent(`FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip gcc g++ libssl-dev curl git
RUN pip3 install pymongo
COPY . /src
WORKDIR /src
RUN python3 buildscripts/scons.py install-mongod
EXPOSE 27017
CMD ["mongod"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);   // unpinned pip
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // no multi-stage
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('mongos router: minimal config-only image', () => {
    const v = lintContent(`FROM mongo:7.0
COPY mongos.conf /etc/mongos.conf
EXPOSE 27017
CMD ["mongos", "--config", "/etc/mongos.conf"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('mongo replicaset init: shell entrypoint', () => {
    const v = lintContent(`FROM mongo:7.0
COPY init-replica.sh /docker-entrypoint-initdb.d/
COPY mongod.conf /etc/mongod.conf
RUN chmod +x /docker-entrypoint-initdb.d/init-replica.sh
HEALTHCHECK --interval=10s CMD mongosh --eval "db.runCommand('ping').ok" || exit 1
EXPOSE 27017
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('mongo backup image: multi-stage with mongodump', () => {
    const v = lintContent(`FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /backup-agent

FROM alpine:3.20
RUN apk add --no-cache mongodb-tools
COPY --from=builder /backup-agent /usr/local/bin/
USER nobody
ENTRYPOINT ["/usr/local/bin/backup-agent"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR in final
  });

  it('mongo test container: ADD with URL, broad COPY', () => {
    const v = lintContent(`FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y wget curl python3
ADD https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2004-7.0.0.tgz /tmp/
RUN tar xzf /tmp/mongodb-linux-x86_64-ubuntu2004-7.0.0.tgz -C /opt
ENV PATH=/opt/mongodb-linux-x86_64-ubuntu2004-7.0.0/bin:$PATH
COPY . /tests
CMD ["python3", "/tests/run_tests.py"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // ADD with URL
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV3020')).toBe(true);   // wget in apt install
  });
});

// ── elastic/elasticsearch patterns ─────────────────────────────────────

describe('OSS: elastic/elasticsearch patterns', () => {
  it('simdvec native build: debian:latest, unpinned apt, separate RUNs', () => {
    const v = lintContent(`FROM debian:latest
RUN apt-get update
RUN apt-get install -y gcc g++ openjdk-21-jdk
COPY . /workspace
WORKDIR /workspace
RUN ./gradlew --quiet --console=plain clean buildSharedLibrary
RUN strip --strip-unneeded build/output/libvec.so
CMD ["cat", "build/output/libvec.so"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest tag
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);   // apt-get update separate
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // no multi-stage
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('krb5kdc test fixture: alpine pinned, apk -y flag on addless apk', () => {
    const v = lintContent(`FROM alpine:3.21.0
ADD src/main/resources /fixture
RUN apk update && apk add -y --no-cache python3 krb5 krb5-server
RUN echo kerberos.build.elastic.co > /etc/hostname
RUN sh /fixture/provision/installkdc.sh
EXPOSE 88
EXPOSE 88/udp
CMD ["sleep", "infinity"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('elasticsearch main Dockerfile: multi-stage with ARG, USER 1000', () => {
    const v = lintContent(`FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y curl
ARG ES_VERSION=8.12.0
RUN curl -fsSL https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ES_VERSION-linux-x86_64.tar.gz -o es.tar.gz
RUN tar xzf es.tar.gz

FROM ubuntu:22.04
COPY --from=builder /elasticsearch-$ES_VERSION /usr/share/elasticsearch
WORKDIR /usr/share/elasticsearch
RUN groupadd -g 1000 elasticsearch && useradd -u 1000 -g elasticsearch elasticsearch
RUN chown -R elasticsearch:elasticsearch /usr/share/elasticsearch
EXPOSE 9200 9300
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["eswrapper"]
USER 1000:0
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER present
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('elasticsearch ironbank variant: labels, tini entrypoint', () => {
    const v = lintContent(`FROM redhat/ubi9:9.3 AS builder
RUN dnf install -y tar gzip shadow-utils
COPY elasticsearch.tar.gz /opt/
RUN tar xzf /opt/elasticsearch.tar.gz -C /opt

FROM redhat/ubi9-minimal:9.3
COPY --from=builder /opt/elasticsearch /usr/share/elasticsearch
RUN microdnf install -y findutils shadow-utils && microdnf clean all
RUN groupadd -g 1000 elasticsearch && useradd -u 1000 -g elasticsearch -d /usr/share/elasticsearch elasticsearch
LABEL name="Elasticsearch" vendor="Elastic" version="8.12.0"
EXPOSE 9200 9300
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["eswrapper"]
USER 1000:0
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER 1000:0
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });
});

// ── cockroachdb/cockroach patterns ─────────────────────────────────────

describe('OSS: cockroachdb/cockroach patterns', () => {
  it('deploy image: ubi-minimal, microdnf, no USER', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi10/ubi-minimal
RUN microdnf update -y && microdnf install -y ca-certificates tzdata hostname tar gzip xz && rm -rf /var/cache/yum
RUN mkdir /usr/local/lib/cockroach /cockroach /licenses /docker-entrypoint-initdb.d
COPY cockroach.sh cockroach /cockroach/
COPY LICENSE THIRD-PARTY-NOTICES.txt /licenses/
COPY libgeos.so libgeos_c.so /usr/local/lib/cockroach/
WORKDIR /cockroach/
ENV PATH=/cockroach:$PATH
ENV COCKROACH_CHANNEL=official-docker
EXPOSE 26257 8080
ENTRYPOINT ["/cockroach/cockroach.sh"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);   // untagged base
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('bazelbuilder: massive build image with SHELL override', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM ubuntu:noble AS fetch
ARG TARGETPLATFORM
SHELL ["/usr/bin/bash", "-c"]
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg2

FROM ubuntu:noble
ARG TARGETPLATFORM
SHELL ["/usr/bin/bash", "-c"]
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends autoconf bison ca-certificates clang-20 cmake curl flex g++ git gnupg2 libncurses-dev make netbase openjdk-8-jre openssh-client patch python-is-python3 python3 unzip zip
RUN curl -fsSL "https://github.com/Kitware/CMake/releases/download/v3.20.3/cmake-3.20.3-linux-x86_64.tar.gz" -o cmake.tar.gz && tar --strip-components=1 -C /usr -xzf cmake.tar.gz && rm cmake.tar.gz
ENTRYPOINT ["autouseradd", "--user", "roach", "--no-create-home"]
CMD ["/usr/bin/bash"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('kdc test fixture: alpine, apk, no USER', () => {
    const v = lintContent(`FROM alpine:3.14
RUN apk add --no-cache krb5-server && rm -rf /var/cache/apk/*
COPY krb5.conf /etc/krb5.conf
RUN kdb5_util create -s -P kpass && kadmin.local -q "addprinc -pw psql tester@MY.EX"
EXPOSE 88
EXPOSE 88/udp
CMD ["/start.sh"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('acceptance test: ubuntu:18.04, broad COPY, complex deps', () => {
    const v = lintContent(`FROM ubuntu:18.04
ARG TARGETPLATFORM
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates curl
RUN curl -fsSL https://dl.yarnpkg.com/debian/pubkey.gpg > /etc/apt/trusted.gpg.d/yarn.asc
RUN apt-get update && apt-get install --yes --no-install-recommends make maven nodejs gcc golang php-cli php-pgsql python python-psycopg2 ruby ruby-pg yarn python3-dev python3-pip python3-setuptools
RUN pip3 install --upgrade pip && pip3 install psycopg
COPY . /testdata
CMD ["/bin/bash"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);   // unpinned pip
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // no multi-stage
  });

  it('roachprod: multi-stage with ARG BAZEL_IMAGE, git clone', () => {
    const v = lintContent(`ARG BAZEL_IMAGE
FROM $BAZEL_IMAGE AS builder
ARG OWNER
ARG REPO
ARG SHA
RUN git clone https://github.com/$OWNER/$REPO /build
WORKDIR /build
RUN git checkout $SHA
RUN bazel build --config=crosslinux //pkg/cmd/roachprod:roachprod
RUN cp $(bazel info bazel-bin --config=crosslinux)/pkg/cmd/roachprod/roachprod_/roachprod ./

FROM golang:1.25
COPY entrypoint.sh build.sh /build/
RUN ["/build/build.sh"]
COPY --from=builder /build/roachprod /usr/local/bin/roachprod
ENTRYPOINT ["/build/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('cypress e2e: single RUN with pnpm install', () => {
    const v = lintContent(`FROM cypress/browsers:node-22.11.0-chrome-130.0.6723.69-1-ff-132.0-edge-130.0.2849.56-1
RUN curl -fsSL https://get.pnpm.io/install.sh | env SHELL=bash PNPM_HOME=/usr/local/bin PNPM_VERSION=9.15.5 sh -
RUN pnpm --version
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // missing .dockerignore hint
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });
});

// ── nats-io/nats-server patterns ───────────────────────────────────────

describe('OSS: nats-io/nats-server patterns', () => {
  it('nightly build: multi-stage, --platform, alpine:latest', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ARG VERSION="nightly"
ARG GIT_COMMIT
ARG TARGETOS
ARG TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH GO111MODULE=on CGO_ENABLED=0
RUN apk add --no-cache ca-certificates
RUN update-ca-certificates
WORKDIR /src
COPY ./nats-server/ /src/nats-server/
RUN cd /src/nats-server && go build -trimpath -o /src/out/$TARGETOS/$TARGETARCH/nats-server .

FROM --platform=$TARGETPLATFORM alpine:latest
ARG TARGETOS
ARG TARGETARCH
COPY ./nats-server/docker/nats-server.conf /nats/conf/nats-server.conf
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/out/$TARGETOS/$TARGETARCH/nats-server /bin/nats-server
EXPOSE 4222 8222 6222 5222
ENTRYPOINT ["/bin/nats-server"]
CMD ["-c", "/nats/conf/nats-server.conf"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // alpine:latest
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning in final stage
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);   // cd instead of WORKDIR
  });

  it('nats scratch image: minimal binary-only', () => {
    const v = lintContent(`FROM scratch
COPY nats-server /nats-server
EXPOSE 4222 8222 6222
ENTRYPOINT ["/nats-server"]
CMD ["--config", "/nats-server.conf"]
`);
    // scratch images produce no violations for USER/HEALTHCHECK in current rules
    expect(v.length).toBe(0);
  });

  it('nats with healthcheck: proper production setup', () => {
    const v = lintContent(`FROM alpine:3.20
RUN apk add --no-cache ca-certificates curl
COPY nats-server /usr/local/bin/
RUN adduser -D -u 1000 nats
USER nats
EXPOSE 4222 8222
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8222/healthz || exit 1
ENTRYPOINT ["nats-server"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // .dockerignore hint
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('nats cluster config: env-heavy, multiple ports', () => {
    const v = lintContent(`FROM nats:2.10-alpine
ENV NATS_CLUSTER_PORT=6222
ENV NATS_ROUTES="nats://nats-1:6222,nats://nats-2:6222"
COPY nats-cluster.conf /etc/nats/nats-cluster.conf
EXPOSE 4222 6222 8222
CMD ["nats-server", "-c", "/etc/nats/nats-cluster.conf"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });
});

// ── Cross-repo patterns: redis/mongo/elasticsearch/cockroach/nats ─────

describe('OSS scan: DB/messaging cross-repo patterns', () => {
  it('microdnf usage (cockroachdb, elasticsearch): custom package manager', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi9-minimal:9.3
RUN microdnf install -y shadow-utils tar gzip && microdnf clean all
RUN groupadd -g 1000 app && useradd -u 1000 -g app app
COPY app /usr/local/bin/app
USER app
ENTRYPOINT ["/usr/local/bin/app"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER present
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('source build pattern (redis, mongo): compile from tarball', () => {
    const v = lintContent(`FROM debian:bookworm AS builder
RUN apt-get update && apt-get install -y gcc make libc6-dev libssl-dev
ARG VERSION=7.2.4
ADD https://example.com/app-$VERSION.tar.gz /tmp/
RUN tar xzf /tmp/app-$VERSION.tar.gz -C /usr/src && make -C /usr/src/app -j && make -C /usr/src/app install

FROM debian:bookworm-slim
COPY --from=builder /usr/local/bin/app-server /usr/local/bin/
USER nobody
EXPOSE 6379
CMD ["app-server"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR in final
  });

  it('multi-platform build (nats, cockroach): BUILDPLATFORM + TARGETPLATFORM', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:1.22 AS builder
ARG TARGETOS TARGETARCH
ENV GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0
WORKDIR /src
COPY . .
RUN go build -o /app

FROM --platform=$TARGETPLATFORM gcr.io/distroless/static:nonroot
COPY --from=builder /app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // .dockerignore hint
  });

  it('database port exposure pattern: standard DB ports', () => {
    const v = lintContent(`FROM alpine:3.20
RUN apk add --no-cache postgresql-client redis mongodb-tools
EXPOSE 5432 6379 27017 9200 26257
CMD ["sleep", "infinity"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
  });

  it('grafana integration (cockroachdb): grafana/grafana:master, env-heavy', () => {
    const v = lintContent(`FROM grafana/grafana:master
ENV GF_INSTALL_PLUGINS grafana-clock-panel,briangann-gauge-panel
ENV GF_SECURITY_ADMIN_PASSWORD x
ENV GF_USERS_ALLOW_SIGN_UP false
ENV GF_DASHBOARDS_JSON_ENABLED true
COPY postgres.yml /etc/grafana/provisioning/datasources/postgres.yml
COPY dashboards.yml /etc/grafana/provisioning/dashboards/dashboards.yml
`);
    expect(v.some(v => v.rule === 'DV1001')).toBe(true);   // password in ENV
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);   // .dockerignore hint
  });
});

// ── minio/minio patterns ──────────────────────────────────────────────

describe('OSS: minio/minio patterns', () => {
  it('Dockerfile: latest tag, chmod 777, no USER, no WORKDIR', () => {
    const v = lintContent(`FROM minio/minio:latest
ARG TARGETARCH
ARG RELEASE
RUN chmod -R 777 /usr/bin
COPY ./minio-\${TARGETARCH}.\${RELEASE} /usr/bin/minio
COPY dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
VOLUME ["/data"]
CMD ["minio"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
    expect(v.some(v => v.rule === 'DV4009')).toBe(true);   // chmod 777
  });

  it('Dockerfile.release: multi-stage, ARG injection in URLs, unpinned apk', () => {
    const v = lintContent(`FROM golang:1.24-alpine AS build
ARG TARGETARCH
ARG RELEASE
ENV CGO_ENABLED=0
WORKDIR /build
RUN apk add -U --no-cache ca-certificates
RUN apk add -U --no-cache curl
RUN apk add -U --no-cache bash
RUN curl -s -q https://dl.min.io/server/minio/release/linux-\${TARGETARCH}/archive/minio.\${RELEASE} -o /go/bin/minio && \\
    chmod +x /go/bin/minio
FROM registry.access.redhat.com/ubi9/ubi-micro:latest
ARG RELEASE
RUN chmod -R 777 /usr/bin
COPY --from=build /go/bin/minio /usr/bin/minio
EXPOSE 9000
VOLUME ["/data"]
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
CMD ["minio"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DV3023')).toBe(true);   // unquoted ARG in URL
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest on ubi-micro
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4009')).toBe(true);   // chmod 777
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // consecutive RUN
  });

  it('Dockerfile.cicd: minimal override, no HEALTHCHECK', () => {
    const v = lintContent(`FROM minio/minio
COPY ./minio /usr/bin/minio
COPY dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
VOLUME ["/data"]
CMD ["minio"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('Dockerfile.scratch: scratch-based, minimal', () => {
    const v = lintContent(`FROM scratch
COPY dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh
COPY minio /usr/bin/minio
ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
VOLUME ["/data"]
CMD ["minio"]
`);
    // scratch images are minimal — fewer rules apply
    const rules = ruleSet(v);
    expect(rules).not.toContain('DV1006'); // scratch can't run USER
  });

  it('object storage pattern: VOLUME + EXPOSE, env-heavy config', () => {
    const v = lintContent(`FROM minio/minio:latest
ENV MINIO_ACCESS_KEY_FILE=access_key \\
    MINIO_SECRET_KEY_FILE=secret_key \\
    MINIO_ROOT_USER_FILE=access_key \\
    MINIO_ROOT_PASSWORD_FILE=secret_key \\
    MC_CONFIG_DIR=/tmp/.mc
RUN chmod -R 777 /usr/bin
EXPOSE 9000
VOLUME ["/data"]
CMD ["minio"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest
    expect(v.some(v => v.rule === 'DV4009')).toBe(true);   // chmod 777
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });
});

// ── influxdata/influxdb patterns ──────────────────────────────────────

describe('OSS: influxdata/influxdb patterns', () => {
  it('Dockerfile: Rust multi-stage, unpinned apt, proper USER', () => {
    const v = lintContent(`FROM rust:1.92-slim-bookworm as build
USER root
RUN apt update \\
    && apt install --yes binutils build-essential curl pkg-config libssl-dev clang lld git patchelf protobuf-compiler zstd libz-dev \\
    && rm -rf /var/lib/{apt,dpkg,cache,log}
RUN mkdir /influxdb3
WORKDIR /influxdb3
COPY . /influxdb3
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt update \\
    && apt install --yes ca-certificates gettext-base libssl3 wget curl --no-install-recommends \\
    && rm -rf /var/lib/{apt,dpkg,cache,log} \\
    && groupadd --gid 1500 influxdb3 \\
    && useradd --uid 1500 --gid influxdb3 --shell /bin/bash --create-home influxdb3
RUN mkdir /var/lib/influxdb3 && \\
    chown influxdb3:influxdb3 /var/lib/influxdb3
USER influxdb3
COPY --from=build /root/influxdb3 /usr/bin/influxdb3
EXPOSE 8181
ENTRYPOINT ["/usr/bin/entrypoint.sh"]
CMD ["serve"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);   // apt update without install in same RUN
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('Dockerfile.ci: CI image with sudo, massive apt install', () => {
    const v = lintContent(`FROM rust:1.92-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \\
  && apt-get install -y \\
    git locales sudo openssh-client ca-certificates tar gzip parallel \\
    unzip zip bzip2 gnupg curl make pkg-config libssl-dev \\
    jq clang lld g++ shellcheck yamllint protobuf-compiler libprotobuf-dev \\
    --no-install-recommends \\
  && apt-get clean autoclean \\
  && rm -rf /var/lib/{apt,dpkg,cache,log}
RUN groupadd -g 1500 rust \\
  && useradd -u 1500 -g rust -s /bin/bash -m rust \\
  && echo 'rust ALL=NOPASSWD: ALL' >> /etc/sudoers.d/10-rust
RUN cargo install cargo-hakari && \\
    cargo install cargo-deny && \\
    chown -R rust:rust /usr/local/cargo
USER rust
CMD ["/bin/bash"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('time-series DB pattern: Rust build with patchelf + custom user', () => {
    const v = lintContent(`FROM rust:1.92-slim-bookworm AS build
WORKDIR /app
RUN apt update && apt install --yes build-essential pkg-config libssl-dev
COPY . .
RUN cargo build --release && patchelf --set-rpath '/lib' /app/target/release/influxdb3

FROM debian:bookworm-slim
RUN groupadd --gid 1500 influxdb3 && useradd --uid 1500 --gid influxdb3 --create-home influxdb3
COPY --from=build /app/target/release/influxdb3 /usr/bin/influxdb3
USER influxdb3
EXPOSE 8181
ENV LOG_FILTER=info
CMD ["serve"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });
});

// ── apache/airflow patterns ──────────────────────────────────────────

describe('OSS: apache/airflow patterns', () => {
  it('main Dockerfile: complex multi-stage with ARG-heavy FROM', () => {
    const v = lintContent(`FROM python:3.12-slim-bookworm AS build
ARG AIRFLOW_VERSION="3.1.7"
ARG AIRFLOW_HOME=/opt/airflow
ENV AIRFLOW_HOME=\${AIRFLOW_HOME}
RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential libpq-dev \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/airflow
COPY . .
RUN pip install --no-cache-dir apache-airflow==\${AIRFLOW_VERSION}

FROM python:3.12-slim-bookworm
ARG AIRFLOW_UID="50000"
RUN groupadd --gid \${AIRFLOW_UID} airflow \\
    && useradd --uid \${AIRFLOW_UID} --gid airflow --create-home airflow
COPY --from=build /opt/airflow /opt/airflow
USER airflow
WORKDIR /opt/airflow
HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1
EXPOSE 8080
CMD ["airflow", "webserver"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
  });

  it('krb5-kdc-server: centos:7, yum + curl pipe pattern', () => {
    const v = lintContent(`FROM centos:7
WORKDIR /root/
RUN yum -y install curl wget python36 && yum clean all && \\
    curl "https://bootstrap.pypa.io/get-pip.py" -o /tmp/get-pip.py && \\
    python3 /tmp/get-pip.py && \\
    rm /tmp/get-pip.py && \\
    pip install --no-cache-dir supervisor
RUN yum -y install ntp krb5-server krb5-libs && yum clean all
ENV KRB5_CONFIG=/etc/krb5.conf
COPY kdc.conf /var/kerberos/krb5kdc/kdc.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/supervisord", "-n", "-c", "/etc/supervisord.conf"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('pgbouncer: alpine multi-stage, proper HEALTHCHECK + USER', () => {
    const v = lintContent(`FROM alpine:3.19 AS builder
SHELL ["/bin/ash", "-e", "-x", "-c", "-o", "pipefail"]
ARG PGBOUNCER_VERSION
ARG PGBOUNCER_SHA256
RUN apk --no-cache add make pkgconfig build-base libtool wget gcc g++ libevent-dev openssl-dev c-ares-dev ca-certificates
RUN wget "https://github.com/pgbouncer/pgbouncer/releases/download/pgbouncer_\${PGBOUNCER_VERSION}/pgbouncer-\${PGBOUNCER_VERSION}.tar.gz" \\
    && echo "\${PGBOUNCER_SHA256}  pgbouncer-\${PGBOUNCER_VERSION}.tar.gz" | sha256sum -c -

FROM alpine:3.19
RUN apk --no-cache add libevent libressl c-ares
COPY --from=builder /usr/bin/pgbouncer /usr/bin/pgbouncer
HEALTHCHECK --interval=10s --timeout=3s CMD stat /tmp/.s.PGSQL.*
EXPOSE 6432
USER nobody
ENTRYPOINT ["/usr/bin/pgbouncer", "-u", "nobody", "/etc/pgbouncer/pgbouncer.ini"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    // Has HEALTHCHECK and USER — good practices
    const rules = ruleSet(v);
    expect(rules).not.toContain('DL3057');
    expect(rules).not.toContain('DV1006');
  });

  it('extending pattern: FROM apache/airflow, USER root then back to airflow', () => {
    const v = lintContent(`FROM apache/airflow:3.2.0
USER root
RUN apt-get update \\
  && apt-get install -y --no-install-recommends \\
       vim \\
  && apt-get autoremove -yqq --purge \\
  && apt-get clean \\
  && rm -rf /var/lib/apt/lists/*
USER airflow
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);   // no WORKDIR
  });

  it('workflow orchestrator pattern: large ENV, pip install', () => {
    const v = lintContent(`FROM python:3.12-slim-bookworm
ARG AIRFLOW_HOME=/opt/airflow
ENV AIRFLOW_HOME=\${AIRFLOW_HOME} \\
    PYTHONPATH=/opt/airflow \\
    FLASK_APP="superset.app:create_app()"
RUN apt-get update && apt-get install -y --no-install-recommends \\
    libpq-dev curl \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR \${AIRFLOW_HOME}
RUN pip install --no-cache-dir apache-airflow[celery,postgres,redis]==3.1.7
EXPOSE 8080
CMD ["airflow", "webserver"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);   // pip best practice
  });
});

// ── apache/superset patterns ──────────────────────────────────────────

describe('OSS: apache/superset patterns', () => {
  it('main Dockerfile: node + python multi-stage, HEALTHCHECK present', () => {
    const v = lintContent(`FROM node:20-trixie-slim AS superset-node-ci
RUN apt-get update && apt-get install -y build-essential python3 zstd \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app/superset-frontend
COPY superset-frontend /app/superset-frontend
RUN npm ci && npm run build

FROM python:3.11-slim-trixie AS python-base
RUN useradd --user-group -m --no-log-init --shell /bin/bash superset
RUN pip install --no-cache-dir --upgrade uv
WORKDIR /app
COPY --from=superset-node-ci /app/superset/static/assets superset/static/assets
COPY superset superset
HEALTHCHECK CMD curl -f http://localhost:8088/health || exit 1
CMD ["/app/docker/entrypoints/run-server.sh"]
EXPOSE 8088
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER in final stage
    // Has HEALTHCHECK
    const rules = ruleSet(v);
    expect(rules).not.toContain('DL3057');
  });

  it('superset-websocket: node multi-stage, proper USER', () => {
    const v = lintContent(`FROM node:22-alpine AS build
WORKDIR /home/superset-websocket
COPY . ./
RUN npm ci && npm run build

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /home/superset-websocket
COPY --from=build /home/superset-websocket/dist ./dist
COPY package*.json ./
RUN npm ci --omit=dev
USER node
CMD [ "npm", "start" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    // Has USER
    const rules = ruleSet(v);
    expect(rules).not.toContain('DV1006');
  });

  it('.devcontainer: dev image, no USER, pipe to sh', () => {
    const v = lintContent(`FROM python:3.11.13-trixie AS base
RUN apt-get update && apt-get install -y \\
    libsasl2-dev \\
    libldap2-dev \\
    libpq-dev \\
    tmux \\
    gh \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);   // curl pipe to sh
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);   // apt-get no -y flag variant
  });

  it('data visualization pattern: Python + Node + HEALTHCHECK', () => {
    const v = lintContent(`FROM python:3.11-slim-trixie
RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl libsasl2-dev libpq-dev libldap2-dev \\
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv
WORKDIR /app
ENV SUPERSET_HOME="/app/superset_home" \\
    FLASK_APP="superset.app:create_app()" \\
    SUPERSET_PORT="8088"
COPY . .
RUN uv pip install -e .
HEALTHCHECK CMD curl -f http://localhost:8088/health || exit 1
EXPOSE 8088
CMD ["/app/docker/entrypoints/run-server.sh"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // unpinned apt
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    // Has HEALTHCHECK
    const rules = ruleSet(v);
    expect(rules).not.toContain('DL3057');
  });

  it('lean image pattern: FROM python-common with USER superset', () => {
    const v = lintContent(`FROM python:3.11-slim-trixie
RUN useradd --user-group -m --shell /bin/bash superset
WORKDIR /app
RUN pip install --no-cache-dir uv
COPY requirements/base.txt requirements/
RUN pip install --no-cache-dir -r requirements/base.txt
RUN python -m compileall /app/superset
USER superset
EXPOSE 8088
CMD ["/app/docker/entrypoints/run-server.sh"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    // Has USER — good
    const rules = ruleSet(v);
    expect(rules).not.toContain('DV1006');
  });
});

// ── trufflesecurity/trufflehog patterns ──────────────────────────────

describe('OSS: trufflesecurity/trufflehog patterns', () => {
  it('Dockerfile: go multi-stage + alpine runtime, unpinned apk', () => {
    const v = lintContent(`FROM golang:bullseye as builder
WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
ARG TARGETOS TARGETARCH
RUN GOOS=\${TARGETOS} GOARCH=\${TARGETARCH} go build -o trufflehog .

FROM alpine:3.22
RUN apk add --no-cache bash git openssh-client ca-certificates rpm2cpio binutils cpio \\
    && rm -rf /var/cache/apk/* && update-ca-certificates
COPY --from=builder /build/trufflehog /usr/bin/trufflehog
COPY entrypoint.sh /etc/entrypoint.sh
RUN chmod +x /etc/entrypoint.sh
ENTRYPOINT ["/etc/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('Dockerfile.goreleaser: alpine-only, pre-built binary', () => {
    const v = lintContent(`FROM alpine:3.22
RUN apk add --no-cache bash git openssh-client ca-certificates \\
    && rm -rf /var/cache/apk/* && update-ca-certificates
WORKDIR /usr/bin/
COPY trufflehog .
COPY entrypoint.sh /etc/entrypoint.sh
RUN chmod +x /etc/entrypoint.sh
ENTRYPOINT ["/etc/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('secret scanner pattern: go build + security tools', () => {
    const v = lintContent(`FROM golang:1.23-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /trufflehog .

FROM alpine:3.22
RUN apk add --no-cache git openssh-client ca-certificates
COPY --from=builder /trufflehog /usr/bin/trufflehog
USER 65534
ENTRYPOINT ["/usr/bin/trufflehog"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    // Has USER
    const rules = ruleSet(v);
    expect(rules).not.toContain('DV1006');
  });

  it('go builder pattern: BUILDPLATFORM + TARGETOS/TARGETARCH', () => {
    const v = lintContent(`FROM --platform=\${BUILDPLATFORM} golang:bullseye as builder
WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
ARG TARGETOS TARGETARCH
RUN GOOS=\${TARGETOS} GOARCH=\${TARGETARCH} go build -o /app .

FROM alpine:3.22
COPY --from=builder /app /usr/bin/app
RUN apk add --no-cache ca-certificates
ENTRYPOINT ["/usr/bin/app"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });
});

// ── keycloak/keycloak patterns ─────────────────────────────────────────

describe('OSS: keycloak/keycloak patterns', () => {
  it('operator/Dockerfile: multi-stage with untagged UBI base, ADD instead of COPY', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi9 AS ubi-micro-build
ADD target/ubi-null.sh /tmp/
RUN bash /tmp/ubi-null.sh java-25-openjdk-headless glibc-langpack-en

FROM registry.access.redhat.com/ubi9-micro
ENV LANG=en_US.UTF-8
COPY --from=ubi-micro-build /tmp/null/rootfs/ /
ADD --chown=1000:0 target/quarkus-app/ /opt/keycloak
RUN chmod -R g+rwX /opt/keycloak
USER 1000
WORKDIR /opt/keycloak
ENTRYPOINT [ "java", "-Djava.util.logging.manager=org.jboss.logmanager.LogManager", "-jar", "quarkus-run.jar" ]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);   // untagged base image
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);   // ADD instead of COPY
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('operator/Dockerfile: USER directive present → no DV1006', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi9-micro
COPY --from=build /app /app
USER 1000
ENTRYPOINT [ "java", "-jar", "quarkus-run.jar" ]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });

  it('quarkus/container/Dockerfile: multi-stage build with dnf install, ADD remote URL', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi9 AS ubi-micro-build
ARG KEYCLOAK_DIST=https://github.com/keycloak/keycloak/releases/download/1.0/keycloak-1.0.tar.gz
RUN dnf install -y tar gzip
ADD $KEYCLOAK_DIST /tmp/keycloak/
RUN mv /tmp/keycloak/keycloak-* /opt/keycloak && mkdir -p /opt/keycloak/data
RUN chmod -R g+rwX /opt/keycloak

FROM registry.access.redhat.com/ubi9-micro
ENV LANG=en_US.UTF-8
COPY --from=ubi-micro-build /tmp/null/rootfs/ /
COPY --from=ubi-micro-build --chown=1000:0 /opt/keycloak /opt/keycloak
USER 1000
EXPOSE 8080
EXPOSE 8443
ENTRYPOINT [ "/opt/keycloak/bin/kc.sh" ]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);   // untagged base
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV3021')).toBe(true);   // multiple RUN consolidation
  });

  it('test-framework/db-edb/container/Dockerfile: secrets mount, curl pipe to bash', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi9
ENV PGUSER=enterprisedb
ENV PGPASSWORD=password
ENV PGDATABASE=keycloak
ENV PGPORT=5432
ENV PGDATA=/var/lib/edb/as18/data
RUN --mount=type=secret,id=edb_repo_token,required=true \\
    export EDB_REPO_TOKEN=$(cat /run/secrets/edb_repo_token) && \\
    (curl -1sSLf "https://downloads.enterprisedb.com/token/enterprise/setup.rpm.sh" | bash) && \\
    dnf -y install edb-as18-server
USER enterprisedb
WORKDIR /usr/edb/as18/bin/
COPY init-and-start-db.sh .
CMD ./init-and-start-db.sh
EXPOSE 5432
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);   // untagged base
    expect(v.some(v => v.rule === 'DV1001')).toBe(true);   // curl pipe to bash
    expect(v.some(v => v.rule === 'DL3025')).toBe(true);   // CMD not JSON
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);   // sensitive ENV
  });

  it('quarkus: multi-stage properly isolates secrets from final image', () => {
    const v = lintContent(`FROM registry.access.redhat.com/ubi9 AS build
RUN dnf install -y tar gzip
FROM registry.access.redhat.com/ubi9-micro
COPY --from=build /opt/keycloak /opt/keycloak
USER 1000
ENTRYPOINT [ "/opt/keycloak/bin/kc.sh" ]
`);
    // Final stage has USER, no secrets leaking
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    expect(v.some(v => v.rule === 'DV1003')).toBe(false);
  });
});

// ── dexidp/dex patterns ────────────────────────────────────────────────

describe('OSS: dexidp/dex patterns', () => {
  it('Dockerfile: complex multi-stage with alpine-sdk, unpinned apk packages', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine3.22 AS builder
RUN apk add --update alpine-sdk ca-certificates openssl clang lld
WORKDIR /usr/local/src/dex
ENV CGO_ENABLED=1
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make release-binary

FROM alpine:3.23.3 AS stager
RUN mkdir -p /var/dex
RUN mkdir -p /etc/dex
COPY config.docker.yaml /etc/dex/

FROM alpine:3.23.3
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=stager --chown=1001:1001 /var/dex /var/dex
COPY --from=stager --chown=1001:1001 /etc/dex /etc/dex
COPY --from=builder /go/bin/dex /usr/local/bin/dex
COPY --from=builder /go/bin/docker-entrypoint /usr/local/bin/docker-entrypoint
USER dex:dex
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["dex", "serve", "/etc/dex/config.docker.yaml"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk version pinning
    expect(v.some(v => v.rule === 'DL3019')).toBe(true);   // apk --no-cache
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // broad COPY .
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('Dockerfile: final stage has USER → no DV1006', () => {
    const v = lintContent(`FROM alpine:3.23.3
COPY --from=builder /go/bin/dex /usr/local/bin/dex
USER dex:dex
ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
CMD ["dex", "serve", "/etc/dex/config.docker.yaml"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });

  it('Dockerfile: distroless image pinned with digest → no DL3006', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian13:nonroot@sha256:f512d819b8f109f2375e8b51d8cfd8aafe81034bc3e319740128b7d7f70d5036 AS distroless
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    expect(v.some(v => v.rule === 'DL3007')).toBe(false);
  });

  it('stager stage: minimal alpine, no USER, no CMD', () => {
    const v = lintContent(`FROM alpine:3.23.3 AS stager
RUN mkdir -p /var/dex
RUN mkdir -p /etc/dex
COPY config.docker.yaml /etc/dex/
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
  });

  it('builder stage: broad COPY . detected in build context', () => {
    const v = lintContent(`FROM golang:1.26.0-alpine3.22 AS builder
WORKDIR /usr/local/src/dex
COPY go.mod go.sum ./
COPY . .
RUN make release-binary
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // COPY . .
  });
});

// ── open-policy-agent/gatekeeper patterns ──────────────────────────────

describe('OSS: open-policy-agent/gatekeeper patterns', () => {
  it('Dockerfile: multi-stage with distroless final, proper USER', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS builder
ARG LDFLAGS
ENV GO111MODULE=on \\
    CGO_ENABLED=0
WORKDIR /go/src/github.com/open-policy-agent/gatekeeper
COPY . .
RUN go build -a -ldflags "\${LDFLAGS}" -o manager

FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
WORKDIR /
COPY --from=builder /go/src/github.com/open-policy-agent/gatekeeper/manager .
USER 65532:65532
ENTRYPOINT ["/manager"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // COPY . .
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER present
  });

  it('Dockerfile: distroless pinned with digest → no DL3006/DL3007 on final', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
WORKDIR /
COPY manager .
USER 65532:65532
ENTRYPOINT ["/manager"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);
    expect(v.some(v => v.rule === 'DL3007')).toBe(false);
  });

  it('build/tooling/Dockerfile: no USER, no CMD, no ENTRYPOINT', () => {
    const v = lintContent(`FROM golang:1.26-trixie
RUN GO111MODULE=on go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.19.0
RUN GO111MODULE=on go install k8s.io/code-generator/cmd/conversion-gen@v0.29.3
RUN mkdir /gatekeeper
WORKDIR /gatekeeper
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);   // no COPY/ADD in final
  });

  it('crd.Dockerfile: scratch base with kubectl from k8s registry', () => {
    const v = lintContent(`FROM --platform=$TARGETPLATFORM registry.k8s.io/kubectl:v1.35.2 AS builder
FROM scratch AS build
USER 65532:65532
COPY --chown=65532:65532 * /crds/
COPY --from=builder /bin/kubectl /kubectl
ENTRYPOINT ["/kubectl"]
`);
    // scratch is valid, USER present, ENTRYPOINT present
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
    expect(v.some(v => v.rule === 'DV4005')).toBe(false);
  });

  it('gator.Dockerfile: multi-stage go build with cache mounts', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS builder
ENV GO111MODULE=on \\
    CGO_ENABLED=0
COPY . /go/src/github.com/open-policy-agent/gatekeeper
WORKDIR /go/src/github.com/open-policy-agent/gatekeeper/cmd/gator
RUN --mount=type=cache,target=/go/pkg/mod \\
    --mount=type=cache,target=/root/.cache/go-build \\
    go build -a -ldflags "\${LDFLAGS}" -o /gator

FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838 AS build
USER 65532:65532
COPY --from=builder --chown=65532:65532 /gator /gator
ENTRYPOINT ["/gator"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // COPY . broad
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER present
  });

  it('test/export/fake-reader/Dockerfile: go mod init in container, distroless final', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS builder
ENV GO111MODULE=on \\
    CGO_ENABLED=0
WORKDIR /go/src/github.com/open-policy-agent/gatekeeper/test/export/fake-reader
COPY . .
RUN go mod init && go mod tidy && go mod vendor
RUN go build -o main

FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
WORKDIR /
COPY --from=builder /go/src/github.com/open-policy-agent/gatekeeper/test/export/fake-reader/main .
USER 65532:65532
ENTRYPOINT ["/main"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // COPY . .
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER present
  });

  it('test/externaldata/dummy-provider: copies certs to final image', () => {
    const v = lintContent(`FROM --platform=$BUILDPLATFORM golang:1.26-trixie AS builder
ENV CGO_ENABLED=0
WORKDIR /go/src/github.com/open-policy-agent/gatekeeper/test/externaldata/dummy-provider
COPY . .
RUN go mod init && go mod tidy
RUN go build -o provider provider.go

FROM gcr.io/distroless/static-debian12@sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
WORKDIR /
COPY --from=builder /go/src/github.com/open-policy-agent/gatekeeper/test/externaldata/dummy-provider/provider .
COPY --from=builder --chown=65532:65532 /go/src/github.com/open-policy-agent/gatekeeper/test/externaldata/dummy-provider/certs/server.crt \\
    /go/src/github.com/open-policy-agent/gatekeeper/test/externaldata/dummy-provider/certs/server.key \\
    /etc/ssl/certs/
USER 65532:65532
ENTRYPOINT ["/provider"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);   // COPY . .
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);  // USER present in final
  });

  it('test/image/Dockerfile: apt without pinning, curl pipe to shell, docker-in-docker', () => {
    const v = lintContent(`FROM golang:1.26-trixie AS builder
RUN apt-get update && apt-get install -y make jq apt-utils
RUN curl -L -O "https://example.com/kustomize.tar.gz" && \\
    tar -zxvf kustomize.tar.gz && chmod +x kustomize && mv kustomize /usr/local/bin
RUN curl -fsSL https://get.docker.com | sh
WORKDIR /app
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // apt version pinning
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);   // curl pipe to sh
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // no CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);   // single stage
  });
});

// ── falcosecurity/falco patterns ───────────────────────────────────────

describe('OSS: falcosecurity/falco patterns', () => {
  it('docker/falco/Dockerfile: wolfi-base with unpinned apk, no USER', () => {
    const v = lintContent(`FROM cgr.dev/chainguard/wolfi-base
ENV FALCO_VERSION="latest"
ENV HOST_ROOT=/host
ENV HOME=/root
RUN apk update && apk add curl ca-certificates jq libstdc++
WORKDIR /
CMD ["/usr/bin/falco"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);   // untagged base
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DL3019')).toBe(true);   // apk --no-cache
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('docker/falco-debian/Dockerfile: apt-key deprecated, no USER', () => {
    const v = lintContent(`FROM debian:12-slim
ENV FALCO_VERSION="latest"
ENV HOST_ROOT=/host
ENV HOME=/root
RUN apt-get -y update && apt-get -y install curl jq ca-certificates gnupg2 \\
    && apt clean -y && rm -rf /var/lib/apt/lists/*
WORKDIR /
RUN curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add -
CMD ["/usr/bin/falco"]
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('docker/driver-loader/Dockerfile: privileged container, massive apt install', () => {
    const v = lintContent(`FROM docker.io/falcosecurity/falco:latest-debian
ENV HOST_ROOT=/host
ENV HOME=/root
RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
    bc bison ca-certificates clang curl dkms dwarves flex gcc gcc-11 \\
    gnupg2 jq libc6-dev libssl-dev llvm make netcat-openbsd patchelf xz-utils zstd \\
    && rm -rf /var/lib/apt/lists/*
RUN rm -df /lib/modules && ln -s $HOST_ROOT/lib/modules /lib/modules
COPY ./docker/driver-loader/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // apt version pinning
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('docker/driver-loader-buster/Dockerfile: debian:buster, massive deps, gcc symlink', () => {
    const v = lintContent(`FROM debian:buster
ENV FALCO_VERSION="latest"
ENV HOST_ROOT=/host
ENV HOME=/root
RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
    bash-completion bc bison clang-7 ca-certificates curl dkms flex \\
    gnupg2 gcc jq libc6-dev libssl-dev llvm-7 netcat patchelf xz-utils zstd \\
    && rm -rf /var/lib/apt/lists/*
RUN rm -rf /usr/bin/gcc && ln -s /usr/bin/gcc-5 /usr/bin/gcc
RUN curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add -
COPY docker/driver-loader-buster/docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);   // apt version pinning
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);   // no HEALTHCHECK
  });

  it('falco wolfi: privileged runtime flags do not suppress static checks', () => {
    const v = lintContent(`FROM cgr.dev/chainguard/wolfi-base
RUN apk update && apk add curl ca-certificates
CMD ["/usr/bin/falco"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);   // untagged
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);   // apk pinning
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });

  it('falco debian-slim: proper cleanup with rm -rf /var/lib/apt/lists/*', () => {
    const v = lintContent(`FROM debian:12-slim
RUN apt-get -y update && apt-get -y install curl jq \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/usr/bin/falco"]
`);
    // Cleanup present, but still triggers apt pinning and no USER
    expect(v.some(v => v.rule === 'DL3009')).toBe(false);  // apt lists cleaned
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);   // no USER
  });
});
// This file will be appended to tests/rules/oss-scan.test.ts

// ── anchore/grype patterns ─────────────────────────────────────────────

describe('OSS: anchore/grype patterns', () => {
  it('Dockerfile: distroless base with :latest tag, scratch final, good labels', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12:latest AS build

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /tmp
COPY grype /

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=\$BUILD_DATE
LABEL org.opencontainers.image.title="grype"
LABEL org.opencontainers.image.description="A vulnerability scanner for container images and filesystems"
LABEL org.opencontainers.image.source=\$VCS_URL
LABEL org.opencontainers.image.revision=\$VCS_REF
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.version=\$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/grype"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);   // :latest tag
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK (multi-stage)
  });

  it('Dockerfile.debug: distroless debug-nonroot, single-stage', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12:debug-nonroot
WORKDIR /tmp
COPY grype /

ARG BUILD_DATE
ARG BUILD_VERSION
LABEL org.opencontainers.image.created=\$BUILD_DATE
LABEL org.opencontainers.image.title="grype"

ENTRYPOINT ["/grype"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DL3007')).toBe(false);   // not :latest
  });

  it('Dockerfile.nonroot: distroless nonroot variant', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /tmp
COPY grype /
ENTRYPOINT ["/grype"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);   // no USER needed for distroless
  });

  it('test-fixtures: FROM scratch with ADD (should use COPY)', () => {
    const v = lintContent(`FROM scratch
ADD package.json /
ADD target /target
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // ADD for local files
  });

  it('test-fixtures: image-alpine-match-coverage — untagged FROM + COPY . .', () => {
    const v = lintContent(`FROM cgr.dev/chainguard/go AS builder

FROM scratch
COPY . .
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);    // untagged image
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY missing --chown or context
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
  });

  it('test-fixtures: openjdk with wget (no version pin)', () => {
    const v = lintContent(`FROM openjdk:15-slim-buster@sha256:1e069bf1c5c23adde58b29b82281b862e473d698ce7cc4e164194a0a2a1c044a
COPY app.java /
ENV PATH="/app/bin:\${PATH}"
WORKDIR /
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV5001')).toBe(true);    // deprecated base image
  });

  it('test-fixtures: rust-auditable with :latest', () => {
    const v = lintContent(`FROM docker.io/tofay/hello-rust-auditable:latest
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // :latest
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
  });

  it('test-fixtures: centos-match-coverage — scratch + COPY . .', () => {
    const v = lintContent(`FROM scratch
COPY . .
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // missing CMD/ENTRYPOINT
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // missing EXPOSE
  });

  it('test-fixtures: node-subprocess with deprecated node:16', () => {
    const v = lintContent(`FROM node:16-stretch@sha256:5810de52349af302a2c5dddf0a3f31174ef65d0eed8985959a5e83bb1084b79b
COPY app.js /
ENV PATH="/app/bin:\${PATH}"
WORKDIR /
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV5001')).toBe(true);    // deprecated base
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // EOL OS
  });

  it('test-fixtures: debian-match-coverage multi-stage with CGO_ENABLED=0', () => {
    const v = lintContent(`FROM docker.io/golang:1.16@sha256:92ccbb6513249c08e582ca3eafc5c9176dbc5cbfe73af245542c5c78250e9b49
WORKDIR /go/src/github.com/anchore/test/
COPY golang/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o go-app .

FROM scratch
COPY --from=0 /go/src/github.com/anchore/test/go-app ./
COPY . .
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY . .
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // no CMD/ENTRYPOINT
  });
});

// ── aquasecurity/kube-bench patterns ───────────────────────────────────

describe('OSS: aquasecurity/kube-bench patterns', () => {
  it('Dockerfile: multi-stage golang + alpine with many anti-patterns', () => {
    const v = lintContent(`FROM golang:1.26.0 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
COPY makefile makefile
COPY go.mod go.sum ./
COPY main.go .
COPY check/ check/
COPY cmd/ cmd/
COPY internal/ internal/
ARG KUBEBENCH_VERSION
RUN make build && cp kube-bench /go/bin/kube-bench

ARG KUBECTL_VERSION TARGETARCH
RUN wget -O /usr/local/bin/kubectl "https://dl.k8s.io/release/v\${KUBECTL_VERSION}/bin/linux/\${TARGETARCH}/kubectl"
RUN wget -O kubectl.sha256 "https://dl.k8s.io/release/v\${KUBECTL_VERSION}/bin/linux/\${TARGETARCH}/kubectl.sha256"
RUN /bin/bash -c 'echo "\$(<kubectl.sha256)  /usr/local/bin/kubectl" | sha256sum -c -'
RUN chmod +x /usr/local/bin/kubectl

FROM alpine:3.23.3 AS run
WORKDIR /opt/kube-bench/
RUN apk --no-cache add procps findutils
RUN apk --no-cache upgrade apk-tools
RUN apk update && apk upgrade && apk --no-cache add openssl
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub
RUN apk add gcompat
RUN apk add jq
RUN apk add bash

ENV PATH=\$PATH:/usr/local/mount-from-host/bin:/go/bin

COPY --from=build /go/bin/kube-bench /usr/local/bin/kube-bench
COPY --from=build /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY entrypoint.sh .
COPY cfg/ cfg/
COPY helper_scripts/check_files_owner_in_dir.sh /go/bin/
RUN chmod a+x /go/bin/check_files_owner_in_dir.sh
ENTRYPOINT ["./entrypoint.sh"]
CMD ["install"]
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // apk upgrade
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk --no-cache missing
    expect(v.some(v => v.rule === 'DL3019')).toBe(true);    // apk add + upgrade in same layer
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);    // wget without checksum
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // LABEL maintainer
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
  });

  it('Dockerfile.ubi: UBI minimal with yum + microdnf mix', () => {
    const v = lintContent(`FROM golang:1.26.0 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
COPY go.mod go.sum ./
COPY main.go .
RUN make build && cp kube-bench /go/bin/kube-bench

ARG KUBECTL_VERSION TARGETARCH
RUN wget -O /usr/local/bin/kubectl "https://dl.k8s.io/release/v\${KUBECTL_VERSION}/bin/linux/\${TARGETARCH}/kubectl"
RUN chmod +x /usr/local/bin/kubectl

FROM registry.access.redhat.com/ubi9/ubi-minimal as run

RUN microdnf install -y yum findutils openssl \\
  && yum -y update-minimal --security --sec-severity=Moderate --sec-severity=Important --sec-severity=Critical \\
  && yum update -y \\
  && yum install -y glibc \\
  && yum install -y procps \\
  && yum install jq -y \\
  && yum clean all \\
  && microdnf remove yum || rpm -e -v yum \\
  && microdnf clean all

WORKDIR /opt/kube-bench/

ENV PATH=\$PATH:/usr/local/mount-from-host/bin

COPY --from=build /go/bin/kube-bench /usr/local/bin/kube-bench
COPY --from=build /usr/local/bin/kubectl /usr/local/bin/kubectl
COPY entrypoint.sh .
COPY cfg/ cfg/
ENTRYPOINT ["./entrypoint.sh"]
CMD ["install"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);    // untagged FROM alias
    expect(v.some(v => v.rule === 'DL3033')).toBe(true);    // yum install without version
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);    // wget without --progress
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
  });

  it('Dockerfile.fips.ubi: FIPS build with UBI base', () => {
    const v = lintContent(`FROM golang:1.26.0 AS build
WORKDIR /go/src/github.com/aquasecurity/kube-bench/
COPY go.mod go.sum ./
COPY main.go .
RUN make build-fips && cp kube-bench /go/bin/kube-bench

FROM registry.access.redhat.com/ubi9/ubi-minimal as run

RUN microdnf install -y yum findutils openssl \\
  && yum -y update-minimal --security \\
  && yum install -y glibc procps jq \\
  && yum clean all \\
  && microdnf clean all

WORKDIR /opt/kube-bench/

COPY --from=build /go/bin/kube-bench /usr/local/bin/kube-bench
COPY entrypoint.sh .
COPY cfg/ cfg/
ENTRYPOINT ["./entrypoint.sh"]
CMD ["install"]
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);    // untagged alias
    expect(v.some(v => v.rule === 'DL3033')).toBe(true);    // yum without version
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // no HEALTHCHECK
  });
});

// ── projectdiscovery/nuclei patterns ───────────────────────────────────

describe('OSS: projectdiscovery/nuclei patterns', () => {
  it('Dockerfile: golang-alpine builder + alpine:latest runtime', () => {
    const v = lintContent(`FROM golang:1.24-alpine AS builder

RUN apk add build-base
WORKDIR /app
COPY . /app
RUN make verify
RUN make build

FROM alpine:latest

RUN apk add --no-cache bind-tools chromium ca-certificates
COPY --from=builder /app/bin/nuclei /usr/local/bin/

ENTRYPOINT ["nuclei"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // alpine:latest
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk add without --no-cache (builder)
    expect(v.some(v => v.rule === 'DL3019')).toBe(true);    // apk add in separate layer
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // installing browser in container
  });

  it('Dockerfile.goreleaser: alpine:latest with labels', () => {
    const v = lintContent(`FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Nuclei is a fast, customizable vulnerability scanner"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="nuclei"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/nuclei"

RUN apk add --no-cache bind-tools chromium ca-certificates
COPY nuclei /usr/local/bin/

ENTRYPOINT ["nuclei"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // :latest
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk version pin
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // chromium in container
  });
});

// ── snyk/cli patterns ──────────────────────────────────────────────────

describe('OSS: snyk/cli patterns', () => {
  it('.circleci/Dockerfile: massive CI build image with many violations', () => {
    const v = lintContent(`FROM debian:bullseye

ARG NODEVERSION
ARG ARCH
ARG GOVERSION

RUN apt-get update && apt-get install -y --no-install-recommends \\
    ca-certificates \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

RUN GOARCH=\$(echo "\$ARCH" | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') \\
    && curl -fsSL "https://go.dev/dl/go\${GOVERSION}.linux-\${GOARCH}.tar.gz" -o /tmp/go.tar.gz \\
    && tar -C /usr/local -xzf /tmp/go.tar.gz \\
    && rm /tmp/go.tar.gz

ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:\$GOPATH/bin:\$PATH

RUN curl -sL https://deb.nodesource.com/setup_\$(echo \$NODEVERSION | cut -f1 -d '.').x | bash -

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \\
    composer \\
    elixir \\
    git \\
    jq \\
    make \\
    maven \\
    nodejs=\$(apt-cache policy nodejs | grep nodesource | xargs | cut -d " " -f2) \\
    python3 \\
    python3-pip \\
    sudo \\
    vim \\
    zip \\
    && apt-get auto-remove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY .circleci/awscli-publickey.pub awscli-publickey.pub
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-\$ARCH.zip" -o "awscliv2.zip"
RUN unzip -q awscliv2.zip
RUN sudo ./aws/install

RUN useradd circleci --create-home
RUN echo "circleci ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER circleci

RUN curl -s "https://get.sdkman.io" | bash
RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

WORKDIR /
ENTRYPOINT [""]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // apt pin versions
    expect(v.some(v => v.rule === 'DL3004')).toBe(true);    // sudo usage
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // apt --no-install-recommends
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV3011')).toBe(true);    // curl pipe bash
    expect(v.some(v => v.rule === 'DV4001')).toBe(true);    // too many RUN layers
  });

  it('.circleci/Dockerfile.scratch-e2e: alpine builder + scratch runtime', () => {
    const v = lintContent(`FROM alpine:3 AS BUILDER

ARG CLI_DOWNLOAD_BASE_URL
ARG SNYK_VERSION

RUN apk --no-cache add curl ca-certificates
RUN curl --compressed -sL \\
    "\${CLI_DOWNLOAD_BASE_URL}cli/v\${SNYK_VERSION}/snyk-linux" \\
    -o /usr/local/bin/snyk \\
    && chmod +x /usr/local/bin/snyk

RUN curl -sL \\
    https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox \\
    -o /usr/local/bin/busybox \\
    && chmod +x /usr/local/bin/busybox

FROM scratch
COPY --from=BUILDER /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=BUILDER /usr/local/bin/busybox /bin/busybox
COPY --from=BUILDER /usr/local/bin/snyk /usr/local/bin/snyk
ENV PATH="/usr/local/bin:/bin"
ENTRYPOINT ["/bin/busybox", "sh"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk version pin
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV3019')).toBe(true);    // curl download without checksum
  });

  it('test/fixtures/docker/Dockerfile: minimal FROM scratch', () => {
    const v = lintContent(`FROM scratch
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);   // empty image (no instructions)
  });

  it('test/fixtures/docker/Dockerfile.alpine-3.12.0: pinned alpine', () => {
    const v = lintContent(`FROM alpine:3.12.0
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
  });

  it('proxy/Dockerfile: massive proxy CI image with apt + curl-pipe-bash', () => {
    const v = lintContent(`FROM --platform=\$TARGETPLATFORM golang:1.20-bullseye

ARG NODEVERSION
ARG ARCH

RUN curl -sL https://deb.nodesource.com/setup_\$(echo \$NODEVERSION | cut -f1 -d '.').x | bash -
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \\
    sudo \\
    git \\
    vim \\
    make \\
    maven \\
    gradle \\
    curl \\
    gnupg \\
    elixir \\
    composer \\
    jq \\
    python3 \\
    python3-pip \\
    squid \\
    traceroute \\
    net-tools \\
    iptables

RUN apt-get auto-remove -y && apt-get clean -y && rm -rf /var/lib/apt/

ADD .circleci/awscli-publickey.pub awscli-publickey.pub

RUN useradd circleci --create-home
RUN echo "circleci ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN mkdir -p /app
COPY . /app
RUN chmod 777 /app && chown -R circleci /app

USER circleci

RUN cd /app && npm install

RUN curl -s "https://get.sdkman.io" | bash
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV http_proxy="http://localhost:3128"
ENV https_proxy="http://localhost:3128"

WORKDIR /app
ENTRYPOINT ["/bin/entrypoint.sh"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // apt version pin
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // apt lists not cleaned properly
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // --no-install-recommends
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // ADD for local file
    expect(v.some(v => v.rule === 'DV3023')).toBe(true);    // curl pipe shell
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // layer count
  });

  it('squid_environment/Dockerfile: debian slim with build tools', () => {
    const v = lintContent(`FROM debian:bullseye-slim

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \\
    && apt-get -y install --no-install-recommends \\
    build-essential \\
    krb5-user krb5-kdc krb5-admin-server krb5-multidev libkrb5-dev \\
    curl openssl ca-certificates \\
    squid \\
    && mkdir -p /etc/cliv2/bin && touch /etc/cliv2/bin/snyk

ENTRYPOINT [ "/etc/cliv2/scripts/setup.sh" ]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // missing HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // build-essential in runtime
  });
});

// ── anchore/syft patterns ──────────────────────────────────────────────

describe('OSS: anchore/syft patterns', () => {
  it('Dockerfile: distroless + scratch with :latest and good labels', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12:latest AS build

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
WORKDIR /tmp
COPY syft /

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=\$BUILD_DATE
LABEL org.opencontainers.image.title="syft"
LABEL org.opencontainers.image.description="CLI tool and library for generating SBOM"
LABEL org.opencontainers.image.source=\$VCS_URL
LABEL org.opencontainers.image.revision=\$VCS_REF
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.version=\$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/syft"]
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // :latest
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
  });

  it('Dockerfile.debug: distroless debug-nonroot with explicit USER', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12:debug-nonroot
WORKDIR /tmp
COPY syft /
USER nonroot
ENTRYPOINT ["/syft"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);   // has USER
  });

  it('Dockerfile.nonroot: distroless nonroot with USER instruction', () => {
    const v = lintContent(`FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /tmp
COPY syft /
USER nonroot
ENTRYPOINT ["/syft"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
    expect(v.some(v => v.rule === 'DV1006')).toBe(false);
  });

  it('test-fixtures: busybox with digest pin, no USER', () => {
    const v = lintContent(`FROM busybox:1.31.1@sha256:95cf004f559831017cdf4628aaf1bb30133677be8702a8c5f2994629f637a209

`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DL3006')).toBe(false);   // pinned with tag+digest
  });

  it('test-fixtures: golang multi-stage cross-compile (elf/win/macos)', () => {
    const v = lintContent(`FROM golang:1.21.1@sha256:cffaba795c36f07e372c7191b35ceaae114d74c31c3763d442982e3a4df3b39e as builder
WORKDIR /app
COPY go.sum go.mod app.go ./

RUN GOOS=linux go build -o elf .
RUN GOOS=windows go build -o win .
RUN GOOS=darwin go build -o macos .

FROM scratch

WORKDIR /tmp
COPY --from=builder /app/elf /
COPY --from=builder /app/win /
COPY --from=builder /app/macos /

ENTRYPOINT ["/elf"]
`);
    expect(v.some(v => v.rule === 'DV4012')).toBe(true);    // multiple RUN in builder
    expect(v.some(v => v.rule === 'DV5001')).toBe(true);    // deprecated golang version
  });

  it('test-fixtures: --platform=linux/amd64 golang-alpine, scratch final', () => {
    const v = lintContent(`FROM --platform=linux/amd64 golang:1.18.10-alpine

FROM scratch

COPY --from=0 /usr/local/go/bin/gofmt bin/gofmt
`);
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform hardcoded
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY relative path
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
  });

  it('test-fixtures: dotnet multi-stage with --platform and busybox', () => {
    const v = lintContent(`FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:7d3a75ca5c8ac4679908ef7a2591b9bc257c62bd530167de32bba105148bb7be AS build
ARG RUNTIME=win-x64
WORKDIR /src

COPY src/*.csproj .
COPY src/packages.lock.json .
RUN dotnet restore -r \$RUNTIME --verbosity normal --locked-mode

COPY src/ .
RUN dotnet publish -r \$RUNTIME --self-contained --no-restore -o /app

FROM busybox
WORKDIR /app
COPY --from=build /app .
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);    // busybox untagged
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform hardcoded
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV4012')).toBe(true);    // multiple stages
  });

  it('test-fixtures: dotnet with runtime base and ENTRYPOINT', () => {
    const v = lintContent(`FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:7d3a75ca5c8ac4679908ef7a2591b9bc257c62bd530167de32bba105148bb7be AS build
ARG RUNTIME=win-x64
WORKDIR /src
COPY src/*.csproj .
RUN dotnet restore -r \$RUNTIME --verbosity normal --locked-mode
COPY src/ .
RUN dotnet publish -r \$RUNTIME --no-restore -o /app

FROM --platform=linux/amd64 mcr.microsoft.com/dotnet/runtime:8.0@sha256:a6fc92280fbf2149cd6846d39c5bf7b9b535184e470aa68ef2847b9a02f6b99e
WORKDIR /app
COPY --from=build /app .
ENTRYPOINT ["dotnet", "dotnetapp.dll"]
`);
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform hardcoded
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
  });

  it('test-fixtures: dotnet compile target with busybox:latest', () => {
    const v = lintContent(`FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine@sha256:3f93439f47fea888d94e6e228d0d0de841f4122ef46f8bfd04f8bd78cbce7ddb AS build
ARG RUNTIME=win-x64
WORKDIR /src

COPY src/helloworld.csproj .
RUN dotnet restore -r \$RUNTIME

COPY src/*.cs .
RUN dotnet publish -c Release -r \$RUNTIME --self-contained false -o /app

FROM busybox:latest

WORKDIR /app
COPY --from=build /app .
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // :latest
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);
  });

  it('test-fixtures: golang builder with upx compression, alpine + scratch', () => {
    const v = lintContent(`FROM --platform=linux/amd64 golang:1.23.2-alpine AS builder

RUN apk add --no-cache upx

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY main.go main.go

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.Version=1.0.0" -o run-me .
RUN upx --best --lzma --exact run-me

FROM scratch

COPY --from=builder /app/run-me /run-me
ENTRYPOINT ["/run-me"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk version pin
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform hardcoded
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
  });

  it('test-fixtures: jenkins war extract + scratch final', () => {
    const v = lintContent(`FROM jenkins/jenkins:2.346.3-slim-jdk17@sha256:028fbbd9112c60ed086f5197fcba71992317864d27644e5949cf9c52ff4b65f0 AS base

USER root

WORKDIR /usr/share/jenkins

RUN mkdir tmp
WORKDIR /usr/share/jenkins/tmp

RUN apt-get update 2>&1 > /dev/null && apt-get install -y less zip 2>&1 > /dev/null

RUN unzip ../jenkins.war 2>&1 > /dev/null
RUN rm -rf ./META-INF/MANIFEST.MF ./WEB-INF ./jsbundles ./scripts ./css

WORKDIR /usr/share/jenkins
RUN rm -rf jenkins.war
RUN cd ./tmp && zip -r ../jenkins.war . && cd ..
RUN rm -rf ./tmp

FROM scratch
COPY --from=base /usr/share/jenkins/jenkins.war /jenkins.war
`);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);    // cd instead of WORKDIR
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // apt version pin
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // apt lists
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // --no-install-recommends
  });

  it('test-fixtures: alpine base with wget and pip for java virtualpath', () => {
    const v = lintContent(`FROM alpine:3.18.3@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a AS base

RUN wget https://repo1.maven.org/maven2/org/jvnet/hudson/main/hudson-war/2.2.1/hudson-war-2.2.1.war
RUN mv hudson-war-2.2.1.war hudson.war

RUN apk add --no-cache python3 py3-pip
COPY extract.py /extract.py
RUN python extract.py

FROM scratch
COPY --from=base /slim /
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk version pin
    expect(v.some(v => v.rule === 'DL3047')).toBe(true);    // wget without --progress
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // pip in container
  });

  it('test-fixtures: fedora kernel modules extraction', () => {
    const v = lintContent(`FROM fedora:37@sha256:3f987b7657e944cf87a129cc262982d4f80e38bd98f7db313ccaf90ca7069dd2

RUN dnf install 'dnf-command(download)' cpio xz -y
RUN dnf download kernel-core-6.0.7-301.fc37 kernel-modules-6.0.7-301.fc37 -y

RUN rpm2cpio kernel-core-*.rpm | cpio -t && \\
    rpm2cpio kernel-core-*.rpm | cpio -idmv ./lib/modules/6.0.7-301.fc37.x86_64/vmlinuz

RUN rpm2cpio kernel-modules-*.rpm | cpio -t && \\
    rpm2cpio kernel-modules-*.rpm | cpio -idmv ./lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko.xz

RUN unxz /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko.xz

FROM scratch

COPY --from=0 /lib/modules/6.0.7-301.fc37.x86_64/vmlinuz /lib/modules/6.0.7-301.fc37.x86_64/vmlinuz
COPY --from=0 /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko /lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko
`);
    expect(v.some(v => v.rule === 'DL3040')).toBe(true);    // dnf install without version
    expect(v.some(v => v.rule === 'DL3041')).toBe(true);    // dnf clean all missing
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // too many layers
  });

  it('test-fixtures: nix builder with scratch final', () => {
    const v = lintContent(`FROM --platform=linux/amd64 nixos/nix:2.28.2@sha256:4215204b5f65c7b756b26a6dd47a6af77f1d906e5edf62b184c95420a7dfa08f AS builder

RUN mkdir -p /etc/nix && \\
    echo 'filter-syscalls = false' > /etc/nix/nix.conf && \\
    echo 'experimental-features = nix-command flakes' >> /etc/nix/nix.conf

RUN mkdir -p /root/nix && \\
    echo 'import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/46688f8eb5.tar.gz") {}' > /root/nix/pinned-nixpkgs.nix

RUN nix-env -f /root/nix/pinned-nixpkgs.nix -iA jq

RUN mkdir -p /nix-minimal && \\
    for dep in \$(nix-store -q --requisites \$(which jq)); do \\
        mkdir -p /nix-minimal\$(dirname \$dep) && \\
        cp -a \$dep /nix-minimal\$dep; \\
    done

FROM scratch
COPY --from=builder /nix-minimal/nix/store /nix/store
`);
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform hardcoded
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // many layers
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // nixos in container
  });

  it('test-fixtures: php apache builder with unpinned apt packages', () => {
    const v = lintContent(`FROM --platform=linux/amd64 httpd:2.4.63-bookworm AS builder

RUN apt update -y && apt install -y libapache2-mod-php php8.2-memcache php8.2-memcache php8.2-xml php8.2-mysqli php8.2-opcache

FROM busybox:latest

COPY --from=builder /usr/lib/apache2/ /usr/lib/apache2/
COPY --from=builder /usr/lib/php/ /usr/lib/php/
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // busybox:latest
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // apt version pin
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // apt lists
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // --no-install-recommends
    expect(v.some(v => v.rule === 'DL3027')).toBe(true);    // apt vs apt-get
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
  });

  it('test-fixtures: rust auditable build + scratch', () => {
    const v = lintContent(`FROM rust:1.82.0 AS builder

WORKDIR /app

RUN cargo install cargo-auditable --version 0.6.4 --locked
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch
RUN cargo auditable build --release

FROM scratch

COPY --from=builder /app/target/release/hello_world /usr/local/bin/hello_world
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // no HEALTHCHECK
    expect(v.some(v => v.rule === 'DV1005')).toBe(false);   // has COPY (implicit command)
  });

  it('test-fixtures: python multi-site-package with many apt + pip installs', () => {
    const v = lintContent(`FROM ubuntu:20.04@sha256:cc9cc8169c9517ae035cf293b15f06922cb8c6c864d625a72b7b18667f264b70 AS base

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3.8 python3.9 python3-pip python3-venv
RUN python3.8 -m pip install --upgrade pip virtualenv==20.31.2
RUN python3.9 -m pip install --upgrade pip virtualenv==20.31.2
RUN python3.9 -m pip install click==8.0.3 beautifulsoup4==4.9.3
RUN python3.8 -m pip install click==8.0.2 beautifulsoup4==4.9.2

RUN mkdir -p /app/project1 /app/project2

WORKDIR /app/project1
RUN python3.9 -m venv --system-site-packages venv
RUN /app/project1/venv/bin/pip install pyyaml==5.4.1

WORKDIR /app/project2
RUN python3.8 -m venv venv
RUN /app/project2/venv/bin/pip install click==8.0.3

FROM scratch
COPY --from=base /app/ /app/
COPY --from=base /usr/local/lib/python3.8/ /usr/local/lib/python3.8/
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // apt version pin
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);    // pip version pin
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);    // pip cache
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // too many layers
    expect(v.some(v => v.rule === 'DV5001')).toBe(true);    // deprecated base (ubuntu 20.04)
  });

  it('test-fixtures: rockylinux with ADD and remove script', () => {
    const v = lintContent(`FROM rockylinux:9.3.20231119@sha256:1097437745db73ba839d60b9b9b96e6648e62751519a1319bfccc849f6a3f74c

ADD remove.sh /remove.sh
RUN /remove.sh

FROM scratch
COPY --from=0 / /
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // ADD for local file
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // COPY / from stage
  });

  it('test-fixtures: php-fpm-alpine with complex apk + pecl build', () => {
    const v = lintContent(`FROM --platform=linux/amd64 php:8.3.27-fpm-alpine3.21 AS builder

RUN set -ex; \\
    apk add --no-cache \\
    imagemagick \\
    rsync

RUN set -ex; \\
    apk add --no-cache --virtual .build-deps \\
    \$PHPIZE_DEPS \\
    autoconf \\
    freetype-dev \\
    icu-dev \\
    libpng-dev \\
    libzip-dev \\
    postgresql-dev

FROM busybox:latest

COPY --from=builder /usr/local/sbin/php-fpm /usr/local/sbin/php-fpm
COPY --from=builder /usr/local/bin/php /usr/local/bin/php
COPY --from=builder /usr/local/lib/php/extensions /usr/local/lib/php/extensions
`);
    expect(v.some(v => v.rule === 'DL3007')).toBe(true);    // busybox:latest
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // apk version pin
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // --platform
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // no USER
  });
});

// ── netdata/netdata patterns ──

describe('OSS: netdata/netdata patterns', () => {
  it('.github/dockerfiles/Dockerfile.build_test: 6 rules (DL3006, DV1005, DV1006, DV1008, DV4003, DV4005)', () => {
    const v = lintContent(`# The default value is overridden in every Dockerfile usage, but adding it here helps avoid issues with
# CI checks that require a non-empty or valid base image name. See more details here:
# https://docs.docker.com/go/dockerfile/rule/invalid-default-arg-in-from/
ARG BASE="netdata"

FROM \${BASE}

ARG PRE
ENV PRE=\${PRE}
ARG RMJSONC
ENV RMJSONC=\${RMJSONC}
ENV DISABLE_TELEMETRY=1
ENV GITHUB_ACTIONS=true

RUN echo "\${PRE}" > /prep-cmd.sh && \\
    echo "\${RMJSONC}" > /rmjsonc.sh && chmod +x /rmjsonc.sh && \\
    /bin/sh /prep-cmd.sh

COPY . /netdata

RUN /netdata/packaging/installer/install-required-packages.sh --dont-wait --non-interactive netdata
`);
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);    // Always tag the version of an image explicitly. Tag
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('.github/dockerfiles/Dockerfile.clang: 13 rules (DL3008, DL3009, DL3015, DV1004, DV1005, DV1006, ...)', () => {
    const v = lintContent(`FROM debian:12 AS build

# Disable apt/dpkg interactive mode
ENV DEBIAN_FRONTEND=noninteractive

# Install all build dependencies
COPY packaging/installer/install-required-packages.sh /tmp/install-required-packages.sh
RUN /tmp/install-required-packages.sh --dont-wait --non-interactive netdata-all

# Install Clang and set as default CC
RUN apt-get install -y clang && \\
    update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100 && \\
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100

WORKDIR /netdata
COPY . .

# Build Netdata
RUN ./netdata-installer.sh --dont-wait --dont-start-it --disable-go
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // Delete the apt-get lists after installing somethin
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);    // Consider using multi-stage builds to reduce final 
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1007')).toBe(true);    // apt-get cache not cleaned. Add `rm -rf /var/lib/ap
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "debian" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);    // DEBIAN_FRONTEND=noninteractive is set as ENV. Use 
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/base-debian12" i
  });

  it('Dockerfile: 8 rules (DV1005, DV1006, DV1008, DV1009, DV3013, DV4003, ...)', () => {
    const v = lintContent(`# SPDX-License-Identifier: GPL-3.0-or-later

# This image contains preinstalled dependencies
# hadolint ignore=DL3007
FROM netdata/builder:v3 AS builder

# One of 'nightly' or 'stable'
ARG RELEASE_CHANNEL=nightly

ARG CFLAGS

ENV CFLAGS=$CFLAGS

ARG EXTRA_INSTALL_OPTS

ENV EXTRA_INSTALL_OPTS=$EXTRA_INSTALL_OPTS

ARG DEBUG_BUILD

ENV DEBUG_BUILD=$DEBUG_BUILD

ARG BUILD_ARCH

ENV BUILD_ARCH=$BUILD_ARCH

# Copy source
COPY . /opt/netdata.git
WORKDIR /opt/netdata.git

# Install from source
RUN chmod +x netdata-installer.sh && \\
   cp -rp /deps/* /usr/local/ && \\
   BUILD_ARCH="\${BUILD_ARCH:-"$(uname -m)"}" && \\
   /bin/echo -e "INSTALL_TYPE='oci'\\nPREBUILT_ARCH='\${BUILD_ARCH}'" > ./system/.install-type && \\
   CFLAGS="$(packaging/docker/gen-cflags.sh)" LDFLAGS="-Wl,--gc-sections" ./netdata-installer.sh --dont-wait --dont-start-it \\
   --use-system-protobuf \\
   --disable-ebpf \\
   --enable-plugin-otel \\
   --enable-plugin-otel-signal-viewer \\
   --internal-systemd-journal \\
   \${EXTRA_INSTALL_OPTS} \\
   --install-no-prefix / \\
   "$([ "$RELEASE_CHANNEL" = stable ] && echo --stable-channel)"

# files to one directory
RUN mkdir -p /app/usr/sbin/ \\
             /app/usr/share \\
             /app/usr/libexec \\
             /app/usr/local \\
             /app/usr/lib \\
             /app/var/cache \\
             /app/var/lib \\
             /app/etc && \\
    mv /usr/share/netdata   /app/usr/share/ && \\
    mv /usr/libexec/netdata /app/usr/libexec/ && \\
    mv /usr/lib/netdata     /app/usr/lib/ && \\
    mv /var/cache/netdata   /app/var/cache/ && \\
    mv /var/lib/netdata     /app/var/lib/ && \\
    mv /etc/netdata         /app/etc/ && \\
    mv /usr/sbin/netdata    /app/usr/sbin/ && \\
    mv /usr/sbin/netdatacli    /app/usr/sbin/ && \\
    mv /usr/sbin/nd-run    /app/usr/sbin/ && \\
    mv /usr/sbin/systemd-cat-native /app/usr/sbin/ && \\
    mv packaging/docker/run.sh        /app/usr/sbin/ && \\
    mv packaging/docker/health.sh     /app/usr/sbin/ && \\
    mkdir -p /deps/etc && \\
    cp -rp /deps/etc /app/usr/local/etc && \\
    chmod -R o+rX /app && \\
    chmod +x /app/usr/sbin/run.sh

#####################################################################
# This image contains preinstalled dependencies
# hadolint ignore=DL3007
FROM netdata/base:v3 AS base

ARG BUILD_DATE
ARG BUILD_VERSION
LABEL org.opencontainers.image.authors="Netdatabot <bot@netdata.cloud>"
LABEL org.opencontainers.image.url="https://netdata.cloud"
LABEL org.opencontainers.image.documentation="https://learn.netdata.cloud"
LABEL org.opencontainers.image.source="https://github.com/netdata/netdata"
LABEL org.opencontainers.image.title="Netdata Agent"
LABEL org.opencontainers.image.description="Official Netdata Agent Docker Image"
LABEL org.opencontainers.image.vendor="Netdata Inc."
LABEL org.opencontainers.image.created=\${BUILD_DATE}
LABEL org.opencontainers.image.version=\${BUILD_VERSION}

ARG OFFICIAL_IMAGE=false
ENV NETDATA_OFFICIAL_IMAGE=$OFFICIAL_IMAGE

ONBUILD ENV NETDATA_OFFICIAL_IMAGE=false

ARG NETDATA_UID=201
ARG NETDATA_GID=201
ENV DOCKER_GRP=netdata
ENV DOCKER_USR=netdata
# If DISABLE_TELEMETRY is set, it will disable anonymous stats collection and reporting
#ENV DISABLE_TELEMETRY=1
ENV NETDATA_LISTENER_PORT=19999
EXPOSE $NETDATA_LISTENER_PORT

ENV NETDATA_EXTRA_DEB_PACKAGES=""

RUN mkdir -p /opt/src /var/log/netdata && \\
    ln -sf /dev/stdout /var/log/netdata/access.log && \\
    ln -sf /dev/stdout /var/log/netdata/aclk.log && \\
    ln -sf /dev/stdout /var/log/netdata/debug.log && \\
    ln -sf /dev/stderr /var/log/netdata/error.log && \\
    ln -sf /dev/stderr /var/log/netdata/daemon.log && \\
    ln -sf /dev/stdout /var/log/netdata/collector.log && \\
    ln -sf /dev/stdout /var/log/netdata/health.log

COPY --from=builder /app /

# Create netdata user and apply the permissions as described in
# https://docs.netdata.cloud/docs/netdata-security/#netdata-directories, but own everything by root group due to https://github.com/netdata/netdata/pull/6543
# hadolint ignore=DL3013
RUN addgroup --gid \${NETDATA_GID} --system "\${DOCKER_GRP}" && \\
    adduser --system --no-create-home --shell /usr/sbin/nologin --uid \${NETDATA_UID} --home /etc/netdata --group "\${DOCKER_USR}" && \\
    chown -R root:root \\
        /etc/netdata \\
        /usr/share/netdata \\
        /usr/libexec/netdata && \\
    chown -R netdata:root \\
        /usr/lib/netdata \\
        /var/cache/netdata \\
        /var/lib/netdata \\
        /var/log/netdata && \\
    chown -R netdata:netdata /var/lib/netdata/cloud.d && \\
    chmod 0700 /var/lib/netdata/cloud.d && \\
    chmod 0755 /usr/libexec/netdata/plugins.d/*.plugin && \\
    for name in cgroup-network \\
                local-listeners \\
                apps.plugin \\
                debugfs.plugin \\
                freeipmi.plugin \\
                go.d.plugin \\
                perf.plugin \\
                ndsudo \\
                slabinfo.plugin \\
                network-viewer.plugin \\
                otel-plugin \\
                otel-signal-viewer-plugin \\
                systemd-journal.plugin; do \\
        [ -f "/usr/libexec/netdata/plugins.d/$name" ] && chmod 4755 "/usr/libexec/netdata/plugins.d/$name"; \\
    done && \\
    # Group write permissions due to: https://github.com/netdata/netdata/pull/6543
    find /var/lib/netdata /var/cache/netdata -type d -exec chmod 0770 {} \\; && \\
    find /var/lib/netdata /var/cache/netdata -type f -exec chmod 0660 {} \\; && \\
    cp -va /etc/netdata /etc/netdata.stock

ENTRYPOINT ["/usr/sbin/run.sh"]

HEALTHCHECK --interval=60s --timeout=10s --retries=3 CMD /usr/sbin/health.sh
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "netdata/builder" with a digest (
    expect(v.some(v => v.rule === 'DV3013')).toBe(true);    // Setting setuid/setgid bit detected. This can enabl
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4004')).toBe(true);    // ARG defined after ENV. Define ARG before ENV for b
    expect(v.some(v => v.rule === 'DV4010')).toBe(true);    // Recursive chown -R increases layer size. Consider 
  });

  it('packaging/docker/Dockerfile: 8 rules (DV1005, DV1006, DV1008, DV1009, DV3013, DV4003, ...)', () => {
    const v = lintContent(`# SPDX-License-Identifier: GPL-3.0-or-later

# This image contains preinstalled dependencies
# hadolint ignore=DL3007
FROM netdata/builder:v3 AS builder

# One of 'nightly' or 'stable'
ARG RELEASE_CHANNEL=nightly

ARG CFLAGS

ENV CFLAGS=$CFLAGS

ARG EXTRA_INSTALL_OPTS

ENV EXTRA_INSTALL_OPTS=$EXTRA_INSTALL_OPTS

ARG DEBUG_BUILD

ENV DEBUG_BUILD=$DEBUG_BUILD

ARG BUILD_ARCH

ENV BUILD_ARCH=$BUILD_ARCH

# Copy source
COPY . /opt/netdata.git
WORKDIR /opt/netdata.git

# Install from source
RUN chmod +x netdata-installer.sh && \\
   cp -rp /deps/* /usr/local/ && \\
   BUILD_ARCH="\${BUILD_ARCH:-"$(uname -m)"}" && \\
   /bin/echo -e "INSTALL_TYPE='oci'\\nPREBUILT_ARCH='\${BUILD_ARCH}'" > ./system/.install-type && \\
   CFLAGS="$(packaging/docker/gen-cflags.sh)" LDFLAGS="-Wl,--gc-sections" ./netdata-installer.sh --dont-wait --dont-start-it \\
   --use-system-protobuf \\
   --disable-ebpf \\
   --enable-plugin-otel \\
   --enable-plugin-otel-signal-viewer \\
   --internal-systemd-journal \\
   \${EXTRA_INSTALL_OPTS} \\
   --install-no-prefix / \\
   "$([ "$RELEASE_CHANNEL" = stable ] && echo --stable-channel)"

# files to one directory
RUN mkdir -p /app/usr/sbin/ \\
             /app/usr/share \\
             /app/usr/libexec \\
             /app/usr/local \\
             /app/usr/lib \\
             /app/var/cache \\
             /app/var/lib \\
             /app/etc && \\
    mv /usr/share/netdata   /app/usr/share/ && \\
    mv /usr/libexec/netdata /app/usr/libexec/ && \\
    mv /usr/lib/netdata     /app/usr/lib/ && \\
    mv /var/cache/netdata   /app/var/cache/ && \\
    mv /var/lib/netdata     /app/var/lib/ && \\
    mv /etc/netdata         /app/etc/ && \\
    mv /usr/sbin/netdata    /app/usr/sbin/ && \\
    mv /usr/sbin/netdatacli    /app/usr/sbin/ && \\
    mv /usr/sbin/nd-run    /app/usr/sbin/ && \\
    mv /usr/sbin/systemd-cat-native /app/usr/sbin/ && \\
    mv packaging/docker/run.sh        /app/usr/sbin/ && \\
    mv packaging/docker/health.sh     /app/usr/sbin/ && \\
    mkdir -p /deps/etc && \\
    cp -rp /deps/etc /app/usr/local/etc && \\
    chmod -R o+rX /app && \\
    chmod +x /app/usr/sbin/run.sh

#####################################################################
# This image contains preinstalled dependencies
# hadolint ignore=DL3007
FROM netdata/base:v3 AS base

ARG BUILD_DATE
ARG BUILD_VERSION
LABEL org.opencontainers.image.authors="Netdatabot <bot@netdata.cloud>"
LABEL org.opencontainers.image.url="https://netdata.cloud"
LABEL org.opencontainers.image.documentation="https://learn.netdata.cloud"
LABEL org.opencontainers.image.source="https://github.com/netdata/netdata"
LABEL org.opencontainers.image.title="Netdata Agent"
LABEL org.opencontainers.image.description="Official Netdata Agent Docker Image"
LABEL org.opencontainers.image.vendor="Netdata Inc."
LABEL org.opencontainers.image.created=\${BUILD_DATE}
LABEL org.opencontainers.image.version=\${BUILD_VERSION}

ARG OFFICIAL_IMAGE=false
ENV NETDATA_OFFICIAL_IMAGE=$OFFICIAL_IMAGE

ONBUILD ENV NETDATA_OFFICIAL_IMAGE=false

ARG NETDATA_UID=201
ARG NETDATA_GID=201
ENV DOCKER_GRP=netdata
ENV DOCKER_USR=netdata
# If DISABLE_TELEMETRY is set, it will disable anonymous stats collection and reporting
#ENV DISABLE_TELEMETRY=1
ENV NETDATA_LISTENER_PORT=19999
EXPOSE $NETDATA_LISTENER_PORT

ENV NETDATA_EXTRA_DEB_PACKAGES=""

RUN mkdir -p /opt/src /var/log/netdata && \\
    ln -sf /dev/stdout /var/log/netdata/access.log && \\
    ln -sf /dev/stdout /var/log/netdata/aclk.log && \\
    ln -sf /dev/stdout /var/log/netdata/debug.log && \\
    ln -sf /dev/stderr /var/log/netdata/error.log && \\
    ln -sf /dev/stderr /var/log/netdata/daemon.log && \\
    ln -sf /dev/stdout /var/log/netdata/collector.log && \\
    ln -sf /dev/stdout /var/log/netdata/health.log

COPY --from=builder /app /

# Create netdata user and apply the permissions as described in
# https://docs.netdata.cloud/docs/netdata-security/#netdata-directories, but own everything by root group due to https://github.com/netdata/netdata/pull/6543
# hadolint ignore=DL3013
RUN addgroup --gid \${NETDATA_GID} --system "\${DOCKER_GRP}" && \\
    adduser --system --no-create-home --shell /usr/sbin/nologin --uid \${NETDATA_UID} --home /etc/netdata --group "\${DOCKER_USR}" && \\
    chown -R root:root \\
        /etc/netdata \\
        /usr/share/netdata \\
        /usr/libexec/netdata && \\
    chown -R netdata:root \\
        /usr/lib/netdata \\
        /var/cache/netdata \\
        /var/lib/netdata \\
        /var/log/netdata && \\
    chown -R netdata:netdata /var/lib/netdata/cloud.d && \\
    chmod 0700 /var/lib/netdata/cloud.d && \\
    chmod 0755 /usr/libexec/netdata/plugins.d/*.plugin && \\
    for name in cgroup-network \\
                local-listeners \\
                apps.plugin \\
                debugfs.plugin \\
                freeipmi.plugin \\
                go.d.plugin \\
                perf.plugin \\
                ndsudo \\
                slabinfo.plugin \\
                network-viewer.plugin \\
                otel-plugin \\
                otel-signal-viewer-plugin \\
                systemd-journal.plugin; do \\
        [ -f "/usr/libexec/netdata/plugins.d/$name" ] && chmod 4755 "/usr/libexec/netdata/plugins.d/$name"; \\
    done && \\
    # Group write permissions due to: https://github.com/netdata/netdata/pull/6543
    find /var/lib/netdata /var/cache/netdata -type d -exec chmod 0770 {} \\; && \\
    find /var/lib/netdata /var/cache/netdata -type f -exec chmod 0660 {} \\; && \\
    cp -va /etc/netdata /etc/netdata.stock

ENTRYPOINT ["/usr/sbin/run.sh"]

HEALTHCHECK --interval=60s --timeout=10s --retries=3 CMD /usr/sbin/health.sh
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "netdata/builder" with a digest (
    expect(v.some(v => v.rule === 'DV3013')).toBe(true);    // Setting setuid/setgid bit detected. This can enabl
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4004')).toBe(true);    // ARG defined after ENV. Define ARG before ENV for b
    expect(v.some(v => v.rule === 'DV4010')).toBe(true);    // Recursive chown -R increases layer size. Consider 
  });

});

// ── VictoriaMetrics/VictoriaMetrics patterns ──

describe('OSS: VictoriaMetrics/VictoriaMetrics patterns', () => {
  it('app/victoria-metrics/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

EXPOSE 8428

ENTRYPOINT ["/victoria-metrics-prod"]
ARG src_binary=non-existing
COPY $src_binary ./victoria-metrics-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/victoria-metrics/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8428
ENTRYPOINT ["/victoria-metrics-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY victoria-metrics-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./victoria-metrics-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmagent/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

EXPOSE 8429

ENTRYPOINT ["/vmagent-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmagent-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmagent/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8429
ENTRYPOINT ["/vmagent-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmagent-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmagent-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmalert-tool/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

EXPOSE 8880

ENTRYPOINT ["/vmalert-tool-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmalert-tool-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmalert-tool/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8429
ENTRYPOINT ["/vmalert-tool-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmalert-tool-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmalert-tool-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmalert/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

EXPOSE 8880

ENTRYPOINT ["/vmalert-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmalert-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmalert/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8880
ENTRYPOINT ["/vmalert-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmalert-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmalert-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmauth/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

EXPOSE 8427

ENTRYPOINT ["/vmauth-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmauth-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmauth/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8427
ENTRYPOINT ["/vmauth-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmauth-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmauth-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmbackup/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

ENTRYPOINT ["/vmbackup-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmbackup-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmbackup/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/vmbackup-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmbackup-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmbackup-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmctl/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

ENTRYPOINT ["/vmctl-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmctl-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmctl/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/vmctl-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmctl-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmctl-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('app/vmrestore/deployment/Dockerfile: 3 rules (DL3045, DL3057, DV1006)', () => {
    const v = lintContent(`ARG base_image=non-existing
FROM $base_image

ENTRYPOINT ["/vmrestore-prod"]
ARG src_binary=non-existing
COPY $src_binary ./vmrestore-prod
`);
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
  });

  it('app/vmrestore/multiarch/Dockerfile: 7 rules (DL3017, DL3018, DL3045, DL3057, DV1006, DV2010, ...)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs
RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/vmrestore-prod"]
ARG TARGETARCH
ARG BINARY_SUFFIX=non-existing
COPY vmrestore-linux-\${TARGETARCH}-prod\${BINARY_SUFFIX} ./vmrestore-prod
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('codespell/Dockerfile: 6 rules (DL3013, DL3042, DL3057, DV1006, DV1009, DV5003)', () => {
    const v = lintContent(`FROM python:3

WORKDIR /opt/node
RUN pip install codespell
WORKDIR /vm
ENTRYPOINT ["codespell"]
`);
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);    // Pin versions in pip. Instead of `pip install codes
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);    // Avoid use of cache directory with pip. Use `pip in
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "python" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/python3-debian12
  });

  it('deployment/docker/base/Dockerfile: 5 rules (DL3017, DL3018, DV1006, DV2010, DV4003)', () => {
    const v = lintContent(`# See https://medium.com/on-docker/use-multi-stage-builds-to-inject-ca-certs-ad1e8f01de1b
ARG certs_image=non-existing
ARG root_image=non-existing
FROM $certs_image AS certs

RUN apk update && apk upgrade && apk --update --no-cache add ca-certificates

FROM $root_image

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
`);
    expect(v.some(v => v.rule === 'DL3017')).toBe(true);    // Do not use apk upgrade. Pin package versions inste
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV2010')).toBe(true);    // Avoid apk upgrade in Dockerfiles. It makes builds 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('deployment/docker/builder/Dockerfile: 9 rules (DL3008, DL3009, DL3015, DL3027, DV1004, DV1006, ...)', () => {
    const v = lintContent(`ARG go_builder_image=non-existing
FROM $go_builder_image
STOPSIGNAL SIGINT
RUN apt update && apt install -y \\
    gcc-x86-64-linux-gnu \\
    gcc-aarch64-linux-gnu
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // Delete the apt-get lists after installing somethin
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3027')).toBe(true);    // Do not use apt as it is meant to be an end-user to
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);    // Consider using multi-stage builds to reduce final 
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1007')).toBe(true);    // apt-get cache not cleaned. Add `rm -rf /var/lib/ap
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

});

// ── thanos-io/thanos patterns ──

describe('OSS: thanos-io/thanos patterns', () => {
  it('.devcontainer/Dockerfile: 5 rules (DV1006, DV1009, DV3019, DV3024, DV4003)', () => {
    const v = lintContent(`# For details, see https://github.com/devcontainers/images/tree/main/src/go
FROM mcr.microsoft.com/devcontainers/go:1.23

RUN echo "Downloading prometheus..." \\
    && curl -sSL -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/prometheus/prometheus/releases" -o /tmp/releases.json \\
    && VERSION_LIST="$(jq -r '.[] | select(.tag_name | contains("rc") | not) | .tag_name | split("v") | .[1]' /tmp/releases.json | tr -d '"' | sort -rV)" \\
    && PROMETHEUS_LATEST_VERSION="$(echo "\${VERSION_LIST}" | head -n 1)" \\
    && PROMETHEUS_FILE_NAME="prometheus-\${PROMETHEUS_LATEST_VERSION}.linux-amd64" \\
    && curl -fsSLO "https://github.com/prometheus/prometheus/releases/download/v\${PROMETHEUS_LATEST_VERSION}/\${PROMETHEUS_FILE_NAME}.tar.gz" \\
    && tar -xzf "\${PROMETHEUS_FILE_NAME}.tar.gz" \\
    && rm "\${PROMETHEUS_FILE_NAME}.tar.gz" \\
    && mv \${PROMETHEUS_FILE_NAME}/prometheus /go/bin/

ENV GOPROXY "https://proxy.golang.org"

COPY .devcontainer/welcome-message.txt /usr/local/etc/vscode-dev-containers/first-run-notice.txt
`);
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "mcr.microsoft.com/devcontainers/
    expect(v.some(v => v.rule === 'DV3019')).toBe(true);    // Downloaded script executed without checksum verifi
    expect(v.some(v => v.rule === 'DV3024')).toBe(true);    // Tarball downloaded and extracted without checksum 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('Dockerfile: 2 rules (DL3057, DV4003)', () => {
    const v = lintContent(`# By default we pin to amd64 sha. Use make docker to automatically adjust for arm64 versions.
ARG BASE_DOCKER_SHA="14d68ca3d69fceaa6224250c83d81d935c053fb13594c811038c461194599973"
FROM quay.io/prometheus/busybox@sha256:\${BASE_DOCKER_SHA}
LABEL maintainer="The Thanos Authors"

RUN adduser \\
    -D \`#Dont assign a password\` \\
    -H \`#Dont create home directory\` \\
    -u 1001 \`#User id\`\\
    thanos

COPY --chown=thanos /thanos_tmp_for_docker /bin/thanos

USER 1001
ENTRYPOINT [ "/bin/thanos" ]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('Dockerfile.e2e-tests: 6 rules (DL3057, DV1005, DV1006, DV1008, DV1009, DV5003)', () => {
    const v = lintContent(`# Taking a non-alpine image for e2e tests so that cgo can be enabled for the race detector.
FROM golang:1.25.0 as builder

WORKDIR $GOPATH/src/github.com/thanos-io/thanos

COPY . $GOPATH/src/github.com/thanos-io/thanos

RUN CGO_ENABLED=1 go build -tags slicelabels -o $GOBIN/thanos -race ./cmd/thanos
# -----------------------------------------------------------------------------

FROM golang:1.25.0
LABEL maintainer="The Thanos Authors"

COPY --from=builder $GOBIN/thanos /bin/thanos

ENV GORACE="halt_on_error=1"

ENTRYPOINT [ "/bin/thanos" ]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/static-debian12"
  });

  it('Dockerfile.multi-arch: 2 rules (DL3057, DV4003)', () => {
    const v = lintContent(`# By default we pin to amd64 sha. Use make docker to automatically adjust for arm64 versions.
ARG BASE_DOCKER_SHA="97a9aacc097e5dbdec33b0d671adea0785e76d26ff2b979ee28570baf6a9155d"

FROM quay.io/prometheus/busybox@sha256:\${BASE_DOCKER_SHA}
LABEL maintainer="The Thanos Authors"

ARG ARCH="amd64"
ARG OS="linux"

COPY .build/\${OS}-\${ARCH}/thanos /bin/thanos

RUN adduser \\
    -D \`#Dont assign a password\` \\
    -H \`#Dont create home directory\` \\
    -u 1001 \`#User id\`\\
    thanos && \\
    chown thanos /bin/thanos
USER 1001
ENTRYPOINT [ "/bin/thanos" ]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('Dockerfile.multi-stage: 7 rules (DL3018, DL3057, DV1005, DV1008, DV1009, DV2011, ...)', () => {
    const v = lintContent(`# By default we pin to amd64 sha. Use make docker to automatically adjust for arm64 versions.
ARG BASE_DOCKER_SHA="14d68ca3d69fceaa6224250c83d81d935c053fb13594c811038c461194599973"
FROM golang:1.24.0-alpine3.20 as builder

WORKDIR $GOPATH/src/github.com/thanos-io/thanos
# Change in the docker context invalidates the cache so to leverage docker
# layer caching, moving update and installing apk packages above COPY cmd
# More info https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#leverage-build-cache
RUN apk update && apk add --no-cache alpine-sdk
# Replaced ADD with COPY as add is generally to download content form link or tar files
# while COPY supports the basic copying of local files into the container.
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy
COPY . $GOPATH/src/github.com/thanos-io/thanos

RUN git update-index --refresh; make build

# -----------------------------------------------------------------------------

FROM quay.io/prometheus/busybox@sha256:\${BASE_DOCKER_SHA}
LABEL maintainer="The Thanos Authors"

COPY --from=builder /go/bin/thanos /bin/thanos

RUN adduser \\
    -D \`#Dont assign a password\` \\
    -H \`#Dont create home directory\` \\
    -u 1001 \`#User id\`\\
    thanos && \\
    chown thanos /bin/thanos
USER 1001
ENTRYPOINT [ "/bin/thanos" ]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add alpin
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2011')).toBe(true);    // apk update is redundant when using apk add --no-ca
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

});

// ── cortexproject/cortex patterns ──

describe('OSS: cortexproject/cortex patterns', () => {
  it('build-image/Dockerfile: 12 rules (DL3008, DL3015, DL3057, DV1003, DV1006, DV1009, ...)', () => {
    const v = lintContent(`FROM golang:1.25.5-trixie
ARG goproxyValue
ENV GOPROXY=\${goproxyValue}
RUN apt-get update && apt-get install -y curl file gettext jq unzip protobuf-compiler libprotobuf-dev && \\
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y nodejs && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install website builder dependencies. Whenever you change these version, please also change website/package.json
# and vice versa.
RUN npm install -g postcss-cli@7.1.2 autoprefixer@9.8.5

ENV SHFMT_VERSION=3.2.4
RUN GOARCH=$(go env GOARCH) && \\
	if [ "$GOARCH" = "amd64" ]; then \\
	DIGEST=3f5a47f8fec27fae3e06d611559a2063f5d27e4b9501171dde9959b8c60a3538; \\
	elif [ "$GOARCH" = "arm64" ]; then \\
	DIGEST=6474d9cc08a1c9fe2ef4be7a004951998e3067d46cf55a011ddd5ff7bfab3de6; \\
	fi && \\
	URL=https://github.com/mvdan/sh/releases/download/v\${SHFMT_VERSION}/shfmt_v\${SHFMT_VERSION}_linux_\${GOARCH}; \\
	curl -fsSLo shfmt "\${URL}" && \\
	echo "$DIGEST  shfmt" | sha256sum -c && \\
	chmod +x shfmt && \\
	mv shfmt /usr/bin

RUN curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s -- -b /usr/bin v2.10.1

ENV HUGO_VERSION=v0.101.0
RUN go install github.com/client9/misspell/cmd/misspell@v0.3.4 &&\\
	go install github.com/golang/protobuf/protoc-gen-go@v1.3.1 &&\\
	go install github.com/gogo/protobuf/protoc-gen-gogoslick@v1.3.0 &&\\
	go install github.com/weaveworks/tools/cover@bdd647e92546027e12cdde3ae0714bb495e43013 &&\\
	go install github.com/fatih/faillint@v1.15.0 &&\\
	go install github.com/campoy/embedmd@v1.0.0 &&\\
	go install --tags extended github.com/gohugoio/hugo@\${HUGO_VERSION} &&\\
	rm -rf /go/pkg /go/src /root/.cache

ENV NODE_PATH=/usr/lib/node_modules
COPY build.sh /
ENV GOCACHE=/go/cache
ENTRYPOINT ["/build.sh"]

ARG revision
LABEL org.opencontainers.image.title="build-image" \\
	org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/build-image" \\
	org.opencontainers.image.revision="\${revision}"
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);    // Avoid piping curl/wget output directly to a shell.
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4001')).toBe(true);    // Multiple package install RUN instructions detected
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // 3 consecutive RUN instructions detected. Consider 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4004')).toBe(true);    // ARG defined after ENV. Define ARG before ENV for b
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/static-debian12"
  });

  it('cmd/cortex/Dockerfile: 5 rules (DL3018, DL3057, DV1006, DV1009, DV4003)', () => {
    const v = lintContent(`FROM       alpine:3.23
ARG TARGETARCH

RUN        apk add --no-cache ca-certificates
COPY       migrations /migrations/
COPY       cortex-$TARGETARCH /bin/cortex
EXPOSE     80
ENTRYPOINT [ "/bin/cortex" ]

ARG revision
LABEL org.opencontainers.image.title="cortex" \\
      org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/cmd/cortex" \\
      org.opencontainers.image.revision="\${revision}"
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/query-tee/Dockerfile: 5 rules (DL3018, DL3057, DV1006, DV1009, DV4003)', () => {
    const v = lintContent(`FROM       alpine:3.23
ARG TARGETARCH

RUN        apk add --no-cache ca-certificates
COPY       query-tee-$TARGETARCH /query-tee
ENTRYPOINT ["/query-tee"]

ARG revision
LABEL org.opencontainers.image.title="query-tee" \\
      org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/tools/query-tee" \\
      org.opencontainers.image.revision="\${revision}"
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/test-exporter/Dockerfile: 5 rules (DL3018, DL3057, DV1006, DV1009, DV4003)', () => {
    const v = lintContent(`FROM       alpine:3.23
ARG TARGETARCH
RUN        apk add --no-cache ca-certificates
COPY       test-exporter-$TARGETARCH /test-exporter
ENTRYPOINT ["/test-exporter"]

ARG revision
LABEL org.opencontainers.image.title="test-exporter" \\
      org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/cmd/test-exporter" \\
      org.opencontainers.image.revision="\${revision}"
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/thanosconvert/Dockerfile: 5 rules (DL3018, DL3057, DV1006, DV1009, DV4003)', () => {
    const v = lintContent(`FROM       alpine:3.23
ARG TARGETARCH
RUN        apk add --no-cache ca-certificates
COPY       thanosconvert-$TARGETARCH /thanosconvert
ENTRYPOINT ["/thanosconvert"]

ARG revision
LABEL org.opencontainers.image.title="thanosconvert" \\
      org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/tools/thanosconvert" \\
      org.opencontainers.image.revision="\${revision}"
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('development/tsdb-blocks-storage-s3-gossip/dev.dockerfile: 5 rules (DL3020, DV1006, DV1009, DV4003, DV4005)', () => {
    const v = lintContent(`FROM golang:1.19
ENV CGO_ENABLED=0
RUN go install github.com/go-delve/delve/cmd/dlv@latest

FROM alpine:3.23

RUN     mkdir /cortex
WORKDIR /cortex
ADD     ./cortex ./
COPY --from=0 /go/bin/dlv ./
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // Use COPY instead of ADD for files and folders
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('development/tsdb-blocks-storage-s3-single-binary/dev.dockerfile: 4 rules (DL3020, DV1006, DV1009, DV4005)', () => {
    const v = lintContent(`FROM alpine:3.23

RUN     mkdir /cortex
WORKDIR /cortex
ADD     ./cortex ./
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // Use COPY instead of ADD for files and folders
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('development/tsdb-blocks-storage-s3/dev.dockerfile: 5 rules (DL3020, DV1006, DV1009, DV4003, DV4005)', () => {
    const v = lintContent(`FROM golang:1.19
ENV CGO_ENABLED=0
RUN go install github.com/go-delve/delve/cmd/dlv@latest

FROM alpine:3.23

RUN     mkdir /cortex
WORKDIR /cortex
ADD     ./cortex ./
COPY --from=0 /go/bin/dlv ./
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // Use COPY instead of ADD for files and folders
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('development/tsdb-blocks-storage-swift-single-binary/dev.dockerfile: 4 rules (DL3020, DV1006, DV1009, DV4005)', () => {
    const v = lintContent(`FROM alpine:3.23

RUN     mkdir /cortex
WORKDIR /cortex
ADD     ./cortex ./
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // Use COPY instead of ADD for files and folders
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('packaging/deb/debian-systemd/Dockerfile: 9 rules (DL3008, DL3015, DL3057, DV1006, DV1009, DV2004, ...)', () => {
    const v = lintContent(`FROM debian:10
ENV container docker
ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \\
        && apt-get install -y systemd \\
        && apt-get clean \\
        && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN rm -f /lib/systemd/system/multi-user.target.wants/* \\
        /etc/systemd/system/*.wants/* \\
        /lib/systemd/system/local-fs.target.wants/* \\
        /lib/systemd/system/sockets.target.wants/*udev* \\
        /lib/systemd/system/sockets.target.wants/*initctl* \\
        /lib/systemd/system/sysinit.target.wants/systemd-tmpfiles-setup* \\
        /lib/systemd/system/systemd-update-utmp*

VOLUME [ "/sys/fs/cgroup" ]
CMD ["/lib/systemd/systemd"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "debian" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);    // DEBIAN_FRONTEND=noninteractive is set as ENV. Use 
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/base-debian12" i
  });

  it('packaging/fpm/Dockerfile: 7 rules (DL3018, DL3028, DL3057, DV1004, DV1006, DV1009, ...)', () => {
    const v = lintContent(`FROM alpine:3.23

RUN apk add --no-cache \\
        ruby \\
        ruby-dev \\
        ruby-etc \\
        gcc \\
        git \\
        libc-dev \\
        libffi-dev \\
        make \\
        rpm \\
        tar \\
        && gem install --no-document fpm

COPY package.sh /
ENTRYPOINT ["/package.sh"]

ARG revision
LABEL org.opencontainers.image.title="fpm" \\
        # TODO: should this label point to the fpm source code?
        org.opencontainers.image.source="https://github.com/cortexproject/cortex/tree/master/packaging/fpm" \\
        org.opencontainers.image.revision="\${revision}"
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ruby`
    expect(v.some(v => v.rule === 'DL3028')).toBe(true);    // Pin versions in gem install. Instead of `gem insta
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1004')).toBe(true);    // Consider using multi-stage builds to reduce final 
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "alpine" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('packaging/rpm/centos-systemd/Dockerfile: 4 rules (DL3057, DV1006, DV1009, DV4003)', () => {
    const v = lintContent(`FROM centos:8
ENV container docker
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == \\
        systemd-tmpfiles-setup.service ] || rm -f $i; done); \\
        rm -f /lib/systemd/system/multi-user.target.wants/*; \\
        rm -f /etc/systemd/system/*.wants/*; \\
        rm -f /lib/systemd/system/local-fs.target.wants/*; \\
        rm -f /lib/systemd/system/sockets.target.wants/*udev*; \\
        rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \\
        rm -f /lib/systemd/system/basic.target.wants/*; \\
        rm -f /lib/systemd/system/anaconda.target.wants/*;

VOLUME [ "/sys/fs/cgroup"]
CMD ["/usr/sbin/init"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "centos" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

});

// ── grafana/loki patterns ──

describe('OSS: grafana/loki patterns', () => {
  it('clients/cmd/docker-driver/Dockerfile: 6 rules (DL3018, DL3057, DV1005, DV1006, DV1008, DV4003)', () => {
    const v = lintContent(`ARG BUILD_IMAGE=grafana/loki-build-image:0.34.6
ARG GOARCH=amd64
# Directories in this file are referenced from the root of the project not this folder
# This file is intended to be called from the root like so:
# docker build -t grafana/loki-docker-driver -f clients/cmd/docker-driver/Dockerfile .

FROM $BUILD_IMAGE AS build
COPY . /src/loki
WORKDIR /src/loki

ARG GOARCH
RUN make clean && make BUILD_IN_CONTAINER=false GOARCH=\${GOARCH} clients/cmd/docker-driver/docker-driver

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS temp

ARG GOARCH

RUN apk add --update --no-cache --arch=\${GOARCH} ca-certificates tzdata

FROM --platform=linux/\${GOARCH} alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

COPY --from=temp /etc/ca-certificates.conf /etc/ca-certificates.conf
COPY --from=temp /usr/share/ca-certificates /usr/share/ca-certificates
COPY --from=temp /usr/share/zoneinfo /usr/share/zoneinfo

COPY --from=build /src/loki/clients/cmd/docker-driver/docker-driver /bin/docker-driver

WORKDIR /bin/
ENTRYPOINT [ "/bin/docker-driver" ]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('clients/cmd/fluent-bit/Dockerfile: 5 rules (DL3057, DV1005, DV1006, DV1008, DV1009)', () => {
    const v = lintContent(`FROM golang:1.24-bullseye AS builder

COPY . /src

WORKDIR /src

ARG LDFLAGS
ENV CGO_ENABLED=1

RUN go build \\
    -trimpath -ldflags "\${LDFLAGS}" \\
    -tags netgo \\
    -buildmode=c-shared \\
    -o clients/cmd/fluent-bit/out_grafana_loki.so \\
    /src/clients/cmd/fluent-bit

FROM fluent/fluent-bit:4.2.3@sha256:a5761fa961cb22dd0875883a4d446b1acd99d4935d77358aa9f50ee177e44fe2

COPY --from=builder /src/clients/cmd/fluent-bit/out_grafana_loki.so /fluent-bit/bin
COPY clients/cmd/fluent-bit/fluent-bit.conf /fluent-bit/etc/fluent-bit.conf

EXPOSE 2020

CMD ["/fluent-bit/bin/fluent-bit", "-e","/fluent-bit/bin/out_grafana_loki.so", "-c", "/fluent-bit/etc/fluent-bit.conf"]
`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
  });

  it('clients/cmd/fluentd/Dockerfile: 7 rules (DL3008, DL3009, DV1005, DV1008, DV1009, DV4003, ...)', () => {
    const v = lintContent(`FROM ruby:4.0.1@sha256:3b8c977b1f13501e132a309c903f2f9931e41be4e52785a719490e937953c3de AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \\
    sudo make gcc g++ libc-dev ruby-dev golang

COPY . /src/loki
WORKDIR /src/loki
RUN make BUILD_IN_CONTAINER=false fluentd-plugin

FROM fluent/fluentd:v1.19-debian-1
ENV LOKI_URL="https://logs-prod-us-central1.grafana.net"

COPY --from=build /src/loki/clients/cmd/fluentd/lib/fluent/plugin/out_loki.rb /fluentd/plugins/out_loki.rb

COPY clients/cmd/fluentd/docker/Gemfile /fluentd/
COPY clients/cmd/fluentd/docker/conf/loki.conf /fluentd/etc/loki.conf

USER root
RUN sed -i '$i''  @include loki.conf' /fluentd/etc/fluent.conf
USER fluent
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // Delete the apt-get lists after installing somethin
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "fluent/fluentd" with a digest (e
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4007')).toBe(true);    // DEBIAN_FRONTEND=noninteractive is set as ENV. Use 
  });

  it('clients/cmd/logstash/Dockerfile: 3 rules (DL3028, DV1011, DV4002)', () => {
    const v = lintContent(`FROM logstash:9.3.1@sha256:d804f4994cebd9002e33a6f0b561dd3a15108222045f5d182da3c2675f26d177

USER logstash
ENV PATH /usr/share/logstash/vendor/jruby/bin:/usr/share/logstash/vendor/bundle/jruby/3.1.0/bin:/usr/share/logstash/jdk/bin:$PATH
ENV LOGSTASH_PATH /usr/share/logstash
ENV GEM_PATH /usr/share/logstash/vendor/bundle/jruby/3.1.0
ENV GEM_HOME /usr/share/logstash/vendor/bundle/jruby/3.1.0

RUN gem install bundler -v 2.6.9

COPY --chown=logstash:logstash ./clients/cmd/logstash/ /home/logstash/
WORKDIR /home/logstash/

# don't run 'bundle update'. It causes a transitive dependency error
RUN bundle config set --local path /usr/share/logstash/vendor/bundle && \\
    bundle install && \\
    bundle exec rake vendor && \\
    bundle exec rspec

RUN cat logstash-output-loki.gemspec | grep s.version | awk '{print $3}' |  cut -d "'" -f 2 > VERSION

RUN gem build logstash-output-loki.gemspec && \\
    PLUGIN_VERSION=$(cat VERSION); /usr/share/logstash/bin/logstash-plugin install logstash-output-loki-\${PLUGIN_VERSION}.gem

EXPOSE 5044
`);
    expect(v.some(v => v.rule === 'DL3028')).toBe(true);    // Pin versions in gem install. Instead of `gem insta
    expect(v.some(v => v.rule === 'DV1011')).toBe(true);    // Possible AWS secret access key detected in ENV "PA
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // 3 consecutive RUN instructions detected. Consider 
  });

  it('clients/cmd/promtail/Dockerfile: 12 rules (DL3008, DL3009, DL3014, DL3015, DL3057, DV1005, ...)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26

FROM golang:\${GO_VERSION}-bookworm AS build
ARG IMAGE_TAG

COPY . /src/loki
WORKDIR /src/loki
RUN apt-get update && apt-get install -qy libsystemd-dev
RUN make clean && make BUILD_IN_CONTAINER=false PROMTAIL_JOURNAL_ENABLED=true IMAGE_TAG=\${IMAGE_TAG} promtail

# Promtail requires debian or ubuntu as the base image to support systemd journal reading
FROM public.ecr.aws/ubuntu/ubuntu:noble
# tzdata required for the timestamp stage to work
# Install dependencies needed at runtime.
RUN  apt-get update \\
 &&  apt-get install -qy libsystemd-dev tzdata ca-certificates \\
 &&  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY --from=build /src/loki/clients/cmd/promtail/promtail /usr/bin/promtail
COPY clients/cmd/promtail/promtail-docker-config.yaml /etc/promtail/config.yml
ENTRYPOINT ["/usr/bin/promtail"]
CMD ["-config.file=/etc/promtail/config.yml"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // Delete the apt-get lists after installing somethin
    expect(v.some(v => v.rule === 'DL3014')).toBe(true);    // Use the -y switch to avoid manual input `apt-get -
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/base-debian12" i
  });

  it('clients/cmd/promtail/Dockerfile.arm32: 12 rules (DL3008, DL3009, DL3014, DL3015, DL3057, DV1005, ...)', () => {
    const v = lintContent(`FROM golang:1.24-bookworm AS build

COPY . /src/loki
WORKDIR /src/loki
RUN apt-get update && apt-get install -qy libsystemd-dev
RUN make clean && make BUILD_IN_CONTAINER=false PROMTAIL_JOURNAL_ENABLED=true promtail

# Promtail requires debian or ubuntu as the base image to support systemd journal reading
FROM public.ecr.aws/ubuntu/ubuntu:noble
# tzdata required for the timestamp stage to work
RUN apt-get update && \\
  apt-get install -qy tzdata ca-certificates wget libsystemd-dev && \\
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY --from=build /src/loki/clients/cmd/promtail/promtail /usr/bin/promtail
COPY clients/cmd/promtail/promtail-local-config.yaml /etc/promtail/local-config.yaml
COPY clients/cmd/promtail/promtail-docker-config.yaml /etc/promtail/config.yml

# Drone CI builds arm32 images using armv8l rather than armv7l. Something in
# our build process above causes ldconfig to be rerun and removes the armhf
# library that debian:stretch-slim on ARM comes with. Symbolically linking to
# ld-linux.so.3 fixes the problem and allows Promtail to start.
#
# This process isn't necessary when building on armv7l so we only do it if the
# library was removed.
RUN sh -c '[ ! -f /lib/ld-linux-armhf.so.3 ] && echo RE-LINKING LD-LINUX-ARMHF.SO.3 && ln -s /lib/ld-linux.so.3 /lib/ld-linux-armhf.so.3'

ENTRYPOINT ["/usr/bin/promtail"]
CMD ["-config.file=/etc/promtail/config.yml"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3009')).toBe(true);    // Delete the apt-get lists after installing somethin
    expect(v.some(v => v.rule === 'DL3014')).toBe(true);    // Use the -y switch to avoid manual input `apt-get -
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/base-debian12" i
  });

  it('clients/cmd/promtail/Dockerfile.cross: 12 rules (DL3008, DL3014, DL3015, DL3029, DL3057, DV1005, ...)', () => {
    const v = lintContent(`ARG BUILD_IMAGE=grafana/loki-build-image:0.34.8
ARG GO_VERSION=1.26
# Directories in this file are referenced from the root of the project not this folder
# This file is intended to be called from the root like so:
# docker build -t grafana/promtail -f clients/cmd/promtail/Dockerfile .
FROM golang:\${GO_VERSION}-alpine AS goenv
RUN go env GOARCH > /goarch && \\
  go env GOARM > /goarm

FROM --platform=linux/amd64 $BUILD_IMAGE as build
COPY --from=goenv /goarch /goarm /
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && GOARCH=$(cat /goarch) GOARM=$(cat /goarm) make BUILD_IN_CONTAINER=false PROMTAIL_JOURNAL_ENABLED=true promtail

# Promtail requires debian or ubuntu as the base image to support systemd journal reading
FROM public.ecr.aws/ubuntu/ubuntu:noble
# tzdata required for the timestamp stage to work
RUN apt-get update && \\
  apt-get install -qy tzdata ca-certificates wget libsystemd-dev && \\
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
COPY --from=build /src/loki/clients/cmd/promtail/promtail /usr/bin/promtail
COPY clients/cmd/promtail/promtail-local-config.yaml /etc/promtail/local-config.yaml
COPY clients/cmd/promtail/promtail-docker-config.yaml /etc/promtail/config.yml
ENTRYPOINT ["/usr/bin/promtail"]
CMD ["-config.file=/etc/promtail/config.yml"]
`);
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3014')).toBe(true);    // Use the -y switch to avoid manual input `apt-get -
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // Do not use --platform flag with FROM
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV5003')).toBe(true);    // Consider using "gcr.io/distroless/base-debian12" i
  });

  it('clients/cmd/promtail/Dockerfile.debug: 9 rules (DL3018, DL3052, DL3057, DV1005, DV1006, DV1008, ...)', () => {
    const v = lintContent(`# Directories in this file are referenced from the root of the project not this folder
# This file is intended to be called from the root like so:
# docker build -t grafana/promtail -f clients/cmd/promtail/Dockerfile.debug .

FROM grafana/loki-build-image:0.34.6 AS build
ARG GOARCH="amd64"
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make BUILD_IN_CONTAINER=false PROMTAIL_JOURNAL_ENABLED=true promtail-debug


FROM       alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN        apk add --update --no-cache ca-certificates tzdata
COPY       --from=build /src/loki/clients/cmd/promtail/promtail-debug /usr/bin/promtail-debug
COPY       --from=build /usr/bin/dlv /usr/bin/dlv
COPY       clients/cmd/promtail/promtail-local-config.yaml /etc/promtail/local-config.yaml
COPY       clients/cmd/promtail/promtail-docker-config.yaml /etc/promtail/config.yml

# Expose 40000 for delve
EXPOSE 40000

# Allow delve to run on Alpine based containers.
RUN apk add --no-cache libc6-compat

# Run delve, ending with -- because we pass params via kubernetes, per the docs:
#   Pass flags to the program you are debugging using --, for example:\`
#   dlv exec ./hello -- server --config conf/config.toml\`
ENTRYPOINT ["/usr/bin/dlv", "--listen=:40000", "--headless=true", "--continue", "--accept-multiclient", "--api-version=2", "exec", "/usr/bin/promtail-debug", "--"]
CMD ["-config.file=/etc/promtail/config.yml"]
`);
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add ca-ce
    expect(v.some(v => v.rule === 'DL3052')).toBe(true);    // ARG GOARCH is declared but never referenced in the
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "grafana/loki-build-image" with a
    expect(v.some(v => v.rule === 'DV4001')).toBe(true);    // Multiple package install RUN instructions detected
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/logcli/Dockerfile: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
ARG IMAGE_TAG
FROM golang:\${GO_VERSION} AS build

COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make BUILD_IN_CONTAINER=false IMAGE_TAG=\${IMAGE_TAG} logcli


FROM gcr.io/distroless/static:debug

COPY --from=build /src/loki/cmd/logcli/logcli /usr/bin/logcli
SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh

ENTRYPOINT [ "/usr/bin/logcli" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/logql-analyzer/Dockerfile: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
FROM golang:\${GO_VERSION} AS build

COPY . /src/loki
WORKDIR /src/loki
RUN make clean && CGO_ENABLED=0 go build ./cmd/logql-analyzer/

FROM gcr.io/distroless/static:debug

COPY --from=build /src/loki/logql-analyzer /usr/bin/logql-analyzer
SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh

ENTRYPOINT [ "/usr/bin/logql-analyzer" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/loki-canary-boringcrypto/Dockerfile: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
FROM golang:\${GO_VERSION} as build
ARG IMAGE_TAG

COPY . /src/loki
WORKDIR /src/loki
RUN go env GOARCH > /goarch
RUN make clean && make GOARCH=$(cat /goarch) BUILD_IN_CONTAINER=true GOEXPERIMENT=boringcrypto IMAGE_TAG=\${IMAGE_TAG} loki-canary-boringcrypto

FROM gcr.io/distroless/base-nossl:debug
COPY --from=build /src/loki/cmd/loki-canary-boringcrypto/loki-canary-boringcrypto /usr/bin/loki-canary
SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh
ENTRYPOINT [ "/usr/bin/loki-canary" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/loki-canary/Dockerfile: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
FROM golang:\${GO_VERSION} AS build
ARG IMAGE_TAG

COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make BUILD_IN_CONTAINER=false IMAGE_TAG=\${IMAGE_TAG} loki-canary

FROM gcr.io/distroless/static:debug

COPY --from=build /src/loki/cmd/loki-canary/loki-canary /usr/bin/loki-canary
SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh
ENTRYPOINT [ "/usr/bin/loki-canary" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/loki-canary/Dockerfile.cross: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG BUILD_IMAGE=grafana/loki-build-image:0.34.8
ARG GO_VERSION=1.26
# Directories in this file are referenced from the root of the project not this folder
# This file is intended to be called from the root like so:
# docker build -t grafana/promtail -f cmd/promtail/Dockerfile .
FROM golang:\${GO_VERSION} AS goenv
RUN go env GOARCH > /goarch && \\
  go env GOARM > /goarm

FROM $BUILD_IMAGE as build
COPY --from=goenv /goarch /goarm /
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && GOARCH=$(cat /goarch) GOARM=$(cat /goarm) make BUILD_IN_CONTAINER=false loki-canary

FROM gcr.io/distroless/static:debug
COPY --from=build /src/loki/cmd/loki-canary/loki-canary /usr/bin/loki-canary
SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh
ENTRYPOINT [ "/usr/bin/loki-canary" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/loki/Dockerfile: 6 rules (DV1005, DV1008, DV1009, DV1012, DV4003, DV4010)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26

# Go build stage
FROM golang:\${GO_VERSION} AS build
ARG IMAGE_TAG
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make BUILD_IN_CONTAINER=false IMAGE_TAG=\${IMAGE_TAG} loki

# Prepare filesystem stage
FROM golang:\${GO_VERSION} AS filesystem
COPY cmd/loki/loki-docker-config.yaml /local-config.yaml
RUN mkdir -p /etc/loki /loki/rules /loki/rules-temp && \\
    cp /local-config.yaml /etc/loki/local-config.yaml && \\
    addgroup --gid 10001 loki && \\
    adduser --uid 10001 --gid 10001 --disabled-password --gecos "" loki && \\
    chown -R loki:loki /etc/loki /loki

# Final stage
FROM gcr.io/distroless/static:nonroot

COPY --from=build /src/loki/cmd/loki/loki /usr/bin/loki
COPY --from=filesystem --chown=10001:10001 /etc/loki /etc/loki
COPY --from=filesystem --chown=10001:10001 /loki /loki
COPY --from=filesystem /etc/passwd /etc/passwd
COPY --from=filesystem /etc/group /etc/group

USER 10001
WORKDIR /
EXPOSE 3100
ENTRYPOINT [ "/usr/bin/loki" ]
CMD ["-config.file=/etc/loki/local-config.yaml"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV1012')).toBe(true);    // COPY --from=filesystem copies potentially sensitiv
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4010')).toBe(true);    // Recursive chown -R increases layer size. Consider 
  });

  it('cmd/loki/Dockerfile.cross: 6 rules (DV1005, DV1008, DV1009, DV1012, DV4003, DV4010)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
# Directories in this file are referenced from the root of the project not this folder
# This file is intended to be called from the root like so:
# docker build -t grafana/loki -f cmd/loki/Dockerfile .
FROM golang:\${GO_VERSION} AS goenv
RUN go env GOARCH > /goarch && \\
    go env GOARM > /goarm

COPY . /src/loki
WORKDIR /src/loki
RUN make clean && GOARCH=$(cat /goarch) GOARM=$(cat /goarm) make BUILD_IN_CONTAINER=false loki

# Prepare filesystem stage
FROM golang:\${GO_VERSION} AS filesystem
COPY cmd/loki/loki-local-config.yaml /local-config.yaml
RUN mkdir -p /etc/loki /loki && \\
    cp /local-config.yaml /etc/loki/local-config.yaml && \\
    addgroup --gid 10001 loki && \\
    adduser --uid 10001 --gid 10001 --disabled-password --gecos "" loki && \\
    chown -R loki:loki /etc/loki /loki

FROM gcr.io/distroless/static:nonroot

COPY --from=goenv /src/loki/cmd/loki/loki /usr/bin/loki
COPY --from=filesystem --chown=10001:10001 /etc/loki /etc/loki
COPY --from=filesystem --chown=10001:10001 /loki /loki
COPY --from=filesystem /etc/passwd /etc/passwd
COPY --from=filesystem /etc/group /etc/group

USER 10001
WORKDIR /
EXPOSE 3100
ENTRYPOINT [ "/usr/bin/loki" ]
CMD ["-config.file=/etc/loki/local-config.yaml"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV1012')).toBe(true);    // COPY --from=filesystem copies potentially sensitiv
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4010')).toBe(true);    // Recursive chown -R increases layer size. Consider 
  });

  it('cmd/loki/Dockerfile.debug: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG BUILD_IMAGE=grafana/loki-build-image:0.34.8
ARG GO_VERSION=1.26
# Directories in this file are referenced from the root of the project not this folder
# This file is intended to be called from the root like so:
# docker build -t grafana/loki -f cmd/loki/Dockerfile.debug .

FROM golang:\${GO_VERSION} as goenv
RUN go env GOARCH > /goarch && \\
    go env GOARM > /goarm && \\
    go install github.com/go-delve/delve/cmd/dlv@latest

FROM $BUILD_IMAGE as build
COPY --from=goenv /goarch /goarm /
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && \\
    GOARCH=$(cat /goarch) GOARM=$(cat /goarm) make BUILD_IN_CONTAINER=false loki-debug

FROM       gcr.io/distroless/base-nossl:debug
COPY       --from=build /src/loki/cmd/loki/loki-debug /usr/bin/loki-debug
COPY       --from=goenv /go/bin/dlv /usr/bin/dlv
COPY       cmd/loki/loki-docker-config.yaml /etc/loki/local-config.yaml
EXPOSE     3100

# Expose 40000 for delve
EXPOSE 40000

SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh


# Run delve, ending with -- because we pass params via kubernetes, per the docs:
#   Pass flags to the program you are debugging using --, for example:\`
#   dlv exec ./hello -- server --config conf/config.toml\`
ENTRYPOINT ["/usr/bin/dlv", "--listen=:40000", "--headless=true", "--log", "--continue", "--accept-multiclient" , "--api-version=2", "exec", "/usr/bin/loki-debug", "--"]
CMD        ["-config.file=/etc/loki/local-config.yaml"]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/migrate/Dockerfile: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
FROM golang:\${GO_VERSION} AS build
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make BUILD_IN_CONTAINER=false migrate

FROM gcr.io/distroless/static:debug

COPY --from=build /src/loki/cmd/migrate/migrate /usr/bin/migrate
SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh
ENTRYPOINT [ "/busybox/tail", "-f", "/dev/null" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('cmd/querytee/Dockerfile: 5 rules (DV1005, DV1006, DV1008, DV1009, DV4003)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
FROM golang:\${GO_VERSION} AS build
ARG IMAGE_TAG

COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make IMAGE_TAG=\${IMAGE_TAG} loki-querytee

FROM gcr.io/distroless/static:debug
COPY --from=build /src/loki/cmd/querytee/querytee /usr/bin/querytee

SHELL [ "/busybox/sh", "-c" ]
RUN ln -s /busybox/sh /bin/sh

ENTRYPOINT [ "/usr/bin/querytee" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('examples/promtail-heroku/Dockerfile: 3 rules (DL3057, DV1006, DV1009)', () => {
    const v = lintContent(`from grafana/promtail:main-c9ef062

# Copy the config.yml file we created in the step above, inside the container itself. This simplifies the 
# configuration of the Promtail instance.
COPY config.yml /etc/promtail/config.yml

# This three flags indicates promtail where the configurations is located, to interpolate the configuration
# file with environment variables (this is to avoid hardcoding values such as API Keys), and lastly, to print
# the whole configuration file to STDERR when starting the container (this is helpful for debugging).
CMD ["-config.file=/etc/promtail/config.yml", "-config.expand-env=true", "-print-config-stderr"]`);
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "grafana/promtail" with a digest 
  });

  it('loki-build-image/Dockerfile: 18 rules (DL3003, DL3006, DL3008, DL3014, DL3015, DL3018, ...)', () => {
    const v = lintContent(`# This is the Dockerfile for the Loki build image that is used by the CI
# pipelines.
# If you make changes to this Dockerfile you also need to update the
# tag of the Docker image in \`../.drone/drone.jsonnet\` and run \`make drone\`.
# See ../docs/sources/community/maintaining/release-loki-build-image.md for instructions
# on how to publish a new build image.
ARG GO_VERSION=1.26.0
ARG GOLANG_BASE_IMAGE=golang:\${GO_VERSION}-trixie

# Install helm (https://helm.sh/) and helm-docs (https://github.com/norwoodj/helm-docs) for generating Helm Chart reference.
FROM \${GOLANG_BASE_IMAGE} AS helm
ARG TARGETARCH
ARG HELM_VER="v3.2.3"
RUN curl -L "https://get.helm.sh/helm-\${HELM_VER}-linux-$TARGETARCH.tar.gz" | tar zx && \\
    install -t /usr/local/bin "linux-$TARGETARCH/helm"
RUN BIN=$([ "$TARGETARCH" = "arm64" ] && echo "helm-docs_Linux_arm64" || echo "helm-docs_Linux_x86_64") &&  \\
    curl -L "https://github.com/norwoodj/helm-docs/releases/download/v1.11.2/$BIN.tar.gz" | tar zx && \\
    install -t /usr/local/bin helm-docs

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS lychee
ARG TARGETARCH
ARG LYCHEE_VER="0.7.0"
RUN apk add --no-cache curl && \\
    curl -L -o /tmp/lychee-$LYCHEE_VER.tgz https://github.com/lycheeverse/lychee/releases/download/\${LYCHEE_VER}/lychee-\${LYCHEE_VER}-x86_64-unknown-linux-gnu.tar.gz && \\
    tar -xz -C /tmp -f /tmp/lychee-$LYCHEE_VER.tgz && \\
    mv /tmp/lychee /usr/bin/lychee && \\
    rm -rf "/tmp/linux-$TARGETARCH" /tmp/lychee-$LYCHEE_VER.tgz

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS golangci
RUN apk add --no-cache curl && \\
    cd / && \\
    curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v2.10.1

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS buf
ARG TARGETOS
RUN apk add --no-cache curl && \\
    curl -sSL "https://github.com/bufbuild/buf/releases/download/v1.4.0/buf-$TARGETOS-$(uname -m)" -o "/usr/bin/buf" && \\
    chmod +x "/usr/bin/buf"

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS docker
RUN apk add --no-cache docker-cli docker-cli-buildx

FROM \${GOLANG_BASE_IMAGE} AS drone
ARG TARGETARCH
RUN curl -L "https://github.com/drone/drone-cli/releases/download/v1.7.0/drone_linux_$TARGETARCH".tar.gz | tar zx && \\
    install -t /usr/local/bin drone

# Install faillint used to lint go imports in CI.
# This collisions with the version of go tools used in the base image, thus we install it in its own image and copy it over.
# Error:
# github.com/fatih/faillint@v1.5.0 requires golang.org/x/tools@v0.0.0-20200207224406-61798d64f025
#   (not golang.org/x/tools@v0.0.0-20190918214920-58d531046acd from golang.org/x/tools/cmd/goyacc@58d531046acdc757f177387bc1725bfa79895d69)
FROM \${GOLANG_BASE_IMAGE} AS faillint
RUN GO111MODULE=on go install github.com/fatih/faillint@v1.15.0
RUN GO111MODULE=on go install golang.org/x/tools/cmd/goimports@v0.38.0

FROM \${GOLANG_BASE_IMAGE} AS delve
RUN GO111MODULE=on go install github.com/go-delve/delve/cmd/dlv@latest

# Install ghr used to push binaries and template the release
# This collides with the version of go tools used in the base image, thus we install it in its own image and copy it over.
FROM \${GOLANG_BASE_IMAGE} AS ghr
RUN GO111MODULE=on go install github.com/tcnksm/ghr@9349474

# Install nfpm (https://nfpm.goreleaser.com) for creating .deb and .rpm packages.
FROM \${GOLANG_BASE_IMAGE} AS nfpm
RUN GO111MODULE=on go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.11.3

# Install gotestsum
FROM \${GOLANG_BASE_IMAGE} AS gotestsum
RUN GO111MODULE=on go install gotest.tools/gotestsum@v1.8.2

# Install tools used to compile jsonnet.
FROM \${GOLANG_BASE_IMAGE} AS jsonnet
RUN GO111MODULE=on go install github.com/jsonnet-bundler/jsonnet-bundler/cmd/jb@v0.5.1
RUN GO111MODULE=on go install github.com/monitoring-mixins/mixtool/cmd/mixtool@16dc166166d91e93475b86b9355a4faed2400c18
RUN GO111MODULE=on go install github.com/google/go-jsonnet/cmd/jsonnet@v0.20.0

FROM aquasec/trivy AS trivy

FROM \${GOLANG_BASE_IMAGE}
RUN apt-get update && \\
    apt-get install -qy \\
    musl gnupg ragel \\
    file zip unzip jq gettext\\
    protobuf-compiler libprotobuf-dev \\
    libsystemd-dev jq && \\
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install dependencies to cross build Promtail to ARM and ARM64.
RUN dpkg --add-architecture armhf && \\
    dpkg --add-architecture arm64 && \\
    apt-get update && \\
    apt-get install -y --no-install-recommends \\
    pkg-config \\
    gcc-aarch64-linux-gnu libc6-dev-arm64-cross libsystemd-dev:arm64 \\
    gcc-arm-linux-gnueabihf libc6-dev-armhf-cross libsystemd-dev:armhf && \\
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=docker /usr/bin/docker /usr/bin/docker
COPY --from=docker /usr/libexec/docker/cli-plugins/docker-buildx /usr/libexec/docker/cli-plugins/docker-buildx
COPY --from=helm /usr/local/bin/helm /usr/bin/helm
COPY --from=helm /usr/local/bin/helm-docs /usr/bin/helm-docs
COPY --from=lychee /usr/bin/lychee /usr/bin/lychee
COPY --from=golangci /bin/golangci-lint /usr/local/bin
COPY --from=buf /usr/bin/buf /usr/bin/buf
COPY --from=drone /usr/local/bin/drone /usr/bin/drone
COPY --from=faillint /go/bin/faillint /usr/bin/faillint
COPY --from=faillint /go/bin/goimports /usr/bin/goimports
COPY --from=delve /go/bin/dlv /usr/bin/dlv
COPY --from=ghr /go/bin/ghr /usr/bin/ghr
COPY --from=nfpm /go/bin/nfpm /usr/bin/nfpm
COPY --from=gotestsum /go/bin/gotestsum /usr/bin/gotestsum
COPY --from=jsonnet /go/bin/jb /usr/bin/jb
COPY --from=jsonnet /go/bin/mixtool /usr/bin/mixtool
COPY --from=jsonnet /go/bin/jsonnet /usr/bin/jsonnet
COPY --from=trivy /usr/local/bin/trivy /usr/bin/trivy

# Install some necessary dependencies.
# Forcing GO111MODULE=on is required to specify dependencies at specific versions using the go mod notation.
# If we don't force this, Go is going to default to GOPATH mode as we do not have an active project or go.mod
# file for it to detect and switch to Go Modules automatically.
# It's possible this can be revisited in newer versions of Go if the behavior around GOPATH vs GO111MODULES changes
RUN GO111MODULE=on go install github.com/golang/protobuf/protoc-gen-go@v1.3.1
RUN GO111MODULE=on go install github.com/gogo/protobuf/protoc-gen-gogoslick@v1.3.0
# Due to the lack of a proper release tag, we use the commit hash of
# https://github.com/golang/tools/releases v0.1.7
RUN GO111MODULE=on go install golang.org/x/tools/cmd/goyacc@58d531046acdc757f177387bc1725bfa79895d69
RUN GO111MODULE=on go install github.com/mitchellh/gox@9f71238 && rm -rf /go/pkg /go/src
ENV GOCACHE=/go/cache
ENV GOTEST="gotestsum --format testname --"

COPY build.sh /
RUN chmod +x /build.sh
ENTRYPOINT ["/build.sh"]
`);
    expect(v.some(v => v.rule === 'DL3003')).toBe(true);    // Use WORKDIR to switch to a directory
    expect(v.some(v => v.rule === 'DL3006')).toBe(true);    // Always tag the version of an image explicitly. Tag
    expect(v.some(v => v.rule === 'DL3008')).toBe(true);    // Pin versions in apt-get install. Instead of `apt-g
    expect(v.some(v => v.rule === 'DL3014')).toBe(true);    // Use the -y switch to avoid manual input `apt-get -
    expect(v.some(v => v.rule === 'DL3015')).toBe(true);    // Avoid additional packages by specifying --no-insta
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add curl`
    expect(v.some(v => v.rule === 'DL3052')).toBe(true);    // ARG GO_VERSION is declared but never referenced in
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1003')).toBe(true);    // Avoid piping curl/wget output directly to a shell.
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "aquasec/trivy" with a digest (e.
    expect(v.some(v => v.rule === 'DV2004')).toBe(true);    // Consider using --no-install-recommends with apt-ge
    expect(v.some(v => v.rule === 'DV3019')).toBe(true);    // Downloaded script executed without checksum verifi
    expect(v.some(v => v.rule === 'DV3023')).toBe(true);    // Unquoted ARG $LYCHEE_VER in download URL. URL inje
    expect(v.some(v => v.rule === 'DV3024')).toBe(true);    // Tarball downloaded and extracted without checksum 
    expect(v.some(v => v.rule === 'DV4001')).toBe(true);    // Multiple package install RUN instructions detected
    expect(v.some(v => v.rule === 'DV4002')).toBe(true);    // 3 consecutive RUN instructions detected. Consider 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('operator/Dockerfile: 1 rules (DV1009)', () => {
    const v = lintContent(`# Build the manager binary
FROM golang:1.25.7 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY api/ api/
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/loki-operator/main.go cmd/loki-operator/main.go
COPY internal/ internal/

# Build
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -mod=readonly -o manager cmd/loki-operator/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
  });

  it('operator/Dockerfile.cross: 3 rules (DL3029, DV1009, DV4003)', () => {
    const v = lintContent(`ARG BUILD_IMAGE=grafana/loki-build-image:0.33.6

FROM golang:1.25.7-alpine as goenv
RUN go env GOARCH > /goarch && \\
  go env GOARM > /goarm

FROM --platform=linux/amd64 $BUILD_IMAGE as builder
COPY --from=goenv /goarch /goarm /
WORKDIR /workspace
# Copy the Go Modules manifests
COPY api/ api/
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/loki-operator/main.go cmd/loki-operator/main.go
COPY internal/ internal/

# Build
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on GOARCH=$(cat /goarch) GOARM=$(cat /goarm) go build -a -o manager cmd/loki-operator/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
`);
    expect(v.some(v => v.rule === 'DL3029')).toBe(true);    // Do not use --platform flag with FROM
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('operator/bundle/community-openshift/bundle.Dockerfile: 1 rules (DV4005)', () => {
    const v = lintContent(`FROM scratch

# Core bundle labels.
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=loki-operator
LABEL operators.operatorframework.io.bundle.channels.v1=alpha
LABEL operators.operatorframework.io.bundle.channel.default.v1=alpha
LABEL operators.operatorframework.io.metrics.builder=operator-sdk-unknown
LABEL operators.operatorframework.io.metrics.mediatype.v1=metrics+v1
LABEL operators.operatorframework.io.metrics.project_layout=go.kubebuilder.io/v4

# Labels for testing.
LABEL operators.operatorframework.io.test.mediatype.v1=scorecard+v1
LABEL operators.operatorframework.io.test.config.v1=tests/scorecard/

# Copy files to locations specified by labels.
COPY ./manifests /manifests/
COPY ./metadata /metadata/
COPY ./tests/scorecard /tests/scorecard/
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('operator/bundle/community/bundle.Dockerfile: 1 rules (DV4005)', () => {
    const v = lintContent(`FROM scratch

# Core bundle labels.
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=loki-operator
LABEL operators.operatorframework.io.bundle.channels.v1=alpha
LABEL operators.operatorframework.io.bundle.channel.default.v1=alpha
LABEL operators.operatorframework.io.metrics.builder=operator-sdk-unknown
LABEL operators.operatorframework.io.metrics.mediatype.v1=metrics+v1
LABEL operators.operatorframework.io.metrics.project_layout=go.kubebuilder.io/v4

# Labels for testing.
LABEL operators.operatorframework.io.test.mediatype.v1=scorecard+v1
LABEL operators.operatorframework.io.test.config.v1=tests/scorecard/

# Copy files to locations specified by labels.
COPY ./manifests /manifests/
COPY ./metadata /metadata/
COPY ./tests/scorecard /tests/scorecard/
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('operator/bundle/openshift/bundle.Dockerfile: 1 rules (DV4005)', () => {
    const v = lintContent(`FROM scratch

# Core bundle labels.
LABEL operators.operatorframework.io.bundle.mediatype.v1=registry+v1
LABEL operators.operatorframework.io.bundle.manifests.v1=manifests/
LABEL operators.operatorframework.io.bundle.metadata.v1=metadata/
LABEL operators.operatorframework.io.bundle.package.v1=loki-operator
LABEL operators.operatorframework.io.bundle.channels.v1=stable
LABEL operators.operatorframework.io.bundle.channel.default.v1=stable
LABEL operators.operatorframework.io.metrics.builder=operator-sdk-unknown
LABEL operators.operatorframework.io.metrics.mediatype.v1=metrics+v1
LABEL operators.operatorframework.io.metrics.project_layout=go.kubebuilder.io/v4

# Labels for testing.
LABEL operators.operatorframework.io.test.mediatype.v1=scorecard+v1
LABEL operators.operatorframework.io.test.config.v1=tests/scorecard/

# Copy files to locations specified by labels.
COPY ./manifests /manifests/
COPY ./metadata /metadata/
COPY ./tests/scorecard /tests/scorecard/
`);
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('operator/calculator.Dockerfile: 1 rules (DV1009)', () => {
    const v = lintContent(`# Build the calculator binary
FROM golang:1.25.7 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY api/ api/
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/size-calculator/main.go main.go
COPY internal/ internal/

# Build
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -o size-calculator main.go

# Use distroless as minimal base image to package the size-calculator binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/size-calculator .
USER 65532:65532

ENTRYPOINT ["/size-calculator"]
`);
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
  });

  it('production/helm/loki/src/helm-test/Dockerfile: 4 rules (DV1005, DV1006, DV1008, DV1009)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26
FROM golang:\${GO_VERSION} as build

# build via Makefile target helm-test-image in root
# Makefile. Building from this directory will not be
# able to access source needed in rest of repo.
COPY . /src/loki
WORKDIR /src/loki
RUN make clean && make BUILD_IN_CONTAINER=false helm-test

FROM gcr.io/distroless/static:debug
COPY --from=build /src/loki/production/helm/loki/src/helm-test/helm-test /usr/bin/helm-test
ENTRYPOINT [ "/usr/bin/helm-test" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
  });

  it('tools/bigtable-backup/Dockerfile: 8 rules (DL3013, DL3018, DL3042, DL3045, DL3057, DV1006, ...)', () => {
    const v = lintContent(`FROM       grafana/bigtable-backup:master-18e7589
RUN        apk add --update --no-cache python3 python3-dev git \\
            && pip3 install --no-cache-dir --upgrade pip
COPY       bigtable-backup.py bigtable-backup.py
COPY       requirements.txt requirements.txt
RUN        pip3 install -r requirements.txt
ENTRYPOINT ["usr/bin/python3", "bigtable-backup.py"]
`);
    expect(v.some(v => v.rule === 'DL3013')).toBe(true);    // Pin versions in pip. Instead of `pip install pip` 
    expect(v.some(v => v.rule === 'DL3018')).toBe(true);    // Pin versions in apk add. Instead of `apk add pytho
    expect(v.some(v => v.rule === 'DL3042')).toBe(true);    // Avoid use of cache directory with pip. Use `pip in
    expect(v.some(v => v.rule === 'DL3045')).toBe(true);    // COPY to a relative destination without WORKDIR set
    expect(v.some(v => v.rule === 'DL3057')).toBe(true);    // HEALTHCHECK instruction missing
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "grafana/bigtable-backup" with a 
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
  });

  it('tools/dev/loki-tsdb-storage-s3/dev.dockerfile: 5 rules (DL3020, DV1006, DV1009, DV4003, DV4005)', () => {
    const v = lintContent(`FROM golang:1.24
ENV CGO_ENABLED=0
RUN go install github.com/go-delve/delve/cmd/dlv@v1.24.2

FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

RUN     mkdir /loki
WORKDIR /loki
ADD     ./loki ./
ADD     ./.src ./src
COPY --from=0 /go/bin/dlv ./
`);
    expect(v.some(v => v.rule === 'DL3020')).toBe(true);    // Use COPY instead of ADD for files and folders
    expect(v.some(v => v.rule === 'DV1006')).toBe(true);    // No USER instruction found. Container will run as r
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4005')).toBe(true);    // No CMD or ENTRYPOINT instruction found in the fina
  });

  it('tools/stream-generator/Dockerfile: 5 rules (DV1005, DV1008, DV1009, DV4003, DV4010)', () => {
    const v = lintContent(`ARG GO_VERSION=1.26

# Go build stage
FROM golang:\${GO_VERSION} AS build
COPY . /src/loki
WORKDIR /src/loki
RUN CGO_ENABLED=0 go build -o stream-generator ./tools/stream-generator/main.go

# Final stage
FROM gcr.io/distroless/static:debug

COPY --from=build /src/loki/stream-generator /usr/bin/stream-generator

SHELL [ "/busybox/sh", "-c" ]

RUN addgroup -g 10001 -S streamgenerator && \\
    adduser -u 10001 -S streamgenerator -G streamgenerator && \\
    chown -R streamgenerator:streamgenerator /usr/bin/stream-generator && \\
    ln -s /busybox/sh /bin/sh

USER 10001
EXPOSE 9090
ENTRYPOINT [ "/usr/bin/stream-generator" ]
`);
    expect(v.some(v => v.rule === 'DV1005')).toBe(true);    // When using COPY with broad sources, ensure a .dock
    expect(v.some(v => v.rule === 'DV1008')).toBe(true);    // COPY . copies the entire build context. Consider c
    expect(v.some(v => v.rule === 'DV1009')).toBe(true);    // Consider pinning "golang" with a digest (e.g., ima
    expect(v.some(v => v.rule === 'DV4003')).toBe(true);    // No WORKDIR set. Use WORKDIR to define the working 
    expect(v.some(v => v.rule === 'DV4010')).toBe(true);    // Recursive chown -R increases layer size. Consider 
  });

});