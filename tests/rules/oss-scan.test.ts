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
