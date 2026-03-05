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
