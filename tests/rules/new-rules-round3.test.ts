import { describe, it, expect } from 'vitest';
import { lintDockerfile, hasRule } from '../helpers';

// =============================================================================
// DV3045: Azure credential value patterns
// =============================================================================
describe('DV3045: Azure credential patterns', () => {
  it('should detect Azure Storage connection string in ENV', () => {
    const v = lintDockerfile(`
FROM node:18
ENV AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ==;EndpointSuffix=core.windows.net"
`);
    expect(hasRule(v, 'DV3045')).toBe(true);
  });

  it('should detect AccountKey in RUN', () => {
    const v = lintDockerfile(`
FROM node:18
RUN az storage blob upload --connection-string "DefaultEndpointsProtocol=https;AccountName=store1;AccountKey=AABBCCDD1234567890abcdefghijklmn=="
`);
    expect(hasRule(v, 'DV3045')).toBe(true);
  });

  it('should detect Azure Cosmos DB connection string', () => {
    const v = lintDockerfile(`
FROM node:18
ENV COSMOS_CONN="AccountEndpoint=https://mydb.documents.azure.com:443/;AccountKey=xyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefgh=="
`);
    expect(hasRule(v, 'DV3045')).toBe(true);
  });

  it('should detect Azure Service Bus connection string', () => {
    const v = lintDockerfile(`
FROM node:18
ENV SERVICEBUS_CONN="Endpoint=sb://mybus.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abcdefghijklmnopqrstuvwxyz012345678901234567=="
`);
    expect(hasRule(v, 'DV3045')).toBe(true);
  });

  it('should detect SharedAccessSignature', () => {
    const v = lintDockerfile(`
FROM node:18
ENV SAS="SharedAccessSignature=sv=2021-06-08;sig=abcdefghijklmnop%2Bqrstuvwxyz=="
`);
    expect(hasRule(v, 'DV3045')).toBe(true);
  });

  it('should NOT flag Dockerfile without Azure credentials', () => {
    const v = lintDockerfile(`
FROM node:18
ENV AZURE_REGION=eastus
RUN echo "Hello Azure"
`);
    expect(hasRule(v, 'DV3045')).toBe(false);
  });

  it('should NOT flag AccountKey with variable reference', () => {
    const v = lintDockerfile(`
FROM node:18
RUN echo "AccountKey=\${STORAGE_KEY}"
`);
    expect(hasRule(v, 'DV3045')).toBe(false);
  });
});

// =============================================================================
// DV8006: Multi-stage build - final stage copies build tool directories
// =============================================================================
describe('DV8006: Final stage copies build tool directories', () => {
  it('should detect COPY --from=builder /usr/local/include', () => {
    const v = lintDockerfile(`
FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /usr/local/include /usr/local/include
COPY --from=builder /app /app
`);
    expect(hasRule(v, 'DV8006')).toBe(true);
  });

  it('should detect COPY --from=builder /usr/local/ (broad)', () => {
    const v = lintDockerfile(`
FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /usr/local/ /usr/local/
`);
    expect(hasRule(v, 'DV8006')).toBe(true);
  });

  it('should detect COPY --from=0 /usr/src', () => {
    const v = lintDockerfile(`
FROM gcc:12
RUN gcc -o /app main.c

FROM debian:bookworm-slim
COPY --from=0 /usr/src /usr/src
COPY --from=0 /app /app
`);
    expect(hasRule(v, 'DV8006')).toBe(true);
  });

  it('should detect COPY --from=builder /usr/share/man', () => {
    const v = lintDockerfile(`
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y gcc

FROM ubuntu:22.04
COPY --from=builder /usr/share/man /usr/share/man
`);
    expect(hasRule(v, 'DV8006')).toBe(true);
  });

  it('should detect COPY --from=builder /root/.cache/go-build', () => {
    const v = lintDockerfile(`
FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /root/.cache/go-build /root/.cache/go-build
`);
    expect(hasRule(v, 'DV8006')).toBe(true);
  });

  it('should NOT flag COPY --from=builder /app (specific artifact)', () => {
    const v = lintDockerfile(`
FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /app /app
`);
    expect(hasRule(v, 'DV8006')).toBe(false);
  });

  it('should NOT flag single-stage builds', () => {
    const v = lintDockerfile(`
FROM node:18
COPY . .
RUN npm install
`);
    expect(hasRule(v, 'DV8006')).toBe(false);
  });

  it('should NOT flag COPY without --from in multi-stage', () => {
    const v = lintDockerfile(`
FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY ./config /config
`);
    expect(hasRule(v, 'DV8006')).toBe(false);
  });
});

// =============================================================================
// DV6025: go build without -trimpath
// =============================================================================
describe('DV6025: go build without -trimpath', () => {
  it('should detect go build without -trimpath', () => {
    const v = lintDockerfile(`
FROM golang:1.21
WORKDIR /app
COPY . .
RUN go build -o /bin/myapp .
`);
    expect(hasRule(v, 'DV6025')).toBe(true);
  });

  it('should detect go install without -trimpath', () => {
    const v = lintDockerfile(`
FROM golang:1.21
RUN go install github.com/example/tool@latest
`);
    expect(hasRule(v, 'DV6025')).toBe(true);
  });

  it('should NOT flag go build with -trimpath', () => {
    const v = lintDockerfile(`
FROM golang:1.21
RUN go build -trimpath -o /bin/myapp .
`);
    expect(hasRule(v, 'DV6025')).toBe(false);
  });

  it('should NOT flag go build with -trimpath in ldflags combo', () => {
    const v = lintDockerfile(`
FROM golang:1.21
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /bin/myapp .
`);
    expect(hasRule(v, 'DV6025')).toBe(false);
  });

  it('should NOT flag RUN without go build', () => {
    const v = lintDockerfile(`
FROM golang:1.21
RUN go mod download
RUN go test ./...
`);
    expect(hasRule(v, 'DV6025')).toBe(false);
  });

  it('should detect go build in multi-command RUN', () => {
    const v = lintDockerfile(`
FROM golang:1.21
RUN cd /app && go build -o server .
`);
    expect(hasRule(v, 'DV6025')).toBe(true);
  });
});
