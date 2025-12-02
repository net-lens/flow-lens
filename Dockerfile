# syntax=docker/dockerfile:1.6

FROM ubuntu:22.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      apt-transport-https \
      ca-certificates \
      curl \
      clang \
      llvm \
      jq \
      libelf-dev \
      libpcap-dev \
      libbpf-dev \
      libbfd-dev \
      binutils-dev \
      build-essential \
      make \
      linux-tools-generic \
      bpfcc-tools \
      python3-pip \
      golang-go \
      git \
      flex \
      bison \
      sudo \
      gcc-multilib \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

FROM base AS builder
ARG TARGETARCH
ARG GO_VERSION=1.21.5
RUN case "${TARGETARCH}" in \
      amd64) GO_ARCH=amd64 ;; \
      arm64) GO_ARCH=arm64 ;; \
      ppc64le) GO_ARCH=ppc64le ;; \
      s390x) GO_ARCH=s390x ;; \
      riscv64) GO_ARCH=riscv64 ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz
ENV GOPATH=/go
ENV PATH=/usr/local/go/bin:${GOPATH}/bin:${PATH}
RUN mkdir -p "${GOPATH}"
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN chmod +x ./run_clang.sh && ./run_clang.sh
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /workspace/bin/flow-lens ./src

FROM ubuntu:22.04 AS runner
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libelf1 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /workspace/bin/flow-lens /usr/local/bin/flow-lens
COPY --from=builder /workspace/bpf ./bpf
ENV METRICS_ADDR=:2112
ENTRYPOINT ["/usr/local/bin/flow-lens"]

