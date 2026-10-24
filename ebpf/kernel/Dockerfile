FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

ARG TARGETARCH
ARG BUILDPLATFORM

# Install clang, libbpf headers, and bpftool for vmlinux.h generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy BPF source and vmlinux.h if checked in
COPY module.bpf.c ./
COPY vmlinux.h* ./

# Generate vmlinux.h if not provided
# Uses the build host's BTF via --mount. Falls back to linux-btf package.
RUN if [ ! -f vmlinux.h ]; then \
      echo "vmlinux.h not found, installing linux-headers for BTF..."; \
      apt-get update && apt-get install -y --no-install-recommends linux-headers-generic && \
      BTF_FILE=$(find /usr/lib/modules -name vmlinux -path '*/btf/*' 2>/dev/null | head -1) && \
      if [ -n "$BTF_FILE" ]; then \
        bpftool btf dump file "$BTF_FILE" format c > vmlinux.h; \
      else \
        echo "ERROR: Cannot generate vmlinux.h. Provide it in the build context."; \
        exit 1; \
      fi; \
    fi && \
    echo "vmlinux.h: $(wc -l < vmlinux.h) lines"

# Compile BPF object for both architectures
# BPF bytecode is arch-independent but needs __TARGET_ARCH_ for struct layout
RUN clang -target bpf -D__TARGET_ARCH_x86 -g -O2 -Wall \
    -I. -c module.bpf.c -o module.x86.bpf.o && \
    clang -target bpf -D__TARGET_ARCH_arm64 -g -O2 -Wall \
    -I. -c module.bpf.c -o module.arm64.bpf.o

# Copy Go loader source
COPY loader/ ./loader/
WORKDIR /build/loader

# Download deps
RUN go mod download

# Build Go binary for target architecture
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -o /loader .

# ---------------------------------------------------------------------------
# Runtime image — minimal
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy loader binary
COPY --from=builder /loader .

# Copy both BPF objects — entrypoint picks the right one at runtime
COPY --from=builder /build/module.x86.bpf.o .
COPY --from=builder /build/module.arm64.bpf.o .

# Entrypoint script selects correct BPF object based on host arch
COPY <<'ENTRYPOINT' /app/entrypoint.sh
#!/bin/sh
set -e
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  BPF_OBJ="/app/module.x86.bpf.o" ;;
    aarch64) BPF_OBJ="/app/module.arm64.bpf.o" ;;
    *)       echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
echo "Arch: $ARCH → $BPF_OBJ"
exec /app/loader "$BPF_OBJ"
ENTRYPOINT
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
