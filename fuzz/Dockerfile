# ----------------------------
#  Amulet-Core Fuzz Container
# ----------------------------
# Multi-stage build provides a tiny runtime surface while
# keeping build tooling out of the final image.

# ---------- Stage 1: builder ----------
FROM rustlang/rust:nightly AS builder
LABEL stage=builder

# Install cargo-fuzz (needed only during build)
RUN cargo install cargo-fuzz --locked --root /usr/local && \
    rustup component add llvm-tools-preview

# Create non-root user early so cargo builds in user space
ARG USERNAME=fuzzer
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# Prepare workdir
WORKDIR /code

# Copy source – assuming build context is repo root (amulet-core)
COPY . .

# Build fuzz targets in release-like mode (debuginfo kept for sanitizers)
WORKDIR /code/fuzz
RUN cargo fuzz build --release

# ---------- Stage 2: runtime ----------
FROM debian:bullseye-slim AS runtime
LABEL org.opencontainers.image.source="github.com/amulet-framework/amulet-core"

# Minimal runtime deps for ASAN/UBSAN symbolizer
RUN apt-get update && \
    apt-get install -y --no-install-recommends libstdc++6 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Re-create user to match UID/GID from builder
ARG USERNAME=fuzzer
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

WORKDIR /home/${USERNAME}/fuzz

# Copy built binaries + corpora from builder stage
COPY --from=builder /code/fuzz/fuzz ./fuzz
COPY --from=builder /code/fuzz/target ./target
COPY --from=builder /code/fuzz/corpus ./corpus
COPY --from=builder /code/fuzz/seeds ./seeds

# Ensure user owns working dir
RUN chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}

USER ${USERNAME}

# By default just print available targets; CI overrides the CMD
CMD ["/bin/bash", "-c", "ls -1 fuzz/* | sed 's#.*/##' | sort"] 