# Pinned by digest for supply-chain reproducibility (OpenSSF Scorecard
# Pinned-Dependencies). Dependabot's docker ecosystem tracks this and opens a
# bump PR when OSS-Fuzz publishes a new base-builder-python.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:25c7fcf0ea816f1532266bad1e38f5d8380eec72c8efe372c42664d64c55478e

COPY . $SRC/agent-guardian
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
WORKDIR $SRC/agent-guardian
