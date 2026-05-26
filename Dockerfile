# syntax=docker/dockerfile:1.6
#
# AgentGuardian Open — primary Dockerfile.
#
# This image builds agent-guardian from local source. Once v1.0.0 ships on
# PyPI (M15), the recommended path will be the PyPI-install variant noted
# below. For now, building from source is the most reliable way to track
# active development.
#
# --- PyPI-install variant (uncomment after M15 PyPI release) ---------------
# FROM python:3.11-slim
# ARG AG_VERSION
# RUN apt-get update && apt-get install -y --no-install-recommends \
#         libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libjpeg62-turbo \
#         libcairo2 fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
# RUN pip install --no-cache-dir "agent-guardian${AG_VERSION:+==$AG_VERSION}"
# RUN useradd -m -u 1000 ag
# USER ag
# WORKDIR /home/ag
# EXPOSE 7474
# ENTRYPOINT ["agent-guardian"]
# CMD ["--help"]
# ---------------------------------------------------------------------------

FROM python:3.11-slim

# Native libraries required by WeasyPrint for PDF report rendering, plus
# default fonts so generated PDFs look reasonable out of the box.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libjpeg62-turbo \
        libcairo2 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Build the wheel from the working copy and install it. We do not copy any
# build artefacts back out — the image just runs the installed console
# script.
COPY . /tmp/agent-guardian
RUN pip install --no-cache-dir uv \
    && cd /tmp/agent-guardian \
    && uv build \
    && pip install dist/*.whl \
    && rm -rf /tmp/agent-guardian /root/.cache

# Run as a non-root user with a writable HOME for the local cache.
RUN useradd -m -u 1000 ag
USER ag
WORKDIR /home/ag

# Dashboard port (M12).
EXPOSE 7474

ENTRYPOINT ["agent-guardian"]
CMD ["--help"]
