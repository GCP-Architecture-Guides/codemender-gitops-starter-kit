# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# you may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This code is for PoC environment only.
# This demo code is not built for production workload.

# Stage 1: Static Next.js UI, taken from the image that was serving all three services on
# 2026-10-22 (pinned by digest), so the dashboard stays byte-identical.
# Why not build from source: frontend/package.json mixes the Juice Shop sample's Angular
# dependencies with the Next.js dashboard and has no committed lockfile. A fresh `npm install`
# is not reproducible and fails on npm 10.8 ("Cannot read properties of null (reading 'edgesOut')").
# The frontend source has not changed since that image was built (883f87e).
# To rebuild the UI from source: restore the node:20-alpine stage (npm install + npx next build)
# and commit a package-lock.json that matches frontend/package.json.
FROM us-central1-docker.pkg.dev/your-gcp-project-id/cloud-run-source-deploy/codemender-backend@sha256:9e73724ba937095cd9fae9fd3cdcb3340045d3696b5bdd462d972f98a73355d8 AS frontend-builder

# Stage 2: Build the production runtime container
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app


# Install system dependencies (polyglot compilers, build essentials, and networking utilities)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    build-essential \
    gcc \
    g++ \
    make \
    golang-go \
    netcat-openbsd \
    sqlite3 \
    default-jdk \
    maven \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory "*" \
    && npm install -g express axios body-parser sqlite3

# Unprivileged runtime user (plan 1.2). The app and every cm subprocess it starts run as this
# user, so the agent can't install packages (apt) or modify the image's code and tools, all of
# which stay root-owned. Writable locations: $HOME (~/.codemender), /tmp (workspaces) and the
# Go paths below. HOME is set at the end, after the root build steps.
RUN useradd --create-home --uid 10001 --shell /bin/bash codemender

ENV NODE_PATH=/usr/local/lib/node_modules
ENV GOPATH=/opt/go
ENV GOCACHE=/opt/go-cache
ENV GO111MODULE=auto
ENV CGO_ENABLED=1

# Pre-populate and compile github.com/mattn/go-sqlite3 in GOPATH so single-file Go samples
# (`vulnerable_app.go` with no go.mod) build and run offline inside `cm verify`. GOPATH and the
# warm build cache belong to the runtime user, which needs a writable Go cache.
RUN git clone --depth 1 --branch v1.14.22 https://github.com/mattn/go-sqlite3.git /opt/go/src/github.com/mattn/go-sqlite3 \
    && rm -rf /opt/go/src/github.com/mattn/go-sqlite3/.git \
    && go install github.com/mattn/go-sqlite3 \
    && printf 'package main\nimport (\n\t"database/sql"\n\t_ "github.com/mattn/go-sqlite3"\n)\nfunc main() { _, _ = sql.Open("sqlite3", ":memory:") }\n' > /tmp/go_sqlite_smoke.go \
    && go build -o /tmp/go_sqlite_smoke /tmp/go_sqlite_smoke.go \
    && /tmp/go_sqlite_smoke \
    && rm -f /tmp/go_sqlite_smoke /tmp/go_sqlite_smoke.go \
    && chown -R codemender:codemender /opt/go /opt/go-cache


# Install python dependencies (constraints pin the exact versions of the currently deployed image)
COPY backend/requirements.txt backend/constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

# Copy backend files
COPY backend/ ./

# Copy Next.js static output from Stage 1 into the folder served by FastAPI StaticFiles
COPY --from=frontend-builder /app/frontend/out ./frontend/out

# Install the CodeMender CLI inside the container path.
# Pinned (not the moving `stable` channel) so every build is reproducible. 0.16.0 is the version
# validated on 2026-10-22. Bump deliberately and re-test find/verify/fix when changing it.
# The download is verified against CM_CLI_SHA256 (sha256 of the 0.16.0 linux-amd64 zip, recorded
# 2026-10-23); update both values together when bumping the version.
ARG CM_CLI_VERSION=0.16.0
ARG CM_CLI_SHA256=a78f89337e567092c1238ca57ecd44769438469f278bacefb0442312dd212cc0
RUN curl -fsSL -o cm-linux-amd64.zip "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3A${CM_CLI_VERSION}%3Acm-linux-amd64.zip:download?alt=media" \
    && echo "${CM_CLI_SHA256}  cm-linux-amd64.zip" | sha256sum -c - \
    && unzip cm-linux-amd64.zip \
    && chmod +x cm \
    && mv cm /usr/local/bin/cm \
    && rm cm-linux-amd64.zip \
    && cm --version

# The cm OS-level sandbox stays on (the cm >= 0.16 default); this image never disables it.
# Emergency lever only: an operator can set CM_DISABLE_SANDBOX=true on the Cloud Run service
# (the cm env allowlist in backend/cm_tools.py forwards it to the CLI).

# 9080, not 8080: cm verification starts sample apps on common ports such as Spring's 8080 (plan 5.5).
EXPOSE 9080
ENV HOME=/home/codemender
RUN chown -R codemender:codemender /home/codemender
USER codemender
CMD python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-9080}
