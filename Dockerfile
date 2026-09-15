# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

# Stage 1: Build the static Next.js UI
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npx next build

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
    && git config --global --add safe.directory "*" \
    && npm install -g express axios body-parser sqlite3

ENV NODE_PATH=/usr/local/lib/node_modules

# Install python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend files
COPY backend/ ./

# Copy Next.js static output from Stage 1 into the folder served by FastAPI StaticFiles
COPY --from=frontend-builder /app/frontend/out ./frontend/out

# Install the CodeMender CLI inside the container path
RUN curl -L -o cm-linux-amd64.zip "https://artifactregistry.googleapis.com/download/v1/projects/cmoc-prod/locations/us/repositories/codemender-cli-production/files/cm%3Astable%3Acm-linux-amd64.zip:download?alt=media" \
    && unzip cm-linux-amd64.zip \
    && chmod +x cm \
    && mv cm /usr/local/bin/cm \
    && rm cm-linux-amd64.zip

EXPOSE 8080
CMD python3 -m uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
