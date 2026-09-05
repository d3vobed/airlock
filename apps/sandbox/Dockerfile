# AIRLOCK sandbox image.
#
# Minimal runtime: Node (for lifecycle/npm install execution) plus the probe.
# Nothing is trusted inside; the workspace/artifact is mounted read-only and
# outbound network is disabled at run time (--network none).
FROM node:20-alpine

WORKDIR /app

# Nothing else. Host paths, secrets, or ~/.ssh are never mounted at runtime.