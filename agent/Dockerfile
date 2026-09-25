# CertPortal on-prem agent image. Build from the repo root:
#   docker build -f agent/Dockerfile -t certportal/agent:latest .
FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production

# install only the agent's runtime deps at the image root so shared modules
# under /app/src resolve them
COPY agent/package.json ./package.json
RUN npm install --omit=dev

# shared PAN-OS ops (kept in sync with the control plane) + the agent
COPY src/config.js ./src/config.js
COPY src/services/panos ./src/services/panos
COPY agent ./agent

USER node
VOLUME ["/data"]
CMD ["node", "agent/index.js"]
