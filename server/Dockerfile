# Zero-dependency server, so there is nothing to install and no lockfile.
FROM node:22-alpine

WORKDIR /app
COPY server.mjs ./

# The dashboard is mounted at /dashboard by compose; serving it from here
# gives one origin for both the page and the API, which sidesteps CORS
# entirely for the common case.
ENV STATIC_DIR=/dashboard \
    STATE_FILE=/data/state.json \
    PORT=8787 \
    HOST=0.0.0.0

# Rotated refresh tokens persist here across restarts.
VOLUME ["/data"]

# Runs unprivileged; the node image ships a `node` user.
RUN mkdir -p /data && chown -R node:node /data
USER node

EXPOSE 8787
CMD ["node", "server.mjs"]
