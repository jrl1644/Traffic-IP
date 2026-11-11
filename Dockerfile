FROM node:22-alpine

ENV NODE_ENV=production \
    PORT=8187 \
    DATA_DIR=/data

# ping for the optional Ping check (Admin → Settings). iputils' ping can run as a
# normal user through unprivileged ICMP sockets, which Docker allows by default.
RUN apk add --no-cache iputils

WORKDIR /app
COPY server.js ./
COPY public ./public

# data lives in a volume so it survives container updates
RUN mkdir -p /data && chown -R node:node /data
VOLUME ["/data"]

USER node
EXPOSE 8187

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/api/health" || exit 1

CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
