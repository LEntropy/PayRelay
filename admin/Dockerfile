FROM node:20-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY lib lib
COPY public public
COPY test test
USER node
EXPOSE 8090
CMD ["node", "server.js"]
