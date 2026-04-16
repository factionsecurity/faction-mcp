FROM node:alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tsconfig.json ./
RUN npm run build

FROM node:alpine AS release
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./
COPY --from=builder /app/package-lock.json ./
ENV NODE_ENV=production
RUN npm ci --ignore-scripts --omit-dev
USER node
ENTRYPOINT ["node", "dist/index.js"]
