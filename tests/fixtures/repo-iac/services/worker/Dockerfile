# 正しく作った側。前の段で入れて消したものは配るイメージに入らず、同じ RUN で書き出して消したものは層に残らない
FROM node:20.17.0 AS build
WORKDIR /app
COPY .npmrc ./
RUN npm ci && rm -f .npmrc
COPY src/ ./src/
RUN npm run build

FROM node:20.17.0-slim
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY config/ ./config/
RUN --mount=type=secret,id=netrc,target=/root/.netrc npm ci --omit=dev
RUN printf 'machine registry.example.test\n' > /root/.netrc && npm run fetch && rm -f /root/.netrc
# RUN rm -f .env
USER node
CMD ["node", "dist/index.js"]
