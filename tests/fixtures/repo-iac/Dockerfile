FROM node:latest
# USER の指定が無いので root で動く
ARG NPM_TOKEN=npm_dummytokenfortest0000000000
ENV DATABASE_PASSWORD=dummy_password_value
COPY . .
RUN npm ci && npm run build
CMD ["node", "server.js"]
