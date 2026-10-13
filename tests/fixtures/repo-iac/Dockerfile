FROM node:latest
# USER の指定が無いので root で動く
ARG NPM_TOKEN=npm_dummytokenfortest0000000000
ENV DATABASE_PASSWORD=dummy_password_value
COPY . .
# 秘密のファイルを入れてから、後の層で消している（COPY の層に残る）
COPY .npmrc ./
RUN npm ci \
  && rm -f .npmrc \
  && npm run build
CMD ["node", "server.js"]
