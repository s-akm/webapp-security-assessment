# tests/docker/Dockerfile — Linux（GNU の grep / sed、mawk）で検査を回すためのイメージ
#
#   docker build -t wsa-linux tests/docker
#   docker run --rm -v "$PWD":/src:ro wsa-linux
#
# macOS の BSD 版の道具だけで確かめていると、GNU との違い（sed の拡張、awk の実装、
# cut の文字の数え方）で壊れていても気づけない。Playwright 入りのイメージを土台にして、
# browser_probe.mjs の実地検査まで省略せずに回す。版は package.json の playwright に合わせる。
FROM mcr.microsoft.com/playwright:v1.63.0-noble
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      git dnsutils python3 python3-openpyxl zip unzip perl mawk openssl \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/mawk /usr/local/bin/awk
ENV LANG=C.UTF-8
WORKDIR /work
# リポジトリは読み取り専用で /src に渡し、コンテナの中で写してから回す（手元の tests/tmp を汚さない）
CMD ["bash", "-c", "cp -r /src /work/r && cd /work/r && npm install --silent --no-audit --no-fund >/dev/null 2>&1; ./tests/run.sh"]
