# 題材: CI のスクリプトだけが LLM を呼び、生成物を CMS へ公開する構成

`tests/run.sh` の事前の洗い出し（0・16・20 節）の検査に使う。コードは動かない。

- `app/` は LLM を呼ばない（アプリ自身は呼んでいない）
- `scripts/gen.mjs` が LLM の API を呼び、生成した HTML を CMS へ書き込む
- `.github/workflows/gen.yml`
  - 穴のある側: 手動実行の入力を `run:` に直接入れる。LLM の鍵をジョブ全体の `env:` に置く
  - 正しく作った側: 入力と CMS の鍵を、使うステップの `env:` から渡す。外部の値は `with:` の引数として渡すだけ
