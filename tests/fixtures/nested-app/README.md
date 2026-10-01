# 題材: アプリ・サービス・基盤の定義を下の階層に置くモノレポ

`audit_grep.sh` が、プロジェクトルートしか見ずに節を丸ごと省いたり、誤った ★ を出したりしないかの検査に使う。
プロジェクトルートには依存の定義も Dockerfile も無く、すべて `apps/`・`services/`・`infra/` の下にある。

- 2d 節: `apps/web/src/middleware.ts` の対象範囲を出す
- 0 節・17 節: `apps/web/Dockerfile` と `apps/api/Dockerfile` を見る。`apps/web/Dockerfile` の `ARG` の秘密と `USER` の無さに ★。
  `.dockerignore` は Dockerfile の置き場ごとに見る（`apps/api` には有り、`apps/web` には無い）。プロジェクトルートに Dockerfile が無いので、
  プロジェクトルートの `.dockerignore` は求めない
- 0 節: `apps/mobile` の Expo、`apps/web` の Clerk・Firebase、`infra/cdk/cdk.json`、`services/chat/supabase` を判定する
- 23 節: 下の階層の Supabase でも Realtime（`.channel(`）を判定する
- 24 節: `services/chat/supabase/config.toml` の SMS の設定を見る
- Convex: `apps/web/convex/` の関数を見る。認証を確かめない `list` に ★、確かめる `mine` には付けない
- 2g 節: `@Body() changes` で受けてサービスに渡す行と、DTO の型の引数を展開して更新に渡す行を並べる。項目を選んで渡す行は並べない
- 19 節: ログインしているかだけで絞る読み取りの方針のうち、持ち主の列（`user_id`）がある `messages` に ★、持ち主の列の無い `rooms` には付けない
