# supply-baas — audit_grep.sh の 1b / 4d / 9b / 10b / 19〜24 節の題材

Next.js + Supabase + Firebase + Clerk + Convex + GitHub Actions + AI エージェントの設定を 1 つに詰めた、
**実在しない**構成。どの節にも「穴のある側」と「正しく作った側」を 1 つずつ置き、
検出することと、誤って指摘しないことの両方を見る。

- 穴: `profiles` の RLS 未有効、search_path 未固定の定義者権限関数、security_invoker の無いビュー、
  user_metadata による認可、公開バケット、verify_jwt = false、`if true` のルール、
  サーバー側の getSession、LLM の鍵の露出、固定していない Action、run: への注入、
  bypassPermissions、folderOpen、見えない Unicode、
  セッションリプレイのマスク解除と利用者の特定、SMS の API の直接呼び出し
- 正しい側: `orders` の RLS、search_path を固定した関数、security_invoker 付きのビュー、
  `'use client'` のファイル（app/ 配下）での getSession、ハッシュで固定した Action、`ok.yml`

**AI エージェントの設定ファイル（22 節の題材）はここに置かない。** `AGENTS.md` への見えない文字、
`.claude/settings.json` の権限の緩和、`.vscode/tasks.json` の `folderOpen` は、このフォルダを開いた人の
エディタやエージェントで**実際に効いてしまう**。公開リポジトリに置けば、それ自体が攻撃の見本になる。
`tests/run.sh` が一時ディレクトリの中でだけ作る。
