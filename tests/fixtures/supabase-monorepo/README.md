# 題材: Supabase のプロジェクトを 2 つ持つモノレポ

`audit_grep.sh` の 0 節と 19 節の検査に使う。リポジトリの根に `supabase/` も `package.json` も無く、サービスごとに Supabase のプロジェクトを置く。

- 0 節は、根に無い置き場も見て「マネージドの基盤: 有 → Supabase」と言うべき
- 19 節の「RLS を有効にしていないテーブル」は、プロジェクトごとに突き合わせる。`services/notes` の `accounts` は RLS が無いので ★。
  同じ名前の表を `services/billing` では有効にしているが、別のプロジェクトなので打ち消さない
