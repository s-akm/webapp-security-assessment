<!--
評価者へ（渡す前にこのコメントを消す）
- SQL は references/03-runtime-verification.md の 1 節・3 節のものを、依頼者が一度に流せる形にしたもの
  （ポリシーは storage・realtime のスキーマも一度に取る）。03 を直したら、ここも合わせる
- 対象の構成に無いもの（Storage・Realtime・多要素認証を使っていない等）は、番号ごと消してから渡す
- ロール名（anon / authenticated）とスキーマ名（public）は構成に合わせて書き換える
- 返ってきた結果は台帳に戻す（references/04-findings-register.md の「依頼者の確認の結果を戻す」）
-->

# データベースの設定の確認のお願い

このシートは、**データベースの権限の設定を、読み取りだけで確認する**ためのものです。
評価者がデータベースの管理画面をお預かりすることは避けています。お手元で SQL を実行し、
**返ってきた行をそのまま貼り付けて**ください。

- 所要時間の目安: 15〜20 分
- **判断は不要です。** 「問題があるか」ではなく、**返ってきたもの**をそのまま貼ってください
- **要約しないでください。** 行を省いたり、並べ替えたりすると、判定に必要な情報が落ちます

---

## 記入欄（最初に）

```
サービス名:
対象の環境（本番 / 検証）:
実行した日時:
実行した画面（例: 管理画面の SQL エディタ / psql）:
使ったアカウントの種類（例: 組織の管理者 / 閲覧のみ）:
```

---

## ⚠️ 実行の前に

- **下にある SQL だけを実行してください。** どれも `select`（読み取り）で、設定もデータも変えません
- **SQL を書き換えないでください。** とくに、列を増やしたり `select *` に変えたりしないでください。
  ここで取るのは、テーブル名・権限・設定だけです。**氏名・メールアドレス・電話番号などの中身は取りません**
- 管理画面の SQL エディタは強い権限で動くことがあります。**別の SQL を続けて実行しないでください**
- 結果に、人の名前やメールアドレスのような**個人の情報が見えたら、貼り付けずに止めて**ご連絡ください
- エラーが出た場合は、**エラーの文面をそのまま**貼ってください。それも確認の結果になります

---

## Q1. 行ごとの権限制御が、どのテーブルで有効になっているか

```sql
select schemaname, tablename, rowsecurity
from pg_tables
where schemaname = 'public'
order by rowsecurity, tablename;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q2. 公開の権限があり、行ごとの権限制御が無効なテーブル

```sql
select g.table_name, g.grantee, string_agg(g.privilege_type, ' / ' order by g.privilege_type) as privs
from information_schema.role_table_grants g
join pg_tables t on t.schemaname = g.table_schema and t.tablename = g.table_name
where g.table_schema = 'public'
  and g.grantee in ('anon', 'authenticated', 'PUBLIC')
  and g.privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
  and not t.rowsecurity
group by g.table_name, g.grantee order by g.table_name, g.grantee;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q3. 権限のルール（ポリシー）の一覧

```sql
select schemaname, tablename, policyname, roles, cmd, qual, with_check
from pg_policies
where schemaname in ('public', 'storage', 'realtime')
order by schemaname, tablename, policyname;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q4. 作成者の権限で動く関数と、それを誰が呼べるか

```sql
select n.nspname, p.proname, p.proconfig,
       has_function_privilege('anon', p.oid, 'execute')          as anon_exec,
       has_function_privilege('authenticated', p.oid, 'execute') as auth_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema')
order by n.nspname, p.proname;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q5. ビューの設定

```sql
select n.nspname, c.relname, c.relkind, c.reloptions
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v', 'm') and n.nspname not in ('pg_catalog', 'information_schema')
order by n.nspname, c.relname;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q6. ファイル置き場（バケット）の公開の設定

```sql
select id, public from storage.buckets order by id;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q7. 変更の通知（Realtime）に入っているテーブル

```sql
select p.schemaname, p.tablename, c.relrowsecurity as rls, c.relreplident as replica_identity
from pg_publication_tables p
join pg_class c on c.relname = p.tablename
join pg_namespace n on n.oid = c.relnamespace and n.nspname = p.schemaname
where p.pubname = 'supabase_realtime'
order by p.schemaname, p.tablename;
```

```
返ってきた行数:
結果（そのまま貼り付け）:

```

## Q8. 多要素認証の登録の数（件数だけ）

```sql
select count(*) as total, count(*) filter (where status = 'verified') as verified
from auth.mfa_factors;
```

```
結果（そのまま貼り付け）:

```

---

## ご返送について

- **記入したこのシート**をお送りください
- 実行できなかった番号は、「未実施」と理由（権限が無かった、画面が見つからなかった等）をお書きください。
  **未確認であることが分かるほうが、確認したつもりで進むより安全です**
- 画面の写真を送っていただく場合は、SQL と結果の部分だけにし、鍵や接続文字列が写っていないことをご確認ください
