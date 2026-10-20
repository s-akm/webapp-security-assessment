# フェーズ 2 — 実機確認

コードを読んでも分からないことがある。DB の権限が実際にどう設定されているか、バックアップが本当に取れているか、WAF が有効か。**リポジトリに答えが書いていない項目は、実環境を見るまで確定しない。**

このフェーズの目的は、フェーズ 1 で実機確認が必要な項目に挙げたもの（`references/02-code-audit.md` の「監査の成果物」の 3）を、**事実として確定させる**ことだけ。判断や修正は後の工程でやる。

## 目次

[2 つのモード](#2-つのモード) ／ [1. データ層の権限](#1-データ層の権限) ／ [2. 外形テストで裏を取る](#2-外形テストで裏を取る) ／
[3. 認証ポリシー](#3-認証ポリシー) ／ [4. バックアップと復旧](#4-バックアップと復旧) ／ [5. ネットワークとアクセス経路](#5-ネットワークとアクセス経路) ／
[6. 鍵の構成](#6-鍵の構成) ／ [7. 環境の分離](#7-環境の分離) ／ [8. エッジ・WAF・流量制御](#8-エッジwaf流量制御) ／
[9. DNS とメール送信ドメイン](#9-dns-とメール送信ドメイン) ／ [10. 本番エンドポイントの外形テスト](#10-本番エンドポイントの外形テスト)（自前のサーバー 1 台の場合を含む） ／
[11. 運用](#11-運用) ／ [記録のしかた](#記録のしかた)

各項目は「**確定させたい問い**」と「**どこを見るか**」で書いてある。問いは構成によらず共通で、見る場所が構成ごとに変わる。

---

## 2 つのモード

**どちらのモードで実施したかを報告書に書く。** 情報の確度が違うため。混在してよい（SQL は依頼者に実行してもらい、外形テストは自分でやる、など）。

- **モード A — 自分で見に行く**（ブラウザ操作の手段がある場合）。管理画面を開いて設定値を読み、SQL 実行環境があればクエリを流す。
  **認証情報を自分で入力しない**（未ログインなら依頼者にログインを頼む）。画面はスクリーンショットよりページのテキストで読む。
  設定を変更しない。トグルに触れない。ダイアログは開いたら閉じる
- **モード B — 手順を渡して結果を受け取る**（手段が無い、または依頼者が自分で実行したい場合）。**貼り付けてそのまま実行できる形**で
  SQL とコマンドを渡し、「要約して」ではなく「返ってきた行をそのまま貼って」と頼む（要約されると判定に必要な情報が抜ける）。
  画面の設定値は、項目名を列挙して「それぞれの値」を聞く。渡す文面は `templates/client-sql-request.md`（SQL）、
  `templates/client-console-checklist.md`（管理画面）、`templates/client-browser-checklist.md`（ログインが必要なブラウザの確認）

---

## 1. データ層の権限

### 問い

1. 全テーブルで行レベルの権限制御が有効になっているか
2. 匿名／一般利用者の資格に付いた業務データへの読み書き権限が、行レベルの権限制御で絞られているか（RLS を使わない構成なら、権限そのものが付いていないか）
3. 権限ポリシーの対象に、公開ロールが含まれていないか
4. コードに定義が無かったテーブルは実在するか。実在するならその設定はどうなっているか

**この 4 つがこのフェーズで最も重要。** 個人情報が入ったテーブルの権限が開いていれば、他の全ての対策が意味を失う。時間が限られるならここだけでも確定させる。

| 構成 | 確認方法 |
|---|---|
| PostgreSQL（行レベルセキュリティ） | 下の SQL を実行する |
| MySQL / MariaDB | `SHOW GRANTS` でアプリ用ユーザーの権限を確認。行レベル制御は通常アプリ側 |
| MongoDB | ロールとコレクション単位の権限、`db.getUsers()` |
| Firestore / Realtime Database | セキュリティルールの本文を取得して読む |
| DynamoDB | IAM ポリシーの `Resource` と `Condition` |
| 自前 DB + アプリのみで防御 | アプリ用ユーザーの権限範囲と、DB への到達経路を確認 |

### 例: PostgreSQL + 行レベルセキュリティ

下の問い合わせは `public` だけを見る。Supabase で API に出すスキーマ（Exposed schemas）を足していれば、
**`public` の所をそのスキーマに替えて同じ問い合わせをする。** `templates/client-sql-request.md` の Q1・Q2 は全スキーマを見る形にしてある。

```sql
-- 1. 全テーブルの行レベルセキュリティ有効状態（false が 1 つでもあれば要強調）
select schemaname, tablename, rowsecurity
from pg_tables
where schemaname = 'public'
order by rowsecurity, tablename;

-- 2. 公開ロールへの権限付与（ロール名は構成に合わせる）
select table_name, grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and grantee in ('anon', 'authenticated', 'PUBLIC')
order by table_name, grantee;

-- 3. ポリシーの一覧と、その適用対象ロール
select schemaname, tablename, policyname, roles, cmd, qual
from pg_policies
where schemaname = 'public'
order by tablename, policyname;

-- 4. これから作るテーブル・関数・シーケンスに、公開ロールへ自動で付く権限（既定の権限）。
--    ここに公開ロールが出れば、今の権限を外しても、次に作るものに付く
select pg_get_userbyid(d.defaclrole) as creator, n.nspname, d.defaclobjtype, d.defaclacl
from pg_default_acl d left join pg_namespace n on n.oid = d.defaclnamespace
where d.defaclacl::text ~ '(anon|authenticated|=)';

-- 5. コードに定義が無かったテーブルのカラム構成（リポジトリへ復元するために使う）
select table_name, column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public'
  and table_name in (<コード監査 E-2 で列挙したテーブル名>)
order by table_name, ordinal_position;
```

**結果が多い場合**: 2 番は数百行返ることがある。`string_agg` で権限をテーブル×ロール単位にまとめて読んでよいが、
**元のクエリの行数は記録する**。集約後の行数だけでは、後から検算できない。

### GRANT と RLS の読み方

**`GRANT` と RLS は別に見て、同じテーブルで突き合わせる。** 付与があることだけでは判定しない。
公開ロールへの自動の付与の既定は、基盤の版やテーブルを作った時期で違う。付与が無ければ RLS より手前で拒否され、付与があれば RLS の中身が全てになる。

- **RLS を前提にした構成**（Supabase のように、公開ロールのまま API からテーブルを読む構成）では、
  `authenticated` への `SELECT` / `INSERT` / `UPDATE` / `DELETE` の付与は**正常**で、守りは RLS のポリシーが担う。
  公開データを未ログインで読ませるなら `anon` への `SELECT` も正常
- **指摘になるのは、RLS が無効なテーブル（1 番で `rowsecurity = false`）、または素通しのポリシー（次の小節）がある
  テーブルに、公開ロールへの `SELECT` / `INSERT` / `UPDATE` / `DELETE` の付与があるとき。** 付与と RLS の穴が揃うと、
  公開鍵だけで行に届く
- **RLS を使わない構成**（アプリが特権資格で接続し、アプリのガードで守る構成。02 の E-1）では、公開ロールへの付与は
  そもそも不要。付与があれば、それ自体を指摘にする
- `REFERENCES` / `TRIGGER` / `TRUNCATE` はデータを読む権限ではない。ただし `TRUNCATE` は**行レベルのポリシーで止まらない**
  操作なので、DB への直接接続経路と併せて評価する
- **権限を外す是正を指示するときは、既定の権限（4 番）も外す。** `alter default privileges ... revoke` は、`for role` を付けなければ
  **実行したロールが作るもの**にしか作用しない。テーブルを作るロール（Supabase なら `postgres` と `supabase_admin`）ごとに
  `for role <作るロール>` を付ける。外したことの確認は、外した権限の種類だけでなく、2 番の全件と 4 番を数え直す

```sql
-- 公開ロールへのデータの権限があり、RLS が無効なテーブル（RLS 前提の構成では、ここに出たものが指摘になる）
select g.table_name, g.grantee, string_agg(g.privilege_type, ' / ' order by g.privilege_type) as privs
from information_schema.role_table_grants g
join pg_tables t on t.schemaname = g.table_schema and t.tablename = g.table_name
where g.table_schema = 'public'
  and g.grantee in ('anon', 'authenticated', 'PUBLIC')
  and g.privilege_type in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
  and not t.rowsecurity
group by g.table_name, g.grantee order by g.table_name, g.grantee;
```

このクエリは RLS が無効なテーブルだけを出す。RLS が有効で素通しのポリシーを持つテーブルは、次の小節のクエリで洗い出し、
**2 番のクエリ（公開ロールへの付与の全件）**と突き合わせる。

### 有効なだけでは足りない。ポリシーの中身を読む

**「全テーブルで有効」は出発点であって、結論ではない。** 3 番のクエリで取った `qual` を 1 つずつ読む。

| ポリシーの中身 | 意味 |
|---|---|
| `true`（`USING (true)`） | **誰でも通る。** 「全ログインユーザーに許可」のつもりで書かれていることが多いが、対象ロールに公開ロールが入っていれば**未認証でも通る** |
| `auth.uid() = user_id` | 本人の行だけ。意図どおり |
| `user_id = current_setting('...')` のような**クライアント由来の値** | **利用者が自分で名乗った値で絞っている。** 詐称できるなら意味がない |
| `cmd` が `ALL` で `with_check` が無い | 読めるだけのつもりが、書き込みも通る |
| `WITH CHECK (true)`（`INSERT`・`UPDATE`・`ALL`） | **誰でも任意の中身の行を書き込める**（対象ロール次第）。`INSERT` のポリシーは `USING` を持たないので、`qual` ではなく `with_check` を読む |

```sql
-- 素通しになっているポリシーを洗い出す。見る列はコマンドで違う:
--   読む・消す・書き換える行の条件は qual（USING）。INSERT は USING を持たず、qual はいつも空
--   書き込む行の中身の条件は with_check（WITH CHECK）。INSERT はここだけ。UPDATE と ALL は省けば USING が使われる
select tablename, policyname, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
  and (   (cmd <> 'INSERT' and (qual is null or btrim(qual) in ('true', '(true)')))
       or (cmd = 'INSERT' and (with_check is null or btrim(with_check) in ('true', '(true)')))
       or (cmd in ('UPDATE', 'ALL') and btrim(coalesce(with_check, '')) in ('true', '(true)')))
order by tablename;
```

**`roles` を併せて見る。** `USING (true)` でも対象が特定ロールに限られていれば意図した設計かもしれない。**公開ロールが入っているかどうかで判定が変わる。**
直し方は、`USING` と `WITH CHECK` の両方に本人や所属の条件（`auth.uid() = user_id` など）を書き、対象のロールを絞ること。

### 更新ポリシーは「どの列を」変えられるかまで見る

**行レベルのポリシーは行を選ぶだけで、列を区別しない。** `for update using (id = auth.uid())` は「自分の行の、この列だけ」ではない。
利用者のロール・所属組織・有効フラグを `profiles` のようなテーブルに持ち、`is_admin()` がそれを読む構成で、
そのテーブルに「自分の行を更新できる」ポリシーがあれば、**利用者は自分をその組織の管理者にできる。**

```sql
-- 認可の根拠になる列を持つテーブルに、本人が更新できるポリシーが無いか
select tablename, policyname, cmd, qual, with_check
from pg_policies
where schemaname = 'public' and cmd in ('UPDATE', 'ALL')
  and tablename in ('profiles', 'users', 'members', 'accounts')   -- 構成に合わせる
order by tablename;

-- 列レベルの権限で守っているか（無ければ全列が更新できる）
select table_name, column_name, privilege_type, grantee
from information_schema.column_privileges
where table_schema = 'public' and grantee in ('authenticated', 'anon')
order by table_name, column_name;
```

- 更新ポリシーがあり、列レベルの権限も、変更を止めるトリガーも無ければ**指摘**
- 是正は「変更を拒否する `before update` トリガー」か「ポリシーを廃止して RPC に置き換える」。
  **本人が自分の情報を編集する画面が無いなら、ポリシーを消すだけでよい**

### ポリシーを迂回する経路

行レベルのポリシーは、**テーブルを直接読むときにしか適用されない**。次の 3 つは迂回する（Supabase 固有の追加の経路は後述）。

```sql
-- 1. 定義者権限で動く関数（呼び出した人ではなく、作った人の権限で動く）
select n.nspname, p.proname, p.prosecdef
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname not in ('pg_catalog', 'information_schema') and p.prosecdef
order by n.nspname, p.proname;

-- 1b. その関数を公開ロールが実行できるか。PostgreSQL は既定で関数の実行権限を PUBLIC に与える
--     search_path を固定していない（proconfig が空の）定義者権限の関数も、中身を読む対象にする
select n.nspname, p.proname, p.proconfig,
       -- anon / authenticated は Supabase のロール。他の構成では、API が使うロール名に置き換える
       has_function_privilege('anon', p.oid, 'execute')          as anon_exec,
       has_function_privilege('authenticated', p.oid, 'execute') as auth_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema');

-- 2. ビューとマテリアライズドビュー。information_schema.views では security_invoker の有無が分からない
--    reloptions の security_invoker が true / on / 1 / yes のどれでもないビューと、
--    マテリアライズドビュー（relkind = 'm'。行レベルの権限が適用されない）は、すべて中身を読む対象にする
select n.nspname, c.relname, c.relkind, c.reloptions
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v', 'm') and n.nspname not in ('pg_catalog', 'information_schema');
```

- **定義者権限の関数が、API から呼べるスキーマに置かれていないか。** マネージドの PostgREST 系では、`public` に置いた関数は
  既定で RPC として公開され、ログイン済みの誰からでも呼べる。関数の中で呼び出し元の所属を確かめていなければ、
  **その関数が読める範囲がそのまま漏れる**。所属を確かめる関数と確かめない関数が混在していることがあるので、1 本ずつ読む。
  直し方は、API が公開しないスキーマへ移すか、`revoke execute ... from public, anon` で実行権限を外し、関数の中で `auth.uid()` から所属を確かめ、`search_path` を固定すること
- **ビューが呼び出し元の権限で動く設定になっているか**（PostgreSQL 15 以降なら `security_invoker = true`）。
  既定は作成者の権限で、**下のテーブルのポリシーを迂回する**
- 3 番目は**特権鍵**。サーバー側で使う鍵はポリシーを完全に無視する。**その鍵がクライアントに出ていないか**は
  コード監査 C-1 と外形調査（`scripts/recon.sh`）で見る

**この 3 つを確かめずに「データ層の防御は機能している」と書かない。**

**Supabase では、さらに次の経路を見る。** 公式の Security Advisor（ダッシュボードの Advisors）が同じものを
機械的に出すので、**その結果の一覧を依頼者からもらう**のが早い。

| 経路 | 何が起きるか |
|---|---|
| マテリアライズドビュー・外部テーブル | RLS が適用されない |
| ポリシーが `user_metadata`（`raw_user_meta_data`）を参照 | 利用者が自分で書き換えられる値で認可している（02 の A-2） |
| 匿名サインインが有効 | **匿名の利用者も `authenticated` ロールになる。** 「ログイン済みなら読める」ポリシーが匿名にも開く |
| Storage のバケットが `public` | **URL を知っていれば誰でもダウンロードできる**（ポリシーは適用されない） |
| 公開スキーマ（Exposed schemas）の設定 | ここに入ったスキーマのテーブル・関数・ビューが API に出る |
| Realtime の「Allow public access to channels」 | **既定で有効。** 有効な間は、`private: true` を付けない Broadcast / Presence の購読にポリシーの確認が走らず、公開鍵を持つ誰でも購読・送信できる。private を強制するには無効にする（`references/07-web-vulnerabilities.md` の 11-3）。テーブルの変更の購読（Postgres Changes）はこの設定と別に、テーブルの RLS で判定される |
| `pg_graphql` の拡張が有効 | 公開スキーマのテーブルが GraphQL の口からも出る（データは RLS と GRANT で守られる）。**イントロスペクションが有効なら、公開鍵でテーブル名と列名の一覧が取れる。** 使っていなければ拡張ごと外す |
| `supabase_realtime` の publication に入れたテーブル | 各テーブルの RLS と replica identity を突き合わせる。**RLS が無効なテーブルは全行の変更が、`replica identity full` なら削除された行の全列が、公開鍵の購読者に流れる** |

```sql
select schemaname, tablename, policyname from pg_policies
where qual ilike '%user_meta%' or with_check ilike '%user_meta%';
select id, public from storage.buckets;
select policyname, cmd, qual from pg_policies where schemaname = 'storage';
-- Realtime: publication に入れたテーブルと、その RLS・replica identity（'f' が full）
select p.schemaname, p.tablename, c.relrowsecurity as rls, c.relreplident as replica_identity
from pg_publication_tables p
join pg_class c on c.relname = p.tablename
join pg_namespace n on n.oid = c.relnamespace and n.nspname = p.schemaname
where p.pubname = 'supabase_realtime';
-- Realtime: チャネルのポリシーがトピックを照合しているか
select policyname, cmd, roles, qual, with_check from pg_policies where schemaname = 'realtime';
```

---

## 2. 外形テストで裏を取る

設定値を読むだけで終わらせない。**公開されている経路から実際に叩いて、拒否されることを確かめる。** 設定の読み違いや、想定していなかった迂回路がここで見つかる。
本番のフロントエンドが読み込む JS から公開用のエンドポイントと公開鍵を取り出し（`scripts/recon.sh` が取る）、
その公開鍵で個人情報を持つテーブル／コレクションへ**読み取りだけ**リクエストして、拒否されることを確かめる。

```bash
# 例: PostgREST 系の API に対して、公開鍵で読み取りを試す
# select で列を絞り limit 0 にして、実データを取得しないようにする
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "apikey: $PUBLISHABLE_KEY" -H "Authorization: Bearer $PUBLISHABLE_KEY" \
  "https://<endpoint>/rest/v1/<table>?select=id&limit=0"
```

期待値は 401 か 403。**200 が返れば、個人情報を持つテーブルに公開鍵だけで届いている**（`references/04-findings-register.md` の問い 1 で P0）。知らせ方は SKILL.md の「守ること」に従う。

`select *` を使わず、`limit 0` か個人情報でない列だけを指定する（値の扱いは SKILL.md の「守ること」）。拒否された場合はエラー本文（権限エラーのコードとメッセージ）を記録する。それが根拠になる。

### 他の構成での同等の確認

| 構成 | 確認 |
|---|---|
| Firestore / Realtime DB | クライアント SDK でコレクションを読む。ルールで拒否されるか |
| 公開 GraphQL | イントロスペクションが開いていないか、型を跨いだ取得ができないか |
| S3 / オブジェクトストレージ | バケットの一覧取得と、推測可能な URL への直接アクセス |
| 自前 API | 認証ヘッダ無しで、認証必須のはずのエンドポイントを叩く |

---

## 3. 認証ポリシー

### 問い

- パスワードの最小長と、要求する文字種。漏えいパスワードの検知が有効か
- 多要素認証が**有効化できる状態か**、そして**実際に登録している利用者がいるか**（数えるのは要素ではなく利用者。下の SQL）
- 多要素認証を**サーバー側で強制しているか**（運営向けの API と DB のポリシーが `aal2` を求めるか。`references/02-code-audit.md` の B-3）
- メールアドレス・パスワードの変更で、現在のパスワードか再認証を求める設定か（Supabase の Secure email change・Secure password change）
- **管理者の判定に使うメールアドレスの一覧の全件に、本人のアカウントがあるか**（無いアドレスは、新規登録が有効なら第三者が先に取れる。02 の A-2）
- メールアドレスの確認が必須か。認証系のレート制限の値。セッションの有効期限、無操作タイムアウト
- 誰でもサインアップできる状態になっていないか
- **確認コード（メール・SMS・TOTP）の検証に試行の上限があるか**（`references/02-code-audit.md` の B-3）
- リフレッシュトークンの再利用を検知して失効させる設定か。登録・ログインに CAPTCHA を掛けているか
- **認証が終わったあとの戻り先の許可一覧**（Supabase の Site URL と Redirect URLs、Firebase の承認済みドメイン、Auth0・Clerk などの
  Allowed Callback URLs）。第三者も作れるドメインのワイルドカード（プレビュー環境の `*.vercel.app` など）・`localhost` の残り・
  パスの `/**` があれば、マジックリンクや OAuth のトークンが他人の用意した先へ届く（`references/07-web-vulnerabilities.md` の 4 節。
  依頼者に渡すときは `templates/client-console-checklist.md` の 1-5・2-4・9）

**基準は NIST SP 800-63B-4**（`references/02-code-audit.md` の B-1）。パスワードだけで認証するなら最小 15 文字、
文字種の強制と定期変更の強制はしない、漏えい済みパスワードとの照合はする。**設定画面の最小長が 6 や 8 のままなら、
それを事実として記録する。**

**「機能が有効」と「実際に使われている」は別物。** 多要素認証が設定上オンでも、登録者が 0 人なら守られていない。認証基盤に登録済みの要素を数える手段があれば、必ず数える。

```sql
-- 例: 多要素認証の登録実績を数える（テーブル名は基盤に合わせる）。
-- 要素の数ではなく、確認済みの要素を持つ利用者の数を見る（1 人が 2 つ登録すると、要素の数は人数を超える）
select count(*) as factors,
       count(distinct user_id) filter (where status = 'verified') as users_verified
from auth.mfa_factors;
```

**運営の人数と比べるなら、運営の利用者に絞って数える。** 全体の数と運営の人数を比べると、運営以外の登録で数が合ってしまう。
運営の判定に使う表や一覧（02 の A-2）で絞った件数を、依頼者に返してもらう。

見る場所は、マネージド認証（Auth0 / Cognito / Firebase Auth / Supabase Auth / Clerk など）なら管理画面のポリシー設定。
自前実装はコードで確認済みのはずなので、ここでは設定値の外部化がないかだけ見る。

### 管理コンソール自体の多要素認証と監査ログ

**利用者の認証より先に、運営者の入口を見る。** ホスティング・DB・認証基盤・ドメイン登録・メール配信の
管理コンソールが乗っ取られれば、アプリ側の対策はすべて無効になる。

- 各コンソールで、**組織（チーム）として多要素認証を強制しているか**。個人が任意で有効にしているだけか
- メンバーの一覧に、退職者・契約終了先・用途不明のアカウントが残っていないか
- コンソールの操作の監査ログが取れているか（上位プラン限定のことが多い。取れないなら「取れない」と書く）

基盤の側がログインの時点で多要素認証を求めていても、**組織として全メンバーに強制しているかは別に確かめる。**
直し方は、各コンソールの組織（チーム）の設定で多要素認証を必須にし、不要なメンバーを外すこと。

### SMS を送っている場合

**送信先の国と上限の既定は基盤ごとにまったく違う**（国を既定で許可する基盤、既定で止める基盤、国を絞る設定を持たない基盤がある）ので、
既定を思い込まずに管理画面と公式の資料で確かめる（`references/02-code-audit.md` の F-4）。
**見るのは、日本だけを相手にしているのに国を絞っていないか、月額の上限と通知があるか、確認の完了率を見ているか**の 3 つ。
国を絞る設定が基盤に無ければ、SMS の送信元（Twilio など）の側か送信のフックで絞る。送信を伴う試験は本番ではしない。

**プラン制限に注意**: 漏えいパスワード検知、セッション設定、SMS による多要素認証などは、上位プラン限定になっている場合がある。画面に「上位プランで利用可能」と出ていたら、**それは「設定していない」ではなく「設定できない」**。指摘の書き方が変わるので区別して記録する。

---

## 4. バックアップと復旧

### 問い

- バックアップが実際に取得されているか。頻度と保持期間
- ある時点への復旧（PITR）が可能か
- **復元を一度でも試したことがあるか**

取得されているだけで復元したことがないバックアップは、復旧手段として数えない。ここは実機確認というより依頼者への質問になる。
無償プランではバックアップ機能自体が提供されないことがある。**「取っていない」のか「取れない」のかを区別する。** 後者ならプラン変更が対策になる。

**何がバックアップに含まれないかも聞く。** たとえば Supabase では、**Storage のファイル本体はデータベースのバックアップに含まれない**
（復元するとメタデータだけ過去に戻り、ファイルとずれる）。**基盤の外に復旧手段を持つなら別に論理ダンプが必要**。

**ランサムウェアや管理アカウントの乗っ取りを想定するなら、削除できない場所に置いているか**を聞く。
同じ管理コンソールから消せるバックアップは、コンソールを乗っ取られたときに一緒に消える。

**基盤の側の都合で止まる経路も聞く。** 無償プランの休止・削除の条件（一定期間アクセスが無いと休止し、その後に削除される基盤がある）、
請求の失敗で止まるか（支払いのカードの期限切れや持ち主の退職。11 節の運用 2・7）、メール送信・決済・認証基盤が止まったときの代わり。

---

## 5. ネットワークとアクセス経路

### 問い

- DB への接続元 IP が制限されているか
- 暗号化されていない接続が拒否されるか
- 管理画面へのアクセスに制限があるか
- 接続ログが記録されているか

制限が無い場合、それ単体では侵入経路にならない（資格情報が別途必要）が、資格情報が漏れたときの被害範囲を決める。**他の指摘と組み合わせて評価する。**

---

## 6. 鍵の構成

### 問い

- 発行されている鍵の種類と用途（**値は取得しない**）
- 新旧の鍵が並行して有効になっていないか
- 特権のある鍵が、クライアントに配布される側に混ざっていないか
- 鍵をローテーションした記録があるか

サービス側が鍵の方式を刷新したとき、**旧方式の鍵が無効化されずに残る**ことがよくある。管理画面に「旧方式を無効化する」ボタンが残っていれば、それは有効なままという意味。

Supabase の旧方式の `anon` / `service_role` の鍵もその例で、新方式へ移っても管理画面で無効にするまで有効なまま
（鍵の入れ替えの手順は `references/05-remediation-plan.md`）。「ローテーションした記録があるか」を聞く前に、**旧方式の鍵が有効なままか**を確かめる。

**公開前提の鍵で、呼べる API が増えていないか。** Google の `AIza…` の鍵は、同じプロジェクトで
Gemini の API を有効にすると、配布済みの鍵でそのまま呼べるようになる（`references/14-mobile.md` の 1 節）。
**鍵ごとに API の制限が掛かっているか**を見る。

---

## 7. 環境の分離

### 問い

- 本番・検証・開発の環境変数が分かれているか
- **本番の特権鍵が、検証環境にも設定されていないか**
- 検証環境が外部から見えないようになっているか。Vercel なら Deployment Protection の設定を見る。
  **自動生成された URL（プレビューや本番のデプロイごとの URL）が保護の対象から外れていないか**、保護を迂回する共有リンクや
  自動化用のバイパス用シークレットが残っていないかも見る。保護がプランの都合で使えないと言われたら、今のプランで使える保護を公式の資料で確かめる
- 検証環境が本番の DB を向いていないか

検証環境が保護されていれば、特権鍵が入っていること自体の実害は下がる。**ただし「検証ビルドが本番データを壊せる」構図は残る**ので、保護の有無とは別に記録する。

環境変数の値が読み出せない設定（秘匿指定）になっている場合、**値の確認は諦めて未確認事項に残す**。無理に読もうとして設定を壊さない。

**秘匿指定になっているかどうか自体は見る。** 秘匿指定でない環境変数は、管理画面のメンバーや基盤の側の事故で読まれうる。
**特権の鍵が秘匿指定になっているか、本番の値を他の環境と分けているか、特権の鍵が開発環境（手元に平文で保存される）にも
登録されていないか**を確かめる。**`NEXT_PUBLIC_` の付いた変数は、秘匿指定にしてもビルドで JS に埋め込まれて公開される。**
直し方は、特権の鍵を秘匿指定にして本番だけに置き、検証環境には別の鍵（別のプロジェクトの鍵）を入れること。

---

## 8. エッジ・WAF・流量制御

### 問い

- WAF が有効か。マネージドルールセットが適用されているか
- BOT 対策が有効か
- レート制限のルールが設定されているか
- 攻撃時に切り替えるモードが用意されているか、その現在の状態

**エッジを迂回してオリジンへ直接届かないか。** CDN や WAF を前に置いていても、オリジンの IP やホスト名に
直接アクセスできれば、WAF もレート制限も迂回される。Cloudflare なら、SSL/TLS のモードが Flexible
（オリジンまで平文）になっていないか、オリジン側で Cloudflare 以外からの接続を拒否しているか
（Authenticated Origin Pulls、Tunnel、IP の許可リスト）を見る。

フェーズ 1 の F-2 で「アプリ側のレート制限が実質機能しない」と判定した場合、ここで**二重に無い状態**になっていないかを確かめる。両方無ければ、指摘の優先度を上げる。

---

## 9. DNS とメール送信ドメイン

アプリのコードには一切現れないが、なりすましの成否を決める。

### 問い

- 送信ドメイン認証（SPF / DKIM / DMARC）が設定されているか。DMARC が監視のみ（`p=none`）で止まっていないか
  （**サブドメイン向けの `sp=` と、存在しないサブドメイン向けの `np=` も見る**）
- DMARC の集計レポート（`rua`）を受け取っているか。**受け取っていなければ、誰も運用していない**
- CAA があるか。DNSSEC が有効か。証明書の更新が自動化されているか
- **使われなくなったサブドメインの CNAME が残っていないか**（サブドメインの乗っ取り）

```bash
dig +short TXT   <domain>          # SPF
dig +short TXT   _dmarc.<domain>   # DMARC
dig +short CAA   <domain>
dig +short DS    <domain>          # DNSSEC
dig +short MX    <domain>
dig +short TXT   _mta-sts.<domain> ; dig +short TXT _smtp._tls.<domain>   # MTA-STS / TLS-RPT
```

**サブドメインの URL しか分からないときは、親へ遡って引く。** DMARC と CAA は親へ遡って探され、DS はゾーンの頂点にしか無い。
`app.example.com` が空でも `example.com` に設定があることは普通にある（`scripts/recon.sh` は親へ遡って探す）。
SPF・DKIM も URL のホスト名ではなく組織のドメインで引く。**DNS が応答しないときは「無い」と判定しない。**

**読み方**: 詐称メールを受信側に拒否させるのは **DMARC の `p=reject`（または `quarantine`）** で、SPF の有無ではない。
メール配信サービスに送信を委ねる構成では SPF と DKIM が**サブドメイン側**にあることが多く、DMARC が `p=reject` なら、
apex に SPF が無くても詐称は DMARC で拒否される。
**メールを送らないドメインでも、`v=spf1 -all` と DMARC の `p=reject` を置くのが定石。** 国内の行政の要請も、
メールを送らないドメインを含めて受信拒否のポリシーでの運用を求めている。

**業界のガイドラインが `p=reject` を求めていることがある**（証券など。サブドメインの乗っ取りへの対策や、
**メールや SMS にログイン用のリンクを載せないこと**を併せて求めるものもある）。有無は取材で聞く（`references/01-scoping.md` の B-4）。

**到達性となりすまし対策を分けて判定する。** 大手のメールサービスは大量送信者に SPF・DKIM・DMARC を求めるが、
要件は `p=none` でも満たせる。**`p=none` は「届く」の条件は満たすが、なりすましは止めない。**
`t=y`（テストモード）が付いていれば、指定より 1 段緩いポリシーで扱われる。
同じ名前に DMARC のレコードが 2 本以上あると、その名前のレコードはすべて捨てられる。
直し方は、集計レポート（`rua`）で正規の送信元が揃ったことを確かめてから、`p=quarantine`、`p=reject` へ段階的に上げること。

認証不要でメールを送れる経路（フェーズ 1 の F-1）が見つかっている場合、DMARC が `p=none` だと**踏み台にされたときに外形的に止める手段が無い**。組にして評価する。

**DNSSEC が無いときも「取っていない」のか「取れない」のかを区別する**（DNS をホスティングの付属機能で運用していると、対応していないことがある）。

### サブドメインの乗っ取り

**CNAME が指す先の資源（ホスティングのプロジェクト、ストレージのバケット）を消した後も CNAME が残っている**と、
第三者がその名前で資源を作ってサブドメインを取れる。取られたサブドメインでは正規の証明書が取れ、**親ドメインに設定された Cookie も読める。**

```bash
# 過去に発行された証明書から、サブドメインを集める（証明書の透明性ログ。外部サービスにドメイン名を送る点に注意）
# その上で、CNAME の行き先が「存在しない」応答を返していないかを 1 本ずつ見る
for s in <サブドメインの一覧>; do
  c=$(dig +short CNAME "$s"); [ -n "$c" ] || continue
  printf '%-40s -> %-40s ' "$s" "$c"
  curl -s -m 8 "https://$s" | grep -oE 'DEPLOYMENT_NOT_FOUND|No such app|The specified bucket does not exist|NoSuchBucket' | head -1
  echo
done
```

**行き先が「存在しない」と答えていれば、その時点で指摘。** 是正は CNAME の削除。

### 証明書

証明書の最長の有効期間は段階的に縮められている（CA/Browser Forum の決定）。**手動で更新している証明書は、もう運用として成り立たない。**
有効期限と発行者を見て、手動の更新が混ざっていないかを聞く。直し方は ACME による自動更新。
**OCSP stapling が無いことは指摘にしない**（OCSP は任意になり、提供をやめた認証局もある）。

```bash
echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null \
  | openssl x509 -noout -issuer -enddate
```

**古い TLS の版を受け付けていないか。** VPS や自前のロードバランサーの構成では TLS 1.0 / 1.1 が残っていることがある。
1.0 / 1.1 が成立すれば指摘にする（優先度は低い。カード決済を扱うなら 06 の「カード決済を扱う場合」も見る）。
手元の `openssl` が古い版の接続を作れないときは「確かめられない」と書く（成立しなかったことと区別する）。

```bash
for v in tls1 tls1_1 tls1_2 tls1_3; do
  out="$(echo | openssl s_client -connect <domain>:443 -servername <domain> -"$v" 2>&1)"
  if grep -qE '^New, (TLS|SSL)|Protocol[[:space:]]*:[[:space:]]*TLSv' <<<"$out"; then echo "$v 成立"; else echo "$v 不成立か確かめられない"; fi
done
```

---

## 10. 本番エンドポイントの外形テスト

コードで確認したガードが、本番で実際に機能しているかを確かめる。

```bash
# 開発用の抜け道が塞がっているか（期待値: 404 か 403）
curl -s -o /dev/null -w "%{http_code}\n" https://<domain>/api/<dev-route>

# セキュリティヘッダの実際の付与状況
curl -sI https://<domain> | grep -iE \
  'strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|x-powered-by|cross-origin-opener-policy|cross-origin-resource-policy|server|x-nextjs-cache|x-vercel-cache'
```

**設定ファイルに書いてあることと、実際の応答は一致しないことがある**（ビルドに反映されていない、エッジ側で上書きされている）。本番の応答を見る。

**ヘッダは有無ではなく中身で判定する。** CSP は `references/07-web-vulnerabilities.md` の 1-6 の基準で読む。
COOP は `same-origin`、CORP は `same-site` が推奨値。`X-XSS-Protection` は付けないか `0`
（古いブラウザの XSS フィルタは、それ自体が情報漏えいの原因になった）。

### ミドルウェアの対象範囲を URL の揺れで確かめる

**ミドルウェア（Next.js 16 では proxy）で認可している構成に限る。** この種の迂回は枠組みの不具合として繰り返し出ている（02 の A-5）。
保護されたパスを、形を変えて 1 本ずつ GET する。
**期待値はすべて 401 / 403 / 404 / ログインへのリダイレクト**（大文字小文字を区別するルーティングでは `/Admin` は 404 になり、
これは迂回ではない）。**200 が返ったものだけ**、SPA の共通の殻（どのパスにも同じ HTML を返す）でないかを
`curl -s … | head -c 300` で確かめる。殻でなく中身が返っていれば迂回が成立している。

```bash
for p in "/admin" "/Admin" "/%61dmin" "/admin/" "/admin.rsc" "/admin?_rsc=x" "/ja/admin" "/en/admin"; do
  printf '%-20s ' "$p"; curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' "https://<domain>$p"
done
```

**依頼者の許可を得た対象にだけ、認証なしの GET で行う。** 状態を変える要求は送らない。

### セッション Cookie の属性

コード監査 B-2 で「ブラウザ側 SDK でログインしている」と判定した場合に、外形から裏を取る。

```bash
# サーバーが Set-Cookie を返しているか（返っていなければ JS 側で書いている）
curl -sI https://<domain>/<ログイン後のパス> | grep -i set-cookie

# ログイン画面に第三者スクリプトが入っていないか
curl -s https://<domain>/<管理画面のログインパス> \
  | grep -oE '<script[^>]*src="[^"]+"' | sort -u
```

**サーバーが認証 Cookie を発行していないなら、その Cookie に `HttpOnly` は付いていない。** 管理画面のログイン画面に広告・分析タグが入っていれば、指摘の重さが一段上がる。

### 外から見えてはいけないもの

**本文は保存しない。ステータスコードだけを取る**（3 本目のエラーページの確認だけは、該当する行を画面に出す）。

```bash
# scripts/recon.sh も同じ一覧で有無を確かめる。手で確かめるときもこの一覧に揃える
for p in /.git/HEAD /.git/config /.env /.env.local /.env.production /.env.bak /.aws/credentials /.npmrc \
         /actuator/env /server-status /phpinfo.php /.DS_Store /server.js.map; do
  printf '%-22s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://<domain>$p"
done
# 配信している JS にソースマップの参照があり、その .map が取れるか
curl -s https://<domain>/ | grep -oE '/_next/static/[^"]+\.js' | head -3 \
  | while read -r js; do printf '%s.map ' "$js"; curl -s -o /dev/null -w '%{http_code}\n' "https://<domain>$js.map"; done
# 存在しないパスで、スタックトレースや枠組みの版が出ないか
curl -s "https://<domain>/sectest-$(date +%s)" | grep -iE 'stack|trace|exception|at .*\(.*:[0-9]+' | head -3
```

- **`.git` や `.env` の中身が返れば P0**（04 の問い 1。`.env` の鍵や `.git` の履歴から、認証の無い第三者がデータに届く。
  知らせ方は SKILL.md の「守ること」）。SPA の構成では、存在しないパスにも 200 でトップページを返すことがあるので、
  **中身の先頭数バイトだけで判定し、値は出さない**。直し方は、公開ディレクトリから外し、配信の設定でドットファイルを拒否し、中にあった鍵を入れ替えること

```bash
# 200 のときだけ。値を画面に出さずに、中身らしいかだけを判定する
curl -s -r 0-15 "https://<domain>/.git/HEAD" | grep '^ref:' >/dev/null && echo '.git/HEAD の中身が返っている'
curl -s -r 0-200 "https://<domain>/.env" | grep -E '^[A-Z_]+=' >/dev/null && echo '.env の中身が返っている'
```
- **ソースマップが公開されていると、元のソースがそのまま読める。** コメントに書いた内部の情報や、
  サーバー用のつもりで書いたコードが出る。Next.js は既定で無効（`productionBrowserSourceMaps`）

### 連絡窓口

- **`/.well-known/security.txt`（RFC 9116）があるか。** 外部の人が脆弱性を見つけたときの連絡先になる。
  あれば `Contact:` と `Expires:`（期限切れでないか）を見る。**無いことは優先度の低い指摘**にする
- HSTS に `preload` を付けているなら、**全サブドメインが HTTPS に対応しているか**（preload は取り消しに数か月かかる）

`scripts/recon.sh <url>` が、この節のヘッダ・外から見えてはいけないファイル・証明書と、9 節の DNS をまとめて実行する
（到達できなかった項目は「無い」ではなく判定なしになる）。**URL の揺れによる迂回の確認、ソースマップ、エラーページは手で行う。**

### curl で見えないところ

同意前の第三者送信、JS が書く Cookie と保存領域、CSP が実際に何を止めるか、認証後の画面が戻るボタンで再表示されるかは、
ブラウザで読み込まないと判定できない。該当するなら `references/09-browser-verification.md` を読む。

### 自前のサーバー 1 台で動かしている場合（ホストの基本）

VPS や自前のサーバー 1 台に、Docker compose と nginx（Caddy など）でアプリと DB を載せている構成に限る。マネージドの
ホスティングなら基盤が持つ部分を、ここでは依頼者が持っている。**評価者はサーバーに入らない。** 下の読み取りだけのコマンドを
依頼者に実行してもらい、出力をそのまま貼ってもらう（モード B）。結果は観点の一覧の 5 節と 10 節の行に残す。

| 確かめること | 依頼者に頼むこと | 問題ありにする形と直し方 |
|---|---|---|
| SSH のログイン | `sudo sshd -T \| grep -iE '^(passwordauthentication\|kbdinteractiveauthentication\|permitrootlogin)'` | `passwordauthentication yes`（または `kbdinteractiveauthentication yes`）でパスワードで入れる、`permitrootlogin yes` で root に直接入れる。総当たりの対象になる。鍵認証だけにし（両方を `no`）、`PermitRootLogin no` にして、一般の利用者から `sudo` で上がる |
| OS とパッケージの更新 | `cat /etc/os-release`。Debian・Ubuntu なら `apt list --upgradable` の行数と、自動のセキュリティ更新（`unattended-upgrades`）が有効か。コンテナの基のイメージをいつ取り直したか | サポートの切れた OS の版。更新が溜まったまま。自動のセキュリティ更新を有効にし、基のイメージを定期に取り直して作り直す |
| 外から開いているポート | `sudo ss -tlnp` と、compose の各サービスの `ports:` の行 | DB（5432・3306・27017・6379 など）、管理画面（pgAdmin・Adminer・Portainer など）、Docker のデーモン（2375・2376）が `0.0.0.0` や `[::]` で待ち受けている。**compose の `ports:` で公開したポートは、Docker が自分で通信の規則を書くので、ホストのファイアウォール（ufw など）の拒否を素通りする。** 公開が不要なサービスは `ports:` を消して compose の内部のネットワークだけで通し、必要なら `127.0.0.1:` を付けて手元だけで待ち受ける。クラウドの側のファイアウォールで 80・443 と SSH（接続元を絞る）だけを許す |
| TLS の終端 | nginx などで TLS を終端しているか、証明書の自動更新（certbot のタイマーなど）が動いているか、アプリのコンテナのポートに TLS 無しで外から届かないか | 平文の HTTP で中身が返る経路がある。手動の更新。HTTP は HTTPS へ転送し、アプリのポートは外に出さない（古い TLS の版は 9 節） |
| バックアップの保存先 | DB のダンプやボリュームの写しをどこに置いているか、いつ取ったか | 同じサーバーの中にしか無い（サーバーを失うと一緒に失う）。別の場所（オブジェクトストレージなど）へ、同じ鍵では消せない形で置く（4 節） |

外から確かめられるのは開いているポートだけで、依頼者の許可を得た対象に、上の数個のポートへの接続の可否
（`nc -z -w 3 <host> <port>`）を確かめる程度にとどめる。広い範囲のポートの走査はしない。

---

## 11. 運用

**コードにも設定画面にも現れにくいが、事故の大きさと気づくまでの時間を決めるもの。** 取材（`references/01-scoping.md` の B-3）と
管理画面（`templates/client-console-checklist.md`）で確かめ、台帳の観点の一覧の「運用」の行に結果を残す。**ここで見たことは、
指摘にしなかったものも観点の一覧に残す。** 未確認事項（U-x）にしか書かないと、再評価で U が消えたときに跡が残らない。

| 観点の一覧の行 | 確かめること | 問題ありにする形 |
|---|---|---|
| 運用 1. 管理コンソールの多要素認証とメンバー | ホスティング・DB・認証基盤・ドメイン・GitHub・タグマネージャの各コンソールで、組織として多要素認証を必須にしているか。メンバーの人数と役割 | 必須にしていない。心当たりの無いメンバー、役割の過大なメンバーがいる（3 節） |
| 運用 2. 退職者・委託先のアカウントと基盤の名義 | 各サービスのオーナーが依頼者の法人の名義か。開発会社・個人の外注・SES が持つ権限（コンソールのメンバー、個人のトークン、デプロイの鍵、`.env` の写し）と、契約が終わったときに引き上げる手順 | オーナーが個人や外注先の名義。契約の終わった人の権限が残っている。引き上げの手順が無く、そのときに鍵を入れ替えていない |
| 運用 3. 監視と通知 | 何に気づけるか（管理者の追加、認証の失敗の急増、エラー率、請求額、外形の死活）と、通知が届く宛先が生きているか | 気づく仕組みが無い。通知が誰も見ない宛先に届く |
| 運用 4. ログの保存期間 | ホスティング・DB・認証基盤のログを何日残しているか、外部へ転送しているか、誰が見られるか | 漏えいの調査に足りない（確報の 30 日、不正の目的なら 60 日までに影響の範囲を決められない）。プランの既定の短い期間のまま |
| 運用 5. 漏えい時の対応の手順と連絡体制 | 誰が報告の要否を判断するか、いつを起点に数えるか（知った時点）、ログと証拠の保全、鍵の失効の手順、本人への通知の文案、委託先から報告が上がる経路、カード決済があれば決済代行への連絡 | 手順が無い。上の要素のどれかが決まっていない（`references/08-privacy-compliance.md` の 4 節） |
| 運用 6. 費用の上限と通知 | ホスティング・DB・SMS・LLM・クラウドの支出の上限と、上限に近づいたときの通知 | 上限も通知も無い従量課金がある（濫用されると請求がそのまま伸びる。02 の F-1） |
| 運用 7. 基盤とドメインの更新 | マネージドの DB のエンジンの版と保留中の更新、ランタイムの版のサポート期限。ドメインの自動更新・支払いの手段・移管のロック・登録者の連絡先 | 保留中のセキュリティの更新が放置されている。ドメインの更新が個人のカードや退職者のアドレスに結び付いている（切れると第三者に取られ、メールもアプリも乗っ取られる） |
| 運用 8. 外部診断と受付窓口 | これまでの外部の診断（日付・範囲・指摘が閉じたか）。脆弱性の連絡を受ける窓口（`security.txt`、問い合わせ先） | 診断の指摘が閉じていない。連絡を受ける窓口が無い |

**判定できないものは、未確認事項にして観点の一覧の結果を「未確認: U-x」にする。** 未確認のまま残すことより、聞いていないことが分からなくなるほうが害が大きい。

## 記録のしかた

**実行した結果をそのまま残す。** 「問題ありませんでした」ではなく、返ってきた行、HTTP ステータス、画面の設定値を書く。

```markdown
### 確認: 全テーブルの行レベルセキュリティ
実行: 1 節の 1 番のクエリ
結果: <n> rows。`rowsecurity = false` は 0 件。（返ってきた表をそのまま貼る）
```

集約や整形をした場合は、**元の行数と、何をしたか**を添える（「<n> 行をテーブル×ロールで集約。集約後 <m> 行、権限の総数は一致」）。

### 一覧表を作る

確認が済んだら、区分ごとの一覧表にまとめる。ここが報告書の中核になる。

| 区分 | 確認項目 | 結果（事実） | 判定 | 関連 ID |
|---|---|---|---|---|
| アクセス制御 | 全テーブルの行レベル権限 | <n> テーブルすべて有効。無効は 0 件 | 問題なし | S-xx |
| 認証 | 多要素認証の登録状況 | 登録済み要素 0 件（管理者 <n> 名全員が未登録） | 問題あり | S-xx |
| 事業継続 | バックアップ | 無償プランのため機能自体が無い | 問題あり | S-xx |

判定の値は `references/04-findings-register.md` の「判定・優先度・状態は別の軸」に従う。事実として記録しておくだけのもの（保有件数、最古の登録日など）は、この表ではなく台帳の「気づいたこと」に置く。

### 確認できなかったことを残す

値が読めない設定、権限不足で開けなかった画面、依頼者しか知らない運用は、**未確認事項として通し番号を振る**。詳しくは `references/04-findings-register.md` の「未確認事項」を参照。
