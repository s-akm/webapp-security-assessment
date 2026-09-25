# フェーズ 2 — 実機確認

コードを読んでも分からないことがある。DB の権限が実際にどう設定されているか、バックアップが本当に取れているか、WAF が有効か。**リポジトリに答えが書いていない項目は、実環境を見るまで確定しない。**

このフェーズの目的は、フェーズ 1 で「要確認」にした項目を、**事実として確定させる**ことだけ。判断や修正は後の工程でやる。

## 目次

- [2 つのモード](#2-つのモード) — モード A（自分で見る）/ モード B（手順を渡して結果を受け取る）
- [確認項目](#確認項目)
- [1. データ層の権限](#1-データ層の権限) — RLS・GRANT・ポリシーの中身・迂回経路・Supabase の Realtime と Storage
- [2. 外形テストで裏を取る](#2-外形テストで裏を取る)
- [3. 認証ポリシー](#3-認証ポリシー) — 管理コンソールの多要素認証、SMS を送っている場合
- [4. バックアップと復旧](#4-バックアップと復旧)
- [5. ネットワークとアクセス経路](#5-ネットワークとアクセス経路)
- [6. 鍵の構成](#6-鍵の構成)
- [7. 環境の分離](#7-環境の分離) — Vercel の Deployment Protection と Secret
- [8. エッジ・WAF・流量制御](#8-エッジwaf流量制御)
- [9. DNS とメール送信ドメイン](#9-dns-とメール送信ドメイン) — DMARC・サブドメインの乗っ取り・証明書
- [10. 本番エンドポイントの外形テスト](#10-本番エンドポイントの外形テスト) — ヘッダ・URL の揺れ・外から見えてはいけないもの・curl で見えないところ
- [記録のしかた](#記録のしかた) — 一覧表と、確認できなかったこと

---

## 2 つのモード

環境によって、確認のやり方が変わる。**どちらのモードで実施したかを報告書に書く。** 情報の確度が違うため。

### モード A — 自分で見に行く

ブラウザ操作の手段がある場合。管理画面を開いて設定値を読み、SQL 実行環境があればクエリを流す。

- **認証情報を自分で入力しない。** 未ログインなら、そこで止めて依頼者にログインを頼む
- 画面を読むときは、スクリーンショットよりページのテキストを取るほうが正確
- 設定を変更しない。トグルに触れない。ダイアログは開いたら閉じる

### モード B — 手順を渡して結果を受け取る

ブラウザ操作の手段が無い、または依頼者が自分で実行したい場合。

- **貼り付けてそのまま実行できる形**で SQL とコマンドを渡す
- 「結果を要約して」ではなく「返ってきた行をそのまま貼って」と頼む。要約されると、判定に必要な情報が落ちる
- 画面の設定値は、項目名を列挙して「それぞれの値」を聞く
- 渡す文面は `templates/` にある。SQL は `templates/client-sql-request.md`、管理画面の設定は `templates/client-console-checklist.md`、
  ログインが要るブラウザの確認は `templates/client-browser-checklist.md`

**混在してよい。** SQL は依頼者に実行してもらい、外形テストは自分でやる、という分け方は普通に起きる。

---

## 確認項目

各項目は「**確定させたい問い**」と「**どこを見るか**」で書いてある。問いは構成によらず共通で、見る場所が構成ごとに変わる。

---

## 1. データ層の権限

### 問い

1. 全テーブルで行レベルの権限制御が有効になっているか
2. 匿名／一般利用者の資格に付いた業務データへの読み書き権限が、行レベルの権限制御で絞られているか（RLS を使わない構成なら、権限そのものが付いていないか）
3. 権限ポリシーの対象に、公開ロールが含まれていないか
4. コードに定義が無かったテーブルは実在するか。実在するならその設定はどうなっているか

**この 4 つがこのフェーズで最も重要。** 個人情報が入ったテーブルの権限が開いていれば、他の全ての対策が意味を失う。時間が限られるならここだけでも確定させる。

### 見る場所

| 構成 | 確認方法 |
|---|---|
| PostgreSQL（行レベルセキュリティ） | 下の SQL を実行する |
| MySQL / MariaDB | `SHOW GRANTS` でアプリ用ユーザーの権限を確認。行レベル制御は通常アプリ側 |
| MongoDB | ロールとコレクション単位の権限、`db.getUsers()` |
| Firestore / Realtime Database | セキュリティルールの本文を取得して読む |
| DynamoDB | IAM ポリシーの `Resource` と `Condition` |
| 自前 DB + アプリのみで防御 | アプリ用ユーザーの権限範囲と、DB への到達経路を確認 |

### 例: PostgreSQL + 行レベルセキュリティ

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

-- 4. コードに定義が無かったテーブルのカラム構成（リポジトリへ復元するために使う）
select table_name, column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public'
  and table_name in (<コード監査 E-2 で列挙したテーブル名>)
order by table_name, ordinal_position;
```

**結果が多い場合の扱い**: 2 番は数百行返ることがある。全行を目で追うのは現実的でないので、`string_agg` で権限をテーブル×ロール単位にまとめて読む。ただし**元のクエリの行数は必ず記録する**。集約後の行数だけ書くと、後から検算できない。

```sql
select table_name, grantee, string_agg(privilege_type, ' / ' order by privilege_type) as privs
from information_schema.role_table_grants
where table_schema = 'public' and grantee in ('anon', 'authenticated')
group by table_name, grantee order by table_name, grantee;
```

**読み方の注意**: 付与があることだけでは判定しない。**`GRANT` と RLS は別に見る**（この節の末尾）。

- **RLS を前提にした構成**（Supabase のように、公開ロールのまま API からテーブルを読む構成）では、
  `authenticated` への `SELECT` / `INSERT` / `UPDATE` / `DELETE` の付与は**正常**で、守りは RLS のポリシーが担う。
  公開データを未ログインで読ませるなら `anon` への `SELECT` も正常
- **指摘になるのは、RLS が無効なテーブル（1 番で `rowsecurity = false`）、または素通しのポリシー（次の小節）がある
  テーブルに、公開ロールへの `SELECT` / `INSERT` / `UPDATE` / `DELETE` の付与があるとき。** 付与と RLS の穴が揃うと、
  公開鍵だけで行に届く
- **RLS を使わない構成**（アプリが特権資格で接続し、アプリのガードで守る構成。02 の E-1）では、公開ロールへの付与は
  そもそも要らない。付与があれば、それ自体を指摘にする
- `REFERENCES` / `TRIGGER` / `TRUNCATE` はデータを読む権限ではない。ただし `TRUNCATE` は**行レベルのポリシーで止まらない**
  操作なので、DB への直接接続経路と併せて評価する

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

素通しのポリシーがあるテーブルは、次の小節のクエリで洗い出し、この付与の一覧と突き合わせる。

### 有効なだけでは足りない。ポリシーの中身を読む

**「行レベルセキュリティが全テーブルで有効」は出発点であって、結論ではない。**
有効でも、中身が素通しなら意味がない。3 番のクエリで取った `qual` を 1 つずつ読む。

| ポリシーの中身 | 意味 |
|---|---|
| `true`（`USING (true)`） | **誰でも通る。** 「全ログインユーザーに許可」のつもりで書かれていることが多いが、対象ロールに公開ロールが入っていれば**未認証でも通る** |
| `auth.uid() = user_id` | 本人の行だけ。意図どおり |
| `user_id = current_setting('...')` のような**クライアント由来の値** | **利用者が自分で名乗った値で絞っている。** 詐称できるなら意味がない |
| `cmd` が `ALL` で `with_check` が無い | 読めるだけのつもりが、書き込みも通る |

```sql
-- 素通しになっているポリシーを洗い出す
select tablename, policyname, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public'
  and (qual is null or btrim(qual) in ('true', '(true)'))
order by tablename;
```

**`roles` を必ず併せて見る。** `USING (true)` でも対象が特定ロールに限られていれば
意図した設計かもしれない。**公開ロールが入っているかどうかで判定が変わる。**

### 更新ポリシーは「どの列を」変えられるかまで見る

**行レベルのポリシーは行を選ぶだけで、列を区別しない。** `for update using (id = auth.uid())` は
「自分の行なら更新できる」であって、「自分の行の、この列だけ」ではない。

**認可の根拠になる列が、そのテーブルにあるとき**に問題になる。利用者のロール、所属組織、
有効フラグを `profiles` のようなテーブルに持ち、`is_admin()` がそれを読む構成は多い。
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

行レベルのポリシーは、**テーブルを直接読むときにしか効かない**。次の 3 つは迂回する（Supabase 固有の追加の経路は後述）。

```sql
-- 1. 定義者権限で動く関数（呼び出した人ではなく、作った人の権限で動く）
select n.nspname, p.proname, p.prosecdef
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname not in ('pg_catalog', 'information_schema') and p.prosecdef
order by n.nspname, p.proname;

-- 1b. その関数を公開ロールが実行できるか。PostgreSQL は既定で関数の実行権限を PUBLIC に与える
--     search_path を固定していない（proconfig が空の）定義者権限の関数も要確認
select n.nspname, p.proname, p.proconfig,
       -- anon / authenticated は Supabase のロール。他の構成では、API が使うロール名に置き換える
       has_function_privilege('anon', p.oid, 'execute')          as anon_exec,
       has_function_privilege('authenticated', p.oid, 'execute') as auth_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema');

-- 2. ビューとマテリアライズドビュー。information_schema.views では security_invoker の有無が分からない
--    reloptions の security_invoker が true / on / 1 / yes のどれでもないビューと、
--    マテリアライズドビュー（relkind = 'm'）はすべて要確認
select n.nspname, c.relname, c.relkind, c.reloptions
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v', 'm') and n.nspname not in ('pg_catalog', 'information_schema');
```

- **定義者権限の関数が、API から呼べるスキーマに置かれていないか。** 置くなら、
  API が公開しないスキーマへ移すのが定石。**マネージドの PostgREST 系では、`public` に
  置いた関数は既定で RPC として公開され、ログイン済みの誰からでも呼べる。**
  関数の中で呼び出し元の所属を確かめていなければ、**その関数が読める範囲がそのまま漏れる**。
  1 つの migration に、所属を確かめる関数と確かめない関数が混在していることがある。1 本ずつ読む
- **ビューが呼び出し元の権限で動く設定になっているか**（PostgreSQL 15 以降なら
  `security_invoker = true`）。既定は作成者の権限で、**下のテーブルのポリシーを迂回する**
- 3 番目は**特権鍵**。サーバー側で使う鍵はポリシーを完全に無視する。
  **その鍵がクライアントに出ていないか**はコード監査 C-1 と外形調査（`scripts/recon.sh`）で見る。
  AI で素早く作ったアプリでは、この露出が実際に相当な割合で起きている

**この 3 つを確かめずに「データ層の防御は機能している」と書かない。** 有効状態の一覧だけでは、
迂回経路を見ていないことになる。

**Supabase では、さらに次の経路を見る。** 公式の Security Advisor（ダッシュボードの Advisors）が同じものを
機械的に出すので、**その結果の一覧を依頼者からもらう**のが早い。

| 経路 | 何が起きるか |
|---|---|
| マテリアライズドビュー・外部テーブル | RLS が効かない |
| ポリシーが `user_metadata`（`raw_user_meta_data`）を参照 | 利用者が自分で書き換えられる値で認可している（02 の A-2） |
| 匿名サインインが有効 | **匿名の利用者も `authenticated` ロールになる。** 「ログイン済みなら読める」ポリシーが匿名にも開く |
| Storage のバケットが `public` | **URL を知っていれば誰でもダウンロードできる**（ポリシーは効かない） |
| 公開スキーマ（Exposed schemas）の設定 | ここに入ったスキーマのテーブル・関数・ビューが API に出る |
| Realtime の「Allow public access to channels」 | **既定で有効。** 有効な間は、`private: true` を付けない Broadcast / Presence の購読にポリシーの確認が走らず、公開鍵を持つ誰でも購読・送信できる。private を強制するには無効にする（`references/07-web-vulnerabilities.md` の 11-3）。テーブルの変更の購読（Postgres Changes）はこの設定と別に、テーブルの RLS で判定される |
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

**`GRANT` と RLS は別に見る。** Supabase は新規テーブルへの公開ロールの自動 `GRANT` を止める方向に変わった
（2026-05 に新規プロジェクトの既定、**2026-10-30 から既存プロジェクトにも適用**）。`GRANT` が無ければ RLS より
手前で拒否される。逆に、変更前に作ったテーブルには `GRANT` が付いたままなので、RLS の中身が全てになる。
**どちらの場合も、付与の有無だけで指摘にしない。** 指摘になるのは、付与と RLS の穴（無効、または素通しのポリシー）が
同じテーブルで揃ったときで、判定のしかたは 2 番のクエリの「読み方の注意」にまとめてある。

---

## 2. 外形テストで裏を取る

設定値を読むだけで終わらせない。**公開されている経路から実際に叩いて、拒否されることを確かめる。** 設定の読み違いや、想定していなかった迂回路がここで見つかる。

### やり方

1. 本番のフロントエンドが読み込む JS から、公開用のエンドポイントと公開鍵を取り出す（`scripts/recon.sh` がやる）
2. その公開鍵で、個人情報を持つテーブル／コレクションへ**読み取りだけ**リクエストする
3. 拒否されることを確認する

```bash
# 例: PostgREST 系の API に対して、公開鍵で読み取りを試す
# select で列を絞り limit 0 にして、実データを取得しないようにする
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "apikey: $PUBLISHABLE_KEY" -H "Authorization: Bearer $PUBLISHABLE_KEY" \
  "https://<endpoint>/rest/v1/<table>?select=id&limit=0"
```

期待値は 401 か 403。**200 が返れば、個人情報を持つテーブルに公開鍵だけで届いている**ので、`references/04-findings-register.md` の問い 1 で P0 になる。**報告書を待たずに依頼者へ知らせる**（SKILL.md の「重大な露出は、見つけた時点で知らせる」）。

### 実データを取らない

`select *` を使わない。`limit 0` か、ID など個人情報でない列だけを指定する。**目的は「読めるかどうか」であって、中身ではない。** 拒否された場合はエラー本文（権限エラーのコードとメッセージ）を記録する。それが根拠になる。

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

- パスワードの最小長と、要求する文字種
- 漏えいパスワードの検知が有効か
- 多要素認証が**有効化できる状態か**、そして**実際に登録している利用者がいるか**
- メールアドレスの確認が必須か
- 認証系のレート制限の値
- セッションの有効期限、無操作タイムアウト
- 誰でもサインアップできる状態になっていないか

**基準は NIST SP 800-63B-4**（`references/02-code-audit.md` の B-1）。パスワードだけで認証するなら最小 15 文字、
文字種の強制と定期変更の強制はしない、漏えい済みパスワードとの照合はする。**設定画面の最小長が 6 や 8 のままなら、
それを事実として記録する。**

**「機能が有効」と「実際に使われている」は別物。** 多要素認証が設定上オンでも、登録者が 0 人なら守られていない。認証基盤に登録済みの要素を数える手段があれば、必ず数える。

```sql
-- 例: 多要素認証の登録実績を数える（テーブル名は基盤に合わせる）
select count(*) as total, count(*) filter (where status = 'verified') as verified
from auth.mfa_factors;
```

### 見る場所

- マネージド認証（Auth0 / Cognito / Firebase Auth / Supabase Auth / Clerk など）: 管理画面のポリシー設定
- 自前実装: コードで確認済みのはずなので、ここでは設定値の外部化がないかだけ見る

### 管理コンソール自体の多要素認証と監査ログ

**利用者の認証より先に、運営者の入口を見る。** ホスティング・DB・認証基盤・ドメイン登録・メール配信の
管理コンソールが乗っ取られれば、アプリ側の対策はすべて無効になる。

- 各コンソールで、**組織（チーム）として多要素認証を強制しているか**。個人が任意で有効にしているだけか
- メンバーの一覧に、退職者・契約終了先・用途不明のアカウントが残っていないか
- コンソールの操作の監査ログが取れているか（上位プラン限定のことが多い。取れないなら「取れない」と書く）

クラウド側でも必須化が進んでいる（AWS は root の MFA を全アカウント種別で必須化、Google Cloud と Azure も
段階的に必須化）。**必須化は「ログインの時点」の話で、組織として強制しているかは別に確かめる。**

### SMS を送っている場合

**既定値が基盤ごとにまったく違う**ので、管理画面で確かめる（`references/02-code-audit.md` の F-4）。

| 基盤 | 送信先の国 | 上限 |
|---|---|---|
| Firebase Authentication | **新規プロジェクトは既定でどの国にも送らない**（許可する国を選ぶ）。古いプロジェクトは設定を見る | プロジェクト全体と IP ごとの上限がある。reCAPTCHA による SMS の防御のモードも見る |
| Supabase Auth | **国を絞る設定が無い**。SMS の送信元（Twilio など）の側か、送信のフックで絞る | プロジェクト全体で既定 30 通/時。同じ利用者への再送は 60 秒あける。CAPTCHA は任意 |
| Twilio | 通常の送信は、新規アカウントでは登録した番号の国だけ。確認用の Verify には別の国の許可設定がある | 通常の送信には番号ごとの上限が無い。濫用の防御は Verify では既定で有効、通常の送信では既定で無効 |
| AWS（SNS / End User Messaging / Cognito） | **国の既定は許可**。保護の設定で国を止める | 月額の上限（SNS は `MonthlySpendLimit`、End User Messaging SMS は `SetTextMessageSpendLimitOverride`。今月の使用額は CloudWatch の `TextMessageMonthlySpend` で見て通知を組む） |

**見るのは、日本だけを相手にしているのに国を絞っていないか、月額の上限と通知があるか、確認の完了率を見ているか**の 3 つ。
送信を伴う試験は本番ではしない。

**プラン制限に注意**: 漏えいパスワード検知、セッション設定、SMS による多要素認証などは、上位プラン限定になっている場合がある。画面に「上位プランで利用可能」と出ていたら、**それは「設定していない」ではなく「設定できない」**。指摘の書き方が変わるので区別して記録する。

---

## 4. バックアップと復旧

### 問い

- バックアップが実際に取得されているか。頻度と保持期間
- ある時点への復旧（PITR）が可能か
- **復元を一度でも試したことがあるか**

取得されているだけで復元したことがないバックアップは、復旧手段として数えない。ここは実機確認というより依頼者への質問になる。

無償プランではバックアップ機能自体が提供されないことがある。**「取っていない」のか「取れない」のかを区別する。** 後者ならプラン変更が対策になる。

**何がバックアップに含まれないかも聞く。** たとえば Supabase では、無償プランに自動バックアップが無く、
**Storage のファイル本体はデータベースのバックアップに含まれない**（復元するとメタデータだけ過去に戻り、
ファイルとずれる）。物理バックアップはダウンロードできないので、**基盤の外に復旧手段を持つなら別に論理ダンプが要る**。

**ランサムウェアや管理アカウントの乗っ取りを想定するなら、削除できない場所に置いているか**を聞く。
同じ管理コンソールから消せるバックアップは、コンソールを乗っ取られたときに一緒に消える。

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

**Supabase が典型。** 新方式（`sb_publishable_…` / `sb_secret_…` と非対称の署名鍵）の鍵を作っても、
旧方式の `anon` / `service_role` の JWT 鍵は**自動では無効にならず、並行して有効なまま**になる。
公式の手順は**新方式へ移り、管理画面（Settings > API Keys）で旧方式を無効にする**ことで、無効にするまで旧方式は生きている。
「ローテーションした記録があるか」を聞く前に、**旧方式の鍵が有効なままか**を確かめる。

**公開前提の鍵で、呼べる API が増えていないか。** Google の `AIza…` の鍵は、同じプロジェクトで
Gemini の API を有効にすると、配布済みの鍵でそのまま呼べるようになる（`references/14-mobile.md` の 1 節）。
**鍵ごとに API の制限が掛かっているか**を見る。

---

## 7. 環境の分離

### 問い

- 本番・検証・開発の環境変数が分かれているか
- **本番の特権鍵が、検証環境にも設定されていないか**
- 検証環境が外部から見えないようになっているか。Vercel なら Deployment Protection の設定を見る。
  **旧来の設定（Legacy の保護）のまま残っていると、自動生成された本番用の URL が公開されたまま**になる。
  2026-09 から **Vercel Authentication による全デプロイ（本番を含む）の保護が全プランで無償**になったので、
  **「上位プランでしか守れない」は理由にならない**（パスワードでの保護は今も Pro の有償オプション）。
  保護を迂回する共有リンクや、自動化用のバイパス用シークレットが残っていないかも見る
- 検証環境が本番の DB を向いていないか

検証環境が保護されていれば、特権鍵が入っていること自体の実害は下がる。**ただし「検証ビルドが本番データを壊せる」構図は残る**ので、保護の有無とは別に記録する。

環境変数の値が読み出せない設定（秘匿指定）になっている場合、**値の確認は諦めて未確認事項に回す**。無理に読もうとして設定を壊さない。

**秘匿指定になっているかどうか自体は見る。** Vercel では秘匿指定でない環境変数が、2026-04 に公表された
Vercel 自身への不正アクセスで読まれた。**特権の鍵が秘匿指定（Secret）になっているか、本番の Secret の値を他の環境と分けさせるチームのポリシー
（Separate Production Secret Values。以前の「秘匿指定の強制」のポリシーは 2026-08 に非推奨）を有効にしているか、
特権の鍵が開発環境（手元に平文で落ちる）にも登録されていないか**を確かめる。Vercel では 2026-08 から、
環境変数が「Config」と「Secret」の 2 種類になった。**`NEXT_PUBLIC_` の付いた変数は、Secret にしても
ビルドで JS に埋め込まれて公開される。**

---

## 8. エッジ・WAF・流量制御

### 問い

- WAF が有効か。マネージドルールセットが適用されているか
- BOT 対策が有効か
- レート制限のルールが設定されているか
- 攻撃時に切り替えるモードが用意されているか、その現在の状態

**エッジを迂回してオリジンへ直接届かないか。** CDN や WAF を前に置いていても、オリジンの IP やホスト名に
直接アクセスできれば、WAF もレート制限も効かない。Cloudflare なら、SSL/TLS のモードが Flexible
（オリジンまで平文）になっていないか、オリジン側で Cloudflare 以外からの接続を拒否しているか
（Authenticated Origin Pulls、Tunnel、IP の許可リスト）を見る。

フェーズ 1 の F-2 で「アプリ側のレート制限が実質機能しない」と判定した場合、ここで**二重に無い状態**になっていないかを確かめる。両方無ければ、指摘の優先度を上げる。

---

## 9. DNS とメール送信ドメイン

見落とされやすい。アプリのコードには一切現れないが、なりすましの成否を決める。

### 問い

- 送信ドメイン認証（SPF / DKIM / DMARC）が設定されているか
- DMARC のポリシーが監視のみ（`p=none`）で止まっていないか。**サブドメイン向け（`sp=`）と
  存在しないサブドメイン向け（`np=`）も見る**
- DMARC の集計レポート（`rua`）を受け取っているか。**受け取っていなければ、誰も運用していない**
- 証明書発行を制限するレコード（CAA）があるか
- DNS 応答の改竄検知（DNSSEC）が有効か
- **使われなくなったサブドメインの CNAME が残っていないか**（サブドメインの乗っ取り）
- 証明書の更新が自動化されているか

```bash
dig +short TXT   <domain>          # SPF
dig +short TXT   _dmarc.<domain>   # DMARC
dig +short CAA   <domain>
dig +short DS    <domain>          # DNSSEC
dig +short MX    <domain>
dig +short TXT   _mta-sts.<domain> ; dig +short TXT _smtp._tls.<domain>   # MTA-STS / TLS-RPT
```

**サブドメインの URL しか分からないときは、親へ遡って引く。** DMARC は受信側が組織のドメインまで遡って探し、
CAA も認証局が親へ遡って確かめ、DS はゾーンの頂点にしか無い。`app.example.com` をそのまま引いて空でも、
`example.com` に設定があることは普通にある。`scripts/recon.sh` は親へ遡って探す。

**読み方**: 詐称メールを受信側に拒否させるのは **DMARC の `p=reject`（または `quarantine`）** で、SPF の有無ではない。
送信をメール配信サービスに委ねている構成では、SPF と DKIM が**サブドメイン側**に設定されていることが多く、
自社からの送信は正しく通る。そのうえで DMARC が `p=reject` なら、apex に SPF が無くても詐称は DMARC で落ちる。
**メールを送らないドメインでも、`v=spf1 -all` と DMARC の `p=reject` を置くのが定石**（2023-02 の経済産業省・
警察庁・総務省の要請は、利用者向けに公開する全てのドメインを「メールの送信を行わないドメイン名を含む」として対象にし、
受信拒否のポリシーでの運用を求めている）。

**業界のガイドラインが `p=reject` を求めていることがある。** たとえば日本証券業協会の「インターネット取引における
不正アクセス等防止に向けたガイドライン」（2025-10-15 施行）は、実施すべき対策として、顧客へ送るメールのドメインの
DMARC を `reject` にすること、サブドメインテイクオーバーへの対策、**メールや SMS にログイン用のリンクを載せないこと**を
挙げている。依頼者の業界にこの種のガイドラインがあるかは取材で聞く（`references/01-scoping.md` の B-4）。

**到達性となりすまし対策を分けて判定する。** 大手のメールサービスは、大量送信者に SPF・DKIM・DMARC を求め、
満たさないメールを弾くようになった（Gmail は 2025-11 から取り締まりを強め、項目に応じて拒否または迷惑メールへの振り分け。
Outlook.com は 2025-05 から `550 5.7.515` で拒否）。
ただし要件は `p=none` でも満たせる。**`p=none` は「届く」の条件は満たすが、なりすましは止めない。**
DMARC の仕様は 2026-05 に RFC 9989〜9991 で改訂され（RFC 7489 を置き換え、Proposed Standard になった）、`pct` が廃止されて
`t=y`（テストモード。指定より 1 段緩いポリシーで扱う）が入り、存在しないサブドメイン向けの `np=` が標準に取り込まれた。
同じ名前に DMARC のレコードが 2 本以上あると、その名前のレコードはすべて捨てられる。

認証不要でメールを送れる経路（フェーズ 1 の F-1）が見つかっている場合、DMARC が `p=none` だと**踏み台にされたときに外形的に止める手段が無い**。組にして評価する。

**DNSSEC が無いときも「取っていない」のか「取れない」のかを区別する。** DNS をホスティングの付属機能で
運用していると、DNSSEC に対応していないことがある（4 節と同じ考え方）。

### サブドメインの乗っ取り

**CNAME が指す先の資源（ホスティングのプロジェクト、ストレージのバケット）を消した後も、CNAME が残っている**と、
第三者がその名前で資源を作ってサブドメインを取れる。取られたサブドメインでは正規の証明書が取れ、
**親ドメインに設定された Cookie も読める。**

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

最長の有効期間は 2026-03 から 200 日、2027-03 から 100 日、2029-03 から 47 日に縮む（CA/Browser Forum の決定）。
**手動で更新している証明書は、もう運用として成り立たない。** 有効期限と発行者を見て、手動の更新が混ざっていないかを聞く。
**OCSP stapling が無いことは指摘にしない**（OCSP は 2024-03 に任意になり、Let's Encrypt は 2025-08 に提供を終えた。
Google Trust Services も大半の証明書から OCSP の情報を外している）。

```bash
echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null \
  | openssl x509 -noout -issuer -enddate
```

---

## 10. 本番エンドポイントの外形テスト

コードで確認したガードが、本番で実際に効いているかを確かめる。

```bash
# 開発用の抜け道が塞がっているか（期待値: 404 か 403）
curl -s -o /dev/null -w "%{http_code}\n" https://<domain>/api/<dev-route>

# セキュリティヘッダの実際の付与状況
curl -sI https://<domain> | grep -iE \
  'strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|x-powered-by|cross-origin-opener-policy|cross-origin-resource-policy|server|x-nextjs-cache|x-vercel-cache'
```

**設定ファイルに書いてあることと、実際の応答は一致しないことがある。** ビルドに反映されていない、エッジ側で上書きされている、といった理由で。必ず本番の応答を見る。

**ヘッダは有無ではなく中身で判定する。** CSP は `references/07-web-vulnerabilities.md` の 1-6 の基準で読む。
COOP は `same-origin`、CORP は `same-site` が推奨値。`X-XSS-Protection` は付けないか `0`
（古いブラウザの XSS フィルタは、それ自体が情報漏えいの原因になった）。

### ミドルウェアの対象範囲を URL の揺れで確かめる

**ミドルウェア（Next.js 16 では proxy）で認可している構成に限る。** 02 の A-5 のとおり、この種の迂回は
枠組みの不具合として繰り返し出ている。保護されたパスを、形を変えて 1 本ずつ GET する。
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

コード監査 B-2 で「ブラウザ側 SDK でログインしている」と判定した場合、外形からも裏を取れる。

```bash
# サーバーが Set-Cookie を返しているか（返っていなければ JS 側で書いている）
curl -sI https://<domain>/<ログイン後のパス> | grep -i set-cookie

# ログイン画面に第三者スクリプトが入っていないか
curl -s https://<domain>/<管理画面のログインパス> \
  | grep -oE '<script[^>]*src="[^"]+"' | sort -u
```

**サーバーが認証 Cookie を発行していないなら、その Cookie に `HttpOnly` は付いていない。** 管理画面のログイン画面に広告・分析タグが入っていれば、指摘の重さが一段上がる。この 2 つは同じ画面で確認できるので、まとめて見る。

### 外から見えてはいけないもの

**本文は保存しない。ステータスコードだけを取る**（3 本目のエラーページの確認だけは、該当する行を画面に出す）。

```bash
for p in /.git/HEAD /.env /.env.local /.env.production /.DS_Store /server.js.map; do
  printf '%-22s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "https://<domain>$p"
done
# 配信している JS にソースマップの参照があり、その .map が取れるか
curl -s https://<domain>/ | grep -oE '/_next/static/[^"]+\.js' | head -3 \
  | while read -r js; do printf '%s.map ' "$js"; curl -s -o /dev/null -w '%{http_code}\n' "https://<domain>$js.map"; done
# 存在しないパスで、スタックトレースや枠組みの版が出ないか
curl -s "https://<domain>/sectest-$(date +%s)" | grep -iE 'stack|trace|exception|at .*\(.*:[0-9]+' | head -3
```

- **`.git` や `.env` の中身が返れば P0**（04 の問い 1。`.env` の鍵や `.git` の履歴から、認証の無い第三者がデータに届く）。
  **報告書を待たずに依頼者へ知らせる。** ただし SPA の構成では、存在しないパスにも 200 で
  トップページを返すことがある。**中身の先頭数バイトだけで判定し、値は出さない**

```bash
# 200 のときだけ。値を画面に出さずに、中身らしいかだけを判定する
curl -s -r 0-15 "https://<domain>/.git/HEAD" | grep -q '^ref:' && echo '.git/HEAD の中身が返っている'
curl -s -r 0-200 "https://<domain>/.env" | grep -qE '^[A-Z_]+=' && echo '.env の中身が返っている'
```
- **ソースマップが公開されていると、元のソースがそのまま読める。** コメントに書いた内部の情報や、
  サーバー用のつもりで書いたコードが出る。Next.js は既定で無効（`productionBrowserSourceMaps`）

### 連絡窓口

- **`/.well-known/security.txt`（RFC 9116）があるか。** 外部の人が脆弱性を見つけたときの連絡先になる。
  あれば `Contact:` と `Expires:`（期限切れでないか）を見る。**無いことは優先度の低い指摘**にする
- HSTS に `preload` を付けているなら、**全サブドメインが HTTPS に対応しているか**。preload は取り消しに
  数か月かかる

`scripts/recon.sh <url>` が、この節のヘッダ・外から見えてはいけないファイル・証明書と、9 節の DNS をまとめて実行する。
**URL の揺れによる迂回の確認、ソースマップ、エラーページは手で行う。**

### curl で見えないところ

**curl は HTML を取ってくるところで止まる。** 事故の多くは、その後の JavaScript が動いてから起きる。
次の 4 つは、ブラウザで読み込まないと判定できない。

- **同意前に第三者への送信が実際に飛ぶか**（HTML にタグがあることと、いつ発火するかは別）
- **JS が書く Cookie と、localStorage に置かれているもの**
- **CSP が実際に何をブロックしているか**（nonce・hash・`strict-dynamic` の無いまま `unsafe-inline` があれば XSS には効かない）
- **認証後の画面が戻るボタンで再表示されるか**

該当するなら `references/09-browser-verification.md` を読む。`scripts/browser_probe.mjs` が、
このうち認証の要らない範囲を自動で取る。

---

## 記録のしかた

**実行した結果をそのまま残す。** 「問題ありませんでした」ではなく、返ってきた行、HTTP ステータス、画面の設定値を書く。

````markdown
### 確認: 全テーブルの行レベルセキュリティ

実行:
```sql
select schemaname, tablename, rowsecurity from pg_tables where schemaname = 'public' order by rowsecurity, tablename;
```

結果: <n> rows。`rowsecurity = false` は 0 件。

| schemaname | tablename | rowsecurity |
|---|---|---|
| public | accounts | true |
| ... | ... | ... |
````

集約や整形をした場合は、**元の行数と、何をしたか**を添える。「<n> 行返ったが読みづらいので、テーブル×ロールで集約した結果を以下に示す（集約後 <m> 行、権限の総数は一致）」のように書く。

### 一覧表を作る

確認が済んだら、区分ごとの一覧表にまとめる。ここが報告書の中核になる。

| 区分 | 確認項目 | 結果（事実） | 判定 | 関連 ID |
|---|---|---|---|---|
| アクセス制御 | 全テーブルの行レベル権限 | <n> テーブルすべて有効。無効は 0 件 | 問題なし | S-xx |
| 認証 | 多要素認証の登録状況 | 登録済み要素 0 件（管理者 <n> 名全員が未登録） | 問題あり | S-xx |
| 事業継続 | バックアップ | 無償プランのため機能自体が無い | 問題あり | S-xx |

判定は 3 値（問題なし／問題あり／判断保留）で、指摘の台帳と同じ意味で使う（`references/04-findings-register.md` の「判定・優先度・状態は別の軸」）。
**「参考」は使わない。** 事実として記録しておくだけのもの（保有件数、最古の登録日など）は、この表ではなく台帳の「気づいたこと」に置く。

### 確認できなかったことを残す

値が読めない設定、権限不足で開けなかった画面、依頼者しか知らない運用は、**未確認事項として通し番号を振る**。詳しくは `references/04-findings-register.md` の「未確認事項」を参照。
