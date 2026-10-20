# アプリケーション層の脆弱性

`references/02-code-audit.md` の D 節（入力と出力）を深掘りするための資料。02 で見当を付けてから、該当する節だけを読む。
各節は「どんな形で現れるか / 何が起きるか / どう直すか」の順に書いてある。

**この資料は、自分たちのシステムの穴を見つけて塞ぐためのもの。** 検証は自分が権限を持つ環境に対してのみ行い、無害な印（`SECTEST<b>1234</b>` のような、太字になるかどうかしか起きない文字列）が想定外の場所に、想定外の形で出るかどうかで判定する。動く攻撃コードを書く必要はないし、書かない。

## 目次

0. [インジェクション（02 の D-1 の補い）](#0-インジェクション02-の-d-1-の補い)
1. [XSS](#1-xss)
2. [CSRF](#2-csrf)
3. [CORS](#3-cors)
4. [オープンリダイレクト](#4-オープンリダイレクト)
5. [SSRF](#5-ssrf)
6. [ファイルアップロード](#6-ファイルアップロード) / [XXE](#6-2-xml-を受け取る場合xxe)
7. [キャッシュ](#7-キャッシュ)
8. [競合と二重送信](#8-競合と二重送信)
9. [業務ロジックの欠陥](#9-業務ロジックの欠陥) / [件数の上限](#9-1-取得する件数大きさを利用者が決めていないか) / [応答に載せる項目](#9-2-応答に載せる項目を絞っているかapi3api10)
10. [言語・処理系に固有のもの](#10-言語処理系に固有のもの)
11. [リアルタイム通信](#11-リアルタイム通信websocket購読チャネル)

---

## 0. インジェクション（02 の D-1 の補い）

02 の D-1 は、SQL を文字列で組み立てる行と生 SQL の入口を拾う。
ここでは、**値を束縛していても残る形と、ORM や BaaS に固有の形**を扱う。

| 形 | 何が起きるか | 直し方 |
|---|---|---|
| **識別子を値から組み立てる**（並び順の列、昇順・降順、テーブル名。`ORDER BY ${sort}`、Prisma の `orderBy: { [req.query.sort]: … }`） | 識別子はプレースホルダで束縛できない。ORM を通していても、列名を利用者が決められる | 受け付ける値の許可リスト（表示名 → 列名の対応表）から選ぶ。対応表に無い値は既定の並びにする |
| **値を束縛しない生 SQL の入口**（Prisma の `$queryRawUnsafe` / `$executeRawUnsafe` / `Prisma.raw`、Drizzle の `sql.raw`、knex の `whereRaw` などにテンプレート文字列を渡す） | 「ORM を使っている」ように見えて、そこだけ文字列の組み立てになる | 束縛する形（Prisma のタグ付きテンプレートの `$queryRaw`、knex の `?` の束縛）に変える |
| **PostgREST のフィルタの文字列に値を差し込む**（Supabase の `` .or(`…${q}…`) ``・`.filter()`・`.not()`） | 値は SQL ではなくフィルタの文法の中に入る。区切りの文字（`,` `(` `)` `.`）を含む値で、条件を足せる | 値を差し込まず、`.ilike()` などの個別のメソッドに値として渡す。`.or()` を使うなら、区切りの文字を含む値を弾く |
| **SQL の文字列を受け取って実行する DB 関数**（`exec_sql` 型の RPC。AI が管理機能の近道として作ることがある） | 公開ロールに実行の権限があれば、公開鍵を持つ誰でも任意の SQL を流せる | 関数を消す。残すなら `anon` / `authenticated` から `execute` の権限を外し、サーバーの特権の鍵からだけ呼ぶ |
| **コマンドの引数に利用者の値を渡す** | シェルを通さなくても、`-` で始まる値はオプションとして読まれる | シェルを通さない呼び方（`execFile`・引数の配列）にし、利用者の値の前に `--` を置く。値の形を許可リストで確かめる |

```bash
# 識別子を値から組み立てる
grep -rnE 'ORDER BY[^;]*(\$\{|" *\+|%s|\{\})|orderBy:[[:space:]]*\{[[:space:]]*\[' --include='*.ts' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' . | head
# 値を束縛しない生 SQL の入口
grep -rnE '\$(queryRaw|executeRaw)Unsafe|Prisma\.raw\(|sql\.raw\(|(whereRaw|orderByRaw|havingRaw|joinRaw)\([[:space:]]*`[^`]*\$\{' --include='*.ts' --include='*.js' . | head
# PostgREST のフィルタの文字列に値を差し込む
grep -rnE '\.(or|filter|not)\([[:space:]]*`[^`]*\$\{' --include='*.ts' --include='*.tsx' --include='*.js' . | head
# SQL の文字列を受け取って実行する DB 関数と、その呼び出し
grep -rniE 'execute[[:space:]]+(format\(|[a-z_]*(sql|query)|\$1)' --include='*.sql' . | head
grep -rnE '\.rpc\([[:space:]]*.(exec|execute|run)_?(sql|query)' --include='*.ts' --include='*.tsx' --include='*.js' . | head
```

関数が見つかったら、`references/03-runtime-verification.md` の 1 節で、公開ロールに `execute` の権限があるかを実機で確かめる。

---

## 1. XSS

現代のフレームワークは既定でエスケープするので、**素の出力から漏れることは少ない。事故は「例外的にエスケープを外した場所」で起きる。** その場所を全部数えるのがこの節の目的。

### 1-1. シンク（危険な出力先）を全部数える

```bash
# HTML を直接流し込む書き方
grep -rnE 'dangerouslySetInnerHTML|v-html|\[innerHTML\]|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.vue' --include='*.svelte' .

# テンプレートエンジンのエスケープ解除
grep -rnE '\{\{\{|\|\s*safe\b|\|\s*raw\b|@Html\.Raw|html_safe|mark_safe|\{\!\!' .

# 動的にコードを組み立てる
grep -rnE '\beval\(|new Function\(|setTimeout\(\s*["'"'"'`]|setInterval\(\s*["'"'"'`]' .
```

**数えたら、1 件ずつ「入力元がどこか」を追う。** 定数やビルド時に確定する値なら問題なし。リクエスト、DB、外部 API から来るなら、**その経路のどこでエスケープされているかを確かめ、無ければ指摘**。
直し方は、エスケープを外した出力をやめて枠組みの通常の出力に戻すこと。HTML を出す必要があるなら、表示の直前に許可リスト方式のサニタイザ（DOMPurify など）を通す（1-3）。

**DB から読んだ値も外部入力として扱う。** 利用者が登録した名前・プロフィール・投稿は、表示する画面では「自分のデータ」に見えるが、
登録した人が別の人でも同じ画面に出る。リクエストの値を直接流し込む行だけを指摘して、保存された値を流し込む行を見送らない。

**サーバーを通らない入力源も追う（DOM XSS）。** URL の断片（`location.hash`）・クエリ（`location.search`・`URLSearchParams`）・
`window.name`・`document.referrer` は、ブラウザの中だけで読まれ、サーバーのログにもエスケープにも現れない。
読んだ値が上のシンクや、1-2 の `href` / `src` に届いていないかを追う。

**別のウィンドウからのメッセージ（`postMessage`）の受け口を見る。**

- 受け口で `event.origin` を**完全一致**で照合しているか。照合が無い、または `indexOf`・`includes`・`startsWith`・`endsWith` の
  部分一致なら、任意のサイトからのメッセージを受ける
- 照合の後で、`event.data` をシンクや `location` に渡していないか
- 送る側で、個人情報やトークンを送るのに宛先を `'*'` にしていないか。埋め込み先が差し替わっても届く
- 直し方は、許可するオリジンの一覧と `===` で比べ、送る側は宛先のオリジンを明示すること

```bash
# DOM の入力源と、メッセージの受け口・送り口
grep -rnE 'location\.(hash|search)|URLSearchParams\(|window\.name|document\.referrer|addEventListener\([[:space:]]*.message.|onmessage[[:space:]]*=|postMessage\(' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.vue' --include='*.svelte' --include='*.html' . | grep -v node_modules | head -30
```

### 1-2. フレームワークの自動エスケープが働かない場所

自動エスケープは「HTML の本文」でしか働かない。次の場所は素通りする。**ここが実務での主戦場。**

| 場所 | 例 | 何が起きるか | 直し方 |
|---|---|---|---|
| **属性値のうち URL を取るもの** | `href={userInput}` / `src={userInput}` | `javascript:` 形式の URL を入れられる（止まるかは枠組みと版で変わる。表の下の注） | URL として解釈し、スキームが `http`・`https`（必要なら `mailto:`）のときだけ使う。保存の時点でも同じ確かめをする |
| **イベントハンドラ属性** | `onclick={...}` | 文字列として組み立てていれば注入できる | 文字列を組み立てず、関数を渡す |
| **`<script>` の中に埋める JSON** | JSON-LD、初期状態の受け渡し | `</script>` を含む文字列でタグを閉じられる | 埋め込む前に `<` を `\u003c` に置き換える（`JSON.stringify(data).replace(/</g, '\\u003c')`） |
| **`<style>` やスタイル属性** | `style={userInput}` | 情報の抜き出しに使われることがある | 利用者の値をスタイルに入れない。選択肢から選ばせる |
| **コンポーネントの `props` を透過的に展開** | `{...userProps}` | 意図しない属性が付く | 渡してよい項目だけを取り出してから渡す |

**URL を取る属性は、枠組みとその版で止まるかが変わる。** React 19 以降（Next.js の App Router が同梱する版を含む）と Angular は、`href`・`src`・`action`・`formAction` に入った
`javascript:` の URL を実行されない値に置き換える。React 18 以前（開発時の警告だけ）、Vue、Svelte、HTML を文字列で組み立てる箇所では止まらない。
止まる版でも、同じ値を `window.location`・`window.open`・メールの本文・Markdown の描画・`dangerouslySetInnerHTML` に流せば止まらない。
**判定は「どの版の何で描画し、その値がほかのどこへ流れるか」をコードと依存の版で確かめてから決める。** 止まる版の属性にしか出ない値でも、
保存の時点で `http`・`https` に絞る是正は勧める（描画の仕組みや版を替えたときに穴が開く）。ほかの出口が無ければ、優先度は低くしてよい。

**JSON-LD は特に見落とされやすい。** `JSON.stringify()` した構造化データに記事タイトルやユーザー入力が混ざると、`</script>` を含む文字列でスクリプトブロックを抜けられる。
`grep -rn 'application/ld+json' -A3 --include='*.tsx' --include='*.jsx' .` で埋め込みを探し、上の表の置き換えをしているかを確かめる。

### 1-3. リッチテキストと Markdown

CMS やユーザー投稿の HTML をそのまま描画していないか。**直し方は、許可リスト方式の HTML のパーサー（DOMPurify・sanitize-html など）を表示時に通すこと。**

- 通しているなら設定を確認する。許可タグに `script` `iframe` `object` `embed` が入っていないか、`on*` 属性と `style` を除いているか。Markdown レンダラの「生 HTML 許可」が有効になっていないか
- **保存時だけに通す構成**は、保存経路が複数あると破れる
- **書き込む側の正規表現の除去は、サニタイズとして認めない。** `<script>` 要素と引用符で囲んだ `on*` 属性を消すだけでは、
  `javascript:` の URL・引用符の無い属性・`iframe`・`form`・`meta` の転送が残る
- **書き手が人でない HTML も同じ扱いにする。** CMS の本文を LLM や外部の連携が書いている経路では、「社内の編集者が書くから信用できる」という前提が成り立たない
  （`references/12-ai-features.md` の 9 節）。書き込みの鍵を持つ人・仕組みのどれか 1 つが侵されれば、本文はそのまま本番の画面に出る

### 1-4. 格納型 XSS の経路

**攻撃者が入力し、別の権限の人が見る画面**を洗う。ここが一番被害が大きい。

- 問い合わせフォームの自由記述 → 管理画面の案件詳細
- 取引先が設定する会社名・担当者名 → 運営の一覧画面
- 外部連携で取り込むデータ → 社内向けダッシュボード

管理画面は「社内だから」と対策が薄くなりがちで、しかも**運営セッションを盗まれると全顧客情報に届く**。優先度は公開画面より高いことが多い。

### 1-5. メール本文

HTML メールを文字列連結で組み立てている箇所は、Web と同じ問題が起きる。**通知関数が複数あるときは全部を突き合わせる。** 1 つだけエスケープを通していない、という形が典型。
直し方は、エスケープするテンプレート（React Email、テンプレートエンジンの通常の出力）で組み立てるか、差し込む値をすべて同じエスケープ関数に通すこと。

```bash
# メール送信関数を列挙して、エスケープ関数を通しているかを見る（TS / JS に加え、Python・Ruby・PHP・Go の書き方）
grep -rnE 'sendMail|sendEmail|resend\.|nodemailer|SES|sendgrid|send_mail|EmailMessage|smtplib|ActionMailer|deliver_(now|later)|Mail::(send|to)|PHPMailer|net/smtp|gomail' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' . | grep -v node_modules | head -30
```

### 1-6. CSP の実効性

CSP は XSS を防ぐものではなく、**成立したときの被害を狭める**もの。実際の応答ヘッダで（`references/03-runtime-verification.md`）、**実際に適用される値**で判定する。
`connect-src`・`object-src` などが無ければ `default-src` が使われる。

| 指令 | 無いとどうなるか |
|---|---|
| `script-src` | 外部からの任意のスクリプトの読み込みを止められない。**`frame-ancestors` だけの CSP は XSS に対して無力** |
| `connect-src` | 盗んだデータの外部送信を止められない |
| `object-src` | プラグイン経由の実行を防げない。推奨は `'none'` |
| `base-uri` | `<base>` を差し込まれると相対パスのスクリプトの読み込み先が変わる。**`default-src` に委ねられない。** 推奨は `'none'` か `'self'` |
| `frame-ancestors` | クリックジャッキングを防げない。**`default-src` に委ねられない** |

- **`<meta http-equiv>` で配る CSP は、`frame-ancestors`・`report-uri`・`sandbox` を無視される。** 応答ヘッダで配っているかを `curl -sI` で別に確かめ、`<meta>` にしか無ければ `frame-ancestors` は無いものとして判定する
- **`'unsafe-inline'` は、あるだけで判定しない。** 同じ `script-src` に nonce・hash・`'strict-dynamic'` のいずれかがあれば、ブラウザは `'unsafe-inline'` を無視する。古いブラウザ向けに並べる形は推奨されていて、指摘にはならない。
  問題になるのは、nonce も hash も `'strict-dynamic'` も無いのに `'unsafe-inline'` があるとき。`'unsafe-eval'` は打ち消されないので、あれば防御が弱まる
- **許可リスト型（`script-src cdn.example.com`）は迂回されやすい。** 許可したドメインに JSONP や古いライブラリがあれば踏み台にされる
- **直し方**: nonce または hash と `'strict-dynamic'`、`object-src 'none'`、`base-uri 'none'` の組み合わせ（strict CSP）。Next.js で nonce を使うとそのページは動的レンダリングになる点を書き添える。
  `innerHTML` などへの文字列の代入そのものを止めたいなら、`require-trusted-types-for 'script'`（Trusted Types）も選択肢になる。
  **既存サイトにいきなり厳格な CSP を入れると壊れる**ので、`Content-Security-Policy-Report-Only` での観測から始める段取りにする

### 1-7. 検証

```bash
# 反射の確認: 無害な印（SECTEST<b>1234</b>）がエスケープされずに応答へ出ていないか
curl -s "https://<domain>/search?q=SECTEST%3Cb%3E1234%3C%2Fb%3E" \
  | grep -oE 'SECTEST(<b>|&lt;b&gt;|&#60;b&#62;|\\u003cb\\u003e)1234' | sort | uniq -c
```

`&lt;b&gt;` などに変換されていれば正しく、`<b>` のまま出ていればその経路はエスケープされていない。タグの形の印なので、依頼者にも「太字になったか」で答えてもらえる（`references/09-browser-verification.md` の 5 節）。
**送る前に、その入力を保存する機能（検索履歴、「人気の検索」、検索語を送る計測）が無いかをコードで確かめる。** あれば GET でも印が本番のデータに残るので、下の格納型と同じ扱いにする。

**格納型は、評価者が保存して確かめない**（保存は状態を変える操作で、SKILL.md の「参照系だけを実行する」に反する）。
保存する経路（1-4）、表示するシンク（1-1）、その間のエスケープとサニタイズ（1-3）をコードで追えば、多くは保存せずに決まる。
決まらなければ、依頼者に検証環境で、試験用のアカウントで印を保存して表示側の画面を見てもらう（`references/03-runtime-verification.md` のモード B）。検証環境が無ければ、未確認事項に残してコードの根拠で指摘を書く。

---

## 2. CSRF

**探し方**: 状態を変えるエンドポイントの認証方式を確認する。

- **Cookie でセッションを持っている** → CSRF の対象。トークン検証、`Sec-Fetch-Site` / `Origin` の照合、`SameSite` 属性のどれで防いでいるか
- **`Authorization` ヘッダでトークンを送る** → ブラウザが自動送信しないので、古典的な CSRF は成立しにくい。
  ただし**画面の JS が URL の値をそのまま API のパスに連結している**と、正規の呼び出しを別のエンドポイントへ
  向け直せる（クライアントサイドのパストラバーサル。CSPT2CSRF）。トークンごと送られるので防げない。直し方は、パスに入れる値を `encodeURIComponent` し、ID の形（UUID・数字）を確かめること

**枠組みが既定で守るかどうかで、探すものが逆になる。**

| 枠組み | 既定 | 探すもの |
|---|---|---|
| Rails・Django・Laravel・Spring Security | Cookie のセッションに対して、既定でトークンを検証する | **外している箇所。** `skip_forgery_protection`・`protect_from_forgery` の `except`、`@csrf_exempt`、Laravel の `VerifyCsrfToken` の `$except` や `validateCsrfTokens(except: …)`、Spring の `csrf` の `disable()` と `ignoringRequestMatchers`。AI は 403 を消すためにこれを足すことがある |
| Express・Koa・Fastify・Hono・Flask・FastAPI・Go（net/http・Gin・Echo） | 既定の対策が無い | Cookie でセッションを持つなら、**状態を変える全ルートを数え**、それぞれに対策（トークン、`Sec-Fetch-Site` / `Origin` の照合、明示の `SameSite`）が掛かっているかを見る。ミドルウェアを入れていても、掛かる範囲から外れたルートは守られない |
| Next.js の Server Actions・SvelteKit | 既定で `Origin` と `Host` を照合する | 照合を緩める設定（`next.config` の `serverActions.allowedOrigins` に `'null'` やワイルドカード、SvelteKit の `checkOrigin: false`） |

**メソッドの上書きを受け付けていないか。** `_method` の値や `X-HTTP-Method-Override` ヘッダで、POST を PUT / DELETE として扱う仕組みがある。
上書きを GET にも認めていると、`SameSite=Lax` でも送られる GET で状態が変わる。対策がメソッドで分岐していれば、上書きの前と後のどちらで判定しているかも見る。

```bash
# 枠組みの防御と、それを外している箇所
grep -rnE 'Sec-Fetch-Site|sec-fetch-site|checkOrigin|allowedOrigins|csrf|CSRF|forgery_protection|VerifyCsrfToken|validateCsrfTokens|ignoringRequestMatchers|CrossOriginProtection' \
  --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' --include='*.rb' --include='*.php' --include='*.java' --include='*.kt' --include='*.go' . | grep -v node_modules | head -30
# メソッドの上書き
grep -rnE '_method|X-HTTP-Method-Override|methodOverride|method_override' --include='*.ts' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' . | grep -v node_modules | head
# CSPT: URL の値を API のパスへ直に連結している箇所（ブラウザ側のコード）
grep -rnE 'fetch\(`[^`]*\$\{(params|searchParams|query|router\.query|slug|id)' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.vue' --include='*.svelte' . | head
```

**`SameSite` の判定**: **明示の `SameSite=Lax` / `Strict` が無ければ、防御は無いものとして判定する。** 属性の無い Cookie を Lax として扱うのは Chromium 系だけで、
Firefox と Safari では付いていないのと同じになり、Chrome の既定 Lax にも発行から 2 分以内は POST でも送る例外がある。
明示されていれば、クロスサイトからの POST は送られず、多くの構成でこれが実質的な防御になっている。その場合も「対策済み」ではなく **「`SameSite` に依存している」と書く。**
同じ登録ドメインの別サブドメイン（利用者がコンテンツを置けるもの、乗っ取られたもの）からの要求は止めず、
`SameSite=None` が必要になったとき（別ドメインへの埋め込み、決済からの戻りなど）に前提が崩れるため。
`GET` で状態が変わるエンドポイントは `SameSite` でも防げない（02 の A-4）。

**直し方**: 推奨の順は、**枠組みの組み込み対策を有効にする → トークン → Fetch Metadata（`Sec-Fetch-Site` で cross-site の状態変更を拒否し、`Origin` と `Host` の照合を予備にする）**。
`SameSite=Lax` の明示は、これらに重ねる多層防御として勧める。

---

## 3. CORS

**探し方**: CORS ヘッダを返している箇所と、その値。

CORS は、コードのほかに枠組みの設定ファイルとホスティングの設定で書かれる。コードだけを探すと見落とす。

| 書く場所 | 例 |
|---|---|
| コード | Express の `cors(`、Flask の `CORS(app`、FastAPI / Starlette の `allow_origins`、Spring の `@CrossOrigin`、ASP.NET の `AllowAnyOrigin` / `SetIsOriginAllowed`、Go の `AllowOrigins` |
| 枠組みの設定 | Django の `CORS_ALLOW_ALL_ORIGINS`（旧名 `CORS_ORIGIN_ALLOW_ALL`）、Rails の `rack-cors`（`config/initializers/cors.rb`）、Laravel の `config/cors.php` |
| ホスティングと配信 | `vercel.json` の `headers`、`next.config.*` の `headers()`、`netlify.toml`、`_headers` |

```bash
grep -rnE 'Access-Control-Allow-(Origin|Credentials)|cors\(|CORS\(|allow_origins|CrossOrigin|AllowAnyOrigin|SetIsOriginAllowed|AllowOrigins|CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL|Rack::Cors|allowed_origins' \
  --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' --include='*.rb' --include='*.php' --include='*.java' --include='*.kt' --include='*.cs' --include='*.go' --include='*.json' --include='*.toml' . | grep -v node_modules | head -30
ls config/cors.php config/initializers/cors.rb vercel.json netlify.toml public/_headers 2>/dev/null
# 実際の応答で確かめる。無関係の Origin と、Origin: null の 2 つを送る
curl -sI -H 'Origin: https://example.invalid' https://<domain>/api/<endpoint> | grep -iE 'access-control|^vary'
curl -sI -H 'Origin: null' https://<domain>/api/<endpoint> | grep -iE 'access-control|^vary'
```

**何が問題か**:

- `Access-Control-Allow-Origin: *` と `Allow-Credentials: true` の併用はブラウザが拒否するが、**リクエストの `Origin` をそのまま反射して返す実装**は同じ危険を生む。認証付きのリクエストが任意のサイトから通る。
  ライブラリによっては、ワイルドカードと資格情報の許可を併せて設定すると反射に切り替わる。**設定の値だけで判定せず、実際の応答で確かめる**
- 許可リストの照合が前方一致・部分一致になっていないか。`example.com` の照合が `evil-example.com.attacker.invalid` を通してしまう形
- **`Origin: null` を許可していないか。** サンドボックスの iframe やローカルのファイルからの要求は `null` になり、誰でもこの値で送れる
- **応答が `Origin` で変わるのに `Vary: Origin` が無いと、** 共有キャッシュで別のオリジン向けの応答が配られる（7 節）

**直し方**: 許可するオリジンを完全一致の一覧で持ち、一覧にあるときだけその値を返す。資格情報を付ける API では `*` も反射も使わず、`null` を一覧に入れない。
同じオリジンからしか呼ばない API なら、CORS の設定そのものを消す。応答が `Origin` で変わるなら `Vary: Origin` を付ける。

---

## 4. オープンリダイレクト

**探し方**: リダイレクト先を外部入力から決めている箇所。ログイン後の戻り先、パスワード再設定、決済からの復帰。事前の洗い出しの 2j 節に候補が出る。

**何が問題か**: フィッシングの踏み台になる。自社ドメインのリンクを踏ませて、攻撃者のサイトへ送れる。認証基盤のトークンを付けた転送なら、トークンが第三者へ渡る（下の表）。

**見落としやすい形**:

- **`/` で始まるかだけを確かめる形は穴。** `//attacker.example` や `/\attacker.example` は `/` で始まるが、ブラウザは別のホストとして扱う
- **サブドメインのワイルドカード許可。** `*.example.com` を許すと、外部サービスに委譲しているサブドメインや、乗っ取られたサブドメインが踏み台になる
- 値を変数に受けてから、離れた行で転送している形。読んだ行から転送の行までに確かめがあるかを追う

**直し方**: 戻り先は許可したパスの一覧から選ぶか、URL として解釈して（`new URL(値, 自サイトのオリジン)`）オリジンが自サイトと一致するときだけ転送する。外部へ送るなら完全一致のホストの一覧で照合する。

```bash
# TS 以外の案件では拡張子と書き方を足す（Django の redirect、Rails の redirect_to、Laravel の redirect()->to など）
grep -rnE 'redirect|redirectTo|returnTo|next=|callbackUrl|redirect_to|return_url' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' . | grep -v node_modules | head -30
```

### 認証基盤の転送先の許可リスト

**転送先はアプリのコードの外でも決まる。** マジックリンク、パスワード再設定のメール、OAuth のログインは、認証基盤が
トークンを付けて転送先へ送る。その転送先の許可リストが広ければ、**トークンが第三者の用意したページへ届く。** コードを読んでも見えない。

| 基盤 | 設定の場所 |
|---|---|
| Supabase Auth | Authentication → URL Configuration の Site URL と Redirect URLs（ワイルドカードを書ける） |
| Firebase Authentication | Authentication → Settings の承認済みドメイン（Authorized domains） |
| Auth0 | アプリケーションの Allowed Callback URLs・Allowed Logout URLs・Allowed Web Origins |
| その他（Clerk・Cognito・自前の OAuth サーバー） | 同じ役割の許可リスト（コールバック URL・リダイレクト URI） |

- **第三者も作れるドメインのワイルドカードが無いか。** ホスティングのプレビュー用の共有ドメイン全体（`*.<ホスティングの共有ドメイン>`）を
  許していると、誰でもその下にページを出せる。プレビューを許すなら、自分のチームやプロジェクトに限った形にする
- **本番の許可リストに `localhost` や開発用のドメインが残っていないか**
- **パス全体のワイルドカード（`/**`）で、自サイトの中の開いた転送（上の形）を経由できないか**

確かめるのは設定の画面なので、`references/03-runtime-verification.md` のモード A か、モード B で依頼者に値を写してもらう。
02 の B-5 の `redirect_uri` の照合と併せて見る。

---

## 5. SSRF

**探し方**: サーバー側から外部へ HTTP リクエストを出している箇所と、その URL の決まり方。

**何が問題か**: URL を外部入力から組み立てていると、内部ネットワークやクラウドのメタデータ endpoint を叩かせられる。

**判定**: 送信先が定数、または環境変数で固定されていれば低リスク。そう書く。可変なら、許可リストの有無とスキーム制限を見る。
直し方は、送信先のホストを許可リストで完全一致で照合し、スキームを `https`（必要なら `http`）に限ること。

**外部のホストを広く許す機能**（OGP の取得、URL を指定した画像の取り込み、Webhook の送信先を利用者が登録する機能）は、
許可リストで絞れない。この場合は、送信先の検証が次の穴を塞いでいるかを見る。

| 穴 | 何が起きるか | 直し方 |
|---|---|---|
| **リダイレクトの追従** | 検証を通った外部の URL が、内部のアドレスへ転送する。`fetch` など多くの HTTP クライアントは既定で転送を追う | 転送を追わない設定（`fetch` の `redirect: 'manual'` など）にし、追うなら転送先ごとに同じ検証をやり直す |
| **名前の再解決** | 検証のときに解決した IP と、接続のときに解決した IP が違う（DNS の応答を短時間で切り替える） | 解決した IP を検証し、**その IP へ接続する**。検証と接続で別々に解決させない |
| **IP の表記の揺れ** | 10 進の整数、8 進、省略形、IPv6 に埋め込んだ IPv4、`0.0.0.0` は、文字列の比較をすり抜ける | 文字列で比べず、標準の関数で IP として解釈してから、ループバック・プライベート・リンクローカル（`169.254.0.0/16`・`fe80::/10`）・IPv6 のユニークローカル（`fc00::/7`）の範囲で弾く |
| **クラウドのメタデータ** | 内部へ届いたとき、インスタンスの資格情報が取れる | AWS なら、メタデータの取得にトークンを要求する設定（IMDSv2 の必須化。Terraform では `metadata_options` の `http_tokens = "required"`）になっているかを `references/13-infrastructure.md` の 3 節の定義で見る |

**見落としやすい経路**:

- リクエストの `Host` ヘッダや、フレームワークが提供する「現在のオリジン」から URL を組み立てている箇所。リバースプロキシの設定次第で、`Host` は攻撃者が指定できる。PDF 生成のフォント取得、画像の取り込み、OGP の取得でよく出る。直し方は、自サイトのオリジンを環境変数で固定して使うこと
- **枠組みの設定。** リライト・リダイレクトの宛先を要求の値から組み立てている、ミドルウェアで要求ヘッダをそのまま上流へ渡している、画像最適化の取得先の許可（Next.js の `remotePatterns`）にワイルドカードがある、という設定も SSRF の入口になる

**サーバー側で HTML を描画して PDF や画像を作る処理も、SSRF とファイルの読み取りの入口になる。** 請求書・領収書・OGP の画像などを
ヘッドレスブラウザ（Puppeteer・Playwright）や HTML から PDF への変換（wkhtmltopdf・WeasyPrint）で作り、その HTML に**利用者の値**（宛名・備考・画像の URL）が入る形。
エスケープせずに差し込むと、`<iframe src="file:///…">` や `<img src="http://内部">` が描画され、サーバーの中のファイルや内部のアドレスが PDF に写る。
直し方は、値を文字としてエスケープして差し込み、描画のときの外部への取得を止め（要求を横取りして許可した取得先だけ通す、`file:` を拒否する、JavaScript を切る）、
描画するプロセスを内部のネットワークに届かない場所で動かすこと。変換の道具は古い版のまま残りやすいので版も確かめる（`references/10-dependencies.md`）。

```bash
grep -rnE "puppeteer|playwright|chromium|wkhtmltopdf|weasyprint|html-pdf|pdfkit|@react-pdf|setContent\(|page\.pdf\(" \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.rb' . 2>/dev/null | grep -v node_modules | head -20
grep -nE 'rewrites|redirects|destination:|remotePatterns|domains:' next.config.* 2>/dev/null
```

---

## 6. ファイルアップロード

該当する機能があれば見る。受け取り口と種類の判定の行は、事前の洗い出しの 3b 節に候補が出る。

| 形 | 何が起きるか | 直し方 |
|---|---|---|
| **禁止する種類を列挙する判定（拒否リスト）** | 一覧に無い種類がすべて通る。`.html`・`.svg`・`.js`、サーバーで実行される拡張子、二重拡張子（`a.php.png`）、大文字（`.PHP`）が抜けやすい | 許す種類の許可リストにする。変えるまで指摘にする |
| 拡張子だけで判定している | 中身の違うファイルが通る | 実際の内容（マジックナンバー）も確かめる |
| **SVG・HTML を受け付けて同じオリジンから配る** | SVG は中にスクリプトを書ける。開いた人の権限で動く | サニタイズするか、別オリジンから `Content-Disposition: attachment` で配る |
| 公開ディレクトリに保存し、実行可能な形式も受け付ける | アップロードしたファイルがサーバーで実行される | 公開しない場所かオブジェクトストレージに保存する |
| ファイル名を外部入力から作る | パストラバーサルで別の場所へ書く | 保存名はサーバーで作る（UUID など） |
| 配信時の `Content-Type` が誤り、`X-Content-Type-Options: nosniff` が無い | ブラウザが中身から種類を推測して HTML として描画する | 正しい `Content-Type` と `nosniff` を付ける |
| サイズと件数の上限が無い | 保存領域と処理を使い切られる | サーバーで上限を確かめる |

**受け取った後の処理でも枯渇する。** 上限を通ったファイルでも、展開や変換で膨らむ。

- **圧縮ファイルの展開**: 展開後のサイズと件数に上限があるか（小さな書庫が数 GB になる zip 爆弾）。
  **書庫の中のファイル名の `../` や絶対パスで、展開先の外へ書かないか**（zip slip。正規化した書き込み先が展開先の中かを確かめる）
- **画像や文書の変換**: 変換ライブラリは外部プロセスを呼ぶことがあり、そこに脆弱性が出る。版を確かめる（`references/10-dependencies.md`）
- **XML の解析**: 6-2 節

### 配信する側

**受け取り口だけでなく、ファイルを返す口も見る。** 利用者の値でファイルのパスを決めて返していると、
`..` を含む値で基準のディレクトリの外（設定ファイル、`.env`、他人のアップロード）を読める。

- `res.sendFile(req.params.name)`・`send_file(os.path.join(dir, name))` のように、利用者の値をパスに連結していないか。
  `path.join` や `os.path.join` は `..` で基準の外へ出る値を拒まない（`os.path.join` は、後ろの引数が `/` で始まると前を捨てる）。
  直し方は、**ID からパスを引く対応表にする**か、基準のディレクトリの外を拒む関数（Flask の `send_from_directory` など）を使うこと。自前なら、正規化した絶対パスが基準の下にあるかを比べる
- **署名付き URL を、利用者の送ったパスから作っていないか**（`createSignedUrl`・`getSignedUrl`）。署名は「誰でも読める」許可になるので、
  パスの持ち主が要求した本人かを署名の前に確かめる

```bash
# ファイルを返す口と、署名付き URL を作る口。1 行ずつ、パスに入る値が利用者から来るかを追う
grep -rnE 'sendFile\(|send_file\(|send_from_directory\(|FileResponse\(|createReadStream\(|readFile(Sync)?\(|createSignedUrl\(|getSignedUrl\(|os\.Open\(|http\.ServeFile\(|File\.(Open|ReadAll)' \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' --include='*.cs' --include='*.java' . | grep -v node_modules | head -30
```

### 6-2. XML を受け取る場合（XXE）

**外部実体の解決を止めているか。** 止めていなければ、XML を送るだけでサーバー上のファイルを
読み出せる。応答に出る内容だけでなく、**エラーメッセージや外部への接続（SSRF）としても成立する。**

**該当するのは、XML を受け取る構成だけ。** SVG のアップロード、SOAP、RSS の取り込み、Office 文書（中身は XML の書庫）、SAML の応答が典型になる。
**JSON しか受け取らないなら、この節は不要。**

- 解析器の設定で外部実体と DTD を無効にしているか。**既定で有効な処理系がある**。直し方は、DTD を禁止する設定（Java の `disallow-doctype-decl`、Python なら `defusedxml`）にすること
- SAML を使っている場合、**署名の検証と実体の解決の順序**まで見る

```bash
# XML を解析している箇所
grep -rnE 'DocumentBuilder|SAXParser|XMLReader|etree|lxml|libxml|SimpleXML|XmlDocument|xml2js' \
  --include='*.java' --include='*.py' --include='*.php' --include='*.cs' --include='*.ts' .
```

---

## 7. キャッシュ

**見落とされやすいわりに、個人情報の漏えいに直結する。**

**探し方**: キャッシュ制御の指定と、認証が必要なページの組み合わせ。アプリの中のデータのキャッシュは、コードで探す（下）。

```bash
# 認証が必要なページのキャッシュヘッダ
curl -sI https://<domain>/<認証が必要なパス> | grep -iE 'cache-control|vary|age|x-cache|cf-cache-status'
```

**何が問題か**:

- **利用者ごとに違う内容を返すページが、CDN やプロキシでキャッシュされる**と、他人の画面が配られる。`Cache-Control: private` か `no-store` が付いているか。
  エラーページやリダイレクト、静的化の仕組み（インクリメンタルな再生成など）の対象に入った個人情報のページも同じ
- 認証状態やロールで内容が変わるのに `Vary` が無いと、混ざる
- **既定は枠組みと版で違う**（Next.js は 15 で `GET` の Route Handler とクライアント側のルーターキャッシュの既定が変わった）。依存の版を確かめてから判定する
- **エッジで認可を判定してキャッシュする構成**は、判定結果ごとキャッシュされると、権限の違う利用者へ同じ応答が配られる

### 4 つを区別する

同じ「キャッシュ」でも、経路が違う。**混ぜると是正の指示を間違える。**

| | 何が起きるか | 見るところ | 直し方 |
|---|---|---|---|
| **漏えい（既定の指定漏れ）** | 認証済みの応答が共有キャッシュに入り、他人へ配られる | `Cache-Control` と `Vary` | 認証済みの応答に `Cache-Control: private, no-store` を付ける。内容を変える要素を `Vary` に入れる |
| **キャッシュ・デセプション** | 攻撃者が**利用者に踏ませた URL** の応答がキャッシュされ、後から攻撃者が取り出す | **URL の解釈がキャッシュ層とアプリで食い違う場所** | キャッシュする対象を拡張子でなく、静的ファイルのパスの一覧か応答の `Content-Type` で決める。認証済みの応答に `no-store` を付ける |
| **キャッシュ・ポイズニング** | 攻撃者の応答がキャッシュに入り、他の利用者へ配られる | キャッシュ鍵に入らないヘッダを見て応答を変えていないか | キャッシュ鍵に入らないヘッダ（`X-Forwarded-Host` など）で応答を変えない。変えるなら鍵に入れる |
| **アプリの中のデータのキャッシュ** | HTTP のヘッダが正しくても、アプリが関数の結果や DB の結果を利用者を区別せずに保存し、他人へ返す | キャッシュの鍵に利用者・テナント・権限が入っているか（下） | 鍵に利用者・テナント・権限を入れる。利用者ごとのデータはキャッシュしないか、キャッシュする関数の外で認可する |

**アプリの中のデータのキャッシュは、HTTP のヘッダを見ても分からない。** Next.js の `unstable_cache`・`'use cache'`・`fetch` のキャッシュ、
Redis や KV に関数の結果を置く書き方、モジュールの変数に結果を持つ書き方で、**キャッシュの鍵（引数・タグ・キー名）に利用者やテナントが入っていない**と、
最初に呼んだ人の結果が次の人に返る。鍵に入っていても、キャッシュする関数の中で Cookie やセッションを読んでいれば、鍵とずれる。

```bash
grep -rnE "unstable_cache\(|['\"]use cache['\"]|cacheTag\(|cacheLife\(|revalidateTag\(|redis\.(get|set)|kv\.(get|set)|new (LRUCache|Map)\(" \
  --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | grep -v node_modules | head -20
```

**デセプションは、静的ファイル扱いされる見た目の URL で中身が返り、そこに共有キャッシュ可の指定が付くかで決まる。**
認証が必要なパスの後ろに静的に見える要素（`/mypage/x.css`・`/mypage;x.js`）を足した URL の応答の状態とキャッシュのヘッダで確かめる。
URL の揺れを含む要求は WAF や監視に攻撃として記録されることがあるので、送る日時と送信元の IP を依頼者の運用側へ先に伝える。

**枠組みやホスティング側の不具合でも起き、アプリのコードを読むだけでは見つからない。** 依存の版を確かめ、
枠組みの公式の勧告の一覧（GitHub の各リポジトリの `security/advisories`）で、キャッシュに関わるものが対象の版に該当しないかを確かめる（`references/10-dependencies.md`）。

---

## 8. 競合と二重送信

**探し方**: 「回数」や「残数」が意味を持つ処理。ポイント、在庫、上限つきの申込、課金の発生。

**何が問題か**: アプリ側で件数を数えてから書き込む実装は、同時に叩かれると両方が通る。
「同時に叩かれることは滅多にない」は成り立たない。数十本の要求を 1 ミリ秒未満の差で同時に届ける手法（single-packet attack）が一般的な道具に入っていて、
数えてから書く実装は、狙われればほぼ確実に破られる前提で判定する。

**判定**: DB の一意制約、トランザクション、行ロック、DB トリガーのいずれかで担保されているか。アプリのチェックだけなら指摘になる。
**担保されていれば、それは評価できる実装として記録する。**

**直し方**: 確かめと書き込みを 1 つの文にする（`UPDATE … SET stock = stock - 1 WHERE id = ? AND stock > 0` で、更新した件数が 0 なら断る）、
一意制約を付ける、`SELECT … FOR UPDATE` で行をロックしたトランザクションにする。二重送信は、冪等キー（決済代行の idempotency key、要求ごとの一意な ID）で弾く。

**このスキルでは試さない。** 同時に書き込む試験は状態を変える。確かめる必要があるなら、
依頼者に検証環境での確認を依頼する（`references/03-runtime-verification.md` のモード B）。

**途中で失敗したときに、前の段の変更を巻き戻しているか**（OWASP Top 10:2025 の A10）。数段に分かれた処理（決済が通る → 注文を作る →
在庫を減らす → クレジットを引く → LLM を呼ぶ）で、途中の段が例外で止まったときに、前の段の変更が残らないか。
DB の変更は 1 つのトランザクションに入れているか。外部の決済のように巻き戻せない段は、後の段の失敗を拾って取り消す処理（返金・付与の取り消し）があるか。
**例外の受け皿が、成功として応答していないか**（`catch` で記録だけして 200 を返す。02 の K-2）。

---

## 9. 業務ロジックの欠陥

自動化された検査では出てこない。**そのサービスの業務を理解しないと見えない。** フェーズ 0 の取材の結果を使うところ。

見るべき問い。

- **金額や数量を、クライアントから受け取っていないか。** 単価をリクエストボディに含めている実装は、値を書き換えられる
- **状態遷移が飛ばせないか。** 「審査中」を経ずに「承認済み」へ行けないか。`status` を条件に入れずにレコードを取得している箇所は、状態を無視して操作できる。
  直し方は、更新の条件に今の状態を入れる（`WHERE id = ? AND status = '審査中'`）こと
- **自分に関する設定のうち、本来は運営が決めるものを自分で変えられないか。** 上限値、料金プラン、権限のフラグ。更新を許可する項目を許可リストで絞っているか、それとも受け取ったオブジェクトをそのまま渡しているか（マスアサインメント。直し方は、更新してよい項目だけをスキーマで取り出して渡すこと）
- **無料で得られるはずのないものを、経路を変えて得られないか。** 有料機能の結果を、別の公開エンドポイントが返していないか

```bash
# 更新系で、受け取ったオブジェクトをそのまま渡していないか（マスアサインメント）。
# 枠組みを問わない候補は事前の洗い出しの 2g 節に出る。これは TS の書き方を補う例
grep -rnE '\.update\(\s*(body|req\.body|data|input)\s*\)|\.update\(\{\s*\.\.\.' --include='*.ts' --include='*.js' .
```

決済と特典まわりで、AI で作ったアプリに出やすい形。

| 形 | 直し方 |
|---|---|
| 決済代行の支払い画面を作るときに、品目や単価（Stripe Checkout の `line_items` の `price_data.unit_amount` など）をクライアントの値から作る | サーバーで商品の ID から価格を引く。決済代行に登録した価格の ID を使う |
| 数量に 0 や負の数、上限を超える数を受け付ける | サーバーで範囲を確かめる。合計の計算の前に弾く |
| クーポンや招待コードを、同じ利用者が何度も使える。使った記録をアプリの中だけで数えている | 使用の記録を DB に持ち、利用者とコードの組に一意制約を付ける（8 節の競合も見る） |
| 無料の試用を、メールアドレスの別名（`+` の付いた別名、ドメインごとの表記の揺れ）で何度も始められる | 試用の権利を、正規化したメールアドレスや支払い手段など、作り直しにくいものに結び付ける |

**検索条件を利用者に組み立てさせていないか（ORM Leak）。** 絞り込みの項目名や演算子を外部入力から取り、
そのまま ORM の `where` に渡していると、関連を辿って**パスワードのハッシュやトークンを 1 文字ずつ漏らせる**
（`password: { startsWith: "a" }` を繰り返す形）。Prisma・Django・Sequelize に加え、Supabase が使う PostgREST でも成立する。
**PostgREST 系では、公開鍵で呼べる API が任意の列で絞り込めること自体がこの経路になる**ので、03 の 1 節で機微な列が読める状態に無いかを併せて見る。
直し方は、絞り込める項目と演算子を許可リストで決め、その対応表から `where` を組み立てること。

```bash
grep -rnE 'where:\s*(body|input|req\.body|params|query|filters?)\b|findMany\(\{\s*where:\s*[a-z]+\s*\}|\.filter\(\*\*(request|data)' --include='*.ts' --include='*.py' . | head
```

### 9-1. 取得する件数・大きさを利用者が決めていないか

一覧の件数（`limit`・`per_page`・`pageSize` など）をリクエストの値で決め、**上限を確かめていなければ、1 回の要求で全件を取り出せる。**
下限（0 以下を弾く）しか見ていない実装が多い。**公開の一覧でも問題になる。** 負荷で止められるうえ、1 件ずつなら目立つ取得を
1 回で済ませられる（件数の制限を業務の決まりとして置いているなら、その決まりを破れる）。「公開の情報だから問題なし」にしない。
事前の洗い出しの 2h 節に候補が出る。

- 上限を付けているか（`Query(…, le=100)`・`@Max(100)`・`max_page_size`）、上限で切り詰めているか（`Math.min(limit, 100)`）。直し方もこの形で、既定値と最大値をサーバーで持つ
- 件数のほかに、取り出す大きさ（画像の幅と高さ、書き出しの期間、入れ子の深さ）を利用者が決めていないか

### 9-2. 応答に載せる項目を絞っているか（API3・API10）

**画面に出していない項目も、応答には載っている。** DB の行や ORM のモデルをそのまま返すと、画面では使っていない列
（パスワードのハッシュ、他人のメールアドレス、`role` などの権限の列、内部のフラグ、トークン）が応答に入る。
**画面を見ても分からないので、応答そのものか、返している値の作り方を見る。**

- `select('*')`・列を指定しない `findMany()`・`fields = '__all__'` のシリアライザの結果を、加工せずに `res.json()` や `return` で返していないか
- 一覧の API で、他人の行の個人情報の列まで返していないか。本人の詳細の API と同じ形を一覧にも使っている形が典型
- SSR やサーバーコンポーネントで、DB の行を丸ごとクライアントのコンポーネントへ渡していないか。渡した値はページの中に埋め込まれて配られる
- 直し方は、**返す列を明示する**（ORM の `select`、DTO、シリアライザの `fields` の列挙）。除く列を並べる形は、列を足したときに漏れる

```bash
# 列を指定せずに取り、そのまま返していそうな箇所
grep -rnE "select\([[:space:]]*[\"']\*[\"'][[:space:]]*\)|findMany\([[:space:]]*\)|fields[[:space:]]*=[[:space:]]*[\"']__all__[\"']|exclude[[:space:]]*=" \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.py' . | grep -v node_modules | head -30
```

**外部 API の応答も、そのまま信じない**（API10）。決済代行・地図・取り込み元・LLM の応答を、型と範囲を確かめずに DB へ保存したり
画面へ出したりしていないか。直し方は、受け取った応答をスキーマ（zod など）で検証してから使うこと。保存した値は、表示するときに外部入力として扱う（1-4 節）。
応答に含まれる URL を追って取りに行くなら、5 節の検証を掛ける。

### 9-3. 段階を踏んで開示する情報（課金の前と後で見せるものが違う）

課金・承認・成約の前に一部だけを見せ、後で全部を見せる作りでは、**開示の前に見せる情報に、開示の後で見せるはずの情報が紛れていないか**を見る。

- 開示の前に見せる項目に**自由記述の欄**が入っていると、書き手が連絡先などを書けば、そのまま開示の前に相手へ届く
- 自由記述から消す処理を**正規表現の拒否リスト**で作っていると、表記の揺れや書き換えを通し、消しきれなかったことにも気づけない
- 開示の判定を、画面で隠すだけでなく、取得して応答に載せる列の段階で切り替えているか（9-2 節）
- 直し方は、開示の前に見せる情報を、**見せてよい項目だけで作り直す**こと（選択式の項目、運営が確かめた要約）

---

## 10. 言語・処理系に固有のもの

**型の緩い比較で照合していないか。** PHP の `==` と JavaScript の `==` は、型の違う値を変換して比べる。トークンや署名、
パスワードの照合を `==` で書くと、数値に見える文字列や配列・`null` を渡して通せる形がある。照合は `===`（PHP なら `hash_equals`）で、
秘密の値の照合は時間が一定の関数（`timingSafeEqual`・`hmac.compare_digest`）で行っているかを見る。

該当する構成のときだけ見る。

- **プロトタイプ汚染**（JavaScript）: 外部入力の深いマージ、`Object.assign` の再帰実装、クエリ文字列のパース。
  枠組み自身の不具合として RCE の前段になることもあるので、優先度を低く見積もらない。
  直し方は、`__proto__`・`constructor`・`prototype` のキーを弾く、`Object.create(null)` や `Map` に受ける、スキーマで検証した値だけを使うこと
- **Unicode の正規化**: 検証した後で `normalize('NFKC')` などをかけていないか。検証を通った文字列が、正規化で `/` や `<` に化ける。正規化してから検証する
- **安全でないデシリアライズ**: `pickle`（Python）、`Marshal`（Ruby）、`ObjectInputStream`（Java）、`unserialize`（PHP）に外部入力を渡していないか。
  YAML も同じで、PyYAML の `yaml.load` は `yaml.safe_load`（または `Loader=yaml.SafeLoader`）に、Ruby は `YAML.unsafe_load` を `YAML.safe_load` に替える
  （Psych 4 より前の版では `YAML.load` も安全でない側）。PHP の `unserialize` は JSON に替えるか、`allowed_classes` を `false` にする
- **テンプレートインジェクション**: テンプレート文字列自体を外部入力から組み立てていないか。テンプレートは固定し、値は変数として渡す
- **正規表現の破滅的後退**: 外部入力を受ける正規表現に、入れ子の量指定子（`(a+)+` の形）が無いか。入力の長さを先に制限し、式を書き換えるか、線形時間のエンジン（RE2 など）を使う
- **GraphQL**: イントロスペクションの公開、クエリの深さ・複雑度の制限、型を跨いだ到達。**バッチやエイリアスで 1 回の要求に
  確認コードを大量に詰め、要求単位のレート制限をすり抜ける**形も見る。直し方は、本番でイントロスペクションを切り、深さ・複雑度・エイリアスの数に上限を置くこと
- **HTTP の要求の食い違い（desync）**: 自前のリバースプロキシを前段に置き、上流を HTTP/1.1 で繋いでいる構成だけが対象。
  マネージドのホスティングならアプリ側の論点は小さい。**本番では絶対に試さない**（他の利用者の応答が混ざる）

---

## 11. リアルタイム通信（WebSocket・購読・チャネル）

**HTTP の認可をどれだけ丁寧に見ても、ここは別の入口として残る。** チャット、通知、共同編集、
管理画面の即時更新のような機能は、画面に出すデータを購読の経路でも配っている。
**AI で作ったアプリでは、公式のサンプル（多くは無認証のエコーサーバー）をそのまま写して、認証の無い購読が本番に出ている**ことが多い。
使っている仕組みと認可の手がかりは事前の洗い出しの 23 節に候補が出る。ログインした後の購読は、依頼者に確かめてもらう（`references/09-browser-verification.md` の 9 節）。

### 11-1. どの仕組みでも共通して見ること

| 問い | なぜ | 直し方 |
|---|---|---|
| 接続のときに認証しているか | 公式のサンプルの多くは無認証のエコーサーバー | 接続時か最初のメッセージでトークンを検証し、通らなければ切る |
| **購読（チャネル・ルーム・トピック）ごとに認可しているか** | 接続の認証だけでは「ログインした誰でも、どのルームにも入れる」 | 参加の要求ごとに、その利用者がそのルームに入れるかを DB で確かめる |
| ルーム名・トピック名を**クライアントから受け取ってそのまま使っていないか** | `user:<他人の ID>` を指定すれば他人宛ての配信を受け取れる | 個人宛てのルーム名は、サーバーが認証済みの利用者 ID から作る |
| メッセージごとに認可しているか（送信できる操作） | 接続した後の送信は HTTP のガードを通らない | 送信の処理ごとに、HTTP のハンドラと同じ認可を通す |
| **ログアウトや権限の剥奪で接続が切れるか** | 多くの仕組みは接続時にしか判定しない | ログアウトや権限の変更のときに、その利用者の接続を切る |
| メッセージの大きさと頻度に上限があるか | 1 本の接続で資源を使い切れる | 大きさの上限（`maxPayload` など）と、接続ごとの頻度の上限を置く |

### 11-2. Cookie で認証する WebSocket は Origin を検証する（CSWSH）

**WebSocket のハンドシェイクには CORS が掛からない。** ブラウザは別サイトのページからでも、
利用者の Cookie を付けて接続する。サーバーが `Origin` ヘッダを許可リストで照合していなければ、
攻撃者のページが利用者の権限で購読・送信できる（Cross-Site WebSocket Hijacking）。
Socket.IO の `cors` オプションは long-polling にしか適用されず、WebSocket の Origin を絞るには `allowRequest` を使う（公式が明記）。

```bash
# WebSocket のサーバーと、認証・Origin 検証の手がかり
grep -rnE 'new (WebSocketServer|Server)\(|WebSocket\.Server|upgradeWebSocket|experimental_upgradeWebSocket|defineWebSocketHandler|@app\.websocket' \
  --include='*.ts' --include='*.js' --include='*.py' . | grep -v node_modules
grep -rnE 'io\.use\(|allowRequest|verifyClient|handleUpgrade|headers\.origin|handshake\.(auth|headers)' --include='*.ts' --include='*.js' . | grep -v node_modules
# クライアントの指定したルームにそのまま入れていないか
grep -rnE 'socket\.join\(|disconnectSockets\(' --include='*.ts' --include='*.js' . | grep -v node_modules
```

**サーバーの定義があるのに Origin の検証が 1 件も無ければ、それだけで指摘の見当が付く。**
Socket.IO の `io.use()` は接続ごとに 1 回しか実行されないので、**接続後に権限が変わっても反映されない**。
ログアウトで `disconnectSockets()` などを呼んで切っているかを見る。

**直し方**: ハンドシェイクで `Origin` を許可リストと完全一致で照合する（`ws` の `verifyClient`・`handleUpgrade` の前の確かめ、Socket.IO の `allowRequest`）。
Cookie に頼らず、接続後の最初のメッセージでトークンを渡す形にすれば、CSWSH の前提が無くなる。

### 11-3. Supabase Realtime

**既定では開いている。** 管理画面の「Allow public access」は既定で有効で、有効な間は、`private: true` を付けない
チャネル（public チャネル）の Broadcast と Presence に**ポリシーの確認が一切行われず、公開鍵を持つ誰でも購読と送信ができる**。
同じトピック名でも private と public は別のチャネルとして扱われるので、private のメッセージを public 側から読めるわけではない。穴になるのは、
**`private: true` を付け忘れた購読が public チャネルとしてそのまま成立する**ことと、**private を必須にしたつもりでも、設定が有効なままなら public チャネルが使える**こと
（公式は「private を強制するには、この設定を無効にする」と書いている）。public チャネルにはどんな認可も関与しないので、使っていれば、偽のメッセージやイベントを配られる前提で見る。

| 経路 | 何が起きるか |
|---|---|
| Broadcast / Presence の public チャネル | 公開鍵（ブラウザに配られている）を持つ誰でも、**トピック名さえ分かれば受信も送信もできる**。トピック名が `room:<連番>` のように推測できれば、全部屋に入れる |
| private チャネルのポリシー | `realtime.messages` の RLS。**`to authenticated using (true)` のようにトピックを照合していない**と、ログインした誰でも全チャネルに入れる。`realtime.topic()` を照合しているかを読む |
| Postgres Changes（テーブルの変更の購読） | `supabase_realtime` の publication に入れたテーブルの変更が流れる。RLS が有効なら読める行だけが届く。**RLS が無効なテーブルを入れると、全行の変更が公開鍵の購読者に流れる** |
| Postgres Changes の DELETE | **公式に「DELETE には RLS が適用されない」とある。** RLS が有効なテーブルでは削除前の行は主キーだけになるが、RLS が無効で `replica identity full` のテーブルでは、**削除された行の全列が購読者全員に届く** |
| 権限の変化（Broadcast / Presence の private チャネル） | 購読の可否は**接続して購読した時点と、新しい JWT を送った時点でしか判定されない**。ロールを剥奪しても、JWT の期限が切れるまで受信が続く。**Postgres Changes はこれと違い、変更 1 件ごとに購読者ひとりずつ RLS で判定される** |

**直し方**: 「Allow public access」を無効にし、購読をすべて `private: true` にする。`realtime.messages` のポリシーで `realtime.topic()` と利用者（`auth.uid()`）の対応を照合する。
publication には RLS が有効なテーブルだけを入れる。トピック名は推測できない値か、サーバーが利用者 ID から作る形にする。

```bash
grep -rnE '\.channel\(|postgres_changes|private:[[:space:]]*(true|false)|setAuth\(' --include='*.ts' --include='*.tsx' --include='*.js' . | grep -v node_modules
grep -rniE 'supabase_realtime|replica identity full|realtime\.(messages|topic|send|broadcast_changes)' --include='*.sql' .
```

実機で見ることは `references/03-runtime-verification.md` の 1 節。

### 11-4. Firebase

- **Realtime Database の `.read` / `.write` は下の階層へ継承され、子で取り消せない。** 親に
  `".read": "auth != null"` があれば、子でどれだけ絞っても取り消せない
- **ルールは絞り込みではない。** Firestore の `onSnapshot` にも普通のクエリと同じルールが掛かるが、
  `allow read` を `get`（1 件）と `list`（一覧）に分けていないと、ID を知らなくても一覧で全件を購読できる。
  逆に `get` だけ絞って `list` を開けたままにしている形もある
- テストモードで作ったデータベースは、期限まで**誰でも読み書きできる**
- 直し方は、許可を親でなく必要な階層にだけ書き、`request.auth.uid` と文書の持ち主を照合し、`get` と `list` を分けて書くこと

ルールの危ない書き方は事前の洗い出しの 19 節に、購読の場所は 23 節に候補が出る。

### 11-5. マネージドの配信サービスと SSE

| 仕組み | 既定 | 見落とされる穴 |
|---|---|---|
| Pusher | 接頭辞の無いチャネルは認可不要。`private-` / `presence-` だけが認可のエンドポイントを通る | 認可のエンドポイントが**チャネル名を照合せずに署名する**（公式のサンプルがそうなっていて「本番でやるな」と注記されている）。個人宛ての配信を public チャネルで流している |
| Ably | 公式は「API キーをクライアントに置くな」としている | キーをブラウザに置いている。トークンの capability に `"*"`（全チャネル）を渡している |
| Liveblocks | `publicApiKey` は「利用者がどの部屋のデータにも触れる」もので、試作か公開ページ用 | 本番で `publicApiKey` を使っている。`allow("org:*", ...)` のような広いワイルドカード |
| PartyKit | 既定で認証無しに接続を受け付ける | `onBeforeConnect` で検証していない |
| Convex | 関数は既定で公開。リアクティブクエリも公開の `query` そのもの | `query` の中で `ctx.auth.getUserIdentity()` を見ていない |
| GraphQL Subscriptions | 購読は HTTP の context を通らない | WebSocket 側の `onConnect` / `context` で認証していない。`withFilter` が無く全購読者に配っている |
| SSE（`text/event-stream`） | 通常の Route Handler と同じ | ハンドラの中で認可していない。**トークンを URL に載せている**（`EventSource` はヘッダを付けられないので起きやすい） |

直し方は、どの仕組みでも 11-1 の表と同じ。認可のエンドポイントでチャネル名と利用者の対応を照合してから署名し、鍵はサーバーにだけ置いて、利用者ごとに範囲を絞ったトークンを渡す。

### 11-6. 検証

**ハンドシェイクと参加の応答だけを見る。** 購読を維持せず、送信（publish・broadcast・track）をしない。依頼者の許可を得た対象に限り、
無関係の `Origin` を付けた要求は監視に攻撃として記録されることがあるので、送る日時と送信元の IP を依頼者の運用側へ先に伝える。

```bash
# 正規の Origin と無関係の Origin で 1 本ずつ送り、応答の 1 行目を比べる（Cookie は付けない。Socket.IO なら /socket.io/?EIO=4&transport=websocket）
for o in "https://<domain>" "https://example.invalid"; do
  curl -si --http1.1 -m 5 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: $o" "https://<domain>/<WebSocket のパス>" | head -1
done
```

- **両方 101** → 接続の段階では拒否していない。**認証が無いことの根拠にはならない**（Supabase Realtime・Socket.IO・graphql-ws のように、接続後の最初のメッセージで認証する仕組みが多い）。
  認証の有無は、接続直後のメッセージ（`connection_init`・参加の要求・`auth` の値）を検証しているかを**コードで確定する**。
  認証が無いと確定し、購読で個人宛ての情報が流れていれば、`references/04-findings-register.md` の問い 1 で P0。Cookie で認証する構成なら、Origin を検証していないこと自体が 11-2 節の指摘になる
- **正規の Origin だけ 101** → Origin は検証している
- **両方 401 / 403** → 認証で拒否している。Origin の検証の有無はコードで確かめる

**認証が必要な確かめ方（他人のチャネル名で認可エンドポイントを呼ぶ、など）は評価者が行わない。**
依頼者が用意した試験用のアカウントで、依頼者自身に確かめてもらう（`references/03-runtime-verification.md` のモード B）。

---

## 指摘の書き方

この資料で見つけたものの優先度と書き方は `references/04-findings-register.md` に従う（攻撃経路を 3 行で書けるかで優先度を決め、
単独では成立せず組み合わせで成立するものは 1 件にまとめて部品を枝番にする）。
