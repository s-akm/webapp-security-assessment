# アプリケーション層の脆弱性

`references/02-code-audit.md` の D 節（入力と出力）を深掘りするための資料。02 で当たりを付けてから、該当する節だけを読む。

**この資料は、自分たちのシステムの穴を見つけて塞ぐためのもの。** 検証は自分が権限を持つ環境に対してのみ行い、無害な印（`SECTEST<b>1234</b>` のような、太字になるかどうかしか起きない文字列）が想定外の場所に、想定外の形で出るかどうかで判定する。動く攻撃コードを書く必要はないし、書かない。

**この資料の grep の例は、書き方の手がかりを示すもの。** 多くは TypeScript / JavaScript の書き方で、`--include` もそれに合わせてある。
Python・Ruby・PHP・Go・Java の案件では、対象の言語の拡張子と書き方を足して実行する。**例の grep が 0 件でも「該当なし」にしない。**
枠組みを問わない事前の洗い出しが `scripts/audit_grep.sh` にある観点（2g 節のマスアサインメント、2j 節のリダイレクト、3 節・3b 節）は、そちらの出力を正とする。

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

02 の D-1 と `scripts/audit_grep.sh` の 3 節は、SQL を文字列で組み立てる行と、生 SQL の入口を拾う。
**値を束縛していても残る形と、ORM や BaaS に固有の形**をここで見る。

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
`scripts/audit_grep.sh` の 3 節は、同じ書き方を枠組みごとの表で拾い、値を流し込む行に ★ を付ける（固定の文字列だけを出す行には付けない）。
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

```bash
# DOM の入力源と、メッセージの受け口・送り口
grep -rnE 'location\.(hash|search)|URLSearchParams\(|window\.name|document\.referrer|addEventListener\([[:space:]]*.message.|onmessage[[:space:]]*=|postMessage\(' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.vue' --include='*.svelte' --include='*.html' . | grep -v node_modules | head -30
```

### 1-2. フレームワークの自動エスケープが働かない場所

自動エスケープは「HTML の本文」でしか働かない。次の場所は素通りする。**ここが実務での主戦場。**

| 場所 | 例 | 何が起きるか |
|---|---|---|
| **属性値のうち URL を取るもの** | `href={userInput}` / `src={userInput}` | `javascript:` 形式の URL を入れられる（止まるかは枠組みと版で変わる。表の下の注） |
| **イベントハンドラ属性** | `onclick={...}` | 文字列として組み立てていれば注入できる |
| **`<script>` の中に埋める JSON** | JSON-LD、初期状態の受け渡し | `</script>` を含む文字列でタグを閉じられる |
| **`<style>` やスタイル属性** | `style={userInput}` | 情報の抜き出しに使われることがある |
| **コンポーネントの `props` を透過的に展開** | `{...userProps}` | 意図しない属性が付く |

**URL を取る属性は、枠組みとその版で止まるかが変わる。** React 19 以降（Next.js の App Router が同梱する版を含む）は、`href`・`src`・`action`・`formAction` に入った
`javascript:` の URL を、画面での描画でもサーバーでの描画でも、実行されない値に置き換える（大文字小文字を混ぜた形や、前に空白・制御文字を置き、途中に改行・タブを挟んだ形も含む）。
Angular も止める。React 18 以前（開発時の警告だけ）、Vue、Svelte、HTML を文字列で組み立てる箇所では止まらない。止まる版でも、同じ値を
`window.location`・`window.open` に渡したり、メールの本文や Markdown の描画・`dangerouslySetInnerHTML` に流したりすると止まらない。
**判定は「どの版の何で描画し、その値がほかのどこへ流れるか」をコードと依存の版で確かめてから決める。** 止まる版の属性にしか出ない値でも、
保存の時点で `http`・`https` に絞る是正は勧める（描画の仕組みや版を替えたときに穴が開く）。ほかの出口が無ければ、優先度は低くしてよい。

**JSON-LD は特に見落とされやすい。** 構造化データを `JSON.stringify()` して `<script type="application/ld+json">` に入れる書き方はよくあるが、値に記事タイトルやユーザー入力が混ざると、`</script>` を含む文字列でスクリプトブロックを抜けられる。埋め込み前に `<` を `\u003c` へ置換しているか（`JSON.stringify(data).replace(/</g, '\\u003c')` の形）を確認する。JSON としては同じ値のまま、`</script>` が文字列の中に現れなくなる。

```bash
# JSON-LD の埋め込みと、その元データ
grep -rn 'application/ld+json' -A3 --include='*.tsx' --include='*.jsx' .
```

### 1-3. リッチテキストと Markdown

CMS やユーザー投稿の HTML をそのまま描画していないか。

- **サニタイズを通しているか。** 通しているなら、ライブラリ名と設定を確認する。許可タグに `script` `iframe` `object` `embed` が入っていないか、`on*` 属性と `style` を落としているか
- Markdown レンダラの「生 HTML 許可」設定が有効になっていないか
- **サニタイズの位置**。保存時だけで、表示時に通していない構成は、保存経路が複数あると破れる。表示時に通すほうが堅い

### 1-4. 格納型 XSS の経路

**攻撃者が入力し、別の権限の人が見る画面**を洗う。ここが一番被害が大きい。

- 問い合わせフォームの自由記述 → 管理画面の案件詳細
- 取引先が設定する会社名・担当者名 → 運営の一覧画面
- 外部連携で取り込むデータ → 社内向けダッシュボード

管理画面は「社内だから」と対策が薄くなりがちで、しかも**運営セッションを盗まれると全顧客情報に届く**。優先度は公開画面より高いことが多い。

### 1-5. メール本文

HTML メールを文字列連結で組み立てている箇所は、Web と同じ問題が起きる。**通知関数が複数あるときは全部を突き合わせる。** 1 つだけエスケープを通していない、という形が典型。

```bash
# メール送信関数を列挙して、エスケープ関数を通しているかを見る（TS / JS に加え、Python・Ruby・PHP・Go の書き方）
grep -rnE 'sendMail|sendEmail|resend\.|nodemailer|SES|sendgrid|send_mail|EmailMessage|smtplib|ActionMailer|deliver_(now|later)|Mail::(send|to)|PHPMailer|net/smtp|gomail' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' . | grep -v node_modules | head -30
```

### 1-6. CSP の実効性

CSP は XSS を防ぐものではなく、**成立したときの被害を狭める**もの。以下を実際の応答ヘッダで確認する（`references/03-runtime-verification.md`）。

| 指令 | 無いとどうなるか |
|---|---|
| `script-src` | 外部への任意のスクリプト読み込みを止められない。**`frame-ancestors` だけの CSP は XSS に対して無力**。無ければ `default-src` が使われるので、**実際に適用される値で判定する** |
| `connect-src` | 盗んだデータの外部送信を止められない（同じく `default-src` に委ねられる） |
| `object-src` | 古いプラグイン経由の実行を防げない（同じく `default-src` に委ねられる）。推奨は `'none'` |
| `base-uri` | `<base>` を差し込まれると相対パスのスクリプトの読み込み先が変わる。**`default-src` に委ねられない**ので、別に要る。推奨は `'none'` か `'self'` |
| `frame-ancestors` | クリックジャッキングを防げない。**`default-src` に委ねられない** |

**`<meta http-equiv="Content-Security-Policy">` で配る CSP は、`frame-ancestors`・`report-uri`・`sandbox` を無視される**（CSP の仕様）。
`scripts/browser_probe.mjs` は `<meta>` の CSP も拾うので、値があっても**応答ヘッダで配っているか**を `curl -sI` で別に確かめる。
`<meta>` にしか無ければ、`frame-ancestors` は無いものとして判定する。

**`'unsafe-inline'` は、あるだけで判定しない。** 同じ `script-src` に nonce・hash・`'strict-dynamic'` の
いずれかがあれば、ブラウザは `'unsafe-inline'` を**無視する**（CSP Level 3）。古いブラウザ向けに
並べて書くのは推奨されている形で、指摘にはならない。**問題になるのは「nonce も hash も
`'strict-dynamic'` も無いのに `'unsafe-inline'` がある」とき。** `'unsafe-eval'` はこの打ち消しの対象外なので、
あれば効果が落ちる。

**許可リスト型（`script-src cdn.example.com`）の CSP は迂回されやすい。** 許可したドメインに
JSONP や古いライブラリがあれば、それを踏み台にされる。推奨は nonce または hash と `'strict-dynamic'`、
`object-src 'none'`、`base-uri 'none'` の組み合わせ（いわゆる strict CSP）。Next.js で nonce を使うと
そのページは動的レンダリングになる点を是正案に書き添える。

**Trusted Types が主要ブラウザで揃った**（2026-02 に Baseline）。`require-trusted-types-for 'script'` が
あれば、`innerHTML` などへの文字列の代入そのものが止まる。是正案として `innerHTML` の代わりに
Sanitizer API の `setHTML()` を示せる（`setHTMLUnsafe()` は安全側ではない）。**`setHTML()` はまだ全ブラウザで
揃っていない**ので、是正案に書く前に MDN で対応状況を確かめ、未対応のブラウザでの代替（DOMPurify など）を添える。

ただし**既存サイトにいきなり厳格な CSP を入れると壊れる**ので、是正案は `Content-Security-Policy-Report-Only` での観測から始める段取りにする。

### 1-7. 検証

```bash
# 反射の確認: 無害な印（SECTEST<b>1234</b>）がエスケープされずに応答へ出ていないか
curl -s "https://<domain>/search?q=SECTEST%3Cb%3E1234%3C%2Fb%3E" \
  | grep -oE 'SECTEST(<b>|&lt;b&gt;|&#60;b&#62;|\\u003cb\\u003e)1234' | sort | uniq -c
```

**送る前に、その入力を保存する機能が無いかをコードで確かめる。** 検索履歴、「人気の検索」、検索語を分析基盤へ送る計測があると、
GET でも印が本番のデータに残り、運営の画面や集計に出る。保存する機能があれば本番では送らず、検証環境で確かめる（下の格納型と同じ扱い）。

`&lt;b&gt;` などに変換されていれば正しい。`<b>` のまま出ていれば、その経路はエスケープされていない。
**タグの形をした印にするのは、画面で観察できるようにするため。** エスケープされていなければ `1234` が太字になり、
依頼者にも「太字になったか」で答えてもらえる（`references/09-browser-verification.md` の 5 節）。

**格納型は、評価者が保存して確かめない。** 保存は状態を変える操作で、SKILL.md の「参照系だけを実行する」に反する。
本番のデータに印が残り、運営の画面や通知メールにも出る。**コードで判定する。** 入力を保存する経路（1-4）と、
それを表示するシンク（1-1）、その間のエスケープとサニタイズ（1-3）を追えば、多くは保存せずに決まる。

コードだけでは決まらず、保存して確かめる必要があるなら、**依頼者に検証環境で確かめてもらう**
（`references/03-runtime-verification.md` のモード B）。試験用のアカウントで印を保存し、表示する側の画面で
「太字になったか」を見てもらう。本番では行わない。検証環境が無ければ、未確認事項に残してコードの根拠で指摘を書く。

---

## 2. CSRF

**探し方**: 状態を変えるエンドポイントの認証方式を確認する。

- **Cookie でセッションを持っている** → CSRF の対象。トークン検証、`Sec-Fetch-Site` / `Origin` の照合、`SameSite` 属性のどれで防いでいるか
- **`Authorization` ヘッダでトークンを送る** → ブラウザが自動送信しないので、古典的な CSRF は成立しにくい。
  ただし**画面の JS が URL の値をそのまま API のパスに連結している**と、正規の呼び出しを別のエンドポイントへ
  向け直せる（クライアントサイドのパストラバーサル。CSPT2CSRF）。トークンごと送られるので防げない

**枠組みが既定で守るかどうかで、探すものが逆になる。**

| 枠組み | 既定 | 探すもの |
|---|---|---|
| Rails・Django・Laravel・Spring Security | Cookie のセッションに対して、既定でトークンを検証する | **外している箇所。** `skip_forgery_protection`・`protect_from_forgery` の `except`、`@csrf_exempt`、Laravel の `VerifyCsrfToken` の `$except` や `validateCsrfTokens(except: …)`、Spring の `csrf` の `disable()` と `ignoringRequestMatchers`。AI は 403 を消すためにこれを足すことがある |
| Express・Koa・Fastify・Hono・Flask・FastAPI・Go（net/http・Gin・Echo） | 既定の対策が無い | Cookie でセッションを持つなら、**状態を変える全ルートを数え**、それぞれに対策（トークン、`Sec-Fetch-Site` / `Origin` の照合、明示の `SameSite`）が掛かっているかを見る。ミドルウェアを入れていても、掛かる範囲から外れたルートは守られない |
| Next.js の Server Actions・SvelteKit | 既定で `Origin` を照合する | 照合を緩める設定（下の `allowedOrigins`、SvelteKit の `checkOrigin: false`） |

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

**判定**: `SameSite=Lax` が付いていれば、クロスサイトからの POST は送られない。多くの構成でこれが実質的な防御になっている。**その場合は「対策済み」ではなく「`SameSite` に依存している」と書く。** 将来 `SameSite=None` が必要になったとき（別ドメインへの埋め込み、決済からの戻りなど）に前提が崩れるため。

**`SameSite` を「付いている」と読む前に、明示されているかを確かめる。** 属性の無い Cookie を Lax として
扱うのは Chromium 系だけで、**Firefox と Safari では付いていないのと同じ**になる。Chrome の既定 Lax にも、
発行から 2 分以内は POST でも送る例外がある。**明示の `SameSite=Lax` / `Strict` が無ければ、防御は無いものとして判定する。**

**`SameSite` はサブドメインからの攻撃を止めない。** 同じ登録ドメインの別サブドメイン（利用者がコンテンツを
置けるもの、乗っ取られたもの）からの要求は same-site 扱いで送られる。OWASP も `SameSite` を多層防御の 1 つと
位置づけ、CSRF 対策の代わりにはしていない。推奨の順は、**枠組みの組み込み対策 → トークン →
Fetch Metadata（`Sec-Fetch-Site` で cross-site の状態変更を拒否し、`Origin` と `Host` の照合を予備にする）**。

**Server Actions は枠組みが `Origin` と `Host` を照合している。** `next.config` の
`serverActions.allowedOrigins` に `'null'` やワイルドカードが入っていないかを見る
（16.0.1〜16.1.6 には `Origin: null` がこの照合を素通りする不具合があった。CVE-2026-27978）。

`GET` で状態が変わるエンドポイントがあれば、`SameSite` でも防げない。02 の A-4 と併せて見る。

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

---

## 4. オープンリダイレクト

**探し方**: リダイレクト先を外部入力から決めている箇所。ログイン後の戻り先、パスワード再設定、決済からの復帰。

**何が問題か**: フィッシングの踏み台になる。自社ドメインのリンクを踏ませて、攻撃者のサイトへ送れる。

**判定の細かい点**: ホスト名の検証をしていても、**サブドメインのワイルドカード許可**は穴になりうる。`*.example.com` を許すと、外部サービスに委譲しているサブドメインや、乗っ取られたサブドメインが踏み台になる。許可は完全一致のリストにするのが安全。

**`scripts/audit_grep.sh` の 2j 節が、転送先らしい名前の値をリクエストから読み、その値で転送している行を枠組みごとの表で並べる。**
変数に受けてから離れた行で転送する書き方も追う。★ は、読んだ行から転送の行までに確かめが見当たらないもの。
**`/` で始まるかだけを確かめる形も ★ にする。** `//attacker.example` や `/\attacker.example` は `/` で始まるが、
ブラウザは別のホストとして扱う。自サイトの中に限るなら、`//` と `/\` で始まるものも弾くか、URL として解釈してオリジンを比べる。

```bash
# 2j 節の補い。TS 以外の案件では拡張子と書き方を足す（Django の redirect、Rails の redirect_to、Laravel の redirect()->to など）
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
- **パス全体のワイルドカード（`/**`）で、自サイトの中の開いた転送（`scripts/audit_grep.sh` の 2j 節の ★）を経由できないか**

確かめるのは設定の画面なので、`references/03-runtime-verification.md` のモード A か、モード B で依頼者に値を写してもらう。
02 の B-5 の `redirect_uri` の照合と併せて見る。

---

## 5. SSRF

**探し方**: サーバー側から外部へ HTTP リクエストを出している箇所と、その URL の決まり方。

**何が問題か**: URL を外部入力から組み立てていると、内部ネットワークやクラウドのメタデータ endpoint を叩かせられる。

**判定**: 送信先が定数、または環境変数で固定されていれば低リスク。そう書く。可変なら、許可リストの有無とスキーム制限を見る。

**外部のホストを広く許す機能**（OGP の取得、URL を指定した画像の取り込み、Webhook の送信先を利用者が登録する機能）は、
許可リストで絞れない。この場合は、送信先の検証が次の穴を塞いでいるかを見る。

| 穴 | 何が起きるか | 直し方 |
|---|---|---|
| **リダイレクトの追従** | 検証を通った外部の URL が、内部のアドレスへ転送する。`fetch` など多くの HTTP クライアントは既定で転送を追う | 転送を追わない設定（`fetch` の `redirect: 'manual'` など）にし、追うなら転送先ごとに同じ検証をやり直す |
| **名前の再解決** | 検証のときに解決した IP と、接続のときに解決した IP が違う（DNS の応答を短時間で切り替える） | 解決した IP を検証し、**その IP へ接続する**。検証と接続で別々に解決させない |
| **IP の表記の揺れ** | 10 進の整数、8 進、省略形、IPv6 に埋め込んだ IPv4、`0.0.0.0` は、文字列の比較をすり抜ける | 文字列で比べず、標準の関数で IP として解釈してから、ループバック・プライベート・リンクローカル（`169.254.0.0/16`・`fe80::/10`）・IPv6 のユニークローカル（`fc00::/7`）の範囲で弾く |
| **クラウドのメタデータ** | 内部へ届いたとき、インスタンスの資格情報が取れる | AWS なら、メタデータの取得にトークンを要求する設定（IMDSv2 の必須化。Terraform では `metadata_options` の `http_tokens = "required"`）になっているかを `references/13-infrastructure.md` の 3 節の定義で見る |

**見落としやすい経路**: リクエストの `Host` ヘッダや、フレームワークが提供する「現在のオリジン」から URL を組み立てている箇所。リバースプロキシの設定次第で、`Host` は攻撃者が指定できる。PDF 生成のフォント取得、画像の取り込み、OGP の取得でよく出る。

**枠組みの設定が SSRF の入口になることがある。** Next.js では、`rewrites()` / `redirects()` の宛先を要求の値から
組み立てている、ミドルウェアで要求ヘッダをそのまま `NextResponse.next({ headers })` に渡している、
画像最適化の `remotePatterns` にワイルドカードがある、の 3 つが 2025〜2026 年の SSRF の条件になった
（CVE-2025-57822、CVE-2026-64645 ほか）。自前でホストしている場合は WebSocket の upgrade 経由のもの
（CVE-2026-44578）もある。

```bash
grep -nE 'rewrites|redirects|destination:|remotePatterns|domains:' next.config.* 2>/dev/null
grep -rn 'NextResponse.next({ *headers' middleware.* proxy.* src/ 2>/dev/null
```

---

## 6. ファイルアップロード

該当する機能があれば見る。受け取り口と種類の判定の行は、`scripts/audit_grep.sh` の 3b 節が枠組みを問わず並べる。

- **許す種類を列挙しているか（許可リスト）。** 禁止する種類を列挙する判定（拒否リスト）は、一覧に無い種類がすべて通る。
  `.html`・`.svg`・`.js`、サーバーで実行される拡張子、二重拡張子（`a.php.png`）、大文字（`.PHP`）が抜けやすい。
  3b 節の ★ はこの形。許可リストに変えるまで指摘にする
- 拡張子だけで判定していないか。実際の内容（マジックナンバー）を見ているか
- 保存先が公開ディレクトリで、かつ実行可能な形式を受け付けていないか
- **SVG を画像として受け付けていないか。** SVG は中にスクリプトを書ける。画像として表示するなら、サニタイズするか、別オリジンから配信するか、`Content-Disposition: attachment` にする
- ファイル名を外部入力から作っていないか（パストラバーサル）
- 配信時に `Content-Type` を正しく付けているか。`X-Content-Type-Options: nosniff` があるか
- サイズと件数の上限があるか

**受け取った後の処理でも枯渇する。** 上限を通ったファイルでも、展開や変換で膨らむ。

- **圧縮ファイルを展開しているか。** 展開後のサイズと件数に上限があるか。
  小さな書庫が展開で数 GB になる形（zip 爆弾）がある
- **画像や文書を変換しているか。** 変換ライブラリは外部プロセスを呼ぶことがあり、
  そこに脆弱性が出る。版を確かめる（`references/10-dependencies.md`）
- **XML を解析しているか。** 6-2 節を見る

### 配信する側

**受け取り口だけでなく、ファイルを返す口も見る。** 利用者の値でファイルのパスを決めて返していると、
`..` を含む値で基準のディレクトリの外（設定ファイル、`.env`、他人のアップロード）を読める。

- `res.sendFile(req.params.name)`・`send_file(os.path.join(dir, name))`・`path.join(base, 利用者の値)` のように、利用者の値をパスに連結していないか。
  `path.join` や `os.path.join` は、`..` で基準の外へ出る値を拒まない（`os.path.join` は、後ろの引数が `/` で始まると前を捨てる）
- 直し方は、**ID からパスを引く対応表にする**か、枠組みの「基準のディレクトリの外を拒む」関数（Flask の `send_from_directory` など）を使う。
  自前で確かめるなら、正規化した絶対パスが基準のディレクトリの下にあるかを比べる
- **署名付き URL を、利用者の送ったパスから作っていないか**（`createSignedUrl`・`getSignedUrl`）。署名は「誰でも読める」許可になるので、
  パスの持ち主が要求した本人かを、署名の前に確かめる
- 返すときに `Content-Disposition: attachment` と正しい `Content-Type` を付けているか（上の SVG・HTML の扱い）

```bash
# ファイルを返す口と、署名付き URL を作る口
grep -rnE 'sendFile\(|send_file\(|send_from_directory\(|FileResponse\(|createReadStream\(|readFile(Sync)?\(|createSignedUrl\(|getSignedUrl\(|os\.Open\(|http\.ServeFile\(|File\.(Open|ReadAll)' \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.rb' --include='*.php' --include='*.go' --include='*.cs' --include='*.java' . | grep -v node_modules | head -30
```

読んだ行ごとに、パスに入る値が利用者から来るかを追う。`scripts/audit_grep.sh` の 3b 節は受け取り口を並べるもので、配信の側はこの grep の結果を 1 行ずつ読む。

### 6-2. XML を受け取る場合（XXE）

**外部実体の解決を止めているか。** 止めていなければ、XML を送るだけでサーバー上のファイルを
読み出せる。攻撃者が読めるのは応答に出る内容だけとは限らず、**エラーメッセージや
外部への接続（SSRF）としても成立する。**

```bash
# XML を解析している箇所
grep -rnE 'DocumentBuilder|SAXParser|XMLReader|etree|lxml|libxml|SimpleXML|XmlDocument|xml2js' \
  --include='*.java' --include='*.py' --include='*.php' --include='*.cs' --include='*.ts' .
```

**該当するのは、XML を受け取る構成だけ。** SVG のアップロード、SOAP、
RSS の取り込み、Office 文書（中身は XML の書庫）、SAML の応答が典型になる。
**JSON しか受け取らないなら、この節は不要。**

- 解析器の設定で外部実体と DTD を無効にしているか。**既定で有効な処理系がある**
- SAML を使っている場合、**署名の検証と実体の解決の順序**まで見る

---

## 7. キャッシュ

**見落とされやすいわりに、個人情報の漏えいに直結する。**

**探し方**: キャッシュ制御の指定と、認証が要るページの組み合わせ。

```bash
# 認証が要るページのキャッシュヘッダ
curl -sI https://<domain>/<認証が要るパス> | grep -iE 'cache-control|vary|age|x-cache|cf-cache-status'
```

**何が問題か**:

- **利用者ごとに違う内容を返すページが、CDN やプロキシでキャッシュされる**と、他人の画面が配られる。`Cache-Control: private` か `no-store` が付いているかを確認する
- フレームワークの既定が「できる限りキャッシュする」側に倒れている構成では、動的なページに明示の指定が要る。
  **既定は版で違う。** Next.js は 14 以前が「既定でキャッシュする」側で、15 から `GET` の Route Handler と
  クライアント側のルーターキャッシュが既定でキャッシュしなくなった。**版を確かめてから判定する**
- `Vary` の指定漏れ。認証状態やロールで内容が変わるのに `Vary` が無いと、混ざる
- **エラーページやリダイレクトがキャッシュされる**ケースもある

静的化の仕組み（インクリメンタルな再生成など）を使っている場合、**個人情報を含むページがその対象に入っていないか**を確認する。

### 3 つを区別する

同じ「キャッシュ」でも、経路が違う。**混ぜると是正の指示を間違える。**

| | 何が起きるか | 見るところ |
|---|---|---|
| **漏えい（既定の指定漏れ）** | 認証済みの応答が共有キャッシュに入り、他人へ配られる | `Cache-Control` と `Vary` |
| **キャッシュ・デセプション** | 攻撃者が**利用者に踏ませた URL** の応答がキャッシュされ、後から攻撃者が取り出す | **URL の解釈がキャッシュ層とアプリで食い違う場所** |
| **キャッシュ・ポイズニング** | 攻撃者の応答がキャッシュに入り、他の利用者へ配られる | キャッシュ鍵に入らないヘッダを見て応答を変えていないか |

**デセプションは、静的ファイル扱いされる見た目の URL を作れるかで決まる。**

**送る前に、依頼者の運用側へ知らせる。** 下のような URL の揺れを含む要求は、WAF や監視に攻撃として記録され、
運用側が調査を始めたり、評価者の IP が遮断されたりする。送る日時と送信元の IP を先に伝えておく（11-6 節の検証も同じ）。

```bash
# 認証が要るパスの後ろに、静的に見える要素を足して応答を見る
for p in "/mypage" "/mypage/x.css" "/mypage;x.js" "/mypage%2Fx.css" "/mypage/..%2fx.js"; do
  printf '%-24s ' "$p"
  curl -s -o /dev/null -w '%{http_code}  ' "https://<domain>$p"
  curl -sI "https://<domain>$p" | grep -iE '^(cache-control|x-vercel-cache|cf-cache-status)' | tr -d '\r' | paste -sd' ' -
done
```

**中身が返るうえに、共有キャッシュ可の指定が付いていれば成立する。** 上のループに、
区切り文字と正規化の食い違いを突く形（`%23`、`%3F`、`%00`）と、RSC の応答を取る形
（末尾に `.rsc`、クエリに `?_rsc=x`）も足す。

**枠組みとホスティング側の不具合で起きることがある。アプリのコードを読むだけでは見つからない。**
版で当たりを付ける。

| 公表 | 識別子 | 条件 | 修正版 |
|---|---|---|---|
| 2026-02 | CVE-2026-27118 | `@sveltejs/adapter-vercel` の ISR 用の内部クエリ引数がすべてのルートで受け付けられ、認証済みの応答が他人へ配られる | 6.3.2 |
| 2025-08 | CVE-2025-57752 | Next.js の画像最適化が、Cookie で内容の変わる API ルートの画像をキャッシュして他人へ配る | 14.2.31 / 15.4.5 |

```bash
grep -A1 -E '"node_modules/(@sveltejs/adapter-vercel|next|nuxt|astro)"' package-lock.json 2>/dev/null | grep '"version"' | head
# scripts/audit_grep.sh の 1b 節が版を出し、上の 2 件は機械的に判定する
```

**同種の不具合は毎月のように出ている。** 枠組みの公式アドバイザリ一覧（github.com の各リポジトリの
`security/advisories`）で、キャッシュに関わるものが対象の版に当たらないかを評価のたびに見る。

**エッジで認可を判定してキャッシュする構成**は、この観点で特に丁寧に見る。
判定結果ごとキャッシュされると、権限の違う利用者へ同じ応答が配られる。

---

## 8. 競合と二重送信

**探し方**: 「回数」や「残数」が意味を持つ処理。ポイント、在庫、上限つきの申込、課金の発生。

**何が問題か**: アプリ側で件数を数えてから書き込む実装は、同時に叩かれると両方が通る。

**判定**: DB の一意制約、トランザクション、行ロック、DB トリガーのいずれかで担保されているか。アプリのチェックだけなら指摘になる。
**「同時に叩かれることは滅多にない」は成り立たない。** 1 つの TCP パケットに 20〜30 本の要求を詰めて
1 ミリ秒未満の差で同時に届ける手法（single-packet attack）が一般的な道具に入っている。
数えてから書く実装は、狙われればほぼ確実に破られる前提で判定する。

**このスキルでは試さない。** 同時に書き込む試験は状態を変える。確かめる必要があるなら、
依頼者に検証環境での確認を依頼する（`references/03-runtime-verification.md` のモード B）。

**担保されていれば、それは評価できる実装として記録する。**

---

## 9. 業務ロジックの欠陥

自動化された検査では出てこない。**そのサービスの業務を理解しないと見えない。** フェーズ 0 の取材の結果を使うところ。

見るべき問い。

- **金額や数量を、クライアントから受け取っていないか。** 単価をリクエストボディに含めている実装は、値を書き換えられる
- **状態遷移が飛ばせないか。** 「審査中」を経ずに「承認済み」へ行けないか。`status` を条件に入れずにレコードを取得している箇所は、状態を無視して操作できる
- **自分に関する設定のうち、本来は運営が決めるものを自分で変えられないか。** 上限値、料金プラン、権限のフラグ。更新を許可する項目を許可リストで絞っているか、それとも受け取ったオブジェクトをそのまま渡しているか
- **無料で得られるはずのないものを、経路を変えて得られないか。** 有料機能の結果を、別の公開エンドポイントが返していないか

決済と特典まわりで、AI で作ったアプリに出やすい形。

| 形 | 直し方 |
|---|---|
| 決済代行の支払い画面を作るときに、品目や単価（Stripe Checkout の `line_items` の `price_data.unit_amount` など）をクライアントの値から作る | サーバーで商品の ID から価格を引く。決済代行に登録した価格の ID を使う |
| 数量に 0 や負の数、上限を超える数を受け付ける | サーバーで範囲を確かめる。合計の計算の前に弾く |
| クーポンや招待コードを、同じ利用者が何度も使える。使った記録をアプリの中だけで数えている | 使用の記録を DB に持ち、利用者とコードの組に一意制約を付ける（8 節の競合も見る） |
| 無料の試用を、メールアドレスの別名（`+` の付いた別名、ドメインごとの表記の揺れ）で何度も始められる | 試用の権利を、正規化したメールアドレスや支払い手段など、作り直しにくいものに結び付ける |

### 9-1. 取得する件数・大きさを利用者が決めていないか

一覧の件数（`limit`・`per_page`・`pageSize` など）をリクエストの値で決め、**上限を確かめていなければ、1 回の要求で全件を取り出せる。**
下限（0 以下を弾く）しか見ていない実装が多い。**公開の一覧でも問題になる。** 負荷で止められるうえ、1 件ずつなら目立つ取得を
1 回で済ませられる（件数の制限を業務の決まりとして置いているなら、その決まりを破れる）。「公開の情報だから問題なし」にしない。

- 上限を付けているか（`Query(…, le=100)`・`@Max(100)`・`max_page_size`）、上限で切り詰めているか（`Math.min(limit, 100)`）
- 件数のほかに、取り出す大きさ（画像の幅と高さ、書き出しの期間、入れ子の深さ）を利用者が決めていないか

`scripts/audit_grep.sh` の 2h 節が、件数を決める値をリクエストから読む行を枠組みごとの表で並べ、
同じファイルに上限の確かめが見当たらない行に ★ を付ける。

```bash
# 更新系で、受け取ったオブジェクトをそのまま渡していないか（マスアサインメント）。
# 枠組みを問わない事前の洗い出しは scripts/audit_grep.sh の 2g 節。これは TS の書き方を補う例
grep -rnE '\.update\(\s*(body|req\.body|data|input)\s*\)|\.update\(\{\s*\.\.\.' --include='*.ts' --include='*.js' .
```

**検索条件を利用者に組み立てさせていないか（ORM Leak）。** 絞り込みの項目名や演算子を外部入力から取り、
そのまま ORM の `where` に渡していると、関連を辿って**パスワードのハッシュやトークンを 1 文字ずつ漏らせる**
（`password: { startsWith: "a" }` を繰り返す形）。Prisma・Django・Sequelize に加え、Supabase が使う
PostgREST でも成立する（2025-12 の研究）。**PostgREST 系では、公開鍵で呼べる API が任意の列で絞り込めること
自体がこの経路になる**ので、03 の 1 節で機微な列が読める状態に無いかを併せて見る。

```bash
grep -rnE 'where:\s*(body|input|req\.body|params|query|filters?)\b|findMany\(\{\s*where:\s*[a-z]+\s*\}|\.filter\(\*\*(request|data)' --include='*.ts' --include='*.py' . | head
```

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
画面へ出したりしていないか。保存した値は、表示するときに外部入力として扱う（1-4 節）。応答に含まれる URL を追って取りに行くなら、5 節の検証を掛ける。

---

## 10. 言語・処理系に固有のもの

該当する構成のときだけ見る。

- **プロトタイプ汚染**（JavaScript）: 外部入力の深いマージ、`Object.assign` の再帰実装、クエリ文字列のパース。
  **2026 年には枠組み自身の不具合として RCE の前段になった例がある**（React Router・SvelteKit）ので、優先度を低く見積もらない
- **Unicode の正規化**: 検証した後で `normalize('NFKC')` などをかけていないか。検証を通った文字列が、正規化で `/` や `<` に化ける
- **安全でないデシリアライズ**: `pickle`（Python）、`Marshal`（Ruby）、`ObjectInputStream`（Java）、`unserialize`（PHP）に外部入力を渡していないか。
  YAML も同じで、PyYAML の `yaml.load` は `yaml.safe_load`（または `Loader=yaml.SafeLoader`）に、Ruby は `YAML.unsafe_load` を `YAML.safe_load` に替える
  （Psych 4 より前の版では `YAML.load` も安全でない側）。PHP の `unserialize` は JSON に替えるか、`allowed_classes` を `false` にする
- **テンプレートインジェクション**: テンプレート文字列自体を外部入力から組み立てていないか
- **正規表現の破滅的後退**: 外部入力を受ける正規表現に、入れ子の量指定子（`(a+)+` の形）が無いか
- **GraphQL**: イントロスペクションの公開、クエリの深さ・複雑度の制限、型を跨いだ到達。**バッチやエイリアスで 1 回の要求に
  確認コードを大量に詰め、要求単位のレート制限をすり抜ける**形も見る
- **HTTP の要求の食い違い（desync）**: 自前のリバースプロキシを前段に置き、上流を HTTP/1.1 で繋いでいる構成だけが対象。
  マネージドのホスティングならアプリ側の論点は小さい。**本番では絶対に試さない**（他の利用者の応答が混ざる）

---

## 11. リアルタイム通信（WebSocket・購読・チャネル）

**HTTP の認可をどれだけ丁寧に見ても、ここは別の入口として残る。** チャット、通知、共同編集、
管理画面の即時更新のような機能は、画面に出すデータを購読の経路でも配っている。
**AI で作ったアプリでは、公式のサンプルをそのまま写して、認証の無い購読が本番に出ている**ことが多い。

`scripts/audit_grep.sh` の 23 節が、使っている仕組みと認可の手がかりを出す。
本番のページがどこへ接続しているかは `scripts/browser_probe.mjs` の 1b 節が出す（ログイン前に開く接続だけ。
接続の URL のクエリは伏せる）。ログインした後の購読は、依頼者に確かめてもらう（`references/09-browser-verification.md` の 9 節）。

### 11-1. どの仕組みでも共通して見ること

| 問い | なぜ |
|---|---|
| 接続のときに認証しているか | 公式のサンプルの多くは無認証のエコーサーバー |
| **購読（チャネル・ルーム・トピック）ごとに認可しているか** | 接続の認証だけでは「ログインした誰でも、どのルームにも入れる」 |
| ルーム名・トピック名を**クライアントから受け取ってそのまま使っていないか** | `user:<他人の ID>` を指定すれば他人宛ての配信を受け取れる |
| メッセージごとに認可しているか（送信できる操作） | 接続した後の送信は HTTP のガードを通らない |
| **ログアウトや権限の剥奪で接続が切れるか** | 多くの仕組みは接続時にしか判定しない |
| メッセージの大きさと頻度に上限があるか | 1 本の接続で資源を使い切れる |

### 11-2. Cookie で認証する WebSocket は Origin を検証する（CSWSH）

**WebSocket のハンドシェイクには CORS が掛からない。** ブラウザは別サイトのページからでも、
利用者の Cookie を付けて接続する。サーバーが `Origin` ヘッダを許可リストで照合していなければ、
攻撃者のページが利用者の権限で購読・送信できる（Cross-Site WebSocket Hijacking）。
Socket.IO の `cors` オプションは long-polling にしか適用されず、WebSocket の Origin を絞るには
`allowRequest` を使う（公式が明記）。2025 年にも開発サーバー（Vite、webpack-dev-server）や
IDE の拡張機能で、Origin を検証していなかったことによる CVE が出ている。

```bash
# WebSocket のサーバーと、認証・Origin 検証の手がかり
grep -rnE 'new (WebSocketServer|Server)\(|WebSocket\.Server|upgradeWebSocket|experimental_upgradeWebSocket|defineWebSocketHandler|@app\.websocket' \
  --include='*.ts' --include='*.js' --include='*.py' . | grep -v node_modules
grep -rnE 'io\.use\(|allowRequest|verifyClient|handleUpgrade|headers\.origin|handshake\.(auth|headers)' --include='*.ts' --include='*.js' . | grep -v node_modules
# クライアントの指定したルームにそのまま入れていないか
grep -rnE 'socket\.join\(|disconnectSockets\(' --include='*.ts' --include='*.js' . | grep -v node_modules
```

**サーバーの定義があるのに Origin の検証が 1 件も無ければ、それだけで当たりが付く。**
Socket.IO の `io.use()` は接続ごとに 1 回しか走らないので、**接続後に権限が変わっても反映されない**。
ログアウトで `disconnectSockets()` などを呼んで切っているかを見る。

**Vercel の Functions が WebSocket に対応した**（2026-06 に公開ベータ）。公式のサンプルは認証も Origin の検証も
無いエコーサーバーで、**写せばそのまま無認証の入口になる**。

### 11-3. Supabase Realtime

**既定では開いている。** 管理画面の「Allow public access」は既定で有効で、有効な間は、`private: true` を付けない
チャネル（public チャネル）の Broadcast と Presence に**ポリシーの確認が一切走らず、公開鍵を持つ誰でも購読と送信ができる**
（公式の設定の説明）。同じトピック名でも private と public は別のチャネルとして扱われ、メッセージは互いに届かないので、
**private のチャネルのメッセージを public 側から読めるわけではない。** 穴になるのは次の 2 つ。

- **`private: true` を付け忘れた購読が、public チャネルとしてそのまま成立する。** そこで流している個人宛ての通知や
  チャットは、トピック名を知っている誰にでも見え、誰でも偽のメッセージを送れる
- **private を必須にしたつもりでも、設定が有効なままなら public チャネルが使える。** 公式は「private を強制するには、
  この設定を無効にする」と書いている

| 経路 | 何が起きるか |
|---|---|
| Broadcast / Presence の public チャネル | 公開鍵（ブラウザに配られている）を持つ誰でも、**トピック名さえ分かれば受信も送信もできる**。トピック名が `room:<連番>` のように推測できれば、全部屋に入れる |
| private チャネルのポリシー | `realtime.messages` の RLS。**`to authenticated using (true)` のようにトピックを照合していない**と、ログインした誰でも全チャネルに入れる。`realtime.topic()` を照合しているかを読む |
| Postgres Changes（テーブルの変更の購読） | `supabase_realtime` の publication に入れたテーブルの変更が流れる。RLS が有効なら読める行だけが届く。**RLS が無効なテーブルを入れると、全行の変更が公開鍵の購読者に流れる** |
| Postgres Changes の DELETE | **公式に「DELETE には RLS が適用されない」とある。** RLS が有効なテーブルでは削除前の行は主キーだけになるが、RLS が無効で `replica identity full` のテーブルでは、**削除された行の全列が購読者全員に届く** |
| 権限の変化（Broadcast / Presence の private チャネル） | 購読の可否は**接続して購読した時点と、新しい JWT を送った時点でしか判定されない**（公式に「接続の間キャッシュされる」とある）。ロールを剥奪しても、JWT の期限が切れるまで受信が続く。**Postgres Changes はこれと違い、変更 1 件ごとに購読者ひとりずつ RLS で判定される** |

**Realtime 自体の勧告も続いている。** 2026-09-24 に公開された勧告（GHSA-9vjf-j9f7-j42c。High、2.137.14 以下、2026-09-25 の確認時点で修正版の記載なし）は、
public チャネルでは「いかなる認可も関与しない」と明記したうえで、Broadcast を送れる者が他の購読者へ
テーブルの変更のイベントを偽造して配れる、としている。**public チャネルを使っていれば、その時点で影響を受ける前提で見る。**

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

`scripts/audit_grep.sh` の 19 節がルールの危ない書き方を、23 節が購読の場所を出す。

### 11-5. マネージドの配信サービスと SSE

| 仕組み | 既定 | 見落とされる穴 |
|---|---|---|
| Pusher | 接頭辞の無いチャネルは認可不要。`private-` / `presence-` だけが認可のエンドポイントを通る | 認可のエンドポイントが**チャネル名を照合せずに署名する**（公式のサンプルがそうなっていて「本番でやるな」と注記されている）。個人宛ての配信を public チャネルで流している |
| Ably | 公式は「API キーをクライアントに置くな」としている | キーをブラウザに置いている。トークンの capability に `"*"`（全チャネル）を渡している |
| Liveblocks | `publicApiKey` は「利用者がどの部屋のデータにも触れる」もので、試作か公開ページ用 | 本番で `publicApiKey` を使っている。`allow("org:*", ...)` のような広いワイルドカード |
| PartyKit | 既定で認証無しに接続を受け付ける | `onBeforeConnect` で検証していない |
| Convex | 関数は既定で公開。リアクティブクエリも公開の `query` そのもの | `query` の中で `ctx.auth.getUserIdentity()` を見ていない（`scripts/audit_grep.sh` の 19 節） |
| GraphQL Subscriptions | 購読は HTTP の context を通らない | WebSocket 側の `onConnect` / `context` で認証していない。`withFilter` が無く全購読者に配っている |
| SSE（`text/event-stream`） | 通常の Route Handler と同じ | ハンドラの中で認可していない。**トークンを URL に載せている**（`EventSource` はヘッダを付けられないので起きやすい） |

### 11-6. 検証

**ハンドシェイクと参加の応答だけを見る。** 購読を維持しない。送信（publish・broadcast・track）をしない。
依頼者の許可を得た対象に限る。無関係の `Origin` を付けた要求は監視に攻撃として記録されることがあるので、
送る日時と送信元の IP を依頼者の運用側へ先に伝える。

```bash
# 正規の Origin と、無関係の Origin の 2 本を送り、応答を比べる（どちらも Cookie は付けない）
for o in "https://<domain>" "https://example.invalid"; do
  printf '%-28s ' "$o"
  curl -si --http1.1 -m 5 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: $o" \
    "https://<domain>/<WebSocket のパス>" | head -1
done
```

- **両方 101** → 接続の段階では Origin でも認証でも拒否していない。**認証が無いことの根拠にはならない。**
  Supabase Realtime・Socket.IO・graphql-ws のように、接続した後の最初のメッセージで認証する仕組みが多い。
  認証の有無は、接続直後のメッセージ（`connection_init`・参加の要求・`auth` の値）を検証しているかを**コードで確定する**。
  コードで認証が無いと確定し、購読で個人宛ての情報が流れていれば、`references/04-findings-register.md` の問い 1 で P0。
  Cookie で認証する構成なら、Origin を検証していないこと自体が 11-2 節の指摘になる
- **正規の Origin だけ 101** → Origin は検証している
- **両方 401 / 403** → 認証で拒否している。Origin の検証の有無はこれだけでは分からないので、コードで確かめる

Socket.IO なら `/socket.io/?EIO=4&transport=websocket` に送る。**認証が要る確かめ方
（他人のチャネル名で Pusher の認可エンドポイントを呼ぶ、など）は評価者が行わない。**
依頼者が用意した試験用のアカウントで、依頼者自身に確かめてもらう（`references/03-runtime-verification.md` のモード B）。

---

## 指摘の書き方

この節で見つけたものは、**攻撃経路を 3 行で書けるかどうか**で優先度が決まる（`references/04-findings-register.md`）。

書ける例:

> 問い合わせフォームの「ご相談内容」に HTML を入れると、そのまま管理画面の案件詳細に描画される。運営が案件を開いた時点でスクリプトが動き、セッション Cookie に `HttpOnly` が無いため、その場でセッションを外部へ送れる。運営セッションでは全顧客の氏名・電話番号・住所に到達できる。

書けない例は、優先度を落とすか、多層防御の欠落として P2 以下に置く。

**単独では成立しないが、組み合わせると成立するもの**は、その旨を明記して 1 件にまとめる。上の例は「格納型 XSS」「Cookie の `HttpOnly` 欠如」「CSP が不十分」の 3 つが揃って初めて成立する。3 件バラバラに書くより、1 件として書いて対策の順序を示すほうが伝わる。優先度は揃った全体で引き、部品は枝番にする（`references/04-findings-register.md` の「組み合わせで成立するもの」）。

**台帳の列との対応**: 上の例の 1 文目（何が起きるか）が指摘事項、2 文目以降（運営が開いた時点で何ができるか）が想定される影響になる。確認の方法は、コードで追ったなら「コード」、依頼者に印を入れてもらったなら「依頼者の確認」。
