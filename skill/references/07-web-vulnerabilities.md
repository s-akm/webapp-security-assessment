# アプリケーション層の脆弱性

`references/02-code-audit.md` の D 節（入力と出力）を深掘りするための資料。02 で当たりを付けてから、該当する節だけを読む。

**この資料は、自分たちのシステムの穴を見つけて塞ぐためのもの。** 検証は自分が権限を持つ環境に対してのみ行い、無害な印（`SECTEST<b>1234</b>` のような、太字になるかどうかしか起きない文字列）が想定外の場所に、想定外の形で出るかどうかで判定する。動く攻撃コードを書く必要はないし、書かない。

## 目次

1. [XSS](#1-xss)
2. [CSRF](#2-csrf)
3. [CORS](#3-cors)
4. [オープンリダイレクト](#4-オープンリダイレクト)
5. [SSRF](#5-ssrf)
6. [ファイルアップロード](#6-ファイルアップロード) / [XXE](#6-2-xml-を受け取る場合xxe)
7. [キャッシュ](#7-キャッシュ)
8. [競合と二重送信](#8-競合と二重送信)
9. [業務ロジックの欠陥](#9-業務ロジックの欠陥)
10. [言語・処理系に固有のもの](#10-言語処理系に固有のもの)
11. [リアルタイム通信](#11-リアルタイム通信websocket購読チャネル)

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

### 1-2. フレームワークの自動エスケープが効かない場所

自動エスケープは「HTML の本文」にしか効かない。次の場所は素通りする。**ここが実務での主戦場。**

| 場所 | 例 | 何が起きるか |
|---|---|---|
| **属性値のうち URL を取るもの** | `href={userInput}` / `src={userInput}` | `javascript:` 形式の URL を入れられる |
| **イベントハンドラ属性** | `onclick={...}` | 文字列として組み立てていれば注入できる |
| **`<script>` の中に埋める JSON** | JSON-LD、初期状態の受け渡し | `</script>` を含む文字列でタグを閉じられる |
| **`<style>` やスタイル属性** | `style={userInput}` | 情報の抜き出しに使われることがある |
| **コンポーネントの `props` を透過的に展開** | `{...userProps}` | 意図しない属性が付く |

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
# メール送信関数を列挙して、エスケープ関数を通しているかを見る
grep -rn 'sendMail\|sendEmail\|resend\.\|nodemailer\|SES\|sendgrid' --include='*.ts' . | head -20
```

### 1-6. CSP の実効性

CSP は XSS を防ぐものではなく、**成立したときの被害を狭める**もの。以下を実際の応答ヘッダで確認する（`references/03-runtime-verification.md`）。

| 指令 | 無いとどうなるか |
|---|---|
| `script-src` | 外部への任意のスクリプト読み込みを止められない。**`frame-ancestors` だけの CSP は XSS に対して無力**。無ければ `default-src` が使われるので、**実際に効く値で判定する** |
| `connect-src` | 盗んだデータの外部送信を止められない（同じく `default-src` に委ねられる） |
| `object-src` | 古いプラグイン経由の実行を防げない（同じく `default-src` に委ねられる）。推奨は `'none'` |
| `base-uri` | `<base>` を差し込まれると相対パスのスクリプトの読み込み先が変わる。**`default-src` に委ねられない**ので、別に要る。推奨は `'none'` か `'self'` |
| `frame-ancestors` | クリックジャッキングを防げない。**`default-src` に委ねられない** |

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

```bash
# 枠組みの防御と Fetch Metadata
grep -rnE 'Sec-Fetch-Site|sec-fetch-site|checkOrigin|allowedOrigins|csrf' --include='*.ts' --include='*.js' --include='*.mjs' . | head
# CSPT: URL の値を API のパスへ直に連結している箇所
grep -rnE 'fetch\(`[^`]*\$\{(params|searchParams|query|router\.query|slug|id)' --include='*.ts' --include='*.tsx' . | head
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

```bash
grep -rn 'Access-Control-Allow-Origin\|cors(' --include='*.ts' --include='*.js' .
curl -sI -H 'Origin: https://example.invalid' https://<domain>/api/<endpoint> | grep -i access-control
```

**何が問題か**:

- `Access-Control-Allow-Origin: *` と `Allow-Credentials: true` の併用はブラウザが拒否するが、**リクエストの `Origin` をそのまま反射して返す実装**は同じ危険を生む。認証付きのリクエストが任意のサイトから通る
- 許可リストの照合が前方一致・部分一致になっていないか。`example.com` の照合が `evil-example.com.attacker.invalid` を通してしまう形

---

## 4. オープンリダイレクト

**探し方**: リダイレクト先を外部入力から決めている箇所。ログイン後の戻り先、パスワード再設定、決済からの復帰。

**何が問題か**: フィッシングの踏み台になる。自社ドメインのリンクを踏ませて、攻撃者のサイトへ送れる。

**判定の細かい点**: ホスト名の検証をしていても、**サブドメインのワイルドカード許可**は穴になりうる。`*.example.com` を許すと、外部サービスに委譲しているサブドメインや、乗っ取られたサブドメインが踏み台になる。許可は完全一致のリストにするのが安全。

```bash
grep -rnE 'redirect|redirectTo|returnTo|next=|callbackUrl' --include='*.ts' . | head -20
```

---

## 5. SSRF

**探し方**: サーバー側から外部へ HTTP リクエストを出している箇所と、その URL の決まり方。

**何が問題か**: URL を外部入力から組み立てていると、内部ネットワークやクラウドのメタデータ endpoint を叩かせられる。

**判定**: 送信先が定数、または環境変数で固定されていれば低リスク。そう書く。可変なら、許可リストの有無とスキーム制限を見る。

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

該当する機能があれば見る。

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
- **XML を解析しているか。** 次節を見る

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
| 2026-02 | CVE-2026-27118 | `@sveltejs/adapter-vercel` の ISR 用の内部クエリ引数がすべてのルートで効き、認証済みの応答が他人へ配られる | 6.3.2 |
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

自動化された検査では出てこない。**そのサービスの業務を理解しないと見えない。** フェーズ 0 の取材が効いてくるところ。

見るべき問い。

- **金額や数量を、クライアントから受け取っていないか。** 単価をリクエストボディに含めている実装は、値を書き換えられる
- **状態遷移が飛ばせないか。** 「審査中」を経ずに「承認済み」へ行けないか。`status` を条件に入れずにレコードを取得している箇所は、状態を無視して操作できる
- **自分に関する設定のうち、本来は運営が決めるものを自分で変えられないか。** 上限値、料金プラン、権限のフラグ。更新を許可する項目を許可リストで絞っているか、それとも受け取ったオブジェクトをそのまま渡しているか
- **無料で得られるはずのないものを、経路を変えて得られないか。** 有料機能の結果を、別の公開エンドポイントが返していないか

```bash
# 更新系で、受け取ったオブジェクトをそのまま渡していないか（マスアサインメント）
grep -rnE '\.update\(\s*(body|req\.body|data|input)\s*\)|\.update\(\{\s*\.\.\.' --include='*.ts' .
```

**検索条件を利用者に組み立てさせていないか（ORM Leak）。** 絞り込みの項目名や演算子を外部入力から取り、
そのまま ORM の `where` に渡していると、関連を辿って**パスワードのハッシュやトークンを 1 文字ずつ漏らせる**
（`password: { startsWith: "a" }` を繰り返す形）。Prisma・Django・Sequelize に加え、Supabase が使う
PostgREST でも成立する（2025-12 の研究）。**PostgREST 系では、公開鍵で呼べる API が任意の列で絞り込めること
自体がこの経路になる**ので、03 の 1 節で機微な列が読める状態に無いかを併せて見る。

```bash
grep -rnE 'where:\s*(body|input|req\.body|params|query|filters?)\b|findMany\(\{\s*where:\s*[a-z]+\s*\}|\.filter\(\*\*(request|data)' --include='*.ts' --include='*.py' . | head
```

---

## 10. 言語・処理系に固有のもの

該当する構成のときだけ見る。

- **プロトタイプ汚染**（JavaScript）: 外部入力の深いマージ、`Object.assign` の再帰実装、クエリ文字列のパース。
  **2026 年には枠組み自身の不具合として RCE の前段になった例がある**（React Router・SvelteKit）ので、優先度を低く見積もらない
- **Unicode の正規化**: 検証した後で `normalize('NFKC')` などをかけていないか。検証を通った文字列が、正規化で `/` や `<` に化ける
- **安全でないデシリアライズ**: `pickle`（Python）、`Marshal`（Ruby）、`ObjectInputStream`（Java）に外部入力を渡していないか
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
Socket.IO の `cors` オプションは long-polling にしか効かず、WebSocket の Origin を絞るには
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

**Realtime 自体の勧告も続いている。** 2026-09-24 に公開された勧告（High、2.137.14 以下、2026-09-25 の確認時点で修正版の記載なし）は、
public チャネルでは「いかなる認可も関与しない」と明記したうえで、Broadcast を送れる者が他の購読者へ
テーブルの変更のイベントを偽造して配れる、としている。**public チャネルを使っていれば、その時点で影響を受ける前提で見る。**

```bash
grep -rnE '\.channel\(|postgres_changes|private:[[:space:]]*(true|false)|setAuth\(' --include='*.ts' --include='*.tsx' --include='*.js' . | grep -v node_modules
grep -rniE 'supabase_realtime|replica identity full|realtime\.(messages|topic|send|broadcast_changes)' --include='*.sql' .
```

実機で見ることは `references/03-runtime-verification.md` の 1 節。

### 11-4. Firebase

- **Realtime Database の `.read` / `.write` は下の階層へ継承され、子で取り消せない。** 親に
  `".read": "auth != null"` があれば、子でどれだけ絞っても効かない
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
依頼者の許可を得た対象に限る。

```bash
# 正規の Origin と、無関係の Origin の 2 本を送り、応答を比べる（どちらも Cookie は付けない）
for o in "https://<domain>" "https://example.invalid"; do
  printf '%-28s ' "$o"
  curl -si --http1.1 -m 5 -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Origin: $o" \
    "https://<domain>/<WebSocket のパス>" | head -1
done
```

- **両方 101** → Origin を検証しておらず、認証も無しに接続できる。購読で個人宛ての情報が流れていれば、`references/04-findings-register.md` の問い 1 で P0
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
