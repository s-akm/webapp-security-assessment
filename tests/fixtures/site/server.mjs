#!/usr/bin/env node
// server.mjs — browser_probe.mjs を検査するための「発火台」
//
//   使い方: node server.mjs [ポート]        （既定 8787）
//
// わざと穴のあるページを配信する。外部へは一切出ない。
// 第三者への送信は 127.0.0.1 を使って模す。ページは localhost で開くため、
// ブラウザから見て 127.0.0.1 は別ホストになり、第三者として数えられる。
//
// 仕込んである穴:
//   - 同意バナーを出しながら、その前に第三者（127.0.0.1）へ送信する
//   - Cookie に HttpOnly も Secure も付けない
//   - localStorage に authToken を置く
//   - CSP に unsafe-inline がある
//   - セキュリティヘッダが無い
//   - /mypage が Cache-Control 無しで個人情報らしきものを出す
//   - /.env の中身が外から取れる
//   - /meta-csp は CSP を <meta> で置き、unsafe-inline を持つ（ヘッダだけを見ると「無い」と誤る）
//   - /default-only は script-src が無く、default-src に unsafe-inline がある
//   - /elem-csp は script-src-elem が厳しく、script-src（イベントハンドラ属性に適用される）に unsafe-inline がある
//   - /ws は同意前に WebSocket を開き、第三者（127.0.0.1）へメッセージを送る
//   - /r は 302 で /ja/ へ転送し、転送先の HTML が src='./ja.js'（一重引用符・相対パス）で
//     LLM の鍵を載せた JS を読み込む
//   - /vendor は、第三者（127.0.0.1）のスクリプトの中身に計測タグの送信先の文字列を持つ
//     （中身まで見て数えると誤検出になる）。自前のインラインスクリプトには GTM の URL を書く
//   - /.git/config・/actuator/env の中身が外から取れる。/server-status は 403 を返す
//   - /waf は、curl の既定の名乗りとヘッドレスのブラウザを 403 で止める（WAF・ボット対策を模す）
//   - /links は、読み込まないリンク（<a>・canonical）と、読み込む参照（stylesheet・img）と、
//     認証部に鍵を載せた URL（Sentry の DSN の形）を並べる。どれも外へは取りに行かない
//   - /ctrl-header は、ヘッダの値に端末の表示を書き換える制御文字を入れる（生のソケットで返す）
//   - /keys は、鍵の形の見本を 1 行に 1 つ並べた JS を読み込む（recon.sh と scan_secrets.sh が同じ種類を拾うかを見る）
//   - /longpoll は、読み込みの後も一定の間隔で送り続け、通信が途切れない
//
// 正しく作られている側:
//   - /clean       同意まで第三者へ送らず、ヘッダを揃える
//   - /strict-csp  nonce と 'strict-dynamic' に unsafe-inline を並べる（ブラウザは無視するので指摘しない）

import { createServer } from "node:http";
import { createHash } from "node:crypto";

const port = Number(process.argv[2] || 8787);

// 第三者を模した配信元。ページの表示ホスト（localhost）とは別ホストになる。
const THIRD = (p) => `http://127.0.0.1:${port}${p}`;

const PAGES = {
  "/": () => ({
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      // unsafe-inline があるため、XSS に対しては実質的に防御にならない
      // unsafe-inline があるため XSS の防御にならない。第三者への送信は通す（実サイトで
      // タグを使うなら許可されているのが普通で、その状態を模す）。
      "content-security-policy":
        "default-src 'self' http://127.0.0.1:" + port +
        "; script-src 'self' 'unsafe-inline' http://127.0.0.1:" + port,
      // HttpOnly も Secure も付けない
      "set-cookie": "session_id=dummyvalue123; Path=/; SameSite=Lax",
      // セキュリティヘッダは意図的に付けない
      "x-powered-by": "TestFixture/1.0",
    },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>発火台</title>
<script src="${THIRD("/tag.js")}"></script>
<script src="${THIRD("/analytics.js")}"></script>
<script src="/app.js"></script>
<!-- 自サイトの絶対 URL。ポートが付いていても第三者として数えられないことを見る -->
<link rel="canonical" href="http://localhost:${port}/">
</head><body>
<h1>ダミーサイト</h1>
<div id="consent">このサイトは Cookie を使用します <button id="ok">同意する</button></div>
<script>
  // 同意を取る前に保存している。ボタンは押されていない。
  localStorage.setItem('authToken', 'dummy-token-value-should-not-be-printed');
  localStorage.setItem('theme', 'dark');
  // キー名に端末の表示を書き換える並び（ESC [2J）を入れる。出力にそのまま出てはいけない
  localStorage.setItem('\u001b[2Jfixture_ctl_key', 'x');
  sessionStorage.setItem('csrf_token', 'dummy-csrf-should-not-be-printed');
  document.getElementById('ok').addEventListener('click', function () {
    document.getElementById('consent').style.display = 'none';
  });
</script>
</body></html>`,
  }),

  "/tag.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    // 第三者スクリプトが、さらに別のリクエストを飛ばす
    body: `fetch('${THIRD("/collect?e=pageview")}').catch(function(){});`,
  }),

  "/analytics.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    // 1 本は届く先へ、もう 1 本は誰も待っていないポートへ。
    // browser_probe が「送信を試みた」と「実際に届いた」を分けて数えられるかを見る。
    body: `new Image().src = '${THIRD("/pixel.gif")}';\n` +
          `fetch('http://127.0.0.1:${port + 1}/beacon').catch(function(){});`,
  }),

  // 自サイト配信の JS。クライアントに出てはいけない鍵が載っている想定。
  // ここに置く値はすべて架空で、実在のサービスに対して有効なものは 1 つも無い。
  "/app.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    body: `const SUPABASE_URL = "https://dummyproject.supabase.co";\n` +
          `const ANON_KEY = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJyb2xlIjogImFub24iLCAiaWF0IjogMTYwMDAwMDAwMH0.ZHVtbXlzaWduYXR1cmVub3RyZWFs";\n` +
          `const PUB = "sb_publishable_dummyvaluefortest0000";\n`,
  }),

  "/collect": () => ({ status: 204, headers: {}, body: "" }),
  "/pixel.gif": () => ({
    status: 200,
    headers: { "content-type": "image/gif" },
    // 1x1 の透明 GIF。空ボディだと画像の読み込みが失敗し、
    // 「成立しなかった」件数に紛れて理由が分からなくなる。
    body: Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"),
  }),

  // 個人情報らしきものを出しながら、キャッシュ指定が無い
  "/mypage": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>マイページ</title></head>
<body><h1>マイページ</h1><p>ダミー太郎 さま</p></body></html>`,
  }),

  // 外から設定ファイルの中身が取れる（値は架空。出力に値が出てはいけない）
  "/.env": () => ({
    status: 200,
    headers: { "content-type": "text/plain" },
    body: "# dummy\nDUMMY_SETTING=dummy-env-value-should-not-be-printed\n",
  }),

  // 塞がれている想定のパス
  // 外部の同意管理サービスを使う構成。ページは site.localhost、同意管理は cmp.localhost、計測タグは 127.0.0.1 から配信する
  // （Chromium は *.localhost を常に自分の端末として扱う）。同意が無い間は計測タグを読み込まない
  "/cmp-external": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>CMP</title>
<script src="http://cmp.localhost:${port}/cmp.js"></script></head><body>
<h1>外部の同意管理</h1>
<script>
  if (window.__cmp && window.__cmp.granted()) {
    const s = document.createElement("script"); s.src = "${THIRD("/tag.js")}"; document.head.appendChild(s);
  }
</script>
</body></html>`,
  }),
  "/cmp.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    body: "window.__cmp = { granted: function () { return false; } };",
  }),
  // 画面遷移を JavaScript で行う構成。最初の読み込みでは第三者へ送らず、画面の切り替え（pushState）のたびに送る
  "/spa": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>SPA</title></head><body>
<div id="root">一覧</div>
<script>
  const push = history.pushState;
  history.pushState = function () {
    push.apply(history, arguments);
    new Image().src = "${THIRD("/pixel.gif")}?ev=route";
  };
</script>
</body></html>`,
  }),
  "/admin": () => ({ status: 403, headers: { "content-type": "text/plain" }, body: "forbidden" }),

  // --- ここから下は「正しく作られている」側 ---
  // 穴を見つけられるかだけでなく、正しい実装を誤検出しないかも見る必要がある。
  // 誤検出するツールは、指摘の山に埋もれて本当に危ないものを隠す。
  "/clean": () => ({
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      // unsafe-inline も unsafe-eval も無い
      "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
      // HttpOnly が付いている。Secure は http では付けられないため SameSite で代替する
      "set-cookie": "session_id=dummyvalue456; Path=/; HttpOnly; SameSite=Strict",
      "strict-transport-security": "max-age=63072000; includeSubDomains",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "geolocation=(), microphone=(), camera=()",
      "cache-control": "no-store",
      // x-powered-by は出さない
    },
    // 同意を取るまで第三者へは送らない。保存領域にも何も置かない。
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>正しい側</title>
</head><body>
<h1>同意を取ってから読み込むページ</h1>
<div id="consent">このサイトは Cookie を使用します <button id="ok">同意する</button></div>
<script src="/consent.js"></script>
</body></html>`,
  }),

  "/consent.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    // 同意ボタンが押されるまで、第三者への読み込みを行わない
    body: `document.getElementById('ok').addEventListener('click', function () {
  var t = document.createElement('script');
  t.src = 'http://127.0.0.1:${port}/tag.js';
  document.head.appendChild(t);
  document.getElementById('consent').style.display = 'none';
});`,
  }),

  // --- CSP を <meta> で置いたページ（ヘッダには無い）---
  "/meta-csp": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'; object-src 'none'">
<title>meta の CSP</title></head><body><h1>meta で CSP を置いたページ</h1></body></html>`,
  }),

  // --- script-src が無く、default-src に unsafe-inline がある ---
  "/default-only": () => ({
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self' 'unsafe-inline'",
    },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>default-src だけ</title></head>
<body><h1>default-src だけのページ</h1></body></html>`,
  }),

  // --- script-src-elem は厳しいが、script-src（属性に適用される）に unsafe-inline がある ---
  "/elem-csp": () => ({
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "script-src-elem 'self'; script-src 'self' 'unsafe-inline'",
    },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>script-src-elem</title></head>
<body><h1>script-src-elem のあるページ</h1></body></html>`,
  }),

  // --- 正しい側: nonce と strict-dynamic に unsafe-inline を並べる（古いブラウザ向けの推奨形）---
  "/strict-csp": () => ({
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy":
        "script-src 'nonce-dummyNonce123' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'",
    },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>strict CSP</title></head>
<body><h1>strict CSP のページ</h1><script nonce="dummyNonce123">document.title = "strict CSP";</script></body></html>`,
  }),

  // --- 同意前に WebSocket を開く。第三者（127.0.0.1）と自サイト（localhost）の 2 本 ---
  // クエリに載せたトークンは出力に出てはいけない（Supabase Realtime は apikey をクエリに載せる）
  "/ws": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>WebSocket</title></head>
<body><h1>リアルタイム通信のページ</h1>
<div id="consent">このサイトは Cookie を使用します <button id="ok">同意する</button></div>
<script>
  var third = new WebSocket('ws://127.0.0.1:${port}/socket?token=dummy-ws-token-should-not-be-printed');
  third.onopen = function () { third.send('hello-before-consent'); };
  var own = new WebSocket('ws://localhost:${port}/socket');
</script>
</body></html>`,
  }),

  // --- 302 で転送する。転送元にはヘッダを付けず、転送先にだけ付ける ---
  "/r": () => ({ status: 302, headers: { location: "/ja/" }, body: "" }),
  "/ja/": () => ({
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
    },
    // 一重引用符・相対パスで読み込む（以前は二重引用符とルート相対しか拾わなかった）
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>転送先</title>
<script src='./ja.js'></script></head><body><h1>転送先のページ</h1></body></html>`,
  }),
  // LLM の鍵がブラウザに出ている想定。値はすべて架空で、リポジトリの中では鍵の形にならないよう
  // 分割して書く（秘密情報の検査や、ホスティング側の鍵の検出に引っかからないように）
  "/ja/ja.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    body: `const OPENAI_KEY = "${"sk-" + "proj-" + "DUMMYdummyDUMMYdummy0000notreal"}";\n` +
          `const ANTHROPIC_KEY = "${"sk-" + "ant-" + "api03-" + "DUMMYdummyDUMMYdummy0000notreal"}";\n`,
  }),

  // --- 第三者のスクリプトの中身に計測タグの文字列がある ---
  // セッションリプレイの SDK は他社の送信先の一覧を中に持つことがある。中身まで数えると誤検出になる。
  // 自前のインラインスクリプトには GTM の URL を文字列として書く（読み込みはしない）。
  "/vendor": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>第三者の SDK</title>
<script src='${THIRD("/vendor.js")}'></script>
<script>window.__gtmUrl = "https://www.googletagmanager.com/gtm.js?id=GTM-DUMMY";</script>
</head><body><h1>第三者の SDK を読み込むページ</h1></body></html>`,
  }),
  // 別ホスト（127.0.0.1 → localhost）への転送。転送先は自サイトとして数える（第三者と言わない）
  "/to-clean": () => ({ status: 302, headers: { location: `http://localhost:${port}/clean` }, body: "" }),
  // CSP で止められる読み込み。コンソールの違反の文言に URL のクエリ（鍵らしき値）が載る
  "/csp-query": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": "script-src 'self'" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>CSP</title>
<script src="${THIRD("/tag.js?key=FIXTURECONSOLEKEY0123")}"></script></head><body></body></html>`,
  }),
  // 計測と同じホストの別物（共有リンク・画像）と、本物の計測（Meta ピクセルの /tr）。前者でタグと言わない
  "/share": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>共有</title>
<script>var shareUrl = "https://www.facebook.com/sharer/sharer.php?u=" + encodeURIComponent(location.href);</script>
</head><body><img src="https://s.yimg.jp/images/top/logo.png" alt=""></body></html>`,
  }),
  "/pixel-noscript": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>ピクセル</title></head>
<body><noscript><img height="1" width="1" src="https://www.facebook.com/tr?id=0&ev=PageView&noscript=1"></noscript></body></html>`,
  }),
  // 外から設定の中身が取れる（値は架空）。/server-status は塞がれている
  "/.git/config": () => ({
    status: 200, headers: { "content-type": "text/plain" },
    body: "[core]\n\trepositoryformatversion = 0\n",
  }),
  "/actuator/env": () => ({
    status: 200, headers: { "content-type": "application/json" },
    body: '{"activeProfiles":[],"propertySources":[]}',
  }),
  "/server-status": () => ({ status: 403, headers: { "content-type": "text/plain" }, body: "forbidden" }),
  // curl の既定の名乗り（curl/…）とヘッドレスのブラウザ（HeadlessChrome）を止める。WAF・ボット対策を模す
  "/waf": (req) => {
    const ua = String(req.headers["user-agent"] || "");
    if (/^curl\//.test(ua) || /HeadlessChrome/.test(ua)) return { status: 403, headers: { "content-type": "text/plain" }, body: "blocked" };
    return { status: 200, headers: { "content-type": "text/html; charset=utf-8" }, body: "<!doctype html><html><body>ok</body></html>" };
  },
  // 読み込まないリンクと、読み込む参照。recon.sh は JS 以外を取りに行かないので、ここに書いた外のホストへは出ない。
  // Sentry の DSN は、URL の認証部に鍵を載せる形（https://<鍵>@<ホスト>/<番号>）。値は架空
  "/links": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>リンク</title>
<link rel="canonical" href="https://canonical.example.invalid/links">
<link rel="stylesheet" href="https://cdn.example.invalid/style.css">
<script>Sentry.init({ dsn: "https://FIXTUREDSNKEY0123@o0.ingest.sentry.io/0" });</script>
</head><body>
<a href="https://sns.example.invalid/fixture">SNS</a>
<img src="https://FIXTUREDSNKEY0123@px.example.invalid/p.gif" alt="">
</body></html>`,
  }),
  // 通信が途切れないページ（ロングポーリングや定期的な送信を模す）。networkidle に達しない
  "/longpoll": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", "set-cookie": "lp_session=dummyvalue789; Path=/; HttpOnly" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>ロングポーリング</title></head><body>
<script>setInterval(function () { fetch("/collect").catch(function () {}); }, 200);</script>
</body></html>`,
  }),
  // 鍵の見本を並べた JS を読み込むページ
  "/keys": () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
    body: `<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>鍵の見本</title>
<script src="/keys/keys.js"></script></head><body></body></html>`,
  }),
  "/keys/keys.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    body: KEY_SAMPLES.map(([a, b], i) => `const K${String(i).padStart(2, "0")} = "${a}${b}";`).join("\n") + "\n",
  }),
  "/vendor.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    // 文字列として持っているだけで、どこにも送らない
    body: `var KNOWN = ["https://r.lr-ingest.io/i", "https://us.i.posthog.com/e", ` +
          `"https://script.hotjar.com", "https://www.clarity.ms/tag", "https://edge.fullstory.com"];\n` +
          `if (typeof window.__tcfapi === "function") { /* CMP があれば問い合わせる */ }\n`,
  }),
};

// 鍵の形の見本。recon.sh（KEYS・LLM_KEYS）と scan_secrets.sh の鍵の検査の両方が、同じ種類を拾うかを見る。
// 値はすべて架空。リポジトリの中では鍵の形にならないよう、接頭辞と本体を分けて書く（秘密情報の検査や、
// ホスティング側の鍵の検出に引っかからないように）。先頭 10 文字は見本ごとに違うものにする（伏字の形で見分けるため）
const H32 = "0123456789abcdef0123456789abcdef";
const B = "PARITYDUMMY0123456789abcdefXYZ";
export const KEY_SAMPLES = [
  ["sk-" + "proj-", B], ["sk-", "PARITYDUMMY012345678" + "T3Blbk" + "FJ" + "PARITYDUMMY012345678"],
  ["sk-" + "ant-" + "api03-", B], ["sk-" + "or-" + "v1-", B], ["gs" + "k_", B], ["xa" + "i-", B],
  ["h" + "f_", B + "abcd"], ["r" + "8_", B + "abcd"], ["pp" + "lx-", B + "abcd"],
  ["sb_" + "secret_", B], ["sb_" + "publishable_", B], ["AI" + "za", B],
  ["pk_" + "live_", B], ["sk_" + "live_", B], ["rk_" + "live_", B], ["sk_" + "test_", B], ["wh" + "sec_", B],
  ["AK" + "IA", "PARITYDUMMY01234"], ["AS" + "IA", "PARITYDUMMY56789"],
  ["Account" + "Key=", B + B.slice(0, 14) + "=="],
  ["gh" + "p_", B], ["gh" + "o_", B], ["github" + "_pat_", B],
  ["np" + "m_", B + "abcd"], ["xo" + "xb-", B], ["xo" + "xe-", B], ["xa" + "pp-1-", B],
  ["A" + "C", H32], ["S" + "K", H32.split("").reverse().join("")],
  ["S" + "G.", "PARITYDUMMY0123456789.PARITYDUMMY0123456789"], ["ke" + "y-", H32.slice(16) + H32.slice(0, 16)],
  ["ey" + "J", "hbGciOiJIUzI1NiJ9.eyJyb2xlIjoicGFyaXR5In0.PARITYDUMMYsig"],
];

// WebSocket の受け口（標準ライブラリだけで握手だけ行う）。受け取ったメッセージは読み捨てる。
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const sockets = new Set();

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  // ヘッダに制御文字を入れた応答。Node の http は不正な文字のヘッダを書かせないので、生のソケットに書く
  if (url.pathname === "/ctrl-header") {
    req.socket.end("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: fixture\x1b[2Jserver\r\n" +
                   "X-Fixture-Note: \x1b]0;fixture\x07note\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    return;
  }
  const page = PAGES[url.pathname];
  if (!page) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  const { status, headers, body } = page(req);
  res.writeHead(status, headers);
  res.end(body);
});

server.on("upgrade", (req, socket) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const key = req.headers["sec-websocket-key"];
  if (url.pathname !== "/socket" || !key) { socket.destroy(); return; }
  const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
               `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
  sockets.add(socket);
  socket.on("data", () => {});
  socket.on("error", () => {});
  socket.on("close", () => sockets.delete(socket));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`発火台を起動した: http://localhost:${port}`);
  console.log(`第三者の配信元として http://127.0.0.1:${port} を使う`);
});

// 親から止められたときに後片付けする
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    for (const s of sockets) s.destroy();
    server.close(() => process.exit(0));
    server.closeAllConnections();
  });
}
