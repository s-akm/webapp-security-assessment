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
//   - /meta-csp は CSP を <meta> で置き、unsafe-inline を持つ（ヘッダだけを見ると「無い」と誤る）
//   - /default-only は script-src が無く、default-src に unsafe-inline がある
//   - /elem-csp は script-src-elem が厳しく、script-src（イベントハンドラ属性に効く）に unsafe-inline がある
//   - /ws は同意前に WebSocket を開き、第三者（127.0.0.1）へメッセージを送る
//   - /r は 302 で /ja/ へ転送し、転送先の HTML が src='./ja.js'（一重引用符・相対パス）で
//     LLM の鍵を載せた JS を読み込む
//   - /vendor は、第三者（127.0.0.1）のスクリプトの中身に計測タグの送信先の文字列を持つ
//     （中身まで見て数えると誤検出になる）。自前のインラインスクリプトには GTM の URL を書く
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
      // unsafe-inline があるため、XSS に対しては実質的に効かない
      // unsafe-inline があるため XSS には効かない。第三者への送信は通す（実サイトで
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

  // 塞がれている想定のパス
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

  // --- script-src-elem は厳しいが、script-src（属性に効く）に unsafe-inline がある ---
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
  "/vendor.js": () => ({
    status: 200,
    headers: { "content-type": "application/javascript" },
    // 文字列として持っているだけで、どこにも送らない
    body: `var KNOWN = ["https://r.lr-ingest.io/i", "https://us.i.posthog.com/e", ` +
          `"https://script.hotjar.com", "https://www.clarity.ms/tag", "https://edge.fullstory.com"];\n` +
          `if (typeof window.__tcfapi === "function") { /* CMP があれば問い合わせる */ }\n`,
  }),
};

// WebSocket の受け口（標準ライブラリだけで握手だけ行う）。受け取ったメッセージは読み捨てる。
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const sockets = new Set();

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const page = PAGES[url.pathname];
  if (!page) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  const { status, headers, body } = page();
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
