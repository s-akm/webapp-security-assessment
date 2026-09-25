#!/usr/bin/env node
// browser_probe.mjs — ブラウザで実際に読み込んで、curl では見えないものを取る（読み取り専用）
//
//   使い方: node browser_probe.mjs <https://example.com> [追加パス...]
//
// 取得するもの:
//   1. 同意前の第三者送信（Cookie を持たない素の訪問で、どこへ何が飛ぶか）と、
//      リアルタイム通信（WebSocket）の接続先
//   2. Cookie の属性（HttpOnly / Secure / SameSite）
//   3. localStorage / sessionStorage に置かれたキーの名前（値は取得しない）
//   4. CSP の実効性（ヘッダと <meta> の両方。実際に効く指令で判定し、Report-Only か、違反の発生も見る）
//   5. 認証後の画面に関わるキャッシュヘッダ
//
// 対象システムの状態は変えない。GET のみで、フォームの送信もクリックもしない。
// 同意バナーには触れないため、「同意前の状態」がそのまま観測できる。
//
// 依存: Node.js 20 以降と Playwright（1.63）。**評価対象のリポジトリには入れない**
// （package.json と lock を書き換えてしまう）。導入の手順は INSTALL を参照。

import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { realpathSync } from "node:fs";

const PW_VERSION = "1.63.0";
const NODE_MIN = 20;

// 評価対象を汚さない導入手順。スキルの外の作業用ディレクトリに版を固定して入れ、NODE_PATH で渡す。
// import() は NODE_PATH を見ないが、このスクリプトは見つからなければ require でも探す。
const INSTALL = [
  "評価対象のリポジトリでは npm install しない（package.json と lock を書き換えてしまう）。",
  "スキルの外の作業用ディレクトリに、版を固定して入れる:",
  "",
  `  npm i --prefix "$HOME/.cache/wsa-playwright" playwright@${PW_VERSION}`,
  `  npx -y playwright@${PW_VERSION} install chromium`,
  `  NODE_PATH="$HOME/.cache/wsa-playwright/node_modules" node <このスクリプト> <URL>`,
];

// 計測・広告の既知の送信先。「ラベル, ホスト名の正規表現」。
// **recon.sh の TAGS と同じ内容に揃える**（tests/run.sh が一致を検査する）。
// ホスト名の末尾で照合する。端の指定が無いと hotjar.com.attacker.example にもラベルが付く。
// ホスト名は各社の公式の CSP の設定例・送信先の一覧で確かめたもの（2026-09）。
export const TAG_SOURCES = [
  ["Google タグマネージャ", "(^|\\.)googletagmanager\\.com$"],
  ["Google アナリティクス", "(^|\\.)(google-analytics\\.com|analytics\\.google\\.com)$"],
  ["Google 広告", "(^|\\.)(googlesyndication\\.com|doubleclick\\.net|googleadservices\\.com)$"],
  ["Meta ピクセル", "(^|\\.)connect\\.facebook\\.net$|^www\\.facebook\\.com$"],
  ["Microsoft Clarity", "(^|\\.)clarity\\.ms$|^c\\.bing\\.com$"],
  ["Hotjar", "(^|\\.)hotjar\\.(com|io)$"],
  ["TikTok ピクセル", "^analytics\\.tiktok\\.com$"],
  ["LinkedIn Insight", "^snap\\.licdn\\.com$"],
  ["X 広告", "^static\\.ads-twitter\\.com$"],
  ["Yahoo! 広告", "^s\\.yimg\\.jp$"],
  ["Sentry", "(^|\\.)(sentry\\.io|sentry-cdn\\.com)$"],
  ["Intercom", "(^|\\.)intercom\\.io$"],
  ["LogRocket", "(^|\\.)(logrocket\\.(io|com)|lr-ingest\\.(io|com)|lr-in\\.com|lr-in-prod\\.com|ingest-lr\\.com|lr-intake\\.com|intake-lr\\.com|logr-ingest\\.com|lrkt-in\\.com|lgrckt-in\\.com|logr-in\\.com)$"],
  ["FullStory", "(^|\\.)fullstory\\.com$"],
  ["PostHog", "(^|\\.)posthog\\.com$"],
  ["Datadog RUM", "(^|\\.)browser-intake-([a-z0-9]+-)?(datadoghq\\.(com|eu)|ddog-gov\\.com)$|^www\\.datadoghq-browser-agent\\.com$"],
  ["Mouseflow", "(^|\\.)mouseflow\\.com$"],
];
// ラベル付けを単体で検査できるよう export している。形は [正規表現, ラベル]。
export const TAGS = TAG_SOURCES.map(([label, re]) => [new RegExp(re), label]);

// リアルタイム通信の既知の接続先（計測・広告に当たらないもの）
export const REALTIME = [
  [/(^|\.)supabase\.co$/, "Supabase Realtime"],
  [/(^|\.)(pusher\.com|pusherapp\.com)$/, "Pusher"],
  [/(^|\.)(firebaseio\.com|firebasedatabase\.app)$/, "Firebase Realtime Database"],
];

// CSP の文字列を指令ごとに分ける。同じ指令が 2 回あれば最初のものだけが効く（CSP Level 3）。
export function parseCsp(policy) {
  const d = new Map();
  for (const part of String(policy).split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    if (!d.has(name)) d.set(name, tokens.slice(1));
  }
  return d;
}

// 1 つの CSP を、references/07-web-vulnerabilities.md の 1-6 の基準で判定する。
//   - script-src が無ければ default-src が使われる（実際に効く値で判定する）
//   - <script> 要素は script-src-elem、イベントハンドラ属性は script-src-attr が優先される。
//     script-src-elem を script-src と取り違えない（以前は "script-src" の前方一致で拾っていた）
//   - 同じ指令に nonce・hash・'strict-dynamic' のいずれかがあれば、'unsafe-inline' は無視される
//   - 'unsafe-eval' はこの打ち消しの対象外
export function judgeCsp(policy) {
  const d = parseCsp(policy);
  const pick = (names) => {
    for (const n of names) if (d.has(n)) return { directive: n, sources: d.get(n) };
    return { directive: null, sources: null };
  };
  const inlineOf = (sources) => {
    if (!sources) return { allowed: true, ignored: false };
    const low = sources.map((s) => s.toLowerCase());
    const hasUI = low.includes("'unsafe-inline'");
    const cancels = low.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s)) || low.includes("'strict-dynamic'");
    return { allowed: hasUI && !cancels, ignored: hasUI && cancels };
  };
  const script = pick(["script-src", "default-src"]);
  const elem = pick(["script-src-elem", "script-src", "default-src"]);
  const attr = pick(["script-src-attr", "script-src", "default-src"]);
  const e = inlineOf(elem.sources);
  const a = inlineOf(attr.sources);
  // 指定のある側（要素・属性）のどちらかでインラインが通れば、XSS の注入はそちらから成立する
  const inlineAllowed = !!((elem.sources && e.allowed) || (attr.sources && a.allowed));
  return {
    script, elem, attr,
    noScriptRestriction: !elem.sources && !attr.sources,
    unsafeInline: inlineAllowed,
    unsafeInlineIgnored: (e.ignored || a.ignored) && !inlineAllowed,
    unsafeEval: !!(script.sources && script.sources.some((s) => s.toLowerCase() === "'unsafe-eval'")),
    frameAncestorsOnly: !elem.sources && !attr.sources && d.has("frame-ancestors"),
  };
}

// 接続先の URL を、クエリを伏せて表示用にする（Supabase Realtime などは apikey をクエリに載せる）
export function safeUrl(u) {
  try {
    const x = new URL(u);
    return `${x.protocol}//${x.host}${x.pathname}${x.search ? "?…（クエリは伏字）" : ""}`;
  } catch { return "（URL として読めない）"; }
}

function usage() {
  console.error("使い方: node browser_probe.mjs <https://example.com> [追加で開くパス...]");
  console.error("");
  console.error(`依存: Node.js ${NODE_MIN} 以降と Playwright ${PW_VERSION}`);
  for (const l of INSTALL) console.error(l ? `  ${l}` : "");
}

// Playwright を探す。まず通常の解決（このスクリプトの置き場所から上へ）、
// 見つからなければ require で NODE_PATH も見る（import() は NODE_PATH を見ないため）。
async function loadPlaywright() {
  try { return await import("playwright"); } catch { /* 次へ */ }
  try { return createRequire(import.meta.url)("playwright"); } catch { /* 次へ */ }
  return null;
}

// 引数の検査を先に済ませる。依存が入っていない環境でも、まず使い方が読めるように。
// 直接実行されたときだけ動かす。import しても副作用が起きないようにするため。
// こうしておくと、TAGS や judgeCsp のような部品を検査から読み込める。
async function main() {
  const raw = process.argv[2];
  if (!raw) { usage(); process.exit(1); }
  const base = raw.replace(/\/$/, "");
  let host;
  try { host = new URL(base).hostname; }
  catch { console.error(`URL として読めない: ${raw}`); usage(); process.exit(1); }
  const paths = process.argv.slice(3);

  const major = Number(process.versions.node.split(".")[0]);
  if (major < NODE_MIN) {
    console.error(`Node.js ${NODE_MIN} 以降が要る（今は ${process.versions.node}）。Playwright ${PW_VERSION} の要件。`);
    process.exit(1);
  }

  const pw = await loadPlaywright();
  if (!pw) {
    console.error("Playwright が見つからない。");
    console.error("");
    for (const l of INSTALL) console.error(l);
    console.error("");
    console.error("入れられない環境なら references/09-browser-verification.md の手順を手で実行する。");
    console.error("自動化は速さのためであって、これが無いと確認できないわけではない。");
    process.exit(1);
  }
  const { chromium } = pw;

  const hr = (s) => console.log(`\n=== ${s} ===`);
  // 自ドメインとそのサブドメインを「第三者ではない」とみなす。転送された先（www から apex など）の
  // ホストも自サイトに含める（recon.sh と同じ）。転送先は読み込みが終わるまで分からないので、
  // 観測した要求はホストごとにいったん全部数え、読み込みの後で自サイトを除く。
  const own = new Set([host]);
  const isOwn = (h) => [...own].some((o) => h === o || h.endsWith(`.${o}`));
  // コンソールの文言には URL が載り、クエリに鍵や識別子が入りうる（?key=…）。クエリと断片を伏せて残す
  const maskUrls = (t) => t.replace(/(https?:\/\/[^\s?#"')]+)[?#][^\s"')]*/g, "$1?…（伏字）");
  const tagOf = (h) => { const t = TAGS.find(([re]) => re.test(h)); return t ? t[1] : ""; };

  const browser = await chromium.launch();
  // 素の訪問を作る。保存された同意状態を持ち込まないため、毎回新しいコンテキストを使う。
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  const seen = new Map();         // ホスト -> 件数（自サイトを含む。送信が試みられた数）
  const failed = new Map();       // ホスト -> 件数（自サイトを含む。実際には飛ばなかった数）
  const wsSeen = new Set();       // WebSocket で接続したホスト（自サイトを含む）
  const thirdParty = new Map();   // 読み込みの後に、seen から自サイトを除いて作る
  const blocked = new Map();
  const wsThird = new Set();
  const sockets = [];             // { url, sent, received, closed }
  const cspViolations = [];
  const consoleErrors = [];

  page.on("request", (req) => {
    try {
      const h = new URL(req.url()).hostname;
      seen.set(h, (seen.get(h) || 0) + 1);
    } catch { /* データ URI など。無視してよい */ }
  });
  // CSP やネットワークの都合で成立しなかったものを分けて数える。
  // 「送信を試みた」と「実際に届いた」は別で、報告では区別する必要がある。
  page.on("requestfailed", (req) => {
    try {
      const h = new URL(req.url()).hostname;
      failed.set(h, (failed.get(h) || 0) + 1);
    } catch { /* 同上 */ }
  });
  // WebSocket は request イベントに出ない。別に拾わないと、同意前の送信とリアルタイム通信の
  // 接続先（Supabase Realtime・Pusher・自前の ws）が丸ごと見えない。
  // メッセージの中身は取らない（数だけ数える）。
  page.on("websocket", (ws) => {
    const s = { url: ws.url(), sent: 0, received: 0, closed: false };
    sockets.push(s);
    try {
      const h = new URL(s.url).hostname;
      seen.set(h, (seen.get(h) || 0) + 1); wsSeen.add(h);
    } catch { /* 同上 */ }
    ws.on("framesent", () => { s.sent++; });
    ws.on("framereceived", () => { s.received++; });
    ws.on("close", () => { s.closed = true; });
  });
  page.on("console", (msg) => {
    const t = msg.text();
    if (/Content Security Policy|Refused to/i.test(t)) cspViolations.push(maskUrls(t).slice(0, 200));
    else if (msg.type() === "error") consoleErrors.push(maskUrls(t).slice(0, 200));
  });

  console.log(`対象: ${base}`);
  console.log(`Cookie を持たない素の訪問。同意バナーには触れない。`);

  let mainRes;
  try {
    mainRes = await page.goto(base, { waitUntil: "networkidle", timeout: 45000 });
  } catch (e) {
    console.error(`\n読み込みに失敗した: ${e.message}`);
    await browser.close();
    process.exit(1);
  }
  // 遅延して発火するタグを拾う。同意バナー表示後に飛ぶものがここに出る。
  await page.waitForTimeout(3000);
  // 転送された先のホストも自サイトとして、第三者の一覧を作る
  try { own.add(new URL(page.url()).hostname); } catch { /* 同上 */ }
  for (const [h, n] of seen) if (!isOwn(h)) thirdParty.set(h, n);
  for (const [h, n] of failed) if (!isOwn(h)) blocked.set(h, n);
  for (const h of wsSeen) if (!isOwn(h)) wsThird.add(h);

  // CSP は <meta http-equiv> でも置ける。ヘッダだけを見ると、meta で置いた CSP を「無い」と言う。
  const metaCsp = await page.evaluate(() =>
    [...document.querySelectorAll("meta[http-equiv]")]
      .map((m) => ({ equiv: (m.httpEquiv || "").toLowerCase(), content: m.content || "" }))
      .filter((m) => m.equiv === "content-security-policy" || m.equiv === "content-security-policy-report-only"));

  // --------------------------------------------------------------------------
  hr("1. 同意前の第三者送信");
  if (thirdParty.size === 0) {
    console.log("  第三者オリジンへの送信は観測されなかった");
  } else {
    const sorted = [...thirdParty.entries()].sort((a, b) => b[1] - a[1]);
    for (const [h, n] of sorted) {
      const b = blocked.get(h) || 0;
      const note = b > 0 ? `（うち ${b} 件は成立せず）` : "";
      const ws = wsThird.has(h) ? "（WebSocket を含む）" : "";
      console.log(`  ${String(n).padStart(3)} 件  ${h.padEnd(30)} ${tagOf(h)}${ws}${note}`);
    }
    const totalBlocked = [...blocked.values()].reduce((a, b) => a + b, 0);
    if (totalBlocked > 0) {
      console.log("");
      console.log(`  ※ ${totalBlocked} 件は成立しなかった（CSP でブロックされた、配信元が落ちている等）。`);
      console.log("    送信を試みたことと、実際に届いたことは別。報告では区別して書く");
    }
    const known = sorted.filter(([h]) => tagOf(h));
    if (known.length > 0) {
      const labels = [...new Set(known.map(([h]) => tagOf(h)))].join("・");
      console.log("");
      console.log(`  ※ 計測・広告に該当するホストが ${known.length} 件（${labels}）。同意を取る前に送信している。`);
      console.log("    references/08-privacy-compliance.md の 2 節・3 節で扱う事実になる。");
      console.log("    セッションリプレイ（Clarity・Hotjar・LogRocket・FullStory・PostHog・Datadog・Mouseflow・Sentry）なら、");
      console.log("    画面の表示と操作まで送っている可能性がある。何が記録されるかは 08 の 1-2 で確かめる");
    }
  }

  hr("1b. リアルタイム通信（WebSocket）");
  if (sockets.length === 0) {
    console.log("  WebSocket の接続は観測されなかった");
  } else {
    for (const s of sockets) {
      let h = "";
      try { h = new URL(s.url).hostname; } catch { /* 無視 */ }
      const who = isOwn(h) ? "自サイト" : "第三者";
      const rt = REALTIME.find(([re]) => re.test(h));
      const label = tagOf(h) || (rt ? rt[1] : "");
      console.log(`  ${safeUrl(s.url)}`);
      console.log(`        ${who}${label ? `・${label}` : ""}  送信 ${s.sent} 件 / 受信 ${s.received} 件（同意前）`);
    }
    console.log("");
    console.log("  ※ 同意前に第三者へメッセージを送っていれば、1 節と同じく同意前の送信になる（08 の 2・3 節）");
    console.log("  ※ 購読・チャネルの認可（他人のチャネルに入れないか）は 07 の 11 節で見る。接続できたことは認可の証拠にならない");
  }

  // --------------------------------------------------------------------------
  hr("2. Cookie の属性");
  const cookies = await ctx.cookies();
  if (cookies.length === 0) {
    console.log("  （Cookie は発行されていない）");
  } else {
    for (const c of cookies) {
      // 値は出さない。名前と属性だけで判定できる。
      const flags = [
        c.httpOnly ? "HttpOnly" : "**HttpOnly なし**",
        c.secure ? "Secure" : "**Secure なし**",
        `SameSite=${c.sameSite || "未設定"}`,
      ].join(" / ");
      console.log(`  ${c.name.padEnd(34)} ${flags}`);
    }
    console.log("");
    console.log("  ※ 認証に使う Cookie に HttpOnly が無ければ、XSS が成立した時点で持ち出される");
  }

  // --------------------------------------------------------------------------
  hr("3. ブラウザ保存領域に置かれたキー（名前のみ・値は取得しない）");
  const storage = await page.evaluate(() => {
    const pick = (s) => { try { return Object.keys(s); } catch { return []; } };
    return { local: pick(localStorage), session: pick(sessionStorage) };
  });
  const SUSPICIOUS = /token|auth|session|password|passwd|secret|key|jwt|credential/i;
  for (const [label, keys] of [["localStorage", storage.local], ["sessionStorage", storage.session]]) {
    if (keys.length === 0) { console.log(`  ${label}: （空）`); continue; }
    console.log(`  ${label}: ${keys.length} 件`);
    for (const k of keys) {
      const warn = SUSPICIOUS.test(k) ? "  ← 認証情報の可能性。値は見ずに、コード側で用途を確かめる" : "";
      console.log(`    ${k}${warn}`);
    }
  }

  // --------------------------------------------------------------------------
  hr("4. CSP の実効性");
  const headers = mainRes ? mainRes.headers() : {};
  // 同じ名前のヘッダが複数あると headers() では 1 つにまとまる。1 本ずつ取り、さらに "," で分ける
  // （1 本のヘッダに複数の CSP を "," でつないで書ける）。
  const hdrArr = mainRes ? await mainRes.headersArray() : [];
  const splitPolicies = (name) => hdrArr
    .filter((x) => x.name.toLowerCase() === name)
    .flatMap((x) => x.value.split(","))
    .map((v) => v.trim()).filter(Boolean);
  const policies = [
    ...splitPolicies("content-security-policy").map((p) => ({ from: "ヘッダ", enforce: true, p })),
    ...metaCsp.filter((m) => m.equiv === "content-security-policy").map((m) => ({ from: "meta", enforce: true, p: m.content })),
    ...splitPolicies("content-security-policy-report-only").map((p) => ({ from: "ヘッダ（Report-Only）", enforce: false, p })),
  ];
  if (policies.length === 0) {
    console.log("  [無] CSP が設定されていない（ヘッダにも <meta> にも無い）");
  } else {
    if (!policies.some((x) => x.enforce)) console.log("  [要確認] Report-Only のみ。観測しているだけでブロックはしない");
    for (const { from, enforce, p } of policies) {
      const j = judgeCsp(p);
      console.log(`  [${from}]`);
      const show = (label, x) => console.log(`    ${label}: ${x.sources ? x.sources.join(" ") : "（指定なし）"}${x.directive ? `  ← ${x.directive} が効く` : ""}`);
      if (j.attr.directive === j.elem.directive) show("スクリプト", j.elem);
      else { show("<script> 要素", j.elem); show("イベントハンドラ属性", j.attr); }
      if (j.noScriptRestriction) {
        console.log("    → script-src も default-src も無い。スクリプトの実行を制限していない");
        if (j.frameAncestorsOnly) console.log("    → frame-ancestors のみ。クリックジャッキング対策であって XSS 対策ではない");
      }
      if (j.unsafeInline) console.log(`    → **unsafe-inline がある。XSS に対しては実質的に効かない**${enforce ? "" : "（Report-Only）"}`);
      else if (j.unsafeInlineIgnored) console.log("    → 'unsafe-inline' は nonce・hash・'strict-dynamic' と並んでいるため、ブラウザは無視する（指摘しない）");
      if (j.unsafeEval) console.log("    → **unsafe-eval がある**");
    }
    if (policies.filter((x) => x.enforce).length > 1) {
      console.log("  ※ 強制の CSP が複数ある。ブラウザはすべてを同時に適用する（いちばん厳しいものが効く）");
    }
    if (metaCsp.length > 0) {
      console.log("  ※ <meta> の CSP は、それより前に書かれた要素には効かない。frame-ancestors・report-uri・sandbox は無視され、");
      console.log("    Report-Only は <meta> では使えない。ヘッダに移すのが確実");
    }
  }
  console.log(`  読み込み中に観測した CSP 違反: ${cspViolations.length} 件`);
  for (const v of cspViolations.slice(0, 5)) console.log(`    ${v}`);
  console.log("  ※ 違反 0 件は「効いている」証拠にならない。違反する記述が無いだけかもしれない");

  // --------------------------------------------------------------------------
  hr("5. セキュリティヘッダとキャッシュ");
  for (const h of ["strict-transport-security", "x-frame-options", "x-content-type-options",
                   "referrer-policy", "permissions-policy", "cache-control"]) {
    console.log(headers[h] ? `  [有] ${h}: ${headers[h]}` : `  [無] ${h}`);
  }
  if (headers["x-powered-by"]) console.log(`  [要確認] x-powered-by: ${headers["x-powered-by"]}（実装情報が露出）`);

  // --------------------------------------------------------------------------
  if (paths.length > 0) {
    hr("6. 追加パスの応答とキャッシュ指定");
    for (const p of paths) {
      const url = `${base}${p.startsWith("/") ? p : "/" + p}`;
      try {
        const r = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
        const cc = r.headers()["cache-control"] || "（指定なし）";
        console.log(`  ${String(r.status()).padEnd(5)} ${p.padEnd(28)} cache-control: ${cc}`);
        console.log(`        → 最終 URL: ${new URL(page.url()).pathname}`);
      } catch (e) {
        console.log(`  ---   ${p.padEnd(28)} 読み込み失敗: ${e.message.slice(0, 60)}`);
      }
    }
    console.log("");
    console.log("  ※ 開発用ルートの期待値は 404 か 403。認証が要る画面はリダイレクト先を見る");
    console.log("  ※ 個人情報が出る画面に no-store が無ければ、戻るボタンで再表示される（09 の 6 節）");
  }

  if (consoleErrors.length > 0) {
    hr("参考: コンソールに出たエラー");
    for (const e of consoleErrors.slice(0, 5)) console.log(`  ${e}`);
  }

  await browser.close();

  hr("完了");
  console.log("この出力をそのまま報告書に貼らないこと。次が混ざっている。");
  console.log("  ・第三者へのリクエスト先ホスト（URL のクエリには閲覧履歴や識別子が載る）");
  console.log("  ・保存領域のキー名（用途を確かめる前の推測が混ざる）");
  console.log("報告書には「同意前に計測 2 ホスト・広告 2 ホストへ送信」までに留める。");
  console.log("");
  console.log("認証が要る確認（権限の境界・ログアウトの実効性・戻るボタン）は自動化していない。");
  console.log("references/09-browser-verification.md の手順を依頼者に渡すこと。");

}

// 実体のパスで比べる。/tmp のようなシンボリックリンクの下に置くと、import.meta.url は実体の側になる
const invoked = (() => {
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; }
  catch { return false; }
})();
if (invoked) await main();
