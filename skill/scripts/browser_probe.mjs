#!/usr/bin/env node
// browser_probe.mjs — ブラウザで実際に読み込んで、curl では見えないものを取る（読み取り専用）
//
//   使い方: node browser_probe.mjs <https://example.com> [追加パス...]
//
// 取得するもの:
//   1. 同意前の第三者送信（Cookie を持たない素の訪問で、どこへ何が飛ぶか）
//   2. Cookie の属性（HttpOnly / Secure / SameSite）
//   3. localStorage / sessionStorage に置かれたキーの名前（値は取得しない）
//   4. CSP の実効性（unsafe-inline の有無、Report-Only か、違反の発生）
//   5. 認証後の画面に関わるキャッシュヘッダ
//
// 対象システムの状態は変えない。GET のみで、フォームの送信もクリックもしない。
// 同意バナーには触れないため、「同意前の状態」がそのまま観測できる。
//
// 依存: Node.js 18 以降と Playwright。
//   npm i -D playwright && npx playwright install chromium

import { pathToFileURL } from "node:url";

// 既知の計測・広告タグ。ラベル付けを単体で検査できるよう export している。
export const TAGS = [
  [/googletagmanager\.com/, "Google タグマネージャ"],
  [/google-analytics\.com|analytics\.google\.com/, "Google アナリティクス"],
  [/googlesyndication\.com|pagead2\./, "Google 広告"],
  [/doubleclick\.net|googleadservices\.com/, "Google 広告"],
  [/connect\.facebook\.net|facebook\.com\/tr/, "Meta ピクセル"],
  [/clarity\.ms/, "Microsoft Clarity"],
  [/hotjar\.com/, "Hotjar"],
  [/analytics\.tiktok\.com/, "TikTok ピクセル"],
  [/snap\.licdn\.com/, "LinkedIn Insight"],
  [/static\.ads-twitter\.com/, "X 広告"],
  [/sentry\.io/, "Sentry"],
  [/intercom\.io/, "Intercom"],
];

function usage() {
  console.error("使い方: node browser_probe.mjs <https://example.com> [追加で開くパス...]");
  console.error("");
  console.error("依存: Node.js 18 以降と Playwright");
  console.error("  npm i -D playwright && npx playwright install chromium");
}

// 引数の検査を先に済ませる。依存が入っていない環境でも、まず使い方が読めるように。
// 直接実行されたときだけ動かす。import しても副作用が起きないようにするため。
// こうしておくと、TAGS のような部品を検査から読み込める。
async function main() {
  const raw = process.argv[2];
  if (!raw) { usage(); process.exit(1); }
  const base = raw.replace(/\/$/, "");
  let host;
  try { host = new URL(base).hostname; }
  catch { console.error(`URL として読めない: ${raw}`); usage(); process.exit(1); }
  const paths = process.argv.slice(3);

  let chromium;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    console.error("Playwright が見つからない。次で導入する。");
    console.error("  npm i -D playwright && npx playwright install chromium");
    console.error("");
    console.error("入れられない環境なら references/09-browser-verification.md の手順を手で実行する。");
    console.error("自動化は速さのためであって、これが無いと確認できないわけではない。");
    process.exit(1);
  }

  const hr = (s) => console.log(`\n=== ${s} ===`);
  // 自ドメインとそのサブドメインを「第三者ではない」とみなす
  const isOwn = (h) => h === host || h.endsWith(`.${host}`);

  const browser = await chromium.launch();
  // 素の訪問を作る。保存された同意状態を持ち込まないため、毎回新しいコンテキストを使う。
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  const thirdParty = new Map();   // ホスト -> 件数（送信が試みられた数）
  const blocked = new Map();      // ホスト -> 件数（実際には飛ばなかった数）
  const cspViolations = [];
  const consoleErrors = [];

  page.on("request", (req) => {
    try {
      const h = new URL(req.url()).hostname;
      if (!isOwn(h)) thirdParty.set(h, (thirdParty.get(h) || 0) + 1);
    } catch { /* データ URI など。無視してよい */ }
  });
  // CSP やネットワークの都合で成立しなかったものを分けて数える。
  // 「送信を試みた」と「実際に届いた」は別で、報告では区別する必要がある。
  page.on("requestfailed", (req) => {
    try {
      const h = new URL(req.url()).hostname;
      if (!isOwn(h)) blocked.set(h, (blocked.get(h) || 0) + 1);
    } catch { /* 同上 */ }
  });
  page.on("console", (msg) => {
    const t = msg.text();
    if (/Content Security Policy|Refused to/i.test(t)) cspViolations.push(t.slice(0, 200));
    else if (msg.type() === "error") consoleErrors.push(t.slice(0, 200));
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

  // --------------------------------------------------------------------------
  hr("1. 同意前の第三者送信");
  if (thirdParty.size === 0) {
    console.log("  第三者オリジンへの送信は観測されなかった");
  } else {
    const sorted = [...thirdParty.entries()].sort((a, b) => b[1] - a[1]);
    for (const [h, n] of sorted) {
      const tag = TAGS.find(([re]) => re.test(h));
      const b = blocked.get(h) || 0;
      const note = b > 0 ? `（うち ${b} 件は成立せず）` : "";
      console.log(`  ${String(n).padStart(3)} 件  ${h.padEnd(30)} ${tag ? tag[1] : ""}${note}`);
    }
    const totalBlocked = [...blocked.values()].reduce((a, b) => a + b, 0);
    if (totalBlocked > 0) {
      console.log("");
      console.log(`  ※ ${totalBlocked} 件は成立しなかった（CSP でブロックされた、配信元が落ちている等）。`);
      console.log("    送信を試みたことと、実際に届いたことは別。報告では区別して書く");
    }
    const known = sorted.filter(([h]) => TAGS.some(([re]) => re.test(h)));
    if (known.length > 0) {
      console.log("");
      console.log(`  ※ 計測・広告に該当するホストが ${known.length} 件。同意を取る前に送信している。`);
      console.log("    references/08-privacy-compliance.md の 2 節・3 節で扱う事実になる");
    }
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
  const csp = headers["content-security-policy"];
  const cspRO = headers["content-security-policy-report-only"];
  if (!csp && !cspRO) {
    console.log("  [無] CSP が設定されていない");
  } else {
    if (cspRO && !csp) console.log("  [要確認] Report-Only のみ。観測しているだけでブロックはしない");
    const target = csp || cspRO;
    const scriptSrc = (target.match(/script-src[^;]*/i) || [""])[0];
    console.log(`  script-src: ${scriptSrc || "（指定なし）"}`);
    if (/unsafe-inline/i.test(scriptSrc)) console.log("    → **unsafe-inline がある。XSS に対しては実質的に効かない**");
    if (/unsafe-eval/i.test(scriptSrc)) console.log("    → **unsafe-eval がある**");
    if (!scriptSrc && /frame-ancestors/i.test(target)) {
      console.log("    → frame-ancestors のみ。クリックジャッキング対策であって XSS 対策ではない");
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

const invoked = process.argv[1]
  ? import.meta.url === pathToFileURL(process.argv[1]).href
  : false;
if (invoked) await main();
