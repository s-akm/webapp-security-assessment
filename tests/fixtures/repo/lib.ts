// 以下はすべて架空の値。形式だけを模した検出テスト用のダミー。
const stripe_secret = "sk_live_00000000000000000000TESTDUMMY";
const ENABLE_GUARD = process.env.GUARD !== 'false';   // fail-open。5 節で検出されるべき
export function render(h) { el.innerHTML = h; }        // 3 節で検出されるべき

// 予測できる乱数を再設定トークンに使っている（13 節で検出されるべき）
export function makeResetToken() { return Math.random().toString(36).slice(2); }
// 証明書の検証を切っている（14 節で検出されるべき）
const agent = new https.Agent({ rejectUnauthorized: false });
// 弱いハッシュ
const digest = crypto.createHash('md5').update(pw).digest('hex');
// XML の解析（15 節で検出されるべき）
import { parseString } from 'xml2js';
