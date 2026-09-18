#!/usr/bin/env bash
# recon.sh — 本番サイトの外形調査を一括で取る（読み取り専用）
#
#   使い方: ./recon.sh https://example.com [追加パス...]
#
# 取得するもの:
#   1. HTTP セキュリティヘッダの実際の付与状況
#   2. DNS レコード（SPF / DMARC / CAA / DNSSEC / MX / NS）と送信ドメイン認証
#   3. クライアント JS バンドル内の、鍵らしき文字列と API エンドポイント
#   4. 第三者への送信先、計測・広告タグ、同意管理の実装（外部送信規律・CMP の検討材料）
#   5. 追加パスを指定した場合、その HTTP ステータス（開発用ルートの確認など）
#
# 対象システムの状態は一切変更しない。GET と DNS 参照のみ。
# 検出した鍵の値は伏字で表示する。値そのものが必要な場合は取得したファイルを直接見る。

set -uo pipefail

URL="${1:-}"
if [[ -z "$URL" ]]; then
  echo "使い方: $0 <https://example.com> [追加で叩くパス...]" >&2
  exit 1
fi
shift || true

URL="${URL%/}"
DOMAIN="$(printf '%s' "$URL" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##')"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

hr() { printf '\n=== %s ===\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# DNS の問い合わせ。RECON_DNS に "サーバー:ポート" を入れると、そのサーバーに聞く。
# 社内の権威サーバーに直接聞きたいとき、検査用の受け口に向けたいときに使う。
# 未設定なら OS の設定どおり（通常はこちら）。
dq() {
  if [[ -n "${RECON_DNS:-}" ]]; then
    dig +short +time=2 +tries=1 "@${RECON_DNS%%:*}" -p "${RECON_DNS##*:}" "$@"
  else
    dig +short +time=3 +tries=1 "$@"
  fi
}

# --------------------------------------------------------------------------
hr "対象"
echo "URL:    $URL"
echo "Domain: $DOMAIN"

# --------------------------------------------------------------------------
hr "1. HTTP レスポンスヘッダ（全体）"
curl -sSI --max-time 20 "$URL" || echo "(取得失敗)"

hr "1b. セキュリティヘッダの判定"
HEADERS="$(curl -sSI --max-time 20 "$URL" 2>/dev/null | tr -d '\r')"
for h in strict-transport-security content-security-policy x-frame-options \
         x-content-type-options referrer-policy permissions-policy; do
  line="$(printf '%s\n' "$HEADERS" | grep -i "^$h:" || true)"
  if [[ -n "$line" ]]; then printf '  [有] %s\n' "$line"; else printf '  [無] %s\n' "$h"; fi
done
if printf '%s\n' "$HEADERS" | grep -qi '^x-powered-by:'; then
  printf '  [要確認] %s （実装情報が露出）\n' "$(printf '%s\n' "$HEADERS" | grep -i '^x-powered-by:')"
else
  printf '  [良] x-powered-by は出ていない\n'
fi

# --------------------------------------------------------------------------
if have dig; then
  hr "2. DNS レコード"
  printf '  NS     : %s\n' "$(dq NS   "$DOMAIN" | tr '\n' ' ')"
  printf '  A      : %s\n' "$(dq A    "$DOMAIN" | tr '\n' ' ')"
  printf '  AAAA   : %s\n' "$(dq AAAA "$DOMAIN" | tr '\n' ' ')"
  printf '  MX     : %s\n' "$(dq MX   "$DOMAIN" | tr '\n' ' ')"
  printf '  CAA    : %s\n' "$(dq CAA  "$DOMAIN" | tr '\n' ' ')"
  printf '  DS     : %s\n' "$(dq DS   "$DOMAIN" | tr '\n' ' ')"

  hr "2b. 送信ドメイン認証"
  SPF="$(dq TXT "$DOMAIN" | tr -d '"' | grep -i '^v=spf1' || true)"
  DMARC="$(dq TXT "_dmarc.$DOMAIN" | tr -d '"' | grep -i '^v=DMARC1' || true)"
  [[ -n "$SPF"   ]] && printf '  [有] SPF   : %s\n' "$SPF"     || printf '  [無] SPF（apex に SPF レコードが無い）\n'
  if [[ -n "$DMARC" ]]; then
    # rua / ruf に入っている連絡先は、DNS 上は公開情報だが報告書には要らない。
    # 出力の時点で伏せる。末尾の注意書きだけでは、貼り付けたときに残る。
    printf '  [有] DMARC : %s\n' "$(printf '%s' "$DMARC" | sed -E 's/mailto:[^,;[:space:]]+/mailto:<伏字>/g')"
    printf '%s' "$DMARC" | grep -qi 'p=none' && printf '        → p=none。監視のみで隔離・拒否をしない\n'
  else
    printf '  [無] DMARC\n'
  fi

  hr "2c. 配信サービス用サブドメイン（よくある名前を総当たり）"
  for sub in send mail email smtp mg em bounce news; do
    s_txt="$(dq TXT "$sub.$DOMAIN" | tr -d '"' | grep -i '^v=spf1' || true)"
    s_mx="$(dq MX "$sub.$DOMAIN" | tr '\n' ' ')"
    if [[ -n "$s_txt$s_mx" ]]; then
      printf '  %s.%s\n' "$sub" "$DOMAIN"
      [[ -n "$s_txt" ]] && printf '    SPF: %s\n' "$s_txt"
      [[ -n "$s_mx"  ]] && printf '    MX : %s\n' "$s_mx"
    fi
  done
  printf '  DKIM セレクタ:\n'
  for sel in resend sendgrid mandrill google s1 s2 k1 default selector1 selector2 mail smtp; do
    d="$(dq TXT "$sel._domainkey.$DOMAIN" | head -c 40 || true)"
    [[ -n "$d" ]] && printf '    [有] %s._domainkey\n' "$sel"
  done
else
  hr "2. DNS レコード"
  echo "  dig が見つからないため省略（dnsutils / bind-utils を入れると取得できる）"
fi

# --------------------------------------------------------------------------
hr "3. クライアント JS バンドル内の鍵とエンドポイント"
cd "$WORK" || exit 1

# トップページと、認証系ページの HTML を集める（ログイン画面に鍵が出ることが多い）
PAGES=("/" "/login" "/signin" "/sign-in" "/admin/login" "/auth/login")
for p in "${PAGES[@]}"; do
  curl -sS --max-time 15 -o "page$(printf '%s' "$p" | tr '/' '_').html" "$URL$p" 2>/dev/null || true
done

# HTML から参照されているスクリプトを集める（相対・絶対の両方）
grep -ohE '(src="|href=")[^"]+\.js' ./*.html 2>/dev/null \
  | sed -E 's/^(src|href)="//' | sort -u > chunks.txt || true
# all.js  … 第三者のスクリプトも含めた全部（鍵の露出を探す用）
# own.js  … 自サイト配信ぶんだけ（自前の実装かどうかを判定する用）
#
# この 2 つを分けるのは重要。たとえば広告スクリプトは、CMP の有無を調べるために
# __tcfapi を参照する。全部を一緒に grep すると「CMP を実装している」と誤判定する。
: > all.js; : > own.js
while IFS= read -r c; do
  [[ -z "$c" ]] && continue
  case "$c" in
    "$URL"/*) curl -sS --max-time 15 "$c" | tee -a own.js >> all.js 2>/dev/null || true ;;
    http*)    curl -sS --max-time 15 "$c" >> all.js 2>/dev/null || true ;;
    /*)       curl -sS --max-time 15 "$URL$c" | tee -a own.js >> all.js 2>/dev/null || true ;;
  esac
done < chunks.txt
cat ./*.html >> all.js 2>/dev/null || true
cat ./*.html >> own.js 2>/dev/null || true

echo "  収集: HTML $(ls -1 ./*.html 2>/dev/null | wc -l | tr -d ' ') 件 / JS $(wc -l < chunks.txt 2>/dev/null || echo 0) 件 / 合計 $(wc -c < all.js 2>/dev/null || echo 0) bytes"

mask() { sed -E 's/(.{10}).*/\1…（以降は伏字）/'; }

echo "  --- 鍵らしき文字列 ---"
found=0
# JWT 形式
if grep -qoE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' all.js 2>/dev/null; then
  n=$(grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' all.js | sort -u | wc -l | tr -d ' ')
  echo "    JWT 形式: ${n} 件"
  grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' all.js | sort -u | while read -r k; do
    echo "      $(printf '%s' "$k" | mask)"
    # JWT のペイロードを覗いて role を見る（値は出さない）
    payload="$(printf '%s' "$k" | cut -d. -f2)"
    pad=$(( 4 - ${#payload} % 4 )); [[ $pad -lt 4 ]] && payload="${payload}$(printf '=%.0s' $(seq $pad))"
    role="$(printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null | grep -oE '"role"[[:space:]]*:[[:space:]]*"[^"]+"' || true)"
    [[ -n "$role" ]] && echo "        → $role  ※ service_role 等の特権ロールならこの時点で最優先の指摘"
  done
  found=1
fi
# 各サービスの公開鍵・秘密鍵の典型パターン
for pat in 'sb_publishable_[A-Za-z0-9_-]{10,}' 'sb_secret_[A-Za-z0-9_-]{10,}' \
           'AIza[0-9A-Za-z_-]{20,}' 'pk_live_[0-9A-Za-z]{10,}' 'sk_live_[0-9A-Za-z]{10,}' \
           'AKIA[0-9A-Z]{16}' 'ghp_[0-9A-Za-z]{20,}' 'xox[baprs]-[0-9A-Za-z-]{10,}'; do
  if grep -qoE "$pat" all.js 2>/dev/null; then
    grep -oE "$pat" all.js | sort -u | while read -r k; do
      echo "    $(printf '%s' "$k" | mask)"
    done
    found=1
  fi
done
[[ $found -eq 0 ]] && echo "    （検出なし）"
echo "    ※ sk_live_ / AKIA / ghp_ / sb_secret_ / service_role はクライアントに出てはいけない種類"

echo "  --- API エンドポイント ---"
grep -ohE 'https://[a-z0-9.-]+\.(supabase\.co|firebaseio\.com|amazonaws\.com|googleapis\.com|appwrite\.io|pocketbase\.io)' all.js 2>/dev/null \
  | sort -u | sed 's/^/    /' || echo "    （検出なし）"

# --------------------------------------------------------------------------
# 外部送信規律・同意管理の検討に使う。通知・公表の対象になる送信先の一覧を作る。
hr "4. 第三者への送信先（外部送信規律・CMP の検討材料）"

# 収集した全ページから、自ドメイン以外のオリジンを抜き出す
grep -ohE '(src|href)="https?://[^"]+"' ./*.html 2>/dev/null \
  | sed -E 's/^(src|href)="//; s/"$//' \
  | sed -E 's#^(https?://[^/]+).*#\1#' \
  | grep -viE "://([a-z0-9-]+\.)?${DOMAIN//./\\.}(:[0-9]+)?$" \
  | sort | uniq -c | sort -rn > thirdparty.txt || true

if [[ -s thirdparty.txt ]]; then
  echo "  --- 読み込まれる第三者オリジン（件数付き） ---"
  sed 's/^/    /' thirdparty.txt
else
  echo "  （第三者オリジンの検出なし）"
fi

echo "  --- 計測・広告の既知タグ ---"
declare -a TAGS=(
  "googletagmanager.com:Google タグマネージャ"
  "google-analytics.com:Google アナリティクス"
  "analytics.google.com:Google アナリティクス"
  "pagead2.googlesyndication.com:Google AdSense"
  "googlesyndication.com:Google 広告"
  "doubleclick.net:Google 広告"
  "googleadservices.com:Google 広告"
  "connect.facebook.net:Meta ピクセル"
  "facebook.com/tr:Meta ピクセル"
  "clarity.ms:Microsoft Clarity"
  "hotjar.com:Hotjar"
  "analytics.tiktok.com:TikTok ピクセル"
  "snap.licdn.com:LinkedIn Insight"
  "static.ads-twitter.com:X 広告"
  "yahoo.co.jp/tag:Yahoo タグ"
  "sentry.io:Sentry"
  "intercom.io:Intercom"
)
found_tag=0
for entry in "${TAGS[@]}"; do
  host="${entry%%:*}"; label="${entry#*:}"
  if grep -qF "$host" ./*.html all.js 2>/dev/null; then
    printf '    [検出] %-34s %s\n' "$host" "$label"
    found_tag=1
  fi
done
[[ $found_tag -eq 0 ]] && echo "    （既知の計測・広告タグは検出されず）"

echo "  --- 同意管理（CMP）の実装 ---"
# 判定は自サイト配信ぶん（own.js）だけを見る。第三者スクリプトの中身で判定しない。
found_cmp=0
for c in "__tcfapi:IAB TCF の API" "cookiebot:Cookiebot" "onetrust:OneTrust" \
         "usercentrics:Usercentrics" "trustarc:TrustArc" "klaro:Klaro" "osano:Osano" \
         "cookieconsent:汎用の同意バナー" "gtag('consent':Google 同意モード" \
         'gtag("consent":Google 同意モード'; do
  key="${c%%:*}"; label="${c#*:}"
  if grep -qiF "$key" own.js 2>/dev/null; then
    printf '    [検出] %s\n' "$label"; found_cmp=1
  fi
done
if [[ $found_cmp -eq 0 ]]; then
  echo "    （自サイトの実装としては検出されず）"
  if [[ $found_tag -eq 1 ]]; then
    echo "    ※ 計測・広告タグがあるのに同意管理が無い。同意前に送信している可能性が高い"
    echo "      references/08-privacy-compliance.md の 2 節・3 節を参照"
  fi
fi
# 第三者スクリプトの側に痕跡がある場合は、誤読を防ぐため明示的に分けて書く
if grep -qiF '__tcfapi' all.js 2>/dev/null && [[ $found_cmp -eq 0 ]]; then
  echo "    参考: 第三者スクリプト側に __tcfapi の参照あり。これは広告スクリプトが"
  echo "          CMP の有無を調べるための処理で、CMP を実装している証拠にはならない"
fi

echo "  --- 管理画面・ログイン画面にもタグが入っているか ---"
ls ./*login*.html ./*admin*.html 2>/dev/null | sort -u | while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  hits="$(grep -oE '(googletagmanager|googlesyndication|google-analytics|doubleclick|connect\.facebook|clarity\.ms|hotjar)[a-z.]*' "$f" 2>/dev/null | sort -u | tr '\n' ' ')"
  [[ -n "$hits" ]] && printf '    %-34s %s\n' "$(basename "$f")" "$hits"
done
echo "    ※ 特権セッションを扱う画面に第三者スクリプトが同居していると、XSS が成立した"
echo "      ときの被害が広がる。references/07-web-vulnerabilities.md の 1-6 と併せて見る"

# --------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
  hr "5. 追加パスの HTTP ステータス"
  for p in "$@"; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$URL$p" 2>/dev/null || echo "---")"
    printf '  %-6s %s\n' "$code" "$p"
  done
  echo "  ※ 開発用ルートの期待値は 404 か 403。200 が返れば指摘"
fi

hr "完了"
echo "この出力をそのまま報告書に貼らないこと。次の 2 つが混ざっている。"
echo "  ・鍵の値（伏字にしてあるが、種類が分かれば十分。値は書かない）"
echo "  ・DMARC の rua に設定された連絡先（出力では伏せてあるが、生の dig の結果を貼らないこと）"
echo "報告書には「◯◯という種類の鍵が露出している」「DMARC は p=none」までに留める。"
