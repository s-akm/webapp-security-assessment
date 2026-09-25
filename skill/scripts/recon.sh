#!/usr/bin/env bash
# recon.sh — 本番サイトの外形調査を一括で取る（読み取り専用）
#
#   使い方: ./recon.sh https://example.com [追加パス...]
#
# 取得するもの:
#   1. HTTP セキュリティヘッダの実際の付与状況（リダイレクトを追った最終的な応答）、
#      外から見えてはいけないファイル、証明書
#   2. DNS レコード（SPF / DMARC / CAA / DNSSEC / MX / NS / MTA-STS）と送信ドメイン認証。
#      DMARC・CAA は親へ遡って探し、DS は SOA で求めたゾーンの頂点で引く。
#      SPF・配信用サブドメイン・DKIM は組織のドメインで引く
#   3. クライアント JS バンドル内の、鍵らしき文字列（LLM の鍵を含む）と API エンドポイント
#   4. 第三者への送信先、計測・広告タグ、同意管理の実装（外部送信規律・CMP の検討材料）
#   5. 追加パスを指定した場合、その HTTP ステータス（開発用ルートの確認など）
#
# 対象システムの状態は一切変更しない。GET と DNS 参照のみ。
# 検出した鍵の値は伏字で表示する。値そのものが必要な場合は取得したファイルを直接見る。
#
# 環境変数:
#   RECON_DNS          "サーバー:ポート"。DNS をそのサーバーに聞く（社内の権威サーバー、検査用の受け口）
#   RECON_DNS_TIMEOUT  dig の 1 回あたりの待ち時間（秒）。既定は 3（RECON_DNS を指定したときは 2）

set -uo pipefail

URL="${1:-}"
if [[ -z "$URL" ]]; then
  echo "使い方: $0 <https://example.com> [追加で叩くパス...]" >&2
  exit 1
fi
shift || true

URL="${URL%/}"
SCHEME="$(printf '%s' "$URL" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*)://.*$#\1#')"
HOSTPORT="$(printf '%s' "$URL" | sed -E 's#^https?://##; s#/.*$##')"
ORIGIN="${SCHEME}://${HOSTPORT}"
DOMAIN="$(printf '%s' "$HOSTPORT" | sed -E 's#:.*$##; s#\.$##')"
PORT_="$(printf '%s' "$HOSTPORT" | grep -oE ':[0-9]+$' | tr -d ':')"
[[ -z "$PORT_" ]] && PORT_=443
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# リダイレクトは追うが、回数に上限を置く（ループや遠回りで時間を使い切らない）
MAXREDIR=5

hr() { printf '\n=== %s ===\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
# DNS の問い合わせ
#
# dig +short は、応答が無いときも「;; connection timed out; no servers could be reached」を
# 標準出力に出す。そのまま使うと、この文言を値として「有」と誤判定する（実際に誤っていた）。
# +short を使わず、応答の状態（status:）と終了コードを見て、失敗を区別する。
#   dq <種別> <名前>   成功: 値を 1 行ずつ出して 0 を返す（無ければ何も出さない）
#                      失敗（無応答・SERVFAIL・REFUSED）: 何も出さずに 1 を返す
if [[ -n "${RECON_DNS:-}" ]]; then DNS_T="${RECON_DNS_TIMEOUT:-2}"; else DNS_T="${RECON_DNS_TIMEOUT:-3}"; fi
dig_() {
  if [[ -n "${RECON_DNS:-}" ]]; then
    dig +time="$DNS_T" +tries=1 "@${RECON_DNS%%:*}" -p "${RECON_DNS##*:}" "$@" 2>&1
  else
    dig +time="$DNS_T" +tries=1 "$@" 2>&1
  fi
}
dq() {
  local type="$1" name="$2" out
  out="$(dig_ +noall +comments +answer "$type" "$name")" || return 1
  # NXDOMAIN は「その名前が無い」ので失敗ではない。NOERROR と NXDOMAIN 以外は取得できていない
  printf '%s\n' "$out" | grep -E 'status: (NOERROR|NXDOMAIN),' >/dev/null || return 1
  # 回答部の行から値（5 列目以降）を取り出す。{n} の繰り返し指定は mawk で使えないため 4 回に分ける
  printf '%s\n' "$out" | grep -vE '^;|^[[:space:]]*$' | awk -v t="$type" '
    toupper($4) == toupper(t) { for (i = 1; i <= 4; i++) sub(/^[^\t ]+[\t ]+/, ""); print }'
  return 0
}

# 親へ遡って最初に見つかったレコードを返す。DMARC は受信側が組織のドメインまで遡り、
# CAA も認証局が親へ遡って確かめる。サブドメインの URL を渡されたときに、
# そのホスト名だけを引いて「無い」と言うと誤る（実際に誤っていた）。
#   up_find <種別> <接頭辞> <grep の条件>   → "見つかった名前<TAB>値" を 1 行
#   戻り値: 0 見つかった / 1 どの階層にも無い / 2 途中で応答が無く、無いとは言えない
up_find() {
  local type="$1" prefix="$2" pat="$3" d="$DOMAIN" v out
  while [[ "$d" == *.* ]]; do
    out="$(dq "$type" "$prefix$d")" || return 2
    # 大文字小文字を区別して照合する。DMARC の v=DMARC1 と MTA-STS の v=STSv1 は値が大小を区別する（RFC 9989 4.7）
    v="$(printf '%s\n' "$out" | tr -d '"' | grep -E "$pat" | tr '\n' ' ')"
    if [[ -n "$v" ]]; then printf '%s\t%s\n' "$prefix$d" "$v"; return 0; fi
    d="${d#*.}"
  done
  return 1
}

# DS はゾーンの頂点にしか無い。親へ遡ると、登録の区切り（co.uk など）の DS を拾って
# 「DNSSEC あり」と誤る。SOA の持ち主の名前でゾーンの頂点を求め、そこだけを引く。
# 応答が無ければ 1 を返す（頂点が分からない）。
zone_apex() {
  local out
  out="$(dig_ +noall +comments +answer +authority SOA "$DOMAIN")" || return 1
  printf '%s\n' "$out" | grep -E 'status: (NOERROR|NXDOMAIN),' >/dev/null || return 1
  printf '%s\n' "$out" | grep -v '^;' | awk '$4=="SOA"{print $1; exit}' | sed 's/\.$//'
}

# DMARC のタグの値を取る。p= を部分一致で見ると sp=none / np=none にも当たる（実際に誤っていた）。
# = の前後の空白を許し（RFC 9989 4.8）、タグ名と p / sp / np の値は大文字小文字を区別せずに読む。
# v の値（DMARC1）だけは大小を区別するので、レコードを探す側（up_find）で区別して照合する
dmarc_tag() { printf '%s' "$2" | tr ';' '\n' | tr -d ' \t' | tr 'A-Z' 'a-z' | grep -E "^$1=" | head -1 | cut -d= -f2-; }

NODNS="（取得できない。DNS が応答しない）"

# --------------------------------------------------------------------------
# HTTP の取得まわり

# 1 節で出すヘッダの伏字。Set-Cookie は値を落として名前と属性だけ残す。
# 判定に使う既知のヘッダはそのまま出し、それ以外で値の長いものは伏せる
# （内部のトークン、署名付き URL、利用者の識別子が任意のヘッダに載ることがある）。
# Location のクエリも伏せる（再設定・招待のトークンが載ることがある）。
mask_headers() {
  awk '
    BEGIN {
      n = split("strict-transport-security content-security-policy content-security-policy-report-only " \
                "x-frame-options x-content-type-options referrer-policy permissions-policy " \
                "cross-origin-opener-policy cross-origin-embedder-policy cross-origin-resource-policy " \
                "x-xss-protection x-powered-by server content-type content-length content-encoding " \
                "content-language cache-control pragma expires age vary via date connection keep-alive " \
                "transfer-encoding accept-ranges x-cache x-vercel-cache x-nextjs-cache cf-cache-status " \
                "access-control-allow-origin access-control-allow-credentials access-control-allow-methods " \
                "access-control-allow-headers", k, " ")
      for (i = 1; i <= n; i++) keep[k[i]] = 1
    }
    /^HTTP\// { print; next }
    {
      c = index($0, ":"); if (c == 0) { print; next }
      name = substr($0, 1, c - 1); val = substr($0, c + 1); sub(/^[ \t]+/, "", val)
      lname = tolower(name)
      if (lname == "set-cookie") {
        s = index(val, ";"); first = (s > 0) ? substr(val, 1, s - 1) : val; rest = (s > 0) ? substr(val, s) : ""
        e = index(first, "="); cname = (e > 0) ? substr(first, 1, e - 1) : first
        print name ": " cname "=<伏字>" rest
      } else if (lname == "location") {
        q = index(val, "?"); if (q > 0) val = substr(val, 1, q - 1) "?<伏字>"
        print name ": " val
      } else if ((lname in keep) || length(val) <= 40) {
        print name ": " val
      } else {
        print name ": <伏字（" length(val) " 文字）>"
      }
    }'
}

# 複数の応答（リダイレクトの各段）が続けて書かれたヘッダから、最後の応答だけを取る
last_block() { tr -d '\r' < "$1" | awk '/^HTTP\//{buf=""} {buf = buf $0 "\n"} END{printf "%s", buf}'; }

# URL のホスト名（ポートを除く、小文字）
host_of() { printf '%s\n' "$1" | sed -E 's#^[A-Za-z][A-Za-z0-9+.-]*://##; s#^//##; s#[/:?\#].*$##' | tr 'A-Z' 'a-z'; }
# URL のオリジン（スキーム + ホスト + ポート）
origin_of() { printf '%s\n' "$1" | sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://[^/?\#]+).*$#\1#'; }

# ページが参照する URL を、そのページの最終的な URL を基準に絶対 URL へ直す。
#   resolve <基準の URL> <参照>
# ./x.js や x.js のような相対パスも拾う（以前は "/" で始まるものしか拾っていなかった）。
# "../" は curl が送る前に畳むので、ここでは連結するだけでよい。
resolve() {
  local base="$1" ref="$2" b rest
  case "$ref" in
    http://*|https://*) printf '%s\n' "$ref" ;;
    //*)                printf '%s:%s\n' "${base%%://*}" "$ref" ;;
    data:*|javascript:*|blob:*|mailto:*) ;;
    /*)                 printf '%s%s\n' "$(origin_of "$base")" "$ref" ;;
    *)
      b="${base%%\?*}"; b="${b%%\#*}"
      rest="${b#*://}"; [[ "$rest" != */* ]] && b="$b/"
      printf '%s/%s\n' "${b%/*}" "${ref#./}" ;;
  esac
}

# src 属性の値（引用符は二重・一重の両方）
src_attrs() { grep -ohiE "src=[\"'][^\"'<> ]+[\"']" "$@" 2>/dev/null | sed -E "s/^[Ss][Rr][Cc]=[\"']//; s/[\"']$//"; }
# スクリプトとして読み込まれる参照（src と、preload などの href）。.js / .mjs で終わるもの
script_refs() {
  grep -ohiE "(src|href)=[\"'][^\"'<> ]+\.m?js([?#][^\"'<> ]*)?[\"']" "$1" 2>/dev/null \
    | sed -E "s/^[A-Za-z]+=[\"']//; s/[\"']$//"
}
# HTML のインラインスクリプトの中身（src の無い <script>）。タグの読み込みを書く定番の断片はここに入る
inline_scripts() {
  perl -0777 -ne 'while (/<script\b([^>]*)>(.*?)<\/script\s*>/gis) { print "$2\n" unless $1 =~ /\bsrc\s*=/i }' "$@" 2>/dev/null
}
# コードの中に書かれた URL のホスト名
url_hosts() { grep -ohE "(https?:)?//[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}" "$@" 2>/dev/null | sed -E 's#^(https?:)?//##' | tr 'A-Z' 'a-z'; }

# 自サイトかどうか。渡された URL のホスト、リダイレクト後の最終的なホスト、そのサブドメインを自サイトとみなす
FINAL_HOST="$DOMAIN"
is_own_host() {
  local h="$1"
  [[ "$h" == "$DOMAIN" || "$h" == "$FINAL_HOST" || "$h" == *".$DOMAIN" ]]
}

# 計測・広告の既知の送信先。「ラベル|ホスト名の正規表現（ERE）」。
# **browser_probe.mjs の TAGS と同じ内容に揃える**（tests/run.sh が一致を検査する）。
# ホスト名の末尾で照合する（端の指定が無いと hotjar.com.attacker.example にもラベルが付く）。
# ホスト名は各社の公式の CSP の設定例・送信先の一覧で確かめたもの（2026-09）。
TAGS=(
  'Google タグマネージャ|(^|\.)googletagmanager\.com$'
  'Google アナリティクス|(^|\.)(google-analytics\.com|analytics\.google\.com)$'
  'Google 広告|(^|\.)(googlesyndication\.com|doubleclick\.net|googleadservices\.com)$'
  'Meta ピクセル|(^|\.)connect\.facebook\.net$|^www\.facebook\.com$'
  'Microsoft Clarity|(^|\.)clarity\.ms$|^c\.bing\.com$'
  'Hotjar|(^|\.)hotjar\.(com|io)$'
  'TikTok ピクセル|^analytics\.tiktok\.com$'
  'LinkedIn Insight|^snap\.licdn\.com$'
  'X 広告|^static\.ads-twitter\.com$'
  'Yahoo! 広告|^s\.yimg\.jp$'
  'Sentry|(^|\.)(sentry\.io|sentry-cdn\.com)$'
  'Intercom|(^|\.)intercom\.io$'
  'LogRocket|(^|\.)(logrocket\.(io|com)|lr-ingest\.(io|com)|lr-in\.com|lr-in-prod\.com|ingest-lr\.com|lr-intake\.com|intake-lr\.com|logr-ingest\.com|lrkt-in\.com|lgrckt-in\.com|logr-in\.com)$'
  'FullStory|(^|\.)fullstory\.com$'
  'PostHog|(^|\.)posthog\.com$'
  'Datadog RUM|(^|\.)browser-intake-([a-z0-9]+-)?(datadoghq\.(com|eu)|ddog-gov\.com)$|^www\.datadoghq-browser-agent\.com$'
  'Mouseflow|(^|\.)mouseflow\.com$'
)
# ホスト名の一覧（1 行 1 件）に既知の送信先が含まれていれば "ラベル<TAB>該当ホスト" を出す
match_tags() {
  local hosts="$1" entry label re hit
  for entry in "${TAGS[@]}"; do
    label="${entry%%|*}"; re="${entry#*|}"
    hit="$(grep -E "$re" "$hosts" 2>/dev/null | sort -u | tr '\n' ' ')"
    [[ -n "$hit" ]] && printf '%s\t%s\n' "$label" "${hit% }"
  done
  return 0
}

# --------------------------------------------------------------------------
hr "対象"
echo "URL:    $URL"
echo "Domain: $DOMAIN"

# --------------------------------------------------------------------------
hr "1. HTTP レスポンスヘッダ（リダイレクトを追った最終的な応答）"
# 最初の取得で到達できるかを確かめる。到達できなければ、以降の HTTP の節は判定を出さずに飛ばす。
# 以前は失敗しても「[無] ヘッダ」「x-powered-by は出ていない」「検出なし」を出していた。
# 取れていないものを「無い」と書くと、確認していない項目が確認済みに見える。
# 到達しない IP では 1 本ごとに待ち時間を使い切り、合計で 4 分ほどかかっていた。最初の失敗で打ち切る。
REACH=1
: > "$WORK/hdr_all.txt"
meta="$(curl -sS -L --max-redirs "$MAXREDIR" --connect-timeout 10 --max-time 20 \
          -D "$WORK/hdr_all.txt" -o "$WORK/page_.html" \
          -w '%{http_code} %{num_redirects} %{url_effective}' "$URL" 2>"$WORK/curl_err.txt")" || REACH=0
code0="${meta%% *}"
[[ -z "$code0" || "$code0" == "000" ]] && REACH=0
if [[ $REACH -eq 0 ]]; then
  printf '  （取得できず: %s）\n' "$(head -1 "$WORK/curl_err.txt" 2>/dev/null | sed 's/^curl: //' | cut -c1-120)"
  echo "  以降の HTTP の節（1b〜1d・3・4・5）は取得できないため飛ばす。判定は出さない（「無い」という意味ではない）"
  rm -f "$WORK/page_.html"
else
  FINAL_URL="${meta#* }"; FINAL_URL="${FINAL_URL#* }"
  nredir="$(printf '%s' "$meta" | awk '{print $2}')"
  FINAL_HOST="$(host_of "$FINAL_URL")"
  if [[ "${nredir:-0}" -gt 0 ]]; then
    printf '  リダイレクト %s 回:\n' "$nredir"
    tr -d '\r' < "$WORK/hdr_all.txt" | awk '
      /^HTTP\// { st = $2 }
      tolower($0) ~ /^location:/ { v = $0; sub(/^[^:]*:[ \t]*/, "", v); q = index(v, "?"); if (q > 0) v = substr(v, 1, q - 1) "?<伏字>"; print "    " st " → " v }'
    printf '  最終的な URL: %s\n' "$(printf '%s' "$FINAL_URL" | sed -E 's/\?.*$/?<伏字>/')"
    echo "  （以下のヘッダと 3・4 節は、最終的な応答で判定する）"
  fi
  echo ""
  last_block "$WORK/hdr_all.txt" > "$WORK/hdr_final.txt"
  mask_headers < "$WORK/hdr_final.txt" | sed 's/^/  /'
  echo "  ※ Set-Cookie は値を伏せ、名前と属性だけを出す。判定に使わないヘッダで値の長いものは伏せる"
fi

if [[ $REACH -eq 1 ]]; then
  hr "1b. セキュリティヘッダの判定"
  HEADERS="$(cat "$WORK/hdr_final.txt")"
  for h in strict-transport-security content-security-policy x-frame-options \
           x-content-type-options referrer-policy permissions-policy; do
    line="$(printf '%s\n' "$HEADERS" | grep -i "^$h:" || true)"
    if [[ -n "$line" ]]; then printf '  [有] %s\n' "$line"; else printf '  [無] %s\n' "$h"; fi
  done
  if printf '%s\n' "$HEADERS" | grep -i '^x-powered-by:' >/dev/null; then
    printf '  [要確認] %s （実装情報が露出）\n' "$(printf '%s\n' "$HEADERS" | grep -i '^x-powered-by:')"
  else
    printf '  [良] x-powered-by は出ていない\n'
  fi

  hr "1c. 外から見えてはいけないもの（ステータスだけ。本文は保存しない）"
  # SPA は存在しないパスにもトップページを 200 で返すことがある。200 のときは先頭だけを見て判定し、
  # 値は出さない。HTML だと言い切るのは、HTML の書き出しがあるときだけにする（それ以外は要確認）。
  # 渡された URL にパスが付いていても、ここはサイトの根（オリジン）から引く。
  for p in /.git/HEAD /.env /.env.local /.env.production /.DS_Store /.well-known/security.txt; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 10 "$ORIGIN$p" 2>/dev/null)"
    note=""
    if [[ -z "$code" || "$code" == "000" ]]; then
      code="---"; note="（接続できない）"
    elif [[ "$code" == "200" ]]; then
      head_="$(curl -s --max-time 10 "$ORIGIN$p" 2>/dev/null | head -c 1024 | tr -d '\0')"
      is_html=""; printf '%s' "$head_" | grep -iE '<(!doctype|html|head|body)' >/dev/null && is_html=1
      case "$p" in
        /.git/HEAD)
          if printf '%s' "$head_" | grep -E '^(ref:|[0-9a-f]{40})' >/dev/null; then note="← 中身が返っている。最優先"
          elif [[ -n "$is_html" ]]; then note="（HTML が返っている。SPA の既定応答）"
          else note="（HTML ではない何かが返っている。要確認）"; fi ;;
        /.env*)
          if printf '%s\n' "$head_" | grep -vE '^[[:space:]]*#' | grep -E '^(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' >/dev/null; then note="← 中身が返っている。最優先"
          elif [[ -n "$is_html" ]]; then note="（HTML が返っている。SPA の既定応答）"
          else note="（HTML ではない何かが返っている。要確認）"; fi ;;
        /.well-known/security.txt)
          if printf '%s' "$head_" | grep -i '^contact:' >/dev/null; then note="（連絡窓口あり）"
          else note="（連絡窓口の書式ではない）"; fi ;;
        /.DS_Store)
          [[ -z "$is_html" ]] && note="← HTML ではない。ファイル一覧が露出している可能性" ;;
      esac
    elif [[ "$p" == "/.well-known/security.txt" ]]; then note="（連絡窓口が無い）"
    fi
    printf '  %-28s %s %s\n' "$p" "$code" "$note"
  done

  if [[ "$URL" == https://* ]] && have openssl; then
    hr "1d. 証明書"
    # 応答の無いサーバーでは s_client が戻らない。macOS には timeout が無いので perl の alarm で打ち切る
    cert="$(echo | perl -e 'alarm 15; exec @ARGV' openssl s_client -connect "$DOMAIN:$PORT_" -servername "$DOMAIN" 2>/dev/null \
      | openssl x509 -noout -issuer -enddate 2>/dev/null)"
    if [[ -n "$cert" ]]; then printf '%s\n' "$cert" | sed 's/^/  /'; else echo "  (取得失敗)"; fi
    echo "  ※ 最長の有効期間は 2026-03 から 200 日、2027-03 から 100 日に縮む。手動更新なら運用を聞く"
  fi
fi

# --------------------------------------------------------------------------
if [[ "$DOMAIN" =~ ^[0-9.]+$ || "$DOMAIN" == *:* ]]; then
  hr "2. DNS レコード"
  echo "  IP アドレスが渡されたため省略（ドメイン名で呼ぶと DNS まで見る）"
elif ! have dig; then
  hr "2. DNS レコード"
  echo "  dig が見つからないため省略（dnsutils / bind-utils を入れると取得できる）"
else
  hr "2. DNS レコード"
  # 最初の問い合わせに応答が無ければ、以降も応答しないとみなして打ち切る。
  # 1 件ごとに待ち時間を使い切ると、DNS が応答しないだけで 1 分半ほどかかっていた。
  DNS_DEAD=0
  if ns="$(dq NS "$DOMAIN")"; then
    printf '  NS     : %s\n' "$(printf '%s' "$ns" | tr '\n' ' ')"
  else
    DNS_DEAD=1
    printf '  DNS が応答しない（%s）。2・2b・2c 節は取得できない。\n' "${RECON_DNS:-OS の設定のサーバー}"
    echo "  「無」という意味ではない。時間を置くか、RECON_DNS で別のサーバーを指定して取り直す"
  fi

  if [[ $DNS_DEAD -eq 0 ]]; then
    for t in A AAAA MX; do
      if v="$(dq "$t" "$DOMAIN")"; then printf '  %-7s: %s\n' "$t" "$(printf '%s' "$v" | tr '\n' ' ')"
      else printf '  %-7s: %s\n' "$t" "$NODNS"; fi
    done
    # CAA は親へ遡る。見つかった階層も出す（サブドメインを渡されたときの誤判定を避ける）
    r="$(up_find CAA '' '.')"; rc=$?
    case $rc in
      0) printf '  CAA    : %s （%s で発見）\n' "${r#*$'\t'}" "${r%%$'\t'*}" ;;
      1) printf '  CAA    : \n' ;;
      *) printf '  CAA    : %s\n' "$NODNS" ;;
    esac
    APEX_OK=1
    APEX="$(zone_apex)" || APEX_OK=0
    [[ -z "$APEX" ]] && APEX="$DOMAIN"
    if [[ $APEX_OK -eq 0 ]]; then
      printf '  DS     : %s（SOA が取れず、ゾーンの頂点が分からない）\n' "$NODNS"
    elif ds="$(dq DS "$APEX")"; then
      ds="$(printf '%s' "$ds" | tr '\n' ' ')"
      if [[ -n "$ds" ]]; then printf '  DS     : %s （ゾーンの頂点 %s）\n' "$ds" "$APEX"
      else printf '  DS     : （ゾーンの頂点 %s）\n' "$APEX"; fi
    else
      printf '  DS     : %s（ゾーンの頂点 %s）\n' "$NODNS" "$APEX"
    fi

    hr "2b. 送信ドメイン認証"
    DMARC=""; DMARC_AT=""
    r="$(up_find TXT '_dmarc.' '^v=DMARC1')"; DMARC_RC=$?
    if [[ $DMARC_RC -eq 0 ]]; then DMARC="${r#*$'\t'}"; DMARC="${DMARC% }"; DMARC_AT="${r%%$'\t'*}"; fi

    # SPF・配信用サブドメイン・DKIM は、URL のホスト名（www.… や app.…）ではなく組織のドメインで引く。
    # メールはふつう組織のドメインから送るので、ホスト名だけを引くと「SPF が無い」と誤る（実際に誤っていた）。
    # 組織のドメインは、DMARC を見つけた階層、無ければ SOA で求めたゾーンの頂点とする。
    if [[ -n "$DMARC_AT" ]]; then ORG="${DMARC_AT#_dmarc.}"; ORG_WHY="DMARC を見つけた階層"
    elif [[ $APEX_OK -eq 1 ]]; then ORG="$APEX"; ORG_WHY="SOA で求めたゾーンの頂点"
    else ORG="$DOMAIN"; ORG_WHY="頂点が分からないためホスト名のまま"; fi
    printf '  組織のドメイン: %s（%s）\n' "$ORG" "$ORG_WHY"

    spf_line() {  # spf_line <名前> <説明>
      local v
      if v="$(dq TXT "$1")"; then
        v="$(printf '%s\n' "$v" | tr -d '"' | grep -i '^v=spf1')"
        if [[ -n "$v" ]]; then printf '  [有] SPF（%s）: %s\n' "$2" "$v"
        else printf '  [無] SPF（%s に SPF レコードが無い）\n' "$2"; fi
      else
        printf '  [?]  SPF（%s）: %s\n' "$2" "$NODNS"
      fi
    }
    spf_line "$ORG" "組織のドメイン $ORG"
    if [[ "$ORG" != "$DOMAIN" ]]; then
      spf_line "$DOMAIN" "ホスト名 $DOMAIN"
      echo "        （ホスト名の結果は、そのホスト名を送信元に使う場合だけ意味を持つ）"
    fi

    # 同じ名前に DMARC のレコードが 2 本以上あると、その名前のレコードはすべて捨てられる（RFC 9989 4.10）
    n_dmarc="$(printf '%s' "$DMARC" | grep -oE 'v=DMARC1' | wc -l | tr -d ' ')"
    if [[ -n "$DMARC" ]]; then
      # rua / ruf に入っている連絡先は、DNS 上は公開情報だが報告書には要らない。
      # 出力の時点で伏せる。末尾の注意書きだけでは、貼り付けたときに残る。
      printf '  [有] DMARC : %s\n' "$(printf '%s' "$DMARC" | sed -E 's/mailto:[^,;[:space:]]+/mailto:<伏字>/g')"
      [[ "$DMARC_AT" != "_dmarc.$DOMAIN" ]] && printf '        （%s で発見。親ドメインの設定が適用される）\n' "$DMARC_AT"
      dp="$(dmarc_tag p "$DMARC")"; dsp="$(dmarc_tag sp "$DMARC")"; dnp="$(dmarc_tag np "$DMARC")"
      if [[ "$n_dmarc" -gt 1 ]]; then
        printf '        → ★ DMARC のレコードが %s 本ある。同じ名前に複数あると受信側はすべて捨てる（上位のドメインにあればそちらが使われる）\n' "$n_dmarc"
      fi
      case "$dp" in
        none)              printf '        → p=none。監視のみで隔離・拒否をしない（到達性の要件は満たすが、なりすましは止めない）\n' ;;
        quarantine|reject) printf '        → p=%s\n' "$dp" ;;
        *)                 printf '        → p の値が読めない（%s）\n' "${dp:-なし}" ;;
      esac
      # 親で見つけたとき、このホストに効くのは sp=（無ければ p=）
      if [[ "$DMARC_AT" != "_dmarc.$DOMAIN" ]]; then
        eff="${dsp:-$dp}"
        if [[ "$eff" == "none" ]]; then
          printf '        → このホストに効くのは %s=none。サブドメインは監視のみ\n' "$([[ -n "$dsp" ]] && echo sp || echo p)"
        else
          printf '        → このホストに効くのは %s=%s\n' "$([[ -n "$dsp" ]] && echo sp || echo p)" "${eff:-（読めない）}"
        fi
      elif [[ "$dsp" == "none" ]]; then
        printf '        → sp=none。サブドメインは監視のみ\n'
      fi
      [[ "$dnp" == "none" ]] && printf '        → np=none。存在しないサブドメインは監視のみ\n'
      [[ "$(dmarc_tag t "$DMARC")" == "y" ]] && printf '        → t=y。テストモード（受信側は指定より 1 段緩いポリシーで扱う）\n'
      [[ -z "$(dmarc_tag rua "$DMARC")" ]] && printf '        → rua が無い。集計レポートを受け取っていない\n'
    elif [[ $DMARC_RC -eq 1 ]]; then
      printf '  [無] DMARC\n'
    else
      printf '  [?]  DMARC : %s\n' "$NODNS"
    fi

    r="$(up_find TXT '_mta-sts.' '^v=STSv1')"; rc=$?
    case $rc in
      0) printf '  [有] MTA-STS : %s （%s）\n' "${r#*$'\t'}" "${r%%$'\t'*}" ;;
      1) printf '  [無] MTA-STS\n' ;;
      *) printf '  [?]  MTA-STS : %s\n' "$NODNS" ;;
    esac
    r="$(up_find TXT '_smtp._tls.' '^v=TLSRPTv1')"; rc=$?
    case $rc in
      0) printf '  [有] TLS-RPT : %s （%s）\n' "$(printf '%s' "${r#*$'\t'}" | sed -E 's/mailto:[^,;[:space:]]+/mailto:<伏字>/g')" "${r%%$'\t'*}" ;;
      1) printf '  [無] TLS-RPT\n' ;;
      *) printf '  [?]  TLS-RPT : %s\n' "$NODNS" ;;
    esac

    hr "2c. 配信サービス用サブドメイン（組織のドメイン ${ORG} で、よくある名前を総当たり）"
    # 途中で応答が無くなったら打ち切る。残りを 1 件ずつ待つと時間だけかかり、結果は同じく「取得できない」
    for sub in send mail email smtp mg em bounce news; do
      if ! s_txt="$(dq TXT "$sub.$ORG")" || ! s_mx="$(dq MX "$sub.$ORG")"; then
        printf '  %s.%s 以降: %s\n' "$sub" "$ORG" "$NODNS"
        break
      fi
      s_txt="$(printf '%s\n' "$s_txt" | tr -d '"' | grep -i '^v=spf1')"
      s_mx="$(printf '%s' "$s_mx" | tr '\n' ' ')"
      if [[ -n "$s_txt$s_mx" ]]; then
        printf '  %s.%s\n' "$sub" "$ORG"
        [[ -n "$s_txt" ]] && printf '    SPF: %s\n' "$s_txt"
        [[ -n "$s_mx"  ]] && printf '    MX : %s\n' "$s_mx"
      fi
    done
    printf '  DKIM セレクタ（%s）:\n' "$ORG"
    for sel in resend sendgrid mandrill google s1 s2 k1 default selector1 selector2 mail smtp; do
      if ! d="$(dq TXT "$sel._domainkey.$ORG")"; then
        printf '    %s._domainkey 以降: %s\n' "$sel" "$NODNS"
        break
      fi
      [[ -n "$d" ]] && printf '    [有] %s._domainkey\n' "$sel"
    done
  fi
fi

# --------------------------------------------------------------------------
if [[ $REACH -eq 1 ]]; then
hr "3. クライアント JS バンドル内の鍵とエンドポイント"
cd "$WORK" || exit 1

# トップページ（渡された URL。1 節で取得済み）と、認証系ページの HTML を集める（ログイン画面に鍵が出ることが多い）。
# 認証系ページはサイトの根から引く。どれもリダイレクトを追い、最終的な URL を控える（相対パスの基準になる）。
printf 'page_.html\t%s\n' "$FINAL_URL" > pages.tsv
for p in /login /signin /sign-in /admin/login /auth/login; do
  f="page$(printf '%s' "$p" | tr '/' '_').html"
  eff="$(curl -sS -L --max-redirs "$MAXREDIR" --connect-timeout 10 --max-time 15 -o "$f" -w '%{url_effective}' "$ORIGIN$p" 2>/dev/null)" || true
  [[ -s "$f" ]] && printf '%s\t%s\n' "$f" "${eff:-$ORIGIN$p}" >> pages.tsv
done

# HTML から参照されているスクリプトを集める。二重・一重の引用符、絶対・プロトコル相対・
# ルート相対・相対（./x.js、x.js）のすべてを、そのページの最終的な URL を基準に絶対 URL へ直す。
: > chunks.txt
while IFS=$'\t' read -r f base; do
  script_refs "$f" | while IFS= read -r ref; do resolve "$base" "$ref"; done >> chunks.txt
done < pages.tsv
sort -u chunks.txt -o chunks.txt

# all.js  … 第三者のスクリプトも含めた全部（鍵の露出を探す用）
# own.js  … 自サイト配信ぶんだけ（自前の実装かどうかを判定する用）
#
# この 2 つを分けるのは重要。たとえば広告スクリプトは、CMP の有無を調べるために
# __tcfapi を参照する。セッションリプレイの SDK は、他社のツールの送信先を中に持っている。
# 全部を一緒に grep すると「CMP を実装している」「計測タグが 9 種ある」と誤判定する（実際に誤っていた）。
#
# 第三者（CDN など）の JS も取得する。第三者の SDK やタグの設定に、利用者側の鍵を埋め込んで
# 配る構成があるため。取得は GET だけで、**対象ページ自身が読み込んでいるスクリプトに限る**
# （ページに書かれていない URL を推測して取りに行かない）。ブラウザで開いたときに起きる取得と
# 同じ範囲で、Referer や Cookie は送らない。
: > all.js; : > own_only.js
while IFS= read -r c; do
  [[ -z "$c" ]] && continue
  if is_own_host "$(host_of "$c")"; then
    curl -sS -L --max-redirs "$MAXREDIR" --connect-timeout 10 --max-time 15 "$c" 2>/dev/null | tee -a own_only.js >> all.js || true
  else
    curl -sS -L --max-redirs "$MAXREDIR" --connect-timeout 10 --max-time 15 "$c" >> all.js 2>/dev/null || true
  fi
done < chunks.txt
cat ./*.html >> all.js 2>/dev/null || true
cat own_only.js ./*.html > own.js 2>/dev/null || true

echo "  収集: HTML $(ls -1 ./*.html 2>/dev/null | wc -l | tr -d ' ') 件 / JS $(wc -l < chunks.txt 2>/dev/null | tr -d ' ') 件 / 合計 $(wc -c < all.js 2>/dev/null | tr -d ' ') bytes"

mask() { sed -E 's/(.{10}).*/\1…（以降は伏字）/'; }

echo "  --- 鍵らしき文字列 ---"
found=0
# JWT 形式
if grep -oE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' all.js >/dev/null 2>&1; then
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

# LLM の鍵。ブラウザに出ていれば、誰でも依頼者の費用で API を呼べる（スキルが最優先に置く指摘。
# references/12-ai-features.md）。値は他の鍵と同じく伏字にする。
#   "サービス名|正規表現"
LLM_KEYS=(
  'OpenAI|sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{20,}'
  'OpenAI（旧形式）|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'
  'Anthropic|sk-ant-[a-z]+[0-9]{2}-[A-Za-z0-9_-]{20,}'
  'OpenRouter|sk-or-v1-[A-Za-z0-9]{20,}'
  'Groq|gsk_[A-Za-z0-9]{20,}'
  'xAI|xai-[A-Za-z0-9]{20,}'
  'Hugging Face|hf_[A-Za-z0-9]{30,}'
  'Replicate|r8_[A-Za-z0-9]{30,}'
  'Perplexity|pplx-[A-Za-z0-9]{30,}'
)
for entry in "${LLM_KEYS[@]}"; do
  label="${entry%%|*}"; pat="${entry#*|}"
  if grep -oE "$pat" all.js >/dev/null 2>&1; then
    grep -oE "$pat" all.js | sort -u | while read -r k; do
      echo "    ★ LLM の鍵（${label}）: $(printf '%s' "$k" | mask)"
    done
    found=1
  fi
done

# 各サービスの公開鍵・秘密鍵の典型パターン
for pat in 'sb_publishable_[A-Za-z0-9_-]{10,}' 'sb_secret_[A-Za-z0-9_-]{10,}' \
           'AIza[0-9A-Za-z_-]{20,}' 'pk_live_[0-9A-Za-z]{10,}' 'sk_live_[0-9A-Za-z]{10,}' \
           'rk_live_[0-9A-Za-z]{10,}' 'AKIA[0-9A-Z]{16}' 'ghp_[0-9A-Za-z]{20,}' \
           'github_pat_[0-9A-Za-z_]{20,}' 'xox[baprs]-[0-9A-Za-z-]{10,}'; do
  if grep -oE "$pat" all.js >/dev/null 2>&1; then
    grep -oE "$pat" all.js | sort -u | while read -r k; do
      echo "    $(printf '%s' "$k" | mask)"
    done
    found=1
  fi
done
[[ $found -eq 0 ]] && echo "    （検出なし）"
echo "    ※ LLM の鍵（★）、sk_live_ / rk_live_ / AKIA / ghp_ / github_pat_ / sb_secret_ / service_role は"
echo "      クライアントに出てはいけない種類。AIza は Gemini API が有効なプロジェクトなら LLM の鍵として働く"

echo "  --- API エンドポイント ---"
ep="$(grep -ohE 'https://[a-z0-9.-]+\.(supabase\.co|firebaseio\.com|amazonaws\.com|googleapis\.com|appwrite\.io|pocketbase\.io)' all.js 2>/dev/null | sort -u)"
if [[ -n "$ep" ]]; then printf '%s\n' "$ep" | sed 's/^/    /'; else echo "    （検出なし）"; fi

# --------------------------------------------------------------------------
# 外部送信規律・同意管理の検討に使う。通知・公表の対象になる送信先の一覧を作る。
hr "4. 第三者への送信先（外部送信規律・CMP の検討材料）"

# 収集した全ページの src / href から、自サイト以外のオリジンを抜き出す（引用符は二重・一重の両方）
: > refs_all.txt
while IFS=$'\t' read -r f base; do
  grep -ohiE "(src|href)=[\"'][^\"'<> ]+[\"']" "$f" 2>/dev/null \
    | sed -E "s/^[A-Za-z]+=[\"']//; s/[\"']$//" \
    | while IFS= read -r ref; do resolve "$base" "$ref"; done >> refs_all.txt
done < pages.tsv
: > thirdparty_raw.txt
while IFS= read -r u; do
  case "$u" in http://*|https://*) ;; *) continue ;; esac
  is_own_host "$(host_of "$u")" || origin_of "$u" >> thirdparty_raw.txt
done < refs_all.txt
sort thirdparty_raw.txt | uniq -c | sort -rn > thirdparty.txt

if [[ -s thirdparty.txt ]]; then
  echo "  --- 読み込まれる第三者オリジン（件数付き） ---"
  sed 's/^/    /' thirdparty.txt
else
  echo "  （第三者オリジンの検出なし）"
fi

echo "  --- 計測・広告の既知タグ ---"
# 判定は、HTML の src 属性と、自サイトが配信するコード（自前の JS とインラインスクリプト）に
# 書かれた送信先だけで行う。第三者スクリプトの中身は見ない（CMP の判定と同じ理由）。
# 以前は第三者スクリプトの中身まで見ていて、LogRocket と PostHog を置いただけで 9 種が検出になっていた。
: > tag_hosts.txt
while IFS=$'\t' read -r f base; do
  src_attrs "$f" | while IFS= read -r ref; do resolve "$base" "$ref"; done \
    | while IFS= read -r u; do host_of "$u"; done >> tag_hosts.txt
done < pages.tsv
{ inline_scripts ./*.html > inline.js; url_hosts inline.js; } >> tag_hosts.txt
url_hosts own_only.js >> tag_hosts.txt
sort -u tag_hosts.txt | sed '/^$/d' > tag_hosts_u.txt
match_tags tag_hosts_u.txt > tags_found.txt
found_tag=0
if [[ -s tags_found.txt ]]; then
  found_tag=1
  while IFS=$'\t' read -r label hosts; do
    printf '    [検出] %-20s %s\n' "$label" "$hosts"
  done < tags_found.txt
else
  echo "    （既知の計測・広告タグは検出されず）"
fi
echo "    ※ タグマネージャの中身（コンテナが読み込む先）はここに出ない。実際の送信先は browser_probe.mjs で見る"

echo "  --- 同意管理（CMP）の実装 ---"
# 判定は自サイト配信ぶん（own.js）だけを見る。第三者スクリプトの中身で判定しない。
found_cmp=0
for c in "__tcfapi:IAB TCF の API" "cookiebot:Cookiebot" "onetrust:OneTrust" \
         "usercentrics:Usercentrics" "trustarc:TrustArc" "klaro:Klaro" "osano:Osano" \
         "cookieconsent:汎用の同意バナー" "gtag('consent':Google 同意モード" \
         'gtag("consent":Google 同意モード'; do
  key="${c%%:*}"; label="${c#*:}"
  if grep -iF "$key" own.js >/dev/null 2>&1; then
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
if grep -iF '__tcfapi' all.js >/dev/null 2>&1 && [[ $found_cmp -eq 0 ]]; then
  echo "    参考: 第三者スクリプト側に __tcfapi の参照あり。これは広告スクリプトが"
  echo "          CMP の有無を調べるための処理で、CMP を実装している証拠にはならない"
fi

echo "  --- 管理画面・ログイン画面にもタグが入っているか ---"
for f in ./*login*.html ./*admin*.html; do
  [[ -f "$f" ]] || continue
  base="$(awk -F'\t' -v f="$(basename "$f")" '$1==f{print $2; exit}' pages.tsv)"
  { src_attrs "$f" | while IFS= read -r ref; do resolve "${base:-$ORIGIN/}" "$ref"; done \
      | while IFS= read -r u; do host_of "$u"; done
    inline_scripts "$f" > inline_one.js; url_hosts inline_one.js; } | sort -u | sed '/^$/d' > one_hosts.txt
  hits="$(match_tags one_hosts.txt | cut -f1 | tr '\n' ' ')"
  [[ -n "$hits" ]] && printf '    %-34s %s\n' "$(basename "$f")" "$hits"
done
echo "    ※ 特権セッションを扱う画面に第三者スクリプトが同居していると、XSS が成立した"
echo "      ときの被害が広がる。references/07-web-vulnerabilities.md の 1-6 と併せて見る"

# --------------------------------------------------------------------------
if [[ $# -gt 0 ]]; then
  hr "5. 追加パスの HTTP ステータス"
  # サイトの根（オリジン）からのパスとして引く。リダイレクトは追わない（3xx そのものが判定材料になる）
  for p in "$@"; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 --max-time 15 "$ORIGIN$p" 2>/dev/null || echo "---")"
    printf '  %-6s %s\n' "$code" "$p"
  done
  echo "  ※ 開発用ルートの期待値は 404 か 403。200 が返れば指摘"
fi
fi  # REACH

hr "完了"
echo "この出力をそのまま報告書に貼らないこと。次の 2 つが混ざっている。"
echo "  ・鍵の値（伏字にしてあるが、種類が分かれば十分。値は書かない）"
echo "  ・DMARC の rua に設定された連絡先（出力では伏せてあるが、生の dig の結果を貼らないこと）"
echo "報告書には「◯◯という種類の鍵が露出している」「DMARC は p=none」までに留める。"
