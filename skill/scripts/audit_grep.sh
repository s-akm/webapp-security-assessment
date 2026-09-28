#!/usr/bin/env bash
# audit_grep.sh — コード監査の機械的な下拵え（読み取り専用）
#
#   使い方: ./audit_grep.sh [リポジトリのパス]   （省略時はカレント）
#
# 出すもの:
#   1. 規模（ハンドラの本数、コミット数）
#   2. ハンドラ × 認可ガードの一覧      ← 空欄が指摘の候補
#   3. 危険な関数の使用箇所
#   4. 秘密情報のハードコードと、クライアント露出の疑い
#   5. fail-open な既定値
#   6. 開発用の抜け道
#   7. git 履歴中の鍵らしき文字列
#   8. コードが参照するテーブル名（スキーマ定義との突合用）
#   ほかに、枠組みの版（1b）、LLM の鍵の露出（4d）、サーバー側のセッション検証（10b）、
#   構成に応じて BaaS の設定（19）、CI の定義（20）、インストール時の防御（21）、
#   AI エージェントの設定ファイル（22）、リアルタイム通信（23）、SMS の送信経路（24）。
#   画面操作の記録（9b）は、ツールがあるときだけ出す
#
# grep は当たりを付けるための道具であって、判定するものではない。
# ここで挙がった箇所は必ず目で読んでから起票する。逆に、ここに挙がらなくても
# 問題があることは普通にある。

set -uo pipefail

# 出力全体を 1 か所で伏字にし、1 行の長さに上限を付ける。節ごとに mask を通し忘れると値がそのまま出る
# （実際に 2b・6・9・9b・10b・20 節で出ていた）。minify された JS の 1 行（十数万文字）も、ここで切る。
# 自分自身を内側で動かし、その出力を通す。bash 3.2 でも動く形にする。
if [[ -z "${AUDIT_GREP_INNER:-}" ]]; then
  out_filter() {
    # 伏字（鍵の形式・URL の認証情報・Bearer・curl -u）。バイト単位で読む（壊れた文字で sed が止まらないように）。
    # 繰り返しの回数は 255 以下にする（BSD の sed の上限。400 と書くと止まる）
    LC_ALL=C sed -E \
      -e 's/(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_.-]{20,}/\1…<JWT・伏字>/g' \
      -e 's/((AKIA|ASIA)[0-9A-Z]{4})[0-9A-Z]{8,}/\1…<伏字>/g' \
      -e 's/(((sk|pk|rk)_(live|test)|whsec)_[0-9A-Za-z]{4})[0-9A-Za-z]{8,}/\1…<伏字>/g' \
      -e 's/(github_pat_[0-9A-Za-z]{4})[0-9A-Za-z_]{8,}/\1…<伏字>/g' \
      -e 's/(gh[pousr]_[0-9A-Za-z]{4})[0-9A-Za-z]{8,}/\1…<伏字>/g' \
      -e 's/(npm_[0-9A-Za-z]{4})[0-9A-Za-z]{8,}/\1…<伏字>/g' \
      -e 's/(sb_(secret|publishable)_[0-9A-Za-z]{4})[0-9A-Za-z_-]{8,}/\1…<伏字>/g' \
      -e 's/(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]{8,}/\1…<伏字>/g' \
      -e 's/(^|[^A-Za-z0-9])(sk-(proj-|ant-(api|admin)[0-9]*-)?[A-Za-z0-9]{4})[A-Za-z0-9_-]{8,}/\1\2…<伏字>/g' \
      -e 's/((AC|SK)[0-9a-f]{4})[0-9a-f]{28}/\1…<伏字>/g' \
      -e 's/(xox[abprs]-[0-9A-Za-z]{2}|xapp-[0-9]-)[0-9A-Za-z-]{8,}/\1…<伏字>/g' \
      -e 's/(SG\.[0-9A-Za-z_-]{4})[0-9A-Za-z_.-]{20,}/\1…<伏字>/g' \
      -e 's#(hooks\.slack\.com/services/)[0-9A-Za-z/]+#\1<伏字>#g' \
      -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]{8,}/\1<伏字>/g' \
      -e 's/(-u[[:space:]]+)[^[:space:]:]+:[^[:space:]]+/\1<伏字>/g' \
      -e 's#://[^/@[:space:]"'"'"']+@#://<伏字>@#g' \
      -e 's/(-----BEGIN [A-Z ]*PRIVATE KEY-----).*/\1 <伏字>/' \
    | LC_ALL=C sed -E 's/^(.{250}.{150}).{20,}$/\1 …（長い行を省略）/' \
    | { if command -v iconv >/dev/null 2>&1; then iconv -c -f UTF-8 -t UTF-8 2>/dev/null; else cat; fi; }
  }
  # ★ の一覧。節の途中に散らばった ★ を最後に集めて出す。★ は「ほぼ確実に指摘になるもの」だが、
  # 節の中に埋もれると読み流される（実地の評価で、2b 節の ★ の /metrics が 2 回続けて台帳に載らなかった）。
  # 説明文の中の ★（「★ は、…」「※ ★ が無くても…」）は数えない
  star_list() {
    LC_ALL=C awk '
      /^=== / { sec = $2; next }
      index($0, "★") && $0 !~ /※/ && $0 !~ /★ (の|が|は|を)/ {
        l = $0; sub(/^[ \t]+/, "", l); n++; item[n] = "  [" sec "] " l
      }
      END {
        printf "\n=== ★ の一覧（%d 件。1 件ずつ判定して台帳に残す） ===\n", n
        if (n == 0) print "  （なし）"
        for (i = 1; i <= n; i++) print item[i]
        print "  ※ 問題あり・問題なし・判断保留のどれかにし、問題なしも理由を「確認の方法」に書く。"
        print "    同じ原因のものは 1 件にまとめてよいが場所を全部並べ、原因の違うものはまとめない（SKILL.md の「スクリプト」）"
      }'
  }
  ALL_OUT="$(mktemp "${TMPDIR:-/tmp}/audit_grep_all.XXXXXX")"
  AUDIT_GREP_INNER=1 bash "$0" "$@" 2>&1 | out_filter | tee "$ALL_OUT"
  st="${PIPESTATUS[0]}"
  [[ "$st" -eq 0 ]] && star_list < "$ALL_OUT"
  rm -f "$ALL_OUT"
  exit "$st"
fi

REPO="${1:-.}"
cd "$REPO" || { echo "パスが開けない: $REPO" >&2; exit 1; }

# -I はバイナリを読み飛ばす。画像や PDF が「HTML を直接流し込む」に当たって並ぶのを防ぐ。
# 依存・生成物・ビルドの出力は読まない。遅くなるうえに、他人のコードが指摘の候補に並ぶ。
EX='-I --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build
    --exclude-dir=.next --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv
    --exclude-dir=__pycache__ --exclude-dir=coverage --exclude-dir=.turbo
    --exclude-dir=.nuxt --exclude-dir=.output --exclude-dir=.svelte-kit --exclude-dir=.vercel
    --exclude-dir=.build --exclude-dir=DerivedData --exclude-dir=Pods --exclude-dir=.gradle
    --exclude-dir=target --exclude=*.min.js --exclude=*.map'
# 単語に分けるだけで、*.min.js をファイル名に展開させない
set -f
# shellcheck disable=SC2206
EXA=($EX)
set +f
# find で辿らないディレクトリ（EX と同じもの）
PRUNE_DIRS='node_modules .git dist build .next vendor venv .venv __pycache__ coverage .turbo .nuxt .output .svelte-kit .vercel .build DerivedData Pods .gradle target'
prune_expr() { local d first=1; printf '( -type d ( '; for d in $PRUNE_DIRS; do
  if [[ $first -eq 1 ]]; then first=0; else printf -- '-o '; fi; printf -- '-name %s ' "$d"; done; printf ') -prune )'; }

# 表示のための切り捨て。切ったときは切ったことと残りの件数を出す（黙って切ると「無い」と読まれる）
lim() { awk -v n="$1" 'NR <= n { print } END { if (NR > n) printf "  （ほか %d 件。全部は元のコマンドを直接実行して見る）\n", NR - n }'; }

hr() { printf '\n=== %s ===\n' "$1"; }
show() { local out; out="$(cat)"; if [[ -n "$out" ]]; then printf '%s\n' "$out"; else echo "  （検出なし）"; fi; }

# 検出した秘密情報の値そのものは出力しない。
# 「どのファイルの何行目に、どの名前で存在するか」までが分かれば起票できる。
# 値が要るときは、この出力ではなく元ファイルを直接開く。
mask_keys() {
  sed -E \
    -e 's/(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_.-]+/\1…<JWT・伏字>/g' \
    -e 's/(AKIA[0-9A-Z]{4})[0-9A-Z]+/\1…<伏字>/g' \
    -e 's/((sk|pk)_live_[0-9A-Za-z]{4})[0-9A-Za-z]+/\1…<伏字>/g' \
    -e 's/(ghp_[0-9A-Za-z]{4})[0-9A-Za-z]+/\1…<伏字>/g' \
    -e 's/(sb_(secret|publishable)_[0-9A-Za-z]{4})[0-9A-Za-z_-]+/\1…<伏字>/g' \
    -e 's/(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]+/\1…<伏字>/g' \
    -e 's/((sk|rk)-(proj-|ant-(api|admin)[0-9]*-)?[A-Za-z0-9]{4})[A-Za-z0-9_-]{8,}/\1…<伏字>/g' \
    -e 's/(gh[pousr]_[0-9A-Za-z]{4})[0-9A-Za-z]{8,}/\1…<伏字>/g' \
    -e 's#://[^/@[:space:]"'"'"']+@#://<伏字>@#g' \
    -e 's/([A-Za-z_]*(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z_]*)[[:space:]]*=[[:space:]]*[^[:space:]"'"'"'`]{8,}/\1=<値は伏字>/g' \
    | cut -c1-200
}
# 設定ファイルの行のように、値ではない文字列（設定名・パッケージ名）が引用符に入る出力には mask_keys を使う。
# mask は引用符の中の長い値をすべて伏せるので、設定名まで消えて読めなくなる（実際に消えた）
mask() { mask_keys | sed -E \
    -e "s/([\"'\`])[A-Za-z0-9_\/+=.:-]{12,}([\"'\`]?)/\1<値は伏字>\2/g"
}

hr "対象"
echo "  $(pwd)"
echo "  節: 0 構成 / 1 規模 / 1b 枠組みの版 / 2 ハンドラ×ガード（2b〜2d）/ 3 危険な関数 / 4 秘密情報（4b〜4d）/"
echo "      5 fail-open / 6 開発用の抜け道 / 7 git 履歴 / 8 テーブル名 / 9 タグ（9b 画面操作の記録）/ 10 トークン（10b）/"
echo "      11 Webhook / 12 例外 / 13 乱数と暗号 / 14 通信 / 15 XML / 16 LLM / 17〜24 は構成に応じて出す"

# --------------------------------------------------------------------------
# 枠組みごとに、ハンドラの置き方が違う。ファイル名で決まるもの、ディレクトリで決まるもの、
# コード中の登録で決まるもの、Server Actions の指示子で決まるものの 4 通りを集める。1 つの枠組みしか見ていないと、
# 他の枠組みでは「検出なし」になって素通りする。
# ルート登録の書き方。枠組みごとに語彙が違うので、1 か所にまとめて使い回す。
ROUTE_REG='(app|router|r|e|mux|srv|http|api|fastify|server|Route)\.(get|post|put|patch|delete|Get|Post|Put|Patch|Delete|GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle|Map[A-Z][a-z]+|route)\('
ROUTE_REG="$ROUTE_REG"'|@(app|router|api)\.(route|get|post|put|patch|delete)'
ROUTE_REG="$ROUTE_REG"'|Route::(get|post|put|patch|delete|middleware|apiResource|resource)'
ROUTE_REG="$ROUTE_REG"'|defineEventHandler|export[[:space:]]+(const|async[[:space:]]+function)[[:space:]]+(GET|POST|PUT|PATCH|DELETE|handler|loader|action)'
ROUTE_REG="$ROUTE_REG"'|#\[(get|post|put|patch|delete)\(|\.route\(["'"'"'`]/|Router::new\(\)'
ROUTE_REG="$ROUTE_REG"'|(publicProcedure|protectedProcedure|authedProcedure)'
ROUTE_REG="$ROUTE_REG"'|^[[:space:]]*(get|post|put|patch|delete)[[:space:]]*[("'"'"'`]'
ROUTE_REG="$ROUTE_REG"'|->[[:space:]]*(get|post|put|patch|delete|map|any)\('
ROUTE_REG="$ROUTE_REG"'|@(Path|GET|POST|PUT|DELETE)|@(Get|Post|Put|Patch|Delete|Request)Mapping|\[Http(Get|Post|Put|Patch|Delete)\]'
ROUTE_REG="$ROUTE_REG"'|routing[[:space:]]*\{|Query:[[:space:]]*\{|Mutation:[[:space:]]*\{'
# サーバーレスの入口。関数そのものが 1 つのルートになる。
ROUTE_REG="$ROUTE_REG"'|exports\.[a-zA-Z_]+[[:space:]]*=|module\.exports[[:space:]]*=[[:space:]]*(async[[:space:]]+)?function'
ROUTE_REG="$ROUTE_REG"'|Deno\.serve|functions\.https\.on(Request|Call)|functions\.[a-z]+\.document'
ROUTE_REG="$ROUTE_REG"'|register_rest_route|add_action\(["'"'"']rest_api_init'
# レシーバ名が変数でない書き方（チェーンで繋ぐ Elysia、Vapor の app.get("a","b")）。
ROUTE_REG="$ROUTE_REG"'|\.(get|post|put|patch|delete)\([[:space:]]*["'"'"'`]'
# 命名規約で決まるもの（Qwik の onGet、Razor Pages の OnGet）。
ROUTE_REG="$ROUTE_REG"'|(export[[:space:]]+const[[:space:]]+)?on(Get|Post|Put|Patch|Delete)\b'
# ルート定義ファイル（Play の conf/routes）。
ROUTE_REG="$ROUTE_REG"'|^(GET|POST|PUT|PATCH|DELETE)[[:space:]]+/'

handler_files() {
  {
    # (1) ファイル名で決まるもの。依存と生成物のディレクトリは -prune で辿らない
    #     （以前は行末の \ が抜けて除外が 1 つも働かず、node_modules が一覧に並んでいた）
    # shellcheck disable=SC2046
    find . $(prune_expr) -o -type f \( -name "route.ts" -o -name "route.js" -o -name "route.mjs" \
              -o -name "+server.ts" -o -name "+server.js" \
              -o -name "+page.server.ts" -o -name "+page.server.js" \
              -o -name "*_controller.rb" -o -name "*_controller.ex" -o -name "*_controller.exs" \
              -o -name "views.py" -o -name "viewsets.py" -o -name "api.py" -o -name "app.py" \
              -o -name "*.controller.ts" -o -name "*.resolver.ts" \
              -o -name "*Controller.php" -o -name "*Controller.java" -o -name "*Controller.cs" \
              -o -name "*Controller.kt" -o -name "*Resource.java" -o -name "*Resource.kt" \
              -o -name "*_handler.go" -o -name "handlers.go" -o -name "handler.go" \
              -o -name "worker.ts" -o -name "worker.js" \
              -o -name "resolvers.ts" -o -name "resolvers.js" -o -name "schema.ts" \
              -o -name "routers.ts" -o -name "router.ts" -o -name "routes.ts" -o -name "routes.js" \
              -o -name "server.ts" -o -name "server.js" -o -name "app.ts" -o -name "app.js" \
              -o -name "Program.cs" -o -name "Startup.cs" \
              -o -name "main.rs" -o -name "lib.rs" -o -name "routes.rs" \
              -o -name "Routing.kt" -o -name "*Routes.kt" \
              -o -name "app.rb" -o -name "config.ru" \
              -o -name "index.php" -o -name "web.php" -o -name "api.php" \
              -o -name "*.cshtml.cs" -o -name "*.razor" \
              -o -name "routes.swift" -o -name "*Controller.scala" -o -name "routes" \
              -o -name "index.ts" -o -name "index.js" -o -name "index.mjs" \) -print 2>/dev/null
    # (2) ディレクトリで決まるもの
    for d in ./pages/api ./src/pages/api ./app/api ./src/app/api \
             ./server/api ./server/routes ./src/server \
             ./app/routes ./routes ./src/routes \
             ./app/Http/Controllers ./app/controllers ./src/Controller \
             ./handlers ./handler ./internal/handlers ./internal/api ./internal/http \
             ./api ./functions ./src/functions ./src/handlers \
             ./supabase/functions ./netlify/functions ./.netlify/functions \
             ./Pages ./Sources ./conf ./app/Controllers; do
      # shellcheck disable=SC2046
      [[ -d "$d" ]] && find "$d" $(prune_expr) -o -type f \
        \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' \
           -o -name '*.php' -o -name '*.rb' -o -name '*.py' -o -name '*.go' \
           -o -name '*.ex' -o -name '*.exs' -o -name '*.rs' -o -name '*.kt' \
           -o -name '*.cs' -o -name '*.java' -o -name '*.scala' -o -name '*.swift' \) -print 2>/dev/null
    done
    # (3) コード中の登録で決まるもの
    grep -rlE "${EXA[@]}" "$ROUTE_REG" \
      --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
      --include='*.py' --include='*.go' --include='*.php' --include='*.rb' \
      --include='*.rs' --include='*.kt' --include='*.ex' --include='*.cs' --include='*.java' --include='*.scala' --include='*.swift' \
      . 2>/dev/null
    # (3b) Server Actions。'use server' を先頭に置いたファイルは、export された関数が
    #      すべてクライアントから直接呼べる入口になる。route.ts と同じ重さで見る。
    grep -rlE "${EXA[@]}" "^[[:space:]]*['\"]use server['\"]" \
      --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' . 2>/dev/null
    # (4) ハンドラの実装だけを持つファイル（登録と実装が別ファイルに分かれる構成）
    grep -rlE "${EXA[@]}" \
      'func[[:space:]].*\(.*(http\.ResponseWriter|gin\.Context|echo\.Context|fiber\.Ctx)|class[[:space:]].*RequestHandler|defmodule[[:space:]].*Controller' \
      --include='*.go' --include='*.py' --include='*.ex' . 2>/dev/null
  } | sed 's|^\./||' | sort -u \
    | grep -vE '^(src/)?(components|utils|hooks|styles|types|__tests__|test|tests)/' \
    | grep -vE '\.(test|spec|stories)\.[a-z]+$' \
    | awk '!/^(src\/)?lib\// || /\/controllers\/|_controller\.(ex|exs|rb)$/'
}

# ハンドラらしき定義の数。言語をまたいで数えるため、広めに取る。
HANDLER_DEF='export[[:space:]]+(default[[:space:]]+)?(async[[:space:]]+)?function|export[[:space:]]+(const|default)[[:space:]]+[A-Za-z_(]|^[[:space:]]*(async[[:space:]]+)?def[[:space:]]|^[[:space:]]*func[[:space:]].*(ResponseWriter|gin\.Context|echo\.Context|fiber\.Ctx|http\.Request)|public[[:space:]]+function[[:space:]]|^[[:space:]]*(pub[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]|def[[:space:]]+[a-z_]+\(conn|class[[:space:]]+[A-Z][A-Za-z0-9_]*(ViewSet|View|Handler|Resource|Controller)|exports\.[a-zA-Z_]+[[:space:]]*=|module\.exports[[:space:]]*=|Deno\.serve|on(Get|Post|Put|Patch|Delete)\b'
HANDLER_DEF="$HANDLER_DEF"'|'"$ROUTE_REG"

hr "0. 構成の判定（どの資料が要るかを決める）"
# 計測・広告タグの語（0 節の判定と 9 節の一覧で同じものを使う。以前は 0 節だけ古い一覧で、9 節が拾うのに
# 0 節は「無」と言っていた）。URL を直に書く形だけでなく、フレームワークのラッパーコンポーネント経由の
# 読み込みも見る。<GoogleTagManager gtmId={...} /> のような書き方は URL が現れず、ドメイン名だけでは取り逃す。
# 送信先は recon.sh・browser_probe.mjs の一覧（ホスト名）と同じ 17 種を、コードに現れる語で引く。
# エラー監視（Sentry）とチャット（Intercom）も、利用者の端末から第三者へ送る点は同じなので含める
# （電気通信事業法の外部送信規律は目的を問わない。08 の 1 節）。短い関数名（ytag・twq・ttq）は、
# keytag( のような別の語に当たらないよう前に語の境界を置き、汎用の CDN（s.yimg.jp）はタグの配信パスまで見る。
TAGPAT='googletagmanager|google-analytics|analytics\.google\.com|gtag\(|adsbygoogle|pagead2|googlesyndication|googleadservices|doubleclick|connect\.facebook|fbq\(|clarity\.ms|@microsoft/clarity|hotjar|analytics\.tiktok|(^|[^A-Za-z0-9_$.])ttq\.|snap\.licdn|_linkedin_partner_id|ads-twitter|(^|[^A-Za-z0-9_$.])twq\(|s\.yimg\.jp/images/listing/tool/cv/ytag\.js|(^|[^A-Za-z0-9_$.])ytag\(|yjads|widget\.intercom\.io|intercomSettings|@intercom/|(^|[^A-Za-z0-9_$.])Intercom\(|@sentry/|sentry\.io|sentry-cdn\.com|Sentry\.init|logrocket|LogRocket|fullstory|FullStory|posthog|datadogRum|browser-rum|mouseflow|_mfq|GoogleTagManager|GoogleAnalytics|@next/third-parties|@vercel/analytics|SpeedInsights|react-ga|vue-gtag|nuxt/scripts'
# 対象に無い技術の資料を読むのは時間の無駄で、逆に「読んだつもり」になる危険もある。
# ここで何があるかを先に確定させ、要る資料だけを開く。
need=""
# 列を揃える。printf の幅はバイト数なので、日本語（UTF-8 で 3 バイト、表示は 2 桁）で崩れる。表示の幅で数える
say() {
  local n b w pad
  n=${#1}; b=$(printf '%s' "$1" | LC_ALL=C wc -c | tr -d ' ')
  w=$(( n + (b - n) / 2 )); pad=$(( 26 - w )); [[ $pad -lt 1 ]] && pad=1
  printf '  %s%*s%s\n' "$1" "$pad" '' "$2"
}

# --- インフラの定義 ---
iac=""
for f in Dockerfile docker-compose.yml docker-compose.yaml compose.yaml; do
  [[ -e "$f" ]] && iac="$iac コンテナ($f)"
done
[[ -n "$(find . -maxdepth 3 -name '*.tf' -not -path '*/.git/*' 2>/dev/null | head -1)" ]] && iac="$iac Terraform"
[[ -e cdk.json ]] && iac="$iac CDK"
[[ -e Pulumi.yaml ]] && iac="$iac Pulumi"
[[ -n "$(find . -maxdepth 3 \( -name 'Chart.yaml' -o -name 'kustomization.y*ml' \) 2>/dev/null | head -1)" ]] && iac="$iac Kubernetes"
[[ -n "$(grep -rl '^kind:[[:space:]]*\(Deployment\|Service\|Ingress\)' --include='*.yaml' --include='*.yml' . 2>/dev/null | head -1)" ]] && iac="$iac Kubernetesマニフェスト"
for f in serverless.yml serverless.yaml template.yaml wrangler.toml; do
  [[ -e "$f" ]] && iac="$iac サーバーレス($f)"
done
if [[ -n "$iac" ]]; then
  say "インフラの定義" "有 →${iac}"
  need="$need references/13-infrastructure.md"
else
  say "インフラの定義" "無（マネージド基盤の想定。設定は 03 で実機を見る）"
fi

# --- モバイル ---
mob=""
[[ -d android ]] && mob="$mob android/"
[[ -d ios ]] && mob="$mob ios/"
[[ -e pubspec.yaml ]] && mob="$mob Flutter"
[[ -e Podfile ]] && mob="$mob CocoaPods"
[[ -n "$(find . -maxdepth 3 -name 'AndroidManifest.xml' -o -maxdepth 3 -name 'Info.plist' 2>/dev/null | head -1)" ]] && mob="$mob ネイティブ設定"
grep -qE '"(react-native|expo|@capacitor/core|cordova)"' package.json 2>/dev/null && mob="$mob クロスプラットフォーム"
[[ -n "$(find . -maxdepth 3 \( -name '*.xcodeproj' -o -name '*.xcworkspace' \) 2>/dev/null | head -1)" ]] && mob="$mob Xcode"
if [[ -n "$mob" ]]; then
  say "モバイルアプリ" "有 →${mob}"
  need="$need references/14-mobile.md"
else
  say "モバイルアプリ" "無"
fi

# --- その他、資料の要否が分かれるもの ---
if [[ -n "$(grep -rlE "${EXA[@]}" 'anthropic|openai|@ai-sdk|langchain|llamaindex|generativeai|bedrock-runtime|modelcontextprotocol' \
     --include='package.json' --include='requirements.txt' --include='pyproject.toml' . 2>/dev/null | head -1)" ]]; then
  say "LLM の利用" "有 → アプリ自身が LLM を呼んでいる"
  need="$need references/12-ai-features.md"
else
  say "LLM の利用" "無"
fi

if [[ -n "$(grep -rlE "${EXA[@]}" "$TAGPAT|replayIntegration" \
     --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.html' --include='*.vue' --include='*.svelte' \
     --include='*.astro' --include='*.php' --include='*.erb' --include='*.twig' --include='*.liquid' . 2>/dev/null | head -1)" ]]; then
  say "計測・広告タグ" "有"
  need="$need references/08-privacy-compliance.md"
else
  say "計測・広告タグ" "無（08 は文書との突き合わせだけ見る）"
fi

if [[ -n "$(grep -rlE "${EXA[@]}" 'DocumentBuilder|SAXParser|XMLReader|etree|lxml|SimpleXML|XmlDocument|xml2js' \
     --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' --include='*.java' --include='*.kt' --include='*.cs' \
     --include='*.php' --include='*.rb' --include='*.go' . 2>/dev/null | head -1)" ]]; then
  say "XML の解析" "有 → 07 の 6-2（XXE）"
else
  say "XML の解析" "無"
fi

# --- マネージドの基盤（BaaS）---
baas=""
{ [[ -d supabase ]] || grep -qE '"@supabase/' package.json 2>/dev/null; } && baas="$baas Supabase"
{ [[ -e firebase.json ]] || [[ -n "$(find . -maxdepth 3 \( -name 'firestore.rules' -o -name 'storage.rules' -o -name 'database.rules.json' \) -not -path '*/node_modules/*' 2>/dev/null | head -1)" ]] \
  || grep -qE '"firebase(-admin)?"' package.json 2>/dev/null; } && baas="$baas Firebase"
grep -qE '"@clerk/' package.json 2>/dev/null && baas="$baas Clerk"
{ [[ -d convex ]] || grep -qE '"convex"' package.json 2>/dev/null; } && baas="$baas Convex"
if [[ -n "$baas" ]]; then
  say "マネージドの基盤" "有 →${baas} → 02 の E 節・03 の 1 節・07 の 11-3・11-4（19 節）"
  need="$need references/07-web-vulnerabilities.md"
else
  say "マネージドの基盤" "無"
fi

# --- CI とエージェントの設定（どちらもリポジトリにある「他人のコードが動く経路」）---
if [[ -d .github/workflows ]]; then
  say "CI の定義" "有 → .github/workflows（20 節）"
  need="$need references/10-dependencies.md"
else
  say "CI の定義" "無"
fi

# node_modules の下まで辿ると大きなリポジトリで遅く、依存の package.json にも当たるので除く
if [[ -n "$(grep -rlE "${EXA[@]}" '"(stripe|@stripe/stripe-js|@stripe/react-stripe-js|payjp|@payjp/[a-z-]+|square|@square/web-sdk|komoju)"' \
     --include='package.json' . 2>/dev/null | head -1)" ]]; then
  say "カード決済" "有 → 06 の「カード決済を扱う場合」"
  need="$need references/06-frameworks.md"
else
  say "カード決済" "無"
fi

agent_files=""
for f in AGENTS.md CLAUDE.md GEMINI.md .cursorrules .windsurfrules .clinerules .cursor/mcp.json .mcp.json .vscode/mcp.json \
         .claude/settings.json .claude/settings.local.json .github/copilot-instructions.md .vscode/settings.json \
         .vscode/tasks.json .gemini/settings.json; do
  [[ -e "$f" ]] && agent_files="$agent_files $f"
done
for d in .cursor/rules .claude/commands .claude/agents .claude/skills .github/instructions; do
  [[ -d "$d" ]] && agent_files="$agent_files $d/"
done
if [[ -n "$agent_files" ]]; then
  say "AI エージェントの設定" "有 →${agent_files}（22 節）"
  need="$need references/10-dependencies.md"
else
  say "AI エージェントの設定" "無"
fi

# リアルタイム通信。HTTP のガードとは別の入口になる
rt=""
# .channel( は Laravel Echo や Phoenix にもある。Supabase を使っている構成に限る
{ [[ -d supabase ]] || grep -qE '"@supabase/' package.json 2>/dev/null; } \
  && grep -rqlE "${EXA[@]}" '\.channel\(|postgres_changes' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null && rt="$rt Supabase-Realtime"
grep -rqlE "${EXA[@]}" 'new (WebSocketServer|WebSocket\.Server)\(|from ["'"'"']ws["'"'"']|require\(["'"'"']ws["'"'"']\)|upgradeWebSocket|experimental_upgradeWebSocket|defineWebSocketHandler|@app\.websocket' \
  --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' . 2>/dev/null && rt="$rt WebSocket"
grep -rqlE "${EXA[@]}" 'socket\.io|new Server\([^)]*\{[^}]*cors' --include='*.ts' --include='*.js' --include='package.json' . 2>/dev/null && rt="$rt Socket.IO"
grep -rqlE "${EXA[@]}" '"(pusher|pusher-js|ably|@liveblocks/[a-z-]+|partykit|partyserver|graphql-ws)"' --include='package.json' . 2>/dev/null && rt="$rt 配信サービス"
grep -rqlE "${EXA[@]}" 'text/event-stream|new EventSource\(' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null && rt="$rt SSE"
grep -rqlE "${EXA[@]}" 'onSnapshot\(|onValue\(|onChildAdded\(' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null && rt="$rt Firebase-購読"

if [[ -n "$rt" ]]; then
  say "リアルタイム通信" "有 →${rt}（23 節）"
  need="$need references/07-web-vulnerabilities.md"
else
  say "リアルタイム通信" "無"
fi

# --- 画面操作の記録（セッションリプレイ）と SMS の送信（どちらも 08・02 の該当節を読む）---
REPLAYPAT='replayIntegration|new Replay\(|replaysSessionSampleRate|replaysOnErrorSampleRate|clarity\.ms|@microsoft/clarity|static\.hotjar\.com|@hotjar/browser|hotjar|logrocket|LogRocket\.init|@fullstory/browser|FullStory\.init|FS\.init|posthog-js|posthog\.init|@datadog/browser-rum|datadogRum\.init|sessionReplaySampleRate|mouseflow|_mfq'
if grep -rqE "${EXA[@]}" "$REPLAYPAT" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
     --include='*.vue' --include='*.svelte' --include='*.html' --include='*.astro' --include='*.php' --include='package.json' . 2>/dev/null; then
  replay=1; say "画面操作の記録" "有 → 08 の 1-2・09 の 11 節（9b 節）"
  need="$need references/08-privacy-compliance.md references/09-browser-verification.md"
else
  replay=""; say "画面操作の記録" "無"
fi

# SMS を送る経路。1 通ごとに費用が出るので、認証不要の経路がそのまま攻撃の費用になる
SMSPAT='verifications\.create|verify\.v2\.services|PublishCommand|SendTextMessageCommand|signInWithPhoneNumber|verifyPhoneNumber|PhoneAuthProvider|signInWithOtp\([^)]*phone|SignUpCommand|ResendConfirmationCodeCommand|sendSms|sendSMS|send_sms'
sms_hit="$(grep -rlE "${EXA[@]}" "$SMSPAT" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.py' . 2>/dev/null | head -1)"
# messages.create は Twilio のほかに Anthropic などの SDK にもある。twilio を読み込んでいるファイルに限る
twilio_direct="$(grep -rlE "${EXA[@]}" 'messages\.create\(' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.py' . 2>/dev/null \
  | while IFS= read -r f; do grep -lE "twilio|Twilio" "$f" 2>/dev/null; done | head -5)"
[[ -z "$sms_hit" && -n "$twilio_direct" ]] && sms_hit="$twilio_direct"
sms_cfg="$(grep -nE '^\[auth\.sms' supabase/config.toml 2>/dev/null | head -1)"
if [[ -n "$sms_hit$sms_cfg" ]]; then say "SMS の送信" "有 → 02 の F-4・03 の 3 節（24 節）"; else say "SMS の送信" "無"; fi

lock=""
for f in package-lock.json yarn.lock pnpm-lock.yaml poetry.lock Gemfile.lock go.sum composer.lock Cargo.lock; do
  [[ -e "$f" ]] && lock="$lock $f"
done
say "ロックファイル" "${lock:-★ 無い。監査した版と本番の版が違いうる（10 の 2 節）}"

echo
if [[ -n "$need" ]]; then
  echo "  この案件で追加で読む資料:"
  for f in $(printf '%s\n' $need | awk '!seen[$0]++'); do echo "    $f"; done
else
  echo "  追加で読む資料は無い（01〜05 と、該当する 07 の節だけで足りる）"
fi
echo "  ※ ここに出ないものは、その技術が無いということ。**無い資料は読まない。**"
echo "  ※ 判定はファイルの有無による。手作業で作った資源はコードに現れないので、03 で実機を見る"

# ハンドラの一覧は 1 回だけ作って使い回す（以前は 3 回計算し、大きなリポジトリで数分かかった）
HF_LIST="$(mktemp "${TMPDIR:-/tmp}/audit_grep.XXXXXX")"
HF_DEF="$HF_LIST.def"; HF_GRD="$HF_LIST.grd"
trap 'rm -f "$HF_LIST" "$HF_LIST".*' EXIT
handler_files > "$HF_LIST"
# ファイルごとの数は、全ファイルをまとめて grep に渡して 1 回で数える。ファイルごとに grep を起動すると、
# ハンドラの多い大きなリポジトリで、1 節と 2 節だけで数分かかっていた。
# /dev/null を足すのは、xargs が分けて起動したどの回も「ファイル名:数」の形で出させるため（1 本だけだと名前が付かない）。
# 空の一覧で xargs が grep を引数なしで起動しても、/dev/null があれば標準入力を待たない。
# 「--」を置くのは、「-」で始まるファイル名（一覧は先頭の ./ を外している）をオプションとして読ませないため。
# 読まれると、その回の grep が丸ごと失敗し、1 節と 2 節の結果が全部消える
hf_grep() { tr '\n' '\0' < "$HF_LIST" | xargs -0 grep "$@" -- /dev/null 2>/dev/null; }
hf_grep -cE "$HANDLER_DEF" > "$HF_DEF"

hr "1. 規模"
n_files="$(wc -l < "$HF_LIST" | tr -d ' ')"
echo "  ハンドラを含むらしきファイル: $n_files 件"
if [[ "$n_files" != "0" ]]; then
  # 「ファイル名:数」の数は最後の「:」の後ろ（ファイル名に「:」があっても数は取れる）
  n_def="$(LC_ALL=C awk '{ sub(/.*:/, ""); t += $0 } END { print t + 0 }' "$HF_DEF")"
  echo "  ハンドラらしき定義の総数: $n_def 件"
fi
git rev-parse --git-dir >/dev/null 2>&1 && echo "  コミット数: $(git log --all --oneline 2>/dev/null | wc -l | tr -d ' ')"

# --------------------------------------------------------------------------
hr "1b. 枠組みの版（ロックファイルの解決結果。公式アドバイザリで照合する）"
# 枠組み本体の脆弱性は「呼んでいるか」ではなく「版が該当するか」で決まる（10 の 1 節）。
# ここでは、公式の勧告で修正版まで一次情報で確かめたものだけを機械的に判定する。
# それ以外は版を並べるだけにする。表は評価の時点で古くなっている前提で、公式の一覧を必ず見る。
# 下の判定表を公式の勧告と照合した日。表を直したら更新する（tests/run.sh が半年を超えたら知らせる）
ADVISORIES_REVIEWED="2026-09-25"
pkgver() {
  local name="$1" v=""
  if [[ -f package-lock.json ]]; then
    v="$(awk -v k="\"node_modules/$name\": {" 'index($0,k){f=1;next} f&&/"version"/{gsub(/[",]/,"",$2);print $2;exit}' package-lock.json 2>/dev/null)"
  fi
  if [[ -z "$v" && -f pnpm-lock.yaml ]]; then
    v="$(grep -oE "^  '?/?$name@[0-9][0-9A-Za-z.+-]*" pnpm-lock.yaml 2>/dev/null | head -1 | sed -E "s/.*@//")"
  fi
  if [[ -z "$v" && -f package.json ]]; then
    v="$(grep -oE "\"$name\"[[:space:]]*:[[:space:]]*\"[^\"]+\"" package.json 2>/dev/null | head -1 | sed -E 's/.*:[[:space:]]*"([^"]+)"/\1/')"
    [[ -n "$v" ]] && v="${v}（package.json の宣言。解決結果ではない）"
  fi
  printf '%s' "$v"
}
# a < b（版の比較）。sort -V に任せる
verlt() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }
# 範囲 [lo, hi) に入るか
inrange() { ! verlt "$1" "$2" && verlt "$1" "$3"; }

fw_found=""
for name in next react-server-dom-webpack react-server-dom-turbopack react-server-dom-parcel \
            nuxt astro @sveltejs/kit @sveltejs/adapter-vercel react-router @remix-run/node; do
  v="$(pkgver "$name")"
  [[ -z "$v" ]] && continue
  fw_found=1
  note=""
  pure="$(printf '%s' "$v" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)"
  # canary などのプレリリースは、修正の範囲が安定版と別に決まっている。機械的には判定しない
  if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+- && "$v" != *宣言* ]]; then
    note=" （プレリリース版。勧告の canary の範囲を公式で確かめる）"; pure=""
  fi
  if [[ -n "$pure" && "$v" != *宣言* ]]; then
    case "$name" in
      next)
        major="${pure%%.*}"
        [[ "$major" -lt 15 ]] && note="$note ★ サポート外（14 以前には 2026 年の修正が出ていない）"
        if ! verlt "$pure" 11.1.4 && { verlt "$pure" 12.3.5 || inrange "$pure" 13.0.0 13.5.9 \
             || inrange "$pure" 14.0.0 14.2.25 || inrange "$pure" 15.0.0 15.2.3; }; then
          note="$note ★ ミドルウェア迂回 CVE-2025-29927 の修正前（02 の A-5）"
        fi
        mm="$(printf '%s' "$pure" | cut -d. -f1-2)"
        fix=""
        case "$mm" in
          15.0) fix=15.0.5 ;; 15.1) fix=15.1.9 ;; 15.2) fix=15.2.6 ;; 15.3) fix=15.3.6 ;;
          15.4) fix=15.4.8 ;; 15.5) fix=15.5.7 ;; 16.0) fix=16.0.7 ;;
        esac
        # App Router の有無。モノレポ（apps/web/app など）も見る
        approuter="$(find . -maxdepth 4 -type d \( -path '*/app' -o -path '*/src/app' \) -not -path '*/node_modules/*' -not -path '*/.next/*' 2>/dev/null | head -1)"
        if [[ -n "$fix" ]] && verlt "$pure" "$fix" && [[ -n "$approuter" ]]; then
          note="$note ★ React2Shell（CVE-2025-55182。Next.js の案内では取り下げ済みの 66478）の修正前。版上げと秘密情報の入れ替えの二段（02 の H）"
        fi ;;
      react-server-dom-*)
        case "$pure" in
          19.0.0|19.1.0|19.1.1|19.2.0) note=" ★ React2Shell（CVE-2025-55182）の対象。版上げと秘密情報の入れ替え" ;;
          *) if inrange "$pure" 19.0.0 19.0.4 || inrange "$pure" 19.1.0 19.1.5 || inrange "$pure" 19.2.0 19.2.4; then
               note=" ★ 後続の DoS・ソース露出の勧告の修正前（CVE-2025-55183 / 55184 / 67779、CVE-2026-23864。すべて直るのは 19.0.4 / 19.1.5 / 19.2.4）"; fi ;;
        esac ;;
      @sveltejs/adapter-vercel)
        verlt "$pure" 6.3.2 && note=" ★ 認証済みの応答がキャッシュされる CVE-2026-27118 の修正前（07 の 7 節）" ;;
    esac
  fi
  printf '  %-28s %s%s\n' "$name" "$v" "$note"
done
[[ -z "$fw_found" ]] && echo "  （判定対象の枠組みは無い）"
echo "  ※ ★ が無くても安全とは限らない。2026 年だけで同種の勧告が多数出ている。"
echo "    github.com の各リポジトリの security/advisories で、この版に当たるものを見る"
# 表が古いまま使われると、照合日より後に出た勧告の対象でも ★ が付かない。照合日と経過日数を出す。
# date の書式の指定は BSD（-j -f）と GNU（-d）で違うので両方試す。どちらも無ければ日付だけ出す
adv_epoch="$(date -j -f %Y-%m-%d "$ADVISORIES_REVIEWED" +%s 2>/dev/null || date -d "$ADVISORIES_REVIEWED" +%s 2>/dev/null || true)"
if [[ "$adv_epoch" =~ ^[0-9]+$ ]]; then
  adv_days=$(( ( $(date +%s) - adv_epoch ) / 86400 ))
  echo "  ※ ★ の判定表を公式の勧告と照合した日: ${ADVISORIES_REVIEWED}（${adv_days} 日前）"
  if [[ "$adv_days" -ge 180 ]]; then
    echo "    ★ 照合から半年を超えている。★ の有無は判断に使わず、公式の勧告だけで判定する"
  fi
else
  echo "  ※ ★ の判定表を公式の勧告と照合した日: ${ADVISORIES_REVIEWED}（経過日数は計算できなかった）"
fi

# --------------------------------------------------------------------------
hr "2. ハンドラ × 認可ガード（空欄は「本当に公開してよいか」を 1 本ずつ確認する）"
# 枠組みごとに、認可の掛け方の語彙が違う。1 つの枠組みの語彙しか持たないと、
# ガードがあるのに「検出なし」と出て、逆に安全側の誤りを生む。
GUARD='require[A-Z][A-Za-z]+|ensure[A-Z][A-Za-z]+|assert[A-Z][A-Za-z]*(Auth|User|Admin|Session|Role)|getUserSession|isAdmin|getCurrentUser|getSession|getServerSession|serverSupabaseUser|verifyToken|authenticate|authorize|ensureAuthenticated|ensureLoggedIn|withAuth|passport\.authenticate'
GUARD="$GUARD"'|@login_required|@permission_required|@user_passes_test|IsAuthenticated|IsAdminUser|permission_classes|Depends\(|current_user|web\.authenticated'
GUARD="$GUARD"'|before_action|authenticate_user!|halt[[:space:]]+40[13]'
GUARD="$GUARD"'|->middleware|middleware\(|Gate::|Auth::|auth:sanctum|auth:api|can:|\$this->authorize|IsGranted|AuthMiddleware'
GUARD="$GUARD"'|@PreAuthorize|@Secured|@RolesAllowed|SecurityFilterChain|hasRole|hasAuthority|@RequiresAuthentication'
GUARD="$GUARD"'|\[Authorize|RequireAuthorization|User\.Identity'
GUARD="$GUARD"'|locals\.(user|session|getSession)|event\.context\.(user|auth)|ctx\.state\.(user|session)|state\.user'
GUARD="$GUARD"'|RequireAuth|CheckAuth|MustAuth|WithAuth|AuthGuard|UseGuards|@Roles'
GUARD="$GUARD"'|protectedProcedure|authedProcedure|preHandler|onRequest'
GUARD="$GUARD"'|plug[[:space:]]+:(require|ensure|authenticate)|require_authenticated_user'
GUARD="$GUARD"'|AuthenticatedUser|BearerAuth|@Authenticated'
GUARD="$GUARD"'|CRON_SECRET|WEBHOOK_SECRET|REVALIDATE_SECRET|API_SECRET'
GUARD="$GUARD"'|permission_callback|current_user_can|is_user_logged_in'
GUARD="$GUARD"'|beforeHandle|sharedMap|grouped\(|authAction|AuthenticatedAction'
GUARD="$GUARD"'|IS_AUTHENTICATED|SecurityRule|@Secured'
# ルートの登録の行で呼ぶ認可の関数（isAuthorized()・Spring の denyAll() など）
GUARD="$GUARD"'|isAuthorized|isAuthenticated|isLoggedIn|denyAll'

# ガードの一致は全ファイルをまとめて 1 回だけ取り（ファイル名:行:一致）、ファイルごとに
# 「一致した語（重複なし・並べ替え）」と「一致した行の数」に集める。出す順は一覧の順。
hf_grep -noE "$GUARD" > "$HF_GRD"
{
  LC_ALL=C awk -v list="$HF_LIST" -v defs="$HF_DEF" '
    BEGIN {
      while ((getline l < list) > 0) { order[++n] = l; inlist[l] = 1 }
      while ((getline l < defs) > 0) {
        c = l; sub(/.*:/, "", c); f = substr(l, 1, length(l) - length(c) - 1); def[f] = c + 0
      }
    }
    {
      # ファイル名にも一致した語（auth:sanctum など）にも「:」がありうる。一覧にあるファイル名で、
      # 直後が「:行番号:」になる位置を前から探して切る
      rest = $0; off = 0; f = ""
      while ((p = index(rest, ":")) > 0) {
        cand = substr($0, 1, off + p - 1); tail = substr($0, off + p + 1)
        if ((cand in inlist) && match(tail, /^[0-9]+:/)) {
          f = cand; ln = substr(tail, 1, RLENGTH - 1); m = substr(tail, RLENGTH + 1); break
        }
        off += p; rest = substr(rest, p + 1)
      }
      if (f == "") next
      if (!((f, ln) in seenl)) { seenl[f, ln] = 1; grd[f]++ }
      if (!((f, m) in seenm)) { seenm[f, m] = 1; nm[f]++; name[f, nm[f]] = m }
    }
    END {
      for (k = 1; k <= n; k++) {
        f = order[k]; g = ""
        # 語を並べ替える（1 ファイルの語は数個なので挿入ソートで足りる）
        for (i = 2; i <= nm[f]; i++) {
          v = name[f, i]; j = i - 1
          while (j >= 1 && name[f, j] > v) { name[f, j + 1] = name[f, j]; j-- }
          name[f, j + 1] = v
        }
        for (i = 1; i <= nm[f]; i++) g = g name[f, i] " "
        if (g == "") g = "← ガード検出なし"
        if (def[f] > 1) printf "  %-46s %-30s (定義 %d / ガード %d)\n", f, g, def[f], grd[f]
        else printf "  %-46s %s\n", f, g
      }
    }' "$HF_GRD"
} | show
echo "  ※ 「定義 N / ガード M」が出た行は、1 ファイルに複数のハンドラがある。"
echo "    N と M が違えば、ガードの無いハンドラが混じっている。関数ごとに目で確かめる"
echo "  ※ ガード名が出ていても、そのハンドラに掛かっているとは限らない。"
echo "    同じファイルの別の場所にあるだけのことがある。空欄と同じ重さで 1 本ずつ読む"

hr "2b. ルート登録の行ごとの認可（登録の行に認可が挟まっているか）"
# app.get('/x', requireAuth, handler) のように、登録の行で認可を挟む書き方を見る。
# ルートを 1 ファイルに集める構成（Express の server.ts など）では、2 の「定義 N / ガード M」だけでは
# どのルートが素通しかが見えない。登録の行ごとに、認可の語が挟まっているかを分けて出す。
# パス付きの app.use('/x', …) も見る（静的配信・ディレクトリ一覧・メトリクスの公開はこの形で書かれる）。
REG_LINE="$ROUTE_REG"'|(app|router)\.use\([[:space:]]*["'"'"'`]/'
# パスの名前の表。枠組みを問わず、名前が内部向け・運用向けを示すもの（★）と、管理・文書化の口（確かめる）に分ける。
# 引用符の直後の / から、区切り（/・引用符・?）までを 1 つの名前として見る
INTERNAL_PATHS='["'"'"'`]/(_?internal|metrics|actuator|debug|__debug__|heapdump|threaddump|env|phpinfo|server-status|server-info|console|graphiql|playground|_profiler|telescope|horizon|jolokia|pprof)([/"'"'"'`?]|$)'
REVIEW_PATHS='["'"'"'`]/(admin|administrator|manage(ment)?|dashboard|swagger(-ui)?|api-docs|openapi|docs|redoc)([/"'"'"'`?.]|$)'
HF_REG="$HF_LIST.reg"; HF_REGT="$HF_LIST.regt"; HF_REGG="$HF_LIST.regg"
grep -rnE "${EXA[@]}" "$REG_LINE" \
  --include='*.ts' --include='*.js' --include='*.mjs' --include='*.go' --include='*.php' \
  . 2>/dev/null | sed 's|^\./||' > "$HF_REG"
# 認可の語は行の本文だけで探す（ファイル名の authenticatedUsers.ts などが一致しないように）。行の番号で突き合わせる
cut -d: -f3- "$HF_REG" > "$HF_REGT"
grep -nE "$GUARD" "$HF_REGT" 2>/dev/null | cut -d: -f1 > "$HF_REGG"
if [[ -s "$HF_REG" ]]; then
  LC_ALL=C awk -v gfile="$HF_REGG" -v cfile="$HF_LIST.regc" -v ufile="$HF_LIST.regu" \
      -v ipath="$INTERNAL_PATHS" -v rpath="$REVIEW_PATHS" '
    BEGIN { while ((getline l < gfile) > 0) g[l] = 1 }
    {
      n++; f = $0; sub(/:.*/, "", f); ln = $0; sub(/^[^:]*:/, "", ln); sub(/:.*/, "", ln)
      t = $0; sub(/^[^:]*:[0-9]+:/, "", t); sub(/^[ \t]+/, "", t)
      # チェーンの書き方（.get('/x', …)）を拾う緩い形は、config.get('キー') のような読み出しにも一致する。
      # 引数が / で始まらず、レシーバもルート登録らしい名前でなければ、登録ではないとして外す
      if (t ~ /\.(get|post|put|patch|delete)\([ \t]*["\047`][^\/]/ \
          && t !~ /(^|[^A-Za-z0-9_$.])(app|router|r|e|mux|srv|api|fastify|server|routes?|group|g)\.(get|post|put|patch|delete)\(/) {
        next
      }
      if (length(t) > 160) t = substr(t, 1, 160) "…"
      if (!(f in tot)) order[++k] = f
      # コメントアウトされた登録。認可の語を含むものは、その認可が外れて動いている可能性がある
      if (t ~ /^(\/\/|#)/) { if (n in g) print "  ★ " f ":" ln ": " t > cfile; next }
      tot[f]++
      if (n in g) { grd[f]++; next }
      # 認可の語の無い登録のうち、パスの名前で「内部向け・運用向け」と分かるものに注記する。
      # 特定の枠組みのパスに絞らず、名前の表で見る（INTERNAL_PATHS は ★、REVIEW_PATHS は確かめる）
      note = ""; star = 0
      if (match(t, ipath)) { note = "  ← 内部向け・運用向けのパスを、登録の行に認可なしで公開"; star = 1 }
      else if (match(t, rpath)) note = "  ← 管理・文書化の口。前段（2d）で認可しているかを確かめる"
      # ★ の付いた行は、打ち切り（lim）に掛からないよう別に出す
      if (star) print "  ★ " f ":" ln ": " t note > (ufile ".star")
      else print "  " f ":" ln ": " t note > ufile
    }
    END {
      for (i = 1; i <= k; i++) {
        f = order[i]; if (!(f in tot)) continue
        printf "  %-46s 登録 %d / 行に認可の語あり %d / なし %d\n", f, tot[f], grd[f] + 0, tot[f] - grd[f]
      }
    }' "$HF_REG"
  if [[ -s "$HF_LIST.regc" ]]; then
    echo "  --- 認可の語を含む登録が、コメントアウトされている（その認可が外れたまま動いている可能性がある）"
    cat "$HF_LIST.regc"
  fi
  if [[ -s "$HF_LIST.regu.star" || -s "$HF_LIST.regu" ]]; then
    echo "  --- 登録の行に認可の語が無いもの（★ を先に出す）"
    [[ -s "$HF_LIST.regu.star" ]] && cat "$HF_LIST.regu.star"
    [[ -s "$HF_LIST.regu" ]] && lim 80 < "$HF_LIST.regu"
  fi
else
  echo "  （検出なし）"
fi
echo "  ※ 行に認可の語が無くても、ハンドラの中や、前段の app.use / ミドルウェア（2d）で見ている場合がある。"
echo "    公開してよいルートかどうかを 1 本ずつ確かめる。★ は、ほぼ確実に指摘になるもの"

hr "2e. ディレクトリ一覧の公開（枠組み・サーバーの設定を問わず）"
# 一覧の公開は、アプリのコードにも、Web サーバーやコンテナの設定にも書かれる。書き方の表で横断して拾う。
# 置いてあるファイルの一覧がそのまま見えるので、鍵・ログ・バックアップが並んでいれば、それだけで露出になる
DIRLIST='serveIndex\(|express-directory|autoindex[[:space:]]+on|Options[[:space:]]+[^#]*\+?Indexes|show_indexes["'"'"']?[[:space:]]*[:=][[:space:]]*True|directory_listing|DirectoryBrowser|UseDirectoryBrowser|http\.FileServer\(|listDirectories|dirListing|serve-index|directoryListing[[:space:]]*[:=][[:space:]]*true|IndexIgnore|fancyindex[[:space:]]+on'
{
  grep -rnE "${EXA[@]}" "$DIRLIST" \
    --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' --include='*.go' --include='*.rb' --include='*.php' \
    --include='*.java' --include='*.kt' --include='*.cs' --include='*.conf' --include='*.config' --include='.htaccess' \
    --include='*.yml' --include='*.yaml' --include='*.toml' --include='*.json' --include='Caddyfile' --include='*.xml' \
    . 2>/dev/null | sed 's|^\./||' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#|\*|<!--)' | sed 's/^/  ★ /' | lim 30
} | show
echo "  ※ 一覧を出す設定は、公開してよいファイルだけを置いたディレクトリに限る。鍵・ログ・バックアップ・ソースが並んでいないかを見る"
echo "    Go の http.FileServer は、index.html の無いディレクトリで既定のまま一覧を出す"

hr "2f. 装飾子・注釈で書くルートごとの認可（NestJS・Spring・ASP.NET・FastAPI・Flask・Symfony など）"
# ルートを装飾子（@Get('x')・@GetMapping・[HttpGet]・@app.get・#[Route]）で宣言する枠組みでは、認可も装飾子で掛ける
# （@UseGuards・@PreAuthorize・[Authorize]・Depends・@login_required・#[IsGranted]）。2b 節の「登録の行」には現れず、
# 2 節のファイル単位の集計では、ルートの多いファイルのどのルートに認可が無いかが見えない。
# ルートの装飾子と、その上下に続く装飾子のまとまり（引数が複数行にまたがるものも含む）と、クラスに付いた装飾子を合わせて見る
DECO_FILES="$(grep -rlE "${EXA[@]}" '@(Get|Post|Put|Patch|Delete|All)\(|@(Get|Post|Put|Patch|Delete|Request)Mapping|\[Http(Get|Post|Put|Patch|Delete)|@[A-Za-z_]+\.(get|post|put|patch|delete|route|api_route)\(|#\[Route\(|@(GET|POST|PUT|PATCH|DELETE)([^A-Za-z]|$)' \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.java' --include='*.kt' --include='*.cs' --include='*.php' \
  . 2>/dev/null | sed 's|^\./||' | grep -vE '(^|/)(test|tests|__tests__|spec|e2e)/|\.(test|spec)\.[a-z]+$' || true)"
if [[ -n "$DECO_FILES" ]]; then
  HF_DECO="$HF_LIST.deco"; : > "$HF_DECO"
  # 1 ルート 1 行: ファイル <TAB> 行 <TAB> 装飾子の行 <TAB> 装飾子のまとまり <TAB> クラスの装飾子 <TAB> 次の行（処理の宣言）
  printf '%s\n' "$DECO_FILES" | while IFS= read -r f; do
    LC_ALL=C awk -v f="$f" '
      function isdeco(l) { return l ~ /^[ \t]*(@[A-Za-z_]|\[[A-Z][A-Za-z]*[(\]]|#\[)/ }
      function isroute(l) {
        return l ~ /@(Get|Post|Put|Patch|Delete|All|Options|Head)\(/ || l ~ /@(Get|Post|Put|Patch|Delete|Request)Mapping/ \
          || l ~ /\[Http(Get|Post|Put|Patch|Delete)/ || l ~ /@[A-Za-z_]+\.(get|post|put|patch|delete|route|api_route)\(/ \
          || l ~ /#\[Route\(/ || l ~ /@(GET|POST|PUT|PATCH|DELETE)([^A-Za-z]|$)/
      }
      function depth(l,   o, c) { o = gsub(/\(/, "(", l); c = gsub(/\)/, ")", l); return o - c }
      {
        line = $0; sub(/\r$/, "", line)
        if (d > 0 || isdeco(line)) {
          blk = blk " " line; d += depth(line); if (d < 0) d = 0
          if (isroute(line)) { n++; rl[n] = NR; rt[n] = line }
          next
        }
        if (line ~ /^[ \t]*$/ && blk == "") next
        sig = line; gsub(/\t/, " ", sig); sub(/^ +/, "", sig)
        # 直後がクラスの宣言なら、まとまりはクラスの装飾子（@RequestMapping("/admin") はパスの前置きで、ルートではない）
        if (line ~ /(^|[^A-Za-z_])class[ \t]/) { cls = blk; n = 0 }
        for (i = 1; i <= n; i++) {
          t = rt[i]; gsub(/\t/, " ", t); sub(/^ +/, "", t); b = blk; gsub(/\t/, " ", b); c = cls; gsub(/\t/, " ", c)
          printf "%s\t%d\t%s\t%s\t%s\t%s\n", f, rl[i], substr(t, 1, 140), b, c, substr(sig, 1, 100)
        }
        n = 0; blk = ""; d = 0
      }' "$f" 2>/dev/null
  done > "$HF_DECO"
  if [[ -s "$HF_DECO" ]]; then
    # 認可の語は、装飾子のまとまりとクラスの装飾子だけで探す（行の番号で突き合わせる）
    cut -f4 "$HF_DECO" | grep -nE "$GUARD" 2>/dev/null | cut -d: -f1 > "$HF_DECO.g" || true
    cut -f5 "$HF_DECO" | grep -nE "$GUARD" 2>/dev/null | cut -d: -f1 > "$HF_DECO.c" || true
    # 処理の宣言の引数に書く認可（FastAPI の user = Depends(get_current_user) など）も数える
    cut -f6 "$HF_DECO" | grep -nE "$GUARD" 2>/dev/null | cut -d: -f1 >> "$HF_DECO.g" || true
    cut -f4 "$HF_DECO" | grep -nE 'AllowAnonymous|@Public\(|permitAll|IS_AUTHENTICATED_ANONYMOUSLY' 2>/dev/null | cut -d: -f1 > "$HF_DECO.p" || true
    LC_ALL=C awk -F'\t' -v gf="$HF_DECO.g" -v cf="$HF_DECO.c" -v pf="$HF_DECO.p" -v ipath="$INTERNAL_PATHS" -v rpath="$REVIEW_PATHS" \
        -v ufile="$HF_DECO.u" '
      BEGIN { while ((getline l < gf) > 0) g[l] = 1; while ((getline l < cf) > 0) c[l] = 1; while ((getline l < pf) > 0) pub[l] = 1 }
      {
        n++; f = $1
        if (!(f in tot)) order[++k] = f
        tot[f]++
        if (n in g) { own[f]++; next }
        if (n in c) { cls[f]++; next }
        note = ""; star = 0
        if (n in pub) note = "  ← 明示的に公開（AllowAnonymous など）。公開してよいかを確かめる"
        else if (match($3, ipath)) { note = "  ← 内部向け・運用向けのパスを、認可の装飾子なしで公開"; star = 1 }
        else if (match($3, rpath)) note = "  ← 管理・文書化の口。全体に掛ける認可があるかを確かめる"
        out = "  " f ":" $2 ": " $3 "  → " $6 note
        if (star) print "  ★" substr(out, 2) > (ufile ".star"); else print out > ufile
      }
      END {
        for (i = 1; i <= k; i++) {
          f = order[i]
          printf "  %-46s ルート %d / 装飾子に認可の語あり %d（うちクラス単位 %d） / なし %d\n", f, tot[f], own[f] + cls[f], cls[f] + 0, tot[f] - own[f] - cls[f]
        }
      }' "$HF_DECO"
    if [[ -s "$HF_DECO.u.star" || -s "$HF_DECO.u" ]]; then
      echo "  --- 装飾子に認可の語が無いルート（★ を先に出す）"
      [[ -s "$HF_DECO.u.star" ]] && cat "$HF_DECO.u.star"
      [[ -s "$HF_DECO.u" ]] && lim 80 < "$HF_DECO.u"
    fi
  else
    echo "  （検出なし）"
  fi
  echo "  ※ 全体に掛ける認可（NestJS の APP_GUARD・useGlobalGuards、Spring の SecurityFilterChain、ASP.NET の FallbackPolicy、"
  echo "    FastAPI の APIRouter(dependencies=…)）があれば、それを先に確かめる。無ければ、認可の語が無いルートは 1 本ずつ読む"
else
  echo "  （装飾子でルートを宣言するファイルは無い）"
fi

hr "2g. 権限や更新の範囲を、利用者が送った値で決めていないか（02 の A-2・07 の 9 節）"
# 認可の装飾子やガードが付いていても、判定の中身が利用者の送った値に頼っていれば成立しない。
# 枠組みごとのリクエストの読み方（NestJS の @Query・Express の req.body・Rails の params・Django の request.data・
# Spring の @RequestParam・PHP の $request->input など）と、権限を示す名前の組み合わせを表で拾う
PRIV_NAME='(is_?admin|admin|roles?|permissions?|privileges?|is_?owner|is_?staff|is_?superuser|access_?level|user_?type)'
PRIV_INPUT="(req|request|ctx|c|event)\.(query|body|params|headers|args|form|json|data|GET|POST)(\.|\[['\"]|\.get\(['\"])${PRIV_NAME}\b"
PRIV_INPUT="$PRIV_INPUT|@(Query|Body|Param|Headers)\(['\"]${PRIV_NAME}['\"]|@RequestParam\((value *= *)?['\"]${PRIV_NAME}['\"]"
PRIV_INPUT="$PRIV_INPUT|\[From(Query|Body|Header|Route)[^]]*\][^,)]*\b${PRIV_NAME}\b|params\[:${PRIV_NAME}\]"
PRIV_INPUT="$PRIV_INPUT|\\\$_(GET|POST|REQUEST)\[['\"]${PRIV_NAME}['\"]\]|\\\$request->(input|get|query|post)\(['\"]${PRIV_NAME}['\"]"
# 受け取ったもの全体（req.body・body・dto・request.data）だけを拾い、項目を選んで読むもの（req.body.email・body['x']）は外す
WHOLE='(req\.body|request\.body|ctx\.request\.body|body|dto|request\.data|request\.json)([^.A-Za-z_[]|$)'
WHOLE_INPUT='(update|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|create|insert|save|merge|upsert|update_attributes|update!|assign_attributes|fill|forceFill)\([^)]{0,40}([^.A-Za-z_]|^)'"$WHOLE"'|\([^)]{0,40}(request\.get_json\(\)|\*\*request|\$request->all\(\)|\$_POST)'
WHOLE_INPUT="$WHOLE_INPUT"'|Object\.assign\([^,]+,[[:space:]]*'"$WHOLE"'|\{[[:space:]]*\.\.\.'"$WHOLE"'|permit!|to_unsafe_h'
INCL=(--include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' --include='*.rb' --include='*.php' --include='*.java' --include='*.kt' --include='*.cs' --include='*.go')
echo "  --- 権限を示す値を、リクエストから読んでいる（判定に使っていれば、利用者が自分で権限を上げられる）"
{ grep -rnEi "${EXA[@]}" "$PRIV_INPUT" "${INCL[@]}" . 2>/dev/null | sed 's|^\./||' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#|\*)' | grep -vE '(^|/)(test|tests|__tests__|spec)/|\.(test|spec)\.[a-z]+:' \
    | sed 's/^/  ★ /' | lim 30; } | show
echo "  --- 受け取ったものを、そのまま作成・更新に渡している（許可する項目を絞っているかを確かめる）"
{ grep -rnE "${EXA[@]}" "$WHOLE_INPUT" "${INCL[@]}" . 2>/dev/null | sed 's|^\./||' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#|\*)' | grep -vE '(^|/)(test|tests|__tests__|spec)/|\.(test|spec)\.[a-z]+:' \
    | sed 's/^/  /' | lim 40; } | show
echo "  ※ ★ は、読んだ値が権限の判定（管理者か、所有者か、役割は何か）に使われていれば指摘になる。絞り込みの条件に使うだけなら問題ない"
echo "    受け取ったものを渡す行は、DTO や許可リストで項目を絞っていれば問題ない。絞っていなければ、利用者が権限や所有者の列を書き換えられる"

hr "2h. 取得する件数・大きさを、利用者が送った値で決めていないか（07 の 9-1 節・API4）"
# 一覧の件数（limit・per_page・pageSize など）を利用者が決め、上限を確かめていなければ、1 回の要求で全件を取り出せる。
# 公開の一覧でも同じ（負荷と、情報の一括取得）。読み方は 2g 節と同じく枠組みごとの表で持ち、名前の表と組み合わせる
SIZE_NAME='(limit|per_?page|perPage|page_?size|pageSize|page_?limit|pageLimit|take|top|max_?results|maxResults|batch_?size|batchSize|max_?items|maxItems)'
SIZE_IN="(req|request|ctx|c|event|r)\.(query|body|params|args|form|GET|POST|query_params|URL\.Query\(\))(\.|\[['\"]|\.get\(['\"]|\.Get\(['\"])${SIZE_NAME}['\"]?"
SIZE_IN="$SIZE_IN|@(Query|Param|Body)\(['\"]${SIZE_NAME}['\"]|@RequestParam\([^)]*['\"]${SIZE_NAME}['\"]|\[FromQuery[^]]*\][^,)]*\b${SIZE_NAME}\b"
SIZE_IN="$SIZE_IN|\b${SIZE_NAME}[[:space:]]*:[[:space:]]*(int|Optional\[int\]|Annotated\[int)[^=]*=[[:space:]]*(Query\(|[0-9])|params\[:${SIZE_NAME}\]"
SIZE_IN="$SIZE_IN|\\\$request->(input|get|query)\(['\"]${SIZE_NAME}['\"]|\\\$_(GET|POST|REQUEST)\[['\"]${SIZE_NAME}['\"]\]|\.(Query|DefaultQuery|QueryParam|FormValue)\(\"${SIZE_NAME}\""
echo "  --- 件数を決める値をリクエストから読んでいる（★ は、同じファイルに上限の確かめが見当たらない）"
{ grep -rnEi "${EXA[@]}" "$SIZE_IN" "${INCL[@]}" . 2>/dev/null | sed 's|^\./||' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#|\*)' | grep -vE '(^|/)(test|tests|__tests__|spec)/|\.(test|spec)\.[a-z]+:' \
    | while IFS= read -r l; do
        f="${l%%:*}"; c="${l#*:}"; c="${c#*:}"
        n="$(printf '%s' "$c" | grep -oEi "$SIZE_NAME" | head -1)"
        # 型と既定値だけの引数（limit: int = 10）は、経路を登録するファイルのときだけ問い合わせの値になる（FastAPI など）
        if ! grep -qE 'Query\(|Annotated' <<<"$c" && grep -qE ":[[:space:]]*(int|Optional\[int\])[^=]*=[[:space:]]*[0-9]" <<<"$c" \
           && ! grep -qE '@(router|app|api|bp|blueprint)\.(get|post|put|patch|delete|route|api_route)\(' "$f" 2>/dev/null; then continue; fi
        # 上限の確かめ: その値を小さいほうに寄せる・大きすぎれば弾く・宣言で上限を付ける（le=・@Max・max_value など）
        ub="(min|clamp|coerceAtMost)[[:space:]]*\([^)]*\b${n}\b|\b${n}\b[[:space:]]*(>|>=)[[:space:]]*([1-9][0-9]+|[A-Za-z_.]*[Mm][Aa][Xx])|\ble[[:space:]]*=|\blte[[:space:]]*=|@Max\(|max_value|MaxValue|max_page_size|maxPageSize|MAX_(PAGE|LIMIT|SIZE)|maxLimit"
        if grep -qE "$ub" <<<"$c" || grep -qE "$ub" "$f" 2>/dev/null; then printf '    %s\n' "$l"; else printf '  ★ %s\n' "$l"; fi
      done | lim 25; } | mask | show
echo "  ※ ★ は、読んだ値のまま件数を決めていれば指摘になる（上限を付けるか、上限で切り詰める）。公開の一覧でも「公開だから問題なし」にしない"
echo "    ★ の無い行も、上限の確かめがその値に掛かっているかを読む。ファイルのどこかに上限の書き方があるだけで ★ を外している"

hr "2c. Server Actions の関数ごとのガード（該当する構成のみ）"
# 'use server' のファイルでは、export された関数 1 つ 1 つが入口になる。
# ファイル単位の「定義 N / ガード M」では、どの関数が素通しかまでは分からない。
# 関数の先頭から次の export までを 1 ブロックとして、その中にガードがあるかを見る。
{
  grep -rlE "${EXA[@]}" "^[[:space:]]*['\"]use server['\"]" \
    --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' . 2>/dev/null \
    | grep -vE '^\./(src/)?(components|lib|utils)/' | sort | while IFS= read -r f; do
    echo "  ${f#./}"
    GUARD="$GUARD" awk '
      function flush() {
        if (name != "") {
          printf "    %-40s %s\n", name, (hit ? "ガードあり" : "← ガード検出なし")
        }
      }
      /^[[:space:]]*export[[:space:]]+(async[[:space:]]+)?function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/ {
        flush()
        match($0, /function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
        name = substr($0, RSTART + 9, RLENGTH - 9); hit = 0; next
      }
      /^[[:space:]]*export[[:space:]]+const[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=/ {
        flush()
        match($0, /const[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)
        name = substr($0, RSTART + 6, RLENGTH - 6); hit = 0; next
      }
      name != "" && $0 ~ ENVIRON["GUARD"] { hit = 1 }
      END { flush() }
    ' "$f"
  done
} | show
echo "  ※ 「ガード検出なし」の関数は、本当に公開してよいものか 1 つずつ確かめる。"
echo "    ログイン・ログアウト・公開データの取得のように意図して公開するもの以外は指摘"
echo "  ※ 関数の先頭でガードを呼んでいても、その戻り値を使わずに先へ進んでいれば、ガードになっていない"

hr "2d. ミドルウェアの対象範囲（ここから外れたルートは素通しになる）"
{
  # Next.js 16 で middleware.ts は proxy.ts に改名された。古い名前だけ見ていると見落とす。
  for f in middleware.ts middleware.js src/middleware.ts src/middleware.js \
           proxy.ts proxy.js src/proxy.ts src/proxy.js \
           app/Http/Kernel.php config/middleware.php; do
    [[ -f "$f" ]] || continue
    echo "  $f"
    # 対象範囲の指定。Next.js の matcher、Laravel のミドルウェアグループなど。
    grep -nE 'matcher|middleware(Group|Groups)?|except|only|withoutMiddleware' "$f" 2>/dev/null \
      | lim 15 | sed 's/^/    /'
  done
  # 枠組みによらず、ルートをまとめて保護する書き方
  grep -rnE "${EXA[@]}" \
    'app\.use\(|router\.use\(|Route::(group|middleware)|\.grouped\(|authenticate\(["'"'"'][^"'"'"']*["'"'"']\)[[:space:]]*\{|@Secured|SecurityFilterChain|UseMiddleware' \
    . 2>/dev/null | lim 15
} | show
echo "  ※ 対象範囲の指定は、書き方しだいで簡単に穴が空く。除外や前方一致の指定があれば、"
echo "    2 の表のルート一覧と 1 本ずつ突き合わせる。**外れているルートは自前のガードが要る**"
echo "  ※ ミドルウェアだけに頼る構成は、その仕組みに不具合が出た時点で全ルートが同時に開く。"
echo "    02 の A-5 を参照"

hr "3. 危険な関数"
echo "  --- 出力に HTML を直接流し込む（★ は値を流し込む行。固定の文字列だけを出す行には付けない）---"
# 枠組みごとの「エスケープを外す書き方」の表。1 つの枠組みの書き方しか持たないと、他の枠組みで素通りする。
# 並べるだけだと、固定の文字列を出す行と値を流し込む行が混ざって読み流される（実地の評価で、DB に入った利用者の
# 名前を流し込む行が一覧に出ていたのに、2 回とも台帳に載らなかった）。値を流し込む行に ★ を付けて 1 行ずつ判定させる
UNESC='dangerouslySetInnerHTML|(^|[^A-Za-z0-9_-])v-html[[:space:]]*=|\[innerHTML\][[:space:]]*=|\.(inner|outer)HTML[[:space:]]*=|insertAdjacentHTML[[:space:]]*\(|document\.write(ln)?[[:space:]]*\('
UNESC="$UNESC"'|bypassSecurityTrust(Html|Script|Url|ResourceUrl)[[:space:]]*\(|\{@html[[:space:]]|@Html\.Raw[[:space:]]*\(|\|[[:space:]]*(safe|raw)([^A-Za-z0-9_]|$)'
UNESC="$UNESC"'|\.html_safe|<%=[[:space:]]*raw[[:space:](]|(^|[^.:A-Za-z0-9_])raw[[:space:]]*\(|<%-|\{!!|th:utext|mark_safe[[:space:]]*\(|Markup[[:space:]]*\(|SafeString[[:space:]]*\(|template\.HTML[[:space:]]*\(|\{\{\{|\{\{&'
{
  grep -rnE "${EXA[@]}" --exclude='*.lock' --exclude='*-lock.json' --exclude='*.lockb' "$UNESC" . 2>/dev/null | sed 's|^\./||' \
    | LC_ALL=C awk '
      # s が固定の文字列（式の埋め込みも連結も無い）で始まっていれば 1
      function lit(s,   q, i, c, n, body, rest) {
        sub(/^[ \t(]+/, "", s); q = substr(s, 1, 1); n = length(s)
        if (q != "\"" && q != "\047" && q != "`") return 0
        for (i = 2; i <= n; i++) { c = substr(s, i, 1); if (c == "\\") { i++; continue } if (c == q) break }
        if (i > n) return 0
        body = substr(s, 2, i - 2); if (body ~ /#\{|\$\{/) return 0
        rest = substr(s, i + 1); sub(/^[ \t]+/, "", rest)
        return rest !~ /^(\+|%|\.format|\.concat|\|\|)/
      }
      # .html_safe の手前が固定の文字列か
      function lit_before(pre,   q, j) {
        sub(/[ \t]+$/, "", pre); q = substr(pre, length(pre), 1)
        if (q != "\"" && q != "\047") return 0
        for (j = length(pre) - 1; j >= 1; j--) if (substr(pre, j, 1) == q && substr(pre, j - 1, 1) != "\\") break
        if (j < 1 || substr(pre, j + 1, length(pre) - j - 1) ~ /#\{/) return 0
        pre = substr(pre, 1, j - 1); sub(/[ \t]+$/, "", pre)
        return pre !~ /(\+|<<)$/
      }
      # 属性の値（v-html="…" など）の中身が固定の文字列か
      function lit_attr(s,   q, k) {
        sub(/^[ \t]+/, "", s); q = substr(s, 1, 1)
        if (q != "\"" && q != "\047") return 0
        s = substr(s, 2); k = index(s, q); if (k == 0) return 0
        return lit(substr(s, 1, k - 1))
      }
      function after(re) { return match(c, re) ? substr(c, RSTART + RLENGTH) : "" }
      {
        f = $0; sub(/:.*/, "", f); c = $0; sub(/^[^:]*:[0-9]+:/, "", c); v = 0
        if (c ~ /\.html_safe/) { i = index(c, ".html_safe"); if (!lit_before(substr(c, 1, i - 1))) v = 1 }
        if (c ~ /dangerouslySetInnerHTML/) { if (c !~ /__html[ \t]*:/ || !lit(after("__html[ \t]*:"))) v = 1 }
        if (c ~ /(^|[^A-Za-z0-9_-])v-html[ \t]*=/ && !lit_attr(after("v-html[ \t]*="))) v = 1
        if (c ~ /\[innerHTML\][ \t]*=/ && !lit_attr(after("\\[innerHTML\\][ \t]*="))) v = 1
        if (c ~ /\.(inner|outer)HTML[ \t]*=/ && !lit(after("\\.(inner|outer)HTML[ \t]*=[ \t]*"))) v = 1
        if (c ~ /insertAdjacentHTML[ \t]*\(/) { a = after("insertAdjacentHTML[ \t]*\\([^,]*,"); if (!lit(a)) v = 1 }
        if (c ~ /document\.write(ln)?[ \t]*\(/ && !lit(after("document\\.write(ln)?[ \t]*\\("))) v = 1
        if (c ~ /(bypassSecurityTrust[A-Za-z]+|@Html\.Raw|mark_safe|Markup|SafeString|template\.HTML)[ \t]*\(/ \
            && !lit(after("(bypassSecurityTrust[A-Za-z]+|@Html\\.Raw|mark_safe|Markup|SafeString|template\\.HTML)[ \t]*\\("))) v = 1
        if (c ~ /<%=[ \t]*raw[ \t(]/ && !lit(after("<%=[ \t]*raw[ \t]*"))) v = 1
        if (c ~ /(^|[^.:A-Za-z0-9_])raw[ \t]*\(/ && c !~ /<%=[ \t]*raw/ && !lit(after("(^|[^.:A-Za-z0-9_])raw[ \t]*\\("))) v = 1
        # テンプレートの式そのものを生で出す書き方は、固定の文字列を書くことがまず無いので、すべて値を流し込む側に数える
        if (c ~ /\{@html[ \t]|\|[ \t]*(safe|raw)([^A-Za-z0-9_]|$)|\{!!|th:utext|\{\{\{|\{\{&/) v = 1
        # <%- は EJS では生の出力、ERB では前の空白を詰める記号。ERB のファイルでは数えない
        if (c ~ /<%-/ && f !~ /\.(erb|rhtml)$/) v = 1
        # ERB で <%- にだけ一致した行（出力ではない）は出さない
        if (!v && f ~ /\.(erb|rhtml)$/) { t = c; gsub(/<%-/, "", t); if (t !~ /\.html_safe|raw[ \t(]/) next }
        if (v) star[++ns] = "  ★ " $0; else plain[++np] = "    " $0
      }
      END {
        for (i = 1; i <= ns && i <= 20; i++) print star[i]
        if (ns > 20) printf "  （★ はほか %d 件。全部は元のコマンドを直接実行して見る）\n", ns - 20
        if (np) print "    （以下は固定の文字列だけを出す行）"
        for (i = 1; i <= np && i <= 10; i++) print plain[i]
        if (np > 10) printf "  （ほか %d 件）\n", np - 10
      }'
} | mask | show
echo "  ※ ★ は、流し込む値の出どころを 1 行ずつたどる。リクエストの値だけでなく、利用者が登録して保存された値"
echo "    （名前・プロフィール・投稿・ファイル名）も外部入力（格納型）。無害化の関数を通していなければ指摘になる（07 の 1 節）"

echo "  --- コード・コマンドを組み立てて実行する ---"
{
  # 言語ごとに書き方が違う。1 つの言語の書き方しか持たないと、他の言語で素通りする。
  grep -rnE "${EXA[@]}" '\beval\(|new Function\(|child_process|execSync|spawnSync' . 2>/dev/null | lim 15
  grep -rnE "${EXA[@]}" 'os\.system|subprocess\.|exec\.Command|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start' . 2>/dev/null | lim 15
  grep -rnE "${EXA[@]}" 'shell_exec|passthru[[:space:]]*\(|\bsystem[[:space:]]*\(|popen[[:space:]]*\(|unserialize[[:space:]]*\(|Marshal\.load' . 2>/dev/null | lim 15
} | mask | sort -u | lim 30 | show

echo "  --- SQL を文字列連結で組み立てる ---"
{
  # SQL らしい文字列の直後に連結演算子が来る形。+ (JS/Go/Java/C#) . (PHP) % と .format (Python)
  # || (SQL/PHP) をまとめて見る。言語別に書くと必ず取りこぼす。
  grep -rniE "${EXA[@]}" \
    '(select[[:space:]]+[^;]{0,80}[[:space:]]from[[:space:]]|insert[[:space:]]+into[[:space:]]|update[[:space:]]+[a-z_."'"'"'`]+[[:space:]]+set[[:space:]]|delete[[:space:]]+from[[:space:]]|drop[[:space:]]+table|alter[[:space:]]+table)[^;]{0,120}["'"'"'`]+[[:space:]]*(\+|\.|%|\|\|)[[:space:]]*[a-z_$@(]' \
    . 2>/dev/null | lim 20
  # 埋め込み構文で値を差し込む形。{} は Rust の format! と Python の .format、
  # ${} は JS のテンプレートリテラル、$"" は C# の文字列補間。
  grep -rniE "${EXA[@]}" \
    '(select[[:space:]]+[^;]{0,80}[[:space:]]from[[:space:]]|insert[[:space:]]+into[[:space:]]|update[[:space:]]+[a-z_."'"'"'`]+[[:space:]]+set[[:space:]]|delete[[:space:]]+from[[:space:]])[^;]{0,120}(\{\}|\{[a-z_][a-z0-9_]*\})' \
    . 2>/dev/null | lim 10
  # テンプレートリテラルに式を埋め込む形
  grep -rniE "${EXA[@]}" '(select[[:space:]]+[^`]{0,80}[[:space:]]from[[:space:]]|insert[[:space:]]+into[[:space:]]|update[[:space:]]+[a-z_]+[[:space:]]+set[[:space:]]|delete[[:space:]]+from[[:space:]])[^`]*\$\{' . 2>/dev/null | lim 10
  # 生 SQL を渡す入り口。組み立て方に関わらず、ここは目で読む
  grep -rnE "${EXA[@]}" '\.raw\(|executeSql|jdbcTemplate\.(execute|query)|ExecuteSql|DB::(select|statement|raw)|db\.Query\(|connection\.execute' . 2>/dev/null | lim 15
} | mask | sort -u | lim 30 | show
echo "  ※ 連結が定数だけなら問題ない。外部入力が混ざる経路があるかを 1 件ずつ読む"

hr "3b. ファイルの受け取り（07 の 6 節）"
# 受け取り口は枠組みごとに書き方が違う。表で持ち、どの言語でも同じ見方で並べる。
# 種類の判定は、許す種類を列挙する（許可リスト）のが基本。禁止する種類を列挙する（拒否リスト）と、
# 一覧に無い種類（.html・.svg・.js・サーバーで実行される拡張子・二重拡張子・大文字）がすべて通る
UPLOAD_IN='multer[[:space:]]*\(|fileFilter|busboy|formidable|express-fileupload|(req|request)\.files?([^A-Za-z0-9_]|$)|ctx\.request\.files|@UploadedFiles?\(|FileInterceptor'
UPLOAD_IN="$UPLOAD_IN"'|UploadFile([^A-Za-z0-9_]|$)|request\.FILES|(File|Image)Field[[:space:]]*\(|FileStorage|has_(one|many)_attached|mount_uploader'
UPLOAD_IN="$UPLOAD_IN"'|params(\[:[a-z_]+\])*\[:[a-z_]*(file|upload|avatar|image|attachment|document)[a-z_]*\]|\.original_filename|UploadedFile|MultipartFile|IFormFile|\$_FILES|->file\([[:space:]]*['"'"'"]|move_uploaded_file'
UPLOAD_IN="$UPLOAD_IN"'|FormFile[[:space:]]*\(|ParseMultipartForm|MultipartForm'
DENY_WORD='(block|blocked|deny|denied|forbid|forbidden|disallow|disallowed|black_?list|banned|reject|rejected|dangerous|prohibited|not_?allowed|excluded)'
KIND_WORD='(ext|exts|extension|extensions|suffix|suffixes|mime|mimes|mime_?types?|content_?types?|file_?types?)'
DENY_KIND="${DENY_WORD}[A-Za-z_]*${KIND_WORD}([^A-Za-z0-9]|$)|${KIND_WORD}[A-Za-z_]*${DENY_WORD}"
KIND_CHECK='extname[[:space:]]*\(|splitext[[:space:]]*\(|File\.extname|getOriginalFilename|originalname|original_filename|\.suffix([^A-Za-z0-9_]|$)|PATHINFO_EXTENSION'
KIND_CHECK="$KIND_CHECK"'|getClientOriginalExtension|getClientMimeType|filepath\.Ext[[:space:]]*\(|Path\.GetExtension|\.content_type|\.mimetype|getContentType\(|\.ContentType'
UP_INCL=("${INCL[@]}" --include='*.tsx' --include='*.jsx' --include='*.cjs' --include='*.scala' --include='*.ex' --include='*.exs' --include='*.rs')
UP_FILES="$(grep -rlE "${EXA[@]}" "$UPLOAD_IN" "${UP_INCL[@]}" . 2>/dev/null | sed 's|^\./||' | grep -vE '(^|/)(test|tests|__tests__|spec)/|\.(test|spec)\.[a-z]+$' || true)"
echo "  --- 受け取り口（ここから、種類の判定・保存先・配信のしかたまでを 1 本ずつたどる）---"
{ if [[ -n "$UP_FILES" ]]; then
    printf '%s\n' "$UP_FILES" | while IFS= read -r f; do grep -nE "$UPLOAD_IN" "$f" 2>/dev/null | sed "s|^|  $f:|"; done
  fi; } | mask | lim 25 | show
echo "  --- 禁止する種類を列挙して判定している（一覧に無い種類はすべて通る）---"
# 大小文字を区別せずに候補を拾い、名前の切れ目（_ か大文字）で語が始まるものだけを残す（blockedText を拾わない）
{ grep -rnEi "${EXA[@]}" "$DENY_KIND" "${UP_INCL[@]}" . 2>/dev/null | sed 's|^\./||' \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#|\*)' | grep -vE '(^|/)(test|tests|__tests__|spec)/|\.(test|spec)\.[a-z]+:' \
    | LC_ALL=C awk '
      BEGIN {
        d = "([Bb]lock|BLOCK|[Dd]en[yi]|DEN[YI]|[Ff]orbid|FORBID|[Dd]isallow|DISALLOW|[Bb]lack_?[Ll]ist|BLACK_?LIST|[Bb]anned|BANNED|[Rr]eject|REJECT|[Dd]angerous|DANGEROUS|[Pp]rohibit|PROHIBIT|[Nn]ot_?[Aa]llowed|NOT_?ALLOWED|[Ee]xclud|EXCLUD)"
        k = "(_(exts?|extensions?|suffix(es)?|mimes?|mime_?types?|content_?types?|file_?types?)|Exts?|Extensions?|Suffix(es)?|Mimes?|MimeTypes?|ContentTypes?|FileTypes?|_?(EXTS?|EXTENSIONS?|SUFFIX(ES)?|MIMES?|MIME_?TYPES?|CONTENT_?TYPES?|FILE_?TYPES?))"
        r = "(^|[^A-Za-z])([Ee]xt(ension)?s?|EXT(ENSION)?S?|[Ss]uffix(es)?|SUFFIX(ES)?|[Mm]ime_?[Tt]ypes?|MIME_?TYPES?|[Mm]imes?|MIMES?|[Cc]ontent_?[Tt]ypes?|CONTENT_?TYPES?|[Ff]ile_?[Tt]ypes?|FILE_?TYPES?)"
        rd = "(Block|BLOCK|Den[yi]|DEN[YI]|Forbid|FORBID|Disallow|DISALLOW|Black_?[Ll]ist|BLACK_?LIST|Banned|BANNED|Reject|REJECT|Dangerous|DANGEROUS|Prohibit|PROHIBIT|Not_?Allowed|NOT_?ALLOWED|Exclud|EXCLUD|_(block|den[yi]|forbid|disallow|black_?list|banned|reject|dangerous|prohibit|not_?allowed|exclud))"
        fwd = d "[A-Za-z_]*" k "([^A-Za-z]|$)"; rev = r "_?" rd
      }
      { c = $0; sub(/^[^:]*:[0-9]+:/, "", c); if (c ~ fwd || c ~ rev) print "  ★ " $0 }' | lim 15; } | mask | show
echo "  --- 受け取り口のあるファイルで、拡張子・種類を判定している行 ---"
{ if [[ -n "$UP_FILES" ]]; then
    printf '%s\n' "$UP_FILES" | while IFS= read -r f; do grep -nE "$KIND_CHECK" "$f" 2>/dev/null | sed "s|^|  $f:|"; done
  fi; } | mask | lim 20 | show
echo "  ※ ★ は、拒否リストで種類を判定している。許す種類の一覧（許可リスト）に変えるまで指摘になる"
echo "    拡張子だけ・申告された Content-Type だけの判定は偽装できる。中身を確かめるか、保存先を公開の配信から外す"
echo "    受け取り口があるのに判定の行が 1 つも無ければ、種類を確かめずに受け取っている"

hr "4. 秘密情報のハードコード（値は伏字にして出力する）"
# .env* はローカル専用の設定ファイルで、値が入っているのが正常。
# 中身を出力すると事故になるので、内容の走査からは外し、存在の有無だけを 4c で見る。
# 2 本の grep は同じ行に当たることがある（例: sk_live_ の代入は両方に該当する）。
# 伏字にしたうえで sort -u を通し、同じ行が二重に並ばないようにする。
{
  grep -rniE "${EXA[@]}" --exclude='.env*' \
    '(api[_-]?key|secret|passwd|password|token|private[_-]?key|credential)[A-Za-z_]*[[:space:]]*[:=][[:space:]]*["'"'"'`]?[A-Za-z0-9_/+.=-]{16,}' \
    . 2>/dev/null | grep -viE 'example|sample|dummy|placeholder|your[_-]|xxx|\.md:|test'
  grep -rnE "${EXA[@]}" --exclude='.env*' \
    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}|(AKIA|ASIA)[0-9A-Z]{16}|(sk|rk)_live_|sk-(proj|ant)-|github_pat_|gh[pousr]_[0-9A-Za-z]{20,}|npm_[0-9A-Za-z]{30,}|xox[abprs]-[0-9A-Za-z]|whsec_[0-9A-Za-z]{16,}|sb_secret_|-----BEGIN [A-Z ]*PRIVATE KEY' \
    . 2>/dev/null
} | mask | sort -u | lim 40 | show

hr "4b. クライアントに露出する環境変数（特権鍵が混ざっていないか）"
{
  grep -rhoE "${EXA[@]}" '(NEXT_PUBLIC|NUXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|GATSBY|STORYBOOK|ASTRO_PUBLIC|PUBLIC|VUE_APP|NG_APP|SVELTE_PUBLIC|REMIX_PUBLIC)_[A-Z0-9_]+' . 2>/dev/null | sort -u | sed 's/^/  /'
} | show
echo "  ※ SERVICE_ROLE / SECRET / PRIVATE / ADMIN を含む名前がこの一覧にあれば、その時点で P0 の候補。報告書を待たずに依頼者へ知らせる（SKILL.md の守ること 6）"

hr "4c. .env の混入と gitignore"
{
  find . -maxdepth 3 -name ".env*" -not -path "*/node_modules/*" 2>/dev/null | sed 's/^/  存在: /'
  if git rev-parse --git-dir >/dev/null 2>&1; then
    tracked="$(git ls-files | grep -E '(^|/)\.env' || true)"
    [[ -n "$tracked" ]] && echo "$tracked" | sed 's/^/  【追跡されている】/'
  fi
  [[ -f .gitignore ]] && grep -nE '\.env' .gitignore | sed 's/^/  gitignore: /'
} | show

# --------------------------------------------------------------------------
hr "4d. LLM の鍵がブラウザに出ていないか（従量課金がそのまま攻撃の費用になる）"
{
  grep -rnE "${EXA[@]}" 'dangerouslyAllowBrowser[[:space:]]*:[[:space:]]*true|anthropic-dangerous-direct-browser-access' . 2>/dev/null | lim 10 | mask_keys
  grep -rnoE "${EXA[@]}" '(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE_AI|GROQ|MISTRAL|COHERE|DEEPSEEK|XAI|PERPLEXITY|OPENROUTER|HF_TOKEN|HUGGINGFACE|REPLICATE|TOGETHER|FIREWORKS)[A-Z0-9_]*' \
    . 2>/dev/null | sort -u | lim 10
} | show
echo "  ※ 出ていれば P0 の候補（直接の金銭被害。04 の問い 2）。サーバー側の中継に移す（02 の C-1）"
echo "  ※ Google の AIza… 鍵は、同じプロジェクトで Gemini を有効にすると呼べる API が増える。鍵の API 制限を 03 の 6 節で見る"

# --------------------------------------------------------------------------
hr "5. fail-open な既定値（未設定のとき有効側に倒れるもの）"
{
  grep -rnE "${EXA[@]}" 'process\.env\.[A-Z0-9_]+\s*!==\s*["'"'"']false["'"'"']' . 2>/dev/null | lim 20
  grep -rnE "${EXA[@]}" 'process\.env\.[A-Z0-9_]+\s*\|\|\s*(true|["'"'"']true)' . 2>/dev/null | lim 20
  grep -rnE "${EXA[@]}" 'getenv\([^)]+\)\s*!=\s*["'"'"']false' . 2>/dev/null | lim 20
} | show
echo "  ※ 検出されたら、その変数が実機で設定されているかを実機確認で確かめる"

# --------------------------------------------------------------------------
hr "6. 開発用の抜け道"
{
  find . -path "*dev*login*" -o -path "*debug*" -o -path "*mock*" 2>/dev/null \
    | grep -vE '(^|/)(node_modules|\.git|dist|build|\.next|vendor|target)(/|$)' | lim 20 | sed 's/^/  /'
  grep -rnE "${EXA[@]}" 'NODE_ENV\s*[!=]==?\s*["'"'"'](production|development)|DEBUG\s*=|SKIP_AUTH|BYPASS' . 2>/dev/null | lim 20
} | mask | show
echo "  ※ 見つかったパスは実機確認で本番へリクエストする（期待値 404 / 403）"

# --------------------------------------------------------------------------
hr "7. git 履歴中の鍵らしき文字列"
if git rev-parse --git-dir >/dev/null 2>&1; then
  {
    git log --all -p 2>/dev/null \
      | grep -niE '^\+.*((api[_-]?key|secret|password|token|credential)[A-Za-z_]*[[:space:]]*[:=][[:space:]]*["'"'"'`]?[A-Za-z0-9_/+.=-]{16,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ|(AKIA|ASIA)[0-9A-Z]{16}|(sk|rk)_live_|sk-(proj|ant)-|github_pat_|gh[pousr]_[0-9A-Za-z]{20,}|npm_[0-9A-Za-z]{30,}|sb_secret_|-----BEGIN [A-Z ]*PRIVATE KEY)' \
      | grep -viE 'example|sample|dummy|placeholder|your[_-]|xxx' | lim 20 | mask
  } | show
  echo "  ※ 該当があれば、現在のコードから消えていても漏れている。鍵の失効が必要"
else
  echo "  （git リポジトリではない）"
fi

# --------------------------------------------------------------------------
hr "8. コードが参照するテーブル／コレクション名"
{
  # ORM ごとに書き方が違う。from( collection( table( だけでなく、
  # SQL 文字列の from 句からも拾う（Go / Java / C# のように ORM を使わない構成のため）。
  grep -rhoE "${EXA[@]}" '(from|collection|table|into|Table)\(["'"'"'`][a-zA-Z_][a-zA-Z0-9_]*["'"'"'`]\)' . 2>/dev/null \
    | sed -E 's/^[A-Za-z]+\(["'"'"'`]//; s/["'"'"'`]\)$//' | sort -u | sed 's/^/  /'
  grep -rhoiE "${EXA[@]}" '(from|join|into|update)[[:space:]]+[a-z_][a-z0-9_]{2,}' . 2>/dev/null \
    | awk '{print tolower($2)}' \
    | grep -vE '^(the|this|that|a|an|it|them|here|there|where|select|import|require|node_modules|auth|https?|public|storage|your|our|my|each|all|any|which|what|scratch|memory|file|files|source|disk|cache|now|date|dual)$' \
    | sort -u | lim 40 | sed 's/^/  /'
} | show
echo "  ※ マイグレーション／スキーマ定義に無いものは、本番の設定が不明。実機確認で先に見る（03 の 1 節）"

# --------------------------------------------------------------------------
hr "9. 第三者タグと同意管理（法令遵守の検討材料）"

echo "  --- 計測・広告タグの読み込み箇所 ---"
{
  grep -rnE "${EXA[@]}" "$TAGPAT" \
    --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
    --include='*.vue' --include='*.svelte' --include='*.html' --include='*.astro' --include='*.php' \
    --include='*.erb' --include='*.twig' --include='*.liquid' . 2>/dev/null | lim 20
} | mask | show

echo "  --- 共通レイアウトに入っていないか（入っていれば全ページで発火する）---"
{
  # 共通レイアウトの置き場所は枠組みごとに違う。1 つの枠組みの名前だけを見ると、
  # 「全ページで発火している」ことに気づけない。
  for f in app/layout.tsx src/app/layout.tsx app/layout.js src/app/layout.js \
           pages/_app.tsx src/pages/_app.tsx pages/_document.tsx \
           app/root.tsx app/root.jsx \
           src/routes/+layout.svelte src/routes/+layout.server.ts \
           app.vue layouts/default.vue src/App.vue src/app.html \
           resources/views/layouts/app.blade.php resources/views/app.blade.php \
           app/views/layouts/application.html.erb \
           templates/base.html templates/layout.html \
           src/main/resources/templates/layout.html \
           index.html public/index.html src/index.html; do
    [[ -f "$f" ]] || continue
    hits="$(grep -cE "$TAGPAT" "$f" 2>/dev/null | head -1)"; hits="${hits:-0}"
    [[ "$hits" != "0" ]] && printf '    %-34s タグらしき記述 %s 行\n' "$f" "$hits"
  done
} | show
echo "  ※ ここに出たものは、管理画面やログイン画面にも読み込まれる。02 の L 節を参照"

echo "  --- 同意管理（CMP）の実装 ---"
{
  grep -rniE "${EXA[@]}" \
    '__tcfapi|cookiebot|onetrust|usercentrics|trustarc|klaro|osano|cookieconsent|gtag\(.{0,3}consent' \
    --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.html' . 2>/dev/null | lim 10
} | show
echo "  ※ フォームの第三者提供同意（third_party_consent 等）は Cookie の同意とは別物。混同しない"
echo "  ※ 詳しくは references/08-privacy-compliance.md。実際の発火は scripts/recon.sh で本番を見る"

echo "  --- 公開している文書（実装との突き合わせ対象）---"
{
  find . -path ./node_modules -prune -o \( -ipath '*privacy*' -o -ipath '*policy*' -o -ipath '*terms*' -o -ipath '*tokushoho*' -o -ipath '*legal*' \) -type f -print 2>/dev/null \
    | grep -vE 'node_modules|\.git' | lim 10 | sed 's/^/    /'
} | show

# --------------------------------------------------------------------------
if [[ -n "$replay" ]]; then
  hr "9b. 画面操作を記録するツール（セッションリプレイ。08 の 1-2）"
  echo "  --- 使っているツールと初期化の場所 ---"
  {
    grep -rnE "${EXA[@]}" "$REPLAYPAT" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
      --include='*.vue' --include='*.svelte' --include='*.html' --include='package.json' . 2>/dev/null | lim 12 | mask
  } | show
  echo "  --- マスクを緩める・通信の本文を記録する設定（1 件ずつ読む）---"
  {
    grep -rnE "${EXA[@]}" 'maskAllText:[[:space:]]*false|maskAllInputs:[[:space:]]*false|blockAllMedia:[[:space:]]*false|unmask:|unblock:|networkDetailAllowUrls|networkCaptureBodies|networkRequestHeaders|networkResponseHeaders|sentry-unmask|data-clarity-unmask|data-hj-(allow|whitelist)|fs-unmask|inputSanitizer:[[:space:]]*false|textSanitizer:[[:space:]]*false|recordHeaders|recordBody|enable_recording_console_log|defaultPrivacyLevel|dd-privacy-allow' \
      . 2>/dev/null | lim 12
  } | show
  echo "  --- 利用者の特定（送信先で個人データと結び付く）---"
  {
    grep -rnE "${EXA[@]}" "Sentry\.setUser|LogRocket\.identify|FS\.identify|FullStory\.identify|posthog\.identify|clarity\(['\"](identify|set)|hj\(['\"]identify|datadogRum\.setUser" \
      . 2>/dev/null | lim 10
  } | show
  echo "  --- 自社ドメインを経由させる設定（送信先のドメインで数えると見えなくなる）---"
  {
    grep -rnE "${EXA[@]}" 'tunnel:|tunnelRoute|api_host|/ingest' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' . 2>/dev/null | lim 5
  } | show
  echo "  ※ 何が記録されたかは、ツールの管理画面で録画を再生しないと分からない。依頼者に確かめてもらう（08 の 1-2）"
  echo "  ※ 既定の記録範囲はツールで大きく違う（Sentry は全部マスク、LogRocket はマスクしない、Clarity は数字とメールだけ）"
fi

# --------------------------------------------------------------------------
hr "10. 認証トークンの検証（署名を見ずに中身だけ取り出していないか）"
echo "  --- 検証せずに復号しているもの（ここが穴になる）---"
{
  grep -rnE "${EXA[@]}" 'jwt\.decode\(|jwtDecode\(|decodeJwt\(|decode_token\(' . 2>/dev/null | lim 15
} | show
echo "  --- 検証しているもの ---"
{
  grep -rnE "${EXA[@]}" 'jwt\.verify\(|jwtVerify\(|verifyIdToken\(|createRemoteJWKSet|decode\([^)]*verify' . 2>/dev/null | lim 15
} | show
echo "  ※ decode だけなら署名を見ていない。role を書き換えたトークンが通る。02 の B-4 を参照"

hr "10b. サーバー側でセッションを検証せずに信じていないか"
echo "  --- Supabase: サーバー側の getSession()（Cookie の中身を検証せずに返す。公式が非推奨）---"
{
  grep -rlE "${EXA[@]}" 'auth\.getSession\(' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' . 2>/dev/null \
    | while IFS= read -r f; do
        grep -qE "^[[:space:]]*['\"]use client['\"]" "$f" && continue
        grep -nE 'auth\.getSession\(' "$f" | sed "s|^|  $f:|"
      done
} | show
echo "  ※ proxy / middleware / Route Handler / Server Action で認可に使っていれば指摘。getClaims() か getUser() で検証する（02 の B-2）"

echo "  --- Server Actions の送信元の許可（'null' やワイルドカードがあれば CSRF の防御が緩む）---"
{
  grep -HnE -A4 'allowedOrigins' next.config.* 2>/dev/null | grep -vE '^[^:]+[-:][0-9]+[-:][[:space:]]*(//|\*|/\*)' \
    | grep -E "\*|'null'|\"null\"" | lim 10
} | show

echo "  --- Host ヘッダから URL を組み立てていないか（再設定リンクの乗っ取り・SSRF）---"
{
  grep -rnE "${EXA[@]}" "\.get\(['\"](host|x-forwarded-host)['\"]\)|headers\.host|headers\[['\"](host|x-forwarded-host)['\"]\]|request\.host\b|getHeader\(['\"]host" \
    . 2>/dev/null | lim 10
} | show
echo "  ※ メールに載せる URL を組み立てていれば指摘。固定の設定値から組み立てる（02 の B-3）"

hr "11. Webhook の受け口と署名検証"
echo "  --- 受け口 ---"
{
  find . \( -path '*webhook*' -o -path '*hooks*' -o -path '*callback*' \) -name 'route.*' \
    -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | lim 15 | sed 's/^/  /'
  grep -rlnE "${EXA[@]}" 'webhook|/hooks?/' --include='*.py' . 2>/dev/null | lim 10 | sed 's/^/  /'
} | show
echo "  --- 署名検証らしき処理 ---"
{
  grep -rnE "${EXA[@]}" 'constructEvent|verifySignature|createHmac|hmac\.new|compare_digest|timingSafeEqual' . 2>/dev/null | lim 15
} | show
echo "  ※ 受け口があって検証が無ければ、誰でも通知を投げられる。02 の M を参照"
echo "  ※ シークレット未設定のときに検証を飛ばしていないかは、目で読んで確かめる"

hr "12. 例外の握りつぶし（認可・認証の周りにあれば優先度を上げる）"
{
  grep -rnE "${EXA[@]}" 'catch[^{]*\{[[:space:]]*\}|except[^:]*:[[:space:]]*pass' . 2>/dev/null | lim 20
} | show
echo "  ※ 検証が例外で落ちても先へ進む形は、検証していないのと同じ。02 の K-2 を参照"

hr "13. 乱数と暗号"
echo "  --- 予測できる乱数（トークンや ID に使っていれば指摘）---"
{
  grep -rnE "${EXA[@]}" \
    'Math\.random\(|\brandom\.random\(|\brandom\.randint\(|\brand\(\)|mt_rand\(|uniqid\(|new Random\(\)' \
    . 2>/dev/null | lim 20
} | show
echo "  --- 暗号として使える乱数（こちらが使われていれば問題なし）---"
{
  grep -rnE "${EXA[@]}" \
    'crypto\.randomBytes|crypto\.randomUUID|getRandomValues|secrets\.token|SecureRandom|random_bytes|randomUUID' \
    . 2>/dev/null | lim 10
} | show
echo "  ※ 画面の見た目に使う乱数は問題ない。何に使われているかを追ってから起票する"
echo "  ※ 再設定トークン・セッション ID・招待コードに使われていれば、それだけで指摘"

echo "  --- パスワードのハッシュと暗号の使い方 ---"
{
  grep -rniE "${EXA[@]}" 'bcrypt|argon2|scrypt|pbkdf2|createHash\(|hashlib\.|MessageDigest' . 2>/dev/null | lim 15
  grep -rniE "${EXA[@]}" 'md5|sha1[^0-9]|ECB|createCipheriv?\(|Cipher\.getInstance' . 2>/dev/null | lim 15
} | mask | sort -u | lim 25 | show
echo "  ※ MD5 / SHA-1 / ECB が出たら、何に使っているかを読む。02 の N 節を参照"

hr "14. 通信の保護（証明書の検証を切っていないか）"
{
  grep -rnE "${EXA[@]}" \
    'rejectUnauthorized[[:space:]]*:[[:space:]]*false|verify[[:space:]]*=[[:space:]]*False|InsecureSkipVerify[[:space:]]*:[[:space:]]*true|CURLOPT_SSL_VERIFYPEER[[:space:]]*,[[:space:]]*(false|0)|NODE_TLS_REJECT_UNAUTHORIZED|ServerCertificateValidationCallback|curl[[:space:]]+-k\b|--insecure' \
    . 2>/dev/null | lim 15
} | show
echo "  ※ 「動かないからとりあえず無効化」がそのまま残る。環境で分岐していても本番の値を実機で確かめる"
{
  grep -rnE "${EXA[@]}" 'http://[a-z0-9.-]+' --include='*.ts' --include='*.js' --include='*.py' \
    --include='*.go' --include='*.php' --include='*.java' . 2>/dev/null \
    | grep -vE 'localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org|net)|schemas?\.|www\.w3\.org|xmlns' | lim 10
} | show
echo "  ※ 平文の宛先。内部通信でも、経路が信頼できるかを確かめる"

hr "15. XML を解析しているか（該当すれば XXE を見る）"
{
  grep -rnE "${EXA[@]}" \
    'DocumentBuilder|SAXParser|XMLReader|etree|lxml|libxml|SimpleXML|XmlDocument|xml2js|xml-js|parseXml' \
    . 2>/dev/null | lim 15
} | show
echo "  ※ 該当すれば references/07-web-vulnerabilities.md の 6-2 を読む。JSON だけなら不要"

hr "16. アプリ自身が LLM を呼んでいるか"
{
  grep -rlnE "${EXA[@]}" 'anthropic|openai|@ai-sdk|langchain|llamaindex|generativeai|bedrock-runtime' \
    --include='package.json' --include='requirements.txt' --include='pyproject.toml' . 2>/dev/null | sed 's/^/  /'
  grep -rlnE "${EXA[@]}" 'modelcontextprotocol|mcp[_-]server' . 2>/dev/null | lim 5 | sed 's/^/  /'
} | show
echo "  ※ 該当すれば references/12-ai-features.md を読む。ツールを実行する構成なら必読"
echo "  ※ 「AI で開発した」ことと「AI を動かしている」ことは別物。ここで見るのは後者"

# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# 以下は 0 節の判定で該当したときだけ出す。対象に無い技術の見出しを並べても、
# 「確認したつもり」を増やすだけになる。
if [[ -n "$iac" ]]; then
  hr "17. インフラの定義（references/13-infrastructure.md）"

  if [[ -n "$(ls Dockerfile* 2>/dev/null)" || -n "$(ls docker-compose*.y*ml compose.y*ml 2>/dev/null)" ]]; then
    echo "  --- コンテナ: 実行時の権限 ---"
    {
      for f in Dockerfile*; do
        [[ -f "$f" ]] || continue
        if grep -qE '^USER[[:space:]]' "$f" 2>/dev/null; then
          grep -nE '^USER[[:space:]]' "$f" | sed "s|^|  $f:|"
        else
          echo "  $f: ★ USER の指定が無い（root で動く）"
        fi
      done
      grep -nE 'privileged|cap_add|/var/run/docker\.sock|network_mode:[[:space:]]*host' \
        docker-compose*.y*ml compose*.y*ml 2>/dev/null
    } | show

    echo "  --- コンテナ: イメージに焼き込まれるもの ---"
    {
      grep -nE '^(ARG|ENV)[[:space:]].*(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)' Dockerfile* 2>/dev/null | mask
      grep -nE '^FROM[[:space:]].*:latest|^FROM[[:space:]][^:]+$' Dockerfile* 2>/dev/null \
        | sed 's/$/   ← 版が固定されていない/'
    } | show
    [[ -f .dockerignore ]] && echo "  .dockerignore: 有" \
      || echo "  ★ .dockerignore が無い。.env や .git がイメージに入る"
  fi

  if [[ -n "$(find . -maxdepth 3 -name '*.tf' -not -path '*/.git/*' 2>/dev/null | head -1)" ]]; then
    echo "  --- クラウド資源: 公開範囲と権限 ---"
    {
      grep -rnE "${EXA[@]}" '0\.0\.0\.0/0|::/0|public-read|allUsers|allAuthenticatedUsers' \
        --include='*.tf' --include='*.json' --include='*.y*ml' . 2>/dev/null | lim 15
      grep -rnE "${EXA[@]}" '"?Action"?[[:space:]]*[:=][[:space:]]*"\*"|"?Resource"?[[:space:]]*[:=][[:space:]]*"\*"|roles/owner' \
        --include='*.tf' --include='*.json' . 2>/dev/null | lim 10
    } | show
    echo "  ※ 意図した公開もある（静的サイトの配信）。用途を確かめてから起票する"

    echo "  --- 状態ファイル（生成された秘密が平文で入る）---"
    {
      find . -name '*.tfstate*' -not -path '*/.git/*' 2>/dev/null | sed 's/^/  存在: /'
      if git rev-parse --git-dir >/dev/null 2>&1; then
        t="$(git log --all --oneline -- '*.tfstate' 2>/dev/null | lim 3)"
        [[ -n "$t" ]] && echo "$t" | sed 's/^/  【履歴にある】/'
      fi
    } | show
    echo "  ※ 履歴に一度でも入っていれば、そこに書かれた鍵は失効が要る"
  fi

  if [[ -n "$(grep -rlE '^kind:[[:space:]]*(Deployment|Service|Ingress|Secret)' --include='*.y*ml' . 2>/dev/null | head -1)" ]]; then
    echo "  --- Kubernetes ---"
    {
      grep -rnE "${EXA[@]}" '^kind:[[:space:]]*Secret|privileged:[[:space:]]*true|hostNetwork:[[:space:]]*true|runAsUser:[[:space:]]*0' \
        --include='*.y*ml' . 2>/dev/null | lim 10
    } | show
    if grep -rlE '^kind:[[:space:]]*NetworkPolicy' --include='*.y*ml' . >/dev/null 2>&1; then
      echo "  NetworkPolicy: 有"
    else
      echo "  ★ NetworkPolicy が無い。どのポッドからどのポッドへも通る"
    fi
    echo "  ※ Secret は base64 であって暗号化ではない。マニフェストにある値は平文と同じ扱い"
  fi
fi

if [[ -n "$mob" ]]; then
  hr "18. モバイルアプリ（references/14-mobile.md）"

  echo "  --- 端末に何を保存しているか ---"
  {
    grep -rnE "${EXA[@]}" 'AsyncStorage|SharedPreferences|UserDefaults|NSUserDefaults' . 2>/dev/null | lim 12
  } | show
  echo "  ※ 上は平文で残る置き場。認証トークンやパスワードを置いていれば指摘"
  {
    grep -rnE "${EXA[@]}" 'Keychain|SecureStore|EncryptedSharedPreferences|FlutterSecureStorage' . 2>/dev/null | lim 8
  } | show
  echo "  ※ 上は資格情報の置き場として意図されたもの。使われていれば問題なし"

  echo "  --- 通信 ---"
  {
    grep -rnE "${EXA[@]}" 'usesCleartextTraffic|cleartextTrafficPermitted|NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads' \
      . 2>/dev/null | lim 10
    grep -rnE "${EXA[@]}" 'allowInvalidCertificates|trustAllCerts|X509TrustManager|setHostnameVerifier|badCertificateCallback' \
      . 2>/dev/null | lim 10
  } | show

  echo "  --- 端末との境界（外から入ってくる経路）---"
  {
    grep -rnE "${EXA[@]}" 'android:scheme|CFBundleURLSchemes|intent-filter|associatedDomains' . 2>/dev/null | lim 10
    grep -rnE "${EXA[@]}" 'addJavascriptInterface|WKWebView|javaScriptEnabled|allowFileAccess|exported="true"' . 2>/dev/null | lim 10
  } | show
  echo "  ※ ディープリンクで受けた値を検証しているか。WebView に任意の URL を読ませていないか"

  echo "  --- 権限と配布物に残るもの ---"
  {
    grep -rhoE "${EXA[@]}" 'android\.permission\.[A-Z_]+' . 2>/dev/null | sort -u | lim 20 | sed 's/^/  /'
    grep -rnE "${EXA[@]}" 'android:debuggable[[:space:]]*=[[:space:]]*"true"|android:allowBackup[[:space:]]*=[[:space:]]*"true"' . 2>/dev/null | lim 5
  } | show
  echo "  ※ 機能に対して過剰な権限が無いか。debuggable が本番に残っていないか"
  echo "  ※ 難読化・改竄検知の不在は、単独で挙げない。時間稼ぎであって防御ではない"
fi

if [[ -n "$baas" ]]; then
  hr "19. マネージドの基盤（BaaS）の設定（02 の E 節・03 の 1 節）"

  OLDIFS="$IFS"
  if [[ "$baas" == *Supabase* ]]; then
    # パスに空白があっても分割されないよう、この塊の間だけ改行でだけ区切る（グロブの展開も止める）
    IFS=$'\n'; set -f
    sqlfiles="$(find . \( -path '*/supabase/migrations/*.sql' -o -path '*/supabase/schemas/*.sql' -o -name 'schema.sql' \) \
                 -not -path '*/node_modules/*' 2>/dev/null)"
    # 空のまま grep に渡すと標準入力を待つ。無ければ空のファイルを渡す
    [[ -z "$sqlfiles" ]] && sqlfiles=/dev/null
    # SQL を「1 文 1 行」にする。コメントを落とし、改行をまたぐ文（2 行に分けた alter など）を 1 行にまとめる。
    # 関数の本体（$$ の中）の ; でも切れるので、本体の中の create table は拾いうる（目で読む）
    sqlstmts() { local f; for f in "$@"; do sed -E 's/--.*$//' "$f"; echo ';'; done | tr '\n' ' ' \
                 | sed -E 's#/\*([^*]|\*[^/])*\*/##g' | tr ';' '\n'; }
    echo "  --- Supabase: マイグレーションで作ったのに RLS を有効にしていないテーブル ---"
    echo "      （ダッシュボードで作ると既定で有効、SQL で作ると無効のまま）"
    {
      if [[ -n "$sqlfiles" ]]; then
        # 名前を正規化して突き合わせる（スキーマ省略時は public、引用符と大文字小文字を外す）
        norm() { tr 'A-Z' 'a-z' | tr -d '"' | sed -E 's/^([a-z0-9_]+)$/public.\1/'; }
        # shellcheck disable=SC2086
        created="$(sqlstmts $sqlfiles | grep -oiE 'create[[:space:]]+(unlogged[[:space:]]+)?table[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?"?[A-Za-z0-9_]+"?(\."?[A-Za-z0-9_]+"?)?' \
                   | awk '{print $NF}' | norm | sort -u)"
        # shellcheck disable=SC2086
        enabled="$(sqlstmts $sqlfiles | grep -oiE 'alter[[:space:]]+table[[:space:]]+(only[[:space:]]+)?(if[[:space:]]+exists[[:space:]]+)?"?[A-Za-z0-9_]+"?(\."?[A-Za-z0-9_]+"?)?[[:space:]]+enable[[:space:]]+row[[:space:]]+level[[:space:]]+security' \
                   | awk '{for(i=1;i<=NF;i++) if(tolower($i)=="enable") print $(i-1)}' | norm | sort -u)"
        comm -23 <(printf '%s\n' "$created" | grep -v '^$') <(printf '%s\n' "$enabled" | grep -v '^$') \
          | grep -vE '^(auth|storage|extensions|realtime|supabase_[a-z_]+|private|internal)\.' | sed 's/^/  ★ /'
      fi
    } | show
    echo "  ※ API に出ないスキーマ（private など）に置いたテーブルは除いている。公開スキーマの設定は 03 の 1 節で確かめる"

    echo "  --- Supabase: 定義者権限（security definer）の関数で search_path を固定していないもの ---"
    {
      # 別の文で alter function … set search_path している関数は、固定したものとして扱う
      # shellcheck disable=SC2086
      fixed="$(sqlstmts $sqlfiles | grep -iE 'alter[[:space:]]+function' | grep -iE 'set[[:space:]]+search_path' \
               | sed -E 's/.*[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn][[:space:]]+([^([:space:]]+).*/\1/' | tr 'A-Z' 'a-z' | tr -d '"' | tr '\n' ' ')"
      for f in $sqlfiles; do
        # コメントを落としてから読む（コメントの中の security definer / search_path に惑わされない）。
        # 関数の終わり（本体の $$ を 2 つ数えたあとの ;）で状態を捨て、次の関数へ持ち越さない
        sed -E 's/--.*$//' "$f" | awk -v F="$f" -v FIXED=" $fixed " '
          function flush() {
            if (name != "" && sd && !sp && index(FIXED, " " tolower(name) " ") == 0)
              printf "  ★ %s: %s（search_path の固定なし）\n", F, name
            name=""; sd=0; sp=0; dq=0 }
          tolower($0) ~ /create[[:space:]]+(or[[:space:]]+replace[[:space:]]+)?function/ {
            flush(); line=$0; sub(/.*[Ff][Uu][Nn][Cc][Tt][Ii][Oo][Nn][[:space:]]+/, "", line); sub(/\(.*/, "", line); gsub(/"/, "", line); name=line }
          name != "" && tolower($0) ~ /security[[:space:]]+definer/ { sd=1 }
          name != "" && tolower($0) ~ /search_path/ { sp=1 }
          name != "" { dq += gsub(/\$\$/, "&") }
          name != "" && dq >= 2 && /;/ { flush() }
          END { flush() }'
      done
      grep -nHiE 'security[[:space:]]+definer' $sqlfiles 2>/dev/null | lim 15 | sed 's/^/  定義者権限: /'
    } | show
    echo "  ※ 公開スキーマの定義者権限の関数は、ログイン済みの誰からでも RPC で呼べる。中で呼び出し元を確かめているかを読む"

    echo "  --- Supabase: ビュー（security_invoker の無いものは RLS を迂回する）とマテリアライズドビュー ---"
    {
      # 文単位で読む（with (security_invoker …) が次の行にあっても拾う）。false / off は付けていないのと同じ
      for f in $sqlfiles; do
        sqlstmts "$f" | grep -iE 'create[[:space:]]+(or[[:space:]]+replace[[:space:]]+)?view' \
          | grep -viE 'security_invoker[[:space:]]*=[[:space:]]*(true|on|1|yes)' \
          | sed -E 's/.*[Vv][Ii][Ee][Ww][[:space:]]+([^([:space:]]+).*/\1/' | tr -d '"' \
          | grep -viE '^(auth|storage|extensions|realtime|private|internal)\.' | sed "s|^|  ★ security_invoker なし: $f: |"
      done
      grep -nHiE 'create[[:space:]]+materialized[[:space:]]+view' $sqlfiles 2>/dev/null | sed 's/^/  ★ RLS が適用されない: /'
    } | show

    echo "  --- Supabase: 利用者が書き換えられる値で認可していないか・公開バケット ---"
    {
      grep -nHiE 'user_meta_?data|raw_user_meta' $sqlfiles 2>/dev/null | grep -iE 'policy|using|check|role|admin' | lim 10 \
        | sed 's/^/  ★ user_metadata を認可に使っている: /'
      grep -nHiE 'storage\.buckets' $sqlfiles 2>/dev/null | grep -iE 'true' | lim 10 | sed 's/^/  公開バケットの疑い: /'
    } | show

    echo "  --- Supabase: JWT の検証を外した Edge Functions（中で自前の認証か署名検証が要る）---"
    {
      find . -name 'config.toml' -path '*supabase*' -not -path '*/node_modules/*' 2>/dev/null | while IFS= read -r c; do
        awk -v C="$c" '/^\[functions\./{fn=$0; gsub(/^\[functions\.|\]$/,"",fn)} /verify_jwt[[:space:]]*=[[:space:]]*false/{printf "  ★ %s: %s\n", C, fn}' "$c"
      done
    } | show
    echo "  ※ 実機の RLS・GRANT・Security Advisor の結果は 03 の 1 節。コードに無いテーブルは実機でしか分からない"
  fi

  IFS="$OLDIFS"; set +f
  if [[ "$baas" == *Firebase* ]]; then
    echo "  --- Firebase: セキュリティルール ---"
    {
      find . \( -name 'firestore.rules' -o -name 'storage.rules' -o -name 'database.rules.json' \) -not -path '*/node_modules/*' 2>/dev/null | while IFS= read -r r; do
        # コメント行（// で始まる）は除く。; の省略と、Realtime Database の文字列の "true" も拾う
        nc() { grep -nE "$1" "$r" | grep -vE '^[0-9]+:[[:space:]]*//'; }
        nc 'if[[:space:]]+true[[:space:]]*(;|$)|allow[[:space:]]+[a-z, ]+;|"\.(read|write)"[[:space:]]*:[[:space:]]*"?true"?' | sed "s|^|  ★ 誰でも: $r:|"
        nc 'request\.time[[:space:]]*<[[:space:]]*timestamp' | sed "s|^|  ★ テストモードの期限付き: $r:|"
        nc 'if[[:space:]]+request\.auth(\.uid)?[[:space:]]*!=[[:space:]]*null[[:space:]]*;?[[:space:]]*$' | sed "s|^|  ログイン済みなら誰でも: $r:|"
        nc '"\.(read|write)"[[:space:]]*:[[:space:]]*"auth[[:space:]]*!=[[:space:]]*null"' | sed "s|^|  ログイン済みなら誰でも: $r:|"
      done
    } | show
    echo "  ※ 「ログイン済みなら誰でも」は、所有者の照合が無ければ他人のデータに届く。App Check はルールの代わりにならない"
  fi

  if [[ "$baas" == *Clerk* ]]; then
    echo "  --- Clerk: 何も保護しないミドルウェア ---"
    {
      grep -rnE "${EXA[@]}" 'clerkMiddleware\(\)' . 2>/dev/null | lim 5 | sed 's/$/   ← 既定では何も保護しない/'
    } | show
    echo "  ※ Route Handler と Server Action の中で auth() を確かめているかは 2 節・2c 節で見る"
  fi

  if [[ "$baas" == *Convex* ]]; then
    echo "  --- Convex: 公開の query / mutation / action と、認証の確認 ---"
    {
      # 関数ごとに見る。1 ファイルに確かめる関数と確かめない関数が混ざっていることがある
      find convex -name '*.ts' -not -path '*/_generated/*' 2>/dev/null | while IFS= read -r f; do
        awk -v F="$f" '
          function flush() { if (name != "") printf "  %s: %-20s %s\n", F, name, (ok ? "認証の確認あり" : "★ 認証の確認なし"); name=""; ok=0 }
          /export[[:space:]]+const[[:space:]]+[A-Za-z0-9_]+[[:space:]]*=[[:space:]]*/ {
            flush()
            if ($0 ~ /=[[:space:]]*(query|mutation|action)\(/) { n=$0; sub(/.*export[[:space:]]+const[[:space:]]+/, "", n); sub(/[[:space:]]*=.*/, "", n); name=n }
          }
          name != "" && /getUserIdentity|getAuthUserId|ctx\.auth/ { ok=1 }
          END { flush() }' "$f"
      done
    } | show
    echo "  ※ 公開の関数は誰でも呼べる。内部からだけ呼ぶものは internalQuery / internalMutation にする"
  fi
fi

if [[ -d .github/workflows ]]; then
  hr "20. CI の定義（.github/workflows。秘密情報と本番への権限を持つ。10 の 3-3）"
  W=.github/workflows
  echo "  --- 版を固定していない Action（40 桁のハッシュ以外）---"
  {
    # 引用符で囲んだハッシュ固定と、ダイジェスト固定の docker:// は除く
    grep -rnE 'uses:[[:space:]]*["'"'"']?[^[:space:]#]+@' "$W" 2>/dev/null | grep -vE '@[0-9a-f]{40}["'"'"']?([[:space:]]|$)' \
      | grep -vE 'uses:[[:space:]]*["'"'"']?\./|@sha256:' | lim 20
  } | show
  echo "  --- 他人のコードが秘密情報と同居しうるトリガー ---"
  {
    grep -rnE 'pull_request_target|workflow_run|issue_comment' "$W" 2>/dev/null
    grep -rnE 'allow-unsafe-pr-checkout|cache-mode:|head\.(sha|ref)|refs/pull/|gh pr checkout' "$W" 2>/dev/null
  } | show
  echo "  --- 外部から来る文字列の \${{ }} 展開（run: | の複数行や github-script の中ならシェル・JS への注入）---"
  {
    # 利用者が自由に書ける値だけに絞る（head.sha のような 16 進の値は注入に使えない）
    grep -rnE '\$\{\{[[:space:]]*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|commits\.[^}]*(message|author)|head_commit\.(message|author))|github\.head_ref)' \
      "$W" 2>/dev/null
  } | show
  echo "  ※ run: や script: の中にあれば指摘。with: の引数として渡しているだけなら問題ない"
  echo "  --- 権限と秘密情報 ---"
  {
    for f in "$W"/*.y*ml; do
      [[ -f "$f" ]] || continue
      grep -qE '^permissions:' "$f" || echo "  ★ $f: トップレベルの permissions が無い（既定の権限で動く）"
    done
    grep -rnE 'permissions:[[:space:]]*write-all|id-token:[[:space:]]*write' "$W" 2>/dev/null
    grep -rnE '(echo|printf|cat|tee).*\$\{\{[[:space:]]*secrets\.|toJSON\(secrets\)|secrets:[[:space:]]*inherit' "$W" 2>/dev/null
  } | show
  echo "  --- 依存の入れ方（npm install はロックファイルを書き換えて進む）---"
  {
    # npm install -g（道具の導入）と、CI で既定がロックファイルを変えない pnpm は除く
    grep -rnE 'npm (install|i)([[:space:]]|$)|yarn install[[:space:]]*$' "$W" 2>/dev/null \
      | grep -vE -- '--frozen-lockfile|--immutable|[[:space:]](-g|--global)([[:space:]]|$)' | lim 5
  } | show
  echo "  ※ 組織の設定（SHA 固定の強制、実行できる人とイベントの制限）はコードから見えない。取材で聞く"
fi

if [[ -f package.json ]]; then
  hr "21. 依存のインストール時の防御（10 の 3-1）"
  if [[ -f package-lock.json ]]; then
    n_is="$(grep -c '"hasInstallScript": true' package-lock.json 2>/dev/null || true)"
    echo "  インストール時にスクリプトが走る依存: ${n_is:-0} 件"
    # 名前は直前に現れた "node_modules/<名前>" のキー。間の行数は決まっていないので -B では取れない
    awk '/^[[:space:]]*"node_modules\//{k=$1} /"hasInstallScript": true/{gsub(/[":]/,"",k); sub(/.*node_modules\//,"",k); print k}' \
      package-lock.json 2>/dev/null | sort -u | lim 15 | sed 's/^/    /'
    # スキームの付いた取得元だけを見る（ワークスペースの "resolved": "packages/ui" は除く）
    nonreg="$(grep -E '"resolved": "[a-z+]+:' package-lock.json 2>/dev/null | grep -vE 'registry\.npmjs\.org|registry\.yarnpkg\.com' | lim 5)"
    # URL に認証情報（user:token@）が入っていることがあるので伏せる
    [[ -n "$nonreg" ]] && { echo "  ★ 公式レジストリ以外から取っている依存:"; printf '%s\n' "$nonreg" | sed -E 's/^[[:space:]]*/    /; s#://[^/@"]+@#://<伏字>@#'; }
  fi
  echo "  --- 防御の設定（無ければ「無い」と出る）---"
  {
    grep -nE 'ignore-scripts|min-release-age|allow-(git|remote|scripts)|strict-allow-scripts|dangerously-allow-all-scripts' .npmrc 2>/dev/null | sed 's/^/  .npmrc:/'
    grep -nE '"(allowScripts|overrides|resolutions|packageManager)"' package.json 2>/dev/null | sed 's/^/  package.json:/'
    grep -nE 'minimumReleaseAge|allowBuilds|onlyBuiltDependencies|dangerouslyAllowAllBuilds|blockExoticSubdeps|npmMinimalAgeGate|enableScripts' \
      pnpm-workspace.yaml .yarnrc.yml bunfig.toml 2>/dev/null | sed 's/^/  /'
    grep -nE '"pnpm"[[:space:]]*:' package.json 2>/dev/null | sed 's/^/  package.json:/'
    grep -nE 'cooldown' .github/dependabot.y*ml 2>/dev/null | sed 's/^/  dependabot:/'
    grep -nE 'installCommand' vercel.json 2>/dev/null | sed 's/^/  vercel.json:/'
  } | show
  # 依存の欄だけを見る（repository / homepage / $schema の URL は依存ではない）
  gitdeps="$(awk '/"(dev|optional|peer)?[Dd]ependencies"[[:space:]]*:/{f=1;next} f&&/}/{f=0} f&&/:[[:space:]]*"(git\+|git:|github:|https?:\/\/|file:)/{print}' package.json 2>/dev/null | mask)"
  [[ -n "$gitdeps" ]] && { echo "  ★ package.json に git や URL から取る依存がある:"; printf '%s\n' "$gitdeps" | sed 's/^[[:space:]]*/    /'; }
  echo "  ※ 手元の設定より、本番のビルドで動く npm / pnpm の版で決まる（Vercel の既定は npm install。npm は Node 24 なら 11、Node 20 / 22 なら 10 で、どちらも依存のスクリプトを止めない）"
fi

if [[ -n "$agent_files" ]]; then
  hr "22. AI エージェントの設定ファイル（開発者の端末で自動的に読み込まれる。10 の 3-5）"
  echo "  存在:$agent_files"
  echo "  --- 自動承認・権限の緩和・フック・フォルダを開くだけで走るもの ---"
  {
    grep -nHE '"hooks"|bypassPermissions|enableAllProjectMcpServers|apiKeyHelper|"defaultMode"' .claude/settings*.json 2>/dev/null | mask_keys
    grep -nHE 'autoApprove|yolo' .vscode/settings.json .gemini/settings.json 2>/dev/null | mask_keys
    grep -nHE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' .vscode/tasks.json 2>/dev/null | mask_keys
    if git rev-parse --git-dir >/dev/null 2>&1; then
      git ls-files 2>/dev/null | grep -E 'settings\.local\.json$' | sed 's/^/  ★ 個人用の設定がコミットされている: /'
    fi
  } | show
  echo "  --- MCP サーバーを版の固定なしで取ってくる定義 ---"
  {
    grep -nHE '"-y"|npx' .mcp.json .cursor/mcp.json .vscode/mcp.json 2>/dev/null | lim 10 | mask_keys
  } | show
  echo "  --- 見えない Unicode（ゼロ幅・双方向制御・タグ文字）---"
  {
    if command -v perl >/dev/null 2>&1; then
      for f in $agent_files; do
        [[ -f "$f" ]] || continue
        perl -Mutf8 -CSD -ne 'print "  ★ $ARGV:$.\n" if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{E0000}-\x{E007F}]/' "$f" 2>/dev/null
      done
      [[ -d .cursor/rules ]] && find .cursor/rules -type f -exec perl -Mutf8 -CSD -ne 'print "  ★ $ARGV:$.\n" if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{E0000}-\x{E007F}]/' {} \; 2>/dev/null
    else
      echo "  （perl が無いため省略）"
    fi
  } | show
  echo "  ※ 見つかったこと自体は指摘ではない。開発者の端末で自動で動くものがあり、その端末に本番の秘密情報があるかを取材で聞く"
fi

if [[ -n "$rt" ]]; then
  hr "23. リアルタイム通信（HTTP のガードを通らない入口。07 の 11 節）"
  echo "  使っているもの:$rt"

  if [[ "$rt" == *Supabase-Realtime* ]]; then
    echo "  --- Supabase Realtime: private 指定の無い購読（public チャネル。公開鍵を持つ誰でも入れる）---"
    {
      # .channel( から、その購読の終わり（.subscribe( か、次の .channel(）までに private: true があるか
      grep -rlE "${EXA[@]}" '\.channel\(' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | while IFS= read -r f; do
        awk -v F="$f" '
          function flush() { if (start && !priv) printf "  ★ %s:%d:%s\n", F, start, substr(first, 1, 150); start=0; priv=0 }
          /\.channel\(/ { flush(); start=NR; first=$0; sub(/^[[:space:]]+/, "", first) }
          start && /private:[[:space:]]*true/ { priv=1 }
          start && (/\.subscribe\(/ || NR - start > 30) { flush() }
          END { flush() }' "$f"
      done
    } | show
    echo "  --- Supabase Realtime: テーブルの変更の購読と、publication・replica identity・チャネルのポリシー ---"
    {
      grep -rnE "${EXA[@]}" 'postgres_changes' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | lim 10
      grep -rniE "${EXA[@]}" 'supabase_realtime|replica identity full|on realtime\.messages|realtime\.topic\(' --include='*.sql' . 2>/dev/null | lim 10
    } | show
    echo "  ※ 管理画面の「Allow public access」が有効なら、private: true を付けていても外して入り直せる（03 の 1 節）"
    echo "  ※ publication に入れたテーブルの RLS が無効なら、全行の変更が流れる。DELETE には RLS が適用されない"
  fi

  if [[ "$rt" == *WebSocket* || "$rt" == *Socket.IO* ]]; then
    echo "  --- WebSocket: サーバーの定義 ---"
    ws_def="$(grep -rnE "${EXA[@]}" 'new (WebSocketServer|WebSocket\.Server|Server)\(|upgradeWebSocket|experimental_upgradeWebSocket|defineWebSocketHandler|@app\.websocket' \
      --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' . 2>/dev/null \
      | grep -vE 'new (http|https)\.Server\(|new Server\(\{[[:space:]]*name|modelcontextprotocol' | lim 10)"
    printf '%s\n' "$ws_def" | grep -v '^$' | show
    echo "  --- WebSocket: 認証と Origin の検証 ---"
    ws_auth="$(grep -rnE "${EXA[@]}" 'io\.use\(|allowRequest|verifyClient|handleUpgrade|headers\.origin|headers\[.origin.\]|handshake\.(auth|headers)|onBeforeConnect' \
      --include='*.ts' --include='*.js' --include='*.mjs' . 2>/dev/null | lim 10)"
    printf '%s\n' "$ws_auth" | grep -v '^$' | show
    if [[ -n "$ws_def" ]] && ! printf '%s' "$ws_auth" | grep -iE 'origin|allowRequest|verifyClient' >/dev/null; then
      echo "  ★ サーバーの定義はあるが、Origin を検証している形跡が無い（Cookie で認証しているなら CSWSH）"
    fi
    echo "  --- WebSocket: ルームへの参加と切断 ---"
    {
      grep -rnE "${EXA[@]}" 'socket\.join\(|disconnectSockets\(|socket\.on\(["'"'"'](join|subscribe)' --include='*.ts' --include='*.js' . 2>/dev/null | lim 10
    } | show
    echo "  ※ socket.join の引数がクライアントの送った値なら、そのルームに入る資格を確かめているかを読む"
  fi

  if [[ "$rt" == *配信サービス* ]]; then
    echo "  --- 配信サービス: 鍵とチャネルの認可 ---"
    {
      grep -rnE "${EXA[@]}" 'authorizeChannel\(|/pusher/auth|publicApiKey|new Ably\.(Realtime|Rest)\(|capability|\.allow\(|onConnect|withFilter\(|connectionParams' \
        --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | lim 12 | mask
    } | show
    echo "  ※ 認可のエンドポイントがチャネル名を照合しているか。publicApiKey や API キーをブラウザに置いていないか"
  fi

  if [[ "$rt" == *SSE* ]]; then
    echo "  --- SSE: 配信のハンドラ ---"
    {
      grep -rlE "${EXA[@]}" 'text/event-stream' --include='*.ts' --include='*.js' . 2>/dev/null | lim 10 | sed 's/^/  /'
      grep -rnE "${EXA[@]}" 'new EventSource\([^)]*(token|key|jwt)' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | lim 5 \
        | mask | sed 's/$/   ← トークンを URL に載せている/'
    } | show
    echo "  ※ 配信のハンドラも 2 節の表に載る。空欄なら、誰でも購読できる"
  fi

  if [[ "$rt" == *Firebase-購読* ]]; then
    echo "  --- Firebase: 購読の場所（ルールは 19 節）---"
    {
      grep -rnE "${EXA[@]}" 'onSnapshot\(|onValue\(|onChildAdded\(|collectionGroup\(' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | lim 10
    } | show
    echo "  ※ allow read を get と list に分けていないと、一覧で全件を購読できる"
  fi
fi

if [[ -n "$sms_hit$sms_cfg" ]]; then
  hr "24. SMS の送信経路（SMS pumping。02 の F-4）"
  echo "  --- SMS を送らせる箇所 ---"
  {
    grep -rnE "${EXA[@]}" "$SMSPAT" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.py' . 2>/dev/null | lim 12
    [[ -n "$twilio_direct" ]] && printf '%s\n' "$twilio_direct" | while IFS= read -r f; do grep -nHE 'messages\.create\(' "$f"; done | lim 6
    [[ -n "$sms_cfg" ]] && grep -nE '^\[auth\.(sms|rate_limit|captcha|hook\.send_sms)|sms_sent|enable_signup|enable_anonymous_sign_ins' supabase/config.toml 2>/dev/null | sed 's/^/  supabase\/config.toml:/'
  } | show
  echo "  --- 番号の検証・レート制限・CAPTCHA の手がかり（無いこと自体が材料）---"
  {
    grep -rnE "${EXA[@]}" 'libphonenumber|parsePhoneNumber|isValidPhoneNumber|isValidNumberForRegion|\+81' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.py' . 2>/dev/null | lim 5
    grep -rnE "${EXA[@]}" '@upstash/ratelimit|Ratelimit|rateLimit|rate-limit|turnstile|hcaptcha|recaptcha|RecaptchaVerifier|captchaToken' --include='*.ts' --include='*.tsx' --include='*.js' . 2>/dev/null | lim 5
  } | show
  if [[ -n "$twilio_direct" ]]; then
    echo "  ★ SMS の API を直接呼んでいる（messages.create）。確認用サービスの組み込みの防御（国の制限・送信回数の制限）を使えない"
  fi
  echo "  ※ 認証なしで届く経路を全部挙げる（サインアップ・再送・再設定・番号の変更・招待）。国の制限と上限は 03 の 3 節で基盤側も見る"
fi

hr "完了"
skipped=""
[[ -z "$replay" ]] && skipped="$skipped 9b（画面操作の記録）"
[[ -z "$iac" ]] && skipped="$skipped 17（インフラ）"
[[ -z "$mob" ]] && skipped="$skipped 18（モバイル）"
[[ -z "$baas" ]] && skipped="$skipped 19（BaaS）"
[[ -d .github/workflows ]] || skipped="$skipped 20（CI）"
[[ -f package.json ]] || skipped="$skipped 21（依存のインストール時）"
[[ -z "$agent_files" ]] && skipped="$skipped 22（エージェントの設定）"
[[ -z "$rt" ]] && skipped="$skipped 23（リアルタイム通信）"
[[ -z "$sms_hit$sms_cfg" ]] && skipped="$skipped 24（SMS）"
echo "該当しないので省いた節:${skipped:- なし}"
echo "  ※ 省いたのは、その技術がファイルに見当たらないため。管理画面で作ったものはコードに現れないので 03 で見る"
echo "ここに挙がったものは候補であって指摘ではない。必ずコードを読んでから起票する。"
