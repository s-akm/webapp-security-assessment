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
#
# grep は当たりを付けるための道具であって、判定するものではない。
# ここで挙がった箇所は必ず目で読んでから起票する。逆に、ここに挙がらなくても
# 問題があることは普通にある。

set -uo pipefail
REPO="${1:-.}"
cd "$REPO" || { echo "パスが開けない: $REPO" >&2; exit 1; }

# -I はバイナリを読み飛ばす。画像や PDF が「HTML を直接流し込む」に当たって並ぶのを防ぐ。
EX='-I --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build
    --exclude-dir=.next --exclude-dir=vendor --exclude-dir=venv --exclude-dir=.venv
    --exclude-dir=__pycache__ --exclude-dir=coverage --exclude-dir=.turbo'
# shellcheck disable=SC2206
EXA=($EX)

hr() { printf '\n=== %s ===\n' "$1"; }
show() { local out; out="$(cat)"; if [[ -n "$out" ]]; then printf '%s\n' "$out"; else echo "  （検出なし）"; fi; }

# 検出した秘密情報の値そのものは出力しない。
# 「どのファイルの何行目に、どの名前で存在するか」までが分かれば起票できる。
# 値が要るときは、この出力ではなく元ファイルを直接開く。
mask() {
  sed -E \
    -e 's/(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_.-]+/\1…<JWT・伏字>/g' \
    -e 's/(AKIA[0-9A-Z]{4})[0-9A-Z]+/\1…<伏字>/g' \
    -e 's/((sk|pk)_live_[0-9A-Za-z]{4})[0-9A-Za-z]+/\1…<伏字>/g' \
    -e 's/(ghp_[0-9A-Za-z]{4})[0-9A-Za-z]+/\1…<伏字>/g' \
    -e 's/(sb_(secret|publishable)_[0-9A-Za-z]{4})[0-9A-Za-z_-]+/\1…<伏字>/g' \
    -e 's/(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]+/\1…<伏字>/g' \
    -e "s/([\"'\`])[A-Za-z0-9_\/+=.-]{12,}([\"'\`]?)/\1<値は伏字>\2/g" \
    -e 's/([A-Za-z_]*(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Za-z_]*)[[:space:]]*=[[:space:]]*[^[:space:]"'"'"'`]{8,}/\1=<値は伏字>/g' \
    | cut -c1-200
}

hr "対象"
echo "  $(pwd)"

# --------------------------------------------------------------------------
# 枠組みごとに、ハンドラの置き方が違う。ファイル名で決まるもの、ディレクトリで決まるもの、
# コード中の登録で決まるものの 3 通りを集める。1 つの枠組みしか見ていないと、
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
    # (1) ファイル名で決まるもの
    find . \( -name "route.ts" -o -name "route.js" -o -name "route.mjs" \
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
              -o -name "index.ts" -o -name "index.js" -o -name "index.mjs" \)
         -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/vendor/*" \
         -not -path "*/dist/*" -not -path "*/build/*" -not -path "*/target/*" 2>/dev/null
    # (2) ディレクトリで決まるもの
    for d in ./pages/api ./src/pages/api ./app/api ./src/app/api \
             ./server/api ./server/routes ./src/server \
             ./app/routes ./routes ./src/routes \
             ./app/Http/Controllers ./app/controllers ./src/Controller \
             ./handlers ./handler ./internal/handlers ./internal/api ./internal/http \
             ./api ./functions ./src/functions ./src/handlers \
             ./supabase/functions ./netlify/functions ./.netlify/functions \
             ./Pages ./Sources ./conf ./app/Controllers; do
      [[ -d "$d" ]] && find "$d" -type f \
        \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' \
           -o -name '*.php' -o -name '*.rb' -o -name '*.py' -o -name '*.go' \
           -o -name '*.ex' -o -name '*.exs' -o -name '*.rs' -o -name '*.kt' \
           -o -name '*.cs' -o -name '*.java' -o -name '*.scala' -o -name '*.swift' \)
        -not -path "*/node_modules/*" 2>/dev/null
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
# 対象に無い技術の資料を読むのは時間の無駄で、逆に「読んだつもり」になる危険もある。
# ここで何があるかを先に確定させ、要る資料だけを開く。
need=""
say() { printf '  %-26s %s\n' "$1" "$2"; }

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
if [[ -n "$(grep -rlE 'anthropic|openai|@ai-sdk|langchain|llamaindex|generativeai|bedrock-runtime|modelcontextprotocol' \
     --include='package.json' --include='requirements.txt' --include='pyproject.toml' . 2>/dev/null | head -1)" ]]; then
  say "LLM の利用" "有 → アプリ自身が LLM を呼んでいる"
  need="$need references/12-ai-features.md"
else
  say "LLM の利用" "無"
fi

if [[ -n "$(grep -rlE 'googletagmanager|google-analytics|gtag\(|adsbygoogle|connect\.facebook|clarity\.ms|hotjar' \
     --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.html' . 2>/dev/null | head -1)" ]]; then
  say "計測・広告タグ" "有"
  need="$need references/08-privacy-compliance.md"
else
  say "計測・広告タグ" "無（08 は文書との突き合わせだけ見る）"
fi

if [[ -n "$(grep -rlE 'DocumentBuilder|SAXParser|XMLReader|etree|lxml|SimpleXML|XmlDocument|xml2js' . 2>/dev/null | head -1)" ]]; then
  say "XML の解析" "有 → 07 の 6-2（XXE）"
else
  say "XML の解析" "無"
fi

lock=""
for f in package-lock.json yarn.lock pnpm-lock.yaml poetry.lock Gemfile.lock go.sum composer.lock Cargo.lock; do
  [[ -e "$f" ]] && lock="$lock $f"
done
say "ロックファイル" "${lock:-★ 無い。監査した版と本番の版が違いうる（10 の 2 節）}"

echo
if [[ -n "$need" ]]; then
  echo "  この案件で追加で読む資料:"
  for f in $need; do echo "    $f"; done
else
  echo "  追加で読む資料は無い（01〜05 と、該当する 07 の節だけで足りる）"
fi
echo "  ※ ここに出ないものは、その技術が無いということ。**無い資料は読まない。**"
echo "  ※ 判定はファイルの有無による。手作業で作った資源はコードに現れないので、03 で実機を見る"

hr "1. 規模"
n_files="$(handler_files | wc -l | tr -d ' ')"
echo "  ハンドラを含むらしきファイル: $n_files 件"
if [[ "$n_files" != "0" ]]; then
  n_def=0
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    c="$(grep -cE "$HANDLER_DEF" "$f" 2>/dev/null | head -1)"; c="${c:-0}"
    n_def=$((n_def + c))
  done < <(handler_files)
  echo "  ハンドラらしき定義の総数: $n_def 件"
fi
git rev-parse --git-dir >/dev/null 2>&1 && echo "  コミット数: $(git log --all --oneline 2>/dev/null | wc -l | tr -d ' ')"

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

{
  handler_files | while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    g="$(grep -ohE "$GUARD" "$f" 2>/dev/null | sort -u | tr '\n' ' ')"
    n_def="$(grep -cE "$HANDLER_DEF" "$f" 2>/dev/null | head -1)"; n_def="${n_def:-0}"
    n_grd="$(grep -cE "$GUARD" "$f" 2>/dev/null | head -1)"; n_grd="${n_grd:-0}"
    if [[ "$n_def" -gt 1 ]]; then
      printf '  %-46s %-30s (定義 %s / ガード %s)\n' "$f" "${g:-← ガード検出なし}" "$n_def" "$n_grd"
    else
      printf '  %-46s %s\n' "$f" "${g:-← ガード検出なし}"
    fi
  done
} | show
echo "  ※ 「定義 N / ガード M」が出た行は、1 ファイルに複数のハンドラがある。"
echo "    N と M が違えば、ガードの無いハンドラが混じっている。関数ごとに目で確かめる"
echo "  ※ ガード名が出ていても、そのハンドラに掛かっているとは限らない。"
echo "    同じファイルの別の場所にあるだけのことがある。空欄と同じ重さで 1 本ずつ読む"

hr "2b. ルート登録の一覧（登録の行に認可が挟まっているか）"
# app.get('/x', requireAuth, handler) のように、登録の行で認可を挟む書き方を見る。
{
  grep -rnE "${EXA[@]}" \
    "$ROUTE_REG" \
    --include='*.ts' --include='*.js' --include='*.mjs' --include='*.go' --include='*.php' \
    . 2>/dev/null | head -40
} | show
echo "  ※ この行に認可の語が無くても、ハンドラの中で見ている場合がある。2 の表と併せて読む"

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
echo "  ※ 関数の先頭でガードを呼んでいても、その戻り値を使わずに先へ進んでいれば効いていない"

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
      | head -15 | sed 's/^/    /'
  done
  # 枠組みによらず、ルートをまとめて保護する書き方
  grep -rnE "${EXA[@]}" \
    'app\.use\(|router\.use\(|Route::(group|middleware)|\.grouped\(|authenticate\(["'"'"'][^"'"'"']*["'"'"']\)[[:space:]]*\{|@Secured|SecurityFilterChain|UseMiddleware' \
    . 2>/dev/null | head -15
} | show
echo "  ※ 対象範囲の指定は、書き方しだいで簡単に穴が空く。除外や前方一致の指定があれば、"
echo "    2 の表のルート一覧と 1 本ずつ突き合わせる。**外れているルートは自前のガードが要る**"
echo "  ※ ミドルウェアだけに頼る構成は、その仕組みに不具合が出た時点で全ルートが同時に開く。"
echo "    02 の A-5 を参照"

hr "3. 危険な関数"
echo "  --- 出力に HTML を直接流し込む ---"
{
  grep -rnE "${EXA[@]}" 'dangerouslySetInnerHTML|v-html|\.innerHTML[[:space:]]*=|@Html\.Raw|\|[[:space:]]*safe|html_safe|mark_safe|\{\{\{' . 2>/dev/null | head -20
} | show

echo "  --- コード・コマンドを組み立てて実行する ---"
{
  # 言語ごとに書き方が違う。1 つの言語の書き方しか持たないと、他の言語で素通りする。
  grep -rnE "${EXA[@]}" '\beval\(|new Function\(|child_process|execSync|spawnSync' . 2>/dev/null | head -15
  grep -rnE "${EXA[@]}" 'os\.system|subprocess\.|exec\.Command|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\.Start' . 2>/dev/null | head -15
  grep -rnE "${EXA[@]}" 'shell_exec|passthru[[:space:]]*\(|\bsystem[[:space:]]*\(|popen[[:space:]]*\(|unserialize[[:space:]]*\(|Marshal\.load' . 2>/dev/null | head -15
} | mask | sort -u | head -30 | show

echo "  --- SQL を文字列連結で組み立てる ---"
{
  # SQL らしい文字列の直後に連結演算子が来る形。+ (JS/Go/Java/C#) . (PHP) % と .format (Python)
  # || (SQL/PHP) をまとめて見る。言語別に書くと必ず取りこぼす。
  grep -rniE "${EXA[@]}" \
    '(select[[:space:]]+[^;]{0,80}[[:space:]]from[[:space:]]|insert[[:space:]]+into[[:space:]]|update[[:space:]]+[a-z_."'"'"'`]+[[:space:]]+set[[:space:]]|delete[[:space:]]+from[[:space:]]|drop[[:space:]]+table|alter[[:space:]]+table)[^;]{0,120}["'"'"'`]+[[:space:]]*(\+|\.|%|\|\|)[[:space:]]*[a-z_$@(]' \
    . 2>/dev/null | head -20
  # 埋め込み構文で値を差し込む形。{} は Rust の format! と Python の .format、
  # ${} は JS のテンプレートリテラル、$"" は C# の文字列補間。
  grep -rniE "${EXA[@]}" \
    '(select[[:space:]]+[^;]{0,80}[[:space:]]from[[:space:]]|insert[[:space:]]+into[[:space:]]|update[[:space:]]+[a-z_."'"'"'`]+[[:space:]]+set[[:space:]]|delete[[:space:]]+from[[:space:]])[^;]{0,120}(\{\}|\{[a-z_][a-z0-9_]*\})' \
    . 2>/dev/null | head -10
  # テンプレートリテラルに式を埋め込む形
  grep -rniE "${EXA[@]}" '(select[[:space:]]+[^`]{0,80}[[:space:]]from[[:space:]]|insert[[:space:]]+into[[:space:]]|update[[:space:]]+[a-z_]+[[:space:]]+set[[:space:]]|delete[[:space:]]+from[[:space:]])[^`]*\$\{' . 2>/dev/null | head -10
  # 生 SQL を渡す入り口。組み立て方に関わらず、ここは目で読む
  grep -rnE "${EXA[@]}" '\.raw\(|executeSql|jdbcTemplate\.(execute|query)|ExecuteSql|DB::(select|statement|raw)|db\.Query\(|connection\.execute' . 2>/dev/null | head -15
} | mask | sort -u | head -30 | show
echo "  ※ 連結が定数だけなら問題ない。外部入力が混ざる経路があるかを 1 件ずつ読む"

hr "4. 秘密情報のハードコード（値は伏字にして出力する）"
# .env* はローカル専用の設定ファイルで、値が入っているのが正常。
# 中身を出力すると事故になるので、内容の走査からは外し、存在の有無だけを 4c で見る。
# 2 本の grep は同じ行に当たることがある（例: sk_live_ の代入は両方に該当する）。
# 伏字にしたうえで sort -u を通し、同じ行が二重に並ばないようにする。
{
  grep -rnE "${EXA[@]}" --exclude='.env*' \
    '(api[_-]?key|secret|passwd|password|token|private[_-]?key)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_/+-]{16,}' \
    . 2>/dev/null | grep -viE 'example|sample|dummy|placeholder|your[_-]|xxx|\.md:|test'
  grep -rnE "${EXA[@]}" --exclude='.env*' \
    'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|sk_live_|ghp_[0-9A-Za-z]{20,}' \
    . 2>/dev/null
} | mask | sort -u | head -40 | show

hr "4b. クライアントに露出する環境変数（特権鍵が混ざっていないか）"
{
  grep -rhoE "${EXA[@]}" '(NEXT_PUBLIC|NUXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|GATSBY|STORYBOOK|ASTRO_PUBLIC|PUBLIC|VUE_APP|NG_APP|SVELTE_PUBLIC|REMIX_PUBLIC)_[A-Z0-9_]+' . 2>/dev/null | sort -u | sed 's/^/  /'
} | show
echo "  ※ SERVICE_ROLE / SECRET / PRIVATE / ADMIN を含む名前がこの一覧にあれば、その時点で最優先の指摘"

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
hr "5. fail-open な既定値（未設定のとき有効側に倒れるもの）"
{
  grep -rnE "${EXA[@]}" 'process\.env\.[A-Z0-9_]+\s*!==\s*["'"'"']false["'"'"']' . 2>/dev/null | head -20
  grep -rnE "${EXA[@]}" 'process\.env\.[A-Z0-9_]+\s*\|\|\s*(true|["'"'"']true)' . 2>/dev/null | head -20
  grep -rnE "${EXA[@]}" 'getenv\([^)]+\)\s*!=\s*["'"'"']false' . 2>/dev/null | head -20
} | show
echo "  ※ 検出されたら、その変数が実機で設定されているかを実機確認で確かめる"

# --------------------------------------------------------------------------
hr "6. 開発用の抜け道"
{
  find . -path "*dev*login*" -o -path "*debug*" -o -path "*mock*" 2>/dev/null \
    | grep -vE 'node_modules|\.git|dist|build' | head -20 | sed 's/^/  /'
  grep -rnE "${EXA[@]}" 'NODE_ENV\s*[!=]==?\s*["'"'"'](production|development)|DEBUG\s*=|SKIP_AUTH|BYPASS' . 2>/dev/null | head -20
} | show
echo "  ※ 見つかったパスは実機確認で本番へリクエストする（期待値 404 / 403）"

# --------------------------------------------------------------------------
hr "7. git 履歴中の鍵らしき文字列"
if git rev-parse --git-dir >/dev/null 2>&1; then
  {
    git log --all -p 2>/dev/null \
      | grep -nE '^\+.*(api[_-]?key|secret|password|token)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_/+-]{16,}' \
      | grep -viE 'example|sample|dummy|placeholder|your[_-]|xxx' | head -20 | mask
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
    | sort -u | head -40 | sed 's/^/  /'
} | show
echo "  ※ マイグレーション／スキーマ定義に無いものは、本番の設定が不明。実機確認の最優先対象"

# --------------------------------------------------------------------------
hr "9. 第三者タグと同意管理（法令遵守の検討材料）"
# URL を直に書く形だけでなく、フレームワークのラッパーコンポーネント経由の読み込みも見る。
# <GoogleTagManager gtmId={...} /> のような書き方は、URL が現れないため
# ドメイン名の grep だけでは取り逃す。実際にこれで見落としが起きる。
TAGPAT='googletagmanager|google-analytics|gtag\(|adsbygoogle|pagead2|googlesyndication|doubleclick|connect\.facebook|fbq\(|clarity\.ms|hotjar|analytics\.tiktok|snap\.licdn|intercom|sentry|GoogleTagManager|GoogleAnalytics|@next/third-parties|@vercel/analytics|SpeedInsights|react-ga|vue-gtag|nuxt/scripts'

echo "  --- 計測・広告タグの読み込み箇所 ---"
{
  grep -rnE "${EXA[@]}" "$TAGPAT" \
    --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
    --include='*.vue' --include='*.svelte' --include='*.html' . 2>/dev/null | head -20
} | show

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
    --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.html' . 2>/dev/null | head -10
} | show
echo "  ※ フォームの第三者提供同意（third_party_consent 等）は Cookie の同意とは別物。混同しない"
echo "  ※ 詳しくは references/08-privacy-compliance.md。実際の発火は scripts/recon.sh で本番を見る"

echo "  --- 公開している文書（実装との突き合わせ対象）---"
{
  find . -path ./node_modules -prune -o \( -ipath '*privacy*' -o -ipath '*policy*' -o -ipath '*terms*' -o -ipath '*tokushoho*' -o -ipath '*legal*' \) -type f -print 2>/dev/null \
    | grep -vE 'node_modules|\.git' | head -10 | sed 's/^/    /'
} | show

# --------------------------------------------------------------------------
hr "10. 認証トークンの検証（署名を見ずに中身だけ取り出していないか）"
echo "  --- 検証せずに復号しているもの（ここが穴になる）---"
{
  grep -rnE "${EXA[@]}" 'jwt\.decode\(|jwtDecode\(|decodeJwt\(|decode_token\(' . 2>/dev/null | head -15
} | show
echo "  --- 検証しているもの ---"
{
  grep -rnE "${EXA[@]}" 'jwt\.verify\(|jwtVerify\(|verifyIdToken\(|createRemoteJWKSet|decode\([^)]*verify' . 2>/dev/null | head -15
} | show
echo "  ※ decode だけなら署名を見ていない。role を書き換えたトークンが通る。02 の B-4 を参照"

hr "11. Webhook の受け口と署名検証"
echo "  --- 受け口 ---"
{
  find . \( -path '*webhook*' -o -path '*hooks*' -o -path '*callback*' \) -name 'route.*' \
    -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | head -15 | sed 's/^/  /'
  grep -rlnE "${EXA[@]}" 'webhook|/hooks?/' --include='*.py' . 2>/dev/null | head -10 | sed 's/^/  /'
} | show
echo "  --- 署名検証らしき処理 ---"
{
  grep -rnE "${EXA[@]}" 'constructEvent|verifySignature|createHmac|hmac\.new|compare_digest|timingSafeEqual' . 2>/dev/null | head -15
} | show
echo "  ※ 受け口があって検証が無ければ、誰でも通知を投げられる。02 の M を参照"
echo "  ※ シークレット未設定のときに検証を飛ばしていないかは、目で読んで確かめる"

hr "12. 例外の握りつぶし（認可・認証の周りにあれば最優先）"
{
  grep -rnE "${EXA[@]}" 'catch[^{]*\{[[:space:]]*\}|except[^:]*:[[:space:]]*pass' . 2>/dev/null | head -20
} | show
echo "  ※ 検証が例外で落ちても先へ進む形は、検証していないのと同じ。02 の K-2 を参照"

hr "13. 乱数と暗号"
echo "  --- 予測できる乱数（トークンや ID に使っていれば指摘）---"
{
  grep -rnE "${EXA[@]}" \
    'Math\.random\(|\brandom\.random\(|\brandom\.randint\(|\brand\(\)|mt_rand\(|uniqid\(|new Random\(\)' \
    . 2>/dev/null | head -20
} | show
echo "  --- 暗号として使える乱数（こちらが使われていれば問題なし）---"
{
  grep -rnE "${EXA[@]}" \
    'crypto\.randomBytes|crypto\.randomUUID|getRandomValues|secrets\.token|SecureRandom|random_bytes|randomUUID' \
    . 2>/dev/null | head -10
} | show
echo "  ※ 画面の見た目に使う乱数は問題ない。何に使われているかを追ってから起票する"
echo "  ※ 再設定トークン・セッション ID・招待コードに使われていれば、それだけで指摘"

echo "  --- パスワードのハッシュと暗号の使い方 ---"
{
  grep -rniE "${EXA[@]}" 'bcrypt|argon2|scrypt|pbkdf2|createHash\(|hashlib\.|MessageDigest' . 2>/dev/null | head -15
  grep -rniE "${EXA[@]}" 'md5|sha1[^0-9]|ECB|createCipheriv?\(|Cipher\.getInstance' . 2>/dev/null | head -15
} | mask | sort -u | head -25 | show
echo "  ※ MD5 / SHA-1 / ECB が出たら、何に使っているかを読む。02 の N 節を参照"

hr "14. 通信の保護（証明書の検証を切っていないか）"
{
  grep -rnE "${EXA[@]}" \
    'rejectUnauthorized[[:space:]]*:[[:space:]]*false|verify[[:space:]]*=[[:space:]]*False|InsecureSkipVerify[[:space:]]*:[[:space:]]*true|CURLOPT_SSL_VERIFYPEER[[:space:]]*,[[:space:]]*(false|0)|NODE_TLS_REJECT_UNAUTHORIZED|ServerCertificateValidationCallback|curl[[:space:]]+-k\b|--insecure' \
    . 2>/dev/null | head -15
} | show
echo "  ※ 「動かないからとりあえず無効化」がそのまま残る。環境で分岐していても本番の値を実機で確かめる"
{
  grep -rnE "${EXA[@]}" 'http://[a-z0-9.-]+' --include='*.ts' --include='*.js' --include='*.py' \
    --include='*.go' --include='*.php' --include='*.java' . 2>/dev/null \
    | grep -vE 'localhost|127\.0\.0\.1|0\.0\.0\.0|example\.(com|org|net)|schemas?\.|www\.w3\.org|xmlns' | head -10
} | show
echo "  ※ 平文の宛先。内部通信でも、経路が信頼できるかを確かめる"

hr "15. XML を解析しているか（該当すれば XXE を見る）"
{
  grep -rnE "${EXA[@]}" \
    'DocumentBuilder|SAXParser|XMLReader|etree|lxml|libxml|SimpleXML|XmlDocument|xml2js|xml-js|parseXml' \
    . 2>/dev/null | head -15
} | show
echo "  ※ 該当すれば references/07-web-vulnerabilities.md の 6-2 を読む。JSON だけなら不要"

hr "16. アプリ自身が LLM を呼んでいるか"
{
  grep -rlnE "${EXA[@]}" 'anthropic|openai|@ai-sdk|langchain|llamaindex|generativeai|bedrock-runtime' \
    --include='package.json' --include='requirements.txt' --include='pyproject.toml' . 2>/dev/null | sed 's/^/  /'
  grep -rlnE "${EXA[@]}" 'modelcontextprotocol|mcp[_-]server' . 2>/dev/null | head -5 | sed 's/^/  /'
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
        --include='*.tf' --include='*.json' --include='*.y*ml' . 2>/dev/null | head -15
      grep -rnE "${EXA[@]}" '"?Action"?[[:space:]]*[:=][[:space:]]*"\*"|"?Resource"?[[:space:]]*[:=][[:space:]]*"\*"|roles/owner' \
        --include='*.tf' --include='*.json' . 2>/dev/null | head -10
    } | show
    echo "  ※ 意図した公開もある（静的サイトの配信）。用途を確かめてから起票する"

    echo "  --- 状態ファイル（生成された秘密が平文で入る）---"
    {
      find . -name '*.tfstate*' -not -path '*/.git/*' 2>/dev/null | sed 's/^/  存在: /'
      if git rev-parse --git-dir >/dev/null 2>&1; then
        t="$(git log --all --oneline -- '*.tfstate' 2>/dev/null | head -3)"
        [[ -n "$t" ]] && echo "$t" | sed 's/^/  【履歴にある】/'
      fi
    } | show
    echo "  ※ 履歴に一度でも入っていれば、そこに書かれた鍵は失効が要る"
  fi

  if [[ -n "$(grep -rlE '^kind:[[:space:]]*(Deployment|Service|Ingress|Secret)' --include='*.y*ml' . 2>/dev/null | head -1)" ]]; then
    echo "  --- Kubernetes ---"
    {
      grep -rnE "${EXA[@]}" '^kind:[[:space:]]*Secret|privileged:[[:space:]]*true|hostNetwork:[[:space:]]*true|runAsUser:[[:space:]]*0' \
        --include='*.y*ml' . 2>/dev/null | head -10
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
    grep -rnE "${EXA[@]}" 'AsyncStorage|SharedPreferences|UserDefaults|NSUserDefaults' . 2>/dev/null | head -12
  } | show
  echo "  ※ 上は平文で残る置き場。認証トークンやパスワードを置いていれば指摘"
  {
    grep -rnE "${EXA[@]}" 'Keychain|SecureStore|EncryptedSharedPreferences|FlutterSecureStorage' . 2>/dev/null | head -8
  } | show
  echo "  ※ 上は資格情報の置き場として意図されたもの。使われていれば問題なし"

  echo "  --- 通信 ---"
  {
    grep -rnE "${EXA[@]}" 'usesCleartextTraffic|cleartextTrafficPermitted|NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads' \
      . 2>/dev/null | head -10
    grep -rnE "${EXA[@]}" 'allowInvalidCertificates|trustAllCerts|X509TrustManager|setHostnameVerifier|badCertificateCallback' \
      . 2>/dev/null | head -10
  } | show

  echo "  --- 端末との境界（外から入ってくる経路）---"
  {
    grep -rnE "${EXA[@]}" 'android:scheme|CFBundleURLSchemes|intent-filter|associatedDomains' . 2>/dev/null | head -10
    grep -rnE "${EXA[@]}" 'addJavascriptInterface|WKWebView|javaScriptEnabled|allowFileAccess|exported="true"' . 2>/dev/null | head -10
  } | show
  echo "  ※ ディープリンクで受けた値を検証しているか。WebView に任意の URL を読ませていないか"

  echo "  --- 権限と配布物に残るもの ---"
  {
    grep -rhoE "${EXA[@]}" 'android\.permission\.[A-Z_]+' . 2>/dev/null | sort -u | head -20 | sed 's/^/  /'
    grep -rnE "${EXA[@]}" 'android:debuggable[[:space:]]*=[[:space:]]*"true"|android:allowBackup[[:space:]]*=[[:space:]]*"true"' . 2>/dev/null | head -5
  } | show
  echo "  ※ 機能に対して過剰な権限が無いか。debuggable が本番に残っていないか"
  echo "  ※ 難読化・改竄検知の不在は、単独で挙げない。時間稼ぎであって防御ではない"
fi

hr "完了"
echo "ここに挙がったものは候補であって指摘ではない。必ずコードを読んでから起票する。"
