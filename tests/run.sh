#!/usr/bin/env bash
# run.sh — スキルを直したときに壊れていないかを確かめる
#
#   使い方: tests/run.sh
#
# ネットワークへは一切出ない。recon.sh だけは実サイトを叩くため動作確認ができず、
# 構文チェックと使い方の表示までしか見ていない。
#
# 見ているのは 3 つ。
#   1. 構造  — SKILL.md の記述と、references / scripts の実態が合っているか
#   2. 機密  — 案件固有の情報が配布物に混ざっていないか
#   3. 動作  — スクリプトが期待どおり検出するか（ダミーの題材に対して）

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL="$ROOT/skill"
TMP="$ROOT/tests/tmp"
rm -rf "$TMP"; mkdir -p "$TMP"

PASS=0; FAIL=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
ng()   { printf '  \033[31m✗\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '      %s\n' "$2"; FAIL=$((FAIL+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# 期待する文字列が出力に含まれるか
contains() {
  local label="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then ok "$label"
  else ng "$label" "「${needle}」が出力に無い"; fi
}

# 出力に含まれてはいけない文字列。誤検出していないかを見るのに使う。
absent() {
  local label="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$needle"; then ng "$label" "「${needle}」を誤って出している"
  else ok "$label"; fi
}

# ==========================================================================
head_ "1. 構造 — SKILL.md と実態が合っているか"

# frontmatter
if head -1 "$SKILL/SKILL.md" | grep -q '^---$'; then ok "SKILL.md に frontmatter がある"
else ng "SKILL.md に frontmatter がある"; fi
for key in name description; do
  if grep -qE "^$key: " "$SKILL/SKILL.md"; then ok "frontmatter に $key がある"
  else ng "frontmatter に $key がある"; fi
done
if grep -qE '^name: webapp-security-assessment$' "$SKILL/SKILL.md"; then
  ok "name がディレクトリ名と一致する"
else ng "name がディレクトリ名と一致する"; fi

# SKILL.md が参照しているファイルがすべて実在するか
missing=""
while IFS= read -r ref; do
  [[ -f "$SKILL/$ref" ]] || missing="$missing $ref"
done < <(grep -ohE '(references|scripts|templates)/[A-Za-z0-9._-]+' \
           "$SKILL/SKILL.md" "$SKILL"/references/*.md "$SKILL"/templates/*.md | sort -u)
if [[ -z "$missing" ]]; then ok "SKILL.md と references が参照するファイルはすべて実在する"
else ng "参照先が実在する" "見つからない:$missing"; fi

# 逆向き。実在するのに SKILL.md から参照されていないファイルが無いか
orphan=""
for f in "$SKILL"/references/*.md "$SKILL"/scripts/* "$SKILL"/templates/*; do
  [[ -f "$f" ]] || continue
  base="$(basename "$(dirname "$f")")/$(basename "$f")"
  grep -qF "$base" "$SKILL/SKILL.md" || orphan="$orphan $base"
done
if [[ -z "$orphan" ]]; then ok "すべての references / scripts / templates が SKILL.md に載っている"
else ng "孤児ファイルが無い" "SKILL.md に記載が無い:$orphan"; fi

# スクリプトの実行権限。拡張子で列挙すると新しい種類を足したときに漏れるため、
# scripts/ 配下のファイルをすべて対象にする（ここには実行するものしか置かない）。
for f in "$SKILL"/scripts/*; do
  [[ -f "$f" ]] || continue
  if [[ -x "$f" ]]; then ok "実行権限: $(basename "$f")"
  else ng "実行権限: $(basename "$f")" "chmod 755 が要る"; fi
done

# 構文
for f in "$SKILL"/scripts/*.sh; do
  if bash -n "$f" 2>/dev/null; then ok "構文: $(basename "$f")"
  else ng "構文: $(basename "$f")"; fi
done
if python3 -c "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())" \
     "$SKILL/scripts/make_register.py" 2>/dev/null; then
  ok "構文: make_register.py"
else ng "構文: make_register.py"; fi
if command -v node >/dev/null 2>&1; then
  for f in "$SKILL"/scripts/*.mjs; do
    if node --check "$f" 2>/dev/null; then ok "構文: $(basename "$f")"
    else ng "構文: $(basename "$f")"; fi
  done
else
  printf '  \033[33m-\033[0m 構文: *.mjs（node が無いため省略）\n'
fi

# ==========================================================================
head_ "2. 機密 — 案件固有の情報が配布物に混ざっていないか"

# 案件固有語。依頼者を示す語そのものが機微なので、リポジトリには入れず
# tests/ngwords.local（.gitignore 済み・1 行 1 語または正規表現）に置く。
# ここには、案件によらず配布物に混ざってはいけない語だけを置く。
# 'CLIENT-NGWORD-CANARY' は検査の検査（mutations.sh）が混入させる語で、手元ファイルが
# 無い環境でもこの検査が生きていることを確かめるために置いてある。
NGWORDS='CLIENT-NGWORD-CANARY'
if [[ -f "$ROOT/tests/ngwords.local" ]]; then
  local_words="$(grep -vE '^[[:space:]]*(#|$)' "$ROOT/tests/ngwords.local" | paste -sd '|' -)"
  [[ -n "$local_words" ]] && NGWORDS="$NGWORDS|$local_words"
else
  printf '  \033[33m-\033[0m 案件固有語: tests/ngwords.local が無い（過去の案件を示す語は検査されない）\n'
fi
hit="$(grep -rniE "$NGWORDS" "$SKILL" 2>/dev/null || true)"
if [[ -z "$hit" ]]; then ok "案件固有語が含まれない"
else ng "案件固有語が含まれない" "$(printf '%s' "$hit" | head -3)"; fi

# 例示以外のドメインが書かれていないか。example.com / example.invalid だけを許す。
bad="$(grep -rhoE 'https?://[A-Za-z0-9.-]+' "$SKILL" 2>/dev/null \
       | grep -vE '://(example\.(com|invalid|org|net)|localhost)' \
       | grep -vE '://(www\.)?(cisa\.gov|owasp\.org|genai\.owasp\.org|mas\.owasp\.org|jvn\.jp|jvndb\.jvn\.jp|jpcert\.or\.jp|ipa\.go\.jp|ppc\.go\.jp|cisecurity\.org|github\.com|nvd\.nist\.gov)' \
       | sort -u || true)"
if [[ -z "$bad" ]]; then ok "実在しうるドメインが書かれていない（公的な基準・警告情報の発行元は除く）"
else ng "実在しうるドメインが書かれていない" "$(printf '%s' "$bad" | tr '\n' ' ')"; fi

# 外部の基準は変わる。最後に版を確認した日から時間が経っていれば知らせる。
# 失敗にはしない。日付が過ぎただけで検査が赤くなると、本当の失敗が埋もれる。
STD="$(grep -oE 'standards-reviewed:[[:space:]]*[0-9]{4}-[0-9]{2}-[0-9]{2}' \
        "$SKILL/references/06-frameworks.md" 2>/dev/null | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)"
if [[ -z "$STD" ]]; then
  ng "基準の版に最終確認日が書いてある" "06-frameworks.md に standards-reviewed が無い"
else
  days="$(python3 -c "
import datetime, sys
d = datetime.date.fromisoformat(sys.argv[1])
print((datetime.date.today() - d).days)
" "$STD" 2>/dev/null || echo 0)"
  if [[ "$days" -ge 365 ]]; then
    printf '  \033[33m!\033[0m 基準の版の確認から %s 日（%s）。評価に入る前に版を確かめる\n' "$days" "$STD"
    ok "基準の版に最終確認日が書いてある（${STD}・${days} 日前）"
  else
    ok "基準の版の確認は ${days} 日前（${STD}）"
  fi
fi

# 日本語の資料に、想定外の文字体系が混ざっていないか。
# 生成の過程でキリル文字やハングルが 1 語だけ紛れ込むことが実際に起きる。
# 校正で見落としやすく、読み手には意味が取れない。
mixed="$(python3 - "$SKILL" <<'PYEOF' 2>/dev/null || true
import pathlib, re, sys
bad = []
for f in sorted(pathlib.Path(sys.argv[1]).rglob("*")):
    if not f.is_file():
        continue
    try:
        t = f.read_text(encoding="utf-8")
    except Exception:
        continue
    for m in re.findall(r"[\u0400-\u04ff\uac00-\ud7a3\u1100-\u11ff]+", t):
        bad.append(f"{f}: {m}")
print("\n".join(bad[:5]))
PYEOF
)"
if [[ -z "$mixed" ]]; then ok "日本語の資料に想定外の文字体系が混ざっていない"
else ng "日本語の資料に想定外の文字体系が混ざっていない" "$mixed"; fi

# 自前の混入検査を自分自身に当てる
out="$(bash "$SKILL/scripts/scan_secrets.sh" "$SKILL" 2>&1 || true)"
n="$(printf '%s' "$out" | grep -cE '^\[検出\]' || true)"
# メールアドレス 1 件（attacker@example.invalid）は説明用として想定内
if [[ "$n" -le 1 ]]; then ok "scan_secrets.sh の自己検査（検出 $n 種類・想定は 1 以下）"
else ng "scan_secrets.sh の自己検査" "想定外の検出 $n 種類"; fi

# ==========================================================================
head_ "3. 動作 — スクリプトが期待どおり検出するか"

# --- audit_grep.sh ---
# 親リポジトリの git 履歴を舐めないよう、独立したリポジトリとして作り直す
REPO="$TMP/repo"
cp -R "$ROOT/tests/fixtures/repo" "$REPO"
echo 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=dummy' > "$REPO/.env.local"
( cd "$REPO" && git init -q . && git add -A -f >/dev/null 2>&1 \
    && git -c user.email=t@example.invalid -c user.name=t commit -qm fixture >/dev/null 2>&1 ) || true

A="$(bash "$SKILL/scripts/audit_grep.sh" "$REPO" 2>&1)"
contains "audit_grep: ガードの無いハンドラを検出" "← ガード検出なし" "$A"
contains "audit_grep: ガードのあるハンドラを検出"  "isAdmin"           "$A"
contains "audit_grep: クライアント露出の特権鍵名"   "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" "$A"
contains "audit_grep: fail-open な既定値"          "ENABLE_GUARD"      "$A"
contains "audit_grep: 危険な関数"                  "innerHTML"         "$A"
contains "audit_grep: 参照テーブル名"              "users"             "$A"
contains "audit_grep: 計測タグ"                    "GoogleTagManager"  "$A"
contains "audit_grep: 検証せず復号する JWT"       "jwt.decode"        "$A"
contains "audit_grep: Webhook の受け口"           "app/api/webhook"   "$A"
contains "audit_grep: 例外の握りつぶし"           "catch (e) {}"      "$A"
contains "audit_grep: LLM を呼んでいるか"         "アプリ自身が LLM"  "$A"
contains "audit_grep: 予測できる乱数"             "Math.random"       "$A"
contains "audit_grep: 弱いハッシュ"               "createHash('md5')" "$A"
contains "audit_grep: 証明書の検証を切っている"    "rejectUnauthorized" "$A"
contains "audit_grep: XML の解析"                 "xml2js"            "$A"
# 鍵の値がそのまま出ていないこと（伏字が効いているか）
if printf '%s' "$A" | grep -qF 'sk_live_00000000000000000000TESTDUMMY'; then
  ng "audit_grep: 鍵の値を伏字にする" "値がそのまま出力されている"
else ok "audit_grep: 鍵の値を伏字にする"; fi
# 同じ行が二重に出ていないこと
dup="$(printf '%s' "$A" | grep -c 'lib.ts.*stripe_secret' || true)"
if [[ "$dup" -le 1 ]]; then ok "audit_grep: 同じ行を重複して出さない"
else ng "audit_grep: 同じ行を重複して出さない" "$dup 回出ている"; fi

# --- audit_grep.sh を各枠組みに当てる ---
# 題材が 1 つの枠組みだけだと、他の書き方への検出が壊れても気づけない。
# 実際、題材を増やすたびに「中核の検出がまるごと効いていない」枠組みが見つかっている。
#
#   枠組み:期待するハンドラのしるし:期待するガード名:期待する危険な書き方
FRAMEWORKS='
rails:app/controllers:before_action:User.connection.execute
django:views.py:@login_required:id = %s
drf:api/views.py:permission_classes:
tornado:app.py:web.authenticated:
nuxt:server/api:requireUserSession:
laravel:app/Http/Controllers:->middleware:where id = " . $request->id
symfony:src/Controller:IsGranted:where id = " . $request->get
slim:public/index.php:AuthMiddleware:
go:handlers/admin.go:RequireAuth:where id = " + id
gin:main.go:AuthMiddleware:where id = " + id
fiber:main.go:RequireAuth:
express:routes.js:requireAuth:+ req.query.id
fastify:server.js:preHandler:
koa:routes.js:requireAuth:
hono:src/index.ts:requireAuth:+ body.id
nestjs:src/admin.controller.ts:UseGuards:+ body.id
trpc:src/server/routers.ts:protectedProcedure:
graphql:src/resolvers.ts:requireAuth:+ args.id
remix:app/routes/admin.tsx:requireUser:
astro:src/pages/api/admin.ts:locals.user:
sveltekit:+server.ts:locals.user:
nextjs-pages:pages/api/admin.ts:getServerSession:
cloudflare-workers:src/worker.ts:requireAuth:
deno-fresh:routes/api/admin.ts:ctx.state.user:
fastapi:main.py:Depends(:
flask:app.py:@login_required:
sinatra:app.rb:authenticate:
phoenix:lib/app_web/controllers:plug :require:
spring:AdminController.java:@PreAuthorize:jdbcTemplate.execute
quarkus:AdminResource.java:@RolesAllowed:createNativeQuery
ktor:Routing.kt:authenticate:
aspnet:Controllers/AdminController.cs:[Authorize:ExecuteSql
dotnet-minimal:Program.cs:RequireAuthorization:ExecuteSql
actix:src/main.rs:AuthenticatedUser:
axum:src/main.rs:RequireAuth:sqlx::query
aws-lambda:src/handlers/admin.js:requireAuth:
firebase-functions:functions/index.js:verifyIdToken:
supabase-edge:supabase/functions/admin:serverSupabaseUser:
azure-functions:AdminFunction/index.js:requireAuth:
wordpress:wp-content/plugins:current_user_can:wpdb->query
adonis:app/Controllers/Http:middleware:rawQuery
elysia:src/index.ts:beforeHandle:
solidstart:src/routes/api/admin.ts:getSession:
qwik:src/routes/api/admin:sharedMap:
micronaut:AdminController.java:@Secured:createNativeQuery
razor-pages:Pages/Admin.cshtml.cs:[Authorize:ExecuteSql
play-scala:AdminController.scala:AuthenticatedAction:
vapor:Sources/App/routes.swift:grouped(:
rocket:src/main.rs:AuthenticatedUser:
'
while IFS=: read -r fw mark guard danger; do
  [[ -z "$fw" ]] && continue
  SRC="$ROOT/tests/fixtures/repo-$fw"
  [[ -d "$SRC" ]] || { ng "題材がある: repo-$fw" "tests/fixtures/repo-$fw が無い"; continue; }
  cp -R "$SRC" "$TMP/repo-$fw"
  F="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/repo-$fw" 2>&1)"
  # 中核はこの 3 つ。ハンドラを見つけ、ガードを読み、ガードの無いものを名指しできること。
  contains "audit_grep[$fw]: ハンドラを見つける"     "$mark"            "$F"
  contains "audit_grep[$fw]: ガードを読み取る"       "$guard"           "$F"
  # ガードの無いハンドラを名指しできるか。1 ファイルに全部入っている題材では
  # 「定義 N / ガード M」の差で示されるため、そちらを見る。
  # 単一の入口で自前にルーティングする構成は、ハンドラの数を機械的に数えられない。
  # 免除する代わりに、そのことを資料（02 の A-1）に書いてある。
  if [[ "$fw" == "cloudflare-workers" ]]; then
    printf '  \033[33m-\033[0m audit_grep[%s]: 単一の入口のため数を数えない（設計どおり）\n' "$fw"
  elif printf '%s' "$F" | grep -qF "← ガード検出なし"; then
    ok "audit_grep[$fw]: ガードの無いハンドラを名指しする"
  elif printf '%s' "$F" | grep -qE '\(定義 [0-9]+ / ガード [0-9]+\)'; then
    ok "audit_grep[$fw]: 定義数とガード数の差で示す"
  else
    ng "audit_grep[$fw]: ガードの無いハンドラを示す" "空欄も定義／ガードの併記も出ていない"
  fi
  [[ -n "$danger" ]] && contains "audit_grep[$fw]: 危険な書き方を検出" "$danger" "$F"

  # 枠組みごとに固有の検出も見る。ここも 1 つの枠組みの語彙しか持たないと素通りする。
  case "$fw" in
    nuxt)
      contains "audit_grep[$fw]: クライアント露出の特権鍵名" \
               "NUXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY" "$F" ;;
    go)
      contains "audit_grep[$fw]: ルート登録の一覧"   "http.HandleFunc" "$F"
      contains "audit_grep[$fw]: 参照テーブル名"     "users"           "$F" ;;
    laravel)
      contains "audit_grep[$fw]: ルート定義ファイル" "routes/api.php"  "$F" ;;
    express)
      contains "audit_grep[$fw]: 登録行に認可が挟まる形" "requireAuth"  "$F" ;;
  esac
done <<< "$FRAMEWORKS"

# 現実に近い構成の題材。これまでの題材は「ガードあり 1 本・なし 1 本」の最小構成で、
# 入れ子・多層の認可・ミドルウェアの対象外といった、実際に穴が空く形を模していなかった。
if [[ -d "$ROOT/tests/fixtures/repo-realistic" ]]; then
  cp -R "$ROOT/tests/fixtures/repo-realistic" "$TMP/repo-realistic"
  RE="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/repo-realistic" 2>&1)"
  contains "audit_grep[realistic]: 深い入れ子のルート" \
           "app/api/admin/tenants/[tenantId]/members/[memberId]/route.ts" "$RE"
  contains "audit_grep[realistic]: 動的に組み立てるルート" "app/api/[...proxy]/route.ts" "$RE"
  contains "audit_grep[realistic]: ミドルウェアの対象範囲を出す" "matcher" "$RE"
  contains "audit_grep[realistic]: 2 層目のガードが無いルート" "(定義 2 / ガード 0)" "$RE"
  contains "audit_grep[realistic]: Webhook の受け口" "app/api/webhooks" "$RE"
  contains "audit_grep[realistic]: 生 SQL の組み立て" "name like" "$RE"
  # Server Actions。関数ごとにガードの有無を出せること。
  contains "audit_grep[realistic]: Server Actions のファイルを拾う" "app/actions/cart.ts" "$RE"
  if printf '%s' "$RE" | sed -n '/=== 2c\./,/=== 2d\./p' | grep -qE 'addToCart[[:space:]]+ガードあり'; then
    ok "audit_grep[realistic]: Server Action のガードありを関数単位で示す"
  else ng "audit_grep[realistic]: Server Action のガードありを関数単位で示す" "addToCart がガードありと出ない"; fi
  if printf '%s' "$RE" | sed -n '/=== 2c\./,/=== 2d\./p' | grep -qE 'clearCart[[:space:]]+← ガード検出なし'; then
    ok "audit_grep[realistic]: Server Action のガードなしを関数単位で示す"
  else ng "audit_grep[realistic]: Server Action のガードなしを関数単位で示す" "clearCart が空欄と出ない"; fi
  # export していない内部関数は入口ではないので出さない
  absent "audit_grep[realistic]: 内部関数を入口に数えない" "recalc" "$RE"
  # ユーティリティをハンドラとして数えないこと（偽陽性）
  if printf '%s' "$RE" | sed -n '/=== 2\. /,/=== 2b/p' | grep -qF "lib/db.ts"; then
    ng "audit_grep[realistic]: ユーティリティをハンドラに数えない" "lib/db.ts が一覧に出ている"
  else ok "audit_grep[realistic]: ユーティリティをハンドラに数えない"; fi
fi

# 構成の判定。対象に無い技術の資料を読ませないための仕組みで、
# 「有」と「無」の両方が正しく出ることを見る。
for fw in iac mobile; do
  SRC="$ROOT/tests/fixtures/repo-$fw"
  [[ -d "$SRC" ]] || continue
  cp -R "$SRC" "$TMP/repo-$fw"
  C="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/repo-$fw" 2>&1)"
  case "$fw" in
    iac)
      contains "audit_grep[iac]: インフラの定義を検出"   "Terraform"                    "$C"
      contains "audit_grep[iac]: コンテナを検出"         "Dockerfile"                   "$C"
      contains "audit_grep[iac]: Kubernetes を検出"      "Kubernetes"                   "$C"
      if printf '%s' "$C" | sed -n '/追加で読む資料:/,/※/p' | grep -qF "references/13-infrastructure.md"; then
        ok "audit_grep[iac]: 読む資料を名指しする"
      else ng "audit_grep[iac]: 読む資料を名指しする" "「追加で読む資料」に 13 が無い"; fi
      absent   "audit_grep[iac]: モバイルは要らないと言える" "references/14-mobile.md"  "$C" ;;
    mobile)
      contains "audit_grep[mobile]: モバイルを検出"       "android/"                     "$C"
      if printf '%s' "$C" | sed -n '/追加で読む資料:/,/※/p' | grep -qF "references/14-mobile.md"; then
        ok "audit_grep[mobile]: 読む資料を名指しする"
      else ng "audit_grep[mobile]: 読む資料を名指しする" "「追加で読む資料」に 14 が無い"; fi
      absent   "audit_grep[mobile]: IaC は要らないと言える" "references/13-infrastructure.md" "$C" ;;
  esac

  # 資料に「見る」と書いた観点を、機械的にも拾えること。
  # 資料だけあって下拵えが無いと、毎回すべて手で探すことになる。
  case "$fw" in
    iac)
      contains "audit_grep[iac]: root で動くコンテナ"        "USER の指定が無い"    "$C"
      contains "audit_grep[iac]: 特権コンテナ"               "privileged"           "$C"
      contains "audit_grep[iac]: ホストのソケットを渡している" "docker.sock"          "$C"
      contains "audit_grep[iac]: 版が固定されていないイメージ" "版が固定されていない"  "$C"
      contains "audit_grep[iac]: .dockerignore の不在"       ".dockerignore が無い"  "$C"
      contains "audit_grep[iac]: 全開放の受信規則"           "0.0.0.0/0"            "$C"
      contains "audit_grep[iac]: 公開読み取りのストレージ"    "public-read"          "$C"
      contains "audit_grep[iac]: NetworkPolicy の不在"       "NetworkPolicy が無い"  "$C"
      # ここが最も大事。イメージに焼き込まれる値を出力に混ぜないこと。
      leaked=""
      for v in "npm_dummytokenfortest0000000000" "dummy_password_value"; do
        printf '%s' "$C" | grep -qF -- "$v" && leaked="$leaked $v"
      done
      if [[ -z "$leaked" ]]; then ok "audit_grep[iac]: ビルド引数の値を伏字にする"
      else ng "audit_grep[iac]: ビルド引数の値を伏字にする" "出力に含まれた:$leaked"; fi ;;
    mobile)
      contains "audit_grep[mobile]: 平文の保存領域"       "AsyncStorage"          "$C"
      contains "audit_grep[mobile]: 平文通信の許可"       "usesCleartextTraffic"  "$C"
      contains "audit_grep[mobile]: iOS の通信例外"       "NSAllowsArbitraryLoads" "$C"
      contains "audit_grep[mobile]: ディープリンク"       "android:scheme"        "$C"
      contains "audit_grep[mobile]: 他アプリへの公開"     'exported="true"'       "$C"
      contains "audit_grep[mobile]: 要求している権限"     "ACCESS_FINE_LOCATION"  "$C"
      contains "audit_grep[mobile]: 配布物に残る設定"     "debuggable"            "$C" ;;
  esac
done

# Angular のようなフロント専用の枠組みには、そもそもハンドラが無い。
# 見るのは「クライアントに出る値」と「HTML を直接書き込む箇所」になる。
if [[ -d "$ROOT/tests/fixtures/repo-angular" ]]; then
  cp -R "$ROOT/tests/fixtures/repo-angular" "$TMP/repo-angular"
  A2="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/repo-angular" 2>&1)"
  contains "audit_grep[angular]: クライアント露出の特権鍵名" \
           "NG_APP_SUPABASE_SERVICE_ROLE_KEY" "$A2"
fi

# --- scan_secrets.sh ---
# わざと深い場所に置く。この検査は以前、絶対パスが長いと検出内容が表示幅から
# 押し出されて読めなくなる不具合があった。浅い場所に置くと再現しないため、
# パスの長さそのものをテストの条件にしている。
REP="$TMP/deeply/nested/output/directory/for/the/security/assessment/report"
mkdir -p "$REP"
# 以下はすべて架空。検出できるかを見るためだけの値。
cat > "$REP/README.md" <<'EOF'
# ダミーの報告書
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlhdCI6MTYwMH0.zzzzzzzzzz
接続文字列: postgresql://user:pass@db.example.com:5432/app
連絡先: taro.yamada@example.invalid、電話 03-0000-0000
所在地: 東京都渋谷区神南1-2-3。この行は長い。切り詰めが文字の途中で起きると、行末の日本語が壊れる。末尾の目印は神奈川県横浜市西区5-6
カード: 4111 1111 1111 1111
select * from users を実行した。
EOF
# LC_ALL=C で走らせる。cut -c はロケールによってバイト単位で動き、日本語を
# 途中で切って文字化けさせる。その条件を再現しないと、この検査は素通りする。
S="$(env LC_ALL=C bash "$SKILL/scripts/scan_secrets.sh" "$REP" 2>&1)"
for pair in "JWT 形式のトークン" "接続文字列" "メールアドレス" "電話番号らしき並び" \
            "クレジットカード番号らしき並び" "住所らしき記述" "select * の使用"; do
  contains "scan_secrets: $pair" "$pair" "$S"
done
# 検出内容が読める形で出ているか（長いパスに食われて消えていないか）
# 検出行が "./" で始まる（検査対象からの相対パス）こと。絶対パスのままだと、
# パスの長さしだいで肝心の検出内容が表示幅から押し出される。
if printf '%s' "$S" | grep -qE '^  \./README\.md:[0-9]+:'; then
  ok "scan_secrets: 検出行の中身が表示される（相対パスで出る）"
else ng "scan_secrets: 検出行の中身が表示される" "検出行が相対パスで始まっていない"; fi
# 日本語が文字化けしていないか
# 切り詰めが文字の途中で起きると、不正なバイト列が出力に混ざる。
# 特定の文字があるかではなく「出力全体が正しい UTF-8 か」で見る。
# 長い行は 200 文字で切られるので、末尾の文字を期待値にすると正しい実装でも落ちる。
if printf '%s' "$S" | python3 -c "import sys; sys.stdin.buffer.read().decode('utf-8')" 2>/dev/null; then
  ok "scan_secrets: 日本語が壊れない（出力が正しい UTF-8）"
else ng "scan_secrets: 日本語が壊れない" "出力に不正な UTF-8 バイト列が混ざっている"; fi

# --- make_register.py ---
PY_BIN=""
for c in python3 /usr/bin/python3 python; do
  command -v "$c" >/dev/null 2>&1 || continue
  "$c" -c 'import openpyxl' 2>/dev/null && { PY_BIN="$c"; break; }
done
if [[ -z "$PY_BIN" ]]; then
  printf '  \033[33m-\033[0m make_register: openpyxl を持つ python が無いため省略\n'
  # 依存が無いときに、素の ImportError ではなく案内を出すことだけは確かめる
  msg="$(python3 "$SKILL/scripts/make_register.py" "$TMP/x.xlsx" 2>&1 || true)"
  contains "make_register: openpyxl 不在時に案内を出す" "openpyxl が見つからない" "$msg"
else
  for mode in none owasp full; do
    M="$("$PY_BIN" "$SKILL/scripts/make_register.py" "$TMP/r-$mode.xlsx" --frameworks "$mode" 2>&1)"
    case "$mode" in
      none)  want="シート 6 枚" ;;
      owasp) want="シート 7 枚" ;;
      full)  want="シート 9 枚" ;;
    esac
    contains "make_register: --frameworks $mode で $want" "$want" "$M"
  done
  # オプションごとの中身。シート数だけでは、中の項目が消えても気づけない
  M2="$("$PY_BIN" "$SKILL/scripts/make_register.py" "$TMP/r-2021.xlsx" --owasp 2021 2>&1)"
  contains "make_register: --owasp 2021 が選べる" "OWASP 2021 版" "$M2"
  M3="$("$PY_BIN" "$SKILL/scripts/make_register.py" "$TMP/r-api.xlsx" --frameworks full --api 2>&1)"
  contains "make_register: --api で API シートが増える" "4b_API_Top10" "$M3"
  V2="$("$PY_BIN" - "$TMP/r-2021.xlsx" "$TMP/r-full.xlsx" "$TMP/r-api.xlsx" <<'PYEOF' 2>&1
import sys
from openpyxl import load_workbook
bad = []
w = load_workbook(sys.argv[1])["7_枠組みへの当てはめ"]
a10 = [w.cell(r,2).value for r in range(5,15) if w.cell(r,1).value == "A10"]
if not a10 or "Server-Side Request Forgery" not in a10[0]: bad.append("2021 版の A10 が SSRF でない")
wb = load_workbook(sys.argv[2])
w = wb["4_OWASP_Top10"]
a10 = [w.cell(r,2).value for r in range(5,15) if w.cell(r,1).value == "A10"]
if not a10 or "Exceptional" not in a10[0]: bad.append("2025 版の A10 が例外処理でない")
ws = wb["3_個人情報セキュリティ"]
kub = {ws.cell(r,1).value for r in range(6, ws.max_row+1) if ws.cell(r,1).value and ws.cell(r,2).value}
if len(kub) < 11: bad.append(f"個人情報シートの区分が {len(kub)}（11 以上のはず）")
n = sum(1 for r in range(6, ws.max_row+1) if ws.cell(r,2).value)
if n < 50: bad.append(f"個人情報シートの項目が {n}（50 以上のはず）")
ws = wb["5_IPA非機能要求グレード"]
dai = {ws.cell(r,1).value for r in range(13, ws.max_row+1) if ws.cell(r,1).value and ws.cell(r,2).value}
if len(dai) < 6: bad.append(f"IPA の大項目が {len(dai)}（6 のはず）")
ws = load_workbook(sys.argv[3])["4b_API_Top10"]
n = sum(1 for r in range(5, ws.max_row+1) if str(ws.cell(r,1).value or "").startswith("API"))
if n != 10: bad.append(f"API シートが {n} 行（10 のはず）")
print("ALL OK" if not bad else " / ".join(bad))
PYEOF
)"
  if printf '%s' "$V2" | grep -q '^ALL OK$'; then ok "make_register: 版と構成ごとの中身が正しい（2021/2025 の A10、個人情報 11 区分、IPA 6 大項目、API 10 行）"
  else ng "make_register: 版と構成ごとの中身" "$V2"; fi

  # 集計数式が、その構成の指摘一覧シートを正しく指しているか
  V="$("$PY_BIN" - "$TMP/r-full.xlsx" "$TMP/r-owasp.xlsx" <<'PY' 2>&1
import sys
from openpyxl import load_workbook
for path, expect in ((sys.argv[1], "6_指摘事項一覧"), (sys.argv[2], "3_指摘事項一覧")):
    wb = load_workbook(path)
    ws = wb[wb.sheetnames[0]]
    found = False
    for r in range(1, ws.max_row + 1):
        v = ws.cell(r, 2).value
        if isinstance(v, str) and v.startswith("=COUNTIF"):
            found = expect in v
            break
    print(("OK " if found else "NG ") + path.rsplit("/", 1)[-1] + " -> " + expect)
PY
)"
  if printf '%s' "$V" | grep -q '^NG'; then
    ng "make_register: 集計数式が指摘一覧シートを正しく指す" "$V"
  else ok "make_register: 集計数式が指摘一覧シートを正しく指す"; fi
fi

# --- recon.sh / browser_probe.mjs は実サイトへ出る。発火台を立てて確かめる ---
# わざと穴のあるページをローカルで配信し、期待する検出が出るかを見る。外部へは出ない。

U="$(bash "$SKILL/scripts/recon.sh" 2>&1 || true)"
contains "recon: 引数が無いときに使い方を出す" "使い方" "$U"

if command -v node >/dev/null 2>&1; then
  B="$(node "$SKILL/scripts/browser_probe.mjs" 2>&1 || true)"
  contains "browser_probe: 引数が無いときに使い方を出す" "使い方" "$B"
  B2="$(node "$SKILL/scripts/browser_probe.mjs" 'not a url' 2>&1 || true)"
  contains "browser_probe: URL でない引数を弾く" "URL として読めない" "$B2"

  # 既知タグのラベル付けは、発火台では検査できない（ローカルでは googletagmanager.com
  # というホスト名を作れないため）。スクリプトから TAGS を読み込んで直接当てる。
  # import しても副作用が起きないよう、実行部分は main() に入れてある。
  T="$(node - "$SKILL/scripts/browser_probe.mjs" <<'NODE' 2>&1 || true
import { pathToFileURL } from "node:url";
const { TAGS } = await import(pathToFileURL(process.argv[2]).href);
const cases = [
  ["www.googletagmanager.com", "Google タグマネージャ"],
  ["www.google-analytics.com", "Google アナリティクス"],
  ["pagead2.googlesyndication.com", "Google 広告"],
  ["connect.facebook.net", "Meta ピクセル"],
  ["www.clarity.ms", "Microsoft Clarity"],
  ["o0.ingest.sentry.io", "Sentry"],
];
let bad = 0;
for (const [host, want] of cases) {
  const hit = TAGS.find(([re]) => re.test(host));
  if (!hit || hit[1] !== want) { console.log(`NG ${host} -> ${hit ? hit[1] : "(未検出)"} / 期待 ${want}`); bad++; }
}
// 自ドメインらしきホストを取り違えないこと
for (const host of ["example.com", "cdn.example.com", "notgoogle.example.com"]) {
  const hit = TAGS.find(([re]) => re.test(host));
  if (hit) { console.log(`NG ${host} を ${hit[1]} と誤判定した`); bad++; }
}
console.log(bad === 0 ? "ALL OK" : `${bad} 件失敗`);
NODE
)"
  if printf '%s' "$T" | grep -q '^ALL OK$'; then ok "browser_probe: 既知タグのラベル付け（12 種・誤判定 3 例）"
  else ng "browser_probe: 既知タグのラベル付け" "$T"; fi
else
  printf '  \033[33m-\033[0m browser_probe（node が無いため省略）\n'
fi

if ! command -v node >/dev/null 2>&1; then
  printf '  \033[33m-\033[0m 発火台を使う検査（node が無いため省略）\n'
else
  PORT="$(node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
  node "$ROOT/tests/fixtures/site/server.mjs" "$PORT" > "$TMP/site.log" 2>&1 &
  SITE_PID=$!
  trap 'kill $SITE_PID 2>/dev/null' EXIT
  # 起動を待つ。固定の sleep だと遅い環境で落ちる
  for _ in $(seq 1 40); do
    node -e "require('net').connect($PORT,'127.0.0.1').on('connect',()=>process.exit(0)).on('error',()=>process.exit(1))" \
      >/dev/null 2>&1 && break
    sleep 0.25
  done

  # ---- recon.sh ----
  R1="$(bash "$SKILL/scripts/recon.sh" "http://localhost:$PORT" /admin 2>&1 || true)"
  contains "recon[実地]: セキュリティヘッダの欠如を検出"   "[無] x-frame-options" "$R1"
  contains "recon[実地]: x-powered-by の露出を検出"        "実装情報が露出"       "$R1"
  contains "recon[実地]: クライアントの JWT を検出"        "JWT 形式: 1 件"       "$R1"
  contains "recon[実地]: JWT のロールを読む"               '"role": "anon"'       "$R1"
  contains "recon[実地]: 第三者オリジンを列挙"             "127.0.0.1:$PORT"      "$R1"
  contains "recon[実地]: 追加パスのステータスを出す"       "403"                  "$R1"
  # 自サイトの絶対 URL（canonical）が第三者に混ざらないこと。ポート付きでも同じ。
  if printf '%s' "$R1" | sed -n '/第三者オリジン/,/既知タグ/p' | grep -qF "localhost:$PORT"; then
    ng "recon[実地]: 自サイトを第三者に数えない" "localhost:$PORT が第三者として出ている"
  else ok "recon[実地]: 自サイトを第三者に数えない"; fi
  # 鍵の値をそのまま出していないこと
  if printf '%s' "$R1" | grep -qE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}'; then
    ng "recon[実地]: 鍵の値を伏字にする" "JWT がそのまま出力されている"
  else ok "recon[実地]: 鍵の値を伏字にする"; fi

  # 正しく作られている側にも当てる。誤検出するツールは、指摘の山に埋もれて
  # 本当に危ないものを隠す。
  R2="$(bash "$SKILL/scripts/recon.sh" "http://localhost:$PORT/clean" 2>&1 || true)"
  absent   "recon[誤検出]: 揃ったヘッダを欠如と言わない"     "[無] x-frame-options" "$R2"
  absent   "recon[誤検出]: x-powered-by が無ければ触れない"  "実装情報が露出"       "$R2"
  contains "recon[誤検出]: 第三者が無ければ無いと言える"     "第三者オリジンの検出なし" "$R2"

  # ---- recon.sh の DNS まわり ----
  # 発火台は localhost だが、localhost は OS が特別扱いして常に 127.0.0.1 を返すため、
  # DNS の検査には使えない。別の受け口（tests/fixtures/site/dns.py）を立て、
  # RECON_DNS でそこへ向け、解決できない名前（example.test）で recon.sh を呼ぶ。
  # HTTP 側は即座に失敗するが、DNS の節は独立して動く。
  DPORT="$(node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
  python3 "$ROOT/tests/fixtures/site/dns.py" "$DPORT" > "$TMP/dns.log" 2>&1 &
  DNS_PID=$!
  trap 'kill $SITE_PID $DNS_PID 2>/dev/null' EXIT
  for _ in $(seq 1 20); do grep -q '起動した' "$TMP/dns.log" 2>/dev/null && break; sleep 0.25; done
  if command -v dig >/dev/null 2>&1; then
    R3="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://example.test:1" 2>&1 || true)"
    contains "recon[DNS]: apex に SPF が無いと判定"        "[無] SPF"                "$R3"
    contains "recon[DNS]: DMARC を検出"                     "[有] DMARC"              "$R3"
    contains "recon[DNS]: DMARC が p=none だと指摘"         "p=none。監視のみ"        "$R3"
    contains "recon[DNS]: 配信サービス用サブドメインの SPF" "send.example.test"       "$R3"
    contains "recon[DNS]: DKIM セレクタを検出"              "resend._domainkey"       "$R3"
    contains "recon[DNS]: NS を取得"                        "ns1.example.invalid"     "$R3"
    # CAA と DS は返さない = 空で出ること（誤って何かを表示しない）
    if printf '%s' "$R3" | grep -qE '^  CAA    : *$'; then ok "recon[DNS]: CAA が無ければ空で出す"
    else ng "recon[DNS]: CAA が無ければ空で出す" "CAA の行に何か出ている"; fi
    # DMARC の rua に入っているアドレスを、出力に出さないこと（報告書に不要な個人情報）
    absent "recon[DNS]: DMARC の連絡先アドレスを出力に混ぜない" "dmarc@example.invalid" "$R3"
  else
    printf '  \033[33m-\033[0m recon の DNS 検査（dig が無いため省略）\n'
  fi
  kill $DNS_PID 2>/dev/null

  # ---- browser_probe.mjs ----
  if ! node -e 'import("playwright")' >/dev/null 2>&1; then
    B3="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT" 2>&1 || true)"
    contains "browser_probe: Playwright 不在時に導入手順を出す" "npx playwright install" "$B3"
    printf '  \033[33m-\033[0m browser_probe の実地検査（playwright が無いため省略）\n'
  else
    P="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT" /mypage /admin 2>&1 || true)"
    contains "browser_probe[実地]: 同意前の第三者送信を数える"     "127.0.0.1" "$P"
    contains "browser_probe[実地]: 成立しなかった送信を区別する"   "成立せず"  "$P"
    contains "browser_probe[実地]: HttpOnly の無い Cookie を検出"  "**HttpOnly なし**" "$P"
    contains "browser_probe[実地]: 保存領域の認証情報らしきキー"   "authToken" "$P"
    contains "browser_probe[実地]: CSP の unsafe-inline を検出"    "unsafe-inline がある" "$P"
    contains "browser_probe[実地]: セキュリティヘッダの欠如を検出" "[無] x-frame-options" "$P"
    contains "browser_probe[実地]: x-powered-by の露出を検出"      "x-powered-by" "$P"
    contains "browser_probe[実地]: 追加パスの応答を出す"           "403" "$P"

    # ここがいちばん大事。値を出力に混ぜていないこと。
    leaked=""
    for v in "dummy-token-value-should-not-be-printed" \
             "dummy-csrf-should-not-be-printed" \
             "dummyvalue123"; do
      printf '%s' "$P" | grep -qF -- "$v" && leaked="$leaked $v"
    done
    if [[ -z "$leaked" ]]; then ok "browser_probe[実地]: Cookie と保存領域の値を出力しない"
    else ng "browser_probe[実地]: Cookie と保存領域の値を出力しない" "出力に含まれた:$leaked"; fi

    # ---- 正しく作られている側に当てて、誤検出しないことを見る ----
    # 穴を見つけられるかだけでは足りない。誤検出するツールは、指摘の山に埋もれて
    # 本当に危ないものを隠す。/clean は同意を取るまで第三者へ送らず、HttpOnly を付け、
    # CSP に unsafe-inline を持たず、セキュリティヘッダを揃えてある。
    C="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT/clean" 2>&1 || true)"
    contains "browser_probe[誤検出]: 同意前の送信が無いことを言える" "送信は観測されなかった" "$C"
    absent   "browser_probe[誤検出]: HttpOnly のある Cookie を咎めない" "**HttpOnly なし**" "$C"
    absent   "browser_probe[誤検出]: 健全な CSP を咎めない"           "unsafe-inline がある" "$C"
    absent   "browser_probe[誤検出]: 揃ったヘッダを欠如と言わない"     "[無] x-frame-options" "$C"
    absent   "browser_probe[誤検出]: x-powered-by が無ければ触れない"  "実装情報が露出"       "$C"
    contains "browser_probe[誤検出]: 空の保存領域を空と言える"         "localStorage: （空）" "$C"
  fi

  kill $SITE_PID 2>/dev/null
  trap - EXIT
fi

# ==========================================================================
printf '\n\033[1m結果\033[0m  成功 %d / 失敗 %d\n' "$PASS" "$FAIL"
if [[ $FAIL -gt 0 ]]; then exit 1; fi
rm -rf "$TMP"
