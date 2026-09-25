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

# 題材を一時ディレクトリへ写す。依存の定義ファイル（package.json・ロックファイル・requirements.txt）は、
# リポジトリの中では末尾に .fixture を付けて置き、ここで元の名前に戻す。そのまま置くと GitHub の依存関係グラフが
# 題材のわざと古い版を拾い、Dependabot の警告が出続ける。
fixture_cp() {
  cp -R "$1" "$2"
  find "$2" -type f -name '*.fixture' | while IFS= read -r f; do mv "$f" "${f%.fixture}"; done
}
# 環境に道具が無くて検査を省いたとき。数えて結果の行に出す（省略で件数が減っても緑に見えないように）
SKIPPED=0
skip() { printf '  \033[33m-\033[0m %s\n' "$1"; SKIPPED=$((SKIPPED+1)); }

# 期待する文字列が出力に含まれるか
contains() {
  local label="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -F -- "$needle" >/dev/null; then ok "$label"
  else ng "$label" "「${needle}」が出力に無い"; fi
}

# 出力に含まれてはいけない文字列。誤検出していないかを見るのに使う。
absent() {
  local label="$1" needle="$2" hay="$3"
  if printf '%s' "$hay" | grep -F -- "$needle" >/dev/null; then ng "$label" "「${needle}」を誤って出している"
  else ok "$label"; fi
}

# ==========================================================================
head_ "1. 構造 — SKILL.md と実態が合っているか"

# frontmatter
if head -1 "$SKILL/SKILL.md" | grep '^---$' >/dev/null; then ok "SKILL.md に frontmatter がある"
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

# 題材の依存の定義ファイルは .fixture を付けて置く（fixture_cp の説明を参照）
raw="$(git -C "$ROOT" ls-files tests/fixtures 2>/dev/null | grep -E '(^|/)(package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|requirements\.txt|pyproject\.toml|Gemfile|Gemfile\.lock|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|composer\.json|composer\.lock|pom\.xml|Package\.swift)$' || true)"
if [[ -z "$raw" ]]; then ok "題材の依存の定義ファイルに .fixture が付いている（依存関係グラフに拾わせない）"
else ng "題材の依存の定義ファイルに .fixture が付いている（依存関係グラフに拾わせない）" "$(printf '%s' "$raw" | tr '\n' ' ')"; fi

# スクリプトの実行権限。拡張子で列挙すると新しい種類を足したときに漏れるため、
# scripts/ 配下のファイルをすべて対象にする（ここには実行するものしか置かない）。
for f in "$SKILL"/scripts/*; do
  [[ -f "$f" ]] || continue
  if [[ -x "$f" ]]; then ok "実行権限: $(basename "$f")"
  else ng "実行権限: $(basename "$f")" "chmod 755 が要る"; fi
done

# 構文
for f in "$SKILL"/scripts/*.sh "$ROOT"/build/hooks/*; do
  if bash -n "$f" 2>/dev/null; then ok "構文: $(basename "$f")"
  else ng "構文: $(basename "$f")"; fi
done
# bash 3.2（macOS の既定）は、UTF-8 の環境で "$v（" のように変数名の直後に全角文字が続くと、
# その文字まで変数名として読み、set -u で止まる。実際に 1b 節がロックファイルの無い構成で止まっていた。
# 構文検査（bash -n）では見つからないので、書き方で捕まえる。${v} と書けば起きない。
mb="$(LC_ALL=C grep -nE '\$[A-Za-z_][A-Za-z0-9_]*[^ -~[:space:]]' "$SKILL"/scripts/*.sh "$ROOT"/tests/*.sh "$ROOT"/build/*.sh "$ROOT"/build/hooks/* 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)"
# pipefail のもとで「… | grep -q」と書くと、grep -q が見つけた時点で終わり、書き手が SIGPIPE で落ちて
# パイプライン全体が失敗扱いになる。見つかったのに「無い」と判定することが確率的に起きる（Linux で 200 回に 1 回）。
# 検査の absent では、本当は出ている文字列を「出ていない」として素通りさせる。grep ... >/dev/null で読み切らせる。
gq="$(grep -nE '(^|[^|])\|[[:space:]]*grep[[:space:]]+-q' "$SKILL"/scripts/*.sh "$ROOT"/tests/*.sh "$ROOT"/build/*.sh "$ROOT"/build/hooks/* 2>/dev/null \
      | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#|s = s\.replace\(' || true)"
if [[ -z "$gq" ]]; then ok "パイプで grep -q に渡していない（pipefail のもとで確率的に誤る書き方）"
else ng "パイプで grep -q に渡していない（pipefail のもとで確率的に誤る書き方）" "$(printf '%s' "$gq" | head -3 | cut -c1-120)"; fi
if [[ -z "$mb" ]]; then ok "変数名の直後に全角文字が続かない（bash 3.2 で止まる書き方）"
else ng "変数名の直後に全角文字が続かない（bash 3.2 で止まる書き方）" "$(printf '%s' "$mb" | head -3 | cut -c1-120)"; fi
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
  skip "構文: *.mjs（node が無いため省略）"
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
  skip "案件固有語: tests/ngwords.local が無い（過去の案件を示す語は検査されない）"
fi
hit="$(grep -rniE "$NGWORDS" "$SKILL" 2>/dev/null || true)"
if [[ -z "$hit" ]]; then ok "案件固有語が含まれない"
else ng "案件固有語が含まれない" "$(printf '%s' "$hit" | head -3)"; fi

# 例示以外のドメインが書かれていないか。example.com / example.invalid だけを許す。
bad="$(grep -rhoE 'https?://[A-Za-z0-9.-]+' "$SKILL" 2>/dev/null \
       | grep -vE '://(example\.(com|invalid|org|net)|localhost)' \
       | grep -vE '://(www\.)?(cisa\.gov|owasp\.org|genai\.owasp\.org|mas\.owasp\.org|top10\.owasp\.org|api-security\.owasp\.org|jvn\.jp|jvndb\.jvn\.jp|jpcert\.or\.jp|ipa\.go\.jp|ppc\.go\.jp|soumu\.go\.jp|cisecurity\.org|github\.com|nvd\.nist\.gov|csrc\.nist\.gov|cwe\.mitre\.org|pcisecuritystandards\.org|j-credit\.or\.jp)' \
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
fixture_cp "$ROOT/tests/fixtures/repo" "$REPO"
echo 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=dummy' > "$REPO/.env.local"
# 履歴の検査に使うのでコミットまでする。利用者の署名の設定・フック・GIT_DIR に左右されないようにする
( cd "$REPO" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
  git init -q . && git add -A -f >/dev/null 2>&1 \
    && git -c user.email=t@example.invalid -c user.name=t -c commit.gpgsign=false -c core.hooksPath=/dev/null \
         commit -qm fixture >/dev/null 2>&1 ) || true

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
if printf '%s' "$A" | grep -F 'sk_live_00000000000000000000TESTDUMMY' >/dev/null; then
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
  fixture_cp "$SRC" "$TMP/repo-$fw"
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
  elif printf '%s' "$F" | grep -F "← ガード検出なし" >/dev/null; then
    ok "audit_grep[$fw]: ガードの無いハンドラを名指しする"
  elif printf '%s' "$F" | grep -E '\(定義 [0-9]+ / ガード [0-9]+\)' >/dev/null; then
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
  fixture_cp "$ROOT/tests/fixtures/repo-realistic" "$TMP/repo-realistic"
  # 題材は「.gitignore で無視された .env を持つ構成」。無視されたファイルは clone に来ないので、ここで作る
  printf 'NEXT_PUBLIC_API_URL=https://example.invalid\nSTRIPE_WEBHOOK_SECRET=whsec_dummy\n' > "$TMP/repo-realistic/.env.local"
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
  if printf '%s' "$RE" | sed -n '/=== 2c\./,/=== 2d\./p' | grep -E 'addToCart[[:space:]]+ガードあり' >/dev/null; then
    ok "audit_grep[realistic]: Server Action のガードありを関数単位で示す"
  else ng "audit_grep[realistic]: Server Action のガードありを関数単位で示す" "addToCart がガードありと出ない"; fi
  if printf '%s' "$RE" | sed -n '/=== 2c\./,/=== 2d\./p' | grep -E 'clearCart[[:space:]]+← ガード検出なし' >/dev/null; then
    ok "audit_grep[realistic]: Server Action のガードなしを関数単位で示す"
  else ng "audit_grep[realistic]: Server Action のガードなしを関数単位で示す" "clearCart が空欄と出ない"; fi
  # export していない内部関数は入口ではないので出さない
  absent "audit_grep[realistic]: 内部関数を入口に数えない" "recalc" "$RE"
  # ユーティリティをハンドラとして数えないこと（偽陽性）
  if printf '%s' "$RE" | sed -n '/=== 2\. /,/=== 2b/p' | grep -F "lib/db.ts" >/dev/null; then
    ng "audit_grep[realistic]: ユーティリティをハンドラに数えない" "lib/db.ts が一覧に出ている"
  else ok "audit_grep[realistic]: ユーティリティをハンドラに数えない"; fi
fi

# 基盤・CI・依存・エージェント設定・リアルタイム・SMS の題材（1b / 4d / 9b / 10b / 19〜24 節）。
# どの節にも「穴のある側」と「正しく作った側」を置き、検出と誤検出の両方を見る。
# 名前を repo* にしないのは、枠組みごとの題材の数（README）に数えないため。
if [[ -d "$ROOT/tests/fixtures/supply-baas" ]]; then
  fixture_cp "$ROOT/tests/fixtures/supply-baas" "$TMP/supply-baas"
  # AI エージェントの設定ファイルは、開いた人の環境で実際に効くのでリポジトリに置かない。ここで作る
  A="$TMP/supply-baas"
  mkdir -p "$A/.claude" "$A/.vscode"
  printf '{ "permissions": { "defaultMode": "bypassPermissions" } }\n' > "$A/.claude/settings.json"
  printf '{ "version": "2.0.0", "tasks": [ { "label": "setup", "command": "true", "runOptions": { "runOn": "folderOpen" } } ] }\n' > "$A/.vscode/tasks.json"
  printf '{ "mcpServers": { "db": { "command": "npx", "args": ["-y", "EXAMPLE-NOT-A-PACKAGE"], "env": { "DATABASE_URL": "postgres://admin:FIXTURE-PASSWORD@db.example.invalid/app" } } } }\n' > "$A/.mcp.json"
  printf '# 題材\n\nこの行の中には見えない文字\xe2\x80\x8bがある。\n' > "$A/AGENTS.md"
  printf '# 題材\n\n見えない文字は無い。\n' > "$A/CLAUDE.md"
  echo '{}' > "$A/.claude/settings.local.json"
  # 個人用の設定がコミットされている形を作る。git ls-files は索引を読むので add だけで足りる。
  # コミットしないのは、利用者の署名の設定で止まったり、GIT_DIR が外のリポジトリを指していて
  # そちらに書き込んだりするのを避けるため
  ( cd "$A" && env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git init -q \
    && env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git add -A \
    && env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE git add -f .claude/settings.local.json ) >/dev/null 2>&1 || true
  SB="$(bash "$SKILL/scripts/audit_grep.sh" "$A" 2>&1)"
  # 節の切り出し。見出しから次の見出しの直前まで。LC_ALL=C で読み、出力に不正なバイトが混ざっても
  # 空にならないようにする（空になると absent の検査が何も見ずに通る）
  sec() { printf '%s\n' "$SB" | LC_ALL=C awk -v s="=== $1" 'index($0, s) == 1 { f = 1; print; next } f && /^=== / { exit } f'; }
  S0="$(sec '0.')"; S1B="$(sec '1b.')"; S4D="$(sec '4d.')"; S10B="$(sec '10b.')"
  S19="$(sec '19.')"; S20="$(sec '20.')"; S21="$(sec '21.')"; S22="$(sec '22.')"
  # 切り出しが空なら、それ自体を失敗にする（absent が素通りするのを防ぐ）
  for v in S0 S1B S4D S10B S19 S20 S21 S22; do
    if [[ -n "${!v}" ]]; then ok "audit_grep[基盤]: 節を切り出せる（${v}）"
    else ng "audit_grep[基盤]: 節を切り出せる（${v}）" "空。見出しが変わったか、出力が壊れている"; fi
  done

  contains "audit_grep[基盤]: 構成の判定で BaaS を名指しする"        "Supabase Firebase Clerk Convex" "$S0"
  contains "audit_grep[基盤]: カード決済なら 06 を読ませる"          "references/06-frameworks.md"    "$S0"
  contains "audit_grep[基盤]: 画面操作の記録を 0 節で名指しする"    "有 → 08 の 1-2・09 の 11 節（9b 節）" "$S0"
  contains "audit_grep[基盤]: BaaS なら読む節を名指しする"          "07 の 11-3・11-4（19 節）"      "$S0"
  # SKILL.md の「どの資料が要るか」の表と、0 節の「追加で読む資料」が揃っているか
  if printf '%s' "$S0" | sed -n '/追加で読む資料:/,/※/p' | grep -F "references/09-browser-verification.md" >/dev/null; then
    ok "audit_grep[基盤]: 画面操作の記録があれば 09 を読ませる"
  else ng "audit_grep[基盤]: 画面操作の記録があれば 09 を読ませる" "「追加で読む資料」に 09 が無い"; fi
  contains "audit_grep[基盤]: SMS の送信を 0 節で名指しする"        "有 → 02 の F-4・03 の 3 節（24 節）" "$S0"
  # 1b. 枠組みの版
  contains "audit_grep[版]: ミドルウェア迂回の修正前を判定"          "CVE-2025-29927 の修正前"        "$S1B"
  contains "audit_grep[版]: React2Shell の修正前を判定"              "React2Shell（CVE-2025-55182"      "$S1B"
  contains "audit_grep[版]: adapter-vercel のキャッシュ不具合"       "CVE-2026-27118 の修正前"        "$S1B"
  absent   "audit_grep[版]: 15 系をサポート外と言わない"             "サポート外"                     "$S1B"
  # 4d. LLM の鍵
  contains "audit_grep[LLM鍵]: ブラウザから直接呼ぶ指定"             "dangerouslyAllowBrowser"        "$S4D"
  contains "audit_grep[LLM鍵]: 公開用の接頭辞が付いた LLM の鍵"      "NEXT_PUBLIC_OPENAI_API_KEY"     "$S4D"
  # 10b. サーバー側のセッション検証
  contains "audit_grep[セッション]: サーバー側の getSession"         "lib/supabase-server.ts"         "$S10B"
  absent   "audit_grep[セッション]: 'use client' の getSession は除く" "app/HeaderClient.tsx"        "$S10B"
  contains "audit_grep[セッション]: allowedOrigins のワイルドカード" "*.example.com"                  "$S10B"
  contains "audit_grep[セッション]: Host ヘッダから URL を組む"      "app/api/reset/route.ts"         "$S10B"
  # 19. BaaS
  contains "audit_grep[基盤]: RLS を有効にしていないテーブル"        "★ public.profiles"              "$S19"
  if printf '%s' "$S19" | grep -E '★ public\.orders$' >/dev/null; then ng "audit_grep[基盤]: RLS を有効にしたテーブルを咎めない" "orders が★で出ている"
  else ok "audit_grep[基盤]: RLS を有効にしたテーブルを咎めない"; fi
  absent   "audit_grep[基盤]: API に出ないスキーマは除く"            "audit_log"                      "$S19"
  contains "audit_grep[基盤]: search_path を固定しない定義者権限"    "admin_list_profiles（search_path の固定なし）" "$S19"
  absent   "audit_grep[基盤]: search_path を固定した関数は咎めない"  "my_orders（search_path"         "$S19"
  contains "audit_grep[基盤]: security_invoker の無いビュー"         "order_summary"                  "$S19"
  absent   "audit_grep[基盤]: security_invoker 付きのビューは咎めない" "my_order_view"                "$S19"
  contains "audit_grep[基盤]: マテリアライズドビュー"                "order_stats"                    "$S19"
  contains "audit_grep[基盤]: user_metadata による認可"              "user_metadata を認可に使っている" "$S19"
  contains "audit_grep[基盤]: 公開バケット"                          "公開バケットの疑い"             "$S19"
  contains "audit_grep[基盤]: JWT の検証を外した Edge Function"      "stripe-hook"                    "$S19"
  if printf '%s' "$S19" | grep -E 'config\.toml: api$' >/dev/null; then ng "audit_grep[基盤]: verify_jwt = true の関数を咎めない" "api が出ている"
  else ok "audit_grep[基盤]: verify_jwt = true の関数を咎めない"; fi
  contains "audit_grep[基盤]: Firebase の誰でも読めるルール"         "★ 誰でも: ./firestore.rules:5" "$S19"
  contains "audit_grep[基盤]: ログイン済みなら誰でも"               "ログイン済みなら誰でも: ./firestore.rules:8" "$S19"
  absent   "audit_grep[基盤]: 所有者を照合するルールは咎めない"      "firestore.rules:11"            "$S19"
  contains "audit_grep[基盤]: 何も保護しない clerkMiddleware"        "既定では何も保護しない"         "$S19"
  if printf '%s' "$S19" | grep -E 'convex/messages\.ts: list +★ 認証の確認なし' >/dev/null; then ok "audit_grep[基盤]: 認証を確かめない Convex の関数"
  else ng "audit_grep[基盤]: 認証を確かめない Convex の関数" "messages.ts の list が★で出ない"; fi
  if printf '%s' "$S19" | grep -E 'convex/tasks\.ts: mine +認証の確認あり' >/dev/null; then ok "audit_grep[基盤]: 認証を確かめる Convex の関数は咎めない"
  else ng "audit_grep[基盤]: 認証を確かめる Convex の関数は咎めない" "tasks.ts の mine が確認ありと出ない"; fi
  # 同じファイルの中でも関数ごとに見る。前の関数の確認を次の関数へ持ち越さない
  if printf '%s' "$S19" | grep -E 'convex/tasks\.ts: all +★ 認証の確認なし' >/dev/null; then ok "audit_grep[基盤]: Convex の確認を次の関数へ持ち越さない"
  else ng "audit_grep[基盤]: Convex の確認を次の関数へ持ち越さない" "tasks.ts の all が★で出ない"; fi
  # 20. CI
  contains "audit_grep[CI]: 固定していない Action"                   "actions/checkout@v4"            "$S20"
  contains "audit_grep[CI]: サブパス付きの Action も拾う"            "codeql-action/init@v3"          "$S20"
  absent   "audit_grep[CI]: ハッシュで固定した Action は出さない"    "0123456789abcdef0123456789abcdef01234567" "$S20"
  absent   "audit_grep[CI]: ローカルの Action は出さない"            "./.github/actions/local"        "$S20"
  contains "audit_grep[CI]: 危険なトリガー"                          "pull_request_target"            "$S20"
  contains "audit_grep[CI]: PR の中身の取得"                          "pull_request.head.sha"          "$S20"
  contains "audit_grep[CI]: run: への外部値の埋め込み"               "github.event.pull_request.title" "$S20"
  contains "audit_grep[CI]: permissions の無いワークフロー"          "ci.yml: トップレベルの permissions が無い" "$S20"
  absent   "audit_grep[CI]: permissions のあるワークフローは咎めない" "ok.yml: トップレベル"          "$S20"
  contains "audit_grep[CI]: 秘密情報の出力"                          'echo ${{ secrets.NPM_TOKEN }}'  "$S20"
  contains "audit_grep[CI]: npm install を使うビルド"                "ci.yml:13"                      "$S20"
  absent   "audit_grep[CI]: npm ci は咎めない"                        "npm ci"                         "$S20"
  # 21. インストール時の防御
  contains "audit_grep[依存]: インストール時のスクリプト"            "@scope/native-thing"            "$S21"
  contains "audit_grep[依存]: 公式レジストリ以外の取得元"            "公式レジストリ以外から取っている依存" "$S21"
  contains "audit_grep[依存]: クールダウンの設定を読む"              "min-release-age=3"              "$S21"
  # 22. エージェントの設定
  contains "audit_grep[エージェント]: 権限の緩和"                    "bypassPermissions"              "$S22"
  contains "audit_grep[エージェント]: フォルダを開くだけで走るタスク" "folderOpen"                    "$S22"
  contains "audit_grep[エージェント]: 版を固定しない MCP サーバー"   "EXAMPLE-NOT-A-PACKAGE"          "$S22"
  absent   "audit_grep[エージェント]: 設定の中の接続文字列の認証情報を伏せる" "FIXTURE-PASSWORD"         "$S22"
  contains "audit_grep[エージェント]: 個人用設定のコミット"          "個人用の設定がコミットされている" "$S22"
  if command -v perl >/dev/null 2>&1; then
    contains "audit_grep[エージェント]: 見えない Unicode"            "★ AGENTS.md:3"                  "$S22"
    absent   "audit_grep[エージェント]: 普通の指示書は咎めない"      "★ CLAUDE.md"                    "$S22"
  fi
  # 23. リアルタイム通信
  S23="$(sec '23.')"
  contains "audit_grep[リアルタイム]: private の無い Supabase のチャネル"   "★ ./app/chat.ts:3:"             "$S23"
  absent   "audit_grep[リアルタイム]: private: true のチャネルは咎めない"   "chat.ts:8:"                     "$S23"
  contains "audit_grep[リアルタイム]: publication と replica identity"      "replica identity full"          "$S23"
  contains "audit_grep[リアルタイム]: Origin を検証しない WebSocket"        "Origin を検証している形跡が無い" "$S23"
  contains "audit_grep[リアルタイム]: クライアントの指定したルームに参加"   "socket.join(data.room)"         "$S23"
  contains "audit_grep[リアルタイム]: SSE の配信ハンドラ"                   "app/api/stream/route.ts"        "$S23"
  contains "audit_grep[リアルタイム]: トークンを URL に載せた SSE"         "トークンを URL に載せている"    "$S23"
  # 9b. セッションリプレイ / 24. SMS
  S9B="$(sec '9b.')"; S24="$(sec '24.')"
  contains "audit_grep[リプレイ]: 使っているツール"                  "replayIntegration"              "$S9B"
  contains "audit_grep[リプレイ]: マスクを緩める設定"                "maskAllText: false"             "$S9B"
  contains "audit_grep[リプレイ]: 通信の本文の記録"                  "networkDetailAllowUrls"         "$S9B"
  contains "audit_grep[リプレイ]: 利用者の特定"                      "Sentry.setUser"                 "$S9B"
  contains "audit_grep[SMS]: SMS を送らせる箇所"                     "lib/sms.ts"                     "$S24"
  contains "audit_grep[SMS]: Supabase の SMS の設定"                 "[auth.sms]"                     "$S24"
  contains "audit_grep[SMS]: API の直接呼び出し"                     "SMS の API を直接呼んでいる"    "$S24"
  # 確認用サービス（verifications.create）だけなら、直接呼び出しとは言わない（誤検出）
  mkdir -p "$TMP/sms-ok"
  printf 'export const send = (to) => client.verify.v2.services(SID).verifications.create({ to, channel: "sms" });\n' > "$TMP/sms-ok/otp.ts"
  SO="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/sms-ok" 2>&1)"
  contains "audit_grep[SMS]: 確認用サービスの呼び出しを拾う"         "verifications.create"           "$SO"
  absent   "audit_grep[SMS]: 確認用サービスだけなら直接呼び出しと言わない" "SMS の API を直接呼んでいる" "$SO"
  # Origin を検証していれば咎めない（誤検出）
  mkdir -p "$TMP/ws-ok"
  cp "$ROOT/tests/fixtures/supply-baas/server/ws.js" "$TMP/ws-ok/ws.js"
  cat > "$TMP/ws-ok/upgrade.js" <<'JS'
server.on('upgrade', (req, socket, head) => {
  if (!ALLOWED.includes(req.headers.origin)) return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});
JS
  WO="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/ws-ok" 2>&1)"
  contains "audit_grep[リアルタイム]: Origin の検証を読み取る"               "headers.origin"                 "$WO"
  absent   "audit_grep[リアルタイム]: Origin を検証していれば咎めない"       "Origin を検証している形跡が無い" "$WO"
  # 途中で止まらず最後まで出ること（bash 3.2 の set -u で止まった不具合があった）
  contains "audit_grep[基盤]: 最後の節まで出力する"                 "=== 完了 ==="                   "$SB"
  # ロックファイルが無く package.json だけの構成でも止まらないこと（1b 節の旧不具合）
  mkdir -p "$TMP/nolock" && printf '{"dependencies":{"next":"^15.1.0"}}\n' > "$TMP/nolock/package.json"
  NL="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/nolock" 2>&1)"
  contains "audit_grep[版]: ロックファイルが無くても止まらない"      "package.json の宣言。解決結果ではない" "$NL"
  contains "audit_grep[版]: ロックファイルが無くても最後まで出す"    "=== 完了 ==="                   "$NL"
  absent   "audit_grep[版]: 宣言の範囲では版を判定しない"           "修正前"                            "$(printf '%s' "$NL" | sed -n '/=== 1b/,/=== 2\./p')"
  # マイグレーションのパスに空白があっても読み飛ばさない（空白で分割していた旧不具合）
  mkdir -p "$TMP/sp ace/supabase/migrations"
  printf '{"dependencies":{"@supabase/supabase-js":"2"}}\n' > "$TMP/sp ace/package.json"
  printf 'create table public.secrets (id int);\n' > "$TMP/sp ace/supabase/migrations/001 init.sql"
  SPC="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/sp ace" 2>&1)"
  contains "audit_grep[基盤]: 空白を含むパスのマイグレーションも読む" "★ public.secrets"          "$SPC"
  # 依存名は、実際のロックファイルのように間に integrity / dev が入っても取れること
  absent   "audit_grep[依存]: 取得元の URL の認証情報を伏せる"       "user:secret"                    "$S21"
  # ---- 依存と生成物を読まない・値を出さない・切り捨てを示す（2.17.4 の修正） ----
  G="$TMP/guards"; mkdir -p "$G/node_modules/pkg" "$G/.next/server/app/api/x" "$G/app/api/ok" "$G/app/api/host" \
    "$G/.github/workflows" "$G/scripts/rebuild" "$G/theme" "$G/app/api/chat" "$G/app/api/many"
  printf 'export function GET(){}\n' > "$G/node_modules/pkg/index.js"
  printf 'export function GET(){}\n' > "$G/.next/server/app/api/x/route.js"
  printf 'export async function GET(){ await requireUser(); }\n' > "$G/app/api/ok/route.ts"
  # 伏字を通していなかった節（10b の Host ヘッダ、20 の CI、6 の DEBUG）に値を置く
  printf 'export async function POST(req){ const h = req.headers.get("host"); const k = "AIzaFIXTUREFIXTUREFIXTUREFIXTUREFIX1"; }\n' > "$G/app/api/host/route.ts"
  printf 'on: push\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - run: curl -u admin:FIXTURE-CI-PASSWORD https://example.invalid/\n' > "$G/.github/workflows/ci.yml"
  printf 'DEBUG = "FIXTURE-DEBUG-SECRET-VALUE-1234567890"\n' > "$G/settings.py"
  printf 'export const k = "x";\n' > "$G/scripts/rebuild/debug.ts"
  # Anthropic の SDK の messages.create は SMS ではない
  printf 'import Anthropic from "@anthropic-ai/sdk";\nexport async function POST(){ return client.messages.create({ model: "m", messages: [] }); }\n' > "$G/app/api/chat/route.ts"
  # PHP のテンプレートの計測タグ
  printf '<script async src="https://www.googletagmanager.com/gtag/js?id=G-FIXTURE"></script>\n' > "$G/theme/header.php"
  # 切り捨て: 同じ危険な関数を 25 か所に置く（3 節の一覧は 20 件で切る）
  for i in $(seq 1 25); do printf 'export function GET(){ el.innerHTML = x%s; }\n' "$i"; done > "$G/app/api/many/route.ts"
  # 大文字の変数名と新しい鍵の形式（4 節）
  printf 'API_KEY = "FIXTUREFIXTUREFIXTUREFIXTURE12"\nconst k = "sk-proj-FIXTUREFIXTUREFIXTUREFIXTURE"\n' > "$G/config.py"
  # minify された長い 1 行
  # 節ごとの伏字（200 文字で切る）を通らない節（12 節の例外の握りつぶし）に置く
  { printf 'try{f()}catch(e){}'; for i in $(seq 1 300); do printf '+b'; done; printf '\n'; } > "$G/app/api/ok/bundle.js"
  GD="$(bash "$SKILL/scripts/audit_grep.sh" "$G" 2>&1)"
  S2G="$(printf '%s\n' "$GD" | LC_ALL=C awk 'index($0, "=== 2. ") == 1 { f = 1; print; next } f && /^=== / { exit } f')"
  contains "audit_grep[除外]: 自前のハンドラは一覧に出す"            "app/api/ok/route.ts"            "$S2G"
  absent   "audit_grep[除外]: node_modules を一覧に出さない"          "node_modules"                   "$S2G"
  absent   "audit_grep[除外]: .next を一覧に出さない"                 ".next/"                         "$S2G"
  absent   "audit_grep[伏字]: Host ヘッダの行の鍵を出さない"          "AIzaFIXTUREFIXTUREFIXTUREFIXTUREFIX1" "$GD"
  absent   "audit_grep[伏字]: CI の curl -u の認証情報を出さない"     "FIXTURE-CI-PASSWORD"            "$GD"
  absent   "audit_grep[伏字]: DEBUG の値を出さない"                   "FIXTURE-DEBUG-SECRET-VALUE"     "$GD"
  absent   "audit_grep[伏字]: sk-proj の鍵を出さない"                 "sk-proj-FIXTUREFIXTUREFIXTUREFIXTURE" "$GD"
  contains "audit_grep[鍵]: 大文字の変数名の鍵を拾う"                "config.py:1"                    "$GD"
  contains "audit_grep[鍵]: sk-proj の鍵を拾う"                      "config.py:2"                    "$GD"
  contains "audit_grep[除外]: rebuild を含むパスを落とさない"        "scripts/rebuild/debug.ts"       "$GD"
  absent   "audit_grep[SMS]: Anthropic の messages.create を SMS と言わない" "=== 24."             "$GD"
  contains "audit_grep[タグ]: PHP のテンプレートのタグを拾う"         "theme/header.php"               "$GD"
  contains "audit_grep[切り捨て]: 切ったことと残りの件数を示す"       "（ほか "                        "$GD"
  contains "audit_grep[長い行]: 長い行を切る"                         "（長い行を省略）"               "$GD"
  if printf '%s\n' "$GD" | LC_ALL=C awk 'length($0) > 700 { bad = 1 } END { exit bad ? 0 : 1 }'; then
    ng "audit_grep[長い行]: 700 バイトを超える行を出さない" "長い行がそのまま出ている"
  else ok "audit_grep[長い行]: 700 バイトを超える行を出さない"; fi
  contains "audit_grep[節]: 該当しないので省いた節を示す"           "該当しないので省いた節:"        "$GD"
  contains "audit_grep[節]: 冒頭に節の一覧"                          "節: 0 構成 / 1 規模"            "$GD"
  # 列の幅は表示の幅で揃える（日本語 2 桁）。「インフラの定義」は 7 文字＝14 桁なので、値は 29 桁目から始まる
  if printf '%s\n' "$GD" | grep -E '^  インフラの定義 {12}(有|無)' >/dev/null; then ok "audit_grep[体裁]: 0 節の列を表示の幅で揃える"
  else ng "audit_grep[体裁]: 0 節の列を表示の幅で揃える" "列がずれている"; fi

  # 題材に無い構成では、これらの節を出さない（見たことにしない）
  RN="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/repo-realistic" 2>&1)"
  absent   "audit_grep[基盤]: BaaS が無ければ 19 節を出さない"       "=== 19."                        "$RN"
  absent   "audit_grep[CI]: CI が無ければ 20 節を出さない"           "=== 20."                        "$RN"
  absent   "audit_grep[リアルタイム]: 無ければ 23 節を出さない"      "=== 23."                        "$RN"
  absent   "audit_grep[リプレイ]: 無ければ 9b 節を出さない"          "=== 9b."                        "$RN"
  absent   "audit_grep[SMS]: 無ければ 24 節を出さない"               "=== 24."                        "$RN"
  contains "audit_grep[基盤]: 画面操作の記録が無ければ無と言う"    "画面操作の記録"                 "$RN"
  absent   "audit_grep[基盤]: 画面操作の記録が無いのに有と言わない" "有 → 08 の 1-2"                 "$RN"
  absent   "audit_grep[基盤]: 画面操作の記録が無ければ 09 を読ませない" "references/09-browser-verification.md" "$RN"
fi

# 構成の判定。対象に無い技術の資料を読ませないための仕組みで、
# 「有」と「無」の両方が正しく出ることを見る。
for fw in iac mobile; do
  SRC="$ROOT/tests/fixtures/repo-$fw"
  [[ -d "$SRC" ]] || continue
  fixture_cp "$SRC" "$TMP/repo-$fw"
  C="$(bash "$SKILL/scripts/audit_grep.sh" "$TMP/repo-$fw" 2>&1)"
  case "$fw" in
    iac)
      contains "audit_grep[iac]: インフラの定義を検出"   "Terraform"                    "$C"
      contains "audit_grep[iac]: コンテナを検出"         "Dockerfile"                   "$C"
      contains "audit_grep[iac]: Kubernetes を検出"      "Kubernetes"                   "$C"
      if printf '%s' "$C" | sed -n '/追加で読む資料:/,/※/p' | grep -F "references/13-infrastructure.md" >/dev/null; then
        ok "audit_grep[iac]: 読む資料を名指しする"
      else ng "audit_grep[iac]: 読む資料を名指しする" "「追加で読む資料」に 13 が無い"; fi
      absent   "audit_grep[iac]: モバイルは要らないと言える" "references/14-mobile.md"  "$C" ;;
    mobile)
      contains "audit_grep[mobile]: モバイルを検出"       "android/"                     "$C"
      if printf '%s' "$C" | sed -n '/追加で読む資料:/,/※/p' | grep -F "references/14-mobile.md" >/dev/null; then
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
        printf '%s' "$C" | grep -F -- "$v" >/dev/null && leaked="$leaked $v"
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
  fixture_cp "$ROOT/tests/fixtures/repo-angular" "$TMP/repo-angular"
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
if printf '%s' "$S" | grep -E '^  \./README\.md:[0-9]+:' >/dev/null; then
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
  skip "make_register: openpyxl を持つ python が無いため省略"
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
  if printf '%s' "$V2" | grep '^ALL OK$' >/dev/null; then ok "make_register: 版と構成ごとの中身が正しい（2021/2025 の A10、個人情報 11 区分、IPA 6 大項目、API 10 行）"
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
  if printf '%s' "$V" | grep '^NG' >/dev/null; then
    ng "make_register: 集計数式が指摘一覧シートを正しく指す" "$V"
  else ok "make_register: 集計数式が指摘一覧シートを正しく指す"; fi
fi

# --- recon.sh / browser_probe.mjs は実サイトへ出る。発火台を立てて確かめる ---
# わざと穴のあるページをローカルで配信し、期待する検出が出るかを見る。外部へは出ない。

U="$(bash "$SKILL/scripts/recon.sh" 2>&1 || true)"
contains "recon: 引数が無いときに使い方を出す" "使い方" "$U"

# 到達できない対象。取れていないものを「無い」と判定しないこと（以前は [無] ヘッダ・
# 「x-powered-by は出ていない」・「検出なし」を出していた）。閉じたポートなので即座に失敗する。
RU="$(bash "$SKILL/scripts/recon.sh" "http://127.0.0.1:1" /admin 2>&1 || true)"
contains "recon[到達不可]: 取得できなかったと言う"             "取得できず"             "$RU"
absent   "recon[到達不可]: ヘッダを「無」と判定しない"        "[無] x-frame-options"   "$RU"
absent   "recon[到達不可]: x-powered-by を「出ていない」と言わない" "x-powered-by は出ていない" "$RU"
absent   "recon[到達不可]: 鍵やタグを「検出なし」と言わない"   "検出なし"               "$RU"
absent   "recon[到達不可]: 以降の HTTP の節を飛ばす"           "=== 5. 追加パス"        "$RU"

if command -v node >/dev/null 2>&1; then
  B="$(node "$SKILL/scripts/browser_probe.mjs" 2>&1 || true)"
  contains "browser_probe: 引数が無いときに使い方を出す" "使い方" "$B"
  B2="$(node "$SKILL/scripts/browser_probe.mjs" 'not a url' 2>&1 || true)"
  contains "browser_probe: URL でない引数を弾く" "URL として読めない" "$B2"

  # Playwright が無いときの案内。評価対象のリポジトリを汚さない手順（版を固定し、スキルの外に入れる）を出すこと。
  # 以前は「npm i -D playwright」で、実行した場所（評価対象）の package.json を書き換えていた。
  # リポジトリの中に置くと親の node_modules が見えてしまうので、OS の一時ディレクトリへ写して走らせる。
  PWT="$(mktemp -d)"
  cp "$SKILL/scripts/browser_probe.mjs" "$PWT/"
  B3="$(cd "$PWT" && env -u NODE_PATH node "$PWT/browser_probe.mjs" "http://localhost:1" 2>&1 || true)"
  contains "browser_probe: Playwright 不在時に版を固定した導入手順を出す" "playwright@1.63" "$B3"
  contains "browser_probe: 導入先をスキルの外にする"                   "NODE_PATH="      "$B3"
  absent   "browser_probe: 評価対象の package.json を書き換える案内をしない" "npm i -D" "$B3"

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
  ["c.bing.com", "Microsoft Clarity"],
  ["o0.ingest.sentry.io", "Sentry"],
  ["js.sentry-cdn.com", "Sentry"],
  ["static.hotjar.com", "Hotjar"],
  ["content.hotjar.io", "Hotjar"],
  ["r.lr-ingest.io", "LogRocket"],
  ["r.lr-in-prod.com", "LogRocket"],
  ["edge.fullstory.com", "FullStory"],
  ["rs.eu1.fullstory.com", "FullStory"],
  ["us.i.posthog.com", "PostHog"],
  ["eu-assets.i.posthog.com", "PostHog"],
  ["browser-intake-datadoghq.com", "Datadog RUM"],
  ["browser-intake-us5-datadoghq.com", "Datadog RUM"],
  ["browser-intake-datadoghq.eu", "Datadog RUM"],
  ["o2.mouseflow.com", "Mouseflow"],
  ["s.yimg.jp", "Yahoo! 広告"],
];
let bad = 0;
for (const [host, want] of cases) {
  const hit = TAGS.find(([re]) => re.test(host));
  if (!hit || hit[1] !== want) { console.log(`NG ${host} -> ${hit ? hit[1] : "(未検出)"} / 期待 ${want}`); bad++; }
}
// 自ドメインらしきホスト、送信先の名前を途中に含むだけのホストを取り違えないこと
for (const host of ["example.com", "cdn.example.com", "notgoogle.example.com",
                    "hotjar.com.attacker.example", "clarity.ms.example.com", "notposthog.com",
                    "bing.com", "www.bing.com", "facebook.com.example.com"]) {
  const hit = TAGS.find(([re]) => re.test(host));
  if (hit) { console.log(`NG ${host} を ${hit[1]} と誤判定した`); bad++; }
}
console.log(bad === 0 ? "ALL OK" : `${bad} 件失敗`);
NODE
)"
  if printf '%s' "$T" | grep '^ALL OK$' >/dev/null; then ok "browser_probe: 既知タグのラベル付け（21 例・誤判定 9 例）"
  else ng "browser_probe: 既知タグのラベル付け" "$T"; fi

  # recon.sh の TAGS と browser_probe.mjs の TAGS が同じ内容であること。
  # 片方だけ直すと、同じ送信先が一方では計測タグ、もう一方では無名になる。
  JT="$(node - "$SKILL/scripts/browser_probe.mjs" <<'NODE' 2>&1 || true
import { pathToFileURL } from "node:url";
const { TAG_SOURCES } = await import(pathToFileURL(process.argv[2]).href);
for (const [label, re] of TAG_SOURCES) console.log(`${label}|${re}`);
NODE
)"
  RT="$(sed -n '/^TAGS=(/,/^)/p' "$SKILL/scripts/recon.sh" | sed -n "s/^[[:space:]]*'\(.*\)'[[:space:]]*$/\1/p")"
  if [[ -n "$RT" && "$RT" == "$JT" ]]; then ok "recon と browser_probe の既知タグの一覧が一致する（$(printf '%s\n' "$RT" | wc -l | tr -d ' ') 種）"
  else ng "recon と browser_probe の既知タグの一覧が一致する" "$(diff <(printf '%s\n' "$RT") <(printf '%s\n' "$JT") | head -4 | tr '\n' ' ')"; fi

  # CSP の判定は references/07 の 1-6 に合わせる。ブラウザを使わずに判定の部品へ直接当てる。
  CJ="$(node - "$SKILL/scripts/browser_probe.mjs" <<'NODE' 2>&1 || true
import { pathToFileURL } from "node:url";
const { judgeCsp } = await import(pathToFileURL(process.argv[2]).href);
const cases = [
  // [CSP, unsafe-inline が効くか, 無視される unsafe-inline があるか, script の制限が無いか]
  ["script-src 'self' 'unsafe-inline'", true, false, false],
  ["default-src 'self' 'unsafe-inline'", true, false, false],                       // script-src が無ければ default-src
  ["default-src 'self'; script-src-elem 'self' 'unsafe-inline'", true, false, false], // 要素側で通る
  ["script-src-elem 'self'; script-src 'self' 'unsafe-inline'", true, false, false],  // 属性側（script-src）で通る
  ["script-src-elem 'self' 'unsafe-inline'; script-src 'self'", true, false, false],  // script-src-elem を script-src と取り違えない
  ["script-src 'nonce-abc' 'unsafe-inline'", false, true, false],                   // nonce があれば無視される
  ["script-src 'sha256-AAAA' 'unsafe-inline'", false, true, false],                 // hash も同じ
  ["script-src 'strict-dynamic' 'nonce-abc' 'unsafe-inline' https:", false, true, false],
  ["default-src 'self'; script-src 'self'", false, false, false],
  ["frame-ancestors 'none'", false, false, true],
];
let bad = 0;
for (const [p, ui, ign, none] of cases) {
  const j = judgeCsp(p);
  if (j.unsafeInline !== ui || j.unsafeInlineIgnored !== ign || j.noScriptRestriction !== none) {
    console.log(`NG ${p} -> inline=${j.unsafeInline} ignored=${j.unsafeInlineIgnored} none=${j.noScriptRestriction}`); bad++;
  }
}
if (!judgeCsp("script-src 'nonce-a' 'unsafe-eval'").unsafeEval) { console.log("NG unsafe-eval は nonce で打ち消されない"); bad++; }
if (!judgeCsp("frame-ancestors 'none'").frameAncestorsOnly) { console.log("NG frame-ancestors のみ"); bad++; }
console.log(bad === 0 ? "ALL OK" : `${bad} 件失敗`);
NODE
)"
  if printf '%s' "$CJ" | grep '^ALL OK$' >/dev/null; then ok "browser_probe: CSP を実際に効く指令で判定する（12 例）"
  else ng "browser_probe: CSP を実際に効く指令で判定する" "$CJ"; fi
else
  skip "browser_probe（node が無いため省略）"
fi

if ! command -v node >/dev/null 2>&1; then
  skip "発火台を使う検査（node が無いため省略）"
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
  if printf '%s' "$R1" | sed -n '/第三者オリジン/,/既知タグ/p' | grep -F "localhost:$PORT" >/dev/null; then
    ng "recon[実地]: 自サイトを第三者に数えない" "localhost:$PORT が第三者として出ている"
  else ok "recon[実地]: 自サイトを第三者に数えない"; fi
  # 鍵の値をそのまま出していないこと
  if printf '%s' "$R1" | grep -E 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}' >/dev/null; then
    ng "recon[実地]: 鍵の値を伏字にする" "JWT がそのまま出力されている"
  else ok "recon[実地]: 鍵の値を伏字にする"; fi
  # 1 節で Set-Cookie の値を出さないこと（名前と属性は残す）
  absent   "recon[実地]: Set-Cookie の値を出さない"          "dummyvalue123"        "$R1"
  contains "recon[実地]: Set-Cookie の名前と属性は残す"      "session_id=<伏字>; Path=/; SameSite=Lax" "$R1"
  # 外から .env の中身が取れる。優先度は 04 の定義に合わせて「P0 の候補」とし、報告書を待たずに
  # 知らせる対象だと示す（SKILL.md の守ること 6）。中身の値は出さない
  contains "recon[実地]: .env の中身が取れれば P0 の候補と言う"  "中身が返っている。P0 の候補" "$R1"
  contains "recon[実地]: 報告書を待たずに知らせると言う"         "報告書を待たずに依頼者へ知らせる" "$R1"
  absent   "recon[実地]: .env の値を出さない"                   "dummy-env-value-should-not-be-printed" "$R1"

  # 正しく作られている側にも当てる。誤検出するツールは、指摘の山に埋もれて
  # 本当に危ないものを隠す。
  R2="$(bash "$SKILL/scripts/recon.sh" "http://localhost:$PORT/clean" 2>&1 || true)"
  absent   "recon[誤検出]: 揃ったヘッダを欠如と言わない"     "[無] x-frame-options" "$R2"
  absent   "recon[誤検出]: x-powered-by が無ければ触れない"  "実装情報が露出"       "$R2"
  contains "recon[誤検出]: 第三者が無ければ無いと言える"     "第三者オリジンの検出なし" "$R2"
  # 渡された URL そのもの（/clean）の HTML を読むこと。以前は "/clean/" を取りに行って 404 を読んでいた
  contains "recon[実地]: 渡された URL の HTML から JS を集める" "JS 1 件"         "$R2"

  # リダイレクトを追う。/r は 302 で /ja/ へ転送し、ヘッダは転送先にだけある。
  # 転送先は一重引用符・相対パス（src='./ja.js'）で、LLM の鍵を載せた JS を読み込む。
  RR="$(bash "$SKILL/scripts/recon.sh" "http://localhost:$PORT/r" 2>&1 || true)"
  contains "recon[転送]: 転送を示す"                         "302 → /ja/"           "$RR"
  contains "recon[転送]: ヘッダを最終的な応答で判定する"     "[有] x-frame-options: DENY" "$RR"
  contains "recon[相対パス]: 一重引用符・相対パスの JS を拾う" "JS 1 件"            "$RR"
  contains "recon[LLM の鍵]: OpenAI の鍵を検出する"          "LLM の鍵（OpenAI）: sk-proj-DU" "$RR"
  contains "recon[LLM の鍵]: Anthropic の鍵を検出する"       "LLM の鍵（Anthropic）"  "$RR"
  contains "recon[LLM の鍵]: P0 の候補として知らせると言う"  "→ P0 の候補。報告書を待たずに" "$RR"
  absent   "recon[LLM の鍵]: 鍵の値を伏字にする"             "DUMMYdummyDUMMYdummy0000notreal" "$RR"

  # 計測タグの判定は、HTML の src 属性と自サイトのコードだけで行う。
  # /vendor は第三者（127.0.0.1）のスクリプトの中に LogRocket・PostHog などの送信先の文字列を持つ。
  RV="$(bash "$SKILL/scripts/recon.sh" "http://localhost:$PORT/vendor" 2>&1 || true)"
  contains "recon[タグ]: 自前のインラインスクリプトの GTM を検出"  "[検出] Google タグマネージャ" "$RV"
  for lbl in LogRocket PostHog Hotjar "Microsoft Clarity" FullStory; do
    absent "recon[タグ誤検出]: 第三者スクリプトの中身で ${lbl} と言わない" "[検出] $lbl" "$RV"
  done
  contains "recon[タグ]: 一重引用符の第三者スクリプトを列挙"       "127.0.0.1:$PORT"       "$RV"

  # ---- recon.sh の DNS まわり ----
  # 発火台は localhost だが、localhost は OS が特別扱いして常に 127.0.0.1 を返すため、
  # DNS の検査には使えない。別の受け口（tests/fixtures/site/dns.py）を立て、
  # RECON_DNS でそこへ向け、解決できない名前（example.test）で recon.sh を呼ぶ。
  # HTTP 側は即座に失敗するが、DNS の節は独立して動く。
  # 応答しない名前の検査が長くならないよう、dig の待ち時間を 1 秒にする。
  DPORT="$(node -e 'const s=require("net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
  python3 "$ROOT/tests/fixtures/site/dns.py" "$DPORT" > "$TMP/dns.log" 2>&1 &
  DNS_PID=$!
  trap 'kill $SITE_PID $DNS_PID 2>/dev/null' EXIT
  for _ in $(seq 1 20); do grep '起動した' "$TMP/dns.log" >/dev/null 2>&1 && break; sleep 0.25; done
  if command -v dig >/dev/null 2>&1; then
    export RECON_DNS_TIMEOUT=1
    R3="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://example.test:1" 2>&1 || true)"
    contains "recon[DNS]: apex に SPF が無いと判定"        "[無] SPF"                "$R3"
    contains "recon[DNS]: DMARC を検出"                     "[有] DMARC"              "$R3"
    contains "recon[DNS]: DMARC が p=none だと指摘"         "p=none。監視のみ"        "$R3"
    contains "recon[DNS]: 配信サービス用サブドメインの SPF" "send.example.test"       "$R3"
    contains "recon[DNS]: DKIM セレクタを検出"              "resend._domainkey"       "$R3"
    contains "recon[DNS]: NS を取得"                        "ns1.example.invalid"     "$R3"
    # CAA と DS は返さない = 空で出ること（誤って何かを表示しない）
    if printf '%s' "$R3" | grep -E '^  CAA    : *$' >/dev/null; then ok "recon[DNS]: CAA が無ければ空で出す"
    else ng "recon[DNS]: CAA が無ければ空で出す" "CAA の行に何か出ている"; fi
    # DMARC の rua に入っているアドレスを、出力に出さないこと（報告書に不要な個人情報）
    absent "recon[DNS]: DMARC の連絡先アドレスを出力に混ぜない" "dmarc@example.invalid" "$R3"
    # HTTP が取れないときは、HTTP の節の判定を出さない（DNS の節は出す）
    absent "recon[DNS]: HTTP が取れなければヘッダを「無」と言わない" "[無] x-frame-options" "$R3"

    # サブドメインの URL を渡されたとき、親に設定があれば親へ遡って見つけること。
    # 以前は URL のホスト名だけを引き、親に DMARC / CAA があっても「無」と出していた。
    # あわせて p=reject; sp=none を「p=none」と取り違えないこと（部分一致で誤っていた）。
    R4="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://app.strict.test:1" 2>&1 || true)"
    contains "recon[DNS]: サブドメインから親の DMARC を見つける" "_dmarc.strict.test で発見" "$R4"
    contains "recon[DNS]: p=reject を読める"                     "→ p=reject"              "$R4"
    absent   "recon[DNS]: sp=none を p=none と取り違えない"      "p=none。監視のみ"        "$R4"
    contains "recon[DNS]: sp=none は別に指摘する"                "sp=none。サブドメインは監視のみ" "$R4"
    contains "recon[DNS]: サブドメインから親の CAA を見つける"   "strict.test で発見）"    "$R4"
    absent   "recon[DNS]: 親の DMARC の連絡先も伏せる"           "dmarc@example.invalid"   "$R4"
    # サブドメインに効くのは sp=（無ければ p=）。p=reject を主に示して、実際に効く sp=none を見落とさせない
    contains "recon[DNS]: このホストに効くポリシーを示す"         "このホストに効くのは sp=none" "$R4"
    # DS は親へ遡らず、SOA で求めたゾーンの頂点で引く（co.uk のような区切りの DS を拾わない）
    contains "recon[DNS]: ゾーンの頂点で DS を引く"               "（ゾーンの頂点 strict.test）" "$R4"
    contains "recon[DNS]: 頂点の DS を見つける"                   "DS     : 12345 13 2"     "$R4"
    contains "recon[DNS]: 未署名なら DS を空で出す"               "DS     : （ゾーンの頂点 example.test）" "$R3"
    # SPF・配信用サブドメイン・DKIM は、URL のホスト名ではなく組織のドメインで引く。
    # 以前は app.strict.test で引き、親にある SPF・DKIM を「無い」と出していた。
    contains "recon[組織のドメイン]: 組織のドメインを示す"         "組織のドメイン: strict.test" "$R4"
    contains "recon[組織のドメイン]: 組織のドメインの SPF を見つける" "[有] SPF（組織のドメイン strict.test）" "$R4"
    contains "recon[組織のドメイン]: ホスト名の SPF と区別して出す" "SPF（ホスト名 app.strict.test" "$R4"
    contains "recon[組織のドメイン]: 配信用サブドメインを組織のドメインで引く" "send.strict.test" "$R4"
    contains "recon[組織のドメイン]: DKIM を組織のドメインで引く"   "[有] resend._domainkey" "$R4"
    # タグは大文字小文字と空白を許して読む（RFC 7489）。レコードが 2 本なら DMARC は無効
    R5="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://caps.test:1" 2>&1 || true)"
    contains "recon[DNS]: 大文字と空白の入ったタグを読む"         "→ p=reject"              "$R5"
    R6="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://dup.test:1" 2>&1 || true)"
    contains "recon[DNS]: DMARC が 2 本あれば無効と言う"          "DMARC のレコードが 2 本ある" "$R6"
    # IP アドレスを渡されたら DNS を引かない
    R7="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://127.0.0.1:1" 2>&1 || true)"
    contains "recon[DNS]: IP アドレスなら DNS を省く"             "IP アドレスが渡されたため省略" "$R7"

    # DNS が応答しないとき。dig +short は「;; connection timed out」を標準出力に出すため、
    # それを値として読むと「有」と誤る（実際に DKIM・CAA・配信用サブドメインで誤っていた）。
    R8="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://silent.test:1" 2>&1 || true)"
    contains "recon[DNS無応答]: 応答しないと言う"                 "DNS が応答しない"        "$R8"
    absent   "recon[DNS無応答]: タイムアウトの文言を値として出さない" "connection timed out"  "$R8"
    absent   "recon[DNS無応答]: DKIM を「有」と言わない"          "[有] resend._domainkey"  "$R8"
    absent   "recon[DNS無応答]: SPF を「無」と言わない"           "[無] SPF"                "$R8"
    absent   "recon[DNS無応答]: DMARC を「無」と言わない"         "[無] DMARC"              "$R8"
    # 一部だけ応答が無いとき。答えた項目は出し、答えなかった項目は「取得できない」と区別する
    R9="$(RECON_DNS="127.0.0.1:$DPORT" bash "$SKILL/scripts/recon.sh" "http://partial.test:1" 2>&1 || true)"
    contains "recon[DNS一部無応答]: 答えた項目は出す"             "NS     : ns1.example.invalid" "$R9"
    contains "recon[DNS一部無応答]: CAA は取得できないと言う"     "CAA    : （取得できない"  "$R9"
    contains "recon[DNS一部無応答]: DS は取得できないと言う"      "DS     : （取得できない"  "$R9"
    contains "recon[DNS一部無応答]: 配信用サブドメインは取得できないと言う" "send.partial.test 以降: （取得できない" "$R9"
    contains "recon[DNS一部無応答]: DKIM は取得できないと言う"    "resend._domainkey 以降: （取得できない" "$R9"
    absent   "recon[DNS一部無応答]: タイムアウトの文言を値として出さない" "connection timed out" "$R9"
    # 受け口そのものに届かないとき（誰も待っていないポート）。最初の失敗で打ち切る
    R10="$(RECON_DNS="127.0.0.1:1" bash "$SKILL/scripts/recon.sh" "http://example.test:1" 2>&1 || true)"
    contains "recon[DNS不達]: 応答しないと言う"                   "DNS が応答しない"        "$R10"
    absent   "recon[DNS不達]: 通信エラーの文言を値として出さない"  ";;"                      "$R10"
    unset RECON_DNS_TIMEOUT
  else
    skip "recon の DNS 検査（dig が無いため省略）"
  fi
  kill $DNS_PID 2>/dev/null

  # ---- browser_probe.mjs ----
  if ! node -e 'import("playwright")' >/dev/null 2>&1; then
    skip "browser_probe の実地検査（playwright が無いため省略）"
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
      printf '%s' "$P" | grep -F -- "$v" >/dev/null && leaked="$leaked $v"
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
    contains "browser_probe[誤検出]: WebSocket が無ければ無いと言える" "WebSocket の接続は観測されなかった" "$C"

    # CSP を <meta> で置いたページ。ヘッダだけを見ると「CSP が無い」と誤る
    PM="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT/meta-csp" 2>&1 || true)"
    contains "browser_probe[CSP]: <meta> の CSP を読む"              "[meta]"               "$PM"
    contains "browser_probe[CSP]: <meta> の CSP の unsafe-inline を検出" "unsafe-inline がある" "$PM"
    absent   "browser_probe[CSP]: <meta> があれば「無」と言わない"     "CSP が設定されていない" "$PM"
    # script-src が無く default-src に unsafe-inline がある。default-src へ遡って判定する
    PD="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT/default-only" 2>&1 || true)"
    contains "browser_probe[CSP]: script-src が無ければ default-src で判定" "default-src が効く" "$PD"
    contains "browser_probe[CSP]: default-src の unsafe-inline を検出"      "unsafe-inline がある" "$PD"
    # nonce・strict-dynamic と並ぶ unsafe-inline はブラウザが無視する。指摘しない
    PS="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT/strict-csp" 2>&1 || true)"
    absent   "browser_probe[CSP誤検出]: nonce と並ぶ unsafe-inline を咎めない" "unsafe-inline がある" "$PS"
    contains "browser_probe[CSP誤検出]: 無視されることを示す"                  "ブラウザは無視する"   "$PS"

    # 同意前に WebSocket を開くページ。WebSocket は request イベントに出ないので、別に拾う必要がある
    PW="$(node "$SKILL/scripts/browser_probe.mjs" "http://localhost:$PORT/ws" 2>&1 || true)"
    contains "browser_probe[WebSocket]: 第三者への接続を拾う"       "ws://127.0.0.1:$PORT/socket" "$PW"
    contains "browser_probe[WebSocket]: 自サイトへの接続も拾う"     "ws://localhost:$PORT/socket" "$PW"
    contains "browser_probe[WebSocket]: 同意前の送信を数える"       "送信 1 件"                   "$PW"
    contains "browser_probe[WebSocket]: 同意前の第三者送信に含める" "（WebSocket を含む）"         "$PW"
    absent   "browser_probe[WebSocket]: クエリのトークンを出さない" "dummy-ws-token-should-not-be-printed" "$PW"

    # 評価対象のリポジトリの外に入れた Playwright を NODE_PATH で渡して動くこと（案内どおりの使い方）
    PWDIR="$(node -e 'const p=require("path");console.log(p.dirname(p.dirname(require.resolve("playwright/package.json",{paths:[process.argv[1]]}))))' "$ROOT" 2>/dev/null || true)"
    if [[ -n "$PWDIR" ]]; then
      PN="$(cd "$PWT" && NODE_PATH="$PWDIR" node "$PWT/browser_probe.mjs" "http://localhost:$PORT/clean" 2>&1 || true)"
      contains "browser_probe: NODE_PATH で渡した Playwright で動く" "送信は観測されなかった" "$PN"
    fi
  fi
  rm -rf "${PWT:-/nonexistent}"

  kill $SITE_PID 2>/dev/null
  trap - EXIT
fi
# ==========================================================================
printf '\n\033[1m結果\033[0m  成功 %d / 失敗 %d / 省略 %d\n' "$PASS" "$FAIL" "$SKIPPED"
[[ $SKIPPED -gt 0 ]] && printf '  ※ 省略した検査がある。道具（node・playwright・dig・openpyxl）を入れて全件を回す\n'
if [[ $FAIL -gt 0 ]]; then exit 1; fi
rm -rf "$TMP"
