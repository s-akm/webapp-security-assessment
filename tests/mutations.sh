#!/usr/bin/env bash
# mutations.sh — 検査が本当に失敗を捕まえるかを確かめる（検査の検査）
#
#   使い方: tests/mutations.sh [--only <名前の一部>]
#
# tests/run.sh は「通ること」しか示さない。通る検査が、壊れたときに落ちるかどうかは別の話で、
# 実際にこのリポジトリでは「浅い場所に題材を置いたため不具合を再現できず素通りしていた」
# 検査があった。ここでは、スキルにわざと欠陥を入れて run.sh を回し、対応する検査が
# 落ちることを 1 つずつ確かめる。落ちない検査は「生きていない」と判定する。
#
# 各ミューテーションは、対象ファイルの一部を置き換え → run.sh → 復元、の順で行う。
# 復元は trap で保証する。途中で止めても元に戻る。

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL="$ROOT/skill"
ONLY="${2:-}"; [[ "${1:-}" == "--only" ]] || ONLY=""

PASS=0; FAIL=0; SKIP=0
BACKUPS=()

# 実行中は skill/ に欠陥が入っている。その間に build や配布の同期を走らせると、
# 欠陥入りの状態が配布物に入る（実際に起きた）。ロックを置いて、他の処理に知らせる。
LOCK="$ROOT/tests/.mutating"
if [[ -e "$LOCK" ]]; then
  echo "別の mutations.sh が実行中（$LOCK がある）。終わるまで待つか、残骸なら消す" >&2; exit 2
fi
echo "$$ $(date +%s)" > "$LOCK"

restore_all() {
  rm -f "$LOCK"
  for b in "${BACKUPS[@]:-}"; do
    [[ -n "$b" ]] || continue
    src="${b%%::*}"; dst="${b##*::}"
    [[ -f "$src" ]] && cp -p "$src" "$dst" && rm -f "$src"
  done
  BACKUPS=()
}
trap restore_all EXIT

# 変異を入れる前に、何も壊していない状態で run.sh が全部通ることを確かめる。
# 土台が壊れていると（出力が化けて節を切り出せない、など）、誤検出の検査は何も見ずに通り、
# 「生きている」「生きていない」の両方が誤った結論になる（実際に起きた）。
base="$(bash "$ROOT/tests/run.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
if printf '%s' "$base" | grep -q '✗'; then
  echo "変異を入れる前の run.sh が失敗している。先に直す:" >&2
  printf '%s\n' "$base" | grep '✗' | head -5 >&2
  exit 1
fi

# 1 つのミューテーションを実行する。
#   mutate <名前> <対象ファイル（skill からの相対）> <落ちるべき検査名の一部> <Python の置換コード>
# Python コードは、変数 s（ファイル内容）を書き換えて返す形で書く。
# 置換が 1 か所も当たらなければ、そのミューテーションは「対象が見つからない」で失敗にする。
# （対象が変わって置換が空振りすると、検査の生死を確かめていないのに通ってしまうため）
mutate() {
  local name="$1" rel="$2" expect="$3" code="$4"
  local target="$SKILL/$rel" bak
  if [[ -n "$ONLY" && "$name" != *"$ONLY"* ]]; then SKIP=$((SKIP+1)); return; fi
  bak="$(mktemp)"; cp -p "$target" "$bak"; BACKUPS+=("$bak::$target")

  # 置換を適用。当たらなければ失敗
  if ! python3 - "$target" "$code" <<'PY' 2>/dev/null
import sys, pathlib
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8"); before = s
exec(sys.argv[2])
if s == before: sys.exit(3)
p.write_text(s, encoding="utf-8")
PY
  then
    printf '  \033[33m?\033[0m %-52s 置換対象が見つからない（ミューテーションを見直す）\n' "$name"
    cp -p "$bak" "$target"; rm -f "$bak"; BACKUPS=("${BACKUPS[@]/$bak::$target/}")
    FAIL=$((FAIL+1)); return
  fi

  # 検査を回し、期待した検査が落ちたかを見る
  local out; out="$(bash "$ROOT/tests/run.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  cp -p "$bak" "$target"; rm -f "$bak"; BACKUPS=("${BACKUPS[@]/$bak::$target/}")

  if printf '%s' "$out" | grep -qE "✗ .*${expect}"; then
    printf '  \033[32m✓\033[0m %-52s → 「%s」が落ちた\n' "$name" "$expect"
    PASS=$((PASS+1))
  else
    printf '  \033[31m✗\033[0m %-52s → 「%s」が落ちなかった。この検査は生きていない\n' "$name" "$expect"
    FAIL=$((FAIL+1))
  fi
}

printf '\n\033[1m検査の検査 — スキルに欠陥を入れて、対応する検査が落ちるか\033[0m\n\n'

# ---- 構造 ----
mutate "存在しない参照先を書く" "SKILL.md" "参照先が実在する" \
  's = s.replace("## 参照ファイル", "## 参照ファイル\n\n`references/99-nonexistent.md` を読む。\n", 1)'
# 実行権限は内容の置換ではないので、mutate を通さず直接扱う
if [[ -z "$ONLY" || "実行権限" == *"$ONLY"* ]]; then
  chmod 644 "$SKILL/scripts/scan_secrets.sh"
  out="$(bash "$ROOT/tests/run.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  chmod 755 "$SKILL/scripts/scan_secrets.sh"
  if printf '%s' "$out" | grep -qE "✗ .*実行権限: scan_secrets.sh"; then
    printf '  \033[32m✓\033[0m %-52s → 「%s」が落ちた\n' "スクリプトの実行権限を外す" "実行権限"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗\033[0m %-52s → 落ちなかった\n' "スクリプトの実行権限を外す"; FAIL=$((FAIL+1))
  fi
fi

# ---- 機密 ----
mutate "案件固有語を混入させる" "SKILL.md" "案件固有語が含まれない" \
  's = s + "\n対象は CLIENT-NGWORD-CANARY のシステムである。\n"'
mutate "実在しうるドメインを書く" "references/01-scoping.md" "実在しうるドメインが書かれていない" \
  's = s + "\n参考: https://some-client.co.jp/\n"'
mutate "想定外の文字体系を混入させる" "references/02-code-audit.md" "想定外の文字体系" \
  's = s + "\nテスト用の混入 материал\n"'
mutate "基準の最終確認日を消す" "references/06-frameworks.md" "基準の版に最終確認日" \
  's = s.replace("standards-reviewed:", "standards-checked:")'

# ---- scan_secrets ----
mutate "scan_secrets: 絶対パスのまま検索する（旧不具合）" "scripts/scan_secrets.sh" "検出行の中身が表示される" \
  's = s.replace("cd \"$DIR\" && grep -rnIE \"${TARGETS[@]}\" -e \"$pattern\" . ", "grep -rnIE \"${TARGETS[@]}\" -e \"$pattern\" \"$DIR\" ")'
mutate "scan_secrets: iconv を外す（日本語が壊れる）" "scripts/scan_secrets.sh" "日本語が壊れない" \
  's = s.replace("cut -c1-200 | iconv -c -f UTF-8 -t UTF-8", "cut -c1-160")'

# ---- audit_grep ----
mutate "audit_grep: ガードの語彙から Laravel を外す" "scripts/audit_grep.sh" "audit_grep\\[laravel\\]: ガードを読み取る" \
  's = s.replace("|->middleware|middleware", "|XXmw|XXmw2")'
mutate "audit_grep: 命名規約 require* を外す" "scripts/audit_grep.sh" "audit_grep\\[remix\\]: ガードを読み取る" \
  's = s.replace("require[A-Z][A-Za-z]+|ensure[A-Z]", "requireXXX|ensure[A-Z]")'
mutate "audit_grep: SQL 連結の検出を壊す" "scripts/audit_grep.sh" "危険な書き方を検出" \
  's = s.replace("(select[[:space:]]+[^;]{0,80}[[:space:]]from[[:space:]]|insert", "(ZZZNOMATCH|insert", 1)'
mutate "audit_grep: 引用符の無い代入を伏字にしない（旧不具合）" "scripts/audit_grep.sh" "ビルド引数の値を伏字にする" \
  's = "\n".join(l for l in s.split("\n") if "CREDENTIAL)[A-Za-z_]*" not in l)'
mutate "audit_grep: Server Actions の関数判定を壊す" "scripts/audit_grep.sh" "Server Action のガードなしを関数単位で示す" \
  's = s.replace("name != \"\" && $0 ~ ENVIRON[\"GUARD\"] { hit = 1 }", "name != \"\" { hit = 1 }")'
mutate "audit_grep: ユーティリティの除外を外す（偽陽性）" "scripts/audit_grep.sh" "ユーティリティをハンドラに数えない" \
  's = s.replace("!/^(src\\/)?lib\\// || /\\/controllers\\/|_controller", "!/^ZZZ\\// || /\\/controllers\\/|_controller")'
mutate "audit_grep: Math.random の検出を壊す" "scripts/audit_grep.sh" "予測できる乱数" \
  's = s.replace(r"Math\.random\(", r"ZZZNOMATCH\(", 1)'
mutate "audit_grep: 構成判定で IaC を要らないと言う" "scripts/audit_grep.sh" "audit_grep\\[iac\\]: 読む資料を名指しする" \
  's = s.replace("need=\"$need references/13-infrastructure.md\"", "need=\"$need\"")'

# ---- recon ----
mutate "recon: ポート付き URL の自サイト判定を戻す（旧不具合）" "scripts/recon.sh" "自サイトを第三者に数えない" \
  's = s.replace("${DOMAIN//./\\\\.}(:[0-9]+)?$\"", "${DOMAIN//./\\\\.}$\"")'

mutate "recon: DMARC の連絡先を伏せない" "scripts/recon.sh" "DMARC の連絡先アドレスを出力に混ぜない" \
  's = s.replace("sed -E \x27s/mailto:[^,;[:space:]]+/mailto:<伏字>/g\x27", "cat")'

mutate "recon: DMARC の p= を部分一致に戻す（旧不具合）" "scripts/recon.sh" "sp=none を p=none と取り違えない" \
  's = s.replace("dp=\"$(dmarc_tag p \"$DMARC\")\"", "dp=\"$(printf %s \"$DMARC\" | grep -qi p=none && echo none)\"")'
mutate "recon: DS を頂点ではなくホスト名で引く（旧不具合）" "scripts/recon.sh" "頂点の DS を見つける" \
  's = s.replace("APEX=\"$(zone_apex)\"", "APEX=\"$DOMAIN\"")'
mutate "recon: 親ドメインへ遡らない（旧不具合）" "scripts/recon.sh" "サブドメインから親の DMARC を見つける" \
  's = s.replace("    d=\"${d#*.}\"\n", "    break\n")'

# ---- browser_probe（Playwright がある環境でのみ）----
if node -e 'import("playwright")' >/dev/null 2>&1; then
  mutate "browser_probe: 保存領域の値を出力してしまう" "scripts/browser_probe.mjs" "Cookie と保存領域の値を出力しない" \
    's = s.replace("const pick = (s) => { try { return Object.keys(s); } catch { return []; } };", "const pick = (s) => { try { return Object.keys(s).map(k => k + \"=\" + s.getItem(k)); } catch { return []; } };")'
  mutate "browser_probe: HttpOnly の判定を反転する（誤検出）" "scripts/browser_probe.mjs" "HttpOnly のある Cookie を咎めない" \
    's = s.replace("c.httpOnly ? \"HttpOnly\" : \"**HttpOnly なし**\"", "!c.httpOnly ? \"HttpOnly\" : \"**HttpOnly なし**\"")'
  mutate "browser_probe: 既知タグのラベルを取り違える" "scripts/browser_probe.mjs" "既知タグのラベル付け" \
    's = s.replace("[/clarity\\.ms/, \"Microsoft Clarity\"],", "[/clarity\\.ms/, \"Hotjar\"],")'
else
  printf '  \033[33m-\033[0m browser_probe の 3 件（playwright が無いため省略）\n'; SKIP=$((SKIP+3))
fi

printf '\n\033[1m結果\033[0m  生きている検査 %d / 生きていない %d / 省略 %d\n' "$PASS" "$FAIL" "$SKIP"
if [[ $FAIL -gt 0 ]]; then
  echo "  「生きていない」検査は、通っていても何も確かめていない。検査か題材を直す。"
  exit 1
fi
