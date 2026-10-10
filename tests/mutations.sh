#!/usr/bin/env bash
# mutations.sh — 検査が本当に失敗を捕まえるかを確かめる（検査の検査）
#
#   使い方: tests/mutations.sh [--only <名前の一部>]
#
# tests/run.sh は「通ること」しか示さない。通る検査が、壊れたときに失敗するかどうかは別の話で、
# 実際にこのリポジトリでは「浅い場所に題材を置いたため不具合を再現できず素通りしていた」
# 検査があった。ここでは、スキルにわざと欠陥を入れて run.sh を実行し、対応する検査が
# 失敗することを 1 つずつ確かめる。失敗しない検査は「生きていない」と判定する。
#
# 各ミューテーションは、対象ファイルの一部を置き換え → run.sh → 復元、の順で行う。
# 復元は trap で保証する。途中で止めても元に戻る。

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL="$ROOT/skill"
# --only <名前の一部> で絞る（| で区切って複数を指定できる）。--shard K/N で、変異を N 個に分けた K 番目だけを実行する（CI で並べて実行するため。
# 変異が 200 件を超え、1 回では CI の時間の上限に近かった）
ONLY=""; SHARD_K=0; SHARD_N=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) ONLY="${2:-}"; shift 2 ;;
    --shard) SHARD_K="${2%%/*}"; SHARD_N="${2##*/}"; shift 2
             [[ "$SHARD_K" =~ ^[0-9]+$ && "$SHARD_N" =~ ^[0-9]+$ && $SHARD_K -ge 1 && $SHARD_K -le $SHARD_N ]] \
               || { echo "--shard は K/N（1 ≤ K ≤ N）で指定する" >&2; exit 2; } ;;
    *) echo "使い方: tests/mutations.sh [--only <名前の一部>] [--shard K/N]" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0; SKIP=0; MIDX=0; OUTSHARD=0
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
if grep '✗' <<<"$base" >/dev/null; then
  echo "変異を入れる前の run.sh が失敗している。先に直す:" >&2
  printf '%s\n' "$base" | grep '✗' | head -5 >&2
  exit 1
fi

# 1 つのミューテーションを実行する。
#   mutate <名前> <対象ファイル（skill からの相対）> <失敗するべき検査名の一部> <Python の置換コード>
# Python コードは、変数 s（ファイル内容）を書き換えて返す形で書く。
# 置換が 1 か所も当たらなければ、そのミューテーションは「対象が見つからない」で失敗にする。
# （対象が変わって置換が空振りすると、検査の生死を確かめていないのに通ってしまうため）
mutate() {
  local name="$1" rel="$2" expect="$3" code="$4"
  local target="$SKILL/$rel" bak
  # --only は | で区切って複数を指定できる（どれかを名前に含めば実行する）
  if [[ -n "$ONLY" ]]; then
    local part hit=0
    IFS='|' read -ra ONLY_PARTS <<<"$ONLY"
    for part in "${ONLY_PARTS[@]}"; do [[ -n "$part" && "$name" == *"$part"* ]] && hit=1; done
    if [[ $hit -eq 0 ]]; then SKIP=$((SKIP+1)); return; fi
  fi
  MIDX=$((MIDX+1))
  if [[ $SHARD_N -gt 0 && $(( (MIDX - 1) % SHARD_N )) -ne $((SHARD_K - 1)) ]]; then OUTSHARD=$((OUTSHARD+1)); return; fi
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

  # 検査を実行し、期待した検査が失敗したかを確かめる
  local out; out="$(bash "$ROOT/tests/run.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  cp -p "$bak" "$target"; rm -f "$bak"; BACKUPS=("${BACKUPS[@]/$bak::$target/}")

  if grep -E "✗ .*${expect}" <<<"$out" >/dev/null; then
    printf '  \033[32m✓\033[0m %-52s → 「%s」が失敗した（欠陥を見つけた）\n' "$name" "$expect"
    PASS=$((PASS+1))
  else
    printf '  \033[31m✗\033[0m %-52s → 「%s」が失敗しなかった。この検査は生きていない\n' "$name" "$expect"
    FAIL=$((FAIL+1))
  fi
}

printf '\n\033[1m検査の検査 — スキルに欠陥を入れて、対応する検査が失敗するか\033[0m\n\n'

# ---- 構造 ----
mutate "存在しない参照先を書く" "SKILL.md" "参照先が実在する" \
  's = s.replace("## 参照ファイル", "## 参照ファイル\n\n`references/99-nonexistent.md` を読む。\n", 1)'
# 実行権限は内容の置換ではないので、mutate を通さず直接扱う
if [[ ( -z "$ONLY" || "実行権限" == *"$ONLY"* ) && $SHARD_K -le 1 ]]; then
  chmod 644 "$SKILL/scripts/scan_secrets.sh"
  out="$(bash "$ROOT/tests/run.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  chmod 755 "$SKILL/scripts/scan_secrets.sh"
  if grep -E "✗ .*実行権限: scan_secrets.sh" <<<"$out" >/dev/null; then
    printf '  \033[32m✓\033[0m %-52s → 「%s」が失敗した（欠陥を見つけた）\n' "スクリプトの実行権限を外す" "実行権限"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗\033[0m %-52s → 失敗しなかった\n' "スクリプトの実行権限を外す"; FAIL=$((FAIL+1))
  fi
fi

# ---- 機密 ----
mutate "案件固有語を混入させる" "SKILL.md" "案件固有語が含まれない" \
  's = s + "\n対象は CLIENT-NGWORD-CANARY のシステムである。\n"'
# 入れるドメインは .test（予約済みで誰も登録できない）。許可リストに無いので検査が捕まえる
mutate "skill/ の外に案件語を書く" "../README.md" "公開するファイルに、案件や評価の題材を特定できる語が無い" \
  's = s + "\n対象は " + "IDW-" + "CANARY-7Q" + " のシステムである。\n"'
mutate "評価の題材の一覧から語を取り出さない" "../build/identifying-words.sh" "評価の題材の名前が追加行にあれば止める" \
  's = s.replace("t = local / \x27targets.tsv\x27", "t = local / \x27no-such.tsv\x27")'
mutate "実在しうるドメインを書く" "references/01-scoping.md" "実在しうるドメインが書かれていない" \
  's = s + "\n参考: https://client-site.example.test/\n"'
mutate "「効」を動詞に使う" "references/05-remediation-plan.md" "「効」を動詞に使う言い回しが無い" \
  's = s + "\nこの対策は効かない。\n"'
mutate "想定外の文字体系を混入させる" "references/02-code-audit.md" "想定外の文字体系" \
  's = s + "\nテスト用の混入 материал\n"'
mutate "基準の最終確認日を消す" "references/06-frameworks.md" "基準の版に最終確認日" \
  's = s.replace("standards-reviewed:", "standards-checked:")'
mutate "勧告の判定表の照合日を消す" "scripts/audit_grep.sh" "既知の勧告の判定表に照合日" \
  's = s.replace("\nADVISORIES_REVIEWED=", "\nADVISORIES_CHECKED=").replace("\"$ADVISORIES_REVIEWED\"", "\"${ADVISORIES_CHECKED:-}\"").replace("${ADVISORIES_REVIEWED}", "${ADVISORIES_CHECKED:-}")'
mutate "audit_grep: 照合日を出さない" "scripts/audit_grep.sh" "判定表の照合日と経過日数を出す" \
  's = s.replace("  echo \"  ※ ★ の判定表を公式の勧告と照合した日: ${ADVISORIES_REVIEWED}（${adv_days} 日前）\"\n", "")'
mutate "audit_grep: 半年を超えても知らせない" "scripts/audit_grep.sh" "照合から半年を超えたら" \
  's = s.replace("[[ \"$adv_days\" -ge 180 ]]", "[[ \"$adv_days\" -ge 999999 ]]")'

# ---- scan_secrets ----
mutate "scan_secrets: 絶対パスのまま検索する（旧不具合）" "scripts/scan_secrets.sh" "検出行の中身が表示される" \
  's = s.replace("(cd \"$DIR\" && tr \x27\\n\x27 \x27\\0\x27 < \"$TEXTS\" | xargs -0 grep -HnoI", "(cd \"$DIR\" && sed \"s#^.#$DIR#\" \"$TEXTS\" | tr \x27\\n\x27 \x27\\0\x27 | xargs -0 grep -HnoI")'
mutate "scan_secrets: iconv を外す（日本語が壊れる）" "scripts/scan_secrets.sh" "日本語が壊れない" \
  's = s.replace("    iconv -c -f UTF-8 -t UTF-8 2>/dev/null\n", "    cat\n")'
mutate "scan_secrets: 検出した値をそのまま出す" "scripts/scan_secrets.sh" "検出した値を出さない" \
  's = s.replace("else v=\"$(mask_value \"$v\")\"; fi", "fi")'
mutate "scan_secrets: 拡張子で絞る（旧不具合）" "scripts/scan_secrets.sh" "scan_secrets\\[形式\\]: HAR の Authorization" \
  's = s.replace("find . -type f ! -name \x27~$*\x27 ! -name \x27.DS_Store\x27", "find . -type f \\( -name \x27*.md\x27 -o -name \x27*.json\x27 \\) ! -name \x27~$*\x27 ! -name \x27.DS_Store\x27")'
mutate "scan_secrets: xlsx を展開しない（旧不具合）" "scripts/scan_secrets.sh" "xlsx の台帳（セルの文字列）" \
  's = s.replace("-iname \x27*.xlsx\x27", "-iname \x27*.ZZZNOMATCH\x27")'
mutate "scan_secrets: unzip が無いのを黙って飛ばす" "scripts/scan_secrets.sh" "unzip が無いと xlsx を未検査と知らせる" \
  's = s.replace("UNREAD+=(\"${f}（unzip が無い）\"); continue", "continue")'
mutate "scan_secrets: 大文字小文字を区別する（取りこぼし）" "scripts/scan_secrets.sh" "大文字の SELECT" \
  's = s.replace("[[ \"$opts\" == *i* ]] && gopt+=(-i)", ":")'
mutate "scan_secrets: 数字の並びの境界を外す（誤検出）" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID" \
  's = s.replace("full=\"(^|[^0-9A-Za-z_.+-]|[A-Za-z]\\\\.)(${pattern})([^0-9A-Za-z_-]|$)\"", "full=\"(${pattern})\"")'
mutate "scan_secrets: 英字の後の「.」を境界に認めない（取りこぼし）" "scripts/scan_secrets.sh" "TEL. の直後" \
  's = s.replace("|[A-Za-z]\\\\.)(${pattern})", ")(${pattern})")'
mutate "scan_secrets: docx の断片を段落でつながない（取りこぼし）" "scripts/scan_secrets.sh" "書式で 2 つに分かれた番号" \
  's = s.replace("DOCX_ENDS=\x27^/(w|a):p$\x27", "DOCX_ENDS=\x27^/(w|a):(p|t)$\x27")'
mutate "scan_secrets: PDF を黙って飛ばす" "scripts/scan_secrets.sh" "PDF を黙って飛ばさず未検査と知らせる" \
  's = s.replace("-iname \x27*.pdf\x27", "-iname \x27*.ZZZNOMATCH\x27")'
mutate "scan_secrets: 日時の 12 桁を除外しない（誤検出）" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID" \
  's = s.replace("\x27^(19|20)[0-9]{2}(0[1-9]|1[0-2])", "\x27^ZZZNOMATCH(19|20)[0-9]{2}(0[1-9]|1[0-2])")'

mutate "scan_secrets: 関数に渡した値を見ない" "scripts/scan_secrets.sh" "ハッシュ関数に渡した値" \
  's = s.replace("((hash|compare|sign|encrypt|decrypt|createHmac|pbkdf2|scrypt|login|authenticate|signIn)", "((zzzhash)")'
mutate "scan_secrets: アルゴリズム名を値と取り違える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("(HS|RS|ES|PS)(256|384|512)|none|", "")'

mutate "scan_secrets: 日本語の文の中の値を見ない" "scripts/scan_secrets.sh" "日本語の文の中の値" \
  's = s.replace("|(パスワード|暗証番号)(は|が|を|:|：)?[[:space:]]*)", ")")'

mutate "scan_secrets: テンプレートの差し込みを値と取り違える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("(\\$\\{|#\\{|\\{\\{|%\\(|%s|\\?|:[A-Za-z_])", "(ZZZNEVER)")'

mutate "scan_secrets: カード番号を Luhn で確かめない" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("\"\" dL", "\"\" d")'
mutate "scan_secrets: 括弧を含むコードを値と取り違える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("|([\"\x27\"\x27\"\x27`]|「)[^\"\x27\"\x27\"\x27`」]*\\(", "")'

mutate "scan_secrets: 見本の接続文字列を値と取り違える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("\"\" \"\" \"://${PH}(:${PH})?@\"", "\"\" \"\" \"://<伏字>@\"", 1)'

mutate "scan_secrets: 差し込みの記法の接続文字列を値と取り違える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("|\\$\\{[^}]*\\}", "", 1)'

# 文字コードの違うテキスト・xlsx のリッチテキスト・終了コード・足した形式
mutate "scan_secrets: xlsx の断片を文字列ごとにつながない" "scripts/scan_secrets.sh" "書式で 2 つに分かれた番号を文字列ごとにつなぐ" \
  's = s.replace("XLSX_ENDS=\x27^/(si|is|c|text)$\x27", "XLSX_ENDS=\x27^/(si|is|c|text|t)$\x27")'
mutate "scan_secrets: UTF-16 のテキストを直さない" "scripts/scan_secrets.sh" "UTF-16 のテキスト" \
  's = s.replace("to_utf8 \"$f\" UTF-16 UTF-16 ||", "false ||")'
mutate "scan_secrets: Shift_JIS のテキストを直さない" "scripts/scan_secrets.sh" "Shift_JIS の CSV" \
  's = s.replace("    to_utf8 \"$f\" CP932 Shift_JIS && continue\n", "")'
mutate "scan_secrets: 読めないファイルを黙って飛ばす" "scripts/scan_secrets.sh" "テキストとして読めないファイルを未検査と知らせる" \
  's = s.replace("    UNREAD+=(\"${f}（テキストとして読めない。画像なら開いて目で確かめる）\")\n", "")'
mutate "scan_secrets: 検出があっても 0 で終える" "scripts/scan_secrets.sh" "検出があれば終了コード 2" \
  's = s.replace("[[ $HITS -gt 0 ]] && exit 2", ":")'
mutate "scan_secrets: 見ていないファイルがあっても 0 で終える" "scripts/scan_secrets.sh" "見ていないファイルだけなら終了コード 3" \
  's = s.replace("[[ ${#UNREAD[@]} -gt 0 ]] && exit 3", ":")'
mutate "scan_secrets: 引用符の無い文の値を見ない" "scripts/scan_secrets.sh" "引用符の無い文の中のパスワード" \
  's = s.replace("\x27(パスワード|暗証番号)(は|が|を|:|：)[[:space:]]*[A-Za-z0-9", "\x27ZZZNEVER(パスワード|暗証番号)(は|が|を|:|：)[[:space:]]*[A-Za-z0-9")'
mutate "scan_secrets: 引用符の無い文で説明文まで数える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("\x27(は|が|を|:|：)[[:space:]]*([^0-9]+|", "\x27ZZZNEVER(", 1)'
mutate "scan_secrets: パスワードのハッシュを見ない" "scripts/scan_secrets.sh" "bcrypt のハッシュ" \
  's = s.replace("\x27\\$2[abxy]?\\$[0-9]{2}\\$[./A-Za-z0-9]{53}|", "\x27ZZZNEVER|")'
mutate "scan_secrets: credentials を名前に含めない" "scripts/scan_secrets.sh" "credentials の名前への代入" \
  's = s.replace("|salt|credentials?|", "|salt|")'
mutate "scan_secrets: Azure の鍵を見ない" "scripts/scan_secrets.sh" "Azure の AccountKey" \
  's = s.replace("|(Account|SharedAccess)Key=[A-Za-z0-9+/]{40,}={0,2}", "")'
mutate "scan_secrets: Mailgun の鍵を見ない" "scripts/scan_secrets.sh" "Mailgun（key-）" \
  's = s.replace("|key-[0-9a-f]{32})", ")")'
mutate "scan_secrets: OpenRouter の鍵を見ない" "scripts/scan_secrets.sh" "OpenRouter（sk-or-v1-）" \
  's = s.replace("|or-v1-[A-Za-z0-9]{20,}", "")'
mutate "scan_secrets: GitHub の送信専用アドレスも数える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("\x27^(noreply|git)@github\\.com$\x27", "\x27^ZZZNEVER$\x27")'
mutate "scan_secrets: GitHub の代理アドレスのドメインを伏せる" "scripts/scan_secrets.sh" "GitHub の代理アドレスはドメインを見せる" \
  's = s.replace("|users\\.noreply\\.github\\.com)$", ")$")'

# ---- 20 節・0 節・16 節（CI と LLM の経路）----
mutate "audit_grep: run: の中の外部の値に ★ を付けない（旧構成）" "scripts/audit_grep.sh" "run: の中の外部の値に ★ を付ける" \
  's = s.replace("if ($1 == 1) print \"  ★ \" $2;", "if (0) print \"  ★ \" $2;")'
mutate "audit_grep: inputs の展開を拾わない（旧構成）" "scripts/audit_grep.sh" "run: の中の inputs を並べる" \
  's = s.replace("CI_IN=\x27(github\\.event\\.inputs|inputs)\\.[A-Za-z0-9_-]+\x27", "CI_IN=\x27NO-SUCH-INPUT\x27")'
mutate "audit_grep: ジョブ全体の env: を見ない（旧構成）" "scripts/audit_grep.sh" "ジョブ全体の env: に置いた秘密情報を並べる" \
  's = s.replace("if (!(p >= 0 && last[p] ~ /^- /)) { inenv = 1;", "if (0) { inenv = 1;")'
mutate "audit_grep: checkout と成果物の組を見ない（旧構成）" "scripts/audit_grep.sh" "資格情報を残す checkout に ★ を付ける" \
  's = s.replace("if (co != \"\" && upr != \"\") {", "if (0) {")'
mutate "audit_grep: 隠しファイルを既定で除く版にも ★ を付ける" "scripts/audit_grep.sh" "隠しファイルを既定で除く版に ★ を付けない" \
  's = s.replace("if (!hid && hides(uv))", "if (0)")'
mutate "audit_grep: include-hidden-files を見ない" "scripts/audit_grep.sh" "include-hidden-files: true に ★ を付ける" \
  's = s.replace("include-hidden-files:[ \\t]*[\"\\047]?true/) hid = 1", "include-hidden-files:[ \\t]*[\"\\047]?true/) hid = 0")'
mutate "audit_grep: persist-credentials: false を見ない" "scripts/audit_grep.sh" "persist-credentials: false のジョブは咎めない" \
  's = s.replace("?false/) pc = 1", "?false/) pc = 0")'
mutate "audit_grep: 前のジョブの checkout を持ち越す" "scripts/audit_grep.sh" "checkout の無いジョブへ前のジョブの checkout を持ち越さない" \
  's = s.replace("co = \"\"; upr = \"\"; ups = \"\"", "upr = \"\"; ups = \"\"")'
mutate "audit_grep: 複数行の path を読まない" "scripts/audit_grep.sh" "複数行の path も読み" \
  's = s.replace("if (v ~ /^[|>]/) pm = k;", "if (0) pm = k;")'
mutate "audit_grep: Action の勧告の表と照合しない（旧構成）" "scripts/audit_grep.sh" "勧告の範囲の版のタグに ★ を付ける" \
  's = s.replace("if (pk[i] == pkg && inrange(ver, rg[i]))", "if (0)")'
mutate "audit_grep: ハッシュの後ろの版の注記を読まない" "scripts/audit_grep.sh" "ハッシュの後ろの版の注記で勧告と照合する" \
  's = s.replace("else if (match($0, /#[ \\t]*v?[0-9]+(\\.[0-9]+)*/)) { ver =", "else if (0) { ver =")'
mutate "audit_grep: 数字だけのハッシュを版と読む" "scripts/audit_grep.sh" "ハッシュの後ろの版の注記で勧告と照合する" \
  's = s.replace("&& length(ref) < 40) { ver = ref;", ") { ver = ref;")'
mutate "audit_grep: 動くタグを系列の先頭の版として照合する" "scripts/audit_grep.sh" "系列の最新が範囲の外の動くタグは咎めない" \
  's = s.replace("while (n < 3) { ver = ver \".999999\"; n++ }", "while (n < 3) { ver = ver \".0\"; n++ }")'
mutate "audit_grep: 道具を latest で入れる入力を拾わない（旧構成）" "scripts/audit_grep.sh" "道具を latest で入れる入力に ★ を付ける" \
  's = s.replace("]?latest[", "]?NO-SUCH-LATEST[")'
mutate "audit_grep: Action の勧告の表に照合日を書かない" "scripts/audit_grep.sh" "Action の勧告の表に照合日が書いてある" \
  's = s.replace("  ACT_ADV_REVIEWED=\"", "  ACT_ADV_REVIEWED=\"未")'
mutate "audit_grep: LLM の呼び出しの置き場を分けない（旧構成）" "scripts/audit_grep.sh" "CI・スクリプトだけの呼び出しを、アプリ自身と言わずに分ける" \
  's = s.replace("elif [[ -n \"$llm_batch$llm_ci\" ]]; then", "elif false; then")'

mutate "audit_grep: 通知の宛先の一覧も役割の判定に並べる" "scripts/audit_grep.sh" "通知の宛先の一覧は並べない" \
  's = s.replace(" | grep -viE \x27NOTIFY|ALERT|_TO[^A-Z]|SENDER|FROM_\x27", "")'
mutate "audit_grep: メールで決める判定の関数の定義を並べない" "scripts/audit_grep.sh" "メールで決める判定の関数の定義を並べる" \
  's = s.replace("|(function|def|const|let|var)[[:space:]]+is[A-Za-z]*(Admin|Staff|Owner|Operator)[A-Za-z]*Email\x27", "\x27")'

mutate "make_register: 観点の一覧から運用の行を落とす" "scripts/make_register.py" "運用の行をすべて持つ" \
  's = s.replace("\n    \"運用 8. 外部診断と受付窓口\",", "")'

mutate "audit_grep: JS の論理和をテンプレートの raw のフィルタと取り違える（旧不具合）" "scripts/audit_grep.sh" "JS の論理和を、テンプレートの raw のフィルタと取り違えない" \
  's = s.replace("(^|[^|])\\|[[:space:]]*(safe|raw)", "\\|[[:space:]]*(safe|raw)").replace("(^|[^|])\\|[ \\t]*(safe|raw)", "\\|[ \\t]*(safe|raw)")'
mutate "audit_grep: 固定の転送先に置き換える行にも ★ を付ける（旧不具合）" "scripts/audit_grep.sh" "固定の転送先に置き換えるだけの行に ★ を付けない" \
  's = s.replace("printf \x27    %s（文字列と比べて、固定の転送先に置き換えている）\\n\x27", "printf \x27  ★ %s\\n\x27")'
mutate "audit_grep: エラー文を応答に返す行を並べない（旧構成）" "scripts/audit_grep.sh" "DB のエラー文をそのまま応答に返す行を並べる" \
  's = s.replace("(message|stack|details?|hint|sqlMessage)", "(no_such_field)")'

mutate "audit_grep: Firebase の書き込みの項目の制限を見ない（旧構成）" "scripts/audit_grep.sh" "Firebase の変える項目を絞らない書き込みを並べる" \
  's = s.replace("if (buf ~ /request\\.auth/ && buf !~", "if (0 && buf !~")'

mutate "audit_grep: 勧告の表に next/og の行が無い（旧構成）" "scripts/audit_grep.sh" "16.3.5 に 2026-09-23 の next/og の critical の勧告" \
  's = s.replace("if inrange \"$pure\" 16.2.0 16.3.6; then", "if false; then", 1)'
mutate "audit_grep: 勧告の表に 2026-10-01 の勧告群の行が無い（旧構成）" "scripts/audit_grep.sh" "16.3.7 に 2026-10-01 の勧告群" \
  's = s.replace("if { [[ \"$major\" -eq 15 ]] && verlt \"$pure\" 15.5.27; } || inrange \"$pure\" 16.0.0 16.3.8; then", "if false; then", 1)'

mutate "make_register: カード決済のシートに不正ログイン対策の場面を書かない（旧構成）" "scripts/make_register.py" "カード決済のシートに 属性情報変更時 がある" \
  's = s.replace("属性情報変更時", "属性変更")'

mutate "make_register: 枠組みのシートの根拠を数えない（旧構成）" "scripts/make_register.py" "整合の確認が枠組みのシートの根拠を 3 通り数える" \
  's = s.replace("    for key, vcol, ecol in ((\"owasp\", \"C\", \"D\"), (\"api\", \"C\", \"E\")):", "    for key, vcol, ecol in ():")'

# ---- version_check・carry_check（古い写しでの評価と、再評価での ID の取りこぼしを止める）----
mutate "version_check: 版を文字列として比べる" "scripts/version_check.sh" "公開より古い写しは 2 で止め" \
  's = s.replace("p = x[i] + 0; q = y[i] + 0", "p = x[i] \"\"; q = y[i] \"\"")'
mutate "version_check: 公開元に届かなくても最新と言う" "scripts/version_check.sh" "公開元に届かなければ 3" \
  's = s.replace("  echo \"  判定           確かめられない\"", "  echo \"  判定           最新\"; exit 0")'
mutate "make_register: 置き場の VERSION を読まない（旧構成）" "scripts/make_register.py" "配布物の並びでは、スキルの直下の VERSION を版に入れる" \
  's = s.replace("        args.skill_version = skill_version_here()", "        pass")'
mutate "carry_check: 前回にあって今回に無い ID を出さない" "scripts/carry_check.py" "前回にあって今回に無い ID を出す（指摘）" \
  's = s.replace("missing = sorted(set(prev_rows) - set(cur_rows), key=sortkey)", "missing = []")'
mutate "carry_check: 資料の節の参照を ID に数える" "scripts/carry_check.py" "資料の節の参照（02 の A-1）を ID に数えない" \
  's = s.replace("                    if SECTION_REF.search(v[:m.start()]):\n                        continue\n", "")'
mutate "carry_check: 番号の使い回しを見比べる候補に出さない" "scripts/carry_check.py" "同じ番号を別の意味に使った ID" \
  's = s.replace("< 0.2]", "< 0.0]")'

mutate "make_register: ★ の行のコードを台帳に写す" "scripts/make_register.py" "コードの写しを台帳に入れない" \
  's = s.replace("rows.append((sec, f\"{loc.group(1)}:{loc.group(2)}\", None))", "rows.append((sec, f\"{loc.group(1)}:{loc.group(2)}\", rest))")'
mutate "make_register: ★ の判定の空欄を数えない" "scripts/make_register.py" "整合の確認が ★ の判定の空欄と" \
  's = s.replace("(\"★ の判定で、判定が空欄の行\", ", "(\"（数えない）\", ")'

# ---- make_register ----
mutate "make_register: 既にあるファイルを黙って上書きする（旧不具合）" "scripts/make_register.py" "既にあるファイルは上書きせずに止まる" \
  's = s.replace("if os.path.exists(args.output) and not args.force:", "if False:")'
mutate "make_register: full の副題を 3_指摘事項一覧 に戻す（旧不具合）" "scripts/make_register.py" "full の副題が 6_指摘事項一覧 を指す" \
  's = s.replace("\"件数と工数は『{}』から自動集計される。\".format(names[\"findings\"])", "\"件数と工数は『3_指摘事項一覧』から自動集計される。\"")'
mutate "make_register: --api で一般の Top 10 と両方を並べる（旧不具合）" "scripts/make_register.py" "一般の Top 10 と両方を並べない" \
  's = s.replace("rebuilt[\"api\"] = v.split(\"_\", 1)[0] + \"_API_Top10\"\n                else:", "rebuilt[k] = v\n                    rebuilt[\"api\"] = \"8_API_Top10\"\n                else:")'
mutate "make_register: 優先度に見送り・クローズを戻す（旧構成）" "scripts/make_register.py" "優先度に 見送り・クローズ を入れない" \
  's = s.replace("PRIORITIES = [\"P0\", \"P1\", \"P2\", \"P3\", \"P4\", \"—\"]", "PRIORITIES = [\"P0\", \"P1\", \"P2\", \"P3\", \"P4\", \"見送り\", \"クローズ\"]")'
mutate "make_register: クローズを 1 つに戻す（旧構成）" "scripts/make_register.py" "状態は クローズ を 2 つに分けた" \
  's = s.replace("\"クローズ（解消）\", \"クローズ（該当なし）\", \"見送り\"]", "\"クローズ\", \"見送り\"]")'
mutate "make_register: 集計が状態を見ない" "scripts/make_register.py" "P0 の件数は 判定=問題あり" \
  's = s.replace("open_crit = (f\x27{rng(\"判定\")},\"問題あり\",{rng(\"状態\")},\"<>クローズ*\",\x27\n                 f\x27{rng(\"状態\")},\"<>見送り\"\x27)", "open_crit = f\x27{rng(\"判定\")},\"問題あり\"\x27")'
mutate "make_register: 人手の工数に AI の列を足す" "scripts/make_register.py" "P0 の工数は" \
  's = s.replace("=SUMIFS({rng(\"人手(h)\")}", "=SUMIFS({rng(\"AI実装(h)\")}")'
mutate "make_register: スキルの版を入れない" "scripts/make_register.py" "skill-version の値が" \
  's = s.replace("(\"評価に使ったスキルの版\", skill_version or None, False)", "(\"評価に使ったスキルの版\", None, False)")'
mutate "make_register: 人的・物理的を範囲外にしない" "scripts/make_register.py" "版と構成ごとの中身" \
  's = s.replace("OUT_OF_SCOPE if area in PRIVACY_OUT_OF_SCOPE else \"\"", "\"\"")'
mutate "make_register: カード決済のシートを常設する" "scripts/make_register.py" "card を付けなければカード決済のシートを作らない" \
  's = s.replace("    if args.card:\n", "    if True:\n")'
mutate "make_register: 任意のシートの番号を枚数から数える" "scripts/make_register.py" "番号を飛ばさない" \
  's = s.replace("return max(nums) + 1", "return len(names) + 1")'
mutate "make_register: 実機確認サマリに「参考」を戻す（旧構成）" "scripts/make_register.py" "「参考」の値を残さない" \
  's = s.replace("中間の値は作らない。", "参考情報として記録するだけの行には「参考」を使う。")'
mutate "make_register: pip だけを案内する（PEP 668 で失敗する）" "scripts/make_register.py" "導入の案内に venv がある" \
  's = "\n".join(l for l in s.split("\n") if "python3 -m venv" not in l)'
mutate "make_register: 集計の範囲を 200 行に戻す（旧構成）" "scripts/make_register.py" "集計の範囲が 1000 行以上ある" \
  's = s.replace("LAST = 2000 ", "LAST = 200 ")'
mutate "make_register: 整合の確認で問題なしの優先度を見ない" "scripts/make_register.py" "問題なしの行の優先度が「—」かを数える" \
  's = s.replace("f\x27=COUNTIFS({J},\"問題なし\",{P},\"<>—\")\x27", "f\x27=0\x27")'
mutate "make_register: 整合の確認で問題なしの状態を見ない" "scripts/make_register.py" "問題なしの行の状態が クローズ（該当なし） かを数える" \
  's = s.replace("{S},\"<>クローズ（該当なし）\")\x27", "{S},\"<>ZZZNEVER\")\x27")'
mutate "make_register: 整合の確認で問題ありの優先度を P0 だけと比べる" "scripts/make_register.py" "問題ありの行の優先度が P0〜P4 かを数える" \
  's = s.replace("{{\"P0\",\"P1\",\"P2\",\"P3\",\"P4\"}}", "{{\"P0\"}}")'
mutate "make_register: 整合の確認で ID の重複を数えない" "scripts/make_register.py" "同じ ID が 2 回以上ある行を数える" \
  's = s.replace("*(COUNTIF({A},{A})>1))", "*0)")'
mutate "make_register: 整合の確認で未確認事項の影響先を見ない" "scripts/make_register.py" "未確認事項の影響する項目が台帳にあるかを数える" \
  's = s.replace("*(COUNTIF({A},{U})+COUNTIF({UNO},{U})=0))", "*0)")'
mutate "make_register: 整合の確認で範囲の外の行を数えない" "scripts/make_register.py" "集計の範囲の外に書いた行を数える" \
  's = s.replace("f\"=COUNTA({F}!${idc}${LAST + 1}:${idc}$1048576)\"", "\"=0\"")'
mutate "make_register: 未確認事項の例示行を S-02 に戻す（例示どうしが食い違う）" "scripts/make_register.py" "未確認事項の例示行が指摘事項一覧の例示行の ID を指す" \
  's = s.replace("\"S-01\"], example=True)", "\"S-02\"], example=True)")'
mutate "make_register: 分類の候補を付けない" "scripts/make_register.py" "分類の候補が 04 の分類と一致する" \
  's = s.replace("    add_list(ws, f\"{fcol(\x27分類\x27)}4:{fcol(\x27分類\x27)}{LAST}\", CATEGORIES, strict=False)\n", "")'
mutate "make_register: 根拠の強さの印を副題に書かない" "scripts/make_register.py" "副題に根拠の強さの印がある" \
  's = s.replace("（【実機確認で確定】【新規・実機確認で判明】【依頼者確認】）", "")'
mutate "make_register: OWASP の判定に入力規則を付けない" "scripts/make_register.py" "OWASP（owasp） のシートの判定" \
  's = s.replace("    add_list(ws, f\"C5:C{4 + len(rows)}\", OWASP_VERDICTS)\n", "")'
mutate "make_register: API の判定に入力規則を付けない" "scripts/make_register.py" "API のシートの判定" \
  's = s.replace("    add_list(ws, f\"C5:C{4 + len(API_TOP10)}\", OWASP_VERDICTS)\n", "")'
mutate "make_register: --date の書式を確かめない" "scripts/make_register.py" "--date の書式が崩れていれば止まる" \
  's = s.replace("        _dt.date.fromisoformat(args.date)\n", "        pass\n")'
mutate "make_register: 出力先のディレクトリを確かめない" "scripts/make_register.py" "出力先のディレクトリが無ければ言葉で知らせる" \
  's = s.replace("    if not os.path.isdir(out_dir):\n", "    if False:\n")'

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

mutate "audit_grep: RLS 判定でスキーマの補完をやめる" "scripts/audit_grep.sh" "audit_grep\\[基盤\\]: RLS を有効にしていないテーブル" \
  's = s.replace("sed -E \x27s/^([a-z0-9_]+)$/public.\\1/\x27", "cat")'
mutate "audit_grep: search_path の判定を外す（誤検出）" "scripts/audit_grep.sh" "search_path を固定した関数は咎めない" \
  's = s.replace("tolower($0) ~ /search_path/ { sp=1 }", "tolower($0) ~ /ZZZNOMATCH/ { sp=1 }")'
mutate "audit_grep: use client の除外を外す（誤検出）" "scripts/audit_grep.sh" "use client' の getSession は除く" \
  's = s.replace("grep -qE \"^[[:space:]]*[\x27\\\"]use client[\x27\\\"]\" \"$f\" && continue", ":")'
mutate "audit_grep: ハッシュ固定の除外を外す（誤検出）" "scripts/audit_grep.sh" "ハッシュで固定した Action は出さない" \
  's = s.replace("grep -vE \x27@[0-9a-f]{40}", "grep -vE \x27@ZZZNOMATCH")'
mutate "audit_grep: private 指定の読み取りを壊す（誤検出）" "scripts/audit_grep.sh" "private: true のチャネルは咎めない" \
  's = s.replace("start && /private:[[:space:]]*true/ { priv=1 }", "start && /ZZZNOMATCH/ { priv=1 }")'
mutate "audit_grep: Origin の検証を読み取らない（誤検出）" "scripts/audit_grep.sh" "Origin を検証していれば咎めない" \
  's = s.replace("grep -iE \x27origin|allowRequest|verifyClient\x27", "grep -iE \x27ZZZNOMATCH\x27")'
mutate "audit_grep: SMS の直接呼び出しの判定を外す" "scripts/audit_grep.sh" "API の直接呼び出し" \
  's = s.replace("twilio_direct=\"$(grep -rlE \"${EXA[@]}\" \x27messages\\.create\\(\x27", "twilio_direct=\"$(grep -rlE \"${EXA[@]}\" \x27ZZZNOMATCH\x27")'
mutate "audit_grep: 伏字から URL の認証情報を外す" "scripts/audit_grep.sh" "設定の中の接続文字列の認証情報を伏せる" \
  's = "\n".join(l for l in s.split("\n") if "#://<伏字>@#g" not in l)'
mutate "audit_grep: Convex の確認を次の関数へ持ち越す" "scripts/audit_grep.sh" "Convex の確認を次の関数へ持ち越さない" \
  's = s.replace("(ok ? \"認証の確認あり\" : \"★ 認証の確認なし\"); name=\"\"; ok=0 }", "(ok ? \"認証の確認あり\" : \"★ 認証の確認なし\"); name=\"\" }")'
mutate "audit_grep: パスを空白でも分割する（旧不具合）" "scripts/audit_grep.sh" "空白を含むパスのマイグレーションも読む" \
  's = s.replace("IFS=$\x27\\n\x27; set -f", "set -f")'
mutate "audit_grep: find の除外を外す（旧不具合）" "scripts/audit_grep.sh" "node_modules を一覧に出さない" \
  's = s.replace("find . $(prune_expr) -o -type f", "find . -type f", 1)'
mutate "audit_grep: 出力全体の伏字を外す" "scripts/audit_grep.sh" "Host ヘッダの行の鍵を出さない" \
  's = s.replace("2>&1 | out_filter", "2>&1 | cat")'
mutate "audit_grep: 切り捨てを黙る" "scripts/audit_grep.sh" "切ったことと残りの件数を示す" \
  's = s.replace("END { if (NR > n) printf", "END { if (0) printf")'
mutate "3: ★ を全体で切っても黙る" "scripts/audit_grep.sh" "3 節の ★ を全体で切った件数を示す" \
  's = s.replace("if (ns > 25) printf", "if (0) printf", 1)'
mutate "audit_grep: messages.create を Twilio に限らない" "scripts/audit_grep.sh" "Anthropic の messages.create を SMS と言わない" \
  's = s.replace("do grep -lE \"twilio|Twilio\" \"$f\" 2>/dev/null; done", "do echo \"$f\"; done")'
mutate "audit_grep: React2Shell の修正版を取り違える" "scripts/audit_grep.sh" "React2Shell の修正前を判定" \
  's = s.replace("15.1) fix=15.1.9", "15.1) fix=15.1.0")'
mutate "audit_grep: 2 節でガードの行ではなく一致の数を数える" "scripts/audit_grep.sh" "1 ファイルの定義とガードの行を数える" \
  's = s.replace("if (!((f, ln) in seenl)) { seenl[f, ln] = 1; grd[f]++ }", "grd[f]++")'
mutate "make_register: 個人情報シートから SMS の確認行を落とす" "scripts/make_register.py" "版と構成ごとの中身" \
  's = "\n".join(l for l in s.split("\n") if "SMS の送信経路（確認コード・通知）" not in l)'
mutate "pre-push: LICENSE も案件語の照合に含める" "../build/hooks/pre-push" "問題の無い main の push は通す" \
  's = s.replace(" -- . \x27:(exclude)LICENSE\x27", "")'
mutate "pre-push: main 以外のブランチも通す" "../build/hooks/pre-push" "main 以外のブランチは止める" \
  's = s.replace("refs/heads/main|refs/tags/v[0-9]*) ;;", "refs/heads/*|refs/tags/v[0-9]*) ;;")'
mutate "pre-push: 手元に無いリモートの先端でも検査を飛ばして通す" "../build/hooks/pre-push" "リモートの先端が手元に無ければ止める" \
  's = s.replace("elif git cat-file -e \"${rsha}^{commit}\" 2>/dev/null; then", "elif true; then").replace("if ! git rev-list $range >/dev/null 2>&1; then", "if false; then")'
mutate "audit_grep: ファイルの前に -- を置かない" "scripts/audit_grep.sh" "で始まるファイル名があっても" \
  's = s.replace("xargs -0 grep \"$@\" -- /dev/null", "xargs -0 grep \"$@\" /dev/null")'
mutate "audit_grep: 0 節だけ古いタグの一覧に戻す" "scripts/audit_grep.sh" "0 節も 9 節と同じ一覧でタグを判定する" \
  's = s.replace("grep -rlE \"${EXA[@]}\" \"$TAGPAT|replayIntegration\"", "grep -rlE \"${EXA[@]}\" \x27googletagmanager|gtag\\(|hotjar\x27")'
mutate "audit_grep: 短い関数名に語の境界を置かない（誤検出）" "scripts/audit_grep.sh" "紛らわしい語だけならタグを無と言う" \
  's = s.replace("(^|[^A-Za-z0-9_$.])ytag\\(", "ytag\\(")'
mutate "recon: タグの判定でパスを見ない（誤検出）" "scripts/recon.sh" "共有リンクの www.facebook.com で Meta ピクセルと言わない" \
  's = s.replace("  \x27www.facebook.com|^/tr([/?#]|$)\x27\n", "")'
mutate "build.sh: コミットしていない変更を見ない" "../build/build.sh" "コミットしていない変更があれば固めない" \
  's = s.replace("if ! git -C \"$ROOT\" diff --quiet HEAD -- skill LICENSE VERSION; then", "if false; then")'
mutate "recon: localhost でも DNS を引く" "scripts/recon.sh" "localhost なら DNS を引かない" \
  's = s.replace("elif [[ \"$DOMAIN\" == \"localhost\" || \"$DOMAIN\" == *.localhost ]]; then", "elif false; then")'
mutate "browser_probe: Playwright の版を 1 か所だけ上げる" "scripts/browser_probe.mjs" "Playwright の版が 3 か所で揃っている" \
  's = s.replace("const PW_VERSION = \"1.63.0\";", "const PW_VERSION = \"1.64.0\";")'
mutate "audit_grep: 画面操作の記録で 09 を読ませない" "scripts/audit_grep.sh" "画面操作の記録があれば 09 を読ませる" \
  's = s.replace("references/08-privacy-compliance.md references/09-browser-verification.md\"", "references/08-privacy-compliance.md\"")'
mutate "audit_grep: X 広告の関数を送信先から外す" "scripts/audit_grep.sh" "X 広告のタグを拾う" \
  's = s.replace("|ads-twitter|(^|[^A-Za-z0-9_$.])twq\\(|", "|ads-twitter|")'
mutate "recon: パイプで grep -Eq に渡す（確率的に誤る書き方）" "scripts/recon.sh" "パイプで grep -q に渡していない" \
  's = s.replace("if grep -E \"$sig\" <<<\"$(grep -vE \x27^[[:space:]]*[#;]\x27 <<<\"$head_\")\" >/dev/null; then", "if grep -vE \x27^[[:space:]]*[#;]\x27 <<<\"$head_\" | grep -Eq \"$sig\"; then", 1)'
mutate "資料: コマンド例でスクリプトの中の変数を使う" "references/02-code-audit.md" "スクリプトの中の変数に頼らない" \
  's = s.replace("grep -rnE --exclude-dir=node_modules --exclude-dir=vendor \x27Math", "grep -rnE \"${EX}\" \x27Math", 1)'
mutate "道具: パイプで grep に渡して出力を捨てる" "../tests/self-audit.sh" "検査の道具で、パイプで grep に渡して出力を捨てていない" \
  's = s.replace("if grep -E \x27生きていない 0\x27 <<<\"$mres\" >/dev/null; then", "if printf \x27%s\x27 \"$mres\" | grep -E \x27生きていない 0\x27 >/dev/null; then", 1)'
mutate "道具: 環境変数を挟んで grep -q に渡す" "../tests/self-audit.sh" "パイプで grep -q に渡していない" \
  's = s.replace("if grep -E \x27生きていない 0\x27 <<<\"$mres\" >/dev/null; then", "if printf \x27%s\x27 \"$mres\" | LC_ALL=C grep -qE \x27生きていない 0\x27; then", 1)'
mutate "台帳: 枠の固定を外したシートの表示を正さない" "scripts/make_register.py" "窓枠の無いシートの選択範囲が" \
  's = s.replace("    fix_views(wb)\n", "", 1)'
mutate "再評価: 消えた ID を数えない" "../tests/eval/carry_score.py" "前回の ID が消えたものと、同じ番号を別の意味に使ったものを数える" \
  's = s.replace("missing = sorted(set(p) - set(c))", "missing = []")'
mutate "網羅表: 答えの viewpoint を見ない" "../tests/eval/coverage.py" "答えの viewpoint を分類より優先する" \
  's = s.replace("    v = item.get(\"viewpoint\")\n", "    v = None\n", 1)'
mutate "網羅表: 失敗した検査も数える" "../tests/eval/coverage.py" "成功した検査だけを観点ごとに数える" \
  's = s.replace("r\"\\s*✓ (audit_grep", "r\"\\s*[✓✗] (audit_grep", 1)'
mutate "採点: 対照を答えとして数える" "../tests/eval/score.py" "対照は見つけた数の分母に入れない" \
  's = s.replace("        if it.get(\x27control\x27):\n", "        if False:\n", 1)'
mutate "比較: 対照への誤検出の増加を見ない" "../tests/eval/compare.py" "対照への誤検出が旧より増えれば" \
  's = s.replace("            if ofp and nfp and mean(nfp) > mean(ofp):", "            if False:", 1)'
mutate "19: プロジェクトルートの supabase/ しか見ない" "scripts/audit_grep.sh" "プロジェクトルートに無い Supabase の置き場も判定する" \
  's = s.replace(" || [[ -n \"$(nested_dir supabase)\" ]] \\\n  || [[ -n \"$(nested_pkg \x27\"@supabase/\x27)\" ]]; } && baas=\"$baas Supabase\"", "; } && baas=\"$baas Supabase\"", 1)'
mutate "19: RLS の突き合わせをプロジェクトで分けない" "scripts/audit_grep.sh" "RLS の突き合わせをプロジェクトごとに行う" \
  's = s.replace("projkey() { sed -E \x27s#/(supabase", "projkey() { sed -E \x27s#.*##; s#/(supabase", 1)'
mutate "0: プロジェクトルートに無いロックファイルを見ない" "scripts/audit_grep.sh" "プロジェクトルートに無いロックファイルも見る" \
  's = s.replace("if [[ -z \"$lock\" ]]; then\n  nl=", "if false; then\n  nl=", 1)'
mutate "1b: 下の階層のロックファイルを置き場に入れない" "scripts/audit_grep.sh" "プロジェクトルートと別に画面の側のロックファイルも見る" \
  's = s.replace("               nested_files package-lock.json pnpm-lock.yaml yarn.lock | while", "               : | while", 1)'
mutate "1b: プロジェクトルートでない置き場の名前を添えない" "scripts/audit_grep.sh" "下の階層のロックファイルで枠組みの版を引く" \
  's = s.replace("where=\"\"; [[ \"$d\" != \".\" ]] && where=\"（${d#./}）\"", "where=\"\"", 1)'
mutate "21: プロジェクトルートの依存しか見ない" "scripts/audit_grep.sh" "下の階層の依存もインストール時の防御を見る" \
  's = s.replace("do [[ -n \"$d\" && -f \"$d/package.json\" ]] && printf", "do [[ \"$d\" == \".\" && -f \"$d/package.json\" ]] && printf", 1)'
mutate "21: 省いた節をプロジェクトルートの package.json で決める" "scripts/audit_grep.sh" "下の階層に依存があれば 21 節を省いたと言わない" \
  's = s.replace("[[ -n \"$DIRS21\" ]] || skipped=", "[[ -f package.json ]] || skipped=", 1)'
mutate "2d: アプリの置き場を下の階層から集めない" "scripts/audit_grep.sh" "下の階層のアプリのミドルウェアも見る" \
  's = s.replace("nested_files package.json \x27next.config.*\x27 \x27svelte.config.*\x27 | while", ": | while", 1)'
mutate "0: 下の階層のコンテナの定義を見ない" "scripts/audit_grep.sh" "下の階層のコンテナの定義も判定する" \
  's = s.replace("<<<\"$(nested_files Dockerfile \x27docker-compose.y*ml\x27 \x27compose.y*ml\x27 | head -5)\"", "<<<\"\"", 1)'
mutate "0: 下の階層の CDK を見ない" "scripts/audit_grep.sh" "下の階層の CDK の定義も判定する" \
  's = s.replace("|| [[ -n \"$(nested_files cdk.json | head -1)\" ]]", "", 1)'
mutate "17: 下の階層の Dockerfile を見ない" "scripts/audit_grep.sh" "下の階層の Dockerfile の焼き込みを見る" \
  's = s.replace("NESTED_DF=\"$(nested_files \x27Dockerfile\x27 \x27Dockerfile.*\x27 \x27*.Dockerfile\x27 | head -20)\"", "NESTED_DF=\"\"", 1)'
mutate "17: .dockerignore をプロジェクトルートだけで判定する" "scripts/audit_grep.sh" "プロジェクトルートに Dockerfile が無ければ、そこの .dockerignore を求めない" \
  's = s.replace("if [[ -n \"$(ls Dockerfile* 2>/dev/null)\" || -z \"$NESTED_DF\" ]]; then", "if true; then", 1)'
mutate "17: 前の段の名前を版の固定の漏れに数える" "scripts/audit_grep.sh" "多段ビルドの前の段の名前を版の固定の漏れに数えない" \
  's = s.replace("skip = (tolower(img) in stage) ||", "skip = 0 ||", 1)'
mutate "0: 下の階層のモバイルアプリを見ない" "scripts/audit_grep.sh" "下の階層のモバイルアプリも判定する" \
  's = s.replace("if [[ -z \"$mob\" ]]; then\n  f=\"$(nested_files pubspec.yaml", "if false; then\n  f=\"$(nested_files pubspec.yaml", 1)'
mutate "0: Clerk を下の階層で判定しない" "scripts/audit_grep.sh" "下の階層の Clerk・Firebase・Convex も判定する" \
  's = s.replace(" || [[ -n \"$(nested_pkg \x27\"@clerk/\x27)\" ]]; } && baas", "; } && baas", 1)'
mutate "23: リアルタイムを古い Supabase の条件で判定する" "scripts/audit_grep.sh" "下の階層の Supabase でもリアルタイム通信を判定する" \
  's = s.replace("[[ \"$baas\" == *Supabase* ]] \\\n  && grep -rqlE", "{ [[ -d supabase ]] || grep -qE \x27\"@supabase/\x27 package.json 2>/dev/null; } \\\n  && grep -rqlE", 1)'
mutate "24: 下の階層の SMS の設定を見ない" "scripts/audit_grep.sh" "下の階層の Supabase の SMS の設定も見る" \
  's = s.replace("-type f -path \x27*supabase/config.toml\x27 -print", "-type f -path \x27./supabase/config.toml\x27 -print", 1)'
mutate "Convex: convex/ しか読まない" "scripts/audit_grep.sh" "下の階層の Convex の関数も見る" \
  's = s.replace("-type f -name \x27*.ts\x27 -path \x27*/convex/*\x27", "-type f -name \x27*.ts\x27 -path \x27./convex/*\x27", 1)'
mutate "2g: 名前を付けて受けた本文の流れを並べない" "scripts/audit_grep.sh" "名前を付けて受けた本文をサービスへ渡す行を並べる" \
  's = s.replace("if (l ~ sp || l ~ ar) {", "if (0) {", 1)'
mutate "2g: DTO の型の引数を集めない" "scripts/audit_grep.sh" "DTO の引数の展開を並べる" \
  's = s.replace("          add(ident_after(substr(s, RSTART, RLENGTH))); s = substr(s, RSTART + RLENGTH) }", "          s = substr(s, RSTART + RLENGTH) }", 1)'
mutate "2g: 項目を選んで渡す行も並べる" "scripts/audit_grep.sh" "項目を選んで渡す行は並べない" \
  's = s.replace("\" n \"[[:space:]]*[,)]\"", "\" n \"\"", 1)'
mutate "19: ログインだけで絞る方針に ★ を付けない" "scripts/audit_grep.sh" "持ち主の列がある表のログインだけの方針に ★" \
  's = s.replace("then printf \x27  ★ %s（表に持ち主の列 %s がある）\\n\x27 \"$st\" \"$oc\"", "then printf \x27    %s\\n\x27 \"$st\"", 1)'
mutate "19: 持ち主の列を見ずに ★ を付ける" "scripts/audit_grep.sh" "持ち主の列の無い表のログインだけの方針に ★ を付けない" \
  's = s.replace("if [[ -n \"$oc\" ]]; then printf", "if true; then printf", 1)'
mutate "資料: URL を取る属性の是正の勧めを消す" "references/07-web-vulnerabilities.md" "URL を取る属性は、止まる版でも是正を勧めると書いている" \
  's = s.replace("止まる版の属性にしか出ない値でも、\n保存の時点で `http`・`https` に絞る是正は勧める", "止まる版の属性にしか出ない値は、\n是正は要らない", 1)'
mutate "前処理: アンカーごとの until を見ない" "../tests/eval/prep_anchors.py" "アンカーごとに範囲の終わりを決める" \
  's = s.replace("until = re.compile(a[2]) if len(a) > 2 else item_until", "until = item_until", 1)'
mutate "前処理: 正規表現の置き換えを当てない" "../tests/eval/prep_anchors.py" "正規表現で見つけて置き換える" \
  's = s.replace("        after = [rx.sub(new, l) for l in before]\n        if after == before:", "        after = before\n        if False:", 1)'
mutate "資料: 使われていない定義を決めつける" "references/13-infrastructure.md" "使われていない古い定義は、決めつけずに確かめ、削除か更新を勧めると書いている" \
  's = s.replace("- **ただし、使われていないと決めつけない。**", "- **使われていないものとして扱う。**", 1)'
mutate "資料: 開発環境向けの設定の残りを見ない" "references/02-code-audit.md" "開発環境向けの設定の残りを、本番でも動く経路があれば指摘すると書いている" \
  's = s.replace("**本番でも同じ値で動く経路があれば、残っている可能性として指摘する。**", "", 1)'
mutate "19: 権限の列の更新を見ない" "scripts/audit_grep.sh" "持ち主しか見ない更新の方針で、権限の列を書き換えられる表に ★" \
  's = s.replace("          [[ -n \"$pc\" ]] || continue\n", "          continue\n", 1)'
mutate "19: 列ごとの更新の権限を見ない" "scripts/audit_grep.sh" "列ごとの更新の権限で絞った表に ★ を付けない" \
  's = s.replace("<<<\"$stmts\")\" && continue\n", "<<<\"$stmts\")\" && true\n", 1)'
mutate "19: 内側の表に結び付く比べ方を見ない" "scripts/audit_grep.sh" "表の名前の無い列が内側の表に結び付く比べ方に ★" \
  's = s.replace("if (col == lr[2]) { hit = m; break }", "if (0) { hit = m; break }", 1)'
mutate "資料: grep のパターンを引用符の中で改行する" "references/14-mobile.md" "パターンを引用符の中で改行していない" \
  's = s.replace("grep -rnE \x27intent-filter|CFBundleURLSchemes|associatedDomains|", "grep -rnE \x27intent-filter|CFBundleURLSchemes|\nassociatedDomains|", 1)'

mutate "資料: 未確認事項が止める相手を ID で書くと決めない" "references/04-findings-register.md" "台帳にある ID で書くと決めている" \
  's = s.replace("。**台帳にある ID（S-x・U-x）だけを書く**。相手がまだ指摘になっていなければ、先に「判断保留」の指摘として載せる", "", 1)'
mutate "3 節: 固定の文字列も値として扱う" "scripts/audit_grep.sh" "固定の文字列だけの行には ★ を付けない（React）" \
  's = s.replace("        return rest !~ /^(\\+|%|\\.format|\\.concat|\\|\\|)/\n", "        return 0\n", 1)'
mutate "3 節: ERB の <%- を生の出力に数える" "scripts/audit_grep.sh" "ERB の空白詰めの記号" \
  's = s.replace("if (c ~ /<%-/ && f !~ /\\.(erb|rhtml)$/) v = 1", "if (c ~ /<%-/) v = 1", 1)'
mutate "3b 節: 名前の切れ目を見ずに拒否リストとする" "scripts/audit_grep.sh" "種類と関係の無い名前" \
  's = s.replace("if (c ~ fwd || c ~ rev) print", "print", 1)'
mutate "3b 節: Rails の入れ子の params を拾わない" "scripts/audit_grep.sh" "受け取り口（Rails の入れ子の params）" \
  's = s.replace("params(\\[:[a-z_]+\\])*\\[:[a-z_]*(file", "params\\[:[a-z_]*(file", 1).replace("|\\.original_filename|UploadedFile", "", 1)'
mutate "2h 節: 上限の確かめを見ない" "scripts/audit_grep.sh" "上限で切り詰める行には ★ を付けない" \
  's = s.replace("if grep -qE \"$ub\" <<<\"$c\" || grep -qE \"$ub\" \"$f\" 2>/dev/null; then", "if false; then", 1)'
mutate "2h 節: 経路の無いファイルの引数も拾う" "scripts/audit_grep.sh" "経路の無いファイルの引数の既定値" \
  's = s.replace("\x27 \"$f\" 2>/dev/null; then continue; fi", "\x27 \"$f\" 2>/dev/null; then :; fi", 1)'
mutate "2h 節: NestJS の @Query を読まない" "scripts/audit_grep.sh" "上限の無い件数に ★（NestJS" \
  's = s.replace("SIZE_IN=\"$SIZE_IN|@(Query|Param|Body)", "SIZE_IN=\"$SIZE_IN|@(Xuery|Param|Body)", 1)'
mutate "2j 節: 確かめを転送の行の先まで探す" "scripts/audit_grep.sh" "次の経路の確かめを拾わない" \
  's = s.replace("reg=\"$(sed -n \"${s},$((n + k))p\"", "reg=\"$(sed -n \"${s},$((n + 40))p\"", 1)'
mutate "2j 節: 受けた変数を追わない" "scripts/audit_grep.sh" "離れた転送の行まで変数を追う" \
  's = s.replace("        if [[ -n \"$v\" ]]; then\n          k=", "        if false; then\n          k=", 1)'
mutate "2j 節: / だけの確かめを区別しない" "scripts/audit_grep.sh" "/ で始まるかだけの確かめを区別する" \
  's = s.replace("elif grep -qE \"$REDIR_SLASH\" <<<\"$reg\"; then", "elif false; then", 1)'
mutate "2j 節: 分割代入を読まない" "scripts/audit_grep.sh" "分割代入で受けた値も追う" \
  's = s.replace("REDIR_IN=\"$REDIR_IN|\\{[^}]*", "REDIR_IN=\"$REDIR_IN|\\{XX[^}]*", 1)'
mutate "2j 節: 安全な転送の関数を確かめとみなさない" "scripts/audit_grep.sh" "安全な転送の関数を通すものには" \
  's = s.replace("|[A-Za-z_]*([Ss]afe|[Ss]anitize|[Vv]alidate)[A-Za-z_]*(Url|URL|Redirect|Return|Path|Next|Dest|Target)[A-Za-z_]*\\(|", "|", 1)'
mutate "13b 節: 別の項目の規則もパスワードの規則とする" "scripts/audit_grep.sh" "別の項目の規則を拾わない（Rails）" \
  's = s.replace("if grep -qE \"$PW_FIELD\" <<<\"$t\"; then break; fi", ":", 1)'
mutate "13b 節: 前の行をさかのぼらない" "scripts/audit_grep.sh" "複数行の規則の下限に ★（Rails）" \
  's = s.replace("while (( j >= 1 && j >= n - 5 ))", "while (( j >= 1 && j >= n ))", 1)'
mutate "伏字: 鍵らしい名前に続く値を伏せない" "scripts/audit_grep.sh" "公開の設定のブロックの値を出さない" \
  's = s.replace("if (!match(t, /(secret|passw|pwd|token|api_?key", "if (!match(t, /(secretX|passwX|pwdX|tokenX|api_?keyX", 1)'
mutate "伏字: 接続文字列の Password= を伏せない" "scripts/audit_grep.sh" "接続文字列の Password= を伏せる" \
  's = s.replace("(password|pwd|accountkey|sharedaccesskey|client_?secret|api_?key|secret|token)=", "(passwordX)=", 1)'
mutate "伏字: 検証の呼び出しの引数を伏せない" "scripts/audit_grep.sh" "検証の呼び出しに直書きした鍵を出さない" \
  's = s.replace("(\\.verify|\\.sign|jwt\\.(decode|encode)|createhmac", "(\\.verifyX|\\.signX|jwtX\\.(decode|encode)|createhmacX", 1)'
mutate "伏字: 設定のキーまで伏せる" "scripts/audit_grep.sh" "設定のキーは伏せない" \
  's = s.replace("&& body !~ /^[A-Za-z_][A-Za-z_-]*$/ ", "", 1)'
mutate "写し: 対象の ★ を置き換えない" "scripts/audit_grep.sh" "対象のコメントの ★ を ☆ に変える" \
  's = s.replace("gsub(/★/, \"☆\", b);", "", 1)'
mutate "写し: 制御文字を落とさない" "scripts/audit_grep.sh" "対象の制御文字を出力に残さない" \
  's = s.replace("    | LC_ALL=C tr -d \x27\\000-\\010\\013-\\037\\177\x27 \\\n", "", 1)'
mutate "0 節: 依存の定義を package.json だけで見る" "scripts/audit_grep.sh" "stripe でカード決済を有と判定する" \
  's = s.replace("DEPF=(--include=\x27package.json\x27 --include=\x27requirements*.txt\x27", "DEPF=(--include=\x27package.json\x27 --include=\x27requirementsX*.txt\x27", 1)'
mutate "0 節: タグをテンプレートで探さない" "scripts/audit_grep.sh" "Handlebars のテンプレートのタグの行を並べる" \
  's = s.replace("--include=\x27*.hbs\x27 ", "", 1)'
mutate "1 節: リンク先の .. を解決しない" "scripts/audit_grep.sh" "リポジトリの外を指すリンクを知らせる" \
  's = s.replace("if [[ -d \"$ab\" ]]; then r=\"$(cd \"$ab\" 2>/dev/null && pwd -P)\"; else", "if false; then :; else", 1)'
mutate "2b: 受け手の左に語の切れ目を置かない" "scripts/audit_grep.sh" "cache.get" \
  's = s.replace("ROUTE_REG=\x27(^|[^A-Za-z0-9_$.]|this\\.)(app|router|r|e|", "ROUTE_REG=\x27(app|router|r|e|", 1)'
mutate "2b: 大文字のメソッドを受け手を問わずに読まない" "scripts/audit_grep.sh" "Gin の大文字のメソッドを登録に数える" \
  's = s.replace("|[A-Za-z_][A-Za-z0-9_]*\\.(GET|POST|PUT|PATCH|DELETE|Map(Get|Post|Put|Patch|Delete|Methods))\\(", "", 1)'
mutate "2b: exports.x = をすべて登録に数える" "scripts/audit_grep.sh" "exports.formatDate = を登録に数えない" \
  's = s.replace("SLS_EXPORT=\x27exports\\.handler[[:space:]]*=|", "SLS_EXPORT=\x27exports\\.[a-zA-Z_]+[[:space:]]*=|", 1)'
mutate "2 節: コメントの行のガードの語を数える" "scripts/audit_grep.sh" "コメントの unauthenticated をガードに数えない" \
  's = s.replace("if (f == \"\" || t ~ /^[ \\t]*(\\/\\/|#|\\*|\\/\\*|<!--)/) next", "if (f == \"\") next", 1)'
mutate "2 節: 単語の途中のガードの語を数える" "scripts/audit_grep.sh" "コメントの unauthenticated をガードに数えない" \
  's = s.replace("if (b ~ /[A-Za-z0-9_]/ && m ~ /^[a-z]/) continue", "", 1)'
mutate "2 節: 再エクスポートだけの index も並べる" "scripts/audit_grep.sh" "再エクスポートだけの index を並べない" \
  's = s.replace("case \"$f\" in */index.*|index.*)", "case \"$f\" in NOMATCH)", 1)'
mutate "2c: lib/ の Server Actions を除く" "scripts/audit_grep.sh" "lib/actions の Server Actions も関数ごとに見る" \
  's = s.replace("    | grep -vE \x27\\.(test|spec|stories)\\.[a-z]+$\x27 | sort | while IFS= read -r f; do", "    | grep -vE \x27^\\./(src/)?(components|lib|utils)/\x27 | sort | while IFS= read -r f; do", 1)'
mutate "2e: 一覧を止める設定にも ★ を付ける" "scripts/audit_grep.sh" "一覧を止める設定（Options -Indexes）に ★ を付けない" \
  's = s.replace("    | grep -vE \x27Options[[:space:]]+([^#]*[[:space:]])?-Indexes|autoindex[[:space:]]+off\x27 | sed", "    | sed", 1)'
mutate "3: jQuery の .append(要素) にも ★ を付ける" "scripts/audit_grep.sh" "jQuery の .append" \
  's = s.replace("(append|prepend|after|before|replaceWith)[ \\t]*\\([ \\t]*[\"\\047`][^\"\\047`]*</) {", "(append|prepend|after|before|replaceWith)[ \\t]*\\(/) {", 1)'
mutate "3: 1 ファイルの ★ を打ち切らない" "scripts/audit_grep.sh" "1 ファイルの ★ は 3 件までにし" \
  's = s.replace("if (++nf[f] > 3) { more[f]++; next }", "", 1)'
mutate "19: IFS を改行のまま除外の式を展開する" "scripts/audit_grep.sh" "Prisma のマイグレーションの表の RLS も見る" \
  's = s.replace("sqlfiles=\"$(IFS=\x27 \x27; find", "sqlfiles=\"$(find", 1)'
mutate "19: 読み取りの true にも ★ を付ける" "scripts/audit_grep.sh" "読み取りの条件が true のポリシーには" \
  's = s.replace("|| ! grep -qiE \x27 for \x27 <<<\"$st\"; then printf \x27  ★ %s\\n\x27 \"$st\"", "|| true; then printf \x27  ★ %s\\n\x27 \"$st\"", 1)'
mutate "10: 検証付きの PyJWT も検証なしに並べる" "scripts/audit_grep.sh" "検証付きの PyJWT の decode" \
  's = s.replace("      | grep -vE \x27jwt\\.decode\\([^)]*algorithms[[:space:]]*=\x27 | grep -vE", "      | grep -vE", 1)'
mutate "4: 環境変数の読み込みも直書きに数える" "scripts/audit_grep.sh" "環境変数からの読み込みを直書きに数えない" \
  's = s.replace("    | grep -vE \x27[:=][[:space:]]*(process\\.env|", "    | grep -vE \x27[:=][[:space:]]*(processX\\.env|", 1)'
mutate "2m: 文字列の埋め込みを経路と取り違える" "scripts/audit_grep.sh" "Ruby の文字列の埋め込み" \
  's = s.replace("|/\\\\{${n}(:[^}]*)?\\\\}|", "|\\\\{${n}(:[^}]*)?\\\\}|", 1)'
mutate "中断: 途中で止まっても知らせない" "scripts/audit_grep.sh" "途中で止まったら、出力が途中までであること" \
  's = s.replace("printf \x27\\n=== 中断 ===\\n", "printf \x27\\n=== X ===\\n", 1)'
# 正規表現を緩める・節を丸ごと消す（「1 語を置き換える」形だけでは、検査が表の中身まで確かめているかが分からない）
mutate "2 節: ガードの語の表を何にでも一致させる" "scripts/audit_grep.sh" "ガードの無いハンドラを" \
  's = s.replace("GUARD=\x27require[A-Z][A-Za-z]+|", "GUARD=\x27.|require[A-Z][A-Za-z]+|", 1)'
mutate "2 節: 節の見出しを消す" "scripts/audit_grep.sh" "2 節を切り出せる" \
  's = s.replace("hr \"2. ハンドラ × 認可ガード（空欄は「本当に公開してよいか」を 1 本ずつ確認する）\"", "", 1)'
mutate "2 節: Firebase の verifyIdToken をガードに数えない" "scripts/audit_grep.sh" "ガードを読み取る" \
  's = s.replace("GUARD=\"$GUARD\"\x27|verifyIdToken|", "GUARD=\"$GUARD\"\x27|verifyIdTokenX|", 1)'
mutate "2 節: onRequest をどこでもガードに数える" "scripts/audit_grep.sh" "firebase-functions]: ガードの無いハンドラを" \
  's = s.replace("|preHandler|onRequest[[:space:]]*:|", "|preHandler|onRequest|", 1)'
mutate "2g: 括弧の直後に渡す形を拾わない" "scripts/audit_grep.sh" "受け取ったものを括弧の直後に更新へ渡す形" \
  's = s.replace("fill|forceFill)\\(([^)]{0,40}[^.A-Za-z_])?\x27", "fill|forceFill)\\([^)]{0,40}([^.A-Za-z_]|^)\x27", 1)'
mutate "11: 秘密が未設定のとき検証を飛ばす形を見ない" "scripts/audit_grep.sh" "秘密が未設定のとき検証を飛ばす Webhook" \
  's = s.replace("\x27[Ss]ecret[A-Za-z_]*[[:space:]]*(&&|and)[^;]{0,80}", "\x27[Ss]ecretX[A-Za-z_]*[[:space:]]*(&&|and)[^;]{0,80}", 1)'
mutate "2k: 試験のパスも並べる" "scripts/audit_grep.sh" "試験のファイルの CORS を並べない" \
  's = s.replace("grep -vE \x27(package|package-lock|tsconfig)\\.json:\x27 | grep -vE \"$TESTPATH\"", "grep -vE \x27(package|package-lock|tsconfig)\\.json:\x27", 1)'
mutate "2k: 資格情報の許可をファイル全体で探す" "scripts/audit_grep.sh" "資格情報の許可が離れていれば" \
  's = s.replace("<<<\"$(sed -n \"${n},$((n + 3))p\" \"$f\" 2>/dev/null)\"", "\"$f\"", 1)'
mutate "2m: 経路の区切りでない :id も拾う" "scripts/audit_grep.sh" "設定の読み出しの :id" \
  's = s.replace("r=\"$r|/:${n}([/", "r=\"$r|:${n}([/", 1)'
# 2m. ハンドラの範囲ごとの持ち主の照合（題材 owner-check）
mutate "2m: ログインの語を照合と数える" "scripts/audit_grep.sh" "現在の利用者を変数に入れるだけの代入を照合と数えない" \
  's = s.replace("if (t ~ ENVIRON[\"M_AUTHZ\"] || t ~ ENVIRON[\"M_EQCUR\"]) chk = 1", "if (t ~ ENVIRON[\"M_AUTHZ\"] || t ~ ENVIRON[\"M_EQCUR\"] || t ~ ENVIRON[\"M_CUR\"]) chk = 1", 1)'
mutate "2m: ハンドラの範囲で分けない" "scripts/audit_grep.sh" "本文の id で更新する形に" \
  's = s.replace("else if (t ~ ENVIRON[\"M_START\"]) { if (deco) deco = 0; else flush() }", "else if (t ~ ENVIRON[\"M_START\"]) { if (deco) deco = 0 }", 1)'
mutate "2m: ID を読む行でも持ち主の列を数える" "scripts/audit_grep.sh" "受け取った ID の名前を持ち主の列と取り違えない" \
  's = s.replace("if (t !~ ENVIRON[\"M_ID\"]) { u = t;", "if (1) { u = t;", 1)'
mutate "2m: 引用符の中の current_user も数える" "scripts/audit_grep.sh" "引用符の中の current_user を現在の利用者と数えない" \
  's = s.replace("M_CUR=\x27req\\.user|request\\.user|(^|[^\"\x27\"\x27\"\x27A-Za-z0-9_])current_?user|", "M_CUR=\x27req\\.user|request\\.user|current_?user|", 1)'
mutate "2m: 空白を挟んだ代入も照合と数える" "scripts/audit_grep.sh" "現在の利用者を変数に入れるだけの代入を照合と数えない" \
  's = s.replace("([[:space:]]*(==|!=|=>|:)=?=?[[:space:]]*|=)(", "([[:space:]]*(==|!=|=>|:|=)=?=?[[:space:]]*)(", 1)'
mutate "2m: 本文の参照先の ID も読む" "scripts/audit_grep.sh" "本文の参照先の ID を並べない" \
  's = s.replace("r=\"$r|\\\\{([^}]*[^A-Za-z0-9_])?${o}(", "r=\"$r|\\\\{([^}]*[^A-Za-z0-9_])?${n}(", 1)'
mutate "2m: slug を読むだけでも数える" "scripts/audit_grep.sh" "slug で読むだけのハンドラに" \
  's = s.replace("if (!idl && idwl && mut)", "if (!idl && idwl)", 1)'
mutate "2m: 本体の無い登録も判定する" "scripts/audit_grep.sh" "処理を別の関数に渡すだけの登録に" \
  's = s.replace("if (idl > 0 && !body) dlg++", "if (idl > 0 && body < 0) dlg++", 1)'
mutate "2m: 装飾子と下の関数を別の範囲にする" "scripts/audit_grep.sh" "複数行の装飾子の経路で受ける ID に" \
  's = s.replace("{ if (deco) deco = 0; else flush() }", "{ deco = 0; flush() }", 1)'
mutate "2m: Ruby の @ を装飾子と見る" "scripts/audit_grep.sh" "受け取った ID の名前を持ち主の列と取り違えない" \
  's = s.replace("if (t ~ ENVIRON[\"M_DECO\"] && !(f ~ /\\.rb$/ && t ~ /^[ \\t]*@/))", "if (t ~ ENVIRON[\"M_DECO\"])", 1)'
mutate "2m: 並べ替えの引数の id も読む" "scripts/audit_grep.sh" "並べ替えの引数の id を ID の読み取りと取り違えない" \
  's = s.replace("\\\\([[:space:]]*[\\\"\x27]${n}[\\\"\x27][[:space:]]*\\\\)|URLParam", "\\\\(([^,)]*,[[:space:]]*)?[\\\"\x27]${n}[\\\"\x27]|URLParam", 1)'
mutate "2m: 文中の <名前> も経路と読む" "scripts/audit_grep.sh" "文中の <名前> を経路の書き方と取り違えない" \
  's = s.replace("|[/\\\"\x27]<([a-z]+:)?${n}>", "|<([a-z]+:)?${n}>", 1)'
mutate "2m: denyAll を認可に数えない" "scripts/audit_grep.sh" "誰にも通さない登録に" \
  's = s.replace("M_AUTHZ=\x27authorize[!(]|denyAll|deny_all|DenyAll|", "M_AUTHZ=\x27authorize[!(]|", 1)'
mutate "2m: ログインを確かめているものを先に並べない" "scripts/audit_grep.sh" "ログインを確かめているものを先に並べる" \
  's = s.replace("grep -F \x27← ログインは確かめている\x27; grep \x27^s\x27 \"$M_OUT\" | grep -vF \x27← ログインは確かめている\x27; }", "grep -vF \x27← ログインは確かめている\x27; grep \x27^s\x27 \"$M_OUT\" | grep -F \x27← ログインは確かめている\x27; }", 1)'
mutate "3: Blade の {!! を対で見ない" "scripts/audit_grep.sh" "TSX の" \
  's = s.replace("|\\{!![^}]*!!\\}|th:utext|mark_safe", "|\\{!!|th:utext|mark_safe", 1)'
mutate "3: 試験のファイルもアプリのコードと並べる" "scripts/audit_grep.sh" "静的な資産の置き場の ★ は" \
  's = s.replace("if (f ~ /(^|\\/)(assets|static|public|lib|libs|javascripts|js|test|", "if (f ~ /NOMATCH(^|\\/)(assets|static|public|lib|libs|javascripts|js|test|", 1)'
mutate "語の一覧: 読めない行でも止めない" "../build/identifying-words.sh" "正規表現として読めない行があれば止まる" \
  's = s.replace("printf \x27\x27 | grep -E -- \"$w\" >/dev/null 2>&1; [[ $? -eq 2 ]] && bad=$((bad + 1))", ":", 1)'
mutate "台帳: 観点の一覧の空欄を数えない" "scripts/make_register.py" "観点の一覧の結果の空欄を数える" \
  's = s.replace("checks.append((\"観点の一覧で、結果が空欄の行\"", "checks.append((\"観点の一覧で、結果の欄\"", 1)'
mutate "台帳: 観点の一覧から節を落とす" "scripts/make_register.py" "02 と 07 の節の見出しをすべて持つ" \
  's = s.replace("\"07 5. SSRF\",", "", 1)'
mutate "04: 複数のハンドラをまとめた範囲を許す" "references/04-findings-register.md" "ハンドラごとに分けると決めている" \
  's = s.replace("複数のハンドラにまたがる指摘は、1 つの範囲にまとめず、ハンドラごとに場所を分けて並べる", "複数のハンドラにまたがる指摘は、1 つの範囲にまとめてよい", 1)'
mutate "scan_secrets: 記号を含む値を見ない" "scripts/scan_secrets.sh" "記号を含む値の SECRET_KEY" \
  's = s.replace("([bruf]?[\"\x27\"\x27\"\x27`][^\"\x27\"\x27\"\x27`<…[:space:]]{16,}|", "([bruf]?[\"\x27\"\x27\"\x27`][A-Za-z0-9_/+=-]{16,}|", 1)'
mutate "scan_secrets: 差し込みの書き方を値とみなす" "scripts/scan_secrets.sh" "誤検出しない" \
  's = s.replace("|process\\.env|os", "|os", 1)'
mutate "資料: 埋め込まれた値の指摘で写しやすいことを書かない" "SKILL.md" "埋め込まれた値の指摘で値を写さない" \
  's = s.replace("値が埋め込まれていること自体を指摘するときが、いちばん写しやすい", "値に注意する", 1)'
mutate "3 節: 差し込みを見ずに問い合わせを並べる" "scripts/audit_grep.sh" "LDAP の検索条件に値を連結する行に ★" \
  's = s.replace("if grep -qE \"$QL_INTERP\" <<<\"$c\" || [[ $lit -eq 0 ]]; then", "if [[ $lit -eq 0 ]]; then", 1)'
mutate "3 節: 変数から作るテンプレートを見ない" "scripts/audit_grep.sh" "テンプレートを変数から作る行に ★" \
  's = s.replace("then lit=0; fi", "then lit=1; fi", 1)'
mutate "資料: 攻撃の手順を書かない決まりを消す" "SKILL.md" "攻撃の手順と動く攻撃の文字列を書かない" \
  's = s.replace("攻撃の手順と、そのまま動く攻撃の文字列（ペイロード）も書かない", "書き方に気をつける", 1)'
mutate "audit_grep: rg の誤りを grep でやり直さない" "scripts/audit_grep.sh" "rg で検索しても grep と同じ結果になる（client-authz）" \
  's = s.replace("  if [[ $st -eq 2 && -z \"$out\" ]]; then command grep \"${orig[@]}\"; return; fi\n", "", 1)'
mutate "audit_grep: rg に除外を先に渡す" "scripts/audit_grep.sh" "除外・rg\]: \*\.min\.js を並べない" \
  's = s.replace("  a+=(${inc[@]+\"${inc[@]}\"} ${exc[@]+\"${exc[@]}\"})", "  a+=(${exc[@]+\"${exc[@]}\"} ${inc[@]+\"${inc[@]}\"})", 1)'
mutate "audit_grep: grep に対象の指定を後で渡す" "scripts/audit_grep.sh" "除外・grep\]: \*\.min\.js を並べない" \
  's = s.replace("    orig=(\"$fl\" ${incs[@]+\"${incs[@]}\"} ${rest[@]+\"${rest[@]}\"})", "    orig=(\"$fl\" ${rest[@]+\"${rest[@]}\"} ${incs[@]+\"${incs[@]}\"})", 1)'
mutate "audit_grep: 勧告の表に 2026-08-26 の行が無い" "scripts/audit_grep.sh" "16.3.0 に 2026-08-26 の critical の勧告" \
  's = s.replace("if { [[ \"$major\" -eq 15 ]] && verlt \"$pure\" 15.5.24; } || inrange \"$pure\" 16.0.0 16.3.3; then", "if false; then", 1)'
mutate "2i 節: 分岐の範囲を次の分岐で区切らない" "scripts/audit_grep.sh" "認可の無い分岐に ★（switch の case）" \
  's = s.replace("if (i < nb && b[i + 1] - 1 < e) e = b[i + 1] - 1", "if (0) e = 0", 1)'
mutate "browser_probe: 画面の切り替えを起こさない" "scripts/browser_probe.mjs" "画面の切り替えのあとの第三者への送信を数える" \
  's = s.replace("      history.pushState({}, \"\", u.toString());\n", "", 1)'
mutate "browser_probe: 同意管理の表から OneTrust を外す" "scripts/browser_probe.mjs" "既知タグと同意管理のラベル付け" \
  's = s.replace("  [/(^|\\.)(cookielaw\\.org|onetrust\\.com)$/, \"同意管理（OneTrust）\"],\n", "", 1)'
# ---- 実地の評価の道具（tests/eval/。mutate の対象は skill/ からの相対パスで渡す）----
mutate "eval: 補助のモデルもモデルの欄に並べる" "../tests/eval/score.py" "モデルの欄は主のモデルだけにする" \
  's = s.replace("\x27model\x27: max((d.get(\x27modelUsage\x27) or {}).items(), key=lambda kv: kv[1].get(\x27costUSD\x27) or 0, default=(\x27\x27, {}))[0],", "\x27model\x27: \x27,\x27.join(sorted((d.get(\x27modelUsage\x27) or {}).keys())),", 1)'
mutate "eval: 失敗した回も採点して記録する" "../tests/eval/run-eval.sh" "実行に失敗した回は採点も記録もしない" \
  's = s.replace("sys.exit(0 if r and not r.get(\"is_error\") and (r.get(\"structured_output\") or {}).get(\"findings\") else 1)", "sys.exit(0)", 1)'
mutate "eval: 範囲の答えを書き始めの行だけで見る" "../tests/eval/score.py" "範囲の答えは、指摘の範囲が重なれば一致させる" \
  's = s.replace("(lo <= r[\x27end\x27] and hi >= r[\x27start\x27] if hi > lo", "(r[\x27start\x27] <= lo <= r[\x27end\x27] if hi > lo", 1)'
mutate "eval: run-eval.sh を少しずつ読む" "../tests/eval/run-eval.sh" "run-eval.sh を実行の前に最後まで読み切る" \
  's = s.replace("\n{\n\nROOT=", "\n\nROOT=", 1).replace("\nexit\n}\n", "\n", 1)'
mutate "eval: 比較で違反の増加を劣後としない" "../tests/eval/compare.py" "違反が旧より増えれば劣後とする" \
  's = s.replace("if mean([num(r[\x27違反\x27]) for r in new]) > mean([num(r[\x27違反\x27]) for r in old]):", "if False:", 1)'
mutate "eval: 比較で 1 回だけの疑いを見逃す" "../tests/eval/compare.py" "新が 1 回だけで疑いがあれば" \
  's = s.replace("        elif doubts and len(new) < 2:", "        elif False:", 1)'
mutate "eval: 比較でモデルの違う旧と判定する" "../tests/eval/compare.py" "旧が別のモデルの回しか無ければ" \
  's = s.replace("        if doubts and model_differs:", "        if False:", 1)'
mutate "eval: 比較で切り替えた回を元のモデルの回に混ぜる" "../tests/eval/compare.py" "途中で切り替えた回を、元のモデルだけの回と分けて" \
  's = s.replace("v, c = compare_group(t, trows, [r for r in new_all if r[\x27モデル\x27] == m])", "v, c = compare_group(t, trows, new_all)", 1)'
mutate "eval: 同じ条件の旧が無くても劣後なしとする" "../tests/eval/compare.py" "劣後なしとも言わない" \
  's = s.replace("        elif not compared:\n            # どの", "        elif False:\n            # どの", 1)'
mutate "eval: 採点で切り替えを記録しない" "../tests/eval/score.py" "元→切り替え先と記録する" \
  's = s.replace("    if fb:\n        meta[\x27model\x27]", "    if False:\n        meta[\x27model\x27]", 1)'
mutate "eval: URL の // もコメントとして消す" "../tests/eval/prep_anchors.py" "URL の中の // を壊さない" \
  's = s.replace("SLASH = [re.compile(r\x27(^|(?<=[\\s;,)\\]}]))//.*$\x27)", "SLASH = [re.compile(r\x27//.*$\x27)")'
mutate "eval: 手掛かりの消し残しがあっても止めない" "../tests/eval/prep_anchors.py" "手掛かりの消し残しがあれば止まる" \
  's = s.replace("            sys.exit(\x27手掛かりの消し残しがある: \x27", "            print(\x27手掛かりの消し残しがある: \x27")'
mutate "eval: 範囲を次の装飾子で止めない" "../tests/eval/prep_anchors.py" "答えを処理の範囲で持つ" \
  's = s.replace("if until.search(lines[i - 1])), len(lines))", "if False), len(lines))")'
mutate "eval: ワイルドカードを使わない" "../tests/eval/prep_anchors.py" "ワイルドカードで指定したファイルだけを消す" \
  's = s.replace("(list(root.glob(rel)) if any(c in rel for c in \x27*?[\x27) else [root / rel])", "[root / rel]")'
mutate "eval: 複数行のコメントを消さない" "../tests/eval/prep_anchors.py" "複数行にまたがる手掛かりのコメント" \
  's = s.replace("        text = pat.sub(blank, text)\n", "        pass\n")'
mutate "eval: 手掛かりのコメントを消さない" "../tests/eval/prep_anchors.py" "手掛かりのコメントを消す" \
  's = s.replace("                line = line[:m.start()] + line[m.end():]\n", "                pass\n")'
mutate "eval: ファイル全体の場所も一致に使う" "../tests/eval/score.py" "広い場所は一致に使わない" \
  's = s.replace("    if hi - lo > WIDE:\n        return False\n", "")'
mutate "eval: 埋め込まれた値の転記を咎めない" "../tests/eval/score.py" "題材に埋め込まれた値の転記を咎める" \
  's = s.replace("        for v in answers.get(\x27secrets\x27) or []:\n", "        for v in []:\n")'
mutate "eval: 範囲にも前後の許容を付ける" "../tests/eval/score.py" "範囲は含む答えにだけ一致" \
  's = s.replace("        return lo <= line <= hi\n", "        return lo - tol <= line <= hi + tol\n")'
mutate "eval: 1 行をいちばん近い答え以外にも一致させる" "../tests/eval/score.py" "範囲は含む答えにだけ一致" \
  's = s.replace("    return abs(line - lo) <= min(abs(x - lo) for x in others)\n", "    return True\n")'
mutate "eval: スキルを置いてから audit_grep を実行する" "../tests/eval/run-eval.sh" "audit_grep をスキルを置く前に実行する" \
  's = s.replace("( cd \"$APP\" && bash \"$SKILL_SRC/scripts/audit_grep.sh\" . )", "mkdir -p \"$APP/.claude/skills\"; cp -R \"$SKILL_SRC\" \"$APP/.claude/skills/x\"\n( cd \"$APP\" && bash \"$SKILL_SRC/scripts/audit_grep.sh\" . )", 1)'
mutate "eval: 未確認事項どうしの依存を咎める" "../tests/eval/score.py" "未確認事項どうしの依存は咎めない" \
  's = s.replace("    ids |= {u.get(\x27id\x27) for u in unconfirmed}\n", "")'
mutate "eval: 行をつなぐのに paste -sd を使う" "../tests/eval/run-eval.sh" "macOS で失敗する paste" \
  's = s.replace("| tr -d \x27\\n\x27 > \"$OUT/skill_commit\"", "| paste -sd \x27\x27 - > \"$OUT/skill_commit\"")'
mutate "eval: 採点の許容を広げる" "../tests/eval/score.py" "前後 3 行を超えたら見落とし" \
  's = s.replace("    if abs(line - lo) > tol:\n", "    if abs(line - lo) > tol + 5:\n")'
mutate "eval: 丸投げの言い回しを咎めない" "../tests/eval/score.py" "判定を丸投げする言い回しを咎める" \
  's = s.replace("BANNED = [\x27要検討\x27, ", "BANNED = [")'
mutate "eval: 題材のエージェント設定を消さない" "../tests/eval/run-eval.sh" "題材のエージェント向けの設定を消す" \
  's = s.replace("for p in .claude CLAUDE.md", "for p in .cursor")'

mutate "audit_grep: コメントアウトした認可を知らせない" "scripts/audit_grep.sh" "認可の付いた登録のコメントアウトを知らせる" \
  's = s.replace("if (n in g) print \"  ★ \" f \":\" ln \": \" t > cfile; next", "next")'
mutate "audit_grep: 2b で行全体（ファイル名込み）から認可の語を探す" "scripts/audit_grep.sh" "ファイル名を認可の語と取り違えない" \
  's = s.replace("cut -d: -f3- \"$HF_REG\" > \"$HF_REGT\"", "cp \"$HF_REG\" \"$HF_REGT\"")'
mutate "audit_grep: 2b で設定の読み出しを外さない" "scripts/audit_grep.sh" "設定の読み出しをルートの登録と取り違えない" \
  's = s.replace("&& t !~ /(^|[^A-Za-z0-9_$.])(app|router|r|e|mux|srv|api|fastify|server|routes?|group|g)", "&& 0 && t !~ /(^|[^A-Za-z0-9_$.])(app|router|r|e|mux|srv|api|fastify|server|routes?|group|g)")'

mutate "audit_grep: ★ の一覧を出さない" "scripts/audit_grep.sh" "最後に ★ を集めて出す" \
  's = s.replace("if [[ \"$st\" -eq 0 ]]; then star_list < \"$ALL_OUT\"", "if [[ \"$st\" -eq 0 ]]; then :", 1)'
mutate "audit_grep: ★ の一覧に説明文の ★ も入れる" "scripts/audit_grep.sh" "説明文の ★ を数えない" \
  's = s.replace("&& $0 !~ /※/ && $0 !~ /★ (の|が|は|を)/ {", "{")'

mutate "audit_grep: 内部向けのパスの表を使わない" "scripts/audit_grep.sh" "内部向けのパスに ★ を付ける（actuator）" \
  's = s.replace("if (match(t, ipath)) {", "if (0) {")'
mutate "audit_grep: 2e で設定ファイルを見ない" "scripts/audit_grep.sh" "ディレクトリ一覧（nginx の設定）" \
  's = s.replace("--include=\x27*.conf\x27 ", "")'
mutate "audit_grep: 2e で Django の書き方を拾わない" "scripts/audit_grep.sh" "Django の show_indexes" \
  's = s.replace("[:=][[:space:]]*True|directory_listing", "=[[:space:]]*True|directory_listing")'

mutate "audit_grep: 2f で装飾子の括弧の深さを数えない" "scripts/audit_grep.sh" "複数行の装飾子をはさんでも認可を読む" \
  's = s.replace("blk = blk \" \" line; d += depth(line); if (d < 0) d = 0", "blk = blk \" \" line")'
mutate "audit_grep: 2f でクラスの装飾子を読まない" "scripts/audit_grep.sh" "クラスに付いた認可を読む" \
  's = s.replace("{ cls = blk; n = 0 }", "{ n = 0 }")'
mutate "audit_grep: 2f で処理の宣言の引数を読まない" "scripts/audit_grep.sh" "処理の宣言の引数の認可を読む" \
  's = s.replace("    cut -f6 \"$HF_DECO\" | grep -nE \"$GUARD\" 2>/dev/null | cut -d: -f1 >> \"$HF_DECO.g\" || true\n", "")'

mutate "audit_grep: 2g で注釈の読み方を拾わない" "scripts/audit_grep.sh" "権限の値をリクエストから読む（Spring）" \
  's = s.replace("|@RequestParam\\((value *= *)?", "|@ZZZNEVER\\((value *= *)?")'
mutate "audit_grep: 2g で項目を選んで読む書き方も並べる" "scripts/audit_grep.sh" "項目を選んで読む書き方は" \
  's = s.replace("request\\.data|request\\.json)([^.A-Za-z_[]|$)\x27", "request\\.data|request\\.json)\x27")'

# 手元の題材の変異（tests/eval/local/mutations.sh）。題材を特定できる情報を含むので公開しない。あるときだけ実行する
# shellcheck disable=SC1091
[[ -f "$ROOT/tests/eval/local/mutations.sh" ]] && source "$ROOT/tests/eval/local/mutations.sh"

# ---- recon ----
# 旧不具合は「自サイトの判定がポートを考えない」。ホスト名にポートを残すだけでは、最終的なホスト名も
# 同じ関数を通るので打ち消し合う。旧実装と同じく、渡されたドメインとだけ比べる形に戻す
mutate "recon: ホスト名にポートを残す（旧不具合）" "scripts/recon.sh" "自サイトを第三者に数えない" \
  's = s.replace("s#[/:?\\#].*$##\x27 | tr", "s#[/?\\#].*$##\x27 | tr", 1).replace("[[ \"$h\" == \"$DOMAIN\" || \"$h\" == \"$FINAL_HOST\" ||", "[[ \"$h\" == \"$DOMAIN\" ||", 1)'
mutate "recon: DNS の無応答を値として読む（旧不具合）" "scripts/recon.sh" "タイムアウトの文言を値として出さない" \
  's = s.replace("dq() {\n  local type", "dq() { dig_ +short \"$1\" \"$2\"; return 0; }\ndq_old() {\n  local type", 1)'
mutate "recon: 親への遡りで無応答を「無い」とする" "scripts/recon.sh" "CAA は取得できないと言う" \
  's = s.replace("out=\"$(dq \"$type\" \"$prefix$d\")\" || return 2", "out=\"$(dq \"$type\" \"$prefix$d\")\" || return 1")'
mutate "recon: 到達できなくても判定を出す（旧不具合）" "scripts/recon.sh" "ヘッダを「無」と判定しない" \
  's = s.replace("if [[ $REACH -eq 1 ]]; then\n  hr \"1b.", "REACH=1; : > \"$WORK/hdr_final.txt\"\nif [[ $REACH -eq 1 ]]; then\n  hr \"1b.", 1)'
mutate "recon: Set-Cookie の値を出す（旧不具合）" "scripts/recon.sh" "Set-Cookie の値を出さない" \
  's = s.replace("print name \": \" cname \"=<伏字>\" rest", "print name \": \" val")'
mutate "recon: リダイレクトを追わない（旧不具合）" "scripts/recon.sh" "ヘッダを最終的な応答で判定する" \
  's = s.replace("meta=\"$(curl -sS -L --max-redirs", "meta=\"$(curl -sS --max-redirs")'
mutate "recon: 相対パスの JS を拾わない（旧不具合）" "scripts/recon.sh" "一重引用符・相対パスの JS を拾う" \
  's = s.replace("printf \x27%s/%s\\n\x27 \"${b%/*}\" \"${ref#./}\" ;;", ";;")'
mutate "recon: 一重引用符の src を拾わない（旧不具合）" "scripts/recon.sh" "一重引用符・相対パスの JS を拾う" \
  's = s.replace("(src|href)=[\\\"\x27][^\\\"\x27<> ]+\\.m?js", "(src|href)=[\\\"][^\\\"\x27<> ]+\\.m?js")'
mutate "recon: 計測タグを第三者スクリプトの中身でも数える（旧不具合）" "scripts/recon.sh" "第三者スクリプトの中身で LogRocket" \
  's = s.replace("url_refs own_only.js | tag_hosts_of >> tag_hosts.txt", "url_refs all.js | tag_hosts_of >> tag_hosts.txt")'
mutate "recon: LLM の鍵を見ない（旧不具合）" "scripts/recon.sh" "OpenAI の鍵を検出する" \
  's = s.replace("\x27OpenAI|sk-(proj|svcacct|admin)-", "\x27OpenAI|ZZZNOMATCH-")'
mutate "recon: SPF をホスト名で引く（旧不具合）" "scripts/recon.sh" "組織のドメインの SPF を見つける" \
  's = s.replace("if [[ -n \"$DMARC_AT\" ]]; then ORG=\"${DMARC_AT#_dmarc.}\"", "if [[ -n \"$DMARC_AT\" ]]; then ORG=\"$DOMAIN\"")'
mutate "recon: 重大な露出を 04 の優先度で言わない" "scripts/recon.sh" ".env の中身が取れれば P0 の候補と言う" \
  's = s.replace("P0NOTE=\"← 中身が返っている。P0 の候補。", "P0NOTE=\"← 中身が返っている。最優先。")'
if command -v node >/dev/null 2>&1; then
  mutate "recon: 既知タグの一覧を browser_probe とずらす" "scripts/recon.sh" "既知タグの一覧が一致する" \
    's = s.replace("  \x27Mouseflow|(^|\\.)mouseflow\\.com$\x27\n", "")'
else
  printf '  \033[33m-\033[0m recon の 1 件（node が無いため省略）\n'; SKIP=$((SKIP+1))
fi

mutate "recon: DMARC の連絡先を伏せない" "scripts/recon.sh" "DMARC の連絡先アドレスを出力に混ぜない" \
  's = s.replace("sed -E \x27s/mailto:[^,;[:space:]]+/mailto:<伏字>/g\x27", "cat")'

mutate "recon: DMARC の p= を部分一致に戻す（旧不具合）" "scripts/recon.sh" "sp=none を p=none と取り違えない" \
  's = s.replace("dp=\"$(dmarc_tag p \"$DMARC\")\"", "dp=\"$(printf %s \"$DMARC\" | grep -qi p=none && echo none)\"")'
mutate "recon: DS を頂点ではなくホスト名で引く（旧不具合）" "scripts/recon.sh" "頂点の DS を見つける" \
  's = s.replace("APEX=\"$(zone_apex)\"", "APEX=\"$DOMAIN\"")'
mutate "recon: 親ドメインへ遡らない（旧不具合）" "scripts/recon.sh" "サブドメインから親の DMARC を見つける" \
  's = s.replace("    d=\"${d#*.}\"\n", "    break\n")'
mutate "recon: curl の既定の名乗りで送る" "scripts/recon.sh" "curl の既定の名乗りで送らない" \
  's = s.replace("curl() { command curl -A \"$UA\" \"$@\"; }", "curl() { command curl \"$@\"; }")'
mutate "recon: 最初の応答が止められても言わない" "scripts/recon.sh" "最初の応答が止められたら、そう言う" \
  's = s.replace("  if is_blocked \"$code_final\"; then", "  if false; then")'
mutate "recon: 1c に .git/config を並べない" "scripts/recon.sh" ".git/config の中身が取れれば P0 の候補と言う" \
  's = s.replace("    \x27p0   /.git/config       ^\\[(core|remote|branch)\x27\n", "")'
mutate "recon: 1c に /actuator/env を並べない" "scripts/recon.sh" "/actuator/env の中身が取れれば内部の設定が見えると言う" \
  's = s.replace("    \x27info /actuator/env      \"(propertySources|activeProfiles)\"\x27\n", "")'
mutate "recon: 1c の 403 に注記を付けない" "scripts/recon.sh" "403 はファイルの有無を示さないと言う" \
  's = s.replace("elif is_blocked \"$code\"; then note=\"（※）\"; blocked_seen=1", "elif false; then :")'
mutate "recon: 4 節で a の href も数える（旧不具合）" "scripts/recon.sh" "<a> のリンク先を数えない" \
  's = s.replace("while ($a =~ /\\bsrc\\s*=", "while ($a =~ /\\b(?:src|href)\\s*=")'
mutate "recon: 4 節で link の rel を見ない" "scripts/recon.sh" "rel=canonical を数えない" \
  's = s.replace("print \"$1\\n\" if $rel =~ /(^|\\s)($rels)(\\s|$)/ && ", "print \"$1\\n\" if ")'
mutate "recon: URL の認証部を落とさない（旧不具合）" "scripts/recon.sh" "URL の認証部（DSN の鍵）を出さない" \
  's = s.replace("s#^([A-Za-z][A-Za-z0-9+.-]*://)[^/?\\#@]*@#\\1#; ", "")'
mutate "recon: 認証部の付いた URL を拾わない（旧不具合）" "scripts/recon.sh" "認証部の付いた URL（Sentry の DSN）でタグを拾う" \
  's = s.replace("//([^/@[:space:]", "//(ZZZNEVER[^/@[:space:]", 1)'
mutate "recon: ヘッダの制御文字を落とさない" "scripts/recon.sh" "端末の表示を書き換える並びを出さない" \
  's = s.replace("last_block() { strip_ctl < \"$1\" |", "last_block() { tr -d \x27\\r\x27 < \"$1\" |")'
mutate "recon: 見た JS の範囲を書かない" "scripts/recon.sh" "見た JS の範囲（遅延読み込みを含まない）を書く" \
  's = s.replace("echo \"      import() で後から読み込む分割されたファイル（管理画面用など）は含まない。鍵が無いと言えるのはこの範囲だけ。\"\n", "")'
mutate "recon: 鍵の表から Twilio を外す（scan_secrets とずれる）" "scripts/recon.sh" "recon\\[鍵\\]: 見本の鍵をすべて拾う" \
  's = s.replace("  \x27secret|Twilio|\\b(AC|SK)[0-9a-f]{32}\\b\x27\n", "")'
mutate "scan_secrets: npm の鍵を見ない（recon とずれる）" "scripts/scan_secrets.sh" "scan_secrets\\[鍵\\]: 見本の鍵をすべて拾う" \
  's = s.replace("|npm_[0-9A-Za-z]{30,})", ")")'

# ---- browser_probe（部品の検査。node があれば Playwright が無くても回る）----
if command -v node >/dev/null 2>&1; then
  mutate "browser_probe: 送信先を末尾で照合しない（旧不具合）" "scripts/browser_probe.mjs" "既知タグと同意管理のラベル付け" \
    's = s.replace("[\"Hotjar\", \"(^|\\\\.)hotjar\\\\.(com|io)$\"]", "[\"Hotjar\", \"hotjar\\\\.(com|io)\"]")'
  mutate "browser_probe: script-src-elem を script-src と取り違える（旧不具合）" "scripts/browser_probe.mjs" "CSP を実際に適用される指令で判定する" \
    's = s.replace("const name = tokens[0].toLowerCase();", "const name = tokens[0].toLowerCase().replace(/^script-src-(elem|attr)$/, \"script-src\");")'
  mutate "browser_probe: 評価対象に npm i -D させる（旧不具合）" "scripts/browser_probe.mjs" "評価対象の package.json を書き換える案内をしない" \
    's = s.replace("npm i --prefix \"$HOME/.cache/wsa-playwright\" playwright@${PW_VERSION}", "npm i -D playwright")'
  mutate "browser_probe: どこからでも読み込める配信元を見ない" "scripts/browser_probe.mjs" "CSP を実際に適用される指令で判定する" \
    's = s.replace("    return low.filter((x) => BROAD_SOURCES.includes(x));", "    return [];")'
  mutate "browser_probe: strict-dynamic があっても配信元の許可を咎める（誤検出）" "scripts/browser_probe.mjs" "CSP を実際に適用される指令で判定する" \
    's = s.replace("    if (low.includes(\"\x27strict-dynamic\x27\")) return [];\n", "")'
  mutate "browser_probe: 既知タグから LINE Tag を外す" "scripts/browser_probe.mjs" "既知タグと同意管理のラベル付け" \
    's = s.replace("  [\"LINE Tag\", \"^tr\\\\.line\\\\.me$|^d\\\\.line-scdn\\\\.net$\"],\n", "")'
else
  printf '  \033[33m-\033[0m browser_probe の部品の 6 件（node が無いため省略）\n'; SKIP=$((SKIP+6))
fi

# ---- browser_probe（Playwright がある環境でのみ）----
if node -e 'import("playwright")' >/dev/null 2>&1; then
  mutate "browser_probe: <meta> の CSP を読まない（旧不具合）" "scripts/browser_probe.mjs" "<meta> の CSP を読む" \
    's = s.replace("...metaCsp.filter((m) => m.equiv === \"content-security-policy\")", "...[].filter((m) => m.equiv === \"content-security-policy\")")'
  mutate "browser_probe: default-src へ遡らない（旧不具合）" "scripts/browser_probe.mjs" "script-src が無ければ default-src で判定" \
    's = s.replace("\"script-src\", \"default-src\"]", "\"script-src\"]")'
  mutate "browser_probe: nonce と並ぶ unsafe-inline を咎める（誤検出）" "scripts/browser_probe.mjs" "nonce と並ぶ unsafe-inline を咎めない" \
    's = s.replace("return { allowed: hasUI && !cancels, ignored: hasUI && cancels };", "return { allowed: hasUI, ignored: false };")'
  mutate "browser_probe: WebSocket を拾わない（旧不具合）" "scripts/browser_probe.mjs" "第三者への接続を拾う" \
    's = s.replace("page.on(\"websocket\", (ws) => {", "page.on(\"websocket-disabled\", (ws) => {")'
  mutate "browser_probe: WebSocket のクエリを伏せない" "scripts/browser_probe.mjs" "クエリのトークンを出さない" \
    's = s.replace("${x.search ? \"?…（クエリは伏字）\" : \"\"}", "${x.search}")'
  mutate "browser_probe: NODE_PATH の Playwright を探さない" "scripts/browser_probe.mjs" "NODE_PATH で渡した Playwright で動く" \
    's = s.replace("  try { return createRequire(import.meta.url)(\"playwright\"); } catch { /* 次へ */ }\n", "")'
  mutate "browser_probe: 保存領域の値を出力してしまう" "scripts/browser_probe.mjs" "Cookie と保存領域の値を出力しない" \
    's = s.replace("const pick = (s) => { try { return Object.keys(s); } catch { return []; } };", "const pick = (s) => { try { return Object.keys(s).map(k => k + \"=\" + s.getItem(k)); } catch { return []; } };")'
  mutate "browser_probe: HttpOnly の判定を反転する（誤検出）" "scripts/browser_probe.mjs" "HttpOnly のある Cookie を咎めない" \
    's = s.replace("c.httpOnly ? \"HttpOnly\" : \"**HttpOnly なし**\"", "!c.httpOnly ? \"HttpOnly\" : \"**HttpOnly なし**\"")'
  mutate "browser_probe: 既知タグのラベルを取り違える" "scripts/browser_probe.mjs" "既知タグと同意管理のラベル付け" \
    's = s.replace("[\"Microsoft Clarity\", \"(^|\\\\.)clarity", "[\"Hotjar\", \"(^|\\\\.)clarity")'
  mutate "browser_probe: 転送先を自サイトに含めない" "scripts/browser_probe.mjs" "転送先のホストを第三者と言わない" \
    's = s.replace("  try { own.add(new URL(page.url()).hostname); } catch { /* 同上 */ }\n", "")'
  mutate "browser_probe: コンソールの URL を伏せない" "scripts/browser_probe.mjs" "コンソールの URL のクエリを伏せる" \
    's = s.replace("cspViolations.push(maskUrls(t).slice(0, 200))", "cspViolations.push(t.slice(0, 200))")'
  mutate "browser_probe: 追加パスを渡された URL の下で開く（旧不具合）" "scripts/browser_probe.mjs" "渡された URL にパスがあってもサイトのルートから開く" \
    's = s.replace("const url = `${new URL(base).origin}${p.startsWith", "const url = `${base}${p.startsWith")'
  mutate "browser_probe: 通信が途切れなければ止まる（旧不具合）" "scripts/browser_probe.mjs" "通信が途切れないページでも Cookie の節を出す" \
    's = s.replace("if (e.name !== \"TimeoutError\" || !navRes) {", "if (true) {")'
  mutate "browser_probe: ボット対策で止められても言わない" "scripts/browser_probe.mjs" "ヘッドレスのブラウザが止められたら、そう言う" \
    's = s.replace("  if (BLOCKED.has(status)) {", "  if (false) {")'
  mutate "browser_probe: 保存領域のキー名の制御文字を落とさない" "scripts/browser_probe.mjs" "キー名の制御文字を落とす" \
    's = s.replace("console.log(`    ${clean(k)}${warn}`);", "console.log(`    ${k}${warn}`);")'
  mutate "browser_probe: Cookie の届く範囲を出さない（旧構成）" "scripts/browser_probe.mjs" "Cookie の届く範囲（ホストのみか・Path）を出す" \
    's = s.replace("        `Path=${c.path}`,\n", "")'
else
  # 件数は上の if の中の mutate の数と揃える（自己監査が README の件数と照合する）
  printf '  \033[33m-\033[0m browser_probe の 16 件（playwright が無いため省略）\n'; SKIP=$((SKIP+16))
fi

printf '\n\033[1m結果\033[0m  生きている検査 %d / 生きていない %d / 省略 %d\n' "$PASS" "$FAIL" "$SKIP"
[[ $SHARD_N -gt 0 ]] && printf '  ※ 分担 %d/%d。ほかの分担の変異 %d 件は、この回では実行していない\n' "$SHARD_K" "$SHARD_N" "$OUTSHARD"
if [[ $FAIL -gt 0 ]]; then
  echo "  「生きていない」検査は、通っていても何も確かめていない。検査か題材を直す。"
  exit 1
fi
