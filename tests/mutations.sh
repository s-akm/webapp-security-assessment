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
if printf '%s' "$base" | grep '✗' >/dev/null; then
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

  if printf '%s' "$out" | grep -E "✗ .*${expect}" >/dev/null; then
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
  if printf '%s' "$out" | grep -E "✗ .*実行権限: scan_secrets.sh" >/dev/null; then
    printf '  \033[32m✓\033[0m %-52s → 「%s」が落ちた\n' "スクリプトの実行権限を外す" "実行権限"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗\033[0m %-52s → 落ちなかった\n' "スクリプトの実行権限を外す"; FAIL=$((FAIL+1))
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
  's = s.replace("(cd \"$DIR\" && grep -rnoI \"${gopt[@]}\" -e \"$full\" . 2>/dev/null)", "grep -rnoI \"${gopt[@]}\" -e \"$full\" \"$DIR\" 2>/dev/null")'
mutate "scan_secrets: iconv を外す（日本語が壊れる）" "scripts/scan_secrets.sh" "日本語が壊れない" \
  's = s.replace("    iconv -c -f UTF-8 -t UTF-8 2>/dev/null\n", "    cat\n")'
mutate "scan_secrets: 検出した値をそのまま出す" "scripts/scan_secrets.sh" "検出した値を出さない" \
  's = s.replace("else v=\"$(mask_value \"$v\")\"; fi", "fi")'
mutate "scan_secrets: 拡張子で絞る（旧不具合）" "scripts/scan_secrets.sh" "scan_secrets\\[形式\\]: HAR の Authorization" \
  's = s.replace("grep -rnoI \"${gopt[@]}\"", "grep -rnoI --include=\x27*.md\x27 --include=\x27*.json\x27 \"${gopt[@]}\"")'
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
  's = s.replace("      *)    (cd \"$DIR\" && unzip -p \"$f\" \"$m\" 2>/dev/null) | xml_para_text > \"$out\" ;;", "      *)    (cd \"$DIR\" && unzip -p \"$f\" \"$m\" 2>/dev/null) | xml_text > \"$out\" ;;")'
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
  's = s.replace("\x27://(<伏字>|<[^>]+>(:<[^>]+>)?)@\x27", "\x27://<伏字>@\x27")'

mutate "scan_secrets: 差し込みの記法の接続文字列を値と取り違える" "scripts/scan_secrets.sh" "誤検出しない（日時・UUID・版・説明文）" \
  's = s.replace("|\\$\\{[^}]*\\}", "", 1)'

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
  's = s.replace("| grep -E \x27^(ref:|[0-9a-f]{40})\x27 >/dev/null", "| grep -Eq \x27^(ref:|[0-9a-f]{40})\x27", 1)'
mutate "資料: コマンド例でスクリプトの中の変数を使う" "references/02-code-audit.md" "スクリプトの中の変数に頼らない" \
  's = s.replace("grep -rnE --exclude-dir=node_modules --exclude-dir=vendor \x27Math", "grep -rnE \"${EX}\" \x27Math", 1)'
mutate "資料: grep のパターンを引用符の中で改行する" "references/14-mobile.md" "パターンを引用符の中で改行していない" \
  's = s.replace("evaluateJavascript\x27 \\\n  -e \x27javaScriptEnabled", "evaluateJavascript|\njavaScriptEnabled", 1)'

mutate "資料: 未確認事項が止める相手を ID で書くと決めない" "references/04-findings-register.md" "台帳にある ID で書くと決めている" \
  's = s.replace("。**台帳にある ID（S-x・U-x）だけを書く**。相手がまだ指摘になっていなければ、先に「判断保留」の指摘として載せる", "", 1)'
# ---- 実地の評価の道具（tests/eval/。mutate の対象は skill/ からの相対パスで渡す）----
mutate "eval: run-eval.sh を少しずつ読む" "../tests/eval/run-eval.sh" "run-eval.sh を実行の前に最後まで読み切る" \
  's = s.replace("\n{\n\nROOT=", "\n\nROOT=", 1).replace("\nexit\n}\n", "\n", 1)'
mutate "eval: 比較で違反を劣後としない" "../tests/eval/compare.py" "新で違反があれば劣後とする" \
  's = s.replace("        if sum(num(r[\x27違反\x27]) for r in new) > 0:", "        if False:", 1)'
mutate "eval: 比較で回数が足りなくても劣後なしと言う" "../tests/eval/compare.py" "新の回数が足りなければ「劣後なし」と言わない" \
  's = s.replace("    if short:\n", "    if False:\n", 1)'
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
mutate "eval: スキルを置いてから audit_grep を回す" "../tests/eval/run-eval.sh" "audit_grep をスキルを置く前に回す" \
  's = s.replace("# スキルを題材の中に置く。", "mkdir -p \"$SRC/.claude/skills\"; cp -R \"$ROOT/skill\" \"$SRC/.claude/skills/x\"\n# スキルを題材の中に置く。", 1).replace("EVID=\"$WORK/evidence\"; mkdir -p \"$EVID\"", "mkdir -p \"$SRC/.claude/skills\"; cp -R \"$ROOT/skill\" \"$SRC/.claude/skills/y\"\nEVID=\"$WORK/evidence\"; mkdir -p \"$EVID\"", 1)'
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
  's = s.replace("  [[ \"$st\" -eq 0 ]] && star_list < \"$ALL_OUT\"\n", "")'
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

# 手元の題材の変異（tests/eval/local/mutations.sh）。題材を特定できる情報を含むので公開しない。あるときだけ回す
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

# ---- browser_probe（部品の検査。node があれば Playwright が無くても回る）----
if command -v node >/dev/null 2>&1; then
  mutate "browser_probe: 送信先を末尾で照合しない（旧不具合）" "scripts/browser_probe.mjs" "既知タグのラベル付け" \
    's = s.replace("[\"Hotjar\", \"(^|\\\\.)hotjar\\\\.(com|io)$\"]", "[\"Hotjar\", \"hotjar\\\\.(com|io)\"]")'
  mutate "browser_probe: script-src-elem を script-src と取り違える（旧不具合）" "scripts/browser_probe.mjs" "CSP を実際に適用される指令で判定する" \
    's = s.replace("const name = tokens[0].toLowerCase();", "const name = tokens[0].toLowerCase().replace(/^script-src-(elem|attr)$/, \"script-src\");")'
  mutate "browser_probe: 評価対象に npm i -D させる（旧不具合）" "scripts/browser_probe.mjs" "評価対象の package.json を書き換える案内をしない" \
    's = s.replace("npm i --prefix \"$HOME/.cache/wsa-playwright\" playwright@${PW_VERSION}", "npm i -D playwright")'
else
  printf '  \033[33m-\033[0m browser_probe の部品の 3 件（node が無いため省略）\n'; SKIP=$((SKIP+3))
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
  mutate "browser_probe: 既知タグのラベルを取り違える" "scripts/browser_probe.mjs" "既知タグのラベル付け" \
    's = s.replace("[\"Microsoft Clarity\", \"(^|\\\\.)clarity", "[\"Hotjar\", \"(^|\\\\.)clarity")'
  mutate "browser_probe: 転送先を自サイトに含めない" "scripts/browser_probe.mjs" "転送先のホストを第三者と言わない" \
    's = s.replace("  try { own.add(new URL(page.url()).hostname); } catch { /* 同上 */ }\n", "")'
  mutate "browser_probe: コンソールの URL を伏せない" "scripts/browser_probe.mjs" "コンソールの URL のクエリを伏せる" \
    's = s.replace("cspViolations.push(maskUrls(t).slice(0, 200))", "cspViolations.push(t.slice(0, 200))")'
else
  # 件数は上の if の中の mutate の数と揃える（自己監査が README の件数と照合する）
  printf '  \033[33m-\033[0m browser_probe の 11 件（playwright が無いため省略）\n'; SKIP=$((SKIP+11))
fi

printf '\n\033[1m結果\033[0m  生きている検査 %d / 生きていない %d / 省略 %d\n' "$PASS" "$FAIL" "$SKIP"
if [[ $FAIL -gt 0 ]]; then
  echo "  「生きていない」検査は、通っていても何も確かめていない。検査か題材を直す。"
  exit 1
fi
