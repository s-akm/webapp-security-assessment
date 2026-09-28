#!/usr/bin/env bash
# スキルを実際に当てて、見つけた割合と方針の遵守を測る。
#
#   tests/eval/run-eval.sh <題材> [--model <モデル>] [--budget <米ドル>] [--skill-ref <タグ|コミット>] [--record] [--prep-only]
#     既定は --model claude-opus-5-5 --budget 10。--skill-ref で、前の版の skill/ を当てる（新しいモデルで基準を作り直すとき）
#   tests/eval/run-eval.sh --score-only <出力のディレクトリ> [--record]
#
# 題材は手元の tests/eval/local/targets.tsv に書く（公開しない。書き方は tests/eval/README.md）。固定したコミットを取ってきて、
# 答えの一覧を取り出し、答えの手掛かりを消してから、スキルだけを読み込ませた claude -p に当てる。
#
# tests/run.sh と違い、外部のネットワークに出て（GitHub から題材を取る・モデルを呼ぶ）、費用がかかる。
# CI では実行しない。スキルの版を上げる前に手で実行し、--record で tests/eval/local/history.tsv に 1 行残す。
# 版を上げてよいかは tests/eval/compare.py で確かめる（全題材で 1 回ずつ当て、疑いのある題材だけもう 1 回）。
set -euo pipefail
# 全体を 1 つの { } に入れ、実行の前に最後まで読み切らせる。bash は長い処理の間もファイルの続きを読むので、
# 評価の実行中にこのファイルを直すと、ずれた位置から読んで壊れる（実測で、採点の手前で止まった）
{

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL="$ROOT/tests/eval"
# 題材ごとの情報（取得元・下拵え・前提・結果）は手元の置き場に置く。題材を特定できる情報を公開リポジトリに入れないため
LOCAL="${WSA_EVAL_LOCAL:-$EVAL/local}"
# 見落としを減らすため、知識の多いモデルで当てる。別名（opus）は CLI の版で指すモデルが変わり、比較が切れるので完全な ID で固定する
MODEL="claude-opus-5-5"; SKILL_REF=""; BUDGET=10; RECORD=0; PREP_ONLY=0; SCORE_ONLY=""; TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model) MODEL="$2"; shift 2 ;;
    --skill-ref) SKILL_REF="$2"; shift 2 ;;
    --budget) BUDGET="$2"; shift 2 ;;
    --record) RECORD=1; shift ;;
    --prep-only) PREP_ONLY=1; shift ;;
    --score-only) SCORE_ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done

# 採点して、求められれば履歴に 1 行足す
score_and_record() {
  local out="$1" target="$2" tcommit="$3"
  # 実行に失敗した回（結果の JSON が無い・エラーで終わった・台帳の中身が無い）は、採点も記録もしない。
  # 記録すると「見つけた 0・違反 1」の行が残り、版の比較を狂わせる（モデルの指定を CLI が知らず、12 回とも即座に失敗したのに記録していた）
  # 指摘が 0 件の回も同じ扱い。モデル側の安全上の判定で台帳の JSON の書き出しが途中で止められ、指摘 0 件で終わった回があった
  if ! python3 -c 'import json,sys
r=json.load(open(sys.argv[1], encoding="utf-8"))
sys.exit(0 if r and not r.get("is_error") and (r.get("structured_output") or {}).get("findings") else 1)' "$out/result.json" 2>/dev/null; then
    echo "実行が失敗した（結果が無いかエラー）。採点も記録もしない。$out/claude.log を見る" >&2
    tail -c 400 "$out/claude.log" 2>/dev/null >&2 || true
    return 1
  fi
  local tr=(); [[ -f "$out/transcript.jsonl" ]] && tr=(--transcript "$out/transcript.jsonl")
  python3 "$EVAL/score.py" "$out/answers.json" "$out/result.json" --summary "$out/summary.json" ${tr[@]+"${tr[@]}"} | tee "$out/report.txt"
  # 守ること 3: 結果に鍵の値や個人情報が混ざっていないか。スキル自身の検査で見る
  # （SQL の select * は、穴の説明で引用していれば出る。値の転記とは分けて読む）
  # JSON のままだと引用符が \" に変わり、報告書の本文なら一致する書き方（password: "…"）を取りこぼす。本文を平文にしてから見る
  mkdir -p "$out/scan"; rm -f "$out/scan/result.json"
  python3 -c 'import json,sys
r=json.load(open(sys.argv[1], encoding="utf-8")).get("structured_output") or {}
with open(sys.argv[2], "w", encoding="utf-8") as f:
    for k in ("findings", "unconfirmed", "maintain"):
        for x in r.get(k) or []:
            for v in x.values():
                if isinstance(v, str): f.write(v + "\n")' "$out/result.json" "$out/scan/result.txt"
  bash "$ROOT/skill/scripts/scan_secrets.sh" "$out/scan" > "$out/scan_secrets.txt" 2>&1 || true
  echo "秘密情報の検査: $(grep -E '^(検出なし|[0-9]+ 種類)' "$out/scan_secrets.txt" || echo '結果を読めない')（詳細は $out/scan_secrets.txt）"
  [[ "$RECORD" -eq 1 ]] || return 0
  # 答えの無い題材（実在の OSS に当てた監査）は、見つけた割合を測れないので履歴に入れない
  if [[ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1], encoding="utf-8")).get("items") or []))' "$out/answers.json")" == "0" ]]; then
    echo "  答えの無い題材なので、履歴には記録しない"; return 0
  fi
  # 版とコミットは、スキルを題材に写した時点で控えたものを使う（実行中に版を上げても、当てた版を記録する）
  local skill_version skill_commit
  skill_version="$(cat "$out/skill_version" 2>/dev/null || cat "$ROOT/VERSION")"
  skill_commit="$(cat "$out/skill_commit" 2>/dev/null || git -C "$ROOT" rev-parse --short HEAD)"
  [[ -f "$LOCAL/history.tsv" ]] || printf '日付\tスキルの版\tスキルのコミット\t題材\t題材のコミット\tモデル\t見つけた\tうち行で指した\t範囲内\t保留\t見誤り\t範囲が広い\t見落とし\t一覧外\t違反\t費用（米ドル）\t分\t入力トークン\tキャッシュ読みトークン\t出力トークン\n' > "$LOCAL/history.tsv"
  # 項目ごとの結果も 1 行ずつ残す（compare.py が、版の間で見つけなくなった項目を探すのに使う）
  [[ -f "$LOCAL/items.tsv" ]] || printf '日付\tスキルの版\tスキルのコミット\t題材\t実行\t項目\t範囲\t状態\tモデル\n' > "$LOCAL/items.tsv"
  python3 - "$out/summary.json" "$LOCAL/history.tsv" "$skill_version" "$skill_commit" "$target" "$tcommit" "$LOCAL/items.tsv" "$(basename "$(dirname "$out")")" <<'PY'
import datetime, json, sys
s = json.load(open(sys.argv[1], encoding='utf-8'))
with open(sys.argv[7], 'a', encoding='utf-8') as f:
    for r in s.get('rows', []):
        f.write('\t'.join([datetime.date.today().isoformat(), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[8],
                           r['id'], r['scope'], r['status'], s.get('model', '')]) + '\n')
row = [datetime.date.today().isoformat(), sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6][:12], s.get('model', ''),
       s['found'], s.get('found_precise', ''), s['in_total'], s['held'], s['misjudged'], s.get('too_wide', ''), s['missed'],
       s['extra'], s['violations'],
       s.get('cost_usd', ''), s.get('minutes', ''),
       s.get('tokens_input', ''), s.get('tokens_cache_read', ''), s.get('tokens_output', '')]
with open(sys.argv[2], 'a', encoding='utf-8') as f:
    f.write('\t'.join(map(str, row)) + '\n')
PY
  echo "  $LOCAL/history.tsv と items.tsv に記録した"
}

if [[ -n "$SCORE_ONLY" ]]; then
  [[ -f "$SCORE_ONLY/answers.json" && -f "$SCORE_ONLY/result.json" ]] || { echo "answers.json と result.json が $SCORE_ONLY に無い" >&2; exit 2; }
  score_and_record "$SCORE_ONLY" "$(cat "$SCORE_ONLY/target" 2>/dev/null || echo '?')" "$(cat "$SCORE_ONLY/target_commit" 2>/dev/null || echo '?')"
  exit 0
fi

[[ -n "$TARGET" ]] || { sed -n '2,13p' "$0"; exit 2; }
[[ -f "$LOCAL/targets.tsv" ]] || { echo "題材の一覧が無い: $LOCAL/targets.tsv（書き方は tests/eval/README.md）" >&2; exit 2; }
line="$(grep -v '^#' "$LOCAL/targets.tsv" | awk -F'\t' -v t="$TARGET" '$1 == t' | head -1)"
[[ -n "$line" ]] || { echo "題材 $TARGET が targets.tsv に無い" >&2; exit 2; }
REPO="$(printf '%s' "$line" | cut -f2)"; COMMIT="$(printf '%s' "$line" | cut -f3)"; PREP="$(printf '%s' "$line" | cut -f5)"
# 下拵えの列は「スクリプト名 [引数]」（例: prep_anchors.py 題材.json）。スクリプトは手元の置き場から探し、無ければ
# 公開の tests/eval/ から探す。引数の相対パスは手元の置き場から見る（下拵えは手元の置き場で動かす）
PREP_SCRIPT="${PREP%% *}"; PREP_ARGS="${PREP#"$PREP_SCRIPT"}"
if [[ -f "$LOCAL/$PREP_SCRIPT" ]]; then PREP_PATH="$LOCAL/$PREP_SCRIPT"; else PREP_PATH="$EVAL/$PREP_SCRIPT"; fi
# 前提の列（6 列目）。無ければ premise/<題材の名前>.md
PREMISE="$(printf '%s' "$line" | cut -f6)"; [[ -n "$PREMISE" ]] || PREMISE="premise/$TARGET.md"
# 当てるディレクトリ（7 列目）。モノレポは対象のアプリのディレクトリだけを渡す（SKILL.md の「スクリプト」）
SUBDIR="$(printf '%s' "$line" | cut -f7)"
# 下拵えの列が「-」なら、答えの無い題材（実在の OSS）。採点せず、指摘の一覧だけを出す
NO_ANSWERS=0; [[ "$PREP" == "-" ]] && NO_ANSWERS=1

# 作業場所はリポジトリの外。題材には本物の形をした鍵や穴のあるコードがあるので、リポジトリに混ぜない
BASE="${WSA_EVAL_DIR:-${TMPDIR:-/tmp}/wsa-eval}"
WORK="$BASE/$TARGET-$(date +%Y%m%d-%H%M%S)"
SRC="$WORK/target"; OUT="$WORK/out"
mkdir -p "$SRC" "$OUT"
printf '%s\n' "$TARGET" > "$OUT/target"; printf '%s\n' "$COMMIT" > "$OUT/target_commit"

echo "題材 $TARGET を取得する（$REPO @ ${COMMIT:0:12}）"
git -C "$SRC" init -q
git -C "$SRC" fetch -q --depth 1 "$REPO" "$COMMIT"
git -C "$SRC" -c advice.detachedHead=false checkout -q FETCH_HEAD
rm -rf "$SRC/.git"   # 履歴には修正のコミットと、その説明が残っている

# 題材の中のエージェント向けの設定を消す。残すと、評価の実行中に題材のフックや指示が読み込まれる
# （教材によっては、.claude/CLAUDE.md や独自のエージェント向けのスキルの置き場を持っている）
for p in .claude CLAUDE.md CLAUDE.local.md .mcp.json AGENTS.md .ai .cursor .cursorrules .codeium .continue .junie \
         .windsurfrules .clinerules .github/copilot-instructions.md .gemini GEMINI.md; do
  rm -rf "${SRC:?}/$p"
done
# モノレポでは下の階層にも置かれる（当てるディレクトリの CLAUDE.md や AGENTS.md は、その場で読み込まれる）
find "$SRC" \( -name node_modules -prune \) -o \( -type f \( -name CLAUDE.md -o -name CLAUDE.local.md -o -name AGENTS.md -o -name GEMINI.md \
  -o -name .cursorrules -o -name .windsurfrules -o -name .clinerules -o -name .mcp.json \) -print \) | while IFS= read -r f; do rm -f "$f"; done
find "$SRC" \( -name node_modules -prune \) -o \( -type d \( -name .claude -o -name .cursor -o -name .gemini -o -name .junie \) -print \) \
  | while IFS= read -r d; do rm -rf "$d"; done
APP="$SRC${SUBDIR:+/$SUBDIR}"
[[ -d "$APP" ]] || { echo "当てるディレクトリが無い: $SUBDIR" >&2; exit 2; }

if [[ "$NO_ANSWERS" -eq 1 ]]; then
  echo "答えの無い題材（採点しない）"
  printf '{"items": [], "secrets": []}\n' > "$OUT/answers.json"
else
  echo "答えの一覧を取り出し、手掛かりを消す"
  # shellcheck disable=SC2086  # 引数は targets.tsv に書いた語。分けて渡す
  ( cd "$LOCAL" && python3 -B "$PREP_PATH" $PREP_ARGS "$SRC" "$OUT/answers.json" )
fi

# audit_grep.sh は先に回して、出力を読ませる。エージェントに回させると、変数やパイプを組み合わせたコマンドになり、
# 許可の条件（読むことと audit_grep.sh の単独の呼び出し）に合わず止められる（初回の実測で 3 回止められ、1 度も回らなかった）。
# 出力の置き場は題材の外で、答えの一覧（$OUT）とも分ける。スキルを題材の中に置く前に回す
# （後に回すと、スキル自身のファイルまで監査の対象に混ざる。2.20.1 までの実測で recon.sh の行が出ていた）
EVID="$WORK/evidence"; mkdir -p "$EVID"
# 当てるスキル。--skill-ref なら、その版の skill/ と VERSION を git から取り出す（下拵えの audit_grep.sh もその版のものを使う）
SKILL_SRC="$ROOT/skill"; SKILL_VERSION_FILE="$ROOT/VERSION"
if [[ -n "$SKILL_REF" ]]; then
  mkdir -p "$WORK/skill-ref"
  git -C "$ROOT" archive "$SKILL_REF" skill VERSION | tar -x -C "$WORK/skill-ref"
  SKILL_SRC="$WORK/skill-ref/skill"; SKILL_VERSION_FILE="$WORK/skill-ref/VERSION"
fi
( cd "$APP" && bash "$SKILL_SRC/scripts/audit_grep.sh" . ) > "$EVID/audit-grep.txt" 2>&1 || true
echo "audit_grep.sh を先に回した（$(wc -l < "$EVID/audit-grep.txt" | tr -d ' ') 行）"

# スキルを題材の中に置く。--setting-sources project で、利用者の手元の設定・スキル・CLAUDE.md は読まない
mkdir -p "$APP/.claude/skills"
cp -R "$SKILL_SRC" "$APP/.claude/skills/webapp-security-assessment"
# 当てるスキルの版とコミットを、写した時点で控える（記録に使う）
cat "$SKILL_VERSION_FILE" > "$OUT/skill_version"
# 行をつなぐのに paste -sd '' は使わない（macOS の paste は区切りを空にできず、失敗して評価が始まらない）
if [[ -n "$SKILL_REF" ]]; then git -C "$ROOT" rev-parse --short "$SKILL_REF^{commit}" | tr -d '\n' > "$OUT/skill_commit"
else { git -C "$ROOT" rev-parse --short HEAD; git -C "$ROOT" diff --quiet HEAD -- skill || echo "+未コミット"; } | tr -d '\n' > "$OUT/skill_commit"; fi


if [[ "$PREP_ONLY" -eq 1 ]]; then
  echo "下拵えだけで止めた: ${SRC}（答えの一覧は ${OUT}/answers.json）"
  exit 0
fi

# 使う claude の実行ファイル。手元の CLI が新しいモデルを知らないときは、WSA_CLAUDE_BIN で新しい版を指す
CLAUDE_BIN="${WSA_CLAUDE_BIN:-claude}"
command -v "$CLAUDE_BIN" >/dev/null || { echo "claude が無い: $CLAUDE_BIN" >&2; exit 2; }
echo "スキルを当てる（モデル ${MODEL}、予算 \$${BUDGET}。数十分かかる）"
# 指示の「前提」は題材ごとのファイル（手元の置き場）から差し込む
premise_file="$LOCAL/$PREMISE"
[[ -f "$premise_file" ]] || { echo "前提のファイルが無い: $premise_file" >&2; exit 2; }
prompt="$(python3 -c 'import sys
t = open(sys.argv[1], encoding="utf-8").read().replace("{{premise}}\n", open(sys.argv[2], encoding="utf-8").read()).replace("{{audit_grep}}", sys.argv[3])
if sys.argv[4] == "1":
    # 答えの無い題材は教材ではない。冒頭の 1 行だけを差し替える
    t = "このディレクトリは、オープンソースで公開されているソフトウェアのリポジトリを、評価のために手元へ写したものです。\n" + t.split("\n", 1)[1]
print(t, end="")' "$EVAL/prompt.md" "$premise_file" "$EVID/audit-grep.txt" "$NO_ANSWERS")"
printf '%s\n' "$prompt" > "$OUT/prompt.txt"
args=(-p "$prompt"
  --output-format stream-json --verbose --json-schema "$(cat "$EVAL/schema.json")"
  --add-dir "$EVID"
  --setting-sources project --strict-mcp-config --no-session-persistence
  --max-budget-usd "$BUDGET"
  --permission-mode dontAsk
  # 読むこととスキルの下拵えのスクリプトだけを許す。書き込み・ネットワーク・下位のエージェントは止める
  --allowedTools Read Grep Glob Skill
    "Bash(bash *audit_grep.sh*)" "Bash(grep *)" "Bash(ls *)" "Bash(wc *)" "Bash(head *)" "Bash(sed -n *)" "Bash(cat *)"
  --disallowedTools WebFetch WebSearch Write Edit NotebookEdit Agent)
args+=(--model "$MODEL")
# 実行の記録（stream-json）を残し、最後の result の行を採点に使う。記録からスキルの使われ方も数える
( cd "$APP" && "$CLAUDE_BIN" "${args[@]}" ) > "$OUT/transcript.jsonl" 2> "$OUT/claude.log" || echo "claude が 0 以外で終わった（$OUT/claude.log）"
python3 -c 'import json,sys
r=[]
for l in open(sys.argv[1], encoding="utf-8"):
    try: e=json.loads(l)
    except ValueError: continue
    if e.get("type")=="result": r.append(e)
json.dump(r[-1] if r else {}, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False)' "$OUT/transcript.jsonl" "$OUT/result.json"

score_and_record "$OUT" "$TARGET" "$COMMIT" || { echo "出力: $OUT"; exit 1; }
echo "出力: $OUT"
exit
}
