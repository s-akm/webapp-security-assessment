#!/usr/bin/env bash
# 前の版と HEAD の事前の洗い出し（scripts/audit_grep.sh）を、前処理済みの題材の写しに当てて、出力の差を題材ごとに数える（費用なし）。
# README の「版を上げる」の 1 の 1 つ目（事前の洗い出しの出力が変わる題材を選ぶ）を道具にしたもの。
#
#   tests/eval/grep-diff.sh [--old <タグ|コミット>] [題材...]
#     既定の --old は最新のタグ。題材を省くと targets.tsv の全部。答えの無い題材（前処理の列が「-」）は除く
#
# 題材の取得と前処理は run-eval.sh --prep-only --no-skill に任せる（GitHub から題材を取るが、モデルは呼ばない）。
# 数えるのは ★ の一覧の件数と、見出し（=== …）・注記（※ …）を除いた行の増減。差の中身は作業場所の diff/<題材>.diff に残す。
# 見出しと注記だけの差は、当てる題材に数えない（README の決まり）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; EVAL="$ROOT/tests/eval"; LOCAL="${WSA_EVAL_LOCAL:-$EVAL/local}"
OLD=""; TARGETS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --old) OLD="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done
[[ -n "$OLD" ]] || OLD="$(git -C "$ROOT" describe --tags --abbrev=0 HEAD)"
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  while IFS=$'\t' read -r name _ _ _ prep _; do
    [[ -z "$name" || "$name" == \#* || "$prep" == "-" ]] && continue
    TARGETS+=("$name")
  done < "$LOCAL/targets.tsv"
fi
OUTD="${WSA_EVAL_DIR:-${TMPDIR:-/tmp}/wsa-eval}/grep-diff-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$OUTD/diff" "$OUTD/old"
git -C "$ROOT" archive "$OLD" skill/scripts/audit_grep.sh | tar -x -C "$OUTD/old"
OLD_AG="$OUTD/old/skill/scripts/audit_grep.sh"; NEW_AG="$ROOT/skill/scripts/audit_grep.sh"
# 見出し・注記・★ の一覧・スキルの版の行を除いた行（候補として並ぶ行）
body() { LC_ALL=C awk '/^=== ★ の一覧/ { exit } /^=== / { next } /^  スキルの版: / { next } /^  ※/ { n = 1; next } n && /^    [^ ]/ { next } { n = 0; print }' "$1"; }
stars() { LC_ALL=C sed -n 's/^=== ★ の一覧（\([0-9][0-9]*\) 件.*/\1/p' "$1" | tail -1; }
printf '前の版 %s と HEAD（%s）の事前の洗い出しの差。出力: %s\n\n' "$OLD" "$(git -C "$ROOT" rev-parse --short HEAD)" "$OUTD"
printf '%-22s %8s %8s %8s %8s  %s\n' "題材" "★ 前" "★ 後" "増えた行" "消えた行" "判定"
for t in "${TARGETS[@]}"; do
  line="$(grep -v '^#' "$LOCAL/targets.tsv" | awk -F'\t' -v t="$t" '$1 == t' | head -1)"
  [[ -n "$line" ]] || { printf '%-22s 題材が targets.tsv に無い\n' "$t"; continue; }
  sub="$(printf '%s' "$line" | cut -f7)"
  log="$("$EVAL/run-eval.sh" "$t" --prep-only --no-skill 2>&1)" || { printf '%-22s 前処理に失敗した\n' "$t"; continue; }
  src="$(printf '%s\n' "$log" | sed -n 's/^題材の前処理だけで止めた: \(.*\)（答えの一覧は .*/\1/p' | tail -1)"
  app="$src${sub:+/$sub}"
  ( cd "$app" && bash "$OLD_AG" . ) > "$OUTD/old/$t.txt" 2>&1 || true
  ( cd "$app" && bash "$NEW_AG" . ) > "$OUTD/$t.txt" 2>&1 || true
  diff <(body "$OUTD/old/$t.txt") <(body "$OUTD/$t.txt") > "$OUTD/diff/$t.diff" || true
  add="$(grep -c '^>' "$OUTD/diff/$t.diff" || true)"; del="$(grep -c '^<' "$OUTD/diff/$t.diff" || true)"
  so="$(stars "$OUTD/old/$t.txt")"; sn="$(stars "$OUTD/$t.txt")"
  verdict="差なし（当てなくてよい）"
  if [[ "$so" != "$sn" ]]; then verdict="★ が変わった（当てる）"
  elif [[ "$add" -gt 0 || "$del" -gt 0 ]]; then verdict="並ぶ行が変わった（中身を読んで決める）"; fi
  printf '%-22s %8s %8s %8s %8s  %s\n' "$t" "${so:-?}" "${sn:-?}" "$add" "$del" "$verdict"
done
