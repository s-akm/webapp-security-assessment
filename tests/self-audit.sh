#!/usr/bin/env bash
# self-audit.sh — スキルを配布する前の自己監査
#
#   使い方: tests/self-audit.sh [--full]
#
# 「動く」と「正しい」は別で、「正しい」と「配ってよい」も別になる。ここでは 4 段で見る。
#
#   1. 検査が通るか              tests/run.sh
#   2. 検査が生きているか        tests/mutations.sh（--full のときだけ。8 分かかる）
#   3. スキル自身が方針を守っているか
#        - 自分の道具（audit_grep / scan_secrets）を自分に当てる
#        - 「分からないことは分からないと書く」に反する曖昧語が無いか
#        - 作業メモ（TODO / FIXME / 要確認）が残っていないか
#   4. 配布物が正しいか
#        - VERSION と CHANGELOG の先頭が一致するか
#        - 配布物に cases/ が入っていないか
#        - 未コミットの変更が無いか
#
# 1 つでも赤があれば配らない。

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL="$ROOT/skill"
FULL=0; [[ "${1:-}" == "--full" ]] && FULL=1
RED=0
if [[ -e "$ROOT/tests/.mutating" ]]; then
  echo "tests/mutations.sh が実行中。skill/ に欠陥が入っている状態なので監査しない" >&2; exit 2
fi
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
ng()   { printf '  \033[31m✗\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '      %s\n' "$2"; RED=$((RED+1)); }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; [[ -n "${2:-}" ]] && printf '      %s\n' "$2"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# ==========================================================================
head_ "1. 検査が通るか"
out="$(bash "$ROOT/tests/run.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
res="$(printf '%s' "$out" | grep -oE '成功 [0-9]+ / 失敗 [0-9]+' | tail -1)"
if printf '%s' "$res" | grep -E '失敗 0$' >/dev/null; then ok "tests/run.sh: $res"
else ng "tests/run.sh: $res" "$(printf '%s' "$out" | grep -E '✗' | head -5 | tr '\n' ' ')"; fi

# ==========================================================================
head_ "2. 検査が生きているか"
if [[ $FULL -eq 1 ]]; then
  mout="$(bash "$ROOT/tests/mutations.sh" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
  mres="$(printf '%s' "$mout" | grep -oE '生きている検査 [0-9]+ / 生きていない [0-9]+' | tail -1)"
  if printf '%s' "$mres" | grep -E '生きていない 0' >/dev/null; then ok "tests/mutations.sh: $mres"
  else ng "tests/mutations.sh: $mres" "$(printf '%s' "$mout" | grep -E '✗|\?' | head -5 | tr '\n' ' ')"; fi
else
  warn "tests/mutations.sh は省略（--full で実行。8 分ほどかかる）" \
       "検査が「通る」ことと「壊れたときに落ちる」ことは別。配布前には一度は回す"
fi

# ==========================================================================
head_ "3. スキル自身が方針を守っているか"

# 3-1. 自分の道具を自分に当てる
ag="$(bash "$SKILL/scripts/audit_grep.sh" "$SKILL" 2>&1)"
# 資料と script は検出パターンそのものを説明として書いているので、そこに当たるのは想定内。
# 見るのは「実装コード（scripts/*.mjs / *.py）に、値として入っていないか」だけ。
for sec in "4. 秘密情報のハードコード" "13. 乱数と暗号" "14. 通信の保護"; do
  body="$(printf '%s' "$ag" | sed -n "/=== $sec/,/^=== [0-9]/p" \
          | grep -E '^\./scripts/[a-z_]+\.(mjs|py):' \
          | grep -vE "grep |'\\|\[/|TAGS|SUSPICIOUS|pattern|正規表現|#|//" || true)"
  if [[ -z "$body" ]]; then ok "audit_grep を自分に当てる: $sec → 実装コードに検出なし（説明文のパターンは除く）"
  else warn "audit_grep を自分に当てる: $sec" "$(printf '%s' "$body" | head -2 | cut -c1-120 | tr '\n' ' ')"; fi
done

ss="$(bash "$SKILL/scripts/scan_secrets.sh" "$SKILL" 2>&1)"
n="$(printf '%s' "$ss" | grep -cE '^\[検出\]' || true)"
if [[ "$n" -le 1 ]]; then ok "scan_secrets を自分に当てる: 検出 $n 種類（説明用の 1 件までは想定内）"
else ng "scan_secrets を自分に当てる: 検出 $n 種類" "$(printf '%s' "$ss" | grep -E '^\[検出\]' | tr '\n' ' ')"; fi

# 3-2. 判定を丸投げする表現。「分からないことは分からないと書く」「判定は 3 値」に反するもの。
#      資料の説明文で「〜かもしれない（だから確かめる）」と書くのは方針に反しないので、
#      報告書に書いてはいけない形（おそらく問題ない／たぶん大丈夫／やや懸念）だけを見る。
vague="$(grep -rnE 'おそらく問題な|たぶん大丈夫|多分大丈夫|やや懸念|要検討。|問題ないと思われ|安全と思われ' \
          "$SKILL"/SKILL.md "$SKILL"/references/*.md "$SKILL"/templates/*.md 2>/dev/null \
        | grep -vE '書かない|使わない|作らない|禁止|悪い例|は書けない|例:|と書けるか|を「未確認」|で止めない|ではなく' || true)"
if [[ -z "$vague" ]]; then ok "判定を丸投げする表現（おそらく問題ない／やや懸念）が、禁止の文脈以外に無い"
else ng "判定を丸投げする表現が残っている" "$(printf '%s' "$vague" | head -3 | cut -c1-120 | tr '\n' ' ')"; fi

# 3-3. 作業メモ
memo="$(grep -rnE '\bTODO\b|\bFIXME\b|\bTBD\b|仮置き|後で直す|あとで直す' \
          "$SKILL"/SKILL.md "$SKILL"/references/*.md "$SKILL"/templates/*.md 2>/dev/null \
        | grep -vE 'TODO: Supabase|TODO を|grep.*TODO|`TODO' || true)"
if [[ -z "$memo" ]]; then ok "作業メモ（TODO / FIXME / 要確認）が残っていない"
else ng "作業メモが残っている" "$(printf '%s' "$memo" | head -3 | cut -c1-120 | tr '\n' ' ')"; fi

# 3-4. 断定の根拠。「必ず」「絶対」が過剰でないか（数を見るだけ。多ければ読み返す）
n_must="$(grep -oE '必ず|絶対に' "$SKILL"/references/*.md | wc -l | tr -d ' ')"
if [[ "$n_must" -lt 80 ]]; then ok "強い断定（必ず／絶対に）は $n_must 箇所"
else warn "強い断定（必ず／絶対に）が $n_must 箇所" "多すぎると読み手が重みを判断できない。読み返す"; fi

# 3-5. README に書いた数値が実態と合っているか。手で書いた数は必ずずれる。
#      実際に「スクリプト 4 本」「52 の枠組み」が更新漏れで残っていた。
n_ref="$(ls "$SKILL"/references/*.md | wc -l | tr -d ' ')"
n_scr="$(ls "$SKILL"/scripts/* | wc -l | tr -d ' ')"
n_fix="$(ls -d "$ROOT"/tests/fixtures/repo* | wc -l | tr -d ' ')"
n_run="$(printf '%s' "$out" | grep -oE '成功 [0-9]+' | tail -1 | grep -oE '[0-9]+')"
n_mut="$(( $(grep -cE '^\s*mutate "' "$ROOT/tests/mutations.sh") + 1 ))"
mism=""
grep -qE "スクリプト ${n_scr} 本" "$ROOT/README.md" || mism="$mism スクリプト(実態${n_scr})"
grep -qE "${n_fix} の枠組みのダミー" "$ROOT/README.md" || mism="$mism 枠組み(実態${n_fix})"
grep -qE "検査本体（${n_run} 件）" "$ROOT/README.md" || mism="$mism 検査件数(実態${n_run})"
grep -qE "落ちるかを見る（${n_mut} 件）" "$ROOT/README.md" || mism="$mism ミューテーション(実態${n_mut})"
if [[ -z "$mism" ]]; then ok "README の数値が実態と一致（資料 ${n_ref} / スクリプト ${n_scr} / 枠組み ${n_fix} / 検査 ${n_run} / 変異 ${n_mut}）"
else ng "README の数値が実態とずれている" "${mism}"; fi

# ==========================================================================
head_ "4. 配布物が正しいか"

ver="$(tr -d ' \n' < "$ROOT/VERSION")"
chlog="$(grep -m1 -oE '^## \[[0-9.]+\]' "$ROOT/CHANGELOG.md" | tr -d '#[] ')"
if [[ "$ver" == "$chlog" ]]; then ok "VERSION（${ver}）と CHANGELOG の先頭（${chlog}）が一致"
else ng "VERSION（${ver}）と CHANGELOG の先頭（${chlog}）が違う" "どちらかを更新し忘れている"; fi

if [[ -f "$ROOT/dist/webapp-security-assessment-v$ver.skill" ]]; then
  if unzip -l "$ROOT/dist/webapp-security-assessment-v$ver.skill" | grep -E 'cases/|tests/|\.env' >/dev/null; then
    ng "配布物に cases/ tests/ .env が混入" "build.sh の除外を見直す"
  else ok "配布物（v${ver}）に cases/ tests/ が入っていない"; fi
else
  warn "配布物 dist/webapp-security-assessment-v$ver.skill が無い" "build/build.sh を回す"
fi

if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  dirty="$(git -C "$ROOT" status --short | grep -v '^??' | wc -l | tr -d ' ')"
  if [[ "$dirty" == "0" ]]; then ok "未コミットの変更が無い"
  else warn "未コミットの変更が $dirty 件" "配る前にコミットする"; fi
fi

# 基準の最終確認日
std="$(grep -oE 'standards-reviewed:[[:space:]]*[0-9-]+' "$SKILL/references/06-frameworks.md" | grep -oE '[0-9-]+$')"
days="$(python3 -c "import datetime,sys; print((datetime.date.today()-datetime.date.fromisoformat(sys.argv[1])).days)" "$std" 2>/dev/null || echo 0)"
if [[ "$days" -lt 180 ]]; then ok "基準の版の確認から $days 日（${std}）"
else warn "基準の版の確認から $days 日（${std}）" "半年を超えている。references/06 の表を一次情報で確かめる"; fi

# ==========================================================================
printf '\n\033[1m自己監査の結果\033[0m  '
if [[ $RED -eq 0 ]]; then printf '\033[32m赤なし。配布できる\033[0m'; [[ $FULL -eq 0 ]] && printf '（--full で検査の検査も回してから）'; printf '\n'
else printf '\033[31m赤 %d 件。配らない\033[0m\n' "$RED"; exit 1; fi
