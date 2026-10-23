#!/usr/bin/env bash
# 成果物（サマリ・台帳・修正指示書）の質を測る。run-eval.sh が台帳の JSON（指摘の場所と判定）しか測らないのを補う。
#
#   tests/eval/deliverable-eval.sh <題材> [--skill-ref <タグ|コミット>] [--no-skill] [--model <評価のモデル>] [--fixer-model <直す役のモデル>] [--record]
#   tests/eval/deliverable-eval.sh --judge-only <作業場所> [--record]   採点の段だけをやり直す（採点が途中で止まった回など）
#
# 3 段で測る。
#   1. 評価: スキルを置いた claude -p に、成果物を docs/security-assessment/ に作らせる（実機の確認はしない）
#   2. 修正: スキルを置かない別の claude -p に、成果物だけを渡して、修正指示書どおりにコードを直させる（依頼者の AI のコーディング支援の役）
#   3. 採点: 答えの一覧を持つ claude -p が、仕込んだ穴ごとに「指摘したか・直し方を書いたか・直ったか」と、
#      サマリと修正指示書の分かりやすさを採点する。あわせて、依頼者向けの文に内部の番号や記号が漏れていないかを機械で数える
# 題材の取得と前処理は run-eval.sh --prep-only に任せる。題材は答えの一覧に穴の中身（name）を持つものを使う。
# 外部のネットワークに出て費用がかかる（1 回 5〜15 米ドルほど）。CI では実行しない。
set -euo pipefail
{
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EVAL="$ROOT/tests/eval"; D="$EVAL/deliverable"
LOCAL="${WSA_EVAL_LOCAL:-$EVAL/local}"
MODEL="claude-opus-5-5"; FIXER_MODEL="claude-sonnet-5-5"; SKILL_REF=""; NO_SKILL=0; RECORD=0; TARGET=""; JUDGE_ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skill-ref) SKILL_REF="$2"; shift 2 ;;
    --no-skill) NO_SKILL=1; shift ;;
    --model) MODEL="$2"; shift 2 ;;
    --fixer-model) FIXER_MODEL="$2"; shift 2 ;;
    --record) RECORD=1; shift ;;
    --judge-only) JUDGE_ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done
CLAUDE_BIN="${WSA_CLAUDE_BIN:-claude}"
if [[ -n "$JUDGE_ONLY" ]]; then
  # 採点の段だけ。評価と修正の出力（out/・judge/）が残っている作業場所を渡す
  WORK="$(cd "$JUDGE_ONLY" && pwd)"; OUT="$WORK/out"; J="$WORK/judge"
  [[ -f "$J/fix.diff" && -d "$J/deliverables" ]] || { echo "採点の材料（$J の fix.diff と deliverables/）が無い" >&2; exit 2; }
  TARGET="$(head -1 "$OUT/target")"
  [[ -f "$OUT/judge.jsonl" ]] && mv "$OUT/judge.jsonl" "$OUT/judge-前回-$(date +%H%M%S).jsonl"
else
[[ -n "$TARGET" ]] || { sed -n '2,14p' "$0"; exit 2; }
line="$(grep -v '^#' "$LOCAL/targets.tsv" | awk -F'\t' -v t="$TARGET" '$1 == t' | head -1)"
[[ -n "$line" ]] || { echo "題材 $TARGET が targets.tsv に無い" >&2; exit 2; }
[[ -z "$(printf '%s' "$line" | cut -f7)" ]] || { echo "当てるディレクトリ（7 列目）を持つ題材には対応していない" >&2; exit 2; }

# 1. 題材の取得と前処理（スキルを置き、事前の洗い出しを実行するところまで）
prep_args=(--prep-only); [[ -n "$SKILL_REF" ]] && prep_args+=(--skill-ref "$SKILL_REF"); [[ "$NO_SKILL" -eq 1 ]] && prep_args+=(--no-skill)
prep_log="$("$EVAL/run-eval.sh" "$TARGET" "${prep_args[@]}")"; printf '%s\n' "$prep_log"
SRC="$(printf '%s\n' "$prep_log" | sed -n 's/^題材の前処理だけで止めた: \(.*\)（答えの一覧は .*/\1/p' | tail -1)"
[[ -d "$SRC" ]] || { echo "前処理の出力から題材の置き場を読めない" >&2; exit 2; }
WS="$(dirname "$SRC")"; WORK="$(dirname "$WS")"; OUT="$WORK/out"; J="$WORK/judge"
mkdir -p "$J"
# 直す前の写し（スキルの置き場は除く）
rsync -a --exclude '/.claude' "$SRC/" "$J/orig/"
cp "$OUT/answers.json" "$J/answers.json"

# 台帳の道具が使う openpyxl。評価の作業場所の外に仮想環境を 1 つ作って使い回す
BASE="$(dirname "$WORK")"; VENV="$BASE/venv-openpyxl"
[[ -x "$VENV/bin/python3" ]] || { python3 -m venv "$VENV" && "$VENV/bin/pip" install -q openpyxl; }
export PATH="$VENV/bin:$PATH"

out_real="$(cd "$OUT" && pwd -P)"; j_real="$(cd "$J" && pwd -P)"; src_real="$(cd "$SRC" && pwd -P)"
deny_out=("Read(/$OUT/**)" "Read(/$out_real/**)" "Read(/$J/**)" "Read(/$j_real/**)")

# 2. 評価
premise_file="$LOCAL/$(printf '%s' "$line" | cut -f6)"; [[ -f "$premise_file" && "$premise_file" != "$LOCAL/" ]] || premise_file="$LOCAL/premise/$TARGET.md"
notes=""
if [[ "$NO_SKILL" -eq 0 ]]; then
  notes="- webapp-security-assessment スキルに従って評価してください
- scripts/audit_grep.sh は実行済みで、出力は $WS/evidence/audit-grep.txt にある。実行し直さずに、これを読む
- スキルの版の確認（scripts/version_check.sh）は済ませてある。置いてある写しの版で進める"
fi
prompt="$(python3 -c 'import sys
t = open(sys.argv[1], encoding="utf-8").read()
t = t.replace("{{premise}}", open(sys.argv[2], encoding="utf-8").read().strip()).replace("{{files}}", sys.argv[3]).replace("{{skill_notes}}", sys.argv[4])
print(t, end="")' "$D/prompt-assess.md" "$premise_file" "$WS/evidence/files.txt" "$notes")"
printf '%s\n' "$prompt" > "$OUT/assess-prompt.txt"
echo "1/3 評価（モデル ${MODEL}。数十分かかる）"
( cd "$SRC" && "$CLAUDE_BIN" -p "$prompt" --output-format stream-json --verbose \
    --setting-sources project --strict-mcp-config --no-session-persistence --max-budget-usd 20 --model "$MODEL" \
    --add-dir "$WS" --permission-mode dontAsk \
    --allowedTools Skill "Bash(bash *audit_grep.sh*)" "Bash(python3 *make_register.py*)" "Bash(bash *scan_secrets.sh*)" "Bash(mkdir *)" \
      "Edit(/$SRC/docs/**)" "Write(/$SRC/docs/**)" "Edit(/$src_real/docs/**)" "Write(/$src_real/docs/**)" \
    --disallowedTools WebFetch WebSearch Agent NotebookEdit "${deny_out[@]}" ) > "$OUT/assess.jsonl" 2> "$OUT/assess.log" || echo "評価が 0 以外で終わった（$OUT/assess.log）"
DELIV="$SRC/docs/security-assessment"
[[ -f "$DELIV/README.md" ]] || { echo "成果物（$DELIV/README.md）が無い。採点しない。出力: $OUT" >&2; exit 1; }
mkdir -p "$J/deliverables"; rsync -a "$DELIV/" "$J/deliverables/"
python3 - "$J/deliverables" "$J/deliverables-xlsx.txt" <<'PY'
import glob, os, sys
import openpyxl
out = []
for p in sorted(glob.glob(os.path.join(sys.argv[1], '**', '*.xlsx'), recursive=True)):
    wb = openpyxl.load_workbook(p, data_only=True)
    for ws in wb.worksheets:
        out.append(f'### {os.path.basename(p)} / {ws.title}')
        for row in ws.iter_rows(values_only=True):
            cells = ['' if v is None else str(v) for v in row]
            if any(cells): out.append('\t'.join(cells).rstrip())
open(sys.argv[2], 'w', encoding='utf-8').write('\n'.join(out) + '\n')
PY

# 3. 修正（スキルを置かない、依頼者の AI のコーディング支援の役）
rsync -a "$J/orig/" "$J/fix/"
mkdir -p "$J/fix/docs"; rsync -a "$DELIV/" "$J/fix/docs/security-assessment/"
fix_real="$(cd "$J/fix" && pwd -P)"
echo "2/3 修正（モデル ${FIXER_MODEL}）"
( cd "$J/fix" && "$CLAUDE_BIN" -p "$(cat "$D/prompt-fix.md")" --output-format stream-json --verbose \
    --setting-sources project --strict-mcp-config --no-session-persistence --max-budget-usd 20 --model "$FIXER_MODEL" \
    --permission-mode dontAsk \
    --allowedTools "Edit(/$J/fix/**)" "Write(/$J/fix/**)" "Edit(/$fix_real/**)" "Write(/$fix_real/**)" "Bash(node --check *)" \
    --disallowedTools WebFetch WebSearch Agent NotebookEdit "Read(/$j_real/answers.json)" "Read(/$j_real/orig/**)" "Read(/$OUT/**)" "Read(/$out_real/**)" ) \
  > "$OUT/fix.jsonl" 2> "$OUT/fix.log" || echo "修正が 0 以外で終わった（$OUT/fix.log）"
python3 -c 'import json,sys
r=[json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.startswith("{")]
r=[e for e in r if e.get("type")=="result"]
open(sys.argv[2],"w",encoding="utf-8").write((r[-1].get("result") or "") if r else "（報告なし）")' "$OUT/fix.jsonl" "$J/fixer-report.txt" || true
( cd "$J" && diff -ruN -x docs orig fix > fix.diff ) || true
fi

# 4. 採点
echo "3/3 採点（モデル ${MODEL}）"
( cd "$J" && "$CLAUDE_BIN" -p "$(cat "$D/prompt-judge.md")" --output-format stream-json --verbose \
    --setting-sources project --strict-mcp-config --no-session-persistence --max-budget-usd 20 --model "$MODEL" \
    --json-schema "$(cat "$D/judge-schema.json")" --permission-mode dontAsk \
    --disallowedTools WebFetch WebSearch Agent NotebookEdit Write Edit ) > "$OUT/judge.jsonl" 2> "$OUT/judge.log" || echo "採点が 0 以外で終わった（$OUT/judge.log）"

# 5. まとめ（依頼者向けの文への内部の番号や記号の漏れは、機械で数える）
python3 - "$OUT" "$J" "$TARGET" "$([[ "$NO_SKILL" -eq 1 ]] && echo なし || cat "$OUT/skill_version")" "$(cat "$OUT/skill_commit")" "$MODEL" "$FIXER_MODEL" "$RECORD" "$LOCAL/deliverable-history.tsv" <<'PY'
import datetime, glob, json, os, re, sys
out, j, target, ver, commit, model, fmodel, record, hist = sys.argv[1:10]
def result(p):
    r = [json.loads(l) for l in open(p, encoding='utf-8') if l.startswith('{')]
    r = [e for e in r if e.get('type') == 'result']
    return r[-1] if r else {}
cost = sum((result(os.path.join(out, f)).get('total_cost_usd') or 0) for f in ('assess.jsonl', 'fix.jsonl', 'judge.jsonl'))
jr = result(os.path.join(out, 'judge.jsonl')).get('structured_output')
if not jr:
    sys.exit('採点の結果が無い。' + os.path.join(out, 'judge.log') + ' を見る')
# 採点の役が利用の上限などで読み切れなかった回は、数を使わない（--judge-only でやり直す）
if re.search(r'使用量の上限|利用の上限|usage limit', json.dumps(jr, ensure_ascii=False)):
    sys.exit('採点が途中で止まった（上限に触れている）。記録しない。--judge-only ' + os.path.dirname(out) + ' でやり直す')
answers = json.load(open(os.path.join(j, 'answers.json'), encoding='utf-8'))
in_ids = {it['id'] for it in answers.get('items') or [] if it.get('scope', 'in') == 'in' and not it.get('control')}
ctl_ids = {it['id'] for it in answers.get('items') or [] if it.get('scope', 'in') == 'in' and it.get('control')}
items = [x for x in jr['items'] if x['id'] in in_ids]
# 対照（正しく作ってある箇所）: 誤って問題として指摘した数と、直したことで壊した数
ctl = [x for x in jr['items'] if x['id'] in ctl_ids]
ctl_flagged = sum(1 for x in ctl if x['reported'])
ctl_broken = sum(1 for x in ctl if x['fixed'] == 'not_fixed')
n = len(in_ids)
rep = sum(1 for x in items if x['reported'])
conc = sum(1 for x in items if x['instructed'] == 'concrete')
human = sum(1 for x in items if x['fixed'] == 'human_task')
fixed = sum(1 for x in items if x['fixed'] == 'fixed') + 0.5 * sum(1 for x in items if x['fixed'] == 'partial')
# 依頼者向けの文（サマリと修正指示書）に出た内部の番号や記号。資料の番号・事前の洗い出しの節・道具の名前・内部の呼び名
LEAK = [r'★', r'(?<![0-9])(0[1-9]|1[0-4]) ?の ?([A-O](-\d+)?\b|\d+(-\d+)? ?節)', r'(?<![0-9])(0[1-9]|1[0-4]) [A-O][.．]', r'\b\d+[a-z]? ?節',
        r'audit_grep', r'make_register', r'scan_secrets', r'references/', r'SKILL\.md', r'モード ?[AB]\b', r'取材の ?[A-Z] ?群', r'守ること ?\d']
texts = {}
for p in [os.path.join(j, 'deliverables', 'README.md')] + sorted(glob.glob(os.path.join(j, 'deliverables', 'remediation', '*.md'))):
    if os.path.exists(p): texts[os.path.relpath(p, os.path.join(j, 'deliverables'))] = open(p, encoding='utf-8').read()
leaks = {k: sum(len(re.findall(pat, t)) for pat in LEAK) for k, t in texts.items()}
ss = {k: v['score'] for k, v in jr['summary_scores'].items()}
rs = {k: v['score'] for k, v in jr['remediation_scores'].items()}
s = {'target': target, 'skill_version': ver, 'skill_commit': commit, 'model': model, 'fixer_model': fmodel,
     'in_total': n, 'reported': rep, 'instructed_concrete': conc, 'human_task': human, 'fixed': fixed,
     'regressions': len(jr['regressions']), 'errors': len(jr['errors']),
     'controls': len(ctl_ids), 'controls_flagged': ctl_flagged, 'controls_broken': ctl_broken,
     'summary_scores': ss, 'remediation_scores': rs,
     'leaks_readme': leaks.get('README.md', 0), 'leaks_total': sum(leaks.values()),
     'chars_readme': len(texts.get('README.md', '')), 'chars_remediation': sum(len(t) for k, t in texts.items() if k != 'README.md'),
     'cost_usd': round(cost, 2)}
json.dump({**s, 'judge': jr, 'leaks_by_file': leaks}, open(os.path.join(out, 'deliverable-summary.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print(f"穴 {n} 件: 指摘 {rep}・具体的な直し方 {conc}・直った {fixed:g}（人の作業 {human}）・壊した {s['regressions']}・誤り {s['errors']}")
if ctl_ids: print(f"対照 {len(ctl_ids)} か所: 誤って指摘 {ctl_flagged}・直したことで壊した {ctl_broken}")
print('サマリ: ' + ' '.join(f'{k}={v}' for k, v in ss.items()) + f"  {s['chars_readme']} 字・漏れ {s['leaks_readme']}")
print('修正指示書: ' + ' '.join(f'{k}={v}' for k, v in rs.items()) + f"  {s['chars_remediation']} 字・漏れ（サマリを含む計） {s['leaks_total']}")
print(f"費用 {s['cost_usd']} 米ドル")
for x in items:
    if not x['reported'] or x['fixed'] in ('not_fixed', 'partial'):
        print(f"  {x['id']}: 指摘 {'有' if x['reported'] else '無'}・直し方 {x['instructed']}・{x['fixed']} — {x['reason'][:120]}")
if record == '1':
    head = ['日付', 'スキルの版', 'スキルのコミット', '題材', '評価のモデル', '直す役のモデル', '範囲内', '指摘', '具体的な直し方', '直った', '人の作業',
            '壊した', '誤り', '対照', '対照を誤って指摘', '対照を壊した', 'サマリ（危険・順序・専門語・量・質問）', '修正指示書（作業・確かめ・正しさ）', 'サマリの字数', '修正指示書の字数', '漏れ（サマリ）', '漏れ（計）', '費用（米ドル）', '出力']
    new = not os.path.exists(hist)
    with open(hist, 'a', encoding='utf-8') as f:
        if new: f.write('\t'.join(head) + '\n')
        f.write('\t'.join(map(str, [datetime.date.today().isoformat(), ver, commit, target, model, fmodel, n, rep, conc, f'{fixed:g}', human,
                                    s['regressions'], s['errors'], len(ctl_ids), ctl_flagged, ctl_broken, '/'.join(str(ss[k]) for k in ('danger', 'order', 'jargon', 'length', 'questions')),
                                    '/'.join(str(rs[k]) for k in ('actionable', 'verifiable', 'correctness')),
                                    s['chars_readme'], s['chars_remediation'], s['leaks_readme'], s['leaks_total'], s['cost_usd'], out])) + '\n')
    print(f'  {hist} に記録した')
PY
echo "出力: ${OUT}（採点の材料は ${J}）"
exit
}
