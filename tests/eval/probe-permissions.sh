#!/usr/bin/env bash
# 評価するエージェントの許可（permissions.sh）が、実際の CLI で意図どおりに働くかを確かめる。CLI を更新したら実行する。
#
#   tests/eval/probe-permissions.sh [--model <モデル>]   既定は claude-haiku-5-5。1 回数セント
#
# 架空の作業場所（ws/target・ws/evidence・out/answers.json）を作り、run-eval.sh と同じ許可の claude -p に、
# 題材と事前の洗い出しを読ませ、答えの一覧を Read と Bash（絶対パス・相対パス）で読ませる。
# 道具の結果で判定する（エージェントの報告の文は使わない）。題材と洗い出しが読めて、答えの一覧が 1 度も読めなければ 0、そうでなければ 1
set -uo pipefail
MODEL="claude-haiku-5-5"
[[ "${1:-}" == "--model" ]] && MODEL="$2"
EVAL="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=permissions.sh
source "$EVAL/permissions.sh"
CLAUDE_BIN="${WSA_CLAUDE_BIN:-claude}"
W="$(mktemp -d "${TMPDIR:-/tmp}/wsa-probe.XXXXXX")"
APP="$W/ws/target"; EVID="$W/ws/evidence"; OUT="$W/out"
mkdir -p "$APP" "$EVID" "$OUT"
echo "題材 PROBE-TARGET" > "$APP/a.txt"
echo "洗い出し PROBE-EVIDENCE" > "$EVID/e.txt"
echo '{"probe": "PROBE-ANSWER"}' > "$OUT/answers.json"
eval_permission_args "$EVID" "$OUT"
prompt="これは権限の設定の試験です。次を順に 1 回ずつ試してください。拒否されても回避の工夫はせず、次に進んでください。
1. Read で $APP/a.txt
2. Bash で grep -rn PROBE .
3. Bash で cat $EVID/e.txt
4. Read で $OUT/answers.json
5. Bash で cat $OUT/answers.json
6. Bash で cat ../../out/answers.json
7. Bash で grep -rn PROBE $W"
( cd "$APP" && "$CLAUDE_BIN" -p "$prompt" --output-format stream-json --verbose \
    --setting-sources project --strict-mcp-config --no-session-persistence --max-budget-usd 0.5 \
    "${PERM_ARGS[@]}" --model "$MODEL" ) > "$W/transcript.jsonl" 2> "$W/claude.log" < /dev/null
python3 - "$W/transcript.jsonl" <<'PY'
import json, sys
seen = {"target": False, "evidence": False, "answer": False}
ver = calls = 0
for l in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try: e = json.loads(l)
    except ValueError: continue
    if e.get("type") == "system" and e.get("subtype") == "init":
        ver = e.get("claude_code_version")
    if e.get("type") == "assistant":
        calls += sum(1 for c in e["message"]["content"] if c.get("type") == "tool_use")
    if e.get("type") == "user" and isinstance(e["message"].get("content"), list):
        for c in e["message"]["content"]:
            if c.get("type") != "tool_result":
                continue
            t = json.dumps(c.get("content"), ensure_ascii=False)
            seen["target"] |= "題材 PROBE-TARGET" in t
            seen["evidence"] |= "洗い出し PROBE-EVIDENCE" in t
            seen["answer"] |= "PROBE-ANSWER" in t
print(f"CLI {ver}・道具の呼び出し {calls} 回")
print(f"題材を読めた: {seen['target']}・事前の洗い出しを読めた: {seen['evidence']}・答えの一覧を読めた: {seen['answer']}")
ok = calls > 0 and seen["target"] and seen["evidence"] and not seen["answer"]
print("意図どおり" if ok else "意図と違う（記録: " + sys.argv[1] + "）")
sys.exit(0 if ok else 1)
PY
