#!/usr/bin/env bash
# 公開してはいけない語の一覧を、拡張正規表現の選択肢として 1 行 1 つ出す（大小を区別しない照合に使う）。
#
#   build/identifying-words.sh [リポジトリのルート]
#
# 語は手元の非公開のファイルからだけ集める。語そのものが案件や題材を特定する情報なので、リポジトリには入れない。
#   1. tests/ngwords.local            実案件を示す語（1 行 1 語または正規表現）
#   2. tests/eval/local/targets.tsv   実地の評価の題材。名前・取得元のリポジトリ名・owner/repo を、区切りの揺れ込みで取り出す
#   3. tests/eval/local/*.json        題材の表の name と secrets（題材に埋め込まれた値）
#   4. tests/eval/local/ngwords       題材を特定できるその他の語（特徴的なパスなど。任意）
# 4 文字未満の語は出さない（一般の語に当たりすぎる）。tests/run.sh・tests/self-audit.sh・build/hooks/pre-push が使う。
set -uo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
LOCAL="$ROOT/tests/eval/local"

# 語は grep -E の選択肢としてつなげて使う。正規表現として読めない行が 1 行でもあると、つないだ全体が誤りになり、
# 呼び出し側の 2>/dev/null の陰で照合が 1 つも行われない（すべて「一致なし」になる）。先に 1 行ずつ確かめて、読めなければ止める
words="$(python3 - "$ROOT" "$LOCAL" <<'PY'
import json, pathlib, re, sys
root, local = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
out = []

def regex_lines(path):
    if path.is_file():
        for l in path.read_text(encoding='utf-8').splitlines():
            if l.strip() and not l.lstrip().startswith('#'):
                out.append(l.strip())

def word(w):
    w = w.strip()
    if len(w) < 4:
        return
    # 区切り（- _ . 空白）の揺れを許す。example-app は "Example App" や "example_app" でも当てる
    parts = [re.escape(p) for p in re.split(r'[-_. ]+', w) if p]
    out.append('[-_. ]?'.join(parts) if len(parts) > 1 else re.escape(w))

regex_lines(root / 'tests/ngwords.local')
t = local / 'targets.tsv'
if t.is_file():
    for l in t.read_text(encoding='utf-8').splitlines():
        if not l.strip() or l.startswith('#'):
            continue
        cols = l.split('\t')
        word(cols[0])
        if len(cols) > 1:
            m = re.search(r'[:/]([^/:]+)/([^/]+?)(\.git)?/?$', cols[1])
            if m:
                out.append(re.escape(f'{m.group(1)}/{m.group(2)}'))
                word(m.group(2))
for j in sorted(local.glob('*.json')) if local.is_dir() else []:
    try:
        d = json.loads(j.read_text(encoding='utf-8'))
    except ValueError:
        continue
    if isinstance(d, dict):
        if d.get('name'):
            word(d['name'])
        for s in d.get('secrets', []):
            if len(s) >= 4:
                out.append(re.escape(s))
regex_lines(local / 'ngwords')
seen = set()
for w in out:
    if w not in seen:
        seen.add(w)
        print(w)
PY
)"
bad=0
while IFS= read -r w; do
  [[ -z "$w" ]] && continue
  printf '' | grep -E -- "$w" >/dev/null 2>&1; [[ $? -eq 2 ]] && bad=$((bad + 1))
done <<<"$words"
if [[ $bad -gt 0 ]]; then
  # 語そのものは出さない（案件や題材を特定する情報なので）
  echo "identifying-words: 正規表現として読めない行が ${bad} 行ある（tests/ngwords.local か tests/eval/local/ngwords を直す）" >&2
  exit 2
fi
[[ -n "$words" ]] && printf '%s\n' "$words"
exit 0
