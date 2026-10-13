#!/usr/bin/env python3
"""評価するエージェントが、答えの一覧の置き場に触れていないかを確かめる。

    leak_check.py <出力の置き場> <実行の記録（stream-json）>...

記録の中の道具の呼び出し（tool_use の入力）に、出力の置き場のパス（/var と /private/var のような別名の書き方でも）か、
答えの一覧のファイル名（answers.json）が出てきたら、その呼び出しを並べて 1 で終わる。出てこなければ 0。

run-eval.sh は許可で出力の置き場を読めなくしてある。これは、許可の書き方の誤りや CLI の変更で読めるようになったときに、
答えを見た回の数字を記録しないための確かめ。道具の結果は見ない（エージェントが自分で探さないかぎり、結果に出てこない）。
"""
import json
import os
import sys


def forms(path):
    """パスの書き方を並べる（macOS の /var・/tmp・/etc は /private の下の別名）。"""
    out = set()
    for p in (os.path.abspath(path), os.path.realpath(path)):
        out.add(p)
        if p.startswith('/private/'):
            out.add(p[len('/private'):])
        elif p.split('/')[1:2] in (['var'], ['tmp'], ['etc']):
            out.add('/private' + p)
    return sorted(out)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    out_dir, transcripts = sys.argv[1], sys.argv[2:]
    needles = [p.rstrip('/') for p in forms(out_dir)] + ['answers.json']
    hits = []
    for t in transcripts:
        with open(t, encoding='utf-8', errors='replace') as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get('type') != 'assistant':
                    continue
                for c in (e.get('message') or {}).get('content') or []:
                    if not isinstance(c, dict) or c.get('type') != 'tool_use' or c.get('name') == 'StructuredOutput':
                        continue
                    s = json.dumps(c.get('input'), ensure_ascii=False)
                    for n in needles:
                        if n in s:
                            hits.append(f'{os.path.basename(t)}: {c.get("name")} {s[:200]}')
                            break
    for h in hits:
        print(h)
    if hits:
        print(f'答えの一覧の置き場に触れた呼び出しが {len(hits)} 件ある')
        sys.exit(1)


if __name__ == '__main__':
    main()
