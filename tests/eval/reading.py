#!/usr/bin/env python3
"""評価の回の記録（transcript.jsonl）から、何をどれだけ読んだかを数える。

  tests/eval/reading.py <出力のディレクトリ>...        回ごとに 1 行
  tests/eval/reading.py --tsv <出力のディレクトリ>...  タブ区切りで出す

資料と事前の洗い出しを読む量が増えて、対象のコードを読む量が減っていないかを確かめるために使う（読む量が逆転するのは本末転倒）。
道具の結果（tool_result）の文字数を、読んだ先で 3 つに分ける。

  資料       スキルの置き場（.claude/skills/ の下）
  洗い出し   事前の洗い出しの出力とファイルの一覧（ws/evidence/ の下）
  コード     それ以外（対象の写し）

あわせて、ファイルの一覧（files.txt）のうち、Read で開いたか、Bash の命令に名前が出たファイルの割合を「開いた割合」として出す。
Bash の命令は、命令の文字列に出たパスで分ける（資料と洗い出しのどちらも含まなければコード）。grep のように複数のファイルを横断する命令は、
結果の文字数だけを数え、開いたファイルには数えない。
"""
import json
import os
import re
import sys


def classify(text):
    if '.claude/skills/' in text:
        return 'skill'
    if '/evidence/' in text:
        return 'evidence'
    return 'code'


def result_len(c):
    t = c.get('content')
    if isinstance(t, list):
        return sum(len(x.get('text', '')) for x in t if isinstance(x, dict))
    return len(t or '')


def measure(out):
    tr = os.path.join(out, 'transcript.jsonl')
    work = os.path.dirname(out.rstrip('/'))
    files_txt = os.path.join(work, 'ws', 'evidence', 'files.txt')
    files = [l.strip() for l in open(files_txt, encoding='utf-8')] if os.path.exists(files_txt) else []
    uses = {}
    size = {'skill': 0, 'evidence': 0, 'code': 0}
    calls = {'skill': 0, 'evidence': 0, 'code': 0}
    opened = set()
    for line in open(tr, encoding='utf-8'):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get('message') if isinstance(e, dict) else None
        if not isinstance(msg, dict):
            continue
        content = msg.get('content')
        for c in content if isinstance(content, list) else []:
            if not isinstance(c, dict):
                continue
            if c.get('type') == 'tool_use' and c.get('name') in ('Read', 'Bash', 'Grep', 'Glob'):
                inp = c.get('input') or {}
                target = inp.get('file_path') or inp.get('command') or inp.get('path') or inp.get('pattern') or ''
                uses[c['id']] = (c['name'], target)
            elif c.get('type') == 'tool_result' and c.get('tool_use_id') in uses:
                name, target = uses[c['tool_use_id']]
                k = classify(target)
                size[k] += result_len(c)
                calls[k] += 1
                if k == 'code' and files:
                    if name == 'Read':
                        for f in files:
                            if target.endswith('/' + f) or target == f:
                                opened.add(f)
                                break
                    elif name == 'Bash' and re.match(r'\s*(cat|sed|head|tail|nl|awk)\b', target):
                        for f in files:
                            if re.search(r'(^|[\s/\'"])' + re.escape(f) + r'($|[\s\'"])', target):
                                opened.add(f)
    total = sum(size.values()) or 1
    return {
        'out': out, 'skill': size['skill'], 'evidence': size['evidence'], 'code': size['code'],
        'skill_share': size['skill'] / total, 'code_share': size['code'] / total,
        'files': len(files), 'opened': len(opened), 'opened_share': (len(opened) / len(files)) if files else None,
        'calls': calls,
    }


def main(argv):
    tsv = False
    if argv and argv[0] == '--tsv':
        tsv, argv = True, argv[1:]
    if not argv:
        print(__doc__.strip().split('\n\n')[0])
        return 2
    if tsv:
        print('\t'.join(['出力', '資料（字）', '洗い出し（字）', 'コード（字）', 'コードの割合', 'ファイル数', '開いたファイル', '開いた割合']))
    for out in argv:
        if not os.path.exists(os.path.join(out, 'transcript.jsonl')):
            print(f'{out}: transcript.jsonl が無い', file=sys.stderr)
            continue
        m = measure(out)
        share = '' if m['opened_share'] is None else f"{m['opened_share']:.0%}"
        if tsv:
            print('\t'.join(map(str, [out, m['skill'], m['evidence'], m['code'], f"{m['code_share']:.0%}", m['files'], m['opened'], share])))
        else:
            print(f"{out}: 資料 {m['skill']:,} 字・洗い出し {m['evidence']:,} 字・コード {m['code']:,} 字（コードの割合 {m['code_share']:.0%}）"
                  f"・開いたファイル {m['opened']}/{m['files']}（{share}）")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
