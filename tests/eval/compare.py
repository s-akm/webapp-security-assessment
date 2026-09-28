#!/usr/bin/env python3
"""版を上げる前に、候補が前の版に劣後していないかを、実地の評価の履歴で確かめる。

  tests/eval/compare.py [--new <版|コミット|タグ>] [--old <版|コミット|タグ>] [--min-runs 2] [--tolerance 2]

既定は、新 = 今の HEAD の skill/、旧 = いちばん新しい v タグの skill/。
履歴の行は「当てたスキルのコミットの skill/ の中身（git の木）」でまとめる。版を上げずに積んだ変更も、
中身が同じなら同じ候補として数え、評価の道具だけを直したコミットで当てた回も、同じ版として数える。
旧の版を当てていない題材は、その題材でいちばん新しく当てた別の中身を旧として使い、そのことを出す。

読むもの（手元の置き場。公開しない）:
  history.tsv  1 回 1 行（run-eval.sh --record が足す）
  items.tsv    1 回・1 項目 1 行（同上。項目ごとの見つけた・見落としを比べるのに使う）

劣後とみなすもの:
  - 新で違反が 1 件でもある
  - 新の見つけた数の平均が、旧の平均から --tolerance を超えて下がった
  - 旧で 2 回以上当ててすべて見つけた項目を、新で 2 回以上当てて 1 度も見つけなかった
終了コード: 0 = 劣後なし、1 = 劣後あり、3 = 新の回数が --min-runs に足りない題材がある（判定できない）
"""
import argparse
import csv
import os
import subprocess
import sys
from collections import OrderedDict, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read_tsv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f, delimiter='\t'))


_tree_cache = {}


def skill_tree(ref):
    """コミット・タグの skill/ の木。解けなければ None（書き換えで消えたコミットなど）"""
    if ref in _tree_cache:
        return _tree_cache[ref]
    try:
        out = subprocess.run(['git', '-C', ROOT, 'rev-parse', '--verify', '-q', f'{ref}^{{commit}}:skill'],
                             capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        out = ''
    _tree_cache[ref] = out or None
    return _tree_cache[ref]


def latest_tag():
    r = subprocess.run(['git', '-C', ROOT, 'describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*', 'HEAD'],
                       capture_output=True, text=True, check=False)
    return r.stdout.strip() or None


def group_key(row):
    """履歴の行をまとめる鍵。未コミットの変更を当てた回は、どの候補とも同じとみなさない"""
    commit = row.get('スキルのコミット', '')
    if '+' in commit:
        return None
    return skill_tree(commit) or f'commit:{commit}'


def resolve(sel, rows):
    """--new・--old の指定を、まとめる鍵の集合にする"""
    tree = skill_tree(sel)
    if tree:
        return {tree}
    keys = {group_key(r) for r in rows if r.get('スキルの版') == sel}
    keys.discard(None)
    return keys


def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--new', default='HEAD')
    ap.add_argument('--old', default=None)
    ap.add_argument('--min-runs', type=int, default=2)
    ap.add_argument('--tolerance', type=float, default=2.0)
    ap.add_argument('--local', default=os.environ.get('WSA_EVAL_LOCAL', os.path.join(ROOT, 'tests', 'eval', 'local')))
    a = ap.parse_args()

    hist = read_tsv(os.path.join(a.local, 'history.tsv'))
    items = read_tsv(os.path.join(a.local, 'items.tsv'))
    if not hist:
        sys.exit(f'履歴が無い: {a.local}/history.tsv')
    old_sel = a.old or latest_tag()
    new_keys = resolve(a.new, hist)
    old_keys = resolve(old_sel, hist) if old_sel else set()
    if not new_keys:
        sys.exit(f'新として指定したもの（{a.new}）を解けない')
    # 版を上げずに評価の道具だけを直したときなど、旧の版と新の skill/ が同じなら、その前に当てた中身と比べる
    same_as_old = bool(old_keys) and old_keys <= new_keys
    old_keys -= new_keys
    print(f'新: {a.new}　旧: {old_sel or "（タグが無い）"}')

    targets = list(OrderedDict.fromkeys(r['題材'] for r in hist))
    regress, short = [], []
    for t in targets:
        trows = [r for r in hist if r['題材'] == t]
        new = [r for r in trows if group_key(r) in new_keys]
        old = [r for r in trows if group_key(r) in old_keys]
        note = ''
        if not old:
            # 旧の版を当てていない題材は、その題材でいちばん新しく当てた別の中身を旧にする
            prev = [r for r in trows if group_key(r) not in new_keys and group_key(r) is not None]
            if prev:
                k = group_key(prev[-1])
                old = [r for r in prev if group_key(r) == k]
                why = '旧の版は新と中身が同じ' if same_as_old else '旧の版はこの題材で未評価'
                note = f'（{why}。代わりに {old[-1]["スキルの版"]}・{old[-1]["スキルのコミット"]} と比べる）'
        print(f'\n■ {t}{note}')
        if not new:
            print('  新: 未評価')
            short.append(t)
            continue

        def line(label, rs):
            f = [num(r['見つけた']) for r in rs]
            return (f'  {label}: {len(rs)} 回　見つけた {"・".join(str(int(x)) for x in f)}（平均 {mean(f):.1f} / {rs[0]["範囲内"]}）'
                    f'　見誤り 平均 {mean([num(r["見誤り"]) for r in rs]):.1f}'
                    f'　一覧外 平均 {mean([num(r["一覧外"]) for r in rs]):.1f}'
                    f'　違反 {int(sum(num(r["違反"]) for r in rs))}'
                    f'　費用 平均 {mean([num(r["費用（米ドル）"]) for r in rs]):.2f} 米ドル')
        if old:
            print(line('旧', old))
        print(line('新', new))

        bad = []
        if sum(num(r['違反']) for r in new) > 0:
            bad.append('新で違反がある')
        if old and mean([num(r['見つけた']) for r in new]) < mean([num(r['見つけた']) for r in old]) - a.tolerance:
            bad.append(f'見つけた数の平均が {a.tolerance:g} 件を超えて下がった')
        if len(new) < a.min_runs:
            short.append(t)
            print(f'  新の回数が {a.min_runs} 回に足りない')

        # 項目ごと。items.tsv の「実行」で 1 回を数える
        def per_item(keys):
            runs = defaultdict(set)
            found = defaultdict(set)
            for r in items:
                if r['題材'] != t or r.get('範囲') != 'in' or group_key(r) not in keys:
                    continue
                runs[r['項目']].add(r['実行'])
                if r['状態'] == '見つけた':
                    found[r['項目']].add(r['実行'])
            return runs, found
        if old:
            okeys = {group_key(old[0])}
            orun, ofound = per_item(okeys)
            nrun, nfound = per_item(new_keys)
            for iid in sorted(set(orun) & set(nrun)):
                on, of, nn, nf = len(orun[iid]), len(ofound[iid]), len(nrun[iid]), len(nfound[iid])
                if of == on and nf == 0:
                    msg = f'{iid}: 旧 {of}/{on} → 新 {nf}/{nn}'
                    if on >= 2 and nn >= 2:
                        bad.append(f'項目を見つけなくなった（{msg}）')
                    else:
                        print(f'  注意: 回数が少ないので劣後とはしない（{msg}）')
                elif of == 0 and nf == nn and nn:
                    print(f'  改善: {iid}: 旧 {of}/{on} → 新 {nf}/{nn}')
        for b in bad:
            print(f'  劣後: {b}')
        if bad:
            regress.append(t)

    print()
    if regress:
        print(f'劣後あり: {"・".join(regress)}')
        return 1
    if short:
        print(f'判定できない（新の評価が {a.min_runs} 回に足りない）: {"・".join(short)}')
        return 3
    print('劣後なし')
    return 0


if __name__ == '__main__':
    sys.exit(main())
