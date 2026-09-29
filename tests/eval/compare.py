#!/usr/bin/env python3
"""版を上げる前に、候補が前の版に劣後していないかを、実地の評価の履歴で確かめる。

  tests/eval/compare.py [--new <版|コミット|タグ>] [--old <版|コミット|タグ>] [--tolerance 2]

既定は、新 = 今の HEAD の skill/、旧 = いちばん新しい v タグの skill/。
履歴の行は「当てたスキルのコミットの skill/ の中身（git の木）」でまとめる。版を上げずに積んだ変更も、
中身が同じなら同じ候補として数え、評価の道具だけを直したコミットで当てた回も、同じ版として数える。
旧の版を当てていない題材は、その題材でいちばん新しく当てた別の中身を旧として使い、そのことを出す。
**旧は、新と同じモデルで当てた回だけを使う。** モデルが違う回しか無ければ、それと比べたうえで、版の差とモデルの差が
混ざっていることを出す（版の良し悪しの判定には使わない）。

読むもの（手元の置き場。公開しない）:
  history.tsv  1 回 1 行（run-eval.sh --record が足す）
  items.tsv    1 回・1 項目 1 行（同上。項目ごとの見つけた・見落としを比べるのに使う）

題材ごとに 1 回ずつ当て、疑いのある題材だけをもう 1 回当てる。疑いは次の 3 つ:
  - 1 回あたりの違反の数が、旧より増えた
  - 見つけた数の平均が、旧の平均から --tolerance を超えて下がった
  - 旧ですべての回で見つけた項目を、新で 1 度も見つけなかった
新が 1 回だけなら「要再確認」、2 回以上でも疑いが残れば「劣後」とする（旧が 1 回だけの項目の抜けは「注意」にとどめる）。
違反が出た回は、劣後でなくても原因を調べて CHANGELOG に残す。

終了コード: 0 = 劣後なし、1 = 劣後あり、3 = 要再確認か未評価の題材がある（もう 1 回当ててから判定する）
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
    # 未コミットの skill/ で当てた回は、どの版の中身か決まらないので比べない。黙って落とすと回数が足りない理由が分からない
    n_dirty = sum(1 for r in hist if group_key(r) is None)
    if n_dirty:
        print(f'  ※ 未コミットの skill/ で当てた回が {n_dirty} 回あり、比較から外した（コミットしてから当て直す）')

    targets = list(OrderedDict.fromkeys(r['題材'] for r in hist))
    regress, recheck, unevaluated, mixed, uncompared = [], [], [], [], []

    def compare_group(t, trows, new):
        """新の回のうち、同じモデルの条件の回（new）を旧と比べる。判定（regress・recheck・mixed・ok）と、同じ条件の旧があったかを返す"""
        verdict = 'ok'
        models = {r['モデル'] for r in new}
        # 旧は、新と同じモデルで当てた回だけ。無ければ別のモデルの回と比べ、判定には使わない
        cands = [r for r in trows if group_key(r) not in new_keys and group_key(r) is not None]
        same_model = [r for r in cands if r['モデル'] in models]
        pool = same_model or cands
        old = [r for r in pool if group_key(r) in old_keys]
        note = ''
        if not old and pool:
            k = group_key(pool[-1])
            old = [r for r in pool if group_key(r) == k]
            why = '旧の版は新と中身が同じ' if same_as_old else '旧の版はこの題材で未評価'
            note = f'（{why}。代わりに {old[-1]["スキルの版"]}・{old[-1]["スキルのコミット"]} と比べる）'
        model_differs = bool(old) and not same_model
        if note:
            print(f'  {note}')
        if model_differs:
            print(f'  ※ 旧は別のモデル（{"・".join(sorted({r["モデル"] for r in old}))}）で当てた回しか無い。'
                  f'版の差とモデルの差が混ざるので、劣後の判定には使わない')

        def line(label, rs):
            f = [num(r['見つけた']) for r in rs]
            return (f'  {label}: {len(rs)} 回（{"・".join(sorted({r["モデル"] for r in rs}))}）　'
                    f'見つけた {"・".join(str(int(x)) for x in f)}（平均 {mean(f):.1f} / {rs[0]["範囲内"]}）'
                    f'　見誤り 平均 {mean([num(r["見誤り"]) for r in rs]):.1f}'
                    f'　一覧外 平均 {mean([num(r["一覧外"]) for r in rs]):.1f}'
                    f'　違反 {"・".join(str(int(num(r["違反"]))) for r in rs)}'
                    f'　費用 平均 {mean([num(r["費用（米ドル）"]) for r in rs]):.2f} 米ドル')
        if old:
            print(line('旧', old))
        print(line('新', new))
        # 答えの数（分母）が旧と新で違えば、答えの一覧か下拵えが変わっている。見つけた数をそのまま比べない
        dens = {r['範囲内'] for r in old} | {r['範囲内'] for r in new}
        if old and len(dens) > 1:
            print(f'  注意: 答えの数が旧と新で違う（{"・".join(sorted(dens))}）。答えの一覧を揃えて当て直すまで判定しない')
            return 'recheck', False

        doubts = []
        if any(num(r['違反']) for r in new):
            print('  注意: 違反が出た回がある。原因を調べて CHANGELOG に残す')
        if old:
            if mean([num(r['違反']) for r in new]) > mean([num(r['違反']) for r in old]):
                doubts.append('1 回あたりの違反の数が旧より増えた')
            if mean([num(r['見つけた']) for r in new]) < mean([num(r['見つけた']) for r in old]) - a.tolerance:
                doubts.append(f'見つけた数の平均が {a.tolerance:g} 件を超えて下がった')

            # 項目ごと。items.tsv の「実行」で 1 回を数え、モデルも揃える
            def per_item(keys, model_set):
                runs, found = defaultdict(set), defaultdict(set)
                for r in items:
                    if r['題材'] != t or r.get('範囲') != 'in' or group_key(r) not in keys:
                        continue
                    if model_set and r.get('モデル', '') not in model_set:
                        continue
                    runs[r['項目']].add(r['実行'])
                    if r['状態'] == '見つけた':
                        found[r['項目']].add(r['実行'])
                return runs, found
            orun, ofound = per_item({group_key(old[0])}, {x['モデル'] for x in old})
            nrun, nfound = per_item(new_keys, models)
            for iid in sorted(set(orun) & set(nrun)):
                on, of, nn, nf = len(orun[iid]), len(ofound[iid]), len(nrun[iid]), len(nfound[iid])
                msg = f'{iid}: 旧 {of}/{on} → 新 {nf}/{nn}'
                if of == on and nf == 0:
                    if on >= 2 or nn < 2:
                        doubts.append(f'項目を見つけなくなった（{msg}）')
                    else:
                        print(f'  注意: 旧が 1 回だけなので劣後とはしない（{msg}）')
                elif of == 0 and nf == nn and nn:
                    print(f'  改善: {msg}')

        if doubts and model_differs:
            for d in doubts:
                print(f'  参考: {d}（モデルが違うので判定しない）')
            verdict = 'mixed'
        elif doubts and len(new) < 2:
            for d in doubts:
                print(f'  要再確認: {d}（新が 1 回だけ。もう 1 回当てて判定する）')
            verdict = 'recheck'
        elif doubts:
            for d in doubts:
                print(f'  劣後: {d}')
            verdict = 'regress'

        return verdict, bool(old) and not model_differs

    for t in targets:
        trows = [r for r in hist if r['題材'] == t]
        new_all = [r for r in trows if group_key(r) in new_keys]
        print(f'\n■ {t}')
        if not new_all:
            print('  新: 未評価')
            unevaluated.append(t)
            continue
        # 新の回を、モデルの条件ごとに分けて比べる。安全上の判定で止められて途中から別のモデルが台帳を書いた回
        # （「元→切り替え先」）は、元のモデルだけの回と条件が違うので混ぜない。元のモデルだけの回を先に出す
        conds = sorted({r['モデル'] for r in new_all}, key=lambda m: ('→' in m, m))
        verdicts, compared = [], False
        for m in conds:
            if len(conds) > 1:
                print(f'  ［{m}］')
            v, c = compare_group(t, trows, [r for r in new_all if r['モデル'] == m])
            verdicts.append(v); compared = compared or c
        if 'regress' in verdicts:
            regress.append(t)
        elif 'recheck' in verdicts:
            recheck.append(t)
        elif not compared:
            # どの条件でも同じ条件の旧が無ければ、版の比較になっていない。劣後なしとは言えない
            uncompared.append(t)
        elif 'mixed' in verdicts:
            mixed.append(t)

    print()
    if regress:
        print(f'劣後あり: {"・".join(regress)}')
        return 1
    if recheck or unevaluated or uncompared:
        if recheck:
            print(f'要再確認（もう 1 回当てる）: {"・".join(recheck)}')
        if uncompared:
            print(f'同じ条件の旧が無い（新か旧を、同じモデルの条件でもう 1 回当てる）: {"・".join(uncompared)}')
        if unevaluated:
            print(f'未評価: {"・".join(unevaluated)}')
        return 3
    if mixed:
        print(f'劣後なし（ただし {"・".join(mixed)} は旧が別のモデルなので、版の比較にはなっていない）')
    else:
        print('劣後なし')
    return 0


if __name__ == '__main__':
    sys.exit(main())
