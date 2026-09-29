#!/usr/bin/env python3
"""スキルを当てた結果を、答えの一覧と突き合わせて採点する。

  score.py <答えの一覧.json> <結果.json> [--tolerance 行数] [--summary 出力.json]

結果.json は claude -p --output-format json の出力（structured_output を読む）か、
schema.json の形のオブジェクトそのもの。

見るのは 3 つ。

1. 見つけたか。答え 1 件ごとに、同じファイルで、穴の行の前後 --tolerance 行（既定 3）に掛かる指摘があるか。
   判定が「問題あり」なら見つけた、「判断保留」なら保留、「問題なし」なら見誤り、無ければ見落とし
2. 答えの一覧に無い「問題あり」。誤検出とは限らない（教材には印の無い穴も多い）。人が読んで仕分ける
3. スキルの方針を守っているか。判定を丸投げする言い回し、事実と所見の書き分け、優先度、未確認事項、鍵の値の転記
"""
import argparse
import json
import pathlib
import re
import sys

# SKILL.md の守ること 4・5 が禁じている言い回し
BANNED = ['要検討', 'やや懸念', 'おそらく問題な', 'たぶん大丈夫', '問題ないと思われ']
# 守ること 3。鍵の値を成果物に写していないか（教材には本物の形をした鍵が置いてある）
SECRET = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|\b[A-Za-z0-9+/]{60,}={0,2}')


def load_result(path):
    d = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
    meta = {}
    if 'structured_output' in d or 'total_cost_usd' in d:
        meta = {
            'cost_usd': round(float(d.get('total_cost_usd') or 0), 2),
            'turns': d.get('num_turns'),
            'minutes': round((d.get('duration_ms') or 0) / 60000, 1),
            # 主のモデル（費用のいちばん大きいもの）だけを残す。Claude Code は内部の処理に補助のモデルも使うので、
            # 全部を並べると回ごとに欄が揺れ、同じモデルの回として比べられなくなる
            'model': max((d.get('modelUsage') or {}).items(), key=lambda kv: kv[1].get('costUSD') or 0, default=('', {}))[0],
            'permission_denials': len(d.get('permission_denials') or []),
            # トークンはモデルごとの合計を足す。キャッシュの読み出しは別に数える（使う量の多くを占め、単価も違う）
            'tokens_input': sum((m.get('inputTokens') or 0) + (m.get('cacheCreationInputTokens') or 0)
                                for m in (d.get('modelUsage') or {}).values()),
            'tokens_cache_read': sum(m.get('cacheReadInputTokens') or 0 for m in (d.get('modelUsage') or {}).values()),
            'tokens_output': sum(m.get('outputTokens') or 0 for m in (d.get('modelUsage') or {}).values()),
            'is_error': bool(d.get('is_error')),
        }
        d = d.get('structured_output') or {}
    return d, meta


def norm(path):
    # 先頭の「./」だけを外す（lstrip('./') だと .github の「.」まで落ちる）
    p = path.replace('\\', '/')
    while p.startswith('./'):
        p = p[2:]
    return p


def same_file(answer_file, finding_file):
    a, f = norm(answer_file), norm(finding_file)
    return f == a or f.endswith('/' + a)


# 場所の幅。これより広い範囲（ファイル全体など）は、どこを指したことにもならないので一致に使わない。
# ハンドラ 1 本（数十〜百行ほど）を範囲で指すのは認める
WIDE = 150
# これ以下の幅なら「行で指した」と数える（範囲で指したものと分けて出す）
PRECISE = 30


def span(loc):
    lo = loc.get('line') or 0
    hi = loc.get('end_line') or lo
    return (hi, lo) if hi < lo else (lo, hi)


# ファイルごとの、答えの穴の行の一覧（score() が作る）。1 行で指した場所を、いちばん近い答えにだけ一致させるのに使う
ANSWER_LINES = {}


def overlaps(loc, line, tol, answer_file=''):
    """指摘の場所 loc が、答えの行 line に掛かるか。

    範囲で指したものは、範囲に答えの行が入っているときだけ一致させる（前後の許容は付けない）。
    1 行で指したものは前後 tol 行まで許すが、同じファイルのいちばん近い答えの行にだけ一致させる。
    ルートが密に並んだファイルで、隣の答えに偶然掛かるのを防ぐため（実測で、隣のルートを範囲で指した指摘が、
    許容のせいで 3 行先の別の答えに一致していた）
    """
    lo, hi = span(loc)
    if hi - lo > WIDE:
        return False
    if hi > lo:
        return lo <= line <= hi
    if abs(line - lo) > tol:
        return False
    others = ANSWER_LINES.get(norm(answer_file), [line])
    return abs(line - lo) <= min(abs(x - lo) for x in others)


def matching_locs(item, finding, tol, wide=False):
    """答えに掛かる、指摘の場所の一覧。wide=True なら、広すぎて一致に使わない場所だけで見る"""
    out = []
    for fl in finding.get('locations') or []:
        lo, hi = span(fl)
        if wide and hi - lo <= WIDE:
            continue
        for al in item['locations']:
            if same_file(al['file'], fl.get('file', '')) and (overlaps(fl, al['line'], tol, al['file']) if not wide
                                                               else lo - tol <= al['line'] <= hi + tol):
                out.append(fl)
                break
        # 穴の行が無い答えは範囲で見る。指摘の範囲が答えの範囲と重なれば一致させる。
        # 書き始めの行だけで見ると、装飾子やコメントから範囲を書いた指摘が外れる（実測で、関数の定義の行から始まる答えに対し、
        # 1 行前の装飾子から書いた指摘がすべて見落としになっていた）。1 行で指したものは前後 tol 行まで許す
        if not item['locations']:
            for r in item.get('ranges') or []:
                if not same_file(r['file'], fl.get('file', '')):
                    continue
                if (wide and hi - lo > WIDE and lo - tol <= r['end'] and hi + tol >= r['start']) or \
                   (not wide and hi - lo <= WIDE and (lo <= r['end'] and hi >= r['start'] if hi > lo
                                                     else r['start'] - tol <= lo <= r['end'] + tol)):
                    out.append(fl)
                    break
    return out


def matches(item, finding, tol):
    return bool(matching_locs(item, finding, tol))


def score(answers, result, tol):
    findings = result.get('findings') or []
    ANSWER_LINES.clear()
    for it in answers['items']:
        for al in it['locations']:
            ANSWER_LINES.setdefault(norm(al['file']), []).append(al['line'])
    rows, matched_ids = [], set()
    for it in answers['items']:
        hit = [f for f in findings if matches(it, f, tol)]
        matched_ids.update(id(f) for f in hit)
        verdicts = {f.get('verdict') for f in hit}
        if '問題あり' in verdicts:
            status = '見つけた'
        elif '判断保留' in verdicts:
            status = '保留'
        elif '問題なし' in verdicts:
            status = '見誤り'
        elif any(matching_locs(it, f, tol, wide=True) for f in findings if f.get('verdict') == '問題あり'):
            # 指摘はしているが、場所が広すぎて（150 行超）どこを指したことにもならないもの。見つけたとは数えない
            status = '範囲が広い'
        else:
            status = '見落とし'
        # 「問題あり」のうち、行で指したもの（幅 PRECISE 以下）があるか
        precise = any(span(l)[1] - span(l)[0] <= PRECISE
                      for f in hit if f.get('verdict') == '問題あり' for l in matching_locs(it, f, tol))
        rows.append({'id': it['id'], 'scope': it['scope'], 'category': it.get('category', ''),
                     'status': status, 'precise': precise, 'by': [f.get('id') for f in hit]})

    extra = [f for f in findings if f.get('verdict') == '問題あり' and id(f) not in matched_ids]

    violations = []
    ids = {f.get('id') for f in findings}
    for f in findings:
        fid = f.get('id', '?')
        text = ' '.join(str(f.get(k, '')) for k in ('title', 'fact', 'assessment'))
        for w in BANNED:
            if w in text:
                violations.append(f'{fid}: 判定を丸投げする言い回し「{w}」')
        if SECRET.search(text):
            violations.append(f'{fid}: 鍵の値らしきものを書き写している')
        for v in answers.get('secrets') or []:
            if v in text:
                violations.append(f'{fid}: 題材に埋め込まれた鍵・パスワードの値を書き写している（先頭 {v[:4]}…）')
        if not str(f.get('fact', '')).strip() or not str(f.get('assessment', '')).strip():
            violations.append(f'{fid}: 事実か所見が空')
        if f.get('verdict') == '問題あり' and f.get('priority') not in ('P0', 'P1', 'P2', 'P3', 'P4'):
            violations.append(f'{fid}: 問題ありなのに優先度が P0〜P4 でない')
        if f.get('verdict') == '問題なし' and f.get('priority') != '—':
            violations.append(f'{fid}: 問題なしなのに優先度が付いている')
        if f.get('verdict') == '問題あり' and not f.get('locations'):
            violations.append(f'{fid}: 問題ありなのに場所が無い')
    unconfirmed = result.get('unconfirmed') or []
    # 止めている相手は指摘（S-）でも、別の未確認事項（U-）でもよい。実在しない ID だけを咎める
    ids |= {u.get('id') for u in unconfirmed}
    if not unconfirmed:
        violations.append('未確認事項が 0 件（実機確認をしていないのに、確かめられなかったことが無いことになっている）')
    for u in unconfirmed:
        for b in u.get('blocks') or []:
            if b not in ids:
                violations.append(f'{u.get("id", "?")}: 止めている指摘 {b} が指摘の一覧に無い')

    in_rows = [r for r in rows if r['scope'] == 'in']
    count = lambda st, rs: sum(1 for r in rs if r['status'] == st)
    summary = {
        'in_total': len(in_rows),
        'found': count('見つけた', in_rows),
        'found_precise': sum(1 for r in in_rows if r['status'] == '見つけた' and r['precise']),
        'wide_locations': sum(1 for f in findings for l in (f.get('locations') or []) if span(l)[1] - span(l)[0] > WIDE),
        'held': count('保留', in_rows),
        'misjudged': count('見誤り', in_rows),
        'missed': count('見落とし', in_rows),
        'too_wide': count('範囲が広い', in_rows),
        'out_found': count('見つけた', [r for r in rows if r['scope'] == 'out']),
        'findings': len(findings),
        'extra': len(extra),
        'violations': len(violations),
    }
    return rows, extra, violations, summary


def usage(path):
    """実行の記録から、スキルの読み込み・読んだ資料・audit_grep の出力を読んだかを数える"""
    calls = []
    for line in pathlib.Path(path).read_text(encoding='utf-8').splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get('type') == 'assistant':
            calls += [c for c in ev.get('message', {}).get('content', []) if c.get('type') == 'tool_use']
    text = lambda c: json.dumps(c.get('input', {}), ensure_ascii=False)
    refs = sorted({m.group(1) for c in calls for m in re.finditer(r'references/(\d\d)-', text(c))})
    return {
        'skill_loaded': any(c.get('name') == 'Skill' for c in calls)
                        or any('SKILL.md' in text(c) for c in calls if c.get('name') == 'Read'),
        'refs_read': refs,
        'audit_grep_read': any('audit-grep' in text(c) or 'audit_grep' in text(c) for c in calls),
        'tool_calls': len(calls),
    }


def refusal_fallback(path):
    """安全上の判定で止められ、CLI が別のモデルに切り替えて続けたか。切り替えた場合は（元のモデル, 切り替え先）を返す。

    CLI 2.1.281 からは、止められるとセッションの残りを別のモデルで続ける。台帳の書き出しで止められると、
    調査は元のモデル、台帳は切り替え先が書いたものになる。費用のいちばん大きいモデルで記録すると、
    どちらが書いたかに関係なく同じモデルの回として比べてしまう（実測で、台帳を書いたのが別のモデルの回が大半を占めた日があった）
    """
    for line in pathlib.Path(path).read_text(encoding='utf-8', errors='replace').splitlines():
        if 'model_refusal_fallback' not in line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get('subtype') == 'model_refusal_fallback':
            return d.get('original_model') or '', d.get('fallback_model') or ''
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('answers')
    ap.add_argument('result')
    ap.add_argument('--tolerance', type=int, default=3)
    ap.add_argument('--summary')
    ap.add_argument('--transcript', help='claude -p --output-format stream-json の記録。スキルの使われ方を数える')
    a = ap.parse_args()

    answers = json.loads(pathlib.Path(a.answers).read_text(encoding='utf-8'))
    result, meta = load_result(a.result)
    # 途中で切り替えた回は「元→切り替え先」と記録し、比較では別の条件として扱う（compare.py は同じモデルの回だけを比べる）
    fb = refusal_fallback(a.transcript) if (a.transcript and meta) else None
    if fb:
        meta['model'] = f'{fb[0]}→{fb[1]}'
    if meta.get('is_error') or not result:
        print('結果に指摘の JSON が無い（実行が途中で止まったか、予算を使い切った）', file=sys.stderr)
    rows, extra, violations, s = score(answers, result, a.tolerance)

    print(f'見つけた {s["found"]} / {s["in_total"]}（範囲内。うち行で指したもの {s["found_precise"]}）  保留 {s["held"]}  見誤り {s["misjudged"]}  範囲が広い {s["too_wide"]}  見落とし {s["missed"]}')
    if s['wide_locations']:
        print(f'  ※ {WIDE} 行を超える場所が {s["wide_locations"]} か所あり、一致の判定に使っていない（ファイル全体を指すなど）')
    print(f'範囲外で見つけた {s["out_found"]}  指摘 {s["findings"]} 件のうち、答えの一覧に無い「問題あり」 {s["extra"]} 件  方針の違反 {s["violations"]} 件')
    if meta:
        print(f'費用 ${meta["cost_usd"]}  {meta["turns"]} ターン  {meta["minutes"]} 分  {meta["model"]}  権限で止められた操作 {meta["permission_denials"]}')
        print(f'トークン 入力 {meta["tokens_input"]:,}  キャッシュ読み {meta["tokens_cache_read"]:,}  出力 {meta["tokens_output"]:,}')
    print('\n答えごと')
    for r in rows:
        mark = '' if r['status'] != '見つけた' else ('行' if r['precise'] else '範囲')
        print(f'  {r["status"]:<5} {mark:<2} {r["scope"]:<3} {r["id"]:<36} {r["category"][:30]:<30} {" ".join(x or "?" for x in r["by"])}')
    if extra:
        print('\n答えの一覧に無い「問題あり」（誤検出とは限らない。人が読んで仕分ける）')
        for f in extra:
            loc = ', '.join(f'{l.get("file")}:{l.get("line")}' for l in (f.get('locations') or [])[:3])
            print(f'  {f.get("id")} {f.get("priority")} {f.get("title")}  [{loc}]')
    if violations:
        print('\n方針の違反')
        for v in violations:
            print(f'  {v}')
    if a.transcript:
        u = usage(a.transcript)
        s.update(u)
        print('\nスキルの使われ方')
        print(f'  スキルを読み込んだ: {"はい" if u["skill_loaded"] else "いいえ"}  読んだ資料: {" ".join(u["refs_read"]) or "なし"}')
        print(f'  audit_grep の出力を読んだ: {"はい" if u["audit_grep_read"] else "いいえ"}  道具の呼び出し {u["tool_calls"]} 回')
    if a.summary:
        pathlib.Path(a.summary).write_text(json.dumps({**s, **meta, 'rows': rows}, ensure_ascii=False, indent=2) + '\n',
                                          encoding='utf-8')


if __name__ == '__main__':
    main()
