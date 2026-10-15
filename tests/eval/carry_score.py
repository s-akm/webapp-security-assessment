#!/usr/bin/env python3
"""再評価の回（run-eval.sh --previous）で、前回の ID の引き継ぎを数える。

    python3 tests/eval/carry_score.py <前回の台帳.json> <今回の result.json> [--out <carry.json>]

前回の台帳は、前回の回の result.json の structured_output（findings・unconfirmed）を写したもの。
数えるのは、前回にあって今回に無い ID（消えた）と、同じ ID なのに中身が大きく違うもの（番号の使い回し）と、
引き継いだ ID に行き先が書かれていないもの。行き先は、評価の指示どおり本文（指摘は題か事実、未確認事項は本文）に書く。
指摘は 解消・未着手・部分対応・再発・未確認、未確認事項は 確定・未確認のまま・取り下げ のどれかと、根拠（「根拠」の語）があるかを見る
（11 と 04 の決まり。台帳の xlsx では未確認事項の行き先の列を carry_check.py が見る）。
中身の比べ方は skill/scripts/carry_check.py の overlap をそのまま使う（台帳の xlsx の確かめと同じ基準にする）。

見つけた割合（score.py）とは別に出す。history.tsv には足さず、版の比較（compare.py）にも混ぜない。
終了コード: 0 = 消えた ID も使い回しも行き先の書き漏れも無い / 2 = どれかがある / 1 = 読めない。
"""
import argparse
import importlib.util
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_overlap():
    p = os.path.join(ROOT, "skill", "scripts", "carry_check.py")
    # skill/ の中に __pycache__ を作らない（配布物の検査がスクリプトの数を数え違える。CI で実際に起きた）
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("carry_check", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # openpyxl は load() の中でだけ読み込むので、ここでは要らない
    return mod.overlap


def rows(register):
    """ID → 比べる文。指摘は題と事実、未確認事項は本文"""
    out = {}
    for f in register.get("findings") or []:
        if f.get("id"):
            out[f["id"].strip()] = " ".join(str(f.get(k) or "") for k in ("title", "fact"))
    for u in register.get("unconfirmed") or []:
        if u.get("id"):
            out[u["id"].strip()] = str(u.get("text") or "")
    return out


DEST_FINDING = re.compile(r"解消|未着手|部分対応|再発|未確認")
DEST_UNCONFIRMED = re.compile(r"行き先[:：]?\s*(確定|未確認のまま|取り下げ)")


def no_destination(register):
    """行き先の書かれていない ID（指摘と未確認事項）"""
    out = []
    for f in register.get("findings") or []:
        t = " ".join(str(f.get(k) or "") for k in ("title", "fact"))
        if f.get("id") and not DEST_FINDING.search(t):
            out.append(f["id"].strip())
    for u in register.get("unconfirmed") or []:
        t = str(u.get("text") or "")
        if u.get("id") and not (DEST_UNCONFIRMED.search(t) and "根拠" in t):
            out.append(u["id"].strip())
    return set(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("previous")
    ap.add_argument("result")
    ap.add_argument("--out")
    a = ap.parse_args()
    try:
        prev = json.load(open(a.previous, encoding="utf-8"))
        res = json.load(open(a.result, encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"読めない: {e}", file=sys.stderr)
        raise SystemExit(1)
    cur = res.get("structured_output") or res
    overlap = load_overlap()
    p, c = rows(prev), rows(cur)
    missing = sorted(set(p) - set(c))
    reused = sorted(i for i in set(p) & set(c) if overlap(p[i], c[i]) < 0.2)
    nodest = sorted((set(p) & set(c)) & no_destination(cur))
    summary = {"previous": len(p), "current": len(c), "missing": missing, "reused": reused,
               "carried": len(set(p) & set(c)) - len(reused), "no_destination": nodest}
    print(f"=== 前回の ID の引き継ぎ（前回 {len(p)} 件・今回 {len(c)} 件）===")
    print(f"  引き継いだ: {summary['carried']} 件")
    print(f"  消えた: {len(missing)} 件 {' '.join(missing)}")
    print(f"  同じ番号を別の意味に使った: {len(reused)} 件 {' '.join(reused)}")
    print(f"  引き継いだのに行き先が無い: {len(nodest)} 件 {' '.join(nodest)}")
    if a.out:
        json.dump(summary, open(a.out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    raise SystemExit(2 if missing or reused or nodest else 0)


if __name__ == "__main__":
    main()
