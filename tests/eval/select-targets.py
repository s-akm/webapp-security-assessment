#!/usr/bin/env python3
"""資料の変更から、版を上げる前に当てる題材を選ぶ（README の「版を上げる」の 1 の 2 つ目）。

  tests/eval/select-targets.py [--old <タグ|コミット>] [--answers <答えの一覧の置き場>]

前の版（既定は最新のタグ）から HEAD までに変えた skill/references と SKILL.md の行を、その行を含む節の観点（観点の網羅表の見出し）に直し、
その観点の答え（範囲内）を持つ題材を並べる。観点に結び付かない変更（判定の決まり・台帳・修正指示書・SKILL.md など）は「全体」とし、
固定の小さな組で確かめる。事前の洗い出し（scripts/audit_grep.sh）の変更は、出力の差で選ぶので tests/eval/grep-diff.sh を使う。
答えの一覧は tests/eval/local/answers/<題材>.json（run-eval.sh が前処理のたびに写す）。題材の名前は手元の出力にだけ出る。
"""
import argparse
import collections
import glob
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import coverage  # noqa: E402  観点の見出しと、答えから観点への振り分けを使い回す

# 資料のファイル → 観点の名前の作り方。02 は「## A.」の英字、07 は「## 7.」の番号を節として観点に直す。
# ほかの資料は資料ごとに 1 つの観点にまとめる。観点の網羅表に無い資料（01・03・04・05・06・09・11）は「全体」
SECTIONED = {"02-code-audit.md": "02", "07-web-vulnerabilities.md": "07"}
WHOLE = {"08-privacy-compliance.md": "08", "10-dependencies.md": "10", "12-ai-features.md": "12",
         "13-infrastructure.md": "13", "14-mobile.md": "14"}


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], check=True, capture_output=True, text=True).stdout


def changed_lines(old, path):
    """HEAD の側で変わった行の番号（足した行と、消した行の位置）"""
    out = git("diff", "-U0", f"{old}..HEAD", "--", path)
    lines = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", out, re.M):
        start, n = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
        lines.update(range(start, start + max(n, 1)))
    return lines


def section_of(text_lines, ln, prefix):
    """ln 行目を含む節の観点の名前（「02 A」「07 7」）。最初の節より前なら None"""
    pat = re.compile(r"^## ([A-Z])\. " if prefix == "02" else r"^## ([0-9]+)\. ")
    cur = None
    for i, l in enumerate(text_lines, start=1):
        if i > ln:
            break
        m = pat.match(l)
        if m:
            cur = f"{prefix} {m.group(1)}"
    return cur


def changed_viewpoints(old):
    files = [f for f in git("diff", "--name-only", f"{old}..HEAD", "--", "skill").split("\n") if f]
    vps = collections.Counter()
    whole, grep_changed = [], False
    for f in files:
        base = os.path.basename(f)
        if f == "skill/scripts/audit_grep.sh":
            grep_changed = True
        elif base in SECTIONED:
            text = git("show", f"HEAD:{f}").split("\n")
            for ln in changed_lines(old, f):
                v = section_of(text, ln, SECTIONED[base])
                if v:
                    vps[v] += 1
                else:
                    whole.append(f"{f}（節の前の部分）")
        elif base in WHOLE:
            vps[WHOLE[base]] += len(changed_lines(old, f))
        elif f.startswith("skill/references/") or f in ("skill/SKILL.md",) or f.startswith("skill/templates/"):
            whole.append(f)
    return vps, sorted(set(whole)), grep_changed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", default=None, help="比べる前の版（既定は最新のタグ）")
    ap.add_argument("--answers", default=coverage.DEFAULT_ANSWERS)
    a = ap.parse_args()
    old = a.old or git("describe", "--tags", "--abbrev=0", "HEAD").strip()
    vps, whole, grep_changed = changed_viewpoints(old)
    # 観点 → 題材 → 範囲内の答えの数
    by_vp = collections.defaultdict(collections.Counter)
    for p in sorted(glob.glob(os.path.join(a.answers, "*.json"))):
        target = os.path.splitext(os.path.basename(p))[0]
        for it in json.load(open(p, encoding="utf-8")).get("items") or []:
            if it.get("scope", "in") != "in" or it.get("control"):
                continue
            for v in coverage.category_viewpoints(it):
                by_vp[v][target] += 1
    print(f"比べる前の版: {old}")
    if not vps and not whole and not grep_changed:
        print("skill/ に変更が無い")
        return 0
    picked = collections.Counter()
    print("\n変えた観点と、その答えを持つ題材（題材: 範囲内の答えの数）:")
    for key, n in sorted(vps.items()):
        heads = coverage.vp(key)
        hits = collections.Counter()
        for h in heads:
            hits.update(by_vp.get(h, {}))
        names = "・".join(f"{t}: {c}" for t, c in hits.most_common()) or "（答えを持つ題材が無い。劣後なしとは言えない）"
        print(f"  {heads[0]}（変えた行 {n}）→ {names}")
        picked.update(hits)
    if whole:
        print("\n観点に結び付かない変更（固定の小さな組で確かめる）:")
        for f in whole:
            print(f"  {f}")
    if grep_changed:
        print("\nscripts/audit_grep.sh が変わった。出力の差の出る題材は tests/eval/grep-diff.sh --old " + old + " で選ぶ")
    if picked:
        print("\n当てる題材の候補（答えの数の多い順）: " + " ".join(t for t, _ in picked.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
