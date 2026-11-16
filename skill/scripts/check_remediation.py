#!/usr/bin/env python3
"""書き終えた修正指示書の、前提の順番と欄の抜けを確かめる。

    python check_remediation.py <修正指示書のディレクトリ（remediation/）>

修正指示書どおりに直させると、前提のタスクが後ろに並んでいて完了条件を満たせない、
答えを待つはずのタスクに手を付けて既存の機能を止める、同じファイルを変える 2 つのタスクの
確かめ方が食い違う、といったことが起きる（references/05-remediation-plan.md の「書き終えたら読み直す」）。
読み合わせは人かエージェントが行う。このスクリプトは、そのうち機械で拾えるものだけを出す。

見るもの:
  1. 前提に挙げたタスク（S-x・T-x など）が、そのタスクより後ろにある・どこにも無い
     （順番は、phase-<番号>.md の番号、ファイルの中では「順番:」の行があればその並び、無ければ見出しの並び）
  2. 完了条件・手順・検証の欄が無いタスク
  3. 実行者が AI で、前提に未確認事項（U-x）を挙げているのに、本文に「着手しない」が無いタスク
     （答えを待たずに実装させないため。05 の実行者区分）
  4. 同じファイルを対象に挙げたタスクの組（読み合わせる候補。終了コードには数えない）

タスクは「## [ID] 題」の見出しから次の「## 」の見出しまで。表の「前提」「実行者」「対象」の行を読む。

終了コード: 0 = 1〜3 が無い / 2 = 1〜3 のどれかがある / 1 = 使い方の誤り・読めない。
"""
import collections
import glob
import os
import re
import sys

ID = r"[A-Z]{1,2}-[0-9]{1,3}[a-z]?"
TASK_HEAD = re.compile(r"^## \[(" + ID + r")\]")
ID_REF = re.compile(r"(?<![A-Za-z0-9-])(" + ID + r")(?![0-9A-Za-z-])")
ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|\s*$")
ORDER_LINE = re.compile(r"^順番[:：]")
PATH = re.compile(r"`([^`\s]+?\.[A-Za-z0-9]{1,6})(?::[0-9][0-9,\-–〜]*)?`")
NEED = ("完了条件", "手順", "検証")
WAIT_WORD = "着手しない"


def phase_no(path):
    m = re.search(r"phase-([0-9]+)", os.path.basename(path))
    return int(m.group(1)) if m else None


def read_tasks(path):
    tasks, order, cur = [], None, None
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if order is None and ORDER_LINE.match(line) and "→" in line:
            order = ID_REF.findall(line)
        m = TASK_HEAD.match(line)
        if m:
            cur = {"id": m.group(1), "file": path, "rows": {}, "heads": set(), "body": []}
            tasks.append(cur)
            continue
        if line.startswith("## "):
            cur = None
            continue
        if cur is None:
            continue
        cur["body"].append(line)
        if line.startswith("### "):
            cur["heads"].add(line[4:].strip())
        r = ROW.match(line)
        if r and r.group(1) not in cur["rows"]:
            cur["rows"][r.group(1).strip("* ")] = r.group(2)
    return tasks, order


def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 1
    d = sys.argv[1]
    files = sorted(glob.glob(os.path.join(d, "phase-*.md")), key=lambda p: (phase_no(p) is None, phase_no(p) or 0, p))
    if not files:
        print(f"{d} に phase-<番号>.md が無い", file=sys.stderr)
        return 1
    pos, tasks = {}, []
    for f in files:
        ts, order = read_tasks(f)
        heads = [t["id"] for t in ts]
        seq = [i for i in (order or []) if i in heads] + [i for i in heads if i not in (order or [])]
        for t in ts:
            t["pos"] = (phase_no(f) or 0, seq.index(t["id"]))
            pos.setdefault(t["id"], t["pos"])
            tasks.append(t)
    ids = set(pos)

    def resolve(ref):
        """S-02 を前提に挙げ、タスクが S-02a・S-02b に分かれているなら、その全部"""
        if ref in ids:
            return [ref]
        return [i for i in ids if re.fullmatch(re.escape(ref) + r"[a-z]", i)]

    bad_order, missing, no_cols, no_wait = [], [], [], []
    for t in tasks:
        name = f"{t['id']}（{os.path.basename(t['file'])}）"
        pre = t["rows"].get("前提", "")
        refs = [r for r in ID_REF.findall(pre) if r != t["id"]]
        for r in refs:
            if r.startswith("U-"):
                continue
            got = resolve(r)
            if not got:
                missing.append(f"  {name}  前提の {r} が指示書のタスクに無い")
            for g in got:
                if pos[g] > t["pos"]:
                    where = os.path.basename([x for x in tasks if x["id"] == g][0]["file"])
                    bad_order.append(f"  {name}  前提の {g}（{where}）が後ろにある")
        lack = [h for h in NEED if not any(h in x for x in t["heads"])]
        if lack:
            no_cols.append(f"  {name}  {'・'.join(lack)} の欄が無い")
        runner = t["rows"].get("実行者", "")
        waits = [r for r in refs if r.startswith("U-")]
        # 実行者が AI か AI+人（人だけのタスクは、もともと AI が手を付けない）
        if waits and "AI" in runner and not any(WAIT_WORD in x for x in t["body"]):
            no_wait.append(f"  {name}  前提に {'・'.join(waits)} があるのに「{WAIT_WORD}」の一文が無い")

    by_file = collections.defaultdict(list)
    for t in tasks:
        for p in set(PATH.findall(t["rows"].get("対象", ""))):
            by_file[p].append(t["id"])
    shared = [(p, ts) for p, ts in sorted(by_file.items()) if len(ts) > 1]

    out = [("前提の順番", bad_order), ("前提のタスクが無い", missing), ("欄の抜け", no_cols), ("答えを待つ一文が無い", no_wait)]
    n = sum(len(x) for _, x in out)
    print(f"タスク {len(tasks)} 件（{len(files)} ファイル）。直すもの {n} 件")
    for title, rows in out:
        if rows:
            print(f"== {title}（{len(rows)} 件）")
            print("\n".join(rows))
    if shared:
        print(f"== 同じファイルを対象にしたタスク（{len(shared)} 組。確かめ方の値と、どちらの変更を残すかを読み合わせる）")
        for p, ts in shared:
            print(f"  {p}: {'・'.join(ts)}")
    return 2 if n else 0


if __name__ == "__main__":
    sys.exit(main())
