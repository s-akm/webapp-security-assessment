#!/usr/bin/env python3
"""観点の網羅表を作る。スキルの観点ごとに、どれだけの根拠で測れているかを数える。

  tests/eval/coverage.py <run.sh の出力> [--answers <答えの一覧の置き場>] [--unmeasured]

根拠は 2 種類。
  スクリプトの検査      tests/run.sh の検査のうち、その観点を扱うスクリプト（事前の洗い出しの audit_grep.sh・実機確認の recon.sh と
                       browser_probe.mjs・scan_secrets.sh・make_register.py）を架空の題材で確かめるものの数。
                       成功した検査だけを数える（run.sh の出力を渡す）
  教材の答え            実地の評価の題材の答えのうち、その観点のものの数（範囲内だけ）と、答えを持つ題材の数。
                       答えの一覧は tests/eval/local/answers/<題材>.json（run-eval.sh が題材の前処理のたびに写す）

題材の名前は出さない（公開の文書に貼るため）。観点への振り分けは、答えの分類（category）と検査の名前の区分で決める。
答えの項目に "viewpoint"（観点の見出し、または見出しのリスト）があれば、分類より優先する。

--unmeasured は、教材の答えが無い観点だけを並べる（リリースノートの「未測定」に使う）。
"""
import argparse
import collections
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ANSWERS = os.path.join(HERE, "local", "answers")

# スキルの観点。02 の A〜O、07 の 0〜11 節、構成に応じて開く資料、実機確認と修正指示書
VIEWPOINTS = [
    "02 A. 認可", "02 B. 認証と資格情報", "02 C. 秘密情報の扱い", "02 D. 入力と出力",
    "02 E. データアクセス層（RLS・定義者権限の関数・ビュー）", "02 F. 濫用対策", "02 G. ログと追跡",
    "02 H. 依存関係とビルド", "02 I. 開発用の抜け道", "02 J. 未使用・孤児コード", "02 K. fail-open のデフォルト",
    "02 L. 第三者タグの読み込み", "02 M. Webhook と外部からの通知", "02 N. 乱数と暗号", "02 O. 通信の保護",
    "07 0. インジェクション", "07 1. XSS", "07 2. CSRF", "07 3. CORS", "07 4. オープンリダイレクト", "07 5. SSRF",
    "07 6. ファイルの受け取りと配信", "07 7. キャッシュ", "07 8. 競合と二重送信", "07 9. 業務ロジックの欠陥",
    "07 10. 言語・処理系に固有のもの", "07 11. リアルタイム通信",
    "08 個人情報保護・外部送信規律", "10 依存とサプライチェーン（CI・エージェントの設定）", "12 AI 機能（LLM・MCP）",
    "13 基盤（IaC・コンテナ）", "14 モバイル",
    "03・09 実機確認（HTTP・ブラウザ）", "04 指摘台帳の形式", "05 修正指示書",
]


# 実地の評価で動かしていない部分（評価はコード監査までで、実機確認・台帳の書き出し・修正指示書は行わない）。答えが無いのは当然なので
# 「未測定」と区別して「範囲外」と出す。ここの品質はスクリプトの検査と実物での確認で見る
OUT_OF_EVAL = ["03・09 実機確認（HTTP・ブラウザ）", "04 指摘台帳の形式", "05 修正指示書"]


def vp(*keys):
    """「02 A」「07 0」「08」のような短い名前から観点の見出しを引く"""
    out = []
    for k in keys:
        hit = [v for v in VIEWPOINTS if v == k or v.startswith(k + ".") or v.startswith(k + " ")]
        if len(hit) != 1:
            raise SystemExit(f"観点の名前が決まらない: {k} → {hit}")
        out.append(hit[0])
    return out


# 答えの分類 → 観点。分類は題材ごとに書き方が違う（OWASP の旧版・新版・独自の名前）。小文字にし、記号を空白にして照らす
CATEGORY = [
    (r"^injection$|sql injection|nosql|command injection|ldap", vp("07 0")),
    (r"broken access control|object level authorization|function level authorization|mass assignment|idor", vp("02 A")),
    (r"^xss$|cross site scripting", vp("07 1")),
    (r"broken authentication|identification and authentication|authentication failures", vp("02 B")),
    (r"excessive data exposure", vp("02 A")),
    (r"sensitive data exposure", vp("02 C")),
    (r"unvalidated redirect|open redirect", vp("07 4")),
    (r"cryptographic failures", vp("02 N")),
    (r"file upload", vp("07 6")),
    (r"path traversal", vp("07 6")),
    (r"^ssrf", vp("07 5")),
    (r"security misconfiguration", vp("02 K")),
    (r"observability|logging", vp("02 G")),
    (r"anti automation|rate limiting|resources", vp("02 F")),
    (r"^xxe|insecure deserialization", vp("07 10")),
    (r"business logic", vp("07 9")),
    (r"improper input validation", vp("02 D")),
    (r"vulnerable components|supply chain", vp("10")),
    (r"^csrf", vp("07 2")),
    (r"^ai security|prompt injection|llm", vp("12")),
    (r"improper assets management", vp("02 J")),
    (r"row level security|rls", vp("02 E")),
]

# 検査の名前の区分 → 観点。検査の名前は「audit_grep[2m]: …」「recon[DNS]: …」の形
TEST_SECTION = {
    "audit_grep": {
        "2": vp("02 A"), "2b": vp("02 A"), "2c": vp("02 A"), "2d": vp("02 A"), "2f": vp("02 A"), "2g": vp("02 A"),
        "2i": vp("02 A"), "2m": vp("02 A"), "realistic": vp("02 A"), "$fw": vp("02 A"), "angular": vp("02 A"),
        "2e": vp("02 K"), "2h": vp("02 F"), "2j": vp("07 4"), "2k": vp("07 2", "07 3"), "2l": vp("02 F"),
        "3": vp("07 0", "07 1"), "3b": vp("07 6"),
        "4": vp("02 C"), "4b": vp("02 C"), "4c": vp("02 C"), "鍵": vp("02 C"), "伏字": vp("02 C"), "LLM鍵": vp("02 C", "12"),
        "5": vp("02 K"), "12": vp("02 K"), "10": vp("02 B"), "セッション": vp("02 B"), "11": vp("02 M"),
        "13": vp("02 N"), "13b": vp("02 B"), "9": vp("02 L", "08"), "タグ": vp("02 L", "08"), "リプレイ": vp("02 L", "08"),
        "基盤": vp("02 E"), "19": vp("02 E"), "SMS": vp("02 F"), "リアルタイム": vp("07 11"),
        "版": vp("02 H", "10"), "1b": vp("02 H", "10"), "依存": vp("10"), "CI": vp("10"), "21": vp("10"),
        "エージェント": vp("10"), "iac": vp("13"), "17": vp("13"), "mobile": vp("14"),
    },
    "recon": vp("03・09"),
    "browser_probe": vp("03・09", "08"),
    "scan_secrets": vp("02 C"),
    "make_register": vp("04"),
}


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", str(s or "").lower()).strip()


def category_viewpoints(item):
    v = item.get("viewpoint")
    if v:
        return vp(*(v if isinstance(v, list) else [v]))
    c = norm(item.get("category"))
    for rx, vs in CATEGORY:
        if re.search(rx, c):
            return vs
    return []


def count_tests(run_output):
    counts = collections.Counter()
    for line in run_output.splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        m = re.match(r"\s*✓ (audit_grep|recon|browser_probe|scan_secrets|make_register)(\[([^\]]+)\])?", line)
        if not m:
            continue
        tool, sec = m.group(1), m.group(3)
        table = TEST_SECTION[tool]
        if isinstance(table, dict):
            if sec is None:
                continue
            sec = sec.split("・")[0].strip()
            for v in table.get(sec, []):
                counts[v] += 1
        else:
            for v in table:
                counts[v] += 1
    return counts


def count_answers(answers_dir):
    ans = collections.Counter()
    ctl = collections.Counter()
    targets = collections.defaultdict(set)
    unmapped = collections.Counter()
    files = sorted(glob.glob(os.path.join(answers_dir, "*.json")))
    for f in files:
        t = os.path.basename(f)[:-5]
        for it in json.load(open(f, encoding="utf-8")).get("items", []):
            if it.get("scope") != "in":
                continue
            vs = category_viewpoints(it)
            if not vs:
                unmapped[it.get("category")] += 1
            for v in vs:
                if it.get("control"):
                    ctl[v] += 1
                else:
                    ans[v] += 1
                    targets[v].add(t)
    return ans, ctl, targets, unmapped, len(files)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_output", help="tests/run.sh の出力を保存したファイル")
    ap.add_argument("--answers", default=DEFAULT_ANSWERS, help="答えの一覧（<題材>.json）の置き場")
    ap.add_argument("--unmeasured", action="store_true", help="教材の答えが無い観点だけを並べる")
    a = ap.parse_args()
    tests = count_tests(open(a.run_output, encoding="utf-8", errors="replace").read())
    ans, ctl, targets, unmapped, n_targets = count_answers(a.answers)
    if a.unmeasured:
        for v in VIEWPOINTS:
            if not ans[v] and v not in OUT_OF_EVAL:
                print(f"- {v}")
        return
    print(f"題材 {n_targets} つ・範囲内の答え {sum(ans.values())} 件（観点が 2 つにまたがる答えは両方に数える）。"
          "状態は、答えが 5 件以上かつ 2 題材以上なら「測定」、答えがあってそれ未満なら「一部」、答えが無ければ「未測定」\n")
    print("| 観点 | 教材の答え | 答えを持つ題材 | 教材の対照 | スクリプトの検査（架空の題材） | 状態 |")
    print("|---|---|---|---|---|---|")
    for v in VIEWPOINTS:
        n, t, c, k = ans[v], len(targets[v]), ctl[v], tests[v]
        if v in OUT_OF_EVAL:
            st = "実地の評価の範囲外"
        elif n >= 5 and t >= 2:
            st = "測定"
        elif n:
            st = "一部（答えが少ない）"
        else:
            st = "**未測定**"
        print(f"| {v} | {n or '—'} | {t or '—'} | {c or '—'} | {k or '—'} | {st} |")
    if unmapped:
        print("\n観点に振り分けられなかった答えの分類: " + "、".join(f"{k}（{n}）" for k, n in unmapped.most_common()),
              file=sys.stderr)


if __name__ == "__main__":
    main()
