#!/usr/bin/env bash
# version_check.sh — 使っているスキルの版が、公開の最新版かを確かめる
#
#   使い方: bash scripts/version_check.sh <スキルの公開元のリポジトリの URL>
#
# 公開元の URL は、依頼の文面（「これを使って監査して <URL>」）にあるものを渡す。
# スクリプトには公開元の URL を書いていない。引数が無ければ WSA_REPO を使い、どちらも無ければ確かめられない（3）。
#
# 評価の最初に 1 回実行する（SKILL.md の「最初に版を確かめる」）。
# スキルは手元に入れた写し（~/.claude/skills/ や、組織に上げたもの）が自動では更新されない。
# 「これを使って監査して <リポジトリの URL>」と頼まれても、エージェントは手元に入っている
# 同じ名前の古い写しをそのまま使うことがある。実際に、3 版前の写しで再評価をして、
# その後に足した観点と台帳の検査が抜けた回があった。
#
# 見るもの:
#   - 使っている版: このスクリプトの 1 つ上（配布物）か 2 つ上（リポジトリ）にある VERSION
#   - 公開の最新版: GitHub のリリースの最新（<URL>/releases/latest の転送先）。取れなければタグの最大
#
# 対象のシステムには何も送らない。問い合わせるのはスキルの公開元だけ。
# 手元のリポジトリのパスも渡せる（タグの最大を見る。検査で使う）。
#
# 終了コード:
#   0  最新（または公開の最新より新しい。保守中の作業ツリー）
#   2  古い。この版で評価を続けない
#   3  確かめられない（VERSION が無い、公開元の URL が分からない、公開元に届かない）

set -uo pipefail

REPO="${1:-${WSA_REPO:-}}"; REPO="${REPO%/}"; REPO="${REPO%.git}"
NAME="webapp-security-assessment"
here="$(cd "$(dirname "$0")" && pwd)"

# 使っている版
vfile=""
for c in "$here/../VERSION" "$here/../../VERSION"; do
  if [[ -f "$c" ]]; then vfile="$(cd "$(dirname "$c")" && pwd)/VERSION"; break; fi
done
local_v=""
[[ -n "$vfile" ]] && local_v="$(tr -d ' \r\n' < "$vfile")"

# 版の比較。数字 3 つだけを比べる（2.9.0 < 2.10.0）。前が小さければ -1、同じなら 0、大きければ 1
vercmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, "."); nb = split(b, y, ".")
    for (i = 1; i <= 3; i++) { p = x[i] + 0; q = y[i] + 0; if (p < q) { print -1; exit } if (p > q) { print 1; exit } }
    print 0 }'
}

# 公開の最新版。リリースを先に見る（タグだけ付けてリリースを作っていない版は、配布物がまだ無い）。
# GitHub の <URL>/releases/latest は、最新のリリースのタグのページへ転送する
latest=""; how=""
case "$REPO" in
  https://github.com/*/*)
    if command -v curl >/dev/null 2>&1; then
      eff="$(curl -fsSIL -m 20 -o /dev/null -w '%{url_effective}' "$REPO/releases/latest" 2>/dev/null || true)"
      latest="$(sed -nE 's#.*/releases/tag/v?([0-9]+\.[0-9]+\.[0-9]+)$#\1#p' <<<"$eff")"
      [[ -n "$latest" ]] && how="リリース"
    fi
    ;;
esac
if [[ -z "$latest" && -n "$REPO" ]] && command -v git >/dev/null 2>&1; then
  tags="$(GIT_TERMINAL_PROMPT=0 git -c http.lowSpeedLimit=1 -c http.lowSpeedTime=20 ls-remote --tags --refs "$REPO" 2>/dev/null || true)"
  latest="$(sed -nE 's#.*refs/tags/v?([0-9]+\.[0-9]+\.[0-9]+)$#\1#p' <<<"$tags" \
    | awk -F. '{ printf "%09d.%09d.%09d %s\n", $1, $2, $3, $0 }' | sort | tail -1 | awk '{ print $2 }')"
  [[ -n "$latest" ]] && how="タグ（リリースが取れなかったので、タグの最大で代えた）"
fi

echo "=== スキルの版 ==="
if [[ -n "$local_v" ]]; then
  echo "  使っている版   ${local_v}（${vfile}）"
else
  echo "  使っている版   不明（VERSION が見当たらない: ${here}/../VERSION・${here}/../../VERSION）"
fi
if [[ -n "$latest" ]]; then
  echo "  公開の最新版   ${latest}（${REPO} の${how}。$(date +%Y-%m-%d) に確認）"
elif [[ -z "$REPO" ]]; then
  echo "  公開の最新版   公開元の URL が分からない（引数か WSA_REPO で渡す。依頼の文面に URL があればそれを使う）"
else
  echo "  公開の最新版   取得できない（${REPO} に届かない。ネットワークの制限か、公開元の変更）"
fi

if [[ -z "$local_v" || -z "$latest" ]]; then
  echo "  判定           確かめられない"
  echo "  ※ 依頼者に伝え、この版で続けるかを決めてもらう。続けるなら、使った版と「最新か確かめられなかった」ことを"
  echo "    台帳の評価の前提と確認の範囲に書く（SKILL.md の「最初に版を確かめる」）"
  exit 3
fi

c="$(vercmp "$local_v" "$latest")"
if [[ "$c" -ge 0 ]]; then
  echo "  判定           最新"
  [[ "$c" -gt 0 ]] && echo "  ※ 公開の最新より新しい（未リリースの作業ツリー）。評価に使うなら、その旨を台帳の評価の前提に書く"
  exit 0
fi

echo "  判定           古い。この版で評価を続けない"
echo ""
echo "  最新の配布物の取り直し方（評価用の作業ディレクトリに置く。対象のリポジトリの中には置かない）:"
echo "    D=\"<評価用の作業ディレクトリ>/${NAME}-v${latest}\""
case "$REPO" in
  https://github.com/*)
    echo "    mkdir -p \"\${D}\" && curl -fsSL -o \"\${D}.skill\" ${REPO}/releases/download/v${latest}/${NAME}-v${latest}.skill && unzip -q \"\${D}.skill\" -d \"\${D}\""
    ;;
  *)
    echo "    git clone -q --depth 1 --branch v${latest} \"${REPO}\" \"\${D}-src\" && cp -R \"\${D}-src/skill\" \"\${D}\" && cp \"\${D}-src/VERSION\" \"\${D}/\""
    ;;
esac
echo "    bash \"\${D}/scripts/version_check.sh\"     # 最新と出ることを確かめる"
echo ""
echo "  ※ 取り直したら、以後の資料とスクリプトはすべて \${D} から読む。読み込んだ古い SKILL.md の手順は使わない"
echo "  ※ 手元に入れてあるスキル（$(dirname "${vfile}")）を書き換えるのは依頼者の判断。古いことと更新の方法を伝える"
exit 2
