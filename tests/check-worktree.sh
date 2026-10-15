#!/usr/bin/env bash
# check-worktree.sh — 検査を、git の管理情報をほかの作業ツリーと共有する「複製した写し」で実行していないかを確かめる
#
#   使い方: tests/check-worktree.sh [<プロジェクトルート>]   （省略したときは、このファイルの 1 つ上）
#   終了コード: 0 = 問題なし / 2 = 複製した写しで動いている（理由を標準エラーに出す）
#
# git worktree で作った作業ツリーでは、.git はディレクトリでなく「gitdir: <本体の .git>/worktrees/<名前>」と書いたファイルになる。
# この作業ツリーを .git ごと cp などで写すと、写しの .git も同じ管理ディレクトリを指し、索引（index）・HEAD・ブランチを
# 元の作業ツリーと共有する。写しで実行した git の操作は元の作業ツリーの索引を書き換え、git ls-files などは
# 写しでなく元の作業ツリーの索引を読む。写しで reset・clean・commit などを実行すれば、元の作業ツリーのブランチと索引が動く。
# （2.30.0 の後、mutations.sh を --shard で並べるために worktree を .git ごと 7 つに写し、4 つの写しで中身が消えた。
# run.sh と mutations.sh が本体に対して使う git は読む操作と索引の更新だけで、同じ形を小さなリポジトリで再現しても
# ファイルは消えず、共有の索引が書き直されただけだった。消えた原因は特定できていないが、共有そのものが誤りのもとなので止める）
#
# 管理ディレクトリの中の gitdir というファイルには、登録した作業ツリーの .git のパスが書いてある。そこから求めた
# 作業ツリーの場所が、今の場所と違えば「複製した写し」と判定して止まる。
#   - .git がディレクトリ（普通の clone・CI の checkout）、または .git が無い → 対象外（0）
#   - .git の指す管理ディレクトリが無い（コンテナに作業ツリーだけを渡したときなど）→ git の操作は失敗するだけで、
#     ほかの作業ツリーには触れないので止めない（0）。git を使う検査は run.sh の側で「省略」と数える
#   - 管理ディレクトリに gitdir が無い（サブモジュール）→ 対象外（0）
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ROOT="$(cd "$ROOT" 2>/dev/null && pwd -P)" || { echo "check-worktree: ディレクトリが無い: ${1:-}" >&2; exit 2; }

[[ -f "$ROOT/.git" ]] || exit 0
line="$(head -n 1 "$ROOT/.git")"
case "$line" in
  "gitdir: "*) gd="${line#gitdir: }" ;;
  *) echo "check-worktree: $ROOT/.git がファイルなのに「gitdir: 」で始まらない。作業ツリーの状態を確かめる" >&2; exit 2 ;;
esac
# 相対パスは .git のファイルのある場所から見る（worktree.useRelativePaths のとき）
[[ "$gd" == /* ]] || gd="$ROOT/$gd"
[[ -d "$gd" ]] || exit 0
[[ -f "$gd/gitdir" ]] || exit 0

reg="$(head -n 1 "$gd/gitdir")"
# 相対パスは管理ディレクトリから見る
[[ "$reg" == /* ]] || reg="$gd/$reg"
regdir="$(cd "$(dirname "$reg")" 2>/dev/null && pwd -P || true)"

if [[ "$regdir" != "$ROOT" ]]; then
  cat >&2 <<EOF
check-worktree: この作業ツリーは、git worktree の作業ツリーを .git ごと写したもの（複製した写し）に見える。止める。
  今の場所:            $ROOT
  .git が指す管理情報: $gd
  その管理情報の持ち主: ${regdir:-（無い。${reg}）}
  複製した写しは、索引（index）・HEAD・ブランチを持ち主の作業ツリーと共有する。ここで git を使うと持ち主の索引を書き換え、
  git ls-files などは持ち主の索引を読むので、検査の結果も当てにならない。
  並べて実行するときは、写しごとに git worktree add で作業ツリーを作る（README の「検査の検査」）。
  例: git worktree add --detach ../wsa-shard1 HEAD && ../wsa-shard1/tests/mutations.sh --shard 1/8
EOF
  exit 2
fi
exit 0
