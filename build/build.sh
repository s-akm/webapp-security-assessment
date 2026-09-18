#!/usr/bin/env bash
# build.sh — skill/ を配布用の .skill（zip）に固める
#
#   使い方: build/build.sh [--skip-tests]
#
# skill/ の中身をそのまま固める。除外リストを持たないのは意図的で、
# cases/ のように機微情報を含むディレクトリを 1 階層外に置くことで、
# 混入を「除外を書き忘れないこと」ではなく構造で防いでいる。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/skill"
DIST="$ROOT/dist"
NAME="webapp-security-assessment"
VERSION="$(tr -d ' \n' < "$ROOT/VERSION")"

SKIP_TESTS=0
[[ "${1:-}" == "--skip-tests" ]] && SKIP_TESTS=1

# 検査の検査（tests/mutations.sh）は実行中に skill/ へ欠陥を入れる。
# その最中に固めると、欠陥入りの配布物ができる。ロックがあれば止まる。
if [[ -e "$ROOT/tests/.mutating" ]]; then
  echo "tests/mutations.sh が実行中。skill/ に欠陥が入っている状態なので固めない" >&2
  echo "（終わるまで待つ。残骸なら rm tests/.mutating）" >&2
  exit 2
fi

# --------------------------------------------------------------------------
# 検査を通ってからでないと固めない。機微情報の混入検査もここに含まれる。
if [[ $SKIP_TESTS -eq 0 ]]; then
  echo "=== 検査 ==="
  "$ROOT/tests/run.sh"
  echo
else
  echo "※ --skip-tests が指定された。検査を飛ばして固める"
  echo
fi

# --------------------------------------------------------------------------
echo "=== ビルド ==="
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp -R "$SRC/." "$WORK/"

# ビルド時に混ざるもの、OS が置いていくものを落とす
find "$WORK" \( -name '.DS_Store' -o -name '*.pyc' -o -name '.gitkeep' \) -delete
find "$WORK" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# 配布物のパーミッションを揃える。zip は記録されたパーミッションをそのまま
# 復元するため、600 のまま固めると展開先によっては読めない。
find "$WORK" -type d -exec chmod 755 {} +
find "$WORK" -type f -exec chmod 644 {} +
# scripts/ には実行するものしか置かない。拡張子で列挙すると、新しい種類の
# スクリプトを足したときに漏れる（実際 .mjs を足したときに漏れた）。
find "$WORK/scripts" -type f -exec chmod 755 {} +

mkdir -p "$DIST"
OUT="$DIST/$NAME-v$VERSION.skill"
rm -f "$OUT"
( cd "$WORK" && zip -q -r -X "$OUT" . )

# 版を付けないほうも置く。取り回しのため
cp "$OUT" "$DIST/$NAME.skill"

echo "生成: ${OUT#"$ROOT"/}"
echo "      ${DIST#"$ROOT"/}/$NAME.skill （同じ内容）"
echo
echo "=== 中身 ==="
unzip -Z -l "$OUT" | sed 's/^/  /'
echo
echo "  合計 $(unzip -l "$OUT" | tail -1 | awk '{print $2}') ファイル / $(wc -c < "$OUT" | tr -d ' ') bytes"
