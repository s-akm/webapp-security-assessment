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
# 固めるのは git が追跡している skill/ のファイルだけ。skill/ に未追跡や無視されたファイル
# （.env.local、エディタの一時ファイル、手元のメモ）があれば止める。以前は skill/ をそのまま
# 写していたので、置いてあるものが何でも配布物に入った。
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  stray="$(git -C "$ROOT" status --porcelain --ignored -- skill | grep -E '^(\?\?|!!)' || true)"
  if [[ -n "$stray" ]]; then
    echo "skill/ に追跡していないファイルがある。配布物に入れないので、消すか git に追加してから固める:" >&2
    printf '%s\n' "$stray" | sed 's/^/  /' >&2
    exit 2
  fi
else
  echo "git の管理下でないので固めない（追跡しているファイルだけを固めるため）" >&2
  exit 2
fi

echo "=== ビルド ==="
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

( cd "$ROOT" && git ls-files -z -- skill ) | ( cd "$ROOT" && xargs -0 -I{} sh -c 'mkdir -p "$1/$(dirname "${2#skill/}")" && cp -p "$2" "$1/${2#skill/}"' _ "$WORK" {} )
# 配布物だけを受け取った人にも、版と使用条件が分かるように同梱する
cp "$ROOT/LICENSE" "$WORK/LICENSE"
printf '%s\n' "$VERSION" > "$WORK/VERSION"

# 配布物のパーミッションを揃える。zip は記録されたパーミッションをそのまま
# 復元するため、600 のまま固めると展開先によっては読めない。
find "$WORK" -type d -exec chmod 755 {} +
find "$WORK" -type f -exec chmod 644 {} +
# scripts/ には実行するものしか置かない。拡張子で列挙すると、新しい種類の
# スクリプトを足したときに漏れる（実際 .mjs を足したときに漏れた）。
find "$WORK/scripts" -type f -exec chmod 755 {} +

# 同じ入力からは同じ zip ができるようにする。ファイルの時刻を最後のコミットの時刻に揃え、
# 並び順を固定し、余計な属性を入れない。時刻が変わるだけで中身の同じ配布物のハッシュが変わっていた。
epoch="$(git -C "$ROOT" log -1 --format=%ct)"
stamp="$(TZ=UTC python3 -c 'import sys,time; print(time.strftime("%Y%m%d%H%M.%S", time.gmtime(int(sys.argv[1]))))' "$epoch")"
find "$WORK" -exec env TZ=UTC touch -t "$stamp" {} +

mkdir -p "$DIST"
OUT="$DIST/$NAME-v$VERSION.skill"
rm -f "$OUT"
( cd "$WORK" && find . -type f | LC_ALL=C sort | TZ=UTC zip -q -X -D "$OUT" -@ )

# 版を付けないほうも置く。取り回しのため
cp "$OUT" "$DIST/$NAME.skill"

# 古い版は dist/archive/ に移す（消さない。事例と突き合わせるときに要る）
mkdir -p "$DIST/archive"
for f in "$DIST"/"$NAME"-v*.skill; do
  [[ "$f" == "$OUT" ]] && continue
  [[ -f "$f" ]] && mv "$f" "$DIST/archive/"
done

echo "生成: ${OUT#"$ROOT"/}"
echo "      ${DIST#"$ROOT"/}/$NAME.skill （同じ内容）"
if command -v shasum >/dev/null 2>&1; then sum="$(shasum -a 256 "$OUT" | awk '{print $1}')"
else sum="$(sha256sum "$OUT" | awk '{print $1}')"; fi
echo "      sha256: $sum"
echo
echo "=== 中身 ==="
unzip -Z -l "$OUT" | sed 's/^/  /'
echo
echo "  合計 $(unzip -l "$OUT" | tail -1 | awk '{print $2}') ファイル / $(wc -c < "$OUT" | tr -d ' ') bytes"
