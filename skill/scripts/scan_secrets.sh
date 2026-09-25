#!/usr/bin/env bash
# scan_secrets.sh — 成果物に秘密情報・個人情報が混入していないかの最終検査
#
#   使い方: ./scan_secrets.sh <報告書のディレクトリ>
#
# 評価の過程では、鍵の値も個人情報も目に入る。手で書き写すつもりがなくても、
# ツールの出力を貼り付けた拍子に混ざる。報告書を書き終えたら必ずこれを通す。
#
# 検出はパターンマッチなので、取りこぼしも誤検出もある。0 件だから安全とは言えない。
# 「明らかな混入を機械的に落とす」ための道具として使う。
#
# 見るもの:
#   - テキストのファイルすべて（拡張子で絞らない。.yml / .log / .har / .env / .MD も見る）
#   - xlsx の台帳と、docx・pptx の報告書（展開して、文字列・コメントに同じパターンを当てる。unzip が要る）
#   - PDF と旧形式の Office（.doc / .xls / .ppt）は中身を読めないので、[未検査] として名前を出す
#   xlsx で数値として入れたセルは先頭の 0 が落ちる（090… が 90… になる）ので、電話番号には当たらない
#
# 検出した値そのものは出さない。位置（ファイルと行）と種類と、先頭の数バイトを残して
# 伏字にした形だけを出す。この出力を報告書や作業ログに貼っても、値が広がらないようにするため。

set -uo pipefail
DIR="${1:-}"
if [[ -z "$DIR" || ! -d "$DIR" ]]; then
  echo "使い方: $0 <報告書のディレクトリ>" >&2
  exit 1
fi

HITS=0
SHOW=20          # 1 種類あたりに表示する件数
KEEP=4           # 伏字にする前に残す先頭のバイト数（日本語は 1 文字、英数字は 4 文字）

# Office の文書を展開したテキストの置き場。検査対象のディレクトリの外に作り、終わったら消す。
XT="$(mktemp -d 2>/dev/null || mktemp -d -t scan_secrets)"
trap 'rm -rf "$XT"' EXIT
XFILES=()        # 展開したテキストのパス
XNAMES=()        # 出力に使う位置の名前（./台帳.xlsx[xl/sharedStrings.xml] の形）
UNREAD=()        # 検査できなかったファイル

# 不完全なバイト列を落とす。伏字の前に残す部分はバイト単位で切るため、日本語の途中で
# 切れることがある。iconv が無ければ、非 ASCII のバイトをまとめて落とす（壊れた文字は出さない）。
clean_utf8() {
  if command -v iconv >/dev/null 2>&1; then
    iconv -c -f UTF-8 -t UTF-8 2>/dev/null
  else
    LC_ALL=C tr -d '\200-\377'
  fi
}

# 検出した値を伏字にする。先頭 KEEP バイトだけ残す。ロケールに依らず同じ結果にするため、
# 文字数ではなくバイト数で切る（LC_ALL=C で走らせても、UTF-8 で走らせても同じ出力になる）。
mask_value() {
  local v="$1" head_
  head_="$(printf '%s' "$v" | LC_ALL=C cut -b "1-$KEEP" | clean_utf8)"
  printf '%s…<伏字>' "$head_"
}

# メールアドレスは、説明用の予約ドメイン（RFC 2606 / 6761）ならドメインを見せる。
# 誤検出かどうかを出力だけで判断できるようにするため。それ以外はドメインも伏せる。
mask_email() {
  local v="$1" dom="${1##*@}"
  if printf '%s' "$dom" | grep -iE '^(([A-Za-z0-9-]+\.)*example\.(com|net|org)|example|([A-Za-z0-9-]+\.)*(example|invalid|test|localhost))$' >/dev/null; then
    printf '%s…<伏字>@%s' "$(printf '%s' "$v" | LC_ALL=C cut -b 1-2 | clean_utf8)" "$dom"
  else
    mask_value "$v"
  fi
}

# --- Office の文書（xlsx・docx・pptx）を展開する ------------------------------
# xlsx は zip なので、grep -I はバイナリとして読み飛ばす。台帳に貼った値がここで素通りしないよう、
# セルの文字列（sharedStrings）、シート（数式やインライン文字列）、コメントを取り出して同じ検査を当てる。
# XML のタグを外し、テキストの節 1 つを 1 行にする（行番号は「何番目の文字列か」になる）。
xml_text() {
  # RS に 1 文字を使うのは、mawk / BSD awk / gawk のどれでも同じに動かすため
  LC_ALL=C awk 'BEGIN { RS = "<" }
    { i = index($0, ">"); if (!i) next
      t = substr($0, i + 1); gsub(/[\r\n]+/, " ", t)
      if (t ~ /[^ \t]/) print t }' \
  | sed -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&apos;/'/g" -e 's/&amp;/\&/g'
}
# docx と pptx は、1 つの段落の文字が書式ごとの断片（<w:t> / <a:t>）に分かれる。電話番号の途中で
# 書式が変わると、断片ごとの行では当たらない。段落（</w:p> / </a:p>）ごとにつないで 1 行にする。
xml_para_text() {
  LC_ALL=C awk 'BEGIN { RS = "<"; buf = "" }
    { i = index($0, ">"); if (!i) next
      tag = substr($0, 1, i - 1); t = substr($0, i + 1); gsub(/[\r\n]+/, " ", t)
      if (tag ~ /^\/(w|a):p$/) { if (buf ~ /[^ \t]/) print buf; buf = ""; next }
      if (tag ~ /^(w:tab|w:br|a:br)( |\/|$)/) buf = buf " "
      buf = buf t }
    END { if (buf ~ /[^ \t]/) print buf }' \
  | sed -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&apos;/'/g" -e 's/&amp;/\&/g'
}

n_office=0
while IFS= read -r f; do
  n_office=$((n_office+1))
  if ! command -v unzip >/dev/null 2>&1; then
    UNREAD+=("${f}（unzip が無い）"); continue
  fi
  # 見る部品: xlsx はセルの文字列・シート・コメント、docx は本文・コメント・脚注・ヘッダとフッタ、
  # pptx はスライド・ノート・コメント
  members="$(cd "$DIR" && unzip -Z1 "$f" 2>/dev/null \
    | grep -E '^(xl/(sharedStrings|worksheets/sheet[0-9]+|comments[0-9]*|threadedComments/[^/]+)|word/(document|comments|footnotes|endnotes|header[0-9]*|footer[0-9]*)|ppt/(slides/slide[0-9]+|notesSlides/notesSlide[0-9]+|comments/[^/]+))\.xml$')"
  if [[ -z "$members" ]]; then
    UNREAD+=("${f}（Office の文書として展開できない）"); continue
  fi
  while IFS= read -r m; do
    [[ -n "$m" ]] || continue
    out="$XT/${#XFILES[@]}.txt"
    case "$m" in
      xl/*) (cd "$DIR" && unzip -p "$f" "$m" 2>/dev/null) | xml_text > "$out" ;;
      *)    (cd "$DIR" && unzip -p "$f" "$m" 2>/dev/null) | xml_para_text > "$out" ;;
    esac
    XFILES+=("$out"); XNAMES+=("$f[$m]")
  done <<< "$members"
# Office が開いている間に作る ~$ で始まる一時ファイルは文書ではないので除く
done < <(cd "$DIR" && find . -type f \( -iname '*.xlsx' -o -iname '*.xlsm' -o -iname '*.docx' -o -iname '*.docm' \
           -o -iname '*.pptx' -o -iname '*.pptm' \) ! -name '~$*' 2>/dev/null | sort)
# 中身を読めない形式。黙って飛ばさず、見ていないことを出す
while IFS= read -r f; do
  UNREAD+=("${f}（PDF・旧形式の Office は中身を読めない。テキストに書き出して検査するか、開いて目で確かめる）")
done < <(cd "$DIR" && find . -type f \( -iname '*.pdf' -o -iname '*.doc' -o -iname '*.xls' -o -iname '*.ppt' \) ! -name '~$*' 2>/dev/null | sort)

# --- 検査 -----------------------------------------------------------------
#   check <種類> <パターン> [注記] [オプション] [除外パターン]
#
#   オプション（文字を並べる）
#     i  大文字小文字を区別しない
#     d  数字の並び。前後が英数字・「-」「.」「_」に接していないものだけを見る
#        （UUID の末尾、バージョン番号、長い数字の一部に当たらないようにする）
#     e  メールアドレスとして伏字にする
#     p  伏字にしない（値ではなく書き方を見る検査）
#   除外パターン: 一致した値がこれに当たれば数えない（日付の並びなど）
check() {
  local label="$1" pattern="$2" note="${3:-}" opts="${4:-}" excl="${5:-}"
  local gopt=(-E) full="$pattern" raw i
  [[ "$opts" == *i* ]] && gopt+=(-i)
  if [[ "$opts" == *d* ]]; then
    # 前の境界の「.」は、数字の続き（1.0312345678 のような小数や版）を除くために外しているが、
    # 英字の後の「.」（TEL.03-…、No.1234…）は区切りとして許す
    full="(^|[^0-9A-Za-z_.+-]|[A-Za-z]\\.)(${pattern})([^0-9A-Za-z_-]|$)"
  fi
  # grep にパターンを渡すときは必ず -e を使う。'-----BEGIN' のように - で始まる
  # パターンをそのまま渡すと、grep がオプションとして解釈して誤動作する。
  #
  # 検査対象のディレクトリへ移動してから "." を検索する。絶対パスのまま検索すると、
  # 出力の先頭が長いパスで埋まり、肝心の検出内容が表示幅から押し出される。
  #
  # -o で一致した部分だけを取り出す。行全体を出すと、同じ行にある値まで表示してしまう。
  raw="$(
    (cd "$DIR" && grep -rnoI "${gopt[@]}" -e "$full" . 2>/dev/null)
    i=0
    while [[ $i -lt ${#XFILES[@]} ]]; do
      grep -no "${gopt[@]}" -e "$full" "${XFILES[$i]}" 2>/dev/null \
        | while IFS= read -r l; do printf '%s:%s\n' "${XNAMES[$i]}" "$l"; done
      i=$((i+1))
    done
  )"
  [[ -n "$raw" ]] || return 0

  local re='^([^:]*):([0-9]+):(.*)$' lines="" n=0 loc v core
  while IFS= read -r l; do
    if [[ "$l" =~ $re ]]; then
      loc="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"; v="${BASH_REMATCH[3]}"
    else
      # 位置を読み取れない行（パスに「:」を含むなど）は、値を丸ごと伏せる
      loc="（位置を読み取れない）"; v=""
    fi
    if [[ "$opts" == *d* && -n "$v" ]]; then
      # 前後の境界の 1 文字を外し、数字の並びそのものを取り出す
      core="$(printf '%s' "$v" | grep -oE "${gopt[@]:1}" -e "$pattern" | head -1)"
      [[ -n "$core" ]] && v="$core"
    fi
    if [[ -n "$excl" && -n "$v" ]] && printf '%s' "$v" | grep -E -e "$excl" >/dev/null; then
      continue
    fi
    n=$((n+1))
    [[ $n -le $SHOW ]] || continue
    if [[ -z "$v" ]]; then v="<伏字>"
    elif [[ "$opts" == *p* ]]; then :
    elif [[ "$opts" == *e* ]]; then v="$(mask_email "$v")"
    else v="$(mask_value "$v")"; fi
    lines="${lines}  ${loc}: ${v}"$'\n'
  done <<< "$raw"
  [[ $n -gt 0 ]] || return 0

  printf '\n[検出] %s\n' "$label"
  [[ -n "$note" ]] && printf '  %s\n' "$note"
  printf '%s' "$lines" | clean_utf8
  [[ $n -gt $SHOW ]] && printf '  …ほか %s 件\n' "$((n - SHOW))"
  HITS=$((HITS+1))
}

echo "検査対象: $DIR"
[[ $n_office -gt 0 ]] && echo "Office の文書（xlsx・docx・pptx）: ${n_office} 件（展開して文字列とコメントも見る）"

# 全角の数字とハイフン。[０-９] のような範囲指定にしない。ロケールによっては
# 「Invalid collation character」で grep 全体が失敗し、検査が黙って素通りする。
# [０１２…] と列挙しても、C ロケールではバイトの集合として解釈されて別の文字に当たる。
# 選択（|）で並べれば、どのロケールでも「その文字の並び」として照合される。
ZD='(０|１|２|３|４|５|６|７|８|９)'
ZN="([0-9]|${ZD})"
ZH='(-|－|‐|−|ー)'

# --- 鍵・トークン ---------------------------------------------------------
check "JWT 形式のトークン" 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}'
# 接頭辞だけでは拾わない。報告書では「sb_publishable_... という鍵」のように
# 種類を説明するために接頭辞を書くことが正当にあるため、実際の鍵の長さがあるものだけを見る。
check "クラウド・決済の鍵（AWS・Stripe・Twilio・SendGrid）" \
      '\b((AKIA|ASIA)[0-9A-Z]{16}|(sk|pk|rk)_(live|test)_[0-9A-Za-z]{12,}|whsec_[0-9A-Za-z]{20,}|(AC|SK)[0-9a-f]{32}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})'
check "コード管理・パッケージのトークン（GitHub・npm）" \
      '\b(gh[pousr]_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{22,}|npm_[0-9A-Za-z]{30,})'
# Webhook の URL は、それだけで投稿できる鍵になる。ドメインは書かず、形で見る。
check "チャットの鍵と Webhook（Slack）" \
      '\b(xox[abeoprs]-[0-9A-Za-z-]{12,}|xapp-[0-9]+-[0-9A-Za-z-]{12,})|hooks\.slack\.[a-z]{2,6}/(services|workflows|triggers)/[A-Za-z0-9/_-]{16,}'
# OpenAI の旧形式（sk- ＋英数字 48）は区切りを含まない。区切りを含む英単語の連なり
# （task-management-... の「sk-」）に当たらないよう、\b と文字の種類で縛る。
check "LLM の鍵（OpenAI・Anthropic）" \
      '\bsk-((proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|ant-[a-z]+[0-9]*-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})'
check "Google・Supabase の鍵" \
      '\b(AIza[0-9A-Za-z_-]{20,}|sb_(secret|publishable)_[0-9A-Za-z_-]{12,})|"type"[[:space:]]*:[[:space:]]*"service_account"' \
      "※ \"type\": \"service_account\" は GCP のサービスアカウントの鍵ファイル。中身ごと貼られていないか確認する"
# 角括弧の中の \t は「\ と t」の 2 文字になる（POSIX）。空白は [:space:] で書く。
# 認証情報を「<伏字>」に置き換えたもの（audit_grep.sh の出力を貼った形）は数えない。
check "接続文字列" '(postgres(ql)?|mysql|mongodb(\+srv)?|redis|rediss|amqps?)://[^[:space:]"'"'"'`]{8,}' "" "" '://<伏字>@'
# URL に埋め込んだ認証情報。「://<伏字>@」のように伏せたものは「:」を含まないので当たらない。
check "URL に埋め込んだ認証情報（user:pass@）" '[A-Za-z][A-Za-z0-9+.-]*://[^/:@[:space:]"'"'"'`<>]+:[^/@[:space:]"'"'"'`<>]+@'
check "秘密鍵ブロック" '-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
check "Authorization ヘッダの値" \
      '(authorization["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?(bearer|basic|token)[[:space:]]+|bearer[[:space:]]+)[A-Za-z0-9._~+/-]{16,}=*' \
      "" i
# 引用符で囲んだ値は形を問わず見る。引用符なし（.env、HAR、ログ）は、説明文の
# 「API_KEY=process.env.X」に当たらないよう、数字を含む 16 文字以上の並びだけを見る。
check "key/secret への値の代入" \
      '(api[_-]?key|secret|password|passwd|token|access[_-]?key|client[_-]?secret)[A-Za-z0-9_]*["'"'"']?[[:space:]]*[:=][[:space:]]*(["'"'"'`][A-Za-z0-9_/+=-]{16,}|[A-Za-z0-9_/+=-]{6,}[0-9][A-Za-z0-9_/+=-]{6,})' \
      "※ 説明文の中の変数名は誤検出。値が書かれていないか確認する" i

# --- 個人情報 -------------------------------------------------------------
check "メールアドレス" '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
      "※ example.com / example.invalid / .test など、説明用の値なら問題ない（その場合はドメインを表示する）" e
# 書き方の揺れ: 0X-XXXX-XXXX、ハイフンなし（10〜11 桁）、括弧付き、+81、全角
check "電話番号らしき並び" \
      "0[0-9]{1,4}-[0-9]{1,4}-[0-9]{3,4}|0[5789]0[0-9]{8}|0[1-9][0-9]{8}|\\(0[0-9]{1,4}\\)[[:space:]]?[0-9]{1,4}-?[0-9]{3,4}|0[0-9]{1,4}\\([0-9]{1,4}\\)[0-9]{3,4}|\\+81[[:space:]-]?\\(?0?[0-9]{1,4}\\)?[[:space:]-]?[0-9]{1,4}[[:space:]-]?[0-9]{3,4}|０${ZD}{1,4}${ZH}${ZD}{1,4}${ZH}${ZD}{3,4}|０${ZD}{9,10}" \
      "" d
# 16 桁（Visa / Mastercard / JCB など）と 15 桁（American Express: 34 / 37 で始まる 4-6-5）
check "クレジットカード番号らしき並び" \
      '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}' "" d
# 年月日時分の 12 桁（202609251030）は日時として数えない
check "12 桁の数字の並び（マイナンバー等）" \
      "[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|${ZD}{4}( |　|－|-)?${ZD}{4}( |　|－|-)?${ZD}{4}" "" d \
      '^(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])[0-5][0-9]$'
# 住所は「都道府県名 + 市区町村 + 数字」まで揃ったものだけを見る。
# 文字クラス（[都道府県]）で書くと 1 文字ずつの照合になり、無関係な日本語文に大量に当たる。
# 数字まで求めるのは、「都道府県と市区町村まではマスクする」のような説明文を拾わないため。
check "住所らしき記述" "(東京都|北海道|大阪府|京都府|[^ |、。＋+]{2,3}県)[^ |、。]{0,12}(市|区|町|村|郡)[^ |、。]{0,16}${ZN}"
# 都道府県を省いた住所。「区」「市」のあとに丁目・番地まで揃ったものだけを見る。
# 「区分 1-2」のような説明文に当たらないよう、「N丁目」か「N-N-N」の形を求める。
# 間の文字に「、。」の除外を書かない。C ロケールでは [^、。] がバイトの集合になり、
# ひらがな（みなとみらい）まで除外して、UTF-8 のときと結果が変わる。
check "住所らしき記述（都道府県なし）" \
      "[^[:space:]|](市|区)[^[:space:]|]{0,18}${ZN}{1,3}(丁目|${ZH}${ZN}{1,4}${ZH}${ZN}{1,4})"
check "郵便番号" "〒[[:space:]　]?([0-9]{3}-?[0-9]{4}|${ZD}{3}${ZH}?${ZD}{4})"

# --- SQL の書き方 ---------------------------------------------------------
check "select * の使用" 'select[[:space:]]+\*[[:space:]]+from' \
      "※ 実データを取得しかねない。必要な列だけを指定する方針と整合しているか確認する" ip

# --------------------------------------------------------------------------
echo
if [[ ${#UNREAD[@]} -gt 0 ]]; then
  echo "[未検査] 次のファイルは中身を見ていない。手で開いて確認する"
  for u in "${UNREAD[@]}"; do printf '  %s\n' "$u"; done
  echo
fi
if [[ $HITS -eq 0 ]]; then
  echo "検出なし。"
else
  echo "$HITS 種類の検出があった。上記を確認し、必要なら伏字にするか削除する。"
  echo "（値は先頭だけを残して伏せてある。元の値は該当の行を開いて確かめる）"
fi
echo
echo "注意: これはパターンマッチであり、取りこぼしも誤検出もある。"
echo "      0 件であることは「機械的に見つかる混入が無い」ことを意味するだけで、"
echo "      安全を保証しない。最終的には自分で読み返すこと。"
