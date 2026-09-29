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
#   - UTF-16（BOM 付き）・Shift_JIS・EUC-JP のテキストは、UTF-8 に直した写しに当てる（iconv が要る）。
#     Windows の PowerShell の「>」や、表計算ソフトの「Unicode テキスト」「CSV」で書き出したファイルがこの形になる
#   - xlsx の台帳と、docx・pptx の報告書（展開して、文字列・コメントに同じパターンを当てる。unzip が要る）
#   - PDF と旧形式の Office（.doc / .xls / .ppt）、テキストとして読めないファイル（画像など）は
#     中身を見ないので、[未検査] として名前を出す
#   xlsx で数値として入れたセルは先頭の 0 が落ちる（090… が 90… になる）ので、電話番号には一致しない
#
# 検出した値そのものは出さない。位置（ファイルと行）と種類と、先頭の数バイトを残して
# 伏字にした形だけを出す。この出力を報告書や作業ログに貼っても、値が広がらないようにするため。
#
# 終了コード（成果物を置く前の検査を自動化するときに使う）:
#   0  検出なしで、すべてのファイルを見た
#   1  使い方の誤り
#   2  検出あり
#   3  検出は無いが、中身を見ていないファイルがある（[未検査] の一覧を手で確かめる）

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
# git の履歴から写した GitHub の代理アドレス（…@users.noreply.github.com）もドメインを見せる。
# 個人の受信箱ではないが、前半にアカウント名が入るので前半は伏せる
mask_email() {
  local v="$1" dom="${1##*@}"
  if printf '%s' "$dom" | grep -iE '^(([A-Za-z0-9-]+\.)*example\.(com|net|org)|example|([A-Za-z0-9-]+\.)*(example|invalid|test|localhost)|users\.noreply\.github\.com)$' >/dev/null; then
    printf '%s…<伏字>@%s' "$(printf '%s' "$v" | LC_ALL=C cut -b 1-2 | clean_utf8)" "$dom"
  else
    mask_value "$v"
  fi
}

# --- Office の文書（xlsx・docx・pptx）を展開する ------------------------------
# xlsx は zip なので、grep -I はバイナリとして読み飛ばす。台帳に貼った値がここで素通りしないよう、
# セルの文字列（sharedStrings）、シート（数式やインライン文字列）、コメントを取り出して同じ検査を当てる。
#
# 文字は書式ごとの断片（<t> / <w:t> / <a:t>）に分かれる。電話番号や鍵の途中で書式が変わると、
# 断片ごとの行では一致しない。断片を、まとまりの終わりのタグまでつないで 1 行にする。
#   xml_join <終わりのタグ（ERE）> <空白をはさむタグ（ERE）> [読み飛ばすタグの名前]
# 終わりのタグ: docx・pptx は段落（</w:p> / </a:p>）、xlsx は 1 つの文字列（</si>）・インライン文字列（</is>）・
# セル（</c>）・コメントの本文（</text>）。行番号は「何番目のまとまりか」になる。
# xlsx の数式と値（</f> / </v>）の間には空白をはさむ（数字どうしがつながって別の並びに一致しないように）。
# 読み飛ばすのはふりがな（<rPh>）。つなぐと住所や氏名の後ろに読みが続き、形が崩れる
xml_join() {
  # RS に 1 文字を使うのは、mawk / BSD awk / gawk のどれでも同じに動かすため
  LC_ALL=C awk -v ends="$1" -v brk="$2" -v skip="${3:-}" 'BEGIN { RS = "<"; buf = ""; sk = 0 }
    { i = index($0, ">"); if (!i) next
      tag = substr($0, 1, i - 1); t = substr($0, i + 1); gsub(/[\r\n]+/, " ", t)
      if (skip != "" && tag ~ ("^" skip "( |$)")) sk = 1
      if (skip != "" && tag == ("/" skip)) { sk = 0; next }
      if (tag ~ ends) { if (buf ~ /[^ \t]/) print buf; buf = ""; next }
      if (tag ~ brk) buf = buf " "
      if (!sk) buf = buf t }
    END { if (buf ~ /[^ \t]/) print buf }' \
  | sed -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e "s/&apos;/'/g" -e 's/&amp;/\&/g'
}
XLSX_ENDS='^/(si|is|c|text)$'
DOCX_ENDS='^/(w|a):p$'

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
      xl/*) (cd "$DIR" && unzip -p "$f" "$m" 2>/dev/null) | xml_join "$XLSX_ENDS" '^/(f|v)$' rPh > "$out" ;;
      *)    (cd "$DIR" && unzip -p "$f" "$m" 2>/dev/null) | xml_join "$DOCX_ENDS" '^(w:tab|w:br|a:br)( |/|$)' > "$out" ;;
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

# --- テキストのファイルを文字コードで分ける ------------------------------------
# grep -I は NUL を含むファイルを丸ごと飛ばす。UTF-16 のテキストは ASCII の文字の半分が NUL なので、
# 黙って検査されずに終わっていた。UTF-8 として正しくないファイル（Shift_JIS の CSV など）も、
# GNU grep は -I でバイナリとして飛ばし、BSD grep でも日本語のパターンは一致しない。
# ファイルごとに文字コードを見て、UTF-8 はそのまま（TEXTS）、それ以外は UTF-8 に直した写しを XFILES に入れる。
# 直せないもの（画像・圧縮ファイルなど）は [未検査] に出す。
#   先頭 2 バイトが BOM（FE FF / FF FE）      → UTF-16 として直す
#   先頭 8KB に NUL がある                     → テキストとして読めない（未検査）
#   UTF-8 として正しくない                     → CP932（Shift_JIS）、EUC-JP の順に直してみる
# iconv が無ければ直せないので、UTF-16 は未検査に出し、それ以外はそのまま当てる（以前と同じ）
TEXTS="$XT/texts.lst"; : > "$TEXTS"
have_iconv=0; command -v iconv >/dev/null 2>&1 && have_iconv=1
to_utf8() {  # to_utf8 <ファイル> <元の文字コード> <表示の名前>。直せたら XFILES に足して 0 を返す
  local out="$XT/${#XFILES[@]}.txt"
  [[ $have_iconv -eq 1 ]] || return 1
  (cd "$DIR" && iconv -f "$2" -t UTF-8 < "$1" > "$out" 2>/dev/null) || { rm -f "$out"; return 1; }
  XFILES+=("$out"); XNAMES+=("$1[$3 を UTF-8 に直して検査]")
}
while IFS= read -r f; do
  # 文字の a / b を先に別の文字へ移してから、BOM の 2 バイトを a / b にする（本文が "ab" で始まるファイルと区別するため）
  bom="$(cd "$DIR" && LC_ALL=C head -c 2 "$f" | LC_ALL=C tr 'ab\376\377' 'xxab')"
  if [[ "$bom" == "ab" || "$bom" == "ba" ]]; then
    to_utf8 "$f" UTF-16 UTF-16 || UNREAD+=("${f}（UTF-16 のテキスト。iconv が無いか、直せなかった）")
    continue
  fi
  # NUL をそのままコマンド置換に通すと bash が警告を出すので、x に置き換えてから受け取る
  nul="$(cd "$DIR" && LC_ALL=C head -c 8192 "$f" | LC_ALL=C tr -dc '\000' | LC_ALL=C head -c 1 | LC_ALL=C tr '\000' x)"
  if [[ -n "$nul" ]]; then
    # git の内部の保管庫（圧縮した履歴）は報告書の中身ではないので、一覧に出さない
    case "$f" in */.git/*) continue ;; esac
    UNREAD+=("${f}（テキストとして読めない。画像なら開いて目で確かめる）")
    continue
  fi
  if [[ $have_iconv -eq 1 ]] && ! (cd "$DIR" && iconv -f UTF-8 -t UTF-8 < "$f" >/dev/null 2>&1); then
    to_utf8 "$f" CP932 Shift_JIS && continue
    to_utf8 "$f" EUC-JP EUC-JP && continue
  fi
  printf '%s\n' "$f" >> "$TEXTS"
# Office・PDF・旧形式の Office は上で扱った。OS が作る一覧用のファイル（.DS_Store・Thumbs.db）は成果物ではない
done < <(cd "$DIR" && find . -type f ! -name '~$*' ! -name '.DS_Store' ! -name 'Thumbs.db' \
           ! -iname '*.xlsx' ! -iname '*.xlsm' ! -iname '*.docx' ! -iname '*.docm' ! -iname '*.pptx' ! -iname '*.pptm' \
           ! -iname '*.pdf' ! -iname '*.doc' ! -iname '*.xls' ! -iname '*.ppt' 2>/dev/null | sort)

# --- 検査 -----------------------------------------------------------------
#   check <種類> <パターン> [注記] [オプション] [除外パターン]
#
#   オプション（文字を並べる）
#     i  大文字小文字を区別しない
#     d  数字の並び。前後が英数字・「-」「.」「_」に接していないものだけを見る
#        （UUID の末尾、バージョン番号、長い数字の一部に一致しないようにする）
#     e  メールアドレスとして伏字にする
#     p  伏字にしない（値ではなく書き方を見る検査）
#   除外パターン: 一致した値がこれに当たれば数えない（日付の並びなど）
# カード番号の検査数字（Luhn）。カード番号は必ずこれを満たすので、満たさない 15・16 桁の並び
# （検証の範囲の 1000…〜9999…、注文番号、連番）はカード番号として数えない
luhn_ok() {
  local d="$1" sum=0 i n dbl=0
  for (( i=${#d}-1; i>=0; i-- )); do
    n=${d:i:1}
    if [[ $dbl -eq 1 ]]; then n=$((n*2)); [[ $n -gt 9 ]] && n=$((n-9)); fi
    sum=$((sum+n)); dbl=$((1-dbl))
  done
  [[ $((sum % 10)) -eq 0 ]]
}

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
  # 検査対象のディレクトリへ移動してから、相対パス（./…）の一覧を渡す。絶対パスのまま検索すると、
  # 出力の先頭が長いパスで埋まり、肝心の検出内容が表示幅から押し出される。
  # 一覧は上で文字コードを見て分けた UTF-8 のテキスト（TEXTS）。-H はファイルが 1 つでも名前を出すため。
  #
  # -o で一致した部分だけを取り出す。行全体を出すと、同じ行にある値まで表示してしまう。
  raw="$(
    [[ -s "$TEXTS" ]] && (cd "$DIR" && tr '\n' '\0' < "$TEXTS" | xargs -0 grep -HnoI "${gopt[@]}" -e "$full" 2>/dev/null)
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
    if [[ -n "$excl" && -n "$v" ]] && grep -E -e "$excl" <<<"$v" >/dev/null; then
      continue
    fi
    if [[ "$opts" == *L* && -n "$v" ]] && ! luhn_ok "$(printf '%s' "$v" | tr -cd '0-9')"; then
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
# [０１２…] と列挙しても、C ロケールではバイトの集合として解釈されて別の文字に一致する。
# 選択（|）で並べれば、どのロケールでも「その文字の並び」として照合される。
ZD='(０|１|２|３|４|５|６|７|８|９)'
ZN="([0-9]|${ZD})"
ZH='(-|－|‐|−|ー)'

# --- 鍵・トークン ---------------------------------------------------------
check "JWT 形式のトークン" 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}'
# 接頭辞だけでは拾わない。報告書では「sb_publishable_... という鍵」のように
# 種類を説明するために接頭辞を書くことが正当にあるため、実際の鍵の長さがあるものだけを見る。
# 鍵の形は recon.sh（クライアントの JS に出た鍵）と同じ種類を見る。tests/run.sh が同じ見本の一覧を両方に当てて、
# 片方だけが拾う種類が無いことを確かめる（どちらかに足したら、もう一方と見本の一覧にも足す）
check "クラウド・決済の鍵（AWS・Azure・Stripe・Twilio・SendGrid・Mailgun）" \
      '\b((AKIA|ASIA)[0-9A-Z]{16}|(sk|pk|rk)_(live|test)_[0-9A-Za-z]{12,}|whsec_[0-9A-Za-z]{20,}|(AC|SK)[0-9a-f]{32}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|(Account|SharedAccess)Key=[A-Za-z0-9+/]{40,}={0,2}|key-[0-9a-f]{32})'
check "コード管理・パッケージのトークン（GitHub・npm）" \
      '\b(gh[pousr]_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{22,}|npm_[0-9A-Za-z]{30,})'
# Webhook の URL は、それだけで投稿できる鍵になる。ドメインは書かず、形で見る。
check "チャットの鍵と Webhook（Slack）" \
      '\b(xox[abeoprs]-[0-9A-Za-z-]{12,}|xapp-[0-9]+-[0-9A-Za-z-]{12,})|hooks\.slack\.[a-z]{2,6}/(services|workflows|triggers)/[A-Za-z0-9/_-]{16,}'
# OpenAI の旧形式（sk- ＋英数字 48）は区切りを含まない。区切りを含む英単語の連なり
# （task-management-... の「sk-」）に一致しないよう、\b と文字の種類で縛る。
# OpenRouter・Groq・xAI・Hugging Face・Replicate・Perplexity は、接頭辞のあとに実際の鍵の長さがあるものだけを見る
check "LLM の鍵（OpenAI・Anthropic・OpenRouter ほか）" \
      '\b(sk-((proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|ant-[a-z]+[0-9]*-[A-Za-z0-9_-]{20,}|or-v1-[A-Za-z0-9]{20,}|[A-Za-z0-9]{32,})|gsk_[A-Za-z0-9]{20,}|xai-[A-Za-z0-9]{20,}|(hf|r8)_[A-Za-z0-9]{30,}|pplx-[A-Za-z0-9]{30,})'
check "Google・Supabase の鍵" \
      '\b(AIza[0-9A-Za-z_-]{20,}|sb_(secret|publishable)_[0-9A-Za-z_-]{12,})|"type"[[:space:]]*:[[:space:]]*"service_account"' \
      "※ \"type\": \"service_account\" は GCP のサービスアカウントの鍵ファイル。中身ごと貼られていないか確認する"
# 角括弧の中の \t は「\ と t」の 2 文字になる（POSIX）。空白は [:space:] で書く。
# 認証情報を「<伏字>」に置き換えたもの（audit_grep.sh の出力を貼った形）は数えない。
# 認証情報の部分が見本（<伏字>・<ユーザー>:<パスワード>）や、テンプレートの差し込み（${user}・#{pw}・{{ pass }}・%(pw)s）の
# ものは、値ではないので外す
PH='(<[^>]+>|\$\{[^}]*\}|#\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s)'
check "接続文字列" '(postgres(ql)?|mysql|mongodb(\+srv)?|redis|rediss|amqps?)://[^[:space:]"'"'"'`]{8,}' "" "" "://${PH}(:${PH})?@"

# URL に埋め込んだ認証情報。「://<伏字>@」のように伏せたものは「:」を含まないので一致しない。
check "URL に埋め込んだ認証情報（user:pass@）" '[A-Za-z][A-Za-z0-9+.-]*://[^/:@[:space:]"'"'"'`<>]+:[^/@[:space:]"'"'"'`<>]+@' "" "" "://${PH}(:${PH})?@"
check "秘密鍵ブロック" '-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----'
check "Authorization ヘッダの値" \
      '(authorization["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?(bearer|basic|token)[[:space:]]+|bearer[[:space:]]+)[A-Za-z0-9._~+/-]{16,}=*' \
      "" i
# 引用符で囲んだ値は形を問わず見る（記号を含む値も。Python の b'…' のような接頭辞も許す）。引用符なし（.env、HAR、ログ）は、説明文の
# 「API_KEY=process.env.X」に一致しないよう、数字を含む 16 文字以上の並びだけを見る。
# 名前は KEY・SALT 単独も見る（実地の評価で、設定ファイルの KEY = b'…' と SECRET_KEY = '記号を含む値' を報告書に写したのを取りこぼした）。
# 差し込みの書き方と環境変数の読み出し（${…}・{{…}}・process.env・os.environ など）は値ではないので外す。
# credential(s) は鍵ファイルを base64 にして環境変数に入れる書き方（GOOGLE_CREDENTIALS_BASE64=…）に使われる
check "key/secret への値の代入" \
      '(api[_-]?key|secret|password|passwd|token|access[_-]?key|client[_-]?secret|salt|credentials?|(^|[^A-Za-z0-9])key)[A-Za-z0-9_]*["'"'"']?[[:space:]]*[:=][[:space:]]*([bruf]?["'"'"'`][^"'"'"'`<…[:space:]]{16,}|[A-Za-z0-9_/+=-]{6,}[0-9][A-Za-z0-9_/+=-]{6,})' \
      "※ 説明文の中の変数名は誤検出。値が書かれていないか確認する" i \
      '["'"'"'`](\$\{|#\{|\{\{|%\(|%s)|process\.env|os\.environ|getenv|ENV\[|import\.meta\.env'

# コードを引用したときや、文の中に書いたときに残る値。上の「代入」は 16 文字以上か数字の混ざった並びしか見ないので、
# bcrypt.hash('短い値', 10) や password: '短い値'、「同一のパスワード'短い値'で作成」を取りこぼす（実地の評価で、サンプルデータの共通パスワードを
# コードの引用ごと報告書に写した）。ハッシュ・署名・暗号化の関数の引数と、パスワードらしき名前への代入を見る。
# 伏字にしたもの（<伏字>・…）と、アルゴリズムや符号化の名前（'sha256'・'HS256' など）と、
# テンプレートや SQL の差し込み（'${…}'・'#{…}'・'{{…}}'・'%s'・'?'・':name'。値ではなく式）と、
# 括弧を含むもの（`crypto.createHash('md5')` のようなコードの引用）は外す
check "パスワード・鍵らしき値の直書き（関数の引数・短い値の代入）" \
      '((hash|compare|sign|encrypt|decrypt|createHmac|pbkdf2|scrypt|login|authenticate|signIn)[A-Za-z]*\([^)]{0,60}|(password|passwd|pwd|passphrase)[A-Za-z0-9_]*["'"'"']?[[:space:]]*[:=][[:space:]]*|(パスワード|暗証番号)(は|が|を|:|：)?[[:space:]]*)(["'"'"'`][^"'"'"'`<…[:space:]]{4,}["'"'"'`]|「[^」<…[:space:]]{4,}」)' \
      "※ コードを引用するときも、値は <伏字> にする（SKILL.md の守ること 3）" i \
      '["'"'"'`](sha-?[0-9]+|md5|hex|base64(url)?|utf-?8|ascii|latin1|binary|(HS|RS|ES|PS)(256|384|512)|none|aes-[0-9a-z-]+)["'"'"'`]|["'"'"'`](\$\{|#\{|\{\{|%\(|%s|\?|:[A-Za-z_])|(["'"'"'`]|「)[^"'"'"'`」]*\('

# 引用符も「」も無い文の中の値（「初期パスワードは ＜英数字の値＞ です」）。上の検査は囲んだ値しか見ない。
# 説明文（「パスワードは 12 文字以上」「パスワードは bcrypt で保存」「パスワードを 2026-09-29 に変更」）に一致しないよう、
# 6 文字以上で数字を含むものだけを数え、版・日付・アルゴリズムの名前は外す
check "パスワードらしき値（引用符の無い文）" \
      '(パスワード|暗証番号)(は|が|を|:|：)[[:space:]]*[A-Za-z0-9!#$%&*+./=?@^_~-]{6,}' \
      "※ 文の中に書いた値も <伏字> にする（SKILL.md の守ること 3）" "" \
      '(は|が|を|:|：)[[:space:]]*([^0-9]+|v?[0-9]+(\.[0-9]+)+|[0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}|[0-9]+(文字|桁)?|([Ss][Hh][Aa]|[Mm][Dd]|[Aa][Ee][Ss]|[Uu][Tt][Ff]|[Hh][Ss]|[Rr][Ss]|[Ee][Ss]|[Pp][Ss])-?[0-9]+|[Aa]rgon2(id|i|d)?|[Pp][Bb][Kk][Dd][Ff]2[A-Za-z0-9_-]*)$'

# パスワードのハッシュ。依頼者から返ってきた SQL の結果（利用者の表）を貼ると混ざる。
# ハッシュでも、弱いパスワードなら総当たりで元に戻せるので、成果物に置かない。
# bcrypt（$2a$ / $2b$ / $2y$）、Argon2、crypt の SHA-256 / SHA-512（$5$ / $6$）、Django の pbkdf2
check "パスワードのハッシュ（bcrypt・Argon2・crypt・PBKDF2）" \
      '\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}|\$argon2(id|i|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{8,}\$[A-Za-z0-9+/]{16,}|\$[56]\$(rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,}|pbkdf2_sha(1|256)\$[0-9]+\$[A-Za-z0-9]+\$[A-Za-z0-9+/=]{20,}' \
      "※ 利用者の表の問い合わせ結果を貼ったときに混ざる。件数と形式だけを書く"

# --- 個人情報 -------------------------------------------------------------
# GitHub の送信専用のアドレスと、SSH で取得するときの URL（git@github.com:…）は個人のアドレスではないので数えない
check "メールアドレス" '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
      "※ example.com / example.invalid / .test など、説明用の値なら問題ない（その場合はドメインを表示する）" e \
      '^(noreply|git)@github\.com$'
# 書き方の揺れ: 0X-XXXX-XXXX、ハイフンなし（10〜11 桁）、括弧付き、+81、全角
check "電話番号らしき並び" \
      "0[0-9]{1,4}-[0-9]{1,4}-[0-9]{3,4}|0[5789]0[0-9]{8}|0[1-9][0-9]{8}|\\(0[0-9]{1,4}\\)[[:space:]]?[0-9]{1,4}-?[0-9]{3,4}|0[0-9]{1,4}\\([0-9]{1,4}\\)[0-9]{3,4}|\\+81[[:space:]-]?\\(?0?[0-9]{1,4}\\)?[[:space:]-]?[0-9]{1,4}[[:space:]-]?[0-9]{3,4}|０${ZD}{1,4}${ZH}${ZD}{1,4}${ZH}${ZD}{3,4}|０${ZD}{9,10}" \
      "" d
# 16 桁（Visa / Mastercard / JCB など）と 15 桁（American Express: 34 / 37 で始まる 4-6-5）
check "クレジットカード番号らしき並び" \
      '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}' "" dL
# 年月日時分の 12 桁（202609251030）は日時として数えない
check "12 桁の数字の並び（マイナンバー等）" \
      "[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|${ZD}{4}( |　|－|-)?${ZD}{4}( |　|－|-)?${ZD}{4}" "" d \
      '^(19|20)[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])([01][0-9]|2[0-3])[0-5][0-9]$'
# 住所は「都道府県名 + 市区町村 + 数字」まで揃ったものだけを見る。
# 文字クラス（[都道府県]）で書くと 1 文字ずつの照合になり、無関係な日本語文に大量に一致する。
# 数字まで求めるのは、「都道府県と市区町村まではマスクする」のような説明文を拾わないため。
check "住所らしき記述" "(東京都|北海道|大阪府|京都府|[^ |、。＋+]{2,3}県)[^ |、。]{0,12}(市|区|町|村|郡)[^ |、。]{0,16}${ZN}"
# 都道府県を省いた住所。「区」「市」のあとに丁目・番地まで揃ったものだけを見る。
# 「区分 1-2」のような説明文に一致しないよう、「N丁目」か「N-N-N」の形を求める。
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

# 終了コードで結果を返す（先頭の説明を参照）。検出があれば 2、見ていないファイルだけなら 3
[[ $HITS -gt 0 ]] && exit 2
[[ ${#UNREAD[@]} -gt 0 ]] && exit 3
exit 0
