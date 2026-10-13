#!/usr/bin/env python3
"""アンカーの表から答えの一覧を作り、答えの手掛かりを消す（題材に依らない前処理）。

  prep_anchors.py <表.json> <写しのディレクトリ> <答えの一覧の出力先.json>

題材ごとの中身は、すべて表（手元の tests/eval/local/ に置く。公開しない）に書く。
表のパスは、すべて写しのプロジェクトルートから、名前を変える前のパスで書く。

  {
    "require": ["challenges.md"],            写しが正しい題材かの確かめ。無ければ止める
    "items": [                               答え。anchors は (ファイル, そのファイルの中の一節)
      {"id": "sqli-login", "basis": "課題 2", "category": "Injection", "scope": "in",
       "anchors": [["server.js", "`SELECT * FROM users WHERE email = '${email}'`"]]},
      {"id": "cmd", "anchors": [["src/app.controller.ts", "@Get('spawn')"]],
       "until": "^\\s*@(Get|Post|Put|Delete|Patch|All)\\("}   範囲で持つ。アンカーの行から、次に until に
    ],                                                          一致する行の手前まで（無ければファイルの終わりまで）
    "remove": ["challenges.md", "docs", "src/**/*.desc.ts"],  答えや手順が書いてあるもの。消す（* と ** を使える）
    "paragraph_hint_regex": "VULN|…",        これを含む行があれば、続いたコメントの行のまとまり（段落）ごと消す（行は保つ）
    "hint_regex": "vulnerab|injection|…",    これを含むコメントだけを消す（行は保つ）
    "residual_regex": "vulnerab|…",          消したあとに残ってはいけない語。中身とファイル・ディレクトリの名前を見る。残れば止める
    "replace": [["package.json", "古い文", "新しい文"]],   コメント以外に残る性格の文（そのファイルだけ）
    "replace_everywhere": [["古い語", "新しい語"]],         識別子などに残るもの（全ファイル）
    "replace_regex": [["src/x.ts", "正規表現", "置き換え"]],  形で見つけて置き換える（そのファイルだけ。1 行ずつ当て、行は保つ）
    "replace_regex_everywhere": [["正規表現", "置き換え"]],   同じことを全ファイルに当てる。どこにも一致しなければ止める
    "blank_lines": [["database/init.sh", "正規表現"]],     一致する行を空にする（行は保つ）
    "rename": [["app/sqli_demo", "app/search"]],           名前に手掛かりがあるファイル・ディレクトリの名前を変える（下の「名前を変える」）
    "secrets": ["題材に埋め込まれた値"]      結果に写していれば違反として数える（score.py）
  }

答えの項目には、次も書ける。
  アンカーの 3 つ目     そのアンカーだけの until（[ファイル, 一節, 正規表現]）。穴の入口（ハンドラ）と、危ない処理をする本体
                       （別のファイルのサービスなど）を 1 つの答えに並べるとき、範囲の終わりの決め方が違うため。
                       書くなら、その項目のアンカーはすべて範囲で持つ（項目の until か、アンカーごとの until）
  "control": true      対照（正しく作ってあり、指摘してはいけない箇所）。score.py が誤検出として数え、見つけた数の分母に入れない
  "viewpoint": "02 E"  観点の網羅表（coverage.py）での振り分け先。書かなければ category から決める

答えの場所は、アンカーを写しの中で探して決める。見つからなければ止める（題材のコミットを上げてコードが
変わったときに、黙ってずれないため）。手掛かりは、行番号を保ったまま消す（答えの行と評価者が見る行を一致させる）。

コメントの消し方は、ファイルの種類ごとの記法の表（SUFFIX_SYNTAX・NAME_SYNTAX）で決める。拡張子で引き、拡張子の無い
ファイルは名前（Dockerfile など）で引く。写しの名前（.example・.backup など）は内側の拡張子で引き、どれにも無ければ
1 行目の #! で決める。表に無い種類のファイルに手掛かりの語（hint_regex・paragraph_hint_regex）が残っていれば止める
（コメントを消せないまま黙って通さないため。表に記法を足すか、replace・remove で扱う）。

名前を変える（rename）: ファイルかディレクトリを、新しいパスへ動かす。答えの場所のパスは新しいパスに移し、行番号は変えない。
ほかのファイルからの参照（import・マニフェストの登録・パス）も同じ規則で置き換える。ディレクトリなら名前、ファイルなら
拡張子を除いた名前を、識別子の一部でない（前後が英数字と _ でない）ところだけ、すべての文字のファイルで新しい名前にする。
置き換えで行の数は変わらない。

調べるファイル: 写しの中の、UTF-8 で読めるファイルすべて（拡張子を問わない）。外すのは、.git と node_modules の中、
シンボリックリンク、バイナリ（NUL を含むか UTF-8 で読めない）だけ。ロックファイル（LOCKFILES）は、中身を消し残しの確かめと
コメントの消去から外し、全体の置き換えと名前の確かめには含める（理由は LOCKFILES の注記）。
"""
import json
import os
import pathlib
import re
import shutil
import sys

# --- コメントの記法 -------------------------------------------------------------------------------
# 1 行の中のコメント。// は行頭か区切りの後だけ（URL の https:// を拾わない）。/* */ と {/* */} は 1 行に収まるもの
SLASH = [re.compile(r'(^|(?<=[\s;,)\]}]))//.*$'), re.compile(r'\{?/\*.*?\*/\}?')]
HASH = [re.compile(r'(^|\s)#.*$')]
DASH = [re.compile(r'(^|\s)--.*$')]
SEMI = [re.compile(r'(^|\s);.*$')]
BANG = [re.compile(r'^\s*!.*$')]
# 複数行にまたがるコメント。手掛かりの語を含めば、行数を保ったまま中身を空にする
XML_BLOCK = re.compile(r'<!--.*?-->', re.S)
C_BLOCK = re.compile(r'/\*.*?\*/', re.S)
ERB_BLOCK = re.compile(r'<%#.*?%>', re.S)
RUBY_BLOCK = re.compile(r'^=begin\b.*?^=end\b', re.S | re.M)
JINJA_BLOCK = re.compile(r'\{#.*?#\}', re.S)
# 画面と処理が混ざる種類（HTML を文字列で持つ言語・テンプレート）は、4 つの形をすべて見る
BLOCKS = [XML_BLOCK, C_BLOCK, ERB_BLOCK, RUBY_BLOCK]
# コメントを持たない形式。手掛かりは replace と消し残しの確かめで扱う（表に無い種類とは分ける）
NO_COMMENT = ([], [])

# 記法の表（拡張子）。値は（1 行の中のコメント, 複数行にまたがるコメント）
SUFFIX_SYNTAX = {
    **dict.fromkeys(('.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.go', '.java', '.kt', '.cs', '.rs', '.swift',
                     '.css', '.scss', '.erb', '.ejs', '.vue', '.svelte'), (SLASH, BLOCKS)),
    '.php': (SLASH + HASH, BLOCKS),
    **dict.fromkeys(('.html', '.htm'), (SLASH, BLOCKS + [JINJA_BLOCK])),
    **dict.fromkeys(('.rb', '.rake', '.gemspec', '.ru', '.podspec', '.jbuilder'), (HASH, BLOCKS)),
    **dict.fromkeys(('.py', '.pyi', '.sh', '.bash', '.zsh', '.ex', '.exs', '.yml', '.yaml', '.toml', '.conf', '.env',
                     '.r', '.pl', '.mk', '.dockerfile'), (HASH, [])),
    **dict.fromkeys(('.tf', '.hcl', '.tfvars'), (HASH + SLASH, [C_BLOCK])),
    **dict.fromkeys(('.kts', '.gradle', '.groovy', '.dart', '.scala', '.c', '.h', '.cc', '.cpp', '.hpp', '.m', '.mm',
                     '.proto', '.jsonc', '.less'), (SLASH, [C_BLOCK])),
    '.sql': (DASH, [C_BLOCK]),
    '.lua': (DASH, []),
    '.properties': (HASH + BANG, []),
    **dict.fromkeys(('.ini', '.cfg'), (HASH + SEMI, [])),
    **dict.fromkeys(('.xml', '.wsdl', '.xsd', '.plist', '.svg', '.xhtml', '.storyboard', '.xib', '.csproj', '.xaml',
                     '.md', '.markdown'), ([], [XML_BLOCK])),
    **dict.fromkeys(('.j2', '.jinja', '.jinja2', '.twig', '.njk'), ([], [JINJA_BLOCK, XML_BLOCK])),
    **dict.fromkeys(('.json', '.txt', '.csv', '.tsv', '.log'), NO_COMMENT),
}
# 記法の表（拡張子の無いファイルの名前。小文字で引く）
NAME_SYNTAX = {
    **dict.fromkeys(('dockerfile', 'containerfile', 'makefile', 'gnumakefile', 'gemfile', 'rakefile', 'podfile',
                     'vagrantfile', 'brewfile', 'fastfile', 'appfile', 'procfile', 'codeowners', 'requirements.txt',
                     '.gitignore', '.dockerignore', '.npmignore', '.gitattributes', '.editorconfig', '.htaccess', '.env',
                     '.npmrc', '.yarnrc'), (HASH, [])),
    **dict.fromkeys(('.coveragerc', '.pylintrc', '.flake8'), (HASH + SEMI, [])),
    'jenkinsfile': (SLASH, [C_BLOCK]),
    **dict.fromkeys(('license', 'licence', 'copying', 'notice', 'authors', 'readme', 'changelog'), NO_COMMENT),
}
# 名前の頭で引くもの（Dockerfile.dev・.env.local など）
NAME_PREFIX_SYNTAX = (('dockerfile.', (HASH, [])), ('containerfile.', (HASH, [])), ('.env.', (HASH, [])))
# 写しや控えに付く拡張子。内側の拡張子で引く（config.yml.example・server.js.backup）
WRAPPERS = ('.example', '.sample', '.dist', '.template', '.orig', '.bak', '.backup', '.old')

# --- 調べるファイル -------------------------------------------------------------------------------
SKIP_DIRS = {'.git', 'node_modules'}
# 依存の一覧を道具が書き出したもの（ロックファイル）。中身の大半は依存の名前・取得元・整合性の値と、登録所が付けた
# 依存の注記（「古い版には広く知られた脆弱性がある」のような非推奨の文）で、題材の作者が書いた文ではない。消し残しの確かめと
# コメントの消去からは外す（題材の Node.js の教材で、依存の非推奨の文が消し残しの語に一致した）。全体の置き換え
# （replace_everywhere・replace_regex_everywhere・rename の参照）には含める。題材自身の名前は package.json と同じく先頭に書かれるので、
# 置き換えから外すとロックファイルにだけ元の名前が残る。ファイルの名前は消し残しの確かめに含める
LOCKFILES = {'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'composer.lock',
             'gemfile.lock', 'poetry.lock', 'pipfile.lock', 'cargo.lock', 'go.sum', 'packages.lock.json', 'podfile.lock',
             'pubspec.lock', 'mix.lock', 'gradle.lockfile'}


def syntax_of(name, first_line=''):
    """ファイルの名前（か拡張子）から、コメントの記法を引く。表に無ければ None"""
    n = name.lower()
    if n in SUFFIX_SYNTAX:   # 拡張子だけを渡したとき
        return SUFFIX_SYNTAX[n]
    if n in NAME_SYNTAX:
        return NAME_SYNTAX[n]
    for pre, syn in NAME_PREFIX_SYNTAX:
        if n.startswith(pre):
            return syn
    base, suf = os.path.splitext(n)
    while suf in WRAPPERS:
        if base in NAME_SYNTAX:
            return NAME_SYNTAX[base]
        base, suf = os.path.splitext(base)
    if suf in SUFFIX_SYNTAX:
        return SUFFIX_SYNTAX[suf]
    if first_line.startswith('#!'):
        return (HASH, [])
    return None


def read_text(p):
    """UTF-8 で読めるファイルの中身。バイナリ（NUL を含むか UTF-8 で読めない）なら None"""
    try:
        b = p.read_bytes()
    except OSError:
        return None
    if b'\0' in b:
        return None
    try:
        return b.decode('utf-8')
    except UnicodeDecodeError:
        return None


def walk(root):
    """写しの中のファイルとディレクトリ（.git と node_modules の中を除く）"""
    for p in sorted(root.rglob('*')):
        if not SKIP_DIRS & set(p.relative_to(root).parts):
            yield p


def text_files(root, locks=False):
    """拡張子を問わず、UTF-8 で読めるファイルすべて（シンボリックリンクと、locks が偽ならロックファイルを除く）"""
    for p in walk(root):
        if p.is_file() and not p.is_symlink() and (locks or p.name.lower() not in LOCKFILES) and read_text(p) is not None:
            yield p


def write_same_lines(p, text, before):
    if text.count('\n') != before.count('\n'):
        sys.exit(f'行の数が変わる書き換え: {p}（表を直す）')
    p.write_text(text, encoding='utf-8')


def strip_hint_blocks(text, hint, blocks=BLOCKS):
    """手掛かりの語を含む複数行のコメントを、改行だけを残して消す（行番号を保つ）"""
    def blank(m):
        return '\n' * m.group(0).count('\n') if hint.search(m.group(0)) else m.group(0)
    for pat in blocks:
        text = pat.sub(blank, text)
    return text


def strip_hint_comments(line, kind, hint):
    """手掛かりの語を含むコメントだけを消す。コードとほかのコメントは残す。kind は拡張子かファイルの名前か記法"""
    for pat in (syntax_of(kind) or NO_COMMENT)[0] if isinstance(kind, str) else kind[0]:
        for m in list(pat.finditer(line)):
            if hint.search(m.group(0)):
                line = line[:m.start()] + line[m.end():]
    return line.rstrip() if line.strip() else ''


XML_LINE = re.compile(r'^\s*<!--.*-->\s*$')


def comment_only(line, syn):
    """コメントだけの行か"""
    for pat in syn[0]:
        m = pat.search(line)
        if m and not line[:m.start()].strip() and not line[m.end():].strip():
            return True
    return XML_BLOCK in syn[1] and bool(XML_LINE.match(line))


def blank_hint_paragraphs(lines, syn, hint):
    """続いたコメントの行のまとまり（段落）に手掛かりの語が 1 つでもあれば、段落ごと空にする。2 行目以降に語の無い説明を残さない"""
    n, i = 0, 0
    while i < len(lines):
        j = i
        while j < len(lines) and comment_only(lines[j], syn):
            j += 1
        if j > i and any(hint.search(l) for l in lines[i:j]):
            for k in range(i, j):
                lines[k] = ''
            n += j - i
        i = max(j, i + 1)
    return n


def moved(rel, old, new):
    """名前を変えたあとのパス"""
    if rel == old or rel.startswith(old + '/'):
        return new + rel[len(old):]
    return rel


def rename(root, old, new):
    """ファイルかディレクトリの名前を変え、ほかのファイルからの参照も同じ規則で置き換える。置き換えたファイルの数を返す"""
    src, dst = root / old, root / new
    if not src.exists():
        sys.exit(f'名前を変える対象が無い: {old}（題材のコミットが変わった。表を直す）')
    if dst.exists():
        sys.exit(f'名前を変える先が既にある: {new}')
    old_tok = src.name if src.is_dir() else src.stem
    new_tok = dst.name if src.is_dir() else dst.stem
    if '\n' in new or not new_tok:
        sys.exit(f'名前を変える先が正しくない: {new!r}')
    dst.parent.mkdir(parents=True, exist_ok=True)
    src.rename(dst)
    if old_tok == new_tok:
        return 0
    rx = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(old_tok) + r'(?![A-Za-z0-9_])')
    n = 0
    for p in text_files(root, locks=True):
        t = read_text(p)
        t2 = rx.sub(lambda m: new_tok, t)
        if t2 != t:
            write_same_lines(p, t2, t)
            n += 1
    return n


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    spec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
    root = pathlib.Path(sys.argv[2]).resolve()
    out = pathlib.Path(sys.argv[3])
    for rel in spec.get('require', []):
        if not (root / rel).exists():
            sys.exit(f'{rel} が無い: {root}（表と題材が合っていないか、前処理済み）')

    # 1. アンカーから答えの場所を決める（手掛かりを消す前。行番号は消した後も変わらない）
    items = []
    for it in spec['items']:
        locs, ranges = [], []
        item_until = re.compile(it['until']) if it.get('until') else None
        for a in it['anchors']:
            rel, anchor = a[0], a[1]
            until = re.compile(a[2]) if len(a) > 2 else item_until
            lines = (root / rel).read_text(encoding='utf-8').split('\n')
            hits = [i for i, l in enumerate(lines, start=1) if anchor in l]
            if not hits:
                sys.exit(f'アンカーが見つからない: {rel}: {anchor}（題材のコードが変わった。表を直す）')
            if until:
                # 処理の範囲で持つ。指摘は処理の本文の中を指すことが多く、アンカーの 1 行からは離れるため
                end = next((i - 1 for i in range(hits[0] + 1, len(lines) + 1) if until.search(lines[i - 1])), len(lines))
                ranges.append({'file': rel, 'start': hits[0], 'end': end})
            else:
                locs.append({'file': rel, 'line': hits[0]})
        if locs and ranges:
            # 採点は行で持つ答えなら範囲を見ないので、混ぜると範囲の側が黙って使われない
            sys.exit(f'{it["id"]}: 行で持つアンカーと範囲で持つアンカーが混ざっている（アンカーごとの until を揃える）')
        row = {'id': it['id'], 'keys': [it.get('basis', it['id'])], 'name': it.get('basis', ''),
               'category': it.get('category', ''), 'scope': it.get('scope', 'in'), 'locations': locs, 'ranges': ranges}
        for k in ('control', 'viewpoint'):
            if k in it:
                row[k] = it[k]
        items.append(row)

    # 2. 手掛かりのコメントを消す（段落ごと → 複数行のコメント → 1 行の中のコメント）。記法は種類ごとの表で引く
    para = re.compile(spec['paragraph_hint_regex'], re.I) if spec.get('paragraph_hint_regex') else None
    hint = re.compile(spec['hint_regex'], re.I) if spec.get('hint_regex') else None
    stripped = 0
    if hint or para:
        for p in text_files(root):
            t = read_text(p)
            syn = syntax_of(p.name, t.split('\n', 1)[0])
            if not syn:
                continue   # 表に無い種類。消せないので、最後に手掛かりの語が残っていないかを確かめる
            lines = t.split('\n')
            if para:
                blank_hint_paragraphs(lines, syn, para)
            t2 = '\n'.join(lines)
            if hint and syn[1]:
                t2 = strip_hint_blocks(t2, hint, syn[1])
            lines = t2.split('\n')
            if hint and syn[0]:
                lines = [strip_hint_comments(l, syn, hint) if hint.search(l) else l for l in lines]
            t2 = '\n'.join(lines)
            if t2 != t:
                stripped += sum(1 for a, b in zip(t.split('\n'), lines) if a != b)
                write_same_lines(p, t2, t)

    # 3. コメント以外に残る性格の文
    for rel, old, new in spec.get('replace', []):
        f = root / rel
        if f.is_file():
            f.write_text(f.read_text(encoding='utf-8').replace(old, new), encoding='utf-8')
    for old, new in spec.get('replace_everywhere', []):
        for p in text_files(root, locks=True):
            t = read_text(p)
            if old in t:
                p.write_text(t.replace(old, new), encoding='utf-8')
    for rel, pattern, new in spec.get('replace_regex', []):
        f = root / rel
        if not f.is_file():
            sys.exit(f'replace_regex の対象が無い: {rel}')
        rx = re.compile(pattern)
        before = f.read_text(encoding='utf-8').split('\n')
        after = [rx.sub(new, l) for l in before]
        if after == before:
            sys.exit(f'replace_regex が一致しない: {rel}: {pattern}（題材のコードが変わった。表を直す）')
        f.write_text('\n'.join(after), encoding='utf-8')
    for pattern, new in spec.get('replace_regex_everywhere', []):
        rx, hit = re.compile(pattern), 0
        for p in text_files(root, locks=True):
            before = read_text(p).split('\n')
            after = [rx.sub(new, l) for l in before]
            if after != before:
                hit += 1
                write_same_lines(p, '\n'.join(after), '\n'.join(before))
        if not hit:
            sys.exit(f'replace_regex_everywhere がどのファイルにも一致しない: {pattern}（題材のコードが変わった。表を直す）')
    for rel, pattern in spec.get('blank_lines', []):
        f = root / rel
        if f.is_file():
            rx = re.compile(pattern, re.I)
            f.write_text('\n'.join('' if rx.search(l) else l for l in f.read_text(encoding='utf-8').split('\n')),
                         encoding='utf-8')

    # 4. 答えや手順が書いてあるファイルを消す
    for rel in spec.get('remove', []):
        for t in (list(root.glob(rel)) if any(c in rel for c in '*?[') else [root / rel]):
            if t.is_dir():
                shutil.rmtree(t)
            elif t.exists():
                t.unlink()

    # 5. 名前に手掛かりがあるファイル・ディレクトリの名前を変える。答えの場所のパスも移す（行番号は変わらない）
    renamed = 0
    for old, new in spec.get('rename', []):
        renamed += rename(root, old.strip('/'), new.strip('/'))
        for row in items:
            for loc in row['locations'] + row['ranges']:
                loc['file'] = moved(loc['file'], old.strip('/'), new.strip('/'))

    # 記法の表に無い種類のファイルに、手掛かりの語が残っていないか（コメントを消せないまま黙って通さない）
    unknown = []
    for rx in (x for x in (para, hint) if x):
        for p in text_files(root):
            t = read_text(p)
            if syntax_of(p.name, t.split('\n', 1)[0]) is None:
                unknown += [f'{p.relative_to(root).as_posix()}:{i}' for i, l in enumerate(t.split('\n'), start=1) if rx.search(l)]
    if unknown:
        sys.exit('コメントの記法の表に無い種類のファイルに、手掛かりの語を含む行がある（prep_anchors.py の表に記法を足すか、'
                 '表の replace・remove で扱う）: ' + ' '.join(sorted(set(unknown))[:10]))

    # 消し残しの確認（中身と、ファイル・ディレクトリの名前）
    if spec.get('residual_regex'):
        residual = re.compile(spec['residual_regex'], re.I)
        left = []
        for p in walk(root):
            if residual.search(p.name):
                left.append(f'{p.relative_to(root).as_posix()}（名前）')
        for p in text_files(root):
            s = read_text(p)
            left += [f'{p.relative_to(root).as_posix()}:{i}' for i, l in enumerate(s.split('\n'), start=1) if residual.search(l)]
        if left:
            sys.exit('手掛かりの消し残しがある: ' + ' '.join(left[:10]))

    data = {'target': spec.get('name', ''), 'secrets': spec.get('secrets', []), 'items': items}
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    n_in = sum(1 for x in items if x['scope'] == 'in' and not x.get('control'))
    n_ctl = sum(1 for x in items if x.get('control'))
    print(f'答え {len(items) - n_ctl} 件（範囲内 {n_in} 件）・対照 {n_ctl} か所／手掛かりのコメントを消した行 {stripped}'
          + (f'／名前を変えて参照を置き換えたファイル {renamed}' if spec.get('rename') else ''))


if __name__ == '__main__':
    main()
