#!/usr/bin/env python3
"""アンカーの表から答えの一覧を作り、答えの手掛かりを消す（題材に依らない下拵え）。

  prep_anchors.py <表.json> <写しのディレクトリ> <答えの一覧の出力先.json>

題材ごとの中身は、すべて表（手元の tests/eval/local/ に置く。公開しない）に書く。

  {
    "require": ["challenges.md"],            写しが正しい題材かの確かめ。無ければ止める
    "items": [                               答え。anchors は (ファイル, そのファイルの中の一節)
      {"id": "sqli-login", "basis": "課題 2", "category": "Injection", "scope": "in",
       "anchors": [["server.js", "`SELECT * FROM users WHERE email = '${email}'`"]]}
    ],
    "remove": ["challenges.md", "docs"],     答えや手順が書いてあるもの。消す
    "hint_regex": "vulnerab|injection|…",    これを含むコメントだけを消す（行は保つ）
    "residual_regex": "vulnerab|…",          消したあとに残ってはいけない語。残れば止める
    "replace": [["package.json", "古い文", "新しい文"]],   コメント以外に残る性格の文（そのファイルだけ）
    "replace_everywhere": [["古い語", "新しい語"]],         識別子などに残るもの（全ファイル）
    "blank_lines": [["database/init.sh", "正規表現"]],     一致する行を空にする（行は保つ）
    "secrets": ["題材に埋め込まれた値"]      結果に写していれば違反として数える（score.py）
  }

答えの場所は、アンカーを写しの中で探して決める。見つからなければ止める（題材のコミットを上げてコードが
変わったときに、黙ってずれないため）。手掛かりは、行番号を保ったまま消す（答えの行と評価者が見る行を一致させる）。
"""
import json
import pathlib
import re
import shutil
import sys

TEXT_SUFFIXES = {'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.erb', '.php', '.go', '.java', '.kt',
                 '.cs', '.rs', '.ex', '.exs', '.swift', '.json', '.sql', '.sh', '.yml', '.yaml', '.toml', '.html',
                 '.css', '.scss', '.md', '.example', '.txt', '.conf', ''}
# コメントを消す対象（設定や文書はコメントの書き方が揃わないので、残り語の確かめだけにする）
CODE_SUFFIXES = {'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.rb', '.erb', '.php', '.go', '.java', '.kt',
                 '.cs', '.rs', '.ex', '.exs', '.swift', '.sql', '.sh', '.css', '.scss'}
# コメントの形。// は行頭か区切りの後だけ（URL の https:// を拾わない）。/* */ と {/* */} は 1 行に収まるもの
SLASH = [re.compile(r'(^|(?<=[\s;,)\]}]))//.*$'), re.compile(r'\{?/\*.*?\*/\}?')]
HASH = [re.compile(r'(^|\s)#.*$')]
DASH = [re.compile(r'(^|\s)--.*$')]
COMMENTS = {'.sql': DASH, '.sh': HASH, '.py': HASH, '.rb': HASH, '.ex': HASH, '.exs': HASH}


def text_files(root):
    for p in root.rglob('*'):
        if p.is_file() and not p.is_symlink() and 'node_modules' not in p.parts and '.git' not in p.parts \
                and p.suffix.lower() in TEXT_SUFFIXES and p.name != 'package-lock.json':
            yield p


def strip_hint_comments(line, suffix, hint):
    """手掛かりの語を含むコメントだけを消す。コードとほかのコメントは残す"""
    for pat in COMMENTS.get(suffix, SLASH):
        for m in list(pat.finditer(line)):
            if hint.search(m.group(0)):
                line = line[:m.start()] + line[m.end():]
    return line.rstrip() if line.strip() else ''


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    spec = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
    root = pathlib.Path(sys.argv[2]).resolve()
    out = pathlib.Path(sys.argv[3])
    for rel in spec.get('require', []):
        if not (root / rel).exists():
            sys.exit(f'{rel} が無い: {root}（表と題材が合っていないか、下拵え済み）')

    # 1. アンカーから答えの場所を決める（手掛かりを消す前。行番号は消した後も変わらない）
    items = []
    for it in spec['items']:
        locs = []
        for rel, anchor in it['anchors']:
            lines = (root / rel).read_text(encoding='utf-8').split('\n')
            hits = [i for i, l in enumerate(lines, start=1) if anchor in l]
            if not hits:
                sys.exit(f'アンカーが見つからない: {rel}: {anchor}（題材のコードが変わった。表を直す）')
            locs.append({'file': rel, 'line': hits[0]})
        items.append({'id': it['id'], 'keys': [it.get('basis', it['id'])], 'name': it.get('basis', ''),
                      'category': it.get('category', ''), 'scope': it.get('scope', 'in'), 'locations': locs, 'ranges': []})

    # 2. 手掛かりのコメントを消す
    hint = re.compile(spec['hint_regex'], re.I) if spec.get('hint_regex') else None
    stripped = 0
    if hint:
        for p in text_files(root):
            if p.suffix.lower() not in CODE_SUFFIXES:
                continue
            try:
                lines = p.read_text(encoding='utf-8').split('\n')
            except UnicodeDecodeError:
                continue
            new = [strip_hint_comments(l, p.suffix.lower(), hint) if hint.search(l) else l for l in lines]
            if new != lines:
                stripped += sum(1 for a, b in zip(lines, new) if a != b)
                p.write_text('\n'.join(new), encoding='utf-8')

    # 3. コメント以外に残る性格の文
    for rel, old, new in spec.get('replace', []):
        f = root / rel
        if f.is_file():
            f.write_text(f.read_text(encoding='utf-8').replace(old, new), encoding='utf-8')
    for old, new in spec.get('replace_everywhere', []):
        for p in text_files(root):
            try:
                t = p.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
            if old in t:
                p.write_text(t.replace(old, new), encoding='utf-8')
    for rel, pattern in spec.get('blank_lines', []):
        f = root / rel
        if f.is_file():
            rx = re.compile(pattern, re.I)
            f.write_text('\n'.join('' if rx.search(l) else l for l in f.read_text(encoding='utf-8').split('\n')),
                         encoding='utf-8')

    # 4. 答えや手順が書いてあるファイルを消す
    for rel in spec.get('remove', []):
        t = root / rel
        if t.is_dir():
            shutil.rmtree(t)
        elif t.exists():
            t.unlink()

    # 消し残しの確認
    if spec.get('residual_regex'):
        residual = re.compile(spec['residual_regex'], re.I)
        left = []
        for p in text_files(root):
            try:
                s = p.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
            left += [f'{p.relative_to(root).as_posix()}:{i}' for i, l in enumerate(s.split('\n'), start=1) if residual.search(l)]
        if left:
            sys.exit('手掛かりの消し残しがある: ' + ' '.join(left[:10]))

    data = {'target': spec.get('name', ''), 'secrets': spec.get('secrets', []), 'items': items}
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    n_in = sum(1 for x in items if x['scope'] == 'in')
    print(f'答え {len(items)} 件（範囲内 {n_in} 件）／手掛かりのコメントを消した行 {stripped}')


if __name__ == '__main__':
    main()
