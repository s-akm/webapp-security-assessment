# 題材: アンカーの表による題材の前処理

`tests/eval/prep_anchors.py` の検査に使う、架空の小さなアプリと表。特定の教材を写したものではない。

- `target/app/server.js` の 4 行目は、穴の種類を言うコメント（消えるべきもの）
- 5 行目は答えの行。行末のコメントは手掛かりの語を含まないので残る
- 8 行目の URL の中の `//` はコメントではない（手掛かりの語 weak を含んでも、コードを壊さない）
- `target/docs/` は答えの置き場（消えるべきもの）

表（`spec.json`）は題材の写しの外に置く（写しの中に置くと、表の中の語が消し残しに見える）。
- `target/app/routes.ts` の run の処理は、答えを範囲（8〜12 行目）で持つ例（until）
- `target/app/routes.desc.ts` は、ワイルドカードで消すファイルの例
- `target/app/header.html.erb` の 2〜4 行目は、複数行にまたがる手掛かりのコメント（行数を保って消えるべきもの）。6 行目のコメントは残る
- `target/app/service.ts` の launch は、run の答えに、危ない処理をする本体として範囲（2〜5 行目）を足す例（アンカーごとの until）
- 同じファイルの 7 行目の文は、正規表現で置き換える例（replace_regex。行は保つ）

基盤とモバイルの題材で見つかった穴の例（コメントの記法の表・名前の手掛かり・全ファイルの確かめ）:

- `target/infra/main.tf`・`target/mobile/AndroidManifest.xml`・`target/mobile/build.gradle`・`target/config/app.yaml` は、
  以前の拡張子の表に無いか、コメントを消していなかった種類。手掛かりのコメント（YAML は行末のもの）が行を保って消えるべきもの
- `target/Dockerfile` は名前で、`target/bin/start` は 1 行目の `#!` で、`target/config/settings.yml.example` と
  `target/app/notes.js.backup` は内側の拡張子で記法を引く例。`target/app/views/list.ejs` はテンプレートのコメント
- `target/app/report.ts` の 2〜3 行目は、2 行目にだけ手掛かりの語（`VULN:`）がある説明の段落。段落ごと消えるべきもの（paragraph_hint_regex）
- `training-build-7` は、ファイルを指定しない正規表現の置き換え（replace_regex_everywhere）で、ロックファイルも含めて置き換わるべきもの
- `target/mobile/vulnerable_cache/` と `target/mobile/SqlInjectionScreen.kt` は、名前に手掛かりがある例（rename）。答えの場所は新しいパスに移り、
  `import` とマニフェストの登録も新しい名前になるべきもの
- `target/app/service.ts` の 6〜8 行目は、2 回目に一致した行から続く 3 行と、別のアンカーの続く 2 行を 1 つの答えにまとめる例（lines・nth。重なる行は 1 つにする）。
  場所を持たない範囲外の答えと、答えの一覧に写す注記（note）の例も表にある
- 表の replace の 2 つ目（`app/server.js` の 4 行目の一節）は、手掛かりのコメントを消す段で先に消える。置き換えの外れとして止めない例
- `target/mobile/src/vulnerable_lab/notes/` は、別の階層へ名前を変える例。空になった元の親（`vulnerable_lab`）が消えるべきもの
- `target/deploy/token.yaml` は、base64 の値の中の語を置き換える例（replace_base64）と、平文と base64 の中から値を集める例（secrets_regex）。
  値は架空のもの
- 表の keep（下の階層の 1 つのディレクトリだけを残す）は、検査が表を書き換えて確かめる
- `target/package-lock.json.fixture` の依存の非推奨の注記は、消し残しの語を含むが、ロックファイルの中身なので止めない例。
  依存関係グラフに拾わせないよう `.fixture` を付けて置き、検査が `fixture_cp` で写すときに外す
