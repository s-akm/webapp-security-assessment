# 題材: 成果物・Action の版・道具の版の扱い

`tests/run.sh` の事前の洗い出し（20 節）の検査に使う。ワークフローは動かない。

- `build.yml`: checkout が資格情報を残したまま、作業ツリーを成果物に上げるジョブ
  - 穴のある側: 隠しファイルも上げる古い upload-artifact、`include-hidden-files: true`、版が分からない参照（複数行の path）
  - 咎めない側: `persist-credentials: false`、ビルドの出力だけを上げる、checkout の無いジョブ
  - ★ を付けずに並べる側: 隠しファイルを既定で除く版
- `deps.yml`: 既知の勧告がある版の Action（タグ、ハッシュの後ろの版の注記、系列の全体が範囲に入る動くタグ）と、範囲の外の版
- `tools.yml`: Action の入力で道具を latest で入れる行と、版を固定した行
