# 評価するエージェント（claude -p）に与える許可。run-eval.sh と probe-permissions.sh が読み込む（source）。
#
#   eval_permission_args <エージェントに見せる置き場> <出力の置き場>
#     PERM_ARGS に claude の引数を入れる。作業ディレクトリ（題材。スキルもこの中に置く）は呼ぶ側が cd で決める
#
# 読めるのは、エージェントに見せる置き場（ws/。題材と事前の洗い出しの出力だけを置く）にする。答えの一覧（出力の置き場の answers.json）は読ませない。
# ws/ 全体を --add-dir で渡す。事前の洗い出しの置き場だけを渡すと、エージェントが題材と洗い出しの共通の親（ws/）に cd してファイルの一覧を
# 取る命令が拒否され、一覧を取れないまま洗い出しに名前の出たファイルだけを読む（2026-10-14 の実測で、5 つのファイルを開かず 12 件を見落とした）
# - Read・Grep・Glob をパスの指定なしで許すと、作業場所の外まで読める（2.29.0 まではそうだった）。何も許さなければ、
#   作業ディレクトリと --add-dir の中だけを読める
# - Bash の読むだけの命令（grep・find・cat など）は、許す規則を書かなくても、作業ディレクトリと --add-dir の中なら通り、
#   外を指すと拒否される（CLI 2.1.299 で確かめた。この版から Grep・Glob の道具が無く、検索は Bash で行う）。
#   Bash(cat *) のような規則はパスで絞れず、外も読めるようになるので書かない
# - 出力の置き場を読む Read は、拒否の規則でも止める。パスは /var と /private/var のように書き方が分かれるので、実体のパスでも並べる。
#   Grep(…)・Glob(…) の形の拒否は書かない（パス付きの規則を受け付けない版では、道具ごと使えなくなるおそれがある）
# CLI を更新したら probe-permissions.sh で確かめ直す（数セントかかる）
eval_permission_args() {
  local ws="$1" out="$2" out_real
  out_real="$(cd "$out" && pwd -P)"
  PERM_ARGS=(
    --add-dir "$ws"
    --permission-mode dontAsk
    # 許すのはスキルと、事前の洗い出しのスクリプトだけ。書き込み・ネットワーク・下位のエージェントは止める
    --allowedTools Skill "Bash(bash *audit_grep.sh*)"
    --disallowedTools WebFetch WebSearch Write Edit NotebookEdit Agent
      "Read(/$out/**)" "Read(/$out_real/**)"
  )
}
