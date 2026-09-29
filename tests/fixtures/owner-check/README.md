# 題材: ID を受け取るハンドラの、持ち主の照合

`audit_grep.sh` の 2m 節の検査に使う。Express・Rails・Django・FastAPI の書き方を、架空の小さな例で並べる。
判定はハンドラの範囲（関数の定義・ルートの登録・装飾子から、次の定義の手前まで）ごとに行う。

- ★ になるべきもの（ID を読むのに、持ち主の照合が無い）
  - `routes.js:2` ログインだけ確かめて ID で取り出す
  - `routes.js:21` 本文の `id` で更新する
  - `routes.js:24` 現在の利用者を変数に入れて記録に使うだけ（空白を挟んだ代入は照合と数えない）
  - `orders_controller.rb:10` `params[:user_id]` で取り出す（受け取った ID の名前を持ち主の列と取り違えない）
  - `views.py:6` テンプレートに渡す辞書のキーの `"current_user"` を、現在の利用者の参照と数えない
  - `items.py:7` 複数行の装飾子の経路で ID を受け、現在の利用者を受け取るだけで比べない
  - `routes.js:38` ログインを確かめずに ID で取り出す（ログインを確かめているものの後に並ぶ）
  - `routes.js:34` slug で削除する（slug・uuid は書き換え・削除をするハンドラのときだけ数える）
- ★ にならないもの（照合がある）
  - `routes.js:6` 条件に `userId: req.user.id`、`routes.js:10` SQL の `owner_id = $2` と次の行の `req.user.id`、`routes.js:29` 誰にも通さない `denyAll()`
  - `orders_controller.rb:4` `current_user.orders.find`、`orders_controller.rb:13` `order.user_id == current_user.id`（Ruby の `@order` を装飾子と取り違えない）
  - `views.py:13` `owner=request.user`、`items.py:17` `item.owner_id != user.id`
- 並ばないもの: 本文の参照先の ID（`routes.js:17` の `roomId`）、`routes.js:30` 処理を別の関数に渡すだけの登録（本数だけ出す）、
  `routes.js:31` slug で読むだけ、`routes.js:40` 文中の `<chainId>`、`routes.js:41` 並べ替えの引数の `'id'`
