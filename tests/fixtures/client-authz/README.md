# 題材: 権限や更新の範囲を、利用者が送った値で決める書き方

`audit_grep.sh` の 2g 節の検査に使う。NestJS・Express・Rails・Django・Spring の書き方を、架空の小さな例で並べる。

- 権限を示す値をリクエストから読む（★ になるべきもの）: `photos.controller.ts:4` の `@Query('isAdmin')`、`routes.js:2` の `req.body.role`、
  `users_controller.rb:4` の `params[:admin]`、`views.py:2` の `request.data.get('is_staff')`、`AccountController.java:2` の `@RequestParam("role")`
- 受け取ったものをそのまま渡す（候補に並ぶべきもの）: `photos.controller.ts:15` の `update(…, body)`、`routes.js:6` の `Object.assign(…, req.body)`、
  `users_controller.rb:8` の `permit!`、`views.py:6` の `update(**request.data)`
- 並んではいけないもの: `photos.controller.ts:9` の `@Query('page')`、`routes.js:9` の `req.query.name`
