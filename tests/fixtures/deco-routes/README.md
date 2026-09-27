# 題材: 装飾子・注釈で書くルート

`audit_grep.sh` の 2f 節の検査に使う。NestJS・Spring・ASP.NET・FastAPI・Flask の書き方を、架空の小さな例で並べる。

- `items.controller.ts`（NestJS）: 3 行目は認可あり。11 行目は、複数行の装飾子をはさんだ上に認可がある（認可ありと読むべきもの）。
  14 行目は認可なし。17 行目は内部向けのパス（★）
- `AdminController.java`（Spring）: クラスに付いた認可（クラス単位で認可あり）
- `OrdersController.cs`（ASP.NET）: 4 行目は認可あり、8 行目は明示的に公開、12 行目は認可なし
- `api.py`（FastAPI・Flask）: 1 行目は処理の宣言の引数に認可（Depends）。5 行目は認可なし。9 行目は下の装飾子に認可
