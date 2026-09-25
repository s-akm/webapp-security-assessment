# インフラの定義（IaC・コンテナ）

**インフラを自分たちのリポジトリで定義しているとき**に読む。

**マネージドの基盤に載せているだけなら、この資料は不要。** Vercel や Supabase のような
構成では、設定は管理画面にあり、コードには現れない。その場合は
`references/03-runtime-verification.md` で実機を見るほうが確実になる。

**要否の判定**は `scripts/audit_grep.sh` の 0 節が出す。次のどれかがあれば読む。

| 見つかったもの | 読む節 |
|---|---|
| `Dockerfile` / `docker-compose.yml` | 2 |
| `*.tf` / `*.tfvars` / CloudFormation / CDK / Pulumi | 3 |
| Kubernetes のマニフェスト / Helm チャート | 4 |
| `serverless.yml` / SAM / `wrangler.toml` | 5 |

**設定項目の網羅的な一覧は CIS Benchmarks にある。** この資料は「AI で素早く作った構成で
実際に空く穴」に絞ってあり、網羅を狙っていない。**取引先が CIS 準拠を求めてきたとき、または
自前ホスティングで設定項目を漏れなく見たいとき**は、対象の製品の版に合った Benchmark を
cisecurity.org から取る（Docker / Kubernetes / PostgreSQL / 各クラウドの版がある）。
**製品の版ごとに別の Benchmark**なので、対象の版を先に確かめる。Level 1 が基本、Level 2 が
より厳しい設定で、**全部を適用するものではない**（可用性や運用と衝突する項目がある）。

---

## 1. どこまでがコードで決まっているか

**最初にこれを確定させる。** インフラの一部だけがコードにあり、残りは手作業、という状態が多い。

```bash
# 定義ファイルの所在
find . \( -name 'Dockerfile*' -o -name 'docker-compose*.y*ml' -o -name '*.tf' \
       -o -name 'serverless.y*ml' -o -name 'template.y*ml' -o -name 'wrangler.toml' \
       -o -name 'Chart.yaml' -o -name 'cdk.json' -o -name 'Pulumi.yaml' \) \
  -not -path '*/node_modules/*' -not -path '*/.git/*' | head -30
```

**コードに無い部分は、実機確認に回す**（03）。ここを曖昧にすると、
「コードを読んだから設定も見た」という誤解が報告書に残る。

**コードと実機がずれていることもある。** 手で変えた設定は、次の適用で戻る。
**適用の履歴が追えるか**（実行ログ、`terraform plan` の差分）を聞いておく。

---

## 2. コンテナ

### 2-1. 実行時の権限

```bash
grep -nE '^USER|privileged|--privileged|cap_add|securityContext' \
  Dockerfile* docker-compose*.y*ml 2>/dev/null
```

- **`USER` の指定が無ければ root で動く。** 侵入されたときに、コンテナ内で何でもできる
- `privileged: true` や広い `cap_add` があれば、ホスト側まで到達しうる
- ホストのソケットやディレクトリを渡していないか（`/var/run/docker.sock` は特に危険）

### 2-2. イメージに焼き込まれたもの

**`ARG` と `ENV` に秘密情報を渡していないか。** ビルド引数はイメージの履歴に残る。
`docker history` で読める。**「ビルド時だけだから消える」は成り立たない。**

```bash
grep -nE 'ARG .*(KEY|SECRET|TOKEN|PASSWORD)|ENV .*(KEY|SECRET|TOKEN|PASSWORD)' Dockerfile* 2>/dev/null
# .dockerignore が無ければ .env や .git がイメージに入る
ls -la .dockerignore 2>/dev/null || echo "  .dockerignore が無い"
```

- **`.dockerignore` が無い**と、`.env`・`.git`・鍵ファイルがそのまま入る。
  `.git` が入れば、履歴に残った秘密情報も一緒に配布される（C-2 と同じ話になる）
- マルチステージビルドを使っていれば、最終段に開発用の道具が残っていないか

### 2-3. ベースイメージ

- **版が固定されているか。** `:latest` は、ビルドのたびに中身が変わる。
  何を監査したのかが言えなくなる（`references/10-dependencies.md` のロックファイルと同じ話）。
  **版のタグも差し替えられる**（2026-03 に、公式のセキュリティツールのイメージの既存タグが悪性版に
  置き換えられた）。確実なのは `FROM image@sha256:…` のダイジェスト固定
- ビルドの中で依存を入れるとき、`npm ci --ignore-scripts` などで**インストール時のスクリプトを止めているか**。
  `.npmrc` や `ARG NPM_TOKEN` でトークンをイメージに持ち込んでいないか
- 由来が確かなイメージか。個人が公開しているものを土台にしていないか
- 更新の仕組みがあるか。**ベースイメージの脆弱性は、アプリを直さなくても増える**

```bash
grep -nE '^FROM' Dockerfile* 2>/dev/null | grep -v '@sha256:'
grep -nE 'npm (install|ci)|COPY .*\.npmrc|ARG .*TOKEN' Dockerfile* 2>/dev/null
```

---

## 3. クラウド資源の定義（Terraform / CloudFormation / CDK）

**見るのは 4 つ。** どれも「既定のまま」で穴が空く。

### 3-1. 公開範囲

```bash
grep -rnE '0\.0\.0\.0/0|::/0|public|acl.*public-read|allUsers|allAuthenticatedUsers' \
  --include='*.tf' --include='*.y*ml' --include='*.json' . 2>/dev/null | head -20
```

- 全開放の受信規則（`0.0.0.0/0`）が、管理用のポートに付いていないか
- ストレージが公開読み取りになっていないか
- **意図した公開もある**（静的サイトの配信）。用途を確かめてから起票する
- **既定値は作成時期で違う。** AWS の S3 は 2023-04 以降に作ったバケットだけ、公開ブロックが有効・ACL 無効が既定になった。
  それより前からあるバケットは変わっていないので、作成日を確かめる

### 3-2. 権限の広さ

```bash
grep -rnE '"Action"[[:space:]]*:[[:space:]]*"\*"|"Resource"[[:space:]]*:[[:space:]]*"\*"|roles/owner|Admin' \
  --include='*.tf' --include='*.json' . 2>/dev/null | head -20
```

**`*` の権限は、その資格情報が漏れたときの被害範囲そのものになる。**
CI に渡している資格情報が広い権限を持っていれば、`references/10-dependencies.md` の
3-3 と合わせて重い指摘になる。

### 3-3. 暗号化とログ

- 保管データの暗号化が有効になっているか（既定で無効な資源がある）
- 監査ログ・アクセスログが有効か。**無効なら、事故のときに何も分からない**（02 の G 節）
- ログの保存期間が決まっているか

### 3-4. 状態ファイル

**`terraform.tfstate` には、生成された秘密情報が平文で入る。**

```bash
find . -name '*.tfstate*' -not -path '*/.git/*' 2>/dev/null
grep -rn 'backend "' --include='*.tf' . 2>/dev/null | head
git log --all --oneline -- '*.tfstate' 2>/dev/null | head
```

- リポジトリに入っていないか。**履歴に一度でも入っていれば、その鍵は失効が要る**
- 遠隔に置いている場合、そのバケットが暗号化・非公開になっているか

---

## 4. Kubernetes

該当する構成のときだけ見る。

- **`Secret` は base64 であって暗号化ではない。** マニフェストがリポジトリにあれば、
  そこに書かれた値は平文と同じ扱いになる
- `securityContext` — root で動いていないか、特権が付いていないか
- **`NetworkPolicy` があるか。** 無ければ、どのポッドからどのポッドへも通る
- RBAC の広さ。`cluster-admin` を配っていないか
- リソース制限（`limits`）があるか。無ければ 1 つのポッドで全体が落ちる

---

## 5. サーバーレスの定義

`serverless.yml` / SAM / `wrangler.toml` などがある場合。

- **関数ごとの権限が分かれているか。** 全関数に同じ広い権限を渡していないか
- 環境変数に秘密情報を直書きしていないか（**定義ファイルはリポジトリにある**）
- 公開する関数と、内部からのみ呼ぶ関数が分かれているか。**AWS Lambda の Function URL で `AuthType: NONE` は
  認証なしの公開**で、関数の中で認証していなければ誰でも呼べる
- タイムアウトと同時実行数の上限。**無制限なら、費用が青天井になる**（02 の F 節）

```bash
# 認証なしで公開される関数の URL（SAM / CloudFormation / CDK / Terraform / Serverless Framework / Firebase）。
# Firebase の HTTP 関数は invoker を書かなければ公開になるので、明示の public だけでなく onRequest / onCall も数え、
# 関数の中で認証しているかを読む
grep -rnE 'AuthType.*NONE|authType:.*NONE|FunctionUrlAuthType|authorization_type[[:space:]]*=[[:space:]]*"NONE"|aws_lambda_function_url|^[[:space:]]*url:[[:space:]]*true|invoker:[[:space:]]*.?public|https\.onRequest\(|https\.onCall\(|onRequest\(|onCall\(' \
  --include='*.y*ml' --include='*.ts' --include='*.json' --include='*.tf' . 2>/dev/null | grep -v node_modules
```

---

## 6. マネージド構成の場合

**この資料の出番はほとんど無い。** 設定は管理画面にあり、コードには現れない。
**ただし `.github/workflows/` は例外。** CI の定義は秘密情報と本番への権限を持つインフラの定義で、
マネージド構成でもリポジトリにある。`references/10-dependencies.md` の 3-3 で見る。
`references/03-runtime-verification.md` の 5〜8 節（ネットワーク、鍵、環境の分離、
エッジ・WAF）で実機を見る。

**「IaC が無いこと」自体は指摘ではない。** 小規模なら管理画面で足りる。
指摘になるのは、**誰が何を変えたか分からない**場合になる。変更の記録が残るか、
権限を持つ人が誰かを 03 で確かめる。

---

## 指摘の書き方

**インフラの指摘は、コードの指摘より「直すと壊れる」危険が高い。**
ネットワークを閉じたら本番が止まった、という形が起きる。

```markdown
| 事実 | 受信規則に 0.0.0.0/0 が 2 件。うち 1 件は管理用のポート（<path>:<line>） |
| 影響 | 資格情報が分かれば、どこからでも管理接続を試せる |
| 是正 | 接続元を絞る。**現在どこから接続しているかを先に調べる**必要がある。
        調べずに閉じると、正規の経路も止まる |
| 注意 | 適用のタイミングを依頼者と決める。無停止で切り替えられない |
```

**「先に調べること」を手順に書く。** これを書かない指摘は、実行されないか、事故になる。
