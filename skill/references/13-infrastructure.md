# インフラの定義（IaC・コンテナ・自前のサーバー）

**インフラを自分たちのリポジトリで定義しているとき**、または**自前のサーバー（VPS など）に載せているとき**に読む。

**マネージドの基盤に載せているだけなら、この資料は不要。** Vercel や Supabase のような
構成では、設定は管理画面にあり、コードには現れない。その場合は
`references/03-runtime-verification.md` で実機を見るほうが確実になる。

**要否の判定**は事前の洗い出しの 0 節に出る。次のどれかがあれば読む。

| 見つかったもの | 読む節 |
|---|---|
| `Dockerfile` / `docker-compose.yml` / `compose.yaml` | 2 |
| `*.tf` / `*.tfvars` / CloudFormation / CDK / Pulumi / Bicep（`*.bicep`） | 3 |
| Kubernetes のマニフェスト / Helm チャート | 4 |
| `serverless.yml` / SAM / `wrangler.toml` / `wrangler.json*` / SST（`sst.config.ts`） | 5 |
| PaaS の定義（`render.yaml` / `fly.toml` / `app.yaml` / `netlify.toml` / `vercel.json`） | 5 と 6 |
| `nginx.conf` / `Caddyfile` / systemd のユニット / ssh や rsync で配る配備の手順 | 7（compose があれば 2 も）。0 節には出ないので、配備先を取材で確かめる |

この資料は「AI で素早く作った構成で実際に空く穴」に絞ってある。設定項目を漏れなく見る必要があるとき（取引先が CIS 準拠を求めたときなど）は、
対象の製品の版に合った CIS Benchmark を使う（Level 1 が基本で、全部を適用するものではない）。

---

## 1. どこまでがコードで決まっているか

**最初にこれを確定させる。** インフラの一部だけがコードにあり、残りは手作業、という状態が多い。

定義ファイルの所在は、上の表の名前で探す（`find . -name 'Dockerfile*' -o -name '*.tf' …`）。

**コードに無い部分は、実機確認（03）で確かめる。** ここを曖昧にすると、「コードを読んだから設定も見た」という誤解が報告書に残る。
コードと実機がずれていることもあるので、**適用の履歴が追えるか**（実行ログ、`terraform plan` の差分）を聞いておく。

---

## 2. コンテナ

### 2-1. 実行時の権限

- **`USER` の指定が無ければ root で動く。** 侵入されたときに、コンテナ内で何でもできる。直し方は、最終段に `USER node` などの一般の利用者を書くこと
- `privileged: true`・広い `cap_add`・ホストのソケットやディレクトリ（特に `/var/run/docker.sock`）を渡していれば、ホスト側まで到達しうる
- **DB やキャッシュのポートを外へ公開していないか。** compose の `ports:` に `"5432:5432"` のように**待ち受けるアドレス無しで**
  書くと、ホストのすべてのインターフェースで待ち受け、サーバーが公開されていればインターネットから届く。
  Docker が公開したポートは、ホストの防火壁（ufw など）の規則より先に通されることがあるので、「ufw で閉じている」を根拠にしない。
  直し方は、コンテナ同士の通信だけなら `ports:` を消すこと。ホストから使うだけなら `"127.0.0.1:5432:5432"` と書く

```bash
grep -nE '^USER|privileged|cap_add|docker\.sock' Dockerfile* *compose*.y*ml 2>/dev/null
# 待ち受けるアドレスを書かずに公開しているポート（DB・キャッシュ・検索の既定のポートを先に見る）
grep -nE '^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+' docker-compose*.y*ml compose*.y*ml 2>/dev/null
grep -nE '"?(5432|3306|6379|27017|9200|11211):' docker-compose*.y*ml compose*.y*ml 2>/dev/null | grep -v '127\.0\.0\.1:'
```

### 2-2. イメージに焼き込まれたもの

**`ARG` と `ENV` に秘密情報を渡していないか。** ビルド引数はイメージの履歴に残り、`docker history` で読める。

```bash
grep -nE 'ARG .*(KEY|SECRET|TOKEN|PASSWORD)|ENV .*(KEY|SECRET|TOKEN|PASSWORD)' Dockerfile* 2>/dev/null
# 秘密らしいファイルを入れる行と消す行（後の RUN で消していれば、入れた層に残る）
grep -nE '^(COPY|ADD|RUN).*(\.env|\.npmrc|\.netrc|id_rsa|\.pem|\.key|credentials)' Dockerfile* 2>/dev/null
ls -la .dockerignore 2>/dev/null || echo "  .dockerignore が無い"
```

- **compose の `environment:`、`terraform.tfvars`、K8s の `ConfigMap` に書いた値は平文で、リポジトリにある。**
  値が `${DB_PASSWORD}` のような参照なら問題ない。値そのものが書かれていれば、秘密情報の入れ替え（`references/05-remediation-plan.md`）の対象になる
- **`.dockerignore` が無い**と、`.env`・`.git`・鍵ファイルがそのまま入る（`.git` が入れば履歴の秘密情報も配布される。C-2）
- **秘密のファイルを `COPY`・`ADD` で入れてから、後の `RUN` で消していないか。** 命令ごとに層ができ、後の層の削除は
  前の層の中身を消さない。イメージを取れば、入れた層から読める。直し方は、`RUN --mount=type=secret` で渡すこと
  （同じ `RUN` の中で書き出して消しても層に残らない）。多段ビルドの前の段で入れて消したものは、配るイメージには入らない

### 2-3. ベースイメージ

- **版が固定されているか。** `:latest` はビルドのたびに中身が変わり、何を監査したのかが言えなくなる。
  タグも差し替えられるので、確実なのは `FROM image@sha256:…` のダイジェスト固定（`grep -nE '^FROM' Dockerfile* | grep -v '@sha256:'`）
- 由来が確かなイメージか（個人が公開しているものを土台にしていないか）。更新の仕組みがあるか。**ベースイメージの脆弱性は、アプリを直さなくても増える**
- ビルドの中の依存のインストールは、`references/10-dependencies.md` の 3-1 と同じに見る（インストール時のスクリプト、`.npmrc` のトークン）

### 2-4. 使われていない・作れない定義

別の配備先に向けた名残の Dockerfile や compose、依存の版と合わずにもうビルドできない定義が、リポジトリに残っていることがある。

- **今の配備に使われていなければ、穴としては扱わない。** 削除するか、使い続けるなら更新することを、低い優先度で勧める
- **ただし、使われていないと決めつけない。** CI の定義・配備の手順・README・別の compose からその定義を参照していないかを確かめる。
  確かめられなければ判断保留にし、依頼者に「この定義で作ったイメージが今どこかで動いているか」を聞く
- 使われているなら、2-1〜2-3 の普通の指摘として扱う

---

## 3. クラウド資源の定義（Terraform / CloudFormation / CDK）

**見るのは 5 つ。** どれも「既定のまま」か、作りかけの設定のままで穴が空く。

### 3-1. 公開範囲

```bash
grep -rnE '0\.0\.0\.0/0|::/0|public|allUsers|publicly_accessible|PubliclyAccessible|http_tokens|HttpTokens|start_ip_address|source_address_prefix|authorized_networks|container_access_type|public_access_prevention' \
  --include='*.tf' --include='*.y*ml' --include='*.json' . 2>/dev/null | grep -v node_modules | head -30
```

- 全開放の受信規則（`0.0.0.0/0`）が、管理用のポート（SSH・RDP）や**DB・キャッシュのポート**
  （PostgreSQL 5432・MySQL 3306・Redis 6379・MongoDB 27017・Elasticsearch 9200）に付いていないか。
  直し方は、接続元を絞るか、DB を非公開のサブネットに置いてアプリからだけ届くようにすること
- **RDS などのマネージド DB に `publicly_accessible = true` が付いていないか。** 受信規則と組み合わさると、
  インターネットから DB へ直接つなげる。Terraform の `aws_db_instance` は書かなければ `false` だが、CloudFormation（RDS の API）は
  サブネットグループの指定によって既定が `true` になる。**CloudFormation では、書いていないことも確かめる**（事前の洗い出しの 17 節に、
  暗号化・公開・削除の保護・メタデータの方式を書いていない資源の候補が出る）
- **EC2 のインスタンスメタデータを IMDSv2 に限っているか**（Terraform は `metadata_options` の `http_tokens = "required"`、
  CloudFormation は `MetadataOptions` の `HttpTokens: required`）。指定が無ければ作成時の既定に任される。IMDSv1 が残っていると、
  アプリの SSRF（`references/07-web-vulnerabilities.md` の 5 節）からインスタンスの資格情報を取られやすくなる
- ストレージが公開読み取りになっていないか（`block_public_acls = false`、`AccessControl: PublicRead` など）。**意図した公開もある**（静的サイトの配信）ので、
  用途を確かめてから起票する。既定値は作成時期とプロバイダの版で違う（S3 は古いバケットなら作成日を確かめる）
- **Azure と Google Cloud も同じ考え方で確かめる。** DB の防火壁の範囲（Azure の `start_ip_address = "0.0.0.0"`・`end_ip_address = "255.255.255.255"`、
  Google Cloud の SQL の `authorized_networks` の `0.0.0.0/0`）、受信の規則（`source_address_prefix` が `*` か `Internet`）、
  ストレージの匿名の公開（`container_access_type` が `blob` か `container`、`public_access_prevention` が `enforced` でない）を見る。
  Azure の `0.0.0.0`〜`0.0.0.0` は「Azure のサービスを許可」で、ほかの契約者の資源からも届く。既定はプロバイダの版で変わるので、使っている版の資料で確かめる

### 3-2. 権限の広さ

```bash
# "Action": "*"・actions = ["*"]・サービス単位の "s3:*"・NotAction・iam:PassRole・管理者のロール
grep -rniE -e '"?(Action|Resource|actions|resources)"?[[:space:]]*[:=][[:space:]]*\[?[[:space:]]*"\*"' \
  -e '"[a-z0-9-]+:\*"|NotAction|not_actions|iam:PassRole|roles/(owner|editor)|AdministratorAccess' \
  --include='*.tf' --include='*.json' --include='*.y*ml' --include='*.ts' . 2>/dev/null | grep -v node_modules | head -20
```

並びを複数行に分けて書くと上の 1 行の検索では拾えないので、`Action`・`Resource` の並びを開いて読む。

**`*` の権限は、その資格情報が漏れたときの被害範囲そのものになる。** サービス単位の `"s3:*"` も、「列挙したもの以外すべて」を許す
`NotAction` も同じ重さで読む。`iam:PassRole` を `Resource: "*"` で持てば、より強いロールを別の資源に渡して動かせる。CI に渡す資格情報なら
`references/10-dependencies.md` の 3-3 と合わせて重い指摘になる。直し方は、使う操作（`s3:GetObject` など）と対象の資源の ARN を列挙すること。

### 3-3. 暗号化とログ

- 保管データの暗号化が有効になっているか。**RDS は Terraform（`storage_encrypted`）でも CloudFormation（`StorageEncrypted`）でも、
  書かなければ暗号化しない。** 作ったあとで切り替えられず、スナップショットからの作り直しになる（Azure Storage と Google Cloud は常に暗号化する）
- 監査ログ・アクセスログが有効で、保存期間が決まっているか。**無効なら、事故のときに何も分からない**（02 の G 節）

### 3-4. 状態ファイル

**`terraform.tfstate` には、生成された秘密情報が平文で入る。**

```bash
find . -name '*.tfstate*' -not -path '*/.git/*' 2>/dev/null
grep -rn 'backend "' --include='*.tf' . 2>/dev/null | head
git log --all --oneline -- '*.tfstate' 2>/dev/null | head
```

- リポジトリに入っていないか（**履歴に一度でも入っていれば、その中の秘密情報は失効させる必要がある**）。遠隔に置くなら、そのバケットが暗号化・非公開か
- 直し方は、`*.tfstate*` を `.gitignore` に入れ、暗号化した非公開のバケットを `backend` に指定し、中にあった秘密情報を入れ替えること

### 3-5. 消失への備え

**定義ファイルで管理している資源は、`terraform destroy` や定義の書き換え 1 回で消える。** 本番の DB が消されないように作られているかを見る。

```bash
grep -rnE 'backup_retention_period|BackupRetentionPeriod|skip_final_snapshot|deletion_protection|DeletionProtection|DeletionPolicy|prevent_destroy' \
  --include='*.tf' --include='*.y*ml' --include='*.json' . 2>/dev/null | head -20
```

- `backup_retention_period = 0` なら自動バックアップが無い（書いていなければ実機の保存期間を確かめる）。`skip_final_snapshot = true` なら、削除のときに最後のスナップショットを残さない
- `deletion_protection` が無いか `false` なら、削除の操作がそのまま通る。直し方は `deletion_protection = true` と `lifecycle { prevent_destroy = true }`（CloudFormation は `DeletionPolicy: Retain`）
- **バックアップが同じアカウントの中にしか無いか。** アカウントの資格情報が漏れれば、バックアップも一緒に消せる。
  復元を試したことがあるかは依頼者に聞く（`references/03-runtime-verification.md` の 4 節）

---

## 4. Kubernetes

該当する構成のときだけ見る。小〜中規模のアプリで実際に空くのは、次の形が多い。

- **`Secret` は base64 であって暗号化ではない。** マニフェストがリポジトリにあれば、そこに書かれた値は平文と同じ扱いになる
- ホストへ届く設定（`privileged: true`、`hostNetwork`・`hostPID`・`hostIPC`、`hostPath`、特にコンテナの実行環境のソケット）が、
  ログ収集などの基盤の部品以外に付いていないか。root で動いていないか
- 外からの入口が意図どおりか（Ingress に `tls:` があるか、`type: NodePort` で認証を通らずに届かないか）。`NetworkPolicy` が無ければどのポッドへも通る
- RBAC に `cluster-admin` や `verbs`・`resources` の `"*"` を付けていないか。API を呼ばないポッドは `automountServiceAccountToken: false` にする
- **Helm のチャートは、`values.yaml` の既定で権限が決まる。** テンプレートが値を差し込んでいれば、`values.yaml` の既定と、
  配備の手順で上書きする値（`-f`・`--set`）まで読む

```bash
grep -rnE '^[[:space:]]*(hostPID|hostIPC|hostNetwork|privileged):[[:space:]]*true|hostPath:|\.sock|cluster-admin|type:[[:space:]]*NodePort' \
  --include='*.y*ml' . 2>/dev/null | grep -vE ':[0-9]+:[[:space:]]*#' | grep -v node_modules | head -30
```

---

## 5. サーバーレスの定義

PaaS の定義（`render.yaml`・`fly.toml`・`app.yaml`・`netlify.toml`・`vercel.json`）も、環境変数の直書きと公開・内部のサービスの分け方をここで見る
（応答ヘッダやリダイレクトの設定は `references/07-web-vulnerabilities.md` の 4 節・7 節）。

- **関数ごとの権限が分かれているか。** 全関数に同じ広い権限を渡していないか
- 環境変数に秘密情報を直書きしていないか（**定義ファイルはリポジトリにある**）
- 公開する関数と、内部からのみ呼ぶ関数が分かれているか。**AWS Lambda の Function URL で `AuthType: NONE` は
  認証なしの公開**で、関数の中で認証していなければ誰でも呼べる。直し方は、内部から呼ぶだけなら `AWS_IAM` にすること。
  公開が必要なら、関数の冒頭でトークンや署名を検証する
- タイムアウトと同時実行数の上限。**無制限なら、費用が青天井になる**（02 の F 節）

```bash
# 認証なしで公開される関数の URL。Firebase の HTTP 関数は既定で公開なので、onRequest / onCall も数えて関数の中の認証を読む
grep -rnE 'AuthType.*NONE|authType:.*NONE|FunctionUrlAuthType|authorization_type[[:space:]]*=[[:space:]]*"NONE"|aws_lambda_function_url|^[[:space:]]*url:[[:space:]]*true|invoker:[[:space:]]*.?public|https\.onRequest\(|https\.onCall\(|onRequest\(|onCall\(' \
  --include='*.y*ml' --include='*.ts' --include='*.json' --include='*.tf' . 2>/dev/null | grep -v node_modules
```

---

## 6. マネージド構成の場合

**この資料の出番はほとんど無い。** `references/03-runtime-verification.md` の 5〜8 節（ネットワーク、鍵、環境の分離、エッジ・WAF）で実機を見る。
`.github/workflows/` はマネージド構成でもリポジトリにあるインフラの定義で、`references/10-dependencies.md` の 3-3 で見る。
**「IaC が無いこと」自体は指摘ではない。** 指摘になるのは、**誰が何を変えたか分からない**場合で、変更の記録と権限を持つ人を 03 で確かめる。

---

## 7. 自前のサーバー（VPS など）に載せている場合

compose と nginx を 1 台のサーバーに置く構成では、ホストそのものが攻撃面になる。ホストの確認（SSH・開いているポート・OS の更新・TLS の終端・バックアップの保存先）は
`references/03-runtime-verification.md` の 10 節の「自前のサーバー 1 台で動かしている場合」の表で依頼者に頼む。ここでは、リポジトリで読めるものを確かめる。

| 見ること | 問題ありにする形 | 直し方 |
|---|---|---|
| compose の `ports:` | DB・管理画面などを `0.0.0.0` で公開している。Docker が公開したポートは防火壁の規則より先に通る（2-1） | 2-1 のとおり `ports:` を消すか `127.0.0.1:` に絞る |
| nginx の設定 | HTTP のまま中身を返す `server` がある、アプリのポートを直接公開している | 80 番は HTTPS への転送だけにし、アプリは `127.0.0.1` で待ち受ける |
| 前段の転送 | nginx の後ろのアプリが、`X-Forwarded-For` を無条件に信じて回数制限や IP の判定に使う（02 の F-1） | 信頼する前段の数か IP を指定する（Express の `trust proxy` など） |

```bash
# nginx の設定（リポジトリにあるもの）。HTTP のまま返す server と、アプリへの転送の設定
grep -rnE 'listen[[:space:]]+80|return[[:space:]]+30[18]|ssl_protocols|proxy_pass|proxy_set_header|real_ip' \
  --include='*.conf' --include='Caddyfile' . 2>/dev/null | grep -v node_modules | head -20
```

---

## 指摘の書き方

**インフラの指摘は、コードの指摘より「直すと壊れる」危険が高い**（ネットワークを閉じたら本番が止まる）。

```markdown
| 事実 | 受信規則に 0.0.0.0/0 が 2 件。うち 1 件は管理用のポート（<path>:<line>） |
| 影響 | 資格情報が分かれば、どこからでも管理接続を試せる |
| 是正 | 接続元を絞る。**現在どこから接続しているかを先に調べる**必要がある。
        調べずに閉じると、正規の経路も止まる |
| 注意 | 適用のタイミングを依頼者と決める。無停止で切り替えられない |
```

**「先に調べること」を手順に書く。** これを書かない指摘は、実行されないか、事故になる。

**台帳の列との対応**（`references/04-findings-register.md`）: 「事実」は指摘事項、「影響」は想定される影響、「是正」と「注意」は是正案（注意は先頭に置く）。修正指示書では「戻し方」の欄を必ず埋める（`references/05-remediation-plan.md` の「戻し方」）。確認の方法は、定義ファイルなら「コード」、管理画面で作った資源なら「実機」か「依頼者の確認」。
