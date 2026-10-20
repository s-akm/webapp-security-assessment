# 依存関係とサプライチェーン

`references/02-code-audit.md` の H 節を深掘りするための資料。**依存の数が多い案件**、**スキャンで high 以上が出た案件**、**CI から本番へ自動で出る構成**で読む。
**AI で作ったアプリ（このスキルの主な対象）では、依存が少なく high が出ていなくても、3-2（名前の紛らわしい依存）と 3-5（エージェントの設定）は見る。**

## この観点の位置づけ

依存の脆弱性は、**指摘としては挙がりやすく、優先度は上がりにくい。** `npm audit` が 30 件出しても、その多くはビルド時にしか使わない依存や、到達しない経路にある。件数をそのまま重大さとして書くと、SKILL.md の「指摘を数で競わない」に反する。

**この節で本当に見るのは 3 つ。**

1. **到達する脆弱性が今あるか**（件数ではなく、経路があるか）
2. **検知の仕組みがあるか**（今日 0 件でも、半年後は分からない）
3. **他人のコードが本番に入る経路がどれだけあるか**（依存の追加、CI、第三者スクリプト）

3 番が本来のサプライチェーンの論点で、いちばん見落とされる。

---

## 1. 到達する脆弱性があるか

**まずスキャンを実行する。**

```bash
npm audit --omit=dev                  # 本番依存だけに絞る
pip-audit -r requirements.txt         # Python。-r を付けないと、評価者のシェルの Python 環境を監査して 0 件を出す
bundle-audit check --update           # Ruby。--update で勧告の一覧を取り直す（古い一覧のままだと新しい勧告が出ない）
govulncheck ./...                     # Go。到達性まで見てくれる
```

`--omit=dev` を付けるかどうかで件数が大きく変わる。**両方取って、差を書く。**

**ロックファイルからエコシステムを決め、それに合う道具で見る。** npm の道具だけで見ると、他のロックファイルの依存は 1 件も照合されない。

| ロックファイル | エコシステム | スキャン |
|---|---|---|
| `package-lock.json` | npm | `npm audit` |
| `pnpm-lock.yaml` | pnpm | `pnpm audit` |
| `yarn.lock` | yarn | `yarn audit`（1 系）・`yarn npm audit`（2 系以降） |
| `bun.lock` / `bun.lockb` | bun | OSV の照合（`osv-scanner`）でその形式を読めるかを確かめる。読めなければ未確認事項に残す |
| `requirements.txt`・`uv.lock`・`poetry.lock`・`Pipfile.lock` | Python | `pip-audit -r <requirements 形式のファイル>`。uv なら `uv export --format requirements-txt` で書き出してから渡す |
| `Gemfile.lock` | Ruby | `bundle-audit check --update` |
| `go.sum` | Go | `govulncheck ./...` |
| `composer.lock` | PHP | `composer audit` |
| `Cargo.lock` | Rust | `cargo audit` |
| `packages.lock.json`・`gradle.lockfile`・`pom.xml` | .NET・Java / Kotlin | `dotnet list package --vulnerable --include-transitive`、Java は OSV の照合か組織の SCA の道具 |

**npm の `package-lock.json` が無いことを、ロックファイルが無いことと読まない**（2 節）。bun・pnpm・yarn のロックファイルがあれば、それが正になる。

| 出たもの | どう扱うか |
|---|---|
| 本番依存に high 以上 | **経路を確かめてから起票する。** その関数を実際に呼んでいるか |
| 開発依存だけに high | 本番には入らないので、`references/04-findings-register.md` の問い 1〜3 には該当しない。CI や開発機で動き、そこにある秘密情報に届く経路（3 節）を 3 行で書ければ問い 5 で P1、他の条件と組み合わせて成立するなら問い 6 で P2、どちらも無ければ P4 |
| moderate 以下 | 1 件ずつは起票しない。到達する経路を具体的に書けるものだけを、04 の問いで優先度を引いて起票する。残りは件数を「仕組み」の行（下の「指摘の書き方」）に添える |
| 修正版が出ていない | 見送りの候補。**代替の緩和策があるかを書く** |

**「呼んでいるか」を確かめずに起票しない。** 脆弱な関数を含むライブラリを入れていても、その関数を使っていなければ到達しない。逆に、使っていれば優先度は一段上がる。

**例外は、枠組み本体の脆弱性。** フレームワークやホスティングの層に穴があると、
アプリのコードが正しくても成立する。この種は「呼んでいるか」で判定できないので、
**版が該当するかどうかで判定する**。認証・認可の枠組みに関わるものは、
`references/04-findings-register.md` の問い 1 に当たりうる（P0 の候補。実例は `references/02-code-audit.md` の A-5）。
版はロックファイルの解決結果で確かめ、勧告は枠組みの公式の勧告を評価の時点で見る。
**事前の洗い出しが照合する既知の勧告の表は、照合した日より後の勧告を含まない。** 表に無いことを、該当しない根拠にしない。

```bash
# 枠組みの版を、ロックファイル側の実際の解決結果で確認する
grep -m1 -A2 '"node_modules/next"' package-lock.json 2>/dev/null
npm ls next react vue svelte 2>/dev/null | head
# 該当ライブラリをどこで使っているか
grep -rn "require('<lib>')\|from '<lib>'" --include='*.ts' --include='*.js' .
# 依存木のどこから来ているか（直接依存か、他の依存が連れてきたか）
npm ls <lib>
```

`npm ls` の結果は指摘の書き方を変える。**直接依存なら上げるだけ**、**他の依存が連れてきたものなら親を上げる必要がある**（あるいは上げられない）。
親を上げられなければ、`overrides`（yarn は `resolutions`）で間接依存の版を修正版に固定するのが標準の手段になる。

**他の依存が連れてきたもの（間接依存）は、上の grep では到達を判定できない。** アプリは間接依存を直接 import しないので、
grep が 0 件でも「呼んでいない」にはならない。勧告に書かれた「影響する機能・関数」を、**親の依存がその機能を使っているか**、
アプリが親のその機能を呼んでいるかで判定する。**判定できなければ、到達するものとして扱う。**

### 1-2. 「実際に悪用されているか」で優先度を分ける

スキャンが出す深刻度（CVSS）は**理論上の重さ**で、**実際に攻撃に使われているか**とは別になる。
優先度を決めるときは、次の情報源で確かめる。

| 情報源 | 何が分かるか | 使い方 |
|---|---|---|
| **CISA KEV**（Known Exploited Vulnerabilities） | **実際に悪用が確認された脆弱性**の公式カタログ。CVE 単位 | スキャンで出た CVE がここにあれば、**CVSS にかかわらず少なくとも P1**。公開資産で、認証なしに届き全制御を許すものは P0（`references/04-findings-register.md` の「悪用が確認されていれば上げる」） |
| GitHub Security Advisories | パッケージ単位の公式勧告。**マルウェアの勧告もここに載る**（CVE が付かないことが多い） | 修正版の有無と、GHSA から CVE・EPSS への引き直し |
| EPSS | 今後 30 日に悪用される確率の推定（FIRST） | KEV に無いものの順位づけ |
| OSV | 各エコシステムの勧告を束ねたもの。**悪性パッケージは `MAL-` で始まる ID** | `osv-scanner` でロックファイルを直接照合できる |
| **JVN iPedia** | 国内の脆弱性対策情報（JPCERT/CC と IPA が運営）。日本語 | 国内製品・国内向けの補足。**依頼者への説明に日本語の一次情報として引ける** |
| JPCERT/CC 注意喚起・IPA 重要なセキュリティ情報 | **国内で影響が大きいもの**への警告 | **評価の最初と最後**に、対象の構成に当たるものが無いかを見る |
| 枠組み自身のアドバイザリ | Next.js / Rails / Django などの公式の勧告 | **枠組み本体の脆弱性**（1 節の例外）はここで版を確かめる |

**KEV との照合は、勧告を CVE に引き直してから行う。** `npm audit --json` の出力には CVE 番号が無く GHSA の URL しか無いので、
CVE で直接照合すると、どんな結果でも「該当なし」になる。GHSA から CVE と EPSS へは GitHub の勧告 API（`gh api /advisories/<GHSA>`）で引ける。
`pip-audit -f json` は勧告の別名に CVE を持つ。**開発依存も含めて照合する**（開発依存は CI と開発機で動く。3-3）。
**判定の順は KEV → EPSS → CVSS。** CVE の付かない勧告（マルウェアの勧告など）は KEV と照合できないので、別に目で見る。

**KEV には依存パッケージだけでなく、CI の Action やツール自体の侵害も載る。** `.github/workflows` の `uses:` も同じように照合する。
**逆に、載っていないことは安全の根拠にならない**（大規模な npm の侵害でも KEV に載らなかったものがある）。

**KEV に載っていることは「今すぐ」の根拠になる。** 載っていない high は「到達性を確かめてから」（1 節）でよい。
**この区別を台帳に書く**と、依頼者が順序を納得しやすい。

**注意喚起は評価の最後にもう一度見る。** 評価に数週間かかると、その間に新しい勧告が出る。
報告書の日付の時点で、対象の構成に当たる注意喚起が無いかを確かめてから出す。

## 2. 検知の仕組みがあるか

**件数より、こちらのほうが指摘として重い。** 今日 0 件でも、依存は勝手に脆弱になる。

- CI にスキャンが入っているか。入っていなければ、誰も見ていない
- 依存更新の自動検知（Dependabot / Renovate）があるか。Dependabot は **3 つを分けて聞く**:
  セキュリティ更新、バージョン更新、**悪性パッケージのアラート（opt-in）**。`npm audit` は悪性パッケージを検知しないので、
  最後の 1 つが無ければ「乗っ取られた版が入っても気づく仕組みが無い」と書ける
- **通知の宛先が生きているか。** 設定されていても、誰も見ていないリポジトリの通知は無いのと同じ
- ロックファイル（`package-lock.json` / `yarn.lock` / `poetry.lock`）がコミットされているか

**直し方。** CI に依存のスキャン（`npm audit --omit=dev` や `osv-scanner`）を入れ、Dependabot か Renovate のセキュリティ更新と悪性パッケージのアラートを有効にし、通知を誰が受けるかを決める。

**ロックファイルがあっても、ビルドで使われているとは限らない。** CI やホスティングのビルドが `npm install` を
使っていると、ロックファイルと食い違えば書き換えて進む。`npm ci`（pnpm なら `--frozen-lockfile`）を使っているかを見る。
**Vercel の既定は `npm install`** なので、`vercel.json` の `installCommand` まで見る。
ロックファイルの `resolved` が公式レジストリ以外（git、任意の URL の tarball）を指していないかも見る。

```bash
grep -rnE 'npm (install|i)( |$)|npm ci|--frozen-lockfile|installCommand' .github/workflows vercel.json package.json 2>/dev/null
grep -nE '"resolved": "' package-lock.json 2>/dev/null | grep -v 'registry.npmjs.org' | head
```

**ロックファイルが無い場合は、それ自体が指摘になる。** ビルドのたびに解決される版が変わり、「動いていたものが動かなくなる」「監査した版と本番の版が違う」が起きる。何を監査したのかが言えなくなる。

```bash
ls package-lock.json yarn.lock pnpm-lock.yaml bun.lock bun.lockb poetry.lock uv.lock Pipfile.lock Gemfile.lock \
  go.sum composer.lock Cargo.lock packages.lock.json gradle.lockfile 2>/dev/null
git log -1 --format=%cr -- <見つかったロックファイル>    # 最後に更新されたのはいつか
```

どれか 1 つがあれば、そのエコシステムのロックファイルはある（1 節の表）。**`package-lock.json` だけを探して「無い」と書かない。**

**ロックファイルが必要かは、パッケージの定義との組で決める。** 依存を宣言した定義（`package.json` の `dependencies`、`pyproject.toml`、
`requirements.txt`、`Gemfile`、`composer.json`、`Cargo.toml`、`pubspec.yaml`、`Podfile` など）が無ければ、ロックファイルが無いことは指摘にならない
（IaC だけのリポジトリなど）。エコシステムごとに扱いが違うものがある。

- **Go** は指摘にならない。`go.mod` が版を決め、最小版選択は新しい版が出ても結果が変わらない（`go.sum` は照合用）
- **Python の `requirements.txt`** は、すべてを `==` で固定していればロックの代わりになる。範囲で書いていれば指摘
- **Gradle・Maven・.NET** はロックが任意か無い。**動的な版**（`1.+`・`latest.release`・`[1.0,2.0)`・`LATEST`・`RELEASE`・NuGet の `4.*`。バージョンカタログの中も含む）を書いていて、ロックが無ければ指摘

## 3. 他人のコードが本番に入る経路

**ここがサプライチェーンの本体。** 依存の脆弱性は「入っているコードに穴がある」話だが、こちらは「意図しないコードが入る」話になる。

### 3-1. インストール時に走るスクリプト

`npm install` は、依存パッケージの `postinstall` を実行する。**依存を 1 つ足すと、他人のスクリプトが開発機と CI で走る。**

```bash
# インストール時にスクリプトが走る依存の数と名前（preinstall / install / binding.gyp も含めてロックファイルに記録されている）
grep -c '"hasInstallScript": true' package-lock.json 2>/dev/null
awk '/^[[:space:]]*"node_modules\//{k=$1} /"hasInstallScript": true/{gsub(/[":]/,"",k); sub(/^node_modules\//,"",k); print k}' package-lock.json 2>/dev/null | head -30
```

**`hasInstallScript` は npm の lockfile v2 以降にしか入らない。** pnpm・yarn・bun と npm の lockfile v1 では上の数が 0 になるので、**0 を「無い」と読まない。**
pnpm は `pnpm-lock.yaml` の `requiresBuild: true` を数え、無ければ既にある `node_modules` の各 `package.json` の `scripts` を見る。
**数えるために依存を入れない**（入れた時点でスクリプトが走る）。数えられなければ「判定不能」と書いて未確認事項に残す。

**パッケージマネージャの新しい版は、依存のスクリプトを既定で実行せず、許可したものだけを動かす方向にある。**
**ただし本番のビルドで動いているのが古い版なら、この保護は働かない。** 見るのは手元の設定ではなく、ホスティングや CI のビルドで何の版が動いているか。

**公開直後の版を入れない設定（クールダウン）があるか。** 乗っ取られた版は、公開から取り下げまで数時間のことが多い。数日の待機でその大半を避けられる。

```bash
grep -nE 'ignore-scripts|min-release-age|allow-(git|remote|scripts)|dangerously-allow-all-scripts|^registry' .npmrc 2>/dev/null
grep -c '_authToken' .npmrc 2>/dev/null   # 数だけ見る。値は出さない。1 以上ならトークンがリポジトリにある
grep -nE '"(allowScripts|overrides|resolutions|packageManager)"' package.json
grep -nE 'minimumReleaseAge|allowBuilds|onlyBuiltDependencies|dangerouslyAllowAllBuilds|blockExoticSubdeps' pnpm-workspace.yaml package.json 2>/dev/null
grep -n 'cooldown' .github/dependabot.yml 2>/dev/null
```

**`overrides` / `resolutions` があれば、中身を読む。** 間接依存の版を強制する仕組みで、脆弱性の回避に使うのが普通だが、
逆向きにも使える。**古い版への固定**（修正版より前の版に留めている。上げた後で外し忘れたものも含む）と、
**取得元の差し替え**（フォークの git リポジトリや任意の URL の tarball を指す）を探す。どちらも、なぜそうしたかがコミットや
コメントに無ければ、依頼者に聞く。

候補は事前の洗い出しの 21 節に出る。

**既知の乗っ取られた版がロックファイルに入っていないか**も見る。入っていたら、
**その版が入ったビルド環境と開発機の秘密情報はすべて漏れたものとして扱う**（入れ替えと、露出していた期間の悪用の調査までを是正に書く。タスクの型は `references/05-remediation-plan.md` の「秘密情報の入れ替え」）。

スクリプトの走る依存が見つかったこと自体は指摘ではない（ビルドに必要なものも多い）。**書くのは、この経路が存在することと、CI で本番の秘密情報が同じ環境にあるかどうか。** 両方が揃うと、依存 1 つの汚染で秘密情報が抜ける経路になる。

**直し方。** 依存のスクリプトは許可したものだけを動かす（npm の `ignore-scripts` と許可の一覧、pnpm の `onlyBuiltDependencies`）。
ビルドでは `npm ci` を使い、クールダウン（pnpm の `minimumReleaseAge`、Dependabot の `cooldown` など）を入れる。本番の秘密情報は、依存を入れるジョブに渡さない。

**リポジトリ自身のスクリプトも、全開発者の端末と CI で走る。** 依存のスクリプトと別に見る。

- `package.json` の `scripts` の `preinstall`・`install`・`postinstall`・`prepare`。`npm install` のたびに走る
- `.husky/` などの Git のフック。コミットや push のたびに走る
- `.devcontainer/devcontainer.json` の `initializeCommand`（ホストの側で走る）・`onCreateCommand`・`postCreateCommand`・`postStartCommand`

```bash
grep -nE '"(preinstall|install|postinstall|prepare)"[[:space:]]*:' package.json 2>/dev/null
ls -d .husky .githooks .devcontainer 2>/dev/null
grep -rnE '"(initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"' .devcontainer 2>/dev/null
```

中身が、外から取ってきたものを実行していないか（外から取った内容をそのままシェルに渡す形、版を固定しない `npx`）を読む。

### 3-2. 名前の紛らわしい依存

タイポスクワッティング（`lodahs` のような、正規のパッケージに似せた名前）を、直接依存だけでも見る（npm の確かめ方は下のコマンド）。

**npm 以外にも同じ経路がある。** `requirements.txt`・`pyproject.toml`・`Gemfile`・`composer.json` の直接依存も同じように目で見る。
レジストリに実在するか、いつから公開されているかは、それぞれ次で確かめられる。

| 定義のファイル | 確かめ方 |
|---|---|
| `requirements.txt`・`pyproject.toml` | `pip index versions <名前>`（公開されている版の一覧） |
| `Gemfile` | `gem info -r <名前>` |
| `composer.json` | `composer show -a <名前>` |

**判定は目でやる。** 機械的には判定できない。週あたりのダウンロード数と、リポジトリの所在を見れば大抵は分かる。

**AI が生成したコードでは、実在しないパッケージ名が混ざる。** モデルが「ありそうな名前」を作り、
後から攻撃者がその名前で悪意あるパッケージを公開して待つ、という形が知られている
（slopsquatting と呼ばれる）。生成される名前は同じプロンプトで再現されやすく、攻撃側は名前を予測して先回りできる。

**この評価の対象では、特にここを見る価値が高い。** AI で素早く作ったアプリは、1 回の作業で
依存が一気に増える。**インストールが通っている以上どこかには存在する**ので、
「入っているから正しい名前」とは言えない。**直接依存を一度も目で見ていないなら、見る。**

```bash
# 直接依存のうち、素性を確かめる価値があるもの（週あたりのダウンロード数が桁違いに小さい等）
# 非公開のスコープ（@<自社のスコープ>/…）は外して渡す。下の段落を見る
node -e "const p=require('./package.json');console.log(Object.keys({...p.dependencies,...p.devDependencies}).join('\n'))" \
  | grep -vE '^@<非公開のスコープ>/' \
  | while read -r m; do printf '%-40s ' "$m"; npm view "$m" time.created 2>/dev/null || echo '（レジストリに無い）'; done
```

**非公開のパッケージの名前を、公開のレジストリへ送らない。** `npm view`・`pip index`・`gem info -r` は名前を公開のレジストリに問い合わせる。
非公開のスコープや社内の名前を渡すと「レジストリに無い」と出るだけでなく、その名前を外へ知らせることになる。
知られた名前は、同じ名前を公開して取り違えを狙う材料になる。**`.npmrc` にスコープごとの取得元（`@<スコープ>:registry=`）があれば、そのスコープは非公開なので先に外す。**

`npm view <名前> dist.attestations repository.url` で、出所の証明（provenance）とリポジトリの所在も見られる。

**公開日が極端に新しいものと、レジストリに無いものを重点的に見る。** 前者は先回りされた名前の候補、
後者はプライベートレジストリ由来か、単にタイプミスになる。疑わしい名前は、正規のパッケージに置き換えるか依存から外し、
既に入れた環境の秘密情報は 3-1 の「乗っ取られた版」と同じく漏れたものとして扱う。

### 3-3. CI から本番への経路

**サプライチェーンの大きな事故の多くは、ここで起きている。** Vercel のようなマネージド構成でも、`.github/workflows/` は
**秘密情報と本番への権限を持つインフラの定義**として見る。候補は事前の洗い出しの 20 節に出る。

- **CI の権限がどこまであるか。** 本番へ直接デプロイできるか。`permissions:` を書いていないワークフローは既定の権限で動く。最小の権限を書く
- **サードパーティの Action をコミットハッシュで固定しているか。** `@v3` のようなタグ参照は、タグが差し替えられると別のコードが走る。
  固定した Action の中で別の Action をタグ参照していれば、そこは固定されない。フォーク側のコミットを指すハッシュでないかも確かめる
- **外部から来る値を `run:` に `${{ }}` で直接埋め込んでいないか。** PR のタイトルやブランチ名、手動実行の入力（`inputs`）を
  そう書くとシェルに注入できる。秘密情報を持つジョブなら指摘にする。`env:` に入れてから `"$名前"` で参照する
- **外部から来る値を、環境ファイル（`$GITHUB_ENV`・`$GITHUB_OUTPUT`・`$GITHUB_PATH`）に書き込んでいないか。** 値に改行を含めれば、
  後続のステップに別の環境変数（`LD_PRELOAD`・`BASH_ENV` など）や `PATH` の先頭を足して任意のコードを動かせる。
  **`env:` で受けて `"$名前"` で使う形でも、値そのものを書き込むので防げない。** 「名前<<区切り」の形で `EOF` のような固定の区切りを使うのも同じ。
  区切りを実行ごとに作る（乱数）か、1 行の値なら改行を除く（`tr -d '\n'`）か、`@actions/core` の `exportVariable`・`setOutput` を使う。
  `workflow_run` で読む前のワークフローの成果物は PR の側から来るので、外部の値として扱う
- **`contains()` で権限を決めていないか。** 第 1 引数が文字列なら部分一致で、`contains(github.event.label.name, 'admin')` はラベル `admin-bypass` でも、
  `contains('alice,bob', github.actor)` は利用者 `ali` でも真になる。権限の判定は `==` で比べるか、配列（`.*.` のフィルタや `fromJSON` の配列）を受ける形にする
- **秘密情報を、使うステップの `env:` だけに置いているか。** ジョブ全体やワークフロー全体の `env:` に置くと、第三者の Action や依存のスクリプトからも読める
  （LLM の鍵や CMS の書き込みの鍵を CI に置く構成で起きやすい。`references/12-ai-features.md` の 9 節）
- **`actions/checkout` が資格情報を残したまま、作業ツリーを成果物に上げていないか。** checkout は既定で `GITHUB_TOKEN` を `.git/config` に残す。
  `.git` を含む範囲（`path: .` など）を成果物に上げると、成果物を取れる人にトークンが渡る。残ったトークンは同じジョブの後のステップからも読める。
  checkout に `persist-credentials: false` を付けるか、上げる範囲をビルドの出力に絞る
- **既知の勧告がある版の Action を使っていないか。** Action も依存の一つで、GitHub の勧告データベースに載る。ハッシュで固定していても、固定した版が勧告の範囲なら残る。
  使っている Action の勧告を評価の時点で見る
- **Action の入力で、道具を最新（`version: latest` など）で入れていないか。** Action を固定しても、中で入れる道具が走るたびに変わる。版を固定する
- **人が件数を指定できる一括処理**（生成して公開する、一斉に送る）に上限があるか。無いと従量課金の費用と公開の量がそのまま伸びる
- **`pull_request_target` / `workflow_run` で PR の中身を取得して動かしていないか。** 秘密情報を持った状態で他人のコードが走る。
  checkout の新しい版はフォークからの PR の取得を既定で拒否するが、古い版のハッシュで固定していればその保護は入らず、手書きの `git fetch` や `gh pr checkout` にも及ばない
- **信頼できないトリガー（フォークからの PR など）からキャッシュを書けないか。** 書ければ、後の信頼されたワークフローが汚染されたキャッシュを読む
- **npm に公開する権限を持つトークンが CI にあるか。** あれば、公開は OIDC による Trusted Publishing に移す。
  ただし出所の証明（provenance）が正しくても安全とは言えない。正規の OIDC 経路から悪性版が公開された事例がある

**組織の設定も聞く。** SHA 固定を強制する方針と、ワークフローを誰が・どのイベントで動かせるかの制限。コードからは見えないので、無ければ未確認事項に残す。

### 3-4. ブラウザに読み込む第三者スクリプト

**これも他人のコードが入る経路。** 02 の L 節・08 の 1 節で扱うが、サプライチェーンとしても数える。配信元が差し替えられれば、そのまま利用者のブラウザで動く。

`integrity` 属性（SRI）が付いているか。付いていなければ、配信元を信頼しているだけの状態になる。**タグマネージャを使っている場合は SRI を付けられない**ので、指摘は「SRI が無い」ではなく「コンテナの変更を誰が承認するか」になる。

- **版を付けない CDN の参照**（`unpkg.com/<名前>`、`@latest`、版の範囲だけの指定）は、中身が予告なく変わるので SRI を付けられない。
  付けても、新しい版が出た時点で読み込みが止まる。**版を完全に固定し、SRI を付ける**か、自分の配信物に取り込む
- **配信元のドメインの持ち主が変わることがある。** 広く使われていた polyfill の配信ドメインが売却され、
  読み込んでいたサイトに悪性のコードが配られた例がある。無名の配信元や、既に保守されていないライブラリの配信元を読み込んでいないかを見る

```bash
grep -rnE 'unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|@latest|polyfill' \
  --include='*.html' --include='*.tsx' --include='*.jsx' --include='*.vue' --include='*.svelte' --include='*.astro' --include='*.erb' --include='*.php' . | grep -v node_modules | head -30
```

### 3-5. AI コーディングエージェントの設定ファイル

**この評価の対象（AI で作ったアプリ）では、リポジトリにエージェントの設定が入っていることが多い。**
これは開発者の端末で動く他人の指示と設定で、**リポジトリを開いただけで読み込まれる**ものがある。

- エージェントへの指示書（`AGENTS.md`、`CLAUDE.md`、`.cursorrules`、`.github/copilot-instructions.md`）に、
  見えない文字で指示が仕込まれていないか
- エージェントの自動承認・権限の緩和・フックがコミットされていないか。**個人用の設定（`*.local.json`）が
  コミットされていないか**
- MCP サーバーの定義（`.mcp.json`、`.cursor/mcp.json`）が、版を固定しない `npx -y` で取ってきていないか
- `.vscode/tasks.json` の `"runOn": "folderOpen"`。**フォルダを開くだけでコマンドが走る**経路で、実際の攻撃に使われた

```bash
ls -la AGENTS.md CLAUDE.md GEMINI.md .cursorrules .cursor/rules .cursor/mcp.json .mcp.json \
  .claude/settings.json .github/copilot-instructions.md .vscode/settings.json .vscode/tasks.json 2>/dev/null
grep -nE '"hooks"|bypassPermissions|enableAllProjectMcpServers|apiKeyHelper' .claude/settings*.json 2>/dev/null
grep -nE 'autoApprove|yolo' .vscode/settings.json .gemini/settings.json 2>/dev/null
grep -nE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' .vscode/tasks.json 2>/dev/null
git ls-files 2>/dev/null | grep -E 'settings\.local\.json$'
# 見えない Unicode（ゼロ幅・双方向制御・タグ文字）。絵文字の異体字セレクタで誤検出することがある
# 対象が 0 件のときに perl が標準入力を待たないよう、xargs で渡す
git ls-files -z '*.md' '*.mdc' '.cursorrules' '*.json' 2>/dev/null \
  | xargs -0 perl -CSD -ne 'print "$ARGV:$.\n" if /[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2069}\x{E0000}-\x{E007F}]/; close ARGV if eof' 2>/dev/null
```

候補は事前の洗い出しの 22 節に出る。

**見つかったこと自体は指摘ではない。** 書くのは、**開発者の端末で自動的に動くものがあるか**と、
**その端末に本番の秘密情報があるか**の 2 つ。両方揃うと、リポジトリへの 1 回の書き込みで本番の鍵が抜ける。
開発者が本番の DB やクラウドに MCP でつないでいるかは取材で聞く（`references/01-scoping.md` の B-3）。

**直し方。** 個人用の設定は `.gitignore` に入れてリポジトリから外し、自動承認と権限の緩和は共有の設定に置かない。
MCP サーバーは版を固定し、`folderOpen` のタスクは外す。指示書に見えない文字があれば消し、誰が入れたかを履歴で確かめる。

---

## 指摘の書き方

**件数だけの指摘にしない。** 次の 3 つが揃って、はじめて読み手が優先度を判断できる。

```markdown
| 事実 | npm audit（--omit=dev）で high 2 件。いずれも <lib> 由来で、
        直接依存ではなく <parent> が連れてきている |
| 到達性 | 該当関数は <path> で呼んでいる。外部入力が届く経路がある／無い |
| 仕組み | CI にスキャンが無く、Dependabot も未設定。今回の 2 件は評価者が
          初めて実行して見つけたもの |
```

**3 番目を書き落とさない。** 個別の 2 件を直しても、仕組みが無ければ同じ状態に戻る。**指摘としては仕組みのほうが上に来ることが多い。**

**台帳の列との対応**（`references/04-findings-register.md`）: 「事実」は指摘事項、「到達性」は想定される影響、「仕組み」は**別の行**として起票する（分類はサプライチェーンと CI）。確認の方法は「コード」（スキャンの結果とロックファイル）で、KEV に載っていれば指摘事項にその旨を書き、優先度は少なくとも P1。
