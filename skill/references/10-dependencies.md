# 依存関係とサプライチェーン

`references/02-code-audit.md` の H 節を深掘りするための資料。**依存の数が多い案件**、**スキャンで high 以上が出た案件**、**CI から本番へ自動で出る構成**で読む。

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
npm audit --omit=dev            # 本番依存だけに絞る
pip-audit                        # Python
bundle audit                     # Ruby
govulncheck ./...                # Go。到達性まで見てくれる
```

`--omit=dev` を付けるかどうかで件数が大きく変わる。**両方取って、差を書く。**

| 出たもの | どう扱うか |
|---|---|
| 本番依存に high 以上 | **経路を確かめてから起票する。** その関数を実際に呼んでいるか |
| 開発依存だけに high | 優先度を落とす。ただしビルド環境が汚染される経路は別途見る（3 節） |
| 修正版が出ていない | 見送りの候補。**代替の緩和策があるかを書く** |

**「呼んでいるか」を確かめずに起票しない。** 脆弱な関数を含むライブラリを入れていても、その関数を使っていなければ到達しない。逆に、使っていれば優先度は一段上がる。

**例外は、枠組み本体の脆弱性。** フレームワークやホスティングの層に穴があると、
アプリのコードが正しくても成立する。この種は「呼んでいるか」で判定できないので、
**版が該当するかどうかで判定する**。認証・認可の枠組みに関わるものは、
`references/04-findings-register.md` の問い 1 に当たりうる（P0 の候補。実例は `references/02-code-audit.md` の A-5）。

```bash
# 枠組みの版を、ロックファイル側の実際の解決結果で確認する
grep -m1 -A2 '"node_modules/next"' package-lock.json 2>/dev/null
npm ls next react vue svelte 2>/dev/null | head
```

```bash
# 該当ライブラリをどこで使っているか
grep -rn "require('<lib>')\|from '<lib>'" --include='*.ts' --include='*.js' .
# 依存木のどこから来ているか（直接依存か、他の依存が連れてきたか）
npm ls <lib>
```

`npm ls` の結果は指摘の書き方を変える。**直接依存なら上げるだけ**、**他の依存が連れてきたものなら親を上げる必要がある**（あるいは上げられない）。

### 1-2. 「実際に悪用されているか」で優先度を分ける

スキャンが出す深刻度（CVSS）は**理論上の重さ**で、**実際に攻撃に使われているか**とは別になる。
優先度を決めるときは、次の順で確かめる。

| 情報源 | 何が分かるか | 使い方 |
|---|---|---|
| **CISA KEV**（Known Exploited Vulnerabilities） | **実際に悪用が確認された脆弱性**の公式カタログ。CVE 単位 | スキャンで出た CVE がここにあれば、**CVSS にかかわらず少なくとも P1**。公開資産で、認証なしに届き全制御を許すものは P0（`references/04-findings-register.md` の「悪用が確認されていれば上げる」） |
| GitHub Security Advisories | パッケージ単位の公式勧告。**マルウェアの勧告もここに載る**（CVE が付かないことが多い） | 修正版の有無と、GHSA から CVE・EPSS への引き直し |
| EPSS | 今後 30 日に悪用される確率の推定（FIRST。2026-06 から v5） | KEV に無いものの順位づけ |
| OSV | 各エコシステムの勧告を束ねたもの。**悪性パッケージは `MAL-` で始まる ID** | `osv-scanner` でロックファイルを直接照合できる |
| **JVN iPedia** | 国内の脆弱性対策情報（JPCERT/CC と IPA が運営）。日本語 | 国内製品・国内向けの補足。**依頼者への説明に日本語の一次情報として引ける** |
| JPCERT/CC 注意喚起・IPA 重要なセキュリティ情報 | **国内で影響が大きいもの**への警告 | 評価期間中に出たものが対象の構成に当たらないかを、**評価の最後にもう一度見る** |
| 枠組み自身のアドバイザリ | Next.js / Rails / Django などの公式の勧告 | **枠組み本体の脆弱性**（1 節の例外）はここで版を確かめる |

```bash
# KEV は JSON で公開されている。スキャンで出た勧告を CVE に引き直してから突き合わせる。
# npm audit --json の via[] には CVE 番号が無い（GHSA の URL しか無い）。CVE で直接照合すると、
# どんな結果でも「該当なし」になるので注意。GHSA → CVE と EPSS は GitHub の勧告 API で引ける（gh が要る）
curl -sS https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  | python3 -c 'import json,sys; print("\n".join(v["cveID"] for v in json.load(sys.stdin)["vulnerabilities"]))' \
  > /tmp/kev.txt
npm audit --json | python3 -c '
import json,sys,re
for a in json.load(sys.stdin).get("vulnerabilities",{}).values():
    for v in a.get("via",[]):
        if isinstance(v,dict):
            m=re.search(r"GHSA(-[0-9a-z]{4}){3}", v.get("url",""))
            if m: print(m.group(0), a["name"], a["severity"])' | sort -u \
  | while read -r ghsa name sev; do
      read -r cve epss < <(gh api "/advisories/$ghsa" --jq '[.cve_id // "-", .epss.percentage // "-"] | @tsv')
      kev=$(grep -qxF "$cve" /tmp/kev.txt && echo KEV || echo -)
      printf '%s\t%s\t%s\t%s\tEPSS=%s\t%s\n' "$kev" "$cve" "$ghsa" "$name" "$epss" "$sev"
    done | sort -r
```

**開発依存も含めて照合する**（`--omit=dev` を付けない）。開発依存は本番には入らないが、CI と開発機で動く（3-3）。

**先頭に `KEV` が出た行から見る**（04 の規則で少なくとも P1）。次に EPSS（今後 30 日に悪用される確率の推定。2026-06 から v5）が
高いものを見る。**判定の順は KEV → EPSS → CVSS。** CVE が `-` の勧告（マルウェアの勧告など、
CVE の付かないもの）は KEV と照合できないので、別に目で見る。

**KEV には依存パッケージだけでなく、CI の Action やツール自体の侵害も載る**（例: tj-actions の
CVE-2025-30066、reviewdog の CVE-2025-30154、Trivy の CVE-2026-33634）。`.github/workflows` の
`uses:` も同じように照合する。**逆に、載っていないことは安全の根拠にならない**
（大規模な npm の侵害でも KEV に載らなかったものがある）。

**KEV に載っていることは「今すぐ」の根拠になる。** 逆に、載っていない high は
「到達性を確かめてから」（1 節）でよい。**この区別を台帳に書く**と、依頼者が順序を納得しやすい。

**注意喚起は評価の最後にもう一度見る。** 評価に数週間かかると、その間に新しい勧告が出る。
報告書の日付の時点で、対象の構成に当たる注意喚起が無いかを確かめてから出す。

## 2. 検知の仕組みがあるか

**件数より、こちらのほうが指摘として重い。** 今日 0 件でも、依存は勝手に脆弱になる。

- CI にスキャンが入っているか。入っていなければ、誰も見ていない
- 依存更新の自動検知（Dependabot / Renovate）があるか。Dependabot は **3 つを分けて聞く**:
  セキュリティ更新（即時）、バージョン更新（2026-07 から既定で 3 日の待機）、
  **悪性パッケージのアラート（opt-in。npm は 2026-03 から）**。`npm audit` は悪性パッケージを検知しないので、
  最後の 1 つが無ければ「乗っ取られた版が入っても気づく仕組みが無い」と書ける
- **通知の宛先が生きているか。** 設定されていても、誰も見ていないリポジトリの通知は無いのと同じ
- ロックファイル（`package-lock.json` / `yarn.lock` / `poetry.lock`）がコミットされているか

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
ls package-lock.json yarn.lock pnpm-lock.yaml poetry.lock Gemfile.lock 2>/dev/null
git log -1 --format=%cr -- package-lock.json    # 最後に更新されたのはいつか
```

## 3. 他人のコードが本番に入る経路

**ここがサプライチェーンの本体。** 依存の脆弱性は「入っているコードに穴がある」話だが、こちらは「意図しないコードが入る」話になる。

### 3-1. インストール時に走るスクリプト

`npm install` は、依存パッケージの `postinstall` を実行する。**依存を 1 つ足すと、他人のスクリプトが開発機と CI で走る。**

```bash
# インストール時にスクリプトが走る依存の数。preinstall / install / binding.gyp も含めて、
# ロックファイルに記録されている（node_modules/*/package.json の grep はスコープ付きと preinstall を落とす）
grep -c '"hasInstallScript": true' package-lock.json 2>/dev/null
# 名前は、その直前に現れた "node_modules/<名前>" のキー。間に version / resolved / integrity / dev が入るので
# 行数を決め打ちした grep -B では取れない
awk '/^[[:space:]]*"node_modules\//{k=$1} /"hasInstallScript": true/{gsub(/[":]/,"",k); sub(/^node_modules\//,"",k); print k}' package-lock.json 2>/dev/null | head -30
```

**パッケージマネージャ側の既定が変わっている。** npm 12（2026-07）と pnpm 10 以降は、依存のスクリプトを
既定で実行せず、許可したものだけを動かす。**ただし実際にビルドしているのが古い npm なら、この保護は効かない**
（Vercel の既定は Node 24 に付く npm 11。Node 20 / 22 を選んでいれば npm 10。どちらも npm 12 ではない）。
見るのは手元の設定ではなく、**本番のビルドで何の版が動いているか**。

**公開直後の版を入れない設定（クールダウン）があるか。** 2025〜2026 年の npm の乗っ取り
（Shai-Hulud、axios など）は、悪性版の公開から取り下げまで数時間だった。数日の待機でその大半を避けられる。

```bash
grep -nE 'ignore-scripts|min-release-age|allow-(git|remote|scripts)|dangerously-allow-all-scripts|^registry' .npmrc 2>/dev/null
grep -c '_authToken' .npmrc 2>/dev/null   # 数だけ見る。値は出さない。1 以上ならトークンがリポジトリにある
grep -nE '"(allowScripts|overrides|resolutions|packageManager)"' package.json
grep -nE 'minimumReleaseAge|allowBuilds|onlyBuiltDependencies|dangerouslyAllowAllBuilds|blockExoticSubdeps' pnpm-workspace.yaml package.json 2>/dev/null
grep -n 'cooldown' .github/dependabot.yml 2>/dev/null
```

`scripts/audit_grep.sh` の 21 節が、スクリプトの走る依存の数と名前、公式レジストリ以外の取得元、防御の設定を出す。

**既知の乗っ取られた版がロックファイルに入っていないか**も見る。入っていたら、
**その版が入ったビルド環境と開発機の秘密情報はすべて漏れたものとして扱う**（入れ替えと、露出していた期間の悪用の調査までを是正に書く。タスクの型は `references/05-remediation-plan.md` の「秘密情報の入れ替え」）。

見つかったこと自体は指摘ではない（ビルドに必要なものも多い）。**書くのは、この経路が存在することと、CI で本番の秘密情報が同じ環境にあるかどうか。** 両方が揃うと、依存 1 つの汚染で秘密情報が抜ける経路になる。

### 3-2. 名前の紛らわしい依存

タイポスクワッティング（`lodahs` のような、正規のパッケージに似せた名前）を、直接依存だけでも見る。

```bash
# 直接依存の一覧を出して、見慣れないものを目で確かめる
node -e "const p=require('./package.json');console.log(Object.keys({...p.dependencies,...p.devDependencies}).join('\n'))"
```

**判定は目でやる。** 機械的には落とせない。週あたりのダウンロード数と、リポジトリの所在を見れば大抵は分かる。

**AI が生成したコードでは、実在しないパッケージ名が混ざる。** モデルが「ありそうな名前」を作り、
後から攻撃者がその名前で悪意あるパッケージを公開して待つ、という形が知られている
（slopsquatting と呼ばれる）。USENIX Security 2025 の研究では、**生成されたパッケージ参照の 19.7% が
実在しない名前**だった（商用モデル平均 5.2%、オープンなモデル平均 21.7%）。同じプロンプトを 10 回投げると
**43% は 10 回とも同じ名前を再現した**。攻撃側は名前を予測して先回りできる。

**この評価の対象では、特にここを見る価値が高い。** AI で素早く作ったアプリは、1 回の作業で
依存が一気に増える。**インストールが通っている以上どこかには存在する**ので、
「入っているから正しい名前」とは言えない。**直接依存を一度も目で見ていないなら、見る。**

```bash
# 直接依存のうち、素性を確かめる価値があるもの（週あたりのダウンロード数が桁違いに小さい等）
node -e "const p=require('./package.json');console.log(Object.keys({...p.dependencies,...p.devDependencies}).join('\n'))" \
  | while read -r m; do printf '%-40s ' "$m"; npm view "$m" time.created 2>/dev/null || echo '（レジストリに無い）'; done
```

`npm view <名前> dist.attestations repository.url` で、出所の証明（provenance）とリポジトリの所在も見られる。

**公開日が極端に新しいものと、レジストリに無いものを重点的に見る。** 前者は先回りされた名前の候補、
後者はプライベートレジストリ由来か、単にタイプミスになる。

### 3-3. CI から本番への経路

**2025〜2026 年の大きな事故の多くは、ここで起きた**（tj-actions、nx、Trivy、TanStack）。
Vercel のようなマネージド構成でも、`.github/workflows/` は**秘密情報と本番への権限を持つインフラの定義**として見る。

- CI の権限がどこまであるか。本番へ直接デプロイできるか。`permissions:` を書いていないワークフローは既定の権限で動く
- **サードパーティの Action を版で固定しているか。** `@v3` のようなタグ参照は、タグが差し替えられると別のコードが走る。
  コミットハッシュでの固定が基本だが、**それだけでは足りない**。固定した Action の中で別の Action をタグ参照していれば、
  そこは固定されない（Trivy の事例）。**フォーク側のコミットを指すハッシュでないか**も確かめる
- **外部から来る値を `run:` に直接埋め込んでいないか。** PR のタイトルやブランチ名を `${{ }}` で `run:` に書くと、
  シェルに注入できる（nx の根本原因）。環境変数に入れてから参照するのが正しい
- **`pull_request_target` / `workflow_run` で PR の中身を取得して動かしていないか。** 秘密情報を持った状態で
  他人のコードが走る。`actions/checkout` は既定で**フォークからの PR** の取得を拒否するようになった
  （v7 で 2026-06、v2〜v6 の最新版にも 2026-07 に取り込み。v1 には無い）が、**古い版のハッシュで固定していれば効かない**。
  解除する入力（`allow-unsafe-pr-checkout`）や、手書きの `git fetch` / `gh pr checkout` にも及ばない。
  公開リポジトリでは、`pull_request_target` を既定で止めるルールが 2026-11-02 から適用される予定
- **信頼できないトリガーからキャッシュを書けないか**（TanStack の事例。2026-06 から既定で読み取り専用だが、
  2026-09 に足された `cache-mode` をワークフローに書くと上書きできる）
- npm に公開する権限を持つトークンが CI にあるか。あれば、**公開は OIDC による Trusted Publishing か**。
  ただし**出所の証明（provenance）が正しくても安全とは言えない。** 正規の OIDC 経路から悪性版が公開された事例がある

```bash
W=.github/workflows
# 版の固定。サブパス付きの Action と再利用ワークフローも拾い、40 桁のハッシュ以外を出す
grep -rnE 'uses:[[:space:]]*[^[:space:]#]+@' $W 2>/dev/null | grep -vE '@[0-9a-f]{40}([[:space:]]|$)'
grep -rnE 'uses:[[:space:]]*docker://' $W 2>/dev/null
# 危険なトリガーと PR の中身の取得
grep -rnE 'pull_request_target|workflow_run|issue_comment' $W 2>/dev/null
grep -rnE 'allow-unsafe-pr-checkout|cache-mode:|head\.(sha|ref)|refs/pull/|gh pr checkout' $W 2>/dev/null
# 外部から来る値の ${{ }} 展開。run: | の複数行ブロックの中にも来るので、ファイル全体で拾い、run: の中かを目で見る
grep -rnE '\$\{\{[[:space:]]*(github\.event\.(issue|pull_request|comment|review|head_commit|commits|pages)|github\.head_ref)' $W 2>/dev/null
# 権限と秘密情報
grep -rLE '^permissions:' $W/*.y*ml 2>/dev/null          # トップレベルの permissions が無い
grep -rnE 'permissions:[[:space:]]*write-all|id-token:[[:space:]]*write' $W 2>/dev/null
grep -rnE '(echo|printf|cat|tee).*\$\{\{[[:space:]]*secrets\.|toJSON\(secrets\)|secrets:[[:space:]]*inherit' $W 2>/dev/null
```

`scripts/audit_grep.sh` の 20 節が、`.github/workflows/` があるときに上をまとめて出す。

**組織の設定も聞く。** SHA 固定を強制する方針（2025-08 から設定できる）と、ワークフローを誰が・どのイベントで
動かせるかの制限（2026-09 に GA）。コードからは見えないので、無ければ未確認事項に残す。

### 3-4. ブラウザに読み込む第三者スクリプト

**これも他人のコードが入る経路。** 02 の L 節・08 の 1 節で扱うが、サプライチェーンとしても数える。配信元が差し替えられれば、そのまま利用者のブラウザで動く。

`integrity` 属性（SRI）が付いているか。付いていなければ、配信元を信頼しているだけの状態になる。**タグマネージャを使っている場合は SRI を付けられない**ので、指摘は「SRI が無い」ではなく「コンテナの変更を誰が承認するか」になる。

### 3-5. AI コーディングエージェントの設定ファイル

**この評価の対象（AI で作ったアプリ）では、リポジトリにエージェントの設定が入っていることが多い。**
これは開発者の端末で動く他人の指示と設定で、**リポジトリを開いただけで効く**ものがある。

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

`scripts/audit_grep.sh` の 22 節が、設定ファイルがあるときに上をまとめて出す。

**見つかったこと自体は指摘ではない。** 書くのは、**開発者の端末で自動的に動くものがあるか**と、
**その端末に本番の秘密情報があるか**の 2 つ。両方揃うと、リポジトリへの 1 回の書き込みで本番の鍵が抜ける。
開発者が本番の DB やクラウドに MCP でつないでいるかは取材で聞く（`references/01-scoping.md` の B-3）。

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
