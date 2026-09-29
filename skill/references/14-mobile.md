# モバイルアプリ

**評価対象にモバイルアプリが含まれるとき**に読む。Web だけなら不要。

**要否の判定**は `scripts/audit_grep.sh` の 0 節が出す。`android/` や `ios/` の
ディレクトリ、`pubspec.yaml`、`Podfile`、`build.gradle`、React Native や Capacitor の
依存があれば該当する。

## Web と何が違うか

**アプリは配布物になる。** ここが最大の違いで、判断の前提が変わる。

| | Web | モバイル |
|---|---|---|
| コードの所在 | サーバー側は手元に無い | **全部が利用者の端末にある** |
| 秘密の隠し場所 | サーバーに置ける | **無い。取り出せる前提で設計する** |
| 更新 | 配信すれば即時 | **審査と、利用者の更新操作が要る** |
| 実行環境 | ブラウザの制約下 | 端末の制約下。root 化された端末もある |

**「アプリの中にあるから見えない」は成り立たない。** 配布されたファイルは逆アセンブルでき、
通信は中継して読める。**サーバー側で守れないものは守れない。**

そのため、この資料で最も重い指摘は次の 2 つになる。

1. **アプリに埋め込まれた秘密情報で、サーバー側の特権操作ができる**
2. **サーバー側の認可が、アプリの画面制御に依存している**

2 は Web の A-1 と同じ話だが、モバイルでは「画面に出していないから安全」という
思い込みが起きやすい。**API を直接叩けば、画面は関係ない。**

---

## 確認項目

**版**: MASVS 2.1.0（2024-01）を土台にしている。L1 / L2 / R の段階は 2.0.0 で廃止された。
試験手順の MASTG は **2.0.0（2026-06）が最初の安定版**で、弱点の一覧 MASWE が両者をつなぐ。
**指摘には、分かる範囲で MASWE と MASTG-TEST の ID を添える**と、依頼者側の開発者が一次情報を引ける。

OWASP MASVS の分類（Storage / Crypto / Auth / Network / Platform / Code / Resilience /
Privacy）に沿って並べてある。**該当しない項目は飛ばす。**

### 1. 埋め込まれた秘密情報（MASVS-CRYPTO / CODE）

```bash
# ソースと設定に埋まっている鍵。Gradle の storePassword "…" のように区切りの記号が無い書き方も拾う。
# 値は画面に出さず、名前と行番号だけを出す
grep -rnoiE --exclude-dir=node_modules \
  '(api[_-]?key|secret|token|password|storePassword|keyPassword)["'"'"']?[[:space:]]*[:=]?[[:space:]]*["'"'"'][^"'"'"'[:space:]]{8,}' \
  --include='*.swift' --include='*.kt' --include='*.kts' --include='*.java' --include='*.dart' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.plist' --include='*.xml' \
  --include='*.gradle' --include='*.properties' --include='app.json' --include='app.config.*' --include='eas.json' . 2>/dev/null \
  | sed -E 's/(["'"'"'])[^"'"'"']{4,}$/\1…/'
# 引用符を使わない .properties と .env は、名前だけ出す
grep -rnoiE --exclude-dir=node_modules '^[[:space:]]*[A-Za-z0-9_.]*(password|secret|token|api[_-]?key)[A-Za-z0-9_.]*[[:space:]]*=' \
  --include='*.properties' --include='.env*' . 2>/dev/null

# アプリに焼き込まれる公開用の環境変数（名前だけ。Expo・React Native・Capacitor の構成）。
# 接頭辞は scripts/audit_grep.sh の公開用の環境変数の節と同じ
grep -rhoE --exclude-dir=node_modules \
  '(NEXT_PUBLIC|NUXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|GATSBY|STORYBOOK|ASTRO_PUBLIC|PUBLIC|VUE_APP|NG_APP|SVELTE_PUBLIC|REMIX_PUBLIC)_[A-Z0-9_]+' \
  . 2>/dev/null | sort -u

# 設定ファイル。配布物に入るもの、入らないが署名の情報を持つもの
find . \( -name 'google-services.json' -o -name 'GoogleService-Info.plist' \
       -o -name '*.jks' -o -name '*.keystore' -o -name '*.p12' -o -name '*.mobileprovision' \
       -o -name 'keystore.properties' -o -name 'key.properties' -o -name 'local.properties' -o -name '.env*' \) \
  -not -path '*/node_modules/*' 2>/dev/null
```

**`EXPO_PUBLIC_` などの接頭辞が付いた変数は、ビルドのときにアプリの中へ文字列として入る。** 名前に KEY・SECRET・TOKEN が
入っていれば、その値は配布物から取り出せる（下の表で用途を分ける）。`keystore.properties` や `key.properties` に
署名鍵のパスワードが書かれ、リポジトリに入っていれば、署名鍵のファイルと合わせて偽アプリを作れる。

**すべての鍵が問題なわけではない。** 用途で分ける。

| 鍵の種類 | 判定 |
|---|---|
| 公開前提の識別子（Firebase の設定、計測 SDK の ID） | 問題なし。**サーバー側の権限設定で守る**（呼べる API が増える例外は下の段落） |
| 第三者 API の鍵で、**課金や特権操作ができる**もの | **問題あり。中継サーバーを挟む** |
| 署名鍵・配布用の証明書がリポジトリにある | **問題あり。これが漏れると偽アプリを作れる** |

**「鍵が入っている」だけで指摘にしない。** その鍵で何ができるかを確かめる。
Firebase の設定ファイルは公開前提で、守るのは**サーバー側の規則**になる。
`references/03-runtime-verification.md` の 1 節で規則を確認する。

**ただし、公開前提の鍵でも呼べる API が増えることがある。** Google の `AIza…` の鍵は、同じ GCP プロジェクトで
Generative Language API（Gemini）を有効にすると、**配布済みの鍵のまま Gemini を呼べる**状態になる
（2026-02 に公表。公開 Web 上で使える鍵が数千件見つかった）。**その鍵に API の制限が掛かっているか**を、
依頼者に GCP のコンソールで確かめてもらう（渡す文面は `templates/client-console-checklist.md` の 11）。確かめられなければ未確認事項に残す。

### 2. 端末に保存しているもの（MASVS-STORAGE）

```bash
grep -rnE -e 'AsyncStorage|SharedPreferences|UserDefaults|NSUserDefaults|localStorage' \
  -e 'sqlite|Realm|shared_preferences|SecureStore|Keychain|EncryptedSharedPreferences' \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.ts' --include='*.js' . 2>/dev/null | head -20
```

**保存先で判定が変わる。**

- **`Keychain`（iOS）/ Android Keystore を使った保存 / `SecureStore`** —
  資格情報の置き場として意図されたもの。問題なし。ただし Keychain は**いつ読めるか**と**どこへ同期されるか**を属性で決める。
  `kSecAttrAccessible` が `kSecAttrAccessibleAlways` 系（非推奨）なら端末のロック中も読める。`ThisDeviceOnly` の付かない値や
  `kSecAttrSynchronizable` が true なら、iCloud キーチェーンやバックアップを通じて別の端末へ移る。トークンは
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` などの端末に閉じた値にしているかを見る
- **`EncryptedSharedPreferences`** — 置き場としては今も安全側で、判定は**問題なし**。ただし**ライブラリ
  （`androidx.security:security-crypto`）全体が 2025 年に非推奨になった**ので、`references/08-privacy-compliance.md` の
  6 節と同じく「気づいたこと」として渡す（指摘には数えない）
- **`UserDefaults` / `SharedPreferences` / `AsyncStorage`** — 平文で残る。
  **認証トークンやパスワードを置いていれば指摘**。端末のバックアップにも入る
- **ログへの出力**。デバッグ用の出力が残っていて、個人情報や token を書いていないか
- **バックアップの対象から外しているか**（Android の `allowBackup`、iOS の除外指定）。
  **Android 12 以降は `android:dataExtractionRules` で、クラウドへのバックアップと端末間の転送を別々に指定する。**
  `allowBackup` だけを見ると判定を誤る

### 3. 通信（MASVS-NETWORK）

```bash
# 平文通信の許可と、利用者が入れた証明書を信頼する設定
grep -rnE -e 'usesCleartextTraffic|cleartextTrafficPermitted|NSAllowsArbitraryLoads' \
  -e 'NSExceptionAllowsInsecureHTTPLoads|certificates src="user"' --include='*.xml' --include='*.plist' . 2>/dev/null
# 証明書の検証を切っている
grep -rnE -e 'ServerTrustManager|allowInvalidCertificates|trustAllCerts|X509TrustManager' \
  -e 'setHostnameVerifier|badCertificateCallback|rejectUnauthorized' . 2>/dev/null | head
```

- **平文通信を許可していないか**（`usesCleartextTraffic="true"` / `NSAllowsArbitraryLoads`）。
  「一部のドメインだけ」の例外指定なら、その範囲を確かめる
- **証明書の検証を切っていないか。** Web の O 節と同じだが、モバイルでは
  **開発中に入れた回避策がそのまま出荷される**ことが多い
- **Android の `network_security_config` で `<certificates src="user" />` を信頼していないか。** 利用者（や端末に入り込んだ
  第三者）が入れた証明書で、通信を中継して読める。`<debug-overrides>` の中だけなら、配布するビルドには作用しない
- **証明書のピン留めをしているか。** 無いこと自体は直ちに指摘ではない。
  扱う情報の重さで決める。**入れる場合は更新の手順まで決まっているか**を見る
  （鍵の更新でアプリが一斉に通信できなくなる事故が起きる）

### 4. 認証とセッション（MASVS-AUTH）

- トークンの保管場所（2 節）と、有効期限
- **生体認証の使い方。** 端末の生体認証は「その端末の持ち主か」を確かめるもので、
  **サーバー側の認証の代わりにはならない**。生体認証が通ったことをアプリ側の判定だけで
  サーバーに伝えていれば指摘になる
- ログアウトでトークンが失効するか（`references/09-browser-verification.md` の 7 節と同じ）
- **アプリや端末の真正性確認（Play Integrity・App Attest・Firebase App Check）を入れているなら、
  判定をサーバー側でしているか。** 端末側で判定させると、改ざんで外せる。Firebase App Check は
  **強制（enforcement）を有効にするまで何も拒否しない**（Firestore・Realtime Database・Storage はコンソールで、
  Cloud Functions はコードの `enforceAppCheck: true` で有効にする）。Firebase の公式は App Check を
  認証やルールを「補う」ものとし、すべての不正利用は防げないとしている。**認証や権限設定の代わりには数えない**

### 5. 端末との境界（MASVS-PLATFORM）

**他のアプリや外部から入ってくる経路。**

```bash
# ディープリンク・URL スキームの定義。検証済みのリンク（App Links の autoVerify、Universal Links の applinks:）かも見る
grep -rnE 'intent-filter|CFBundleURLSchemes|associatedDomains|applinks:|autoVerify|android:scheme|deepLink|"scheme"' \
  --include='*.xml' --include='*.plist' --include='*.json' --include='*.entitlements' . 2>/dev/null | head -15
# WebView。Android の evaluateJavascript と iOS の evaluateJavaScript は大文字小文字が違うので -i で両方拾う
grep -rniE --exclude-dir=node_modules \
  -e 'WebView|WKWebView|InAppBrowser|addJavascriptInterface|evaluateJavascript|WKScriptMessageHandler|addScriptMessageHandler' \
  -e 'javaScriptEnabled|allowFileAccess|AllowUniversalAccessFromFileURLs|AllowFileAccessFromFileURLs|MixedContentMode|MIXED_CONTENT_ALWAYS_ALLOW' \
  . 2>/dev/null | head -20
```

- **ディープリンクで受け取った値を検証しているか。** 他のアプリから任意の値で呼べる。
  これで画面遷移や操作ができるなら、**認可の判定がアプリ側にしかない**ことになる
- **ログインの戻り（OAuth のリダイレクト、マジックリンク）をカスタム URL スキーム（`myapp://`）で受けていないか。**
  カスタム URL スキームは他のアプリも同じ名前で登録でき、どちらが受け取るかをアプリ側で決められない。認可コードや
  トークンが別のアプリに渡ることがある。**検証済みのリンク（Android の App Links、iOS の Universal Links）で受けているか**、
  OAuth なら **PKCE**（`S256`）を使っているかを見る（RFC 8252）
- **ログイン画面をアプリ内の WebView で開いていないか。** WebView ではアプリが入力を読めるうえ、利用者は正規の画面かを
  確かめられない。OS のブラウザを使う仕組み（iOS の `ASWebAuthenticationSession`、Android の Custom Tabs）を使う（RFC 8252）
- **WebView に任意の URL を読み込ませていないか。** 読み込む URL を外部入力から
  組み立てていれば、アプリの文脈で攻撃者のページが動く
- **JavaScript ブリッジ**（Android の `addJavascriptInterface`、iOS の `WKScriptMessageHandler` 等）で、端末側の機能を
  Web 側に渡していないか。WebView に外部のページを表示するなら、その組み合わせは危険。受け取る側でメッセージの送り元
  （表示中のページのオリジン）を確かめているかも見る
- **WebView の緩い設定。** `setAllowUniversalAccessFromFileURLs(true)`・`setAllowFileAccessFromFileURLs(true)` は、
  端末内のファイルとして開いたページから他のファイルや任意のオリジンへ届く。`MIXED_CONTENT_ALWAYS_ALLOW` は
  HTTPS のページに HTTP の読み込みを混ぜる
- **他アプリへ公開している入口**（Android の `exported="true"`）が意図したものか
- **個人情報を表示する画面で、画面の記録を止めているか。** Android は `FLAG_SECURE` でスクリーンショットと
  最近使ったアプリの一覧のサムネイルを止められる。iOS はアプリが背景に回るときのサムネイルに画面が写るので、覆う処理があるかを見る
- **クリップボードに秘密の値を置いていないか。** 確認コードや口座番号をコピーさせる機能は、他のアプリから読まれる
  ことがある。Android 13 以降は、機微な内容として印を付ける指定（`ClipDescription.EXTRA_IS_SENSITIVE`）がある
- **プッシュ通知の本文に個人情報を入れていないか。** ロック画面に表示され、通知を配る事業者（APNs・FCM）も通る。
  本文は「新しいメッセージがあります」のようにし、内容はアプリを開いてから取りに行く形にする

### 6. 権限（MASVS-PRIVACY）

```bash
grep -rnE 'uses-permission|NS[A-Za-z]+UsageDescription' \
  --include='AndroidManifest.xml' --include='Info.plist' . 2>/dev/null | head -20
```

- **要求している権限が、機能に対して過剰でないか。** 位置情報・連絡先・カメラ・
  ストレージは、使っていないなら外す
- 権限の説明文が、実際の用途と合っているか。**ストアの審査と、
  `references/08-privacy-compliance.md` の文書との整合の両方に関わる**
- 取得した情報の送信先が、プライバシーポリシーに書かれているか（08 の 1 節・5 節）

### 7. 配布物に残るもの（MASVS-CODE / RESILIENCE）

- デバッグ用の設定が残っていないか（`android:debuggable`、テスト用のサーバー URL）
- **iOS のプライバシーマニフェスト**（`PrivacyInfo.xcprivacy`）。2024-05 から必須。収集するデータの申告が、
  `references/08-privacy-compliance.md` のプライバシー文書と食い違っていないか
- **Android の対象 API 水準。** Google Play は 2026-08-31 から新規と更新に API 36 を求めている。
  古い水準のままなら、TLS 1.0 / 1.1 の無効化（API 35）などの保護が適用されていない
- ログ出力が本番で無効になっているか
- **難読化・改竄検知は、優先度を上げすぎない。** 時間稼ぎであって、防御ではない。
  **サーバー側で守れていないことの代わりにはならない。**
  「難読化していないこと」を単独で指摘に挙げると、本当に危ないものが埋もれる

---

## 実機での確認

Web の `references/09-browser-verification.md` に相当する部分。**評価者が代行しない。**

- **通信の中継は行わない。** 端末に証明書を入れて通信を覗く作業は、
  依頼者の端末と資格情報を扱うことになる。**手順を渡して結果を受け取る**（03 のモード B）
- ストアの公開ページから確認できることはある（権限の一覧、プライバシーラベル、
  最終更新日、対応 OS 版）。**これは外部から見えるので、評価者が確認してよい**
- **Play の外（APK の直接配布）で配っているか。** Android の認定端末では、開発者の検証が段階的に求められる。
  2026-09-30 からブラジル・インドネシア・シンガポール・タイで、**指定のアプリストア（Google Play など 7 つ）から
  入れるアプリ**が対象になり、**2027 年に全世界の、認定端末に配られるすべてのアプリ**へ広がる。ADB や、利用者が
  危険を承知して 1 回だけ設定する経路では、未検証のアプリも入れられる。配布経路が変わる可能性を依頼者に伝える
- **配布物の解析（逆コンパイル）は、依頼者の許可を明示的に取ってから。**
  自社アプリであっても、契約や利用規約で制限されていることがある

---

## 指摘の書き方

**「アプリに鍵が入っている」で止めない。** その鍵で何ができるかまで書く。

```markdown
| 事実 | 第三者 API の鍵が <path> に埋め込まれている。この鍵は従量課金の
        API を呼べる（読み取り専用の識別子ではない） |
| 影響 | 配布物から取り出して、第三者が課金を発生させられる。
        利用量の上限も設定されていない |
| 是正 | 呼び出しをサーバー側に移し、アプリからは自社の API を叩く形にする。
        **鍵の差し替えにはアプリの更新が要るため、先に鍵を失効させると
        既存の利用者が使えなくなる。** 順序を決めてから実施する |
```

**台帳の列との対応**（`references/04-findings-register.md`）: 「事実」は指摘事項、「影響」は想定される影響、「是正」は是正案。鍵の差し替えは秘密情報の入れ替えとして枝番に分ける（`references/05-remediation-plan.md` の「秘密情報の入れ替え」）。配布物の解析で分かったものは、確認の方法を「実機」と書き、解析の許可を得た日を添える。

**更新の遅れを是正の手順に織り込む。** Web と違い、**直したものが全員に届くまでに
時間がかかる**。強制更新の仕組みがあるかどうかで、対応の組み立てが変わる。
