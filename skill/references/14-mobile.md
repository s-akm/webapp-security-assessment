# モバイルアプリ

**評価対象にモバイルアプリが含まれるとき**に読む。Web だけなら不要。

**要否の判定**は事前の洗い出しの 0 節に出る。`android/` や `ios/` の
ディレクトリ、`pubspec.yaml`、`Podfile`、`build.gradle`、React Native や Capacitor の
依存があれば該当する。

## Web と何が違うか

**アプリは配布物になる。** ここが最大の違いで、判断の前提が変わる。

| | Web | モバイル |
|---|---|---|
| コードの所在 | サーバー側は手元に無い | **全部が利用者の端末にある** |
| 秘密の隠し場所 | サーバーに置ける | **無い。取り出せる前提で設計する** |
| 更新 | 配信すれば即時 | **審査と、利用者の更新操作が必要** |
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

OWASP MASVS の分類（Storage / Crypto / Auth / Network / Platform / Code / Resilience /
Privacy）に沿って並べてある（版は `references/06-frameworks.md` の表）。**該当しない項目は飛ばす。**
指摘には、分かる範囲で MASWE や MASTG-TEST の ID を添えると、依頼者側の開発者が一次情報を引ける。

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
# 引用符を使わない .properties と .env、アプリに焼き込まれる公開用の環境変数は、名前だけ出す
grep -rnoiE --exclude-dir=node_modules '^[[:space:]]*[A-Za-z0-9_.]*(password|secret|token|api[_-]?key)[A-Za-z0-9_.]*[[:space:]]*=' \
  --include='*.properties' --include='.env*' . 2>/dev/null
grep -rhoE --exclude-dir=node_modules '(EXPO_PUBLIC|REACT_APP|VITE|NEXT_PUBLIC|PUBLIC)_[A-Z0-9_]+' . 2>/dev/null | sort -u

# 設定ファイル。配布物に入るもの、入らないが署名の情報を持つもの
find . \( -name 'google-services.json' -o -name 'GoogleService-Info.plist' \
       -o -name '*.jks' -o -name '*.keystore' -o -name '*.p12' -o -name '*.mobileprovision' \
       -o -name 'keystore.properties' -o -name 'key.properties' -o -name 'local.properties' -o -name '.env*' \) \
  -not -path '*/node_modules/*' 2>/dev/null
```

**`EXPO_PUBLIC_` などの接頭辞が付いた変数は、ビルドのときにアプリの中へ文字列として入る。** 名前に SECRET・PRIVATE・SERVICE_ROLE・PASSWORD
が入るものは、その値が配布物から取り出せる。anon key や publishable key のような公開前提の鍵は、その鍵で何ができるかを下の表で確かめる。
`keystore.properties` や `key.properties` に署名鍵のパスワードが書かれ、リポジトリに入っていれば、署名鍵のファイルと合わせて偽アプリを作れる。

**すべての鍵が問題なわけではない。** 用途で分ける。

| 鍵の種類 | 判定 |
|---|---|
| 公開前提の識別子（Firebase の設定、計測 SDK の ID） | 問題なし。**サーバー側の権限設定で守る**（呼べる API が増える例外は下の段落） |
| 第三者 API の鍵で、**課金や特権操作ができる**もの | **問題あり。中継サーバーを挟む** |
| 署名鍵・配布用の証明書がリポジトリにある | **問題あり。これが漏れると偽アプリを作れる** |

**「鍵が入っている」だけで指摘にしない。** その鍵で何ができるかを確かめる。Firebase の設定ファイルは公開前提で、
守るのは**サーバー側の規則**になる（`references/03-runtime-verification.md` の 1 節）。

**ただし、公開前提の鍵でも呼べる API が増えることがある。** Google の `AIza…` の鍵は、同じ GCP プロジェクトで
Generative Language API（Gemini）を有効にすると、**配布済みの鍵のまま Gemini を呼べる**状態になる。
**その鍵に API の制限が掛かっているか**を、依頼者に GCP のコンソールで確かめてもらう
（渡す文面は `templates/client-console-checklist.md` の 11）。確かめられなければ未確認事項に残す。

**直し方:** 課金や特権操作ができる鍵は、自社のサーバー（BaaS の関数など）に移し、アプリはログインした利用者として自社の API を呼ぶ。
公開前提の鍵は、コンソールで呼べる API とアプリ（パッケージ名・バンドル ID）を制限する。署名鍵はリポジトリから外し、CI の秘密情報に置く。

### 2. 端末に保存しているもの（MASVS-STORAGE）

```bash
grep -rnE -e 'AsyncStorage|SharedPreferences|UserDefaults|NSUserDefaults|localStorage' \
  -e 'sqlite|Realm|shared_preferences|SecureStore|Keychain|EncryptedSharedPreferences' \
  -e '@AppStorage|kSecAttrAccessible|kSecAttrSynchronizable|ACCESSIBLE\.ALWAYS' \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.ts' --include='*.js' . 2>/dev/null | head -20
```

**保存先で判定が変わる。**

- **`Keychain`（iOS）/ Android Keystore を使った保存 / `SecureStore`** —
  資格情報の置き場として意図されたもの。問題なし。ただし Keychain の属性が `kSecAttrAccessibleAlways` 系（非推奨。包みのライブラリでは
  `ACCESSIBLE.ALWAYS`・`SecureStore.ALWAYS` など）ならロック中も読め、`ThisDeviceOnly` の付かない値や `kSecAttrSynchronizable` が true なら
  別の端末へ移る。トークンは `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` などの端末に閉じた値にする
- **`EncryptedSharedPreferences`** — 置き場としては今も安全側で、判定は**問題なし**。ライブラリが非推奨になっているので、
  `references/08-privacy-compliance.md` の 6 節と同じく「気づいたこと」として渡す（指摘には数えない）
- **`UserDefaults` / `SharedPreferences` / `AsyncStorage`** — 平文で残り、端末のバックアップにも入る。**認証トークンやパスワードを置いていれば指摘**。
  直し方は、Keychain・Keystore・`SecureStore` に移すこと。iOS は `defaults.set(…)`、Objective-C の `setObject:forKey:`、
  SwiftUI の `@AppStorage("…")`（中身は `UserDefaults`）も同じ置き場になる。鍵の名前（token・password・session など）で候補を絞り、中身を読んで確かめる
- **ログへの出力**。デバッグ用の出力（Android の `Log.*`・`Timber`、iOS の `print`・`NSLog`、React Native の `console.log`）に、個人情報や
  token を書いていないか。Android の `Log.*` は端末の共通のログ（logcat）に入る。直し方は、機微な値の出力を消し、配るビルドでは R8 で
  `Log.v`・`Log.d`・`Log.i` を消すこと（ログの行のうち token・passw・email などの語を含むものを探す）
- **バックアップの対象から外しているか**（Android の `allowBackup`、iOS の除外指定）。
  Android 12 以降は `android:dataExtractionRules` で、クラウドへのバックアップと端末間の転送を別々に指定するので、`allowBackup` だけで判定しない

### 3. 通信（MASVS-NETWORK）

```bash
# 平文通信の許可と、利用者が入れた証明書を信頼する設定
grep -rnE -e 'usesCleartextTraffic|cleartextTrafficPermitted|NSAllowsArbitraryLoads' \
  -e 'NSExceptionAllowsInsecureHTTPLoads|NSExceptionMinimumTLSVersion|NSExceptionRequiresForwardSecrecy|certificates src="user"' \
  --include='*.xml' --include='*.plist' --include='app.json' --include='app.config.*' . 2>/dev/null
# 証明書の検証を切っている
grep -rnE -e 'ServerTrustManager|allowInvalidCertificates|trustAllCerts|X509TrustManager' \
  -e 'setHostnameVerifier|badCertificateCallback|rejectUnauthorized' . 2>/dev/null | head
```

- **平文通信を許可していないか**（`usesCleartextTraffic="true"` / `NSAllowsArbitraryLoads`）。Android の `<base-config cleartextTrafficPermitted="true">`
  （すべての通信）か `<domain-config>`（一部のドメイン）かで重さが違う
- **iOS の ATS は、`NSAllowsArbitraryLoads` のほかにも緩める書き方がある。** 例外のドメインの `NSExceptionMinimumTLSVersion` を
  `TLSv1.2` より下げる、`NSExceptionRequiresForwardSecrecy` を `NO` にする、`NSExceptionAllowsInsecureHTTPLoads`・
  `NSAllowsArbitraryLoadsInWebContent`・`NSAllowsArbitraryLoadsForMedia` でその範囲の平文を許す。Expo では `app.json`・`app.config.*` の
  `ios.infoPlist` に書いた値が `Info.plist` に入るので、そこも読む
- **証明書の検証を切っていないか。** Web の O 節と同じだが、モバイルでは
  **開発中に入れた回避策がそのまま出荷される**ことが多い。直し方は、その回避の処理を消し、開発用の証明書は開発のビルドだけで信頼させること
- **Android の `network_security_config` で `<certificates src="user" />` を信頼していないか。** 利用者（や端末に入り込んだ
  第三者）が入れた証明書で、通信を中継して読める。`<debug-overrides>` の中や `src/debug/` の下だけなら、デバッグのビルドにしか入らない
- **証明書のピン留めは、無いこと自体は直ちに指摘ではない。** 入れているなら、鍵の更新で一斉に通信できなくならないよう更新の手順があるか

### 4. 認証とセッション（MASVS-AUTH）

- トークンの保管場所（2 節）と、有効期限
- **生体認証は「その端末の持ち主か」を確かめるもので、サーバー側の認証の代わりにはならない。** 通ったことをアプリ側の判定だけで
  サーバーに伝えていれば指摘になる（直し方は、Keychain・Keystore に置いた鍵の利用を生体認証で守り、その鍵での署名をサーバーで検証すること）
- ログアウトでトークンが失効するか（`references/09-browser-verification.md` の 7 節と同じ）
- **アプリや端末の真正性確認（Play Integrity・App Attest・Firebase App Check）を入れているなら、判定をサーバー側でしているか。**
  Firebase App Check は強制（enforcement）を有効にするまで何も拒否しない（Cloud Functions はコードの `enforceAppCheck: true`）。
  **認証や権限設定の代わりには数えない**

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
  組み立てていれば、アプリの文脈で攻撃者のページが動く。直し方は、読み込む先を自社のドメインの許可リストに限ること
- **JavaScript ブリッジ**（Android の `addJavascriptInterface`、iOS の `WKScriptMessageHandler` 等）で、端末側の機能を
  Web 側に渡していないか。外部のページを表示する WebView との組み合わせは危険。受け取る側で送り元のオリジンを確かめているか
- **WebView の緩い設定**（ファイルから任意のオリジンへ届く `AllowUniversalAccessFromFileURLs`・`AllowFileAccessFromFileURLs`、HTTP を混ぜる
  `MIXED_CONTENT_ALWAYS_ALLOW`・`mixedContentMode="always"`）。言語ごとに書き方と大文字小文字が違うので、上の検索の結果を読む。
  直し方は、その設定を外し、端末内のファイルは `WebViewAssetLoader` で読ませること
- **他アプリへ公開している入口**（Android の `exported="true"`）が意図したものか
- **画面の外へ個人情報が出る経路。** 個人情報を表示する画面のスクリーンショットとアプリの切り替えのサムネイル（Android は `FLAG_SECURE`、
  iOS は背景に回るときに覆う処理）、クリップボードに置く秘密の値（他のアプリから読まれることがある）、プッシュ通知の本文
  （ロック画面に出る。本文は「新しいメッセージがあります」にし、内容はアプリを開いてから取りに行く）

### 6. 権限（MASVS-PRIVACY）

```bash
grep -rnE 'uses-permission|NS[A-Za-z]+UsageDescription' \
  --include='AndroidManifest.xml' --include='Info.plist' . 2>/dev/null | head -20
```

- **要求している権限が、機能に対して過剰でないか。** 位置情報・連絡先・カメラ・ストレージは、使っていないなら外す
- 権限の説明文が実際の用途と合っているか、取得した情報の送信先がプライバシーポリシーに書かれているか（ストアの審査と 08 の 1 節・5 節の両方に関わる）

### 7. 配布物に残るもの（MASVS-CODE / RESILIENCE）

- デバッグ用の設定が残っていないか（`android:debuggable`、テスト用のサーバー URL）。**Gradle の `buildTypes` で、`debug` 以外
  （`release`・`staging` など）に `debuggable true`（Kotlin の DSL では `isDebuggable = true`）を書いていないか。** `debug` のビルドの種類に
  書いてあるのは問題ない。マニフェストに `android:debuggable="true"` を直に書くと、ビルドの種類を問わず作用する
- **実行時に外からコードを読み込んでいないか**（`DexClassLoader` など）。読み込む元が外部の保存領域や通信で取ったファイルなら、差し替えられて任意のコードが動く

```bash
grep -rnE '(isDebuggable|debuggable)[[:space:]]*=?[[:space:]]*true|android:debuggable="true"|DexClassLoader|InMemoryDexClassLoader' \
  --include='*.gradle' --include='*.kts' --include='AndroidManifest.xml' --include='*.java' --include='*.kt' . 2>/dev/null | grep -v node_modules
```
- **iOS のプライバシーマニフェスト**（`PrivacyInfo.xcprivacy`）の申告が、`references/08-privacy-compliance.md` のプライバシー文書と食い違っていないか
- **Android の対象 API 水準。** Google Play が求める水準を下回っていれば更新を配れなくなり、新しい水準で入った保護も適用されない。
  今の要求水準は Google Play の公式の資料で確かめる
- **難読化・改竄検知は、優先度を上げすぎない。** 時間稼ぎであって、サーバー側で守れていないことの代わりにはならない。
  「難読化していないこと」を単独で指摘に挙げると、本当に危ないものが埋もれる

---

## 実機での確認

Web の `references/09-browser-verification.md` に相当する部分。**評価者が代行しない。**

- **通信の中継は行わない。** 依頼者の端末と資格情報を扱うことになるので、**手順を渡して結果を受け取る**（03 のモード B）
- ストアの公開ページ（権限の一覧、プライバシーラベル、最終更新日、対応 OS 版）は外から見えるので、評価者が確認してよい
- **Play の外（APK の直接配布）で配っているか。** Android の認定端末では、開発者の身元の検証が段階的に求められるようになっている。
  配布経路が変わる可能性を依頼者に伝える（時期と対象は Google の公式の資料で確かめる）
- **配布物の解析（逆コンパイル）は、依頼者の許可を明示的に取ってから。** 自社アプリでも、契約や利用規約で制限されていることがある

---

## 指摘の書き方

**「アプリに鍵が入っている」で止めない。** その鍵で何ができるかまで書く。

```markdown
| 事実 | 第三者 API の鍵が <path> に埋め込まれている。この鍵は従量課金の
        API を呼べる（読み取り専用の識別子ではない） |
| 影響 | 配布物から取り出して、第三者が課金を発生させられる。
        利用量の上限も設定されていない |
| 是正 | 呼び出しをサーバー側に移し、アプリからは自社の API を叩く形にする。
        **鍵の差し替えにはアプリの更新が必要なため、先に鍵を失効させると
        既存の利用者が使えなくなる。** 順序を決めてから実施する |
```

**台帳の列との対応**（`references/04-findings-register.md`）: 「事実」は指摘事項、「影響」は想定される影響、「是正」は是正案。鍵の差し替えは秘密情報の入れ替えとして枝番に分ける（`references/05-remediation-plan.md` の「秘密情報の入れ替え」）。配布物の解析で分かったものは、確認の方法を「実機」と書き、解析の許可を得た日を添える。

**更新の遅れを是正の手順に織り込む。** Web と違い、**直したものが全員に届くまでに
時間がかかる**。強制更新の仕組みがあるかどうかで、対応の組み立てが変わる。
