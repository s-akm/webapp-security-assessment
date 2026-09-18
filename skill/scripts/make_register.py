#!/usr/bin/env python3
"""指摘台帳（xlsx）の雛形を生成する。

    python make_register.py <出力先.xlsx> [--service "サービス名"] [--date 2026-01-15]
                            [--frameworks none|owasp|full] [--owasp 2025|2021] [--api]

--frameworks で枠組みへの当てはめシートの構成を選ぶ。

    none   6 枚。個別の指摘だけを扱う。対外説明が要らない案件向け
    owasp  7 枚（既定）。OWASP Top 10 を 1 枚にまとめる
    full   9 枚。個人情報の安全管理措置・OWASP・IPA 非機能要求グレードを
           それぞれ独立させる。対外説明や水準の提示が要る案件向け

件数と工数の合計は数式で入っているので、指摘の行を足せば自動で追従する。
参照範囲は 200 行まで取ってあるため、行を足すときに数式へ手を入れる必要はない。

各シートには例示行を 1 行だけ入れてある（薄い黄色の網掛け）。書き方の見本なので、
実際の指摘を書き始めるときに上書きするか削除する。

注意: openpyxl は数式を文字列として書き込むだけで、計算結果は保持しない。
表計算ソフトで開くまで合計欄は空に見える。これは正常な挙動。
"""

import argparse
import datetime as _dt

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
except ImportError:  # noqa: BLE001
    import shutil
    import subprocess
    import sys as _sys

    print("openpyxl が見つからない。次のいずれかで導入する。", file=_sys.stderr)
    print(f"  {_sys.executable} -m pip install openpyxl", file=_sys.stderr)
    # 別の python に入っていることが多い。探して案内する。
    for _cand in ("/usr/bin/python3", "python3.13", "python3.12", "python3.11"):
        _path = _cand if _cand.startswith("/") else shutil.which(_cand)
        if not _path or _path == _sys.executable:
            continue
        _r = subprocess.run(
            [_path, "-c", "import openpyxl"], capture_output=True, check=False
        )
        if _r.returncode == 0:
            print(f"  すでに入っている python がある: {_path}", file=_sys.stderr)
            print(f"  例: {_path} {__file__} <出力先.xlsx>", file=_sys.stderr)
            break
    raise SystemExit(1)

FONT = "Yu Gothic"          # 日本語の報告書向け。英語のみなら "Arial" に変える
NAVY = "1D3A5C"
GRAY = "5B6B7B"
EXAMPLE_FILL = "FFFBEA"     # 例示行の網掛け
LAST = 200                  # 数式が参照する最終行

# シート名は構成によって変わる。指摘事項一覧を参照する数式があるため、
# 名前をここで一元管理して、数式側にも同じものを使う。
# full の並びと番号（6b_ を含む）は、実案件で使った台帳の構成に合わせてある。
LAYOUTS = {
    "none": {
        "summary": "1_総合評価", "runtime": "2_実機確認サマリ",
        "findings": "3_指摘事項一覧", "good": "4_評価できる実装",
        "unknown": "5_未確認事項", "roadmap": "6_対応ロードマップ",
    },
    "owasp": {
        "summary": "1_総合評価", "runtime": "2_実機確認サマリ",
        "findings": "3_指摘事項一覧", "good": "4_評価できる実装",
        "unknown": "5_未確認事項", "roadmap": "6_対応ロードマップ",
        "owasp": "7_枠組みへの当てはめ",
    },
    "full": {
        "summary": "1_総合評価", "runtime": "2_実機確認サマリ",
        "privacy": "3_個人情報セキュリティ", "owasp": "4_OWASP_Top10",
        "ipa": "5_IPA非機能要求グレード", "findings": "6_指摘事項一覧",
        "good": "6b_評価できる実装", "unknown": "7_残る未確認事項",
        "roadmap": "8_対応ロードマップ",
    },
}
# シートは LAYOUTS に書いた順に並ぶ（dict は挿入順を保つ）。
# 枠組みシートの位置が構成ごとに違う（owasp は最後、full は指摘一覧の前）ため、
# 全構成で共通の順序表を別に持つとここが必ずずれる。

PRIORITY_FILL = {
    "P0": "F5C6CB", "P1": "F8D7DA", "P2": "FDEBD0",
    "P3": "E3E9F3", "P4": "EDF1F6",
    "見送り": "E9ECEF", "クローズ": "E8F4EA",
}

thin = Side(style="thin", color="D6DCE4")
BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)


def title_block(ws, title, subtitle, width):
    ws["A1"] = title
    ws["A1"].font = Font(name=FONT, size=16, bold=True, color=NAVY)
    ws["A2"] = subtitle
    ws["A2"].font = Font(name=FONT, size=9, color=GRAY)
    ws["A2"].alignment = Alignment(vertical="top", wrap_text=True)
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=width)
    ws.row_dimensions[2].height = 32


def header_row(ws, row, headers, widths):
    for i, (h, w) in enumerate(zip(headers, widths), start=1):
        c = ws.cell(row=row, column=i, value=h)
        c.font = Font(name=FONT, size=10, bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor=NAVY)
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = BORDER
        ws.column_dimensions[get_column_letter(i)].width = w
    ws.row_dimensions[row].height = 30
    ws.freeze_panes = ws.cell(row=row + 1, column=1)


def body_row(ws, row, values, example=False):
    for i, v in enumerate(values, start=1):
        c = ws.cell(row=row, column=i, value=v)
        c.font = Font(name=FONT, size=10, italic=example)
        c.alignment = Alignment(vertical="top", wrap_text=True)
        c.border = BORDER
        if example:
            c.fill = PatternFill("solid", fgColor=EXAMPLE_FILL)
    if example and len(values) > 1 and values[1] in PRIORITY_FILL:
        ws.cell(row=row, column=2).fill = PatternFill("solid", fgColor=PRIORITY_FILL[values[1]])


def note(ws, row, text, width):
    c = ws.cell(row=row, column=1, value=text)
    c.font = Font(name=FONT, size=9, color=GRAY)
    c.alignment = Alignment(vertical="top", wrap_text=True)
    ws.merge_cells(start_row=row, start_column=1, end_row=row + 2, end_column=width)


# --------------------------------------------------------------------------
def sheet_summary(wb, names, service, date):
    ws = wb.create_sheet(names["summary"])
    title_block(ws, f"{service} セキュリティ評価",
                f"評価日 {date}／個人情報を取り扱う Web アプリケーションとしての適合性評価。"
                "件数と工数は『3_指摘事項一覧』から自動集計される。", 5)

    ws["A4"] = "■ 評価の前提"
    ws["A4"].font = Font(name=FONT, size=11, bold=True, color=NAVY)
    for i, (k, v) in enumerate([
        ("対象リビジョン", "（コミットハッシュ）"),
        ("評価方法", "（コードレビューの範囲／実機確認の実施日／外形テストの有無）"),
        ("保持する個人情報", "（具体的に列挙。決済情報の保持有無を明記）"),
        ("ログインする主体", "（役割ごとに、人数の桁と権限の範囲）"),
        ("評価者のアクセス範囲", "（見られたもの／見られなかったもの）"),
    ], start=5):
        ws.cell(row=i, column=1, value=k).font = Font(name=FONT, size=10, bold=True)
        c = ws.cell(row=i, column=2, value=v)
        c.font = Font(name=FONT, size=10, color=GRAY)
        ws.merge_cells(start_row=i, start_column=2, end_row=i, end_column=5)
    ws.column_dimensions["A"].width = 24
    for col in "BCDE":
        ws.column_dimensions[col].width = 22

    ws["A12"] = "■ 指摘事項の内訳（自動集計）"
    ws["A12"].font = Font(name=FONT, size=11, bold=True, color=NAVY)
    header_row(ws, 13, ["優先度", "件数", "", "AI 実装(h)", "人手(h)"], [24, 10, 4, 12, 12])
    ws.freeze_panes = None

    rows = [("P0（即日〜3日）", "P0"), ("P1（1〜2週間）", "P1"), ("P2（1か月）", "P2"),
            ("P3（3か月）", "P3"), ("P4（6か月）", "P4"),
            ("見送り（受容）", "見送り"), ("クローズ（解消済）", "クローズ")]
    src = "'{}'".format(names["findings"])
    for i, (label, key) in enumerate(rows):
        r = 14 + i
        body_row(ws, r, [label, None, "件", None, None])
        ws.cell(row=r, column=2).value = f'=COUNTIF({src}!$B$4:$B${LAST},"{key}")'
        ws.cell(row=r, column=4).value = f'=SUMIF({src}!$B$4:$B${LAST},"{key}",{src}!$G$4:$G${LAST})'
        ws.cell(row=r, column=5).value = f'=SUMIF({src}!$B$4:$B${LAST},"{key}",{src}!$H$4:$H${LAST})'
    r = 14 + len(rows)
    body_row(ws, r, ["合計", None, "件", None, None])
    for col in (2, 4, 5):
        L = get_column_letter(col)
        ws.cell(row=r, column=col).value = f"=SUM({L}14:{L}{r-1})"
        ws.cell(row=r, column=col).font = Font(name=FONT, size=10, bold=True)
    ws.cell(row=r, column=1).font = Font(name=FONT, size=10, bold=True)

    note(ws, r + 2,
         "【結論の書き方】土台として成立している点を先に置き、次に先に塞ぐべきものを 3 件まで。"
         "それぞれ「何が起きるか」を 2〜3 行で書く。5 件も 10 件も挙げるとどれも最優先でなくなる。",
         5)
    return ws


def sheet_runtime(wb, names):
    ws = wb.create_sheet(names["runtime"])
    title_block(ws, "実機確認サマリ",
                "コードからは判定できない実行環境の設定値について、参照系のみで確認した結果。"
                "データ変更・設定変更は行っていない。判定は 問題なし／問題あり／判断保留 の 3 値。"
                "参考情報として記録するだけの行には「参考」を使う。", 5)
    header_row(ws, 4, ["区分", "確認項目", "結果（事実）", "判定", "関連ID"], [16, 30, 70, 12, 14])
    body_row(ws, 5, ["アクセス制御", "全テーブルの行レベル権限",
                     "25 テーブルすべて有効。無効は 0 件（← 実行結果をそのまま書く。「問題ありませんでした」と要約しない）",
                     "問題なし", "S-02"], example=True)
    note(ws, 7,
         "【この欄の使い方】実行した SQL・コマンドの結果をそのまま残す。集約や整形をした場合は、"
         "元の行数と何をしたかを添える。例:「<n> 行返ったが読みづらいため、テーブル×ロールで集約"
         "（集約後 <m> 行、権限の総数は一致）」。", 5)
    return ws


def sheet_findings(wb, names):
    ws = wb.create_sheet(names["findings"])
    title_block(ws, "指摘事項一覧",
                "優先度：P0＝即日〜3日／P1＝1〜2週間／P2＝1か月／P3＝3か月／P4＝6か月／見送り／クローズ。"
                "ID は S-xx（コード監査）、N-xx（実機確認で判明）。一度振った ID は再利用しない。"
                "「指摘事項」には事実を、「想定される影響」には誰が何をできてしまうかを書く。", 10)
    header_row(ws, 3,
               ["ID", "優先度", "分類", "指摘事項", "該当箇所", "想定される影響",
                "AI実装(h)", "人手(h)", "是正案", "対応状況"],
               [8, 10, 18, 80, 40, 80, 11, 11, 88, 14])
    body_row(ws, 4, [
        "S-01", "P1", "認可",
        "注文の詳細を返すハンドラが、ログインの有無は確かめるが、注文の持ち主が要求した本人かを確かめていない。"
        "パスの注文 ID を書き換えると、他人の注文の氏名・配送先住所が返る。",
        "<ハンドラのファイル>:<行>",
        "会員登録をした誰でも、注文 ID を順に変えて全利用者の氏名と住所を取得できる。"
        "ID は連番なので総当たりの手間も無い。",
        1.5, 1,
        "取得の条件に、セッションの利用者 ID と注文の持ち主の一致を加える。同じリポジトリの"
        "<既存の実装のファイル> に同じ書き方があるので揃える。",
        None,
    ], example=True)
    # 合計行はこのシートに置かない。同一シート内に置くと、集計範囲を広く取ったときに
    # 合計セル自身を巻き込んで循環参照になる。範囲を狭く取れば今度は行を足したときに
    # 数式へ手を入れる必要が出る。集計は総合評価シートに一本化してある。
    return ws


def sheet_good(wb, names):
    ws = wb.create_sheet(names["good"])
    title_block(ws, "評価できる実装（維持すべき点）",
                "今後の改修で壊してはいけない実装。これを書かないと、修正の過程で壊れる。"
                "実機確認で裏が取れたものには【実機】と印を付ける。", 2)
    header_row(ws, 4, ["区分", "内容"], [20, 110])
    body_row(ws, 5, ["認可",
                     "全 API ルートにガードが存在する。無認証は問い合わせ受付・計測・ログアウト等、"
                     "意図された公開口のみ【実機】"], example=True)
    return ws


def sheet_unknown(wb, names):
    ws = wb.create_sheet(names["unknown"])
    title_block(ws, "残る未確認事項",
                "コード監査と実機確認を経て、なお確定していない項目。"
                "重要度「高」は、何かの作業を止めているもの。"
                "「調べれば分かるもの」と「担当者しか知らないもの」を区別して書く。", 5)
    header_row(ws, 4, ["No", "確認したい情報", "重要度", "取得方法", "影響する項目"], [8, 44, 10, 70, 16])
    body_row(ws, 5, ["U-1", "管理者アカウントの登録件数と内容", "高",
                     "担当者への確認が唯一の手段。ホスティングの秘匿指定により、"
                     "管理画面・CLI・API のいずれからも値を読み出せない仕様のため。",
                     "S-08"], example=True)
    note(ws, 7,
         "【作業を止めているものは表の外にも書く】例:「U-1 は S-08 の作業を止める。"
         "担当者への確認以外に取得手段がないため、着手と同時に依頼を出すこと。」", 5)
    return ws


def sheet_roadmap(wb, names):
    ws = wb.create_sheet(names["roadmap"])
    title_block(ws, "対応ロードマップ",
                "依存関係で並べる。深刻度順ではない。前提になっているもの（プラン変更、調査タスク、"
                "スキーマ復元）を先に置く。工数に待ち時間（確認待ち・観測期間・承認）は含めない。", 7)
    header_row(ws, 4, ["フェーズ", "時期", "対象ID", "実施内容", "AI実装", "人手", "補足"],
               [13, 13, 15, 44, 11, 11, 88])
    body_row(ws, 5, ["フェーズ1", "1〜2週間", "S-01", "注文の詳細を返すハンドラで、持ち主を照合する", 1.5, 1,
                     "別の利用者の注文 ID で 404 が返ることを自動テストで確かめる"], example=True)
    return ws


# 個人情報の安全管理措置のチェックリスト。実案件で使ったものを土台に、
# 特定の製品名・鍵の呼び名を外して汎用化してある。案件に合わせて足し引きする。
PRIVACY_ITEMS = [
    ("認証", "認証基盤に実績のある仕組みを使っているか"),
    ("認証", "管理者権限に多要素認証が設定されているか"),
    ("認証", "パスワードポリシーが定義されているか"),
    ("認証", "パスワードの配布方法が安全か"),
    ("認証", "パスワード再設定の導線が安全か"),
    ("認証", "アカウント発行が制御されているか"),
    ("認証", "クライアント側のみの認証判定に依存していないか"),
    ("認証", "トークンの署名を検証しているか（復号だけで済ませていないか）"),
    ("認証", "外部の認証基盤を使う場合、戻り先 URL が完全一致で設定されているか"),
    ("認可", "全ての API エンドポイントに認可判定があるか"),
    ("認可", "ロール情報をクライアントが改竄できない場所に保持しているか"),
    ("認可", "他人のデータを ID 指定で操作できないか（IDOR）"),
    ("認可", "認可の付け忘れを機械的に検出できるか"),
    ("認可", "認可の枠組み自体が破られた場合の備えがあるか（多層になっているか）"),
    ("データ保護", "行レベルの権限制御が有効か"),
    ("データ保護", "公開鍵から業務データが読めない設計か"),
    ("データ保護", "権限制御の対象外となる権限が残っていないか"),
    ("データ保護", "権限制御を迂回する鍵がクライアントへ流出しない仕組みがあるか"),
    ("データ保護", "権限制御を迂回する経路が無いか（定義者権限の関数・ビュー）"),
    ("データ保護", "通信が暗号化されているか"),
    ("データ保護", "保管データが暗号化されているか"),
    ("データ保護", "DB への到達経路が制限されているか"),
    ("データ保護", "個人情報の第三者提供が制御されているか"),
    ("データ保護", "個人情報の保存期間・削除方針が定義されているか"),
    ("入力検証", "SQL インジェクション対策"),
    ("入力検証", "サーバー側での入力検証を行っているか"),
    ("入力検証", "XSS 対策"),
    ("入力検証", "CSV 出力の数式インジェクション対策"),
    ("入力検証", "SSRF 対策"),
    ("濫用対策", "公開エンドポイントに BOT 対策があるか"),
    ("濫用対策", "レート制限があるか"),
    ("濫用対策", "メール送信が第三者に悪用されないか"),
    ("濫用対策", "業務上の課金経路が保護されているか"),
    ("濫用対策", "従量課金の経路に上限と監視があるか"),
    ("秘密情報", "ソースコードに秘密情報が含まれていないか"),
    ("秘密情報", "秘密情報の保管場所が適切か"),
    ("秘密情報", "鍵の用途が分離されているか"),
    ("秘密情報", "使用していない鍵が無効化されているか"),
    ("ログ・監査", "個人情報へのアクセス記録を保存しているか"),
    ("ログ・監査", "異常検知・アラートの仕組みがあるか"),
    ("ログ・監査", "ログの保存期間が定義されているか"),
    ("構成管理", "セキュリティヘッダが設定されているか"),
    ("構成管理", "本番に開発用のバイパスが残っていないか"),
    ("構成管理", "検証環境が本番から分離されているか"),
    ("構成管理", "Webhook の真正性を検証しているか"),
    ("構成管理", "例外が起きたときに権限が開く側へ倒れないか"),
    ("構成管理", "DB スキーマがバージョン管理されているか"),
    ("構成管理", "静的解析が CI で動いているか"),
    ("脆弱性管理", "依存パッケージの脆弱性を継続監視しているか"),
    ("脆弱性管理", "依存の取得元と名前を確認しているか"),
    ("脆弱性管理", "基盤のバージョンが最新に保たれているか"),
    ("脆弱性管理", "定期的な脆弱性診断を実施しているか"),
    ("事業継続", "バックアップが取得されているか"),
    ("事業継続", "復旧目標（RTO / RPO）が定義されているか"),
    ("事業継続", "インシデント対応手順があるか"),
    ("委託先管理", "委託先の安全管理措置を確認しているか"),
    ("委託先管理", "越境移転の説明ができるか"),
    ("委託先管理", "権限が必要最小限に絞られているか"),
]

# IPA 非機能要求グレードの 6 大項目と、実案件で使った中項目。
IPA_METRICS = [
    ("A. 可用性", "継続性：運用スケジュール（サービス時間）"),
    ("A. 可用性", "継続性：目標復旧水準（RTO / RPO）"),
    ("A. 可用性", "継続性：稼働率"),
    ("A. 可用性", "耐障害性：サーバ／データの冗長化"),
    ("A. 可用性", "回復性：バックアップ方式・保存期間"),
    ("A. 可用性", "災害対策：システム復旧（リージョン障害）"),
    ("B. 性能・拡張性", "業務量：通常時／ピーク時のリクエスト数"),
    ("B. 性能・拡張性", "性能目標値：レスポンスタイム"),
    ("B. 性能・拡張性", "リソース拡張性：CPU / メモリ / ディスク"),
    ("B. 性能・拡張性", "性能試験：試験実施の有無"),
    ("C. 運用・保守性", "通常運用：運用時間・バックアップ運用"),
    ("C. 運用・保守性", "通常運用：監視（稼働・性能・異常）"),
    ("C. 運用・保守性", "保守運用：パッチ適用（脆弱性対応）"),
    ("C. 運用・保守性", "運用環境：ログ取得・保存期間"),
    ("C. 運用・保守性", "運用環境：検証環境の分離"),
    ("C. 運用・保守性", "運用体制：障害時の連絡体制"),
    ("D. 移行性", "移行方式：移行スケジュール・体制"),
    ("D. 移行性", "移行データ：移行対象・移行ツール"),
    ("E. セキュリティ", "前提条件：情報資産の重要度"),
    ("E. セキュリティ", "認証：本人認証（認証方式）"),
    ("E. セキュリティ", "利用制限：管理方法（アクセス制御）"),
    ("E. セキュリティ", "データの秘匿：暗号化（通信／保管）"),
    ("E. セキュリティ", "不正監視：監視対象・追跡（監査ログ）"),
    ("E. セキュリティ", "Web 対策：不正アクセス対策"),
    ("E. セキュリティ", "ネットワーク対策：経路の制限"),
    ("E. セキュリティ", "マルウェア対策・脆弱性管理"),
    ("E. セキュリティ", "セキュリティリスク分析・診断"),
    ("F. システム環境・エコロジー", "システム制約・前提条件"),
    ("F. システム環境・エコロジー", "環境マネジメント・耐震／免震"),
]


def sheet_privacy(wb, names):
    ws = wb.create_sheet(names["privacy"])
    title_block(ws, "個人情報取扱いのチェックリスト",
                "個人情報保護法の安全管理措置と、実装上の定石にもとづく確認項目。"
                "判定は 適合／不適合／判断保留 の 3 値。根拠には実行結果を書き、"
                "実機で確定したものには【実機確定】と印を付ける。関連 ID が無い行は「—」。"
                "この一覧は出発点で、案件に無い項目は消し、固有の項目は足す。", 5)
    header_row(ws, 4, ["区分", "確認項目", "判定", "確認結果（根拠）", "関連ID"],
               [18, 46, 12, 80, 14])
    body_row(ws, 5, ["認証", "管理者権限に多要素認証が設定されているか", "不適合",
                     "【実機確定】多要素認証の登録が 0 件。9 アカウント全員が未登録（← 実行結果を"
                     "そのまま書く。「設定されていませんでした」と要約しない）",
                     "S-08"], example=True)
    for i, (kubun, item) in enumerate(PRIVACY_ITEMS, start=6):
        body_row(ws, i, [kubun, item, "", "", ""])
    note(ws, len(PRIVACY_ITEMS) + 7,
         "【未確認と判断保留を区別する】「調べれば分かる」ものは未確認事項（U-x）に回す。"
         "「事業側が決める」ものが判断保留。前者を判断保留に混ぜると、誰も動かないまま残る。", 5)
    return ws


def sheet_ipa(wb, names):
    ws = wb.create_sheet(names["ipa"])
    title_block(ws, "IPA 非機能要求グレードによる水準評価",
                "6 大項目について、現状の水準と事業として求められる水準を並べ、ギャップを示す。"
                "可用性や性能が低い水準にあること自体は、事業フェーズによっては合理的な選択。"
                "この表の価値は、セキュリティだけが低い水準に留まってはいけない理由を示せる点にある。", 6)

    ws["A4"] = "■ モデルシステムとの対比"
    ws["A4"].font = Font(name=FONT, size=11, bold=True, color=NAVY)
    header_row(ws, 5, ["区分", "定義", "本システムとの関係", "", "内容", ""], [22, 32, 22, 4, 60, 4])
    ws.merge_cells(start_row=5, start_column=3, end_row=5, end_column=4)
    ws.merge_cells(start_row=5, start_column=5, end_row=5, end_column=6)
    ws.freeze_panes = None
    for i, (a, b) in enumerate([
        ("モデルシステム①", "社会的影響が殆ど無いシステム"),
        ("モデルシステム②", "社会的影響が限定されるシステム"),
        ("モデルシステム③", "社会的影響が極めて大きいシステム"),
    ], start=6):
        body_row(ws, i, [a, b, "（現状水準／求められる水準／該当しない）", "", "", ""])
        ws.merge_cells(start_row=i, start_column=3, end_row=i, end_column=4)
        ws.merge_cells(start_row=i, start_column=5, end_row=i, end_column=6)

    ws["A10"] = "■ 大項目別の評価"
    ws["A10"].font = Font(name=FONT, size=11, bold=True, color=NAVY)
    header_row(ws, 11, ["大項目", "中項目（メトリクス）", "現状Lv", "推奨Lv",
                        "現状の根拠", "ギャップを埋める施策"], [22, 42, 9, 9, 66, 66])
    ws.freeze_panes = None
    body_row(ws, 12, ["A. 可用性", "回復性：バックアップ方式・保存期間", 0, 3,
                      "【実機確定】日次バックアップも時点復旧も存在しない（← 実行結果をそのまま書く）",
                      "有償プランへ移行し日次バックアップを有効化。復元テストまで行う"],
             example=True)
    for i, (dai, chu) in enumerate(IPA_METRICS, start=13):
        body_row(ws, i, [dai, chu, "", "", "", ""])
    note(ws, len(IPA_METRICS) + 14,
         "【全項目を上げましょう、と書かない】上げるべき 1 項目を特定して、"
         "そのギャップの中身を 4 つ以内に絞る。個人情報を第三者に開示する業務を担っているなら、"
         "他の項目が低水準でも、セキュリティだけは一段上が要る。この対比が投資判断の材料になる。", 6)
    return ws


# OWASP Top 10 の版。既定は 2025。依頼者が既に 2021 版で文書を作っている場合や、
# 取引先の審査項目が 2021 版で書かれている場合のために、2021 版も選べるようにしてある。
OWASP = {
    "2025": [
        ("A01", "Broken Access Control"),
        ("A02", "Security Misconfiguration"),
        ("A03", "Software Supply Chain Failures"),
        ("A04", "Cryptographic Failures"),
        ("A05", "Injection"),
        ("A06", "Insecure Design"),
        ("A07", "Authentication Failures"),
        ("A08", "Software or Data Integrity Failures"),
        ("A09", "Security Logging & Alerting Failures"),
        ("A10", "Mishandling of Exceptional Conditions"),
    ],
    "2021": [
        ("A01", "Broken Access Control"),
        ("A02", "Cryptographic Failures"),
        ("A03", "Injection"),
        ("A04", "Insecure Design"),
        ("A05", "Security Misconfiguration"),
        ("A06", "Vulnerable and Outdated Components"),
        ("A07", "Identification and Authentication Failures"),
        ("A08", "Software and Data Integrity Failures"),
        ("A09", "Security Logging and Monitoring Failures"),
        ("A10", "Server-Side Request Forgery"),
    ],
}


# OWASP API Security Top 10 (2023)。API が主体の構成のときだけ使う。
# 一般の Top 10 と重なる部分が多いので、両方を並べない。
API_TOP10 = [
    ("API1", "Broken Object Level Authorization", "他人の ID を指定して到達できないか（監査 A-3）"),
    ("API2", "Broken Authentication", "認証の強度、トークンの検証（監査 B 群）"),
    ("API3", "Broken Object Property Level Authorization",
     "更新でオブジェクトをそのまま渡していないか／応答に不要な項目が無いか"),
    ("API4", "Unrestricted Resource Consumption", "レート制限、件数の上限、ページングの強制（監査 F-2）"),
    ("API5", "Broken Function Level Authorization", "管理用の操作を一般利用者が呼べないか（監査 A-1）"),
    ("API6", "Unrestricted Access to Sensitive Business Flows",
     "自動化されると困る流れに対策があるか（監査 F-1）"),
    ("API7", "Server Side Request Forgery", "外部への通信先を外部入力から組み立てていないか"),
    ("API8", "Security Misconfiguration", "設定の既定値、開発用の残骸（監査 I ／ 実機確認）"),
    ("API9", "Improper Inventory Management", "使われていない旧版の API が生きていないか（監査 J）"),
    ("API10", "Unsafe Consumption of APIs", "呼び出している外部 API の応答を検証しているか"),
]


def sheet_api(wb, names):
    ws = wb.create_sheet(names["api"])
    title_block(ws, "OWASP API Security Top 10 (2023) への当てはめ",
                "API が主体の構成のときに使う。一般の Top 10 と重なるため、両方は並べない。"
                "一般の Top 10 では拾いにくい API3（プロパティ単位の認可）と "
                "API9（旧版 API の放置）のために当てはめる価値がある。", 5)
    header_row(ws, 4, ["No", "カテゴリ", "判定", "主に見るもの", "根拠（要約）"],
               [9, 46, 14, 60, 90])
    for i, (no, name, watch) in enumerate(API_TOP10, start=5):
        body_row(ws, i, [no, name, "", watch, ""])
    note(ws, len(API_TOP10) + 6,
         "【API3 と API9 を書き落とさない】API3 は応答そのものを見ないと分からない"
         "（画面で使っていない項目が含まれていないか）。API9 は旧版が残っていると、"
         "新版で塞いだ穴がそちらに残る。ルート一覧に版ごとの重複が無いかを見る。", 5)
    return ws


def sheet_owasp(wb, names, edition="2025"):
    ws = wb.create_sheet(names["owasp"])
    title_block(ws, f"OWASP Top 10 ({edition}) への当てはめ",
                f"OWASP Top 10 の {edition} 版で判定する。個別の指摘を洗い出した後に行う。"
                "対外説明・網羅性の確認が要る場合のみ。判定だけでなく根拠を 1 行添える。"
                "「適合」だけだと、見たうえでの適合なのか、見ていないだけなのかが分からない。", 4)
    header_row(ws, 4, ["No", "カテゴリ", "判定", "根拠（要約）"], [8, 46, 16, 100])
    rows = OWASP[edition]
    for i, (no, name) in enumerate(rows, start=5):
        body_row(ws, i, [no, name, "", ""])
    extra = ("【どの版で書いたかを必ず明記する】版を書かない適合表は、読み手が何と比べているか"
             "分からない。2025 版では SSRF が A01 に統合され、A03 がサプライチェーン全体に、"
             "A10 が例外処理（fail-open を含む）になっている。"
             if edition == "2025" else
             "【どの版で書いたかを必ず明記する】これは 2021 版。2025 版では順序と範囲が変わっている"
             "（SSRF は A01 に統合、A03 はサプライチェーン全体、A10 は例外処理）。"
             "新しく作る報告書では 2025 版を使う。")
    note(ws, len(rows) + 6,
         extra + "【静的検証の限界を明記する】動的な検査（実際に攻撃を試す）をしていないなら、"
         "そう書く。判定できる範囲がどこまでかを示すことが、報告書の信頼性になる。", 4)
    return ws


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="指摘台帳（xlsx）の雛形を生成する")
    ap.add_argument("output", help="出力先の .xlsx パス")
    ap.add_argument("--service", default="（サービス名）", help="対象サービス名")
    ap.add_argument("--date", default=_dt.date.today().isoformat(), help="評価日 (YYYY-MM-DD)")
    ap.add_argument("--frameworks", choices=("none", "owasp", "full"), default="owasp",
                    help="枠組みへの当てはめシートの構成（既定: owasp）")
    ap.add_argument("--owasp", choices=("2025", "2021"), default="2025",
                    help="OWASP Top 10 の版（既定: 2025）")
    ap.add_argument("--api", action="store_true",
                    help="OWASP API Security Top 10 のシートも作る（API が主体の構成のとき）")
    args = ap.parse_args()

    names = dict(LAYOUTS[args.frameworks])
    if args.api:
        # 枠組みシートの直後に置く。dict は挿入順で並ぶため、作り直して位置を決める。
        if "owasp" in names:
            rebuilt = {}
            for k, v in names.items():
                rebuilt[k] = v
                if k == "owasp":
                    rebuilt["api"] = "4b_API_Top10" if args.frameworks == "full" else "8_API_Top10"
            names = rebuilt
        else:
            names["api"] = "7_API_Top10"
    builders = {
        "summary": lambda: sheet_summary(wb, names, args.service, args.date),
        "runtime": lambda: sheet_runtime(wb, names),
        "privacy": lambda: sheet_privacy(wb, names),
        "owasp": lambda: sheet_owasp(wb, names, args.owasp),
        "api": lambda: sheet_api(wb, names),
        "ipa": lambda: sheet_ipa(wb, names),
        "findings": lambda: sheet_findings(wb, names),
        "good": lambda: sheet_good(wb, names),
        "unknown": lambda: sheet_unknown(wb, names),
        "roadmap": lambda: sheet_roadmap(wb, names),
    }

    wb = Workbook()
    wb.remove(wb.active)
    for key in names:
        builders[key]()
    wb.save(args.output)

    suffix = f" / OWASP {args.owasp} 版" if "owasp" in names else ""
    print(f"生成: {args.output}（--frameworks {args.frameworks}{suffix}）")
    print(f"  シート {len(wb.sheetnames)} 枚: {', '.join(wb.sheetnames)}")
    print()
    print("  ・薄い黄色の斜体行は書き方の例。実際の指摘を書くときに上書きするか削除する")
    print("  ・件数と工数の合計は数式。行を足せば自動で追従する（参照範囲は 200 行まで）")
    print("  ・表計算ソフトで開くまで合計欄は空に見える。openpyxl は計算結果を持たないため")


if __name__ == "__main__":
    main()
