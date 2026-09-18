// 認可ガードが無いハンドラ。audit_grep.sh の 2 節で「ガード検出なし」と出るべき。
export async function POST(req: Request) {
  const { email } = await req.json();
  await sendMail({ to: email });
  return Response.json({ ok: true });
}
