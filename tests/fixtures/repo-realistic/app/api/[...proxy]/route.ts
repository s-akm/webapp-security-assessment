// 任意のパスを受けて外部へ中継する。宛先を外部入力から組み立てている（SSRF）
export async function GET(req: Request, { params }) {
  const target = `https://internal.example.com/${params.proxy.join('/')}`;
  const res = await fetch(target);
  return new Response(await res.text());
}
