// 1 層目。matcher の書き方で /api/public と /api/webhooks が対象から外れている。
// 「ミドルウェアがあるから安全」と考えていると、ここが穴になる。
export const config = {
  matcher: ['/api/admin/:path*', '/api/orders/:path*'],
};

export function middleware(req) {
  const session = req.cookies.get('session');
  if (!session) return Response.redirect(new URL('/login', req.url));
  return Response.next();
}
