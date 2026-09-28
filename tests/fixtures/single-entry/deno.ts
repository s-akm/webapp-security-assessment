Deno.serve(async (req) => {
  const { pathname } = new URL(req.url);
  switch (pathname) {
    case '/health':
      return new Response('ok');
    case '/settings':
      await requireAdmin(req);
      return new Response('{}');
  }
  return new Response('not found', { status: 404 });
});
