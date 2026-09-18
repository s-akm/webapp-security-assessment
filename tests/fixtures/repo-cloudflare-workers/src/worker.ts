export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/admin') {
      const user = await requireAuth(request, env);
      if (!user) return new Response('no', { status: 401 });
      return new Response('{}');
    }
    if (url.pathname === '/api/report') {
      await sendMail(await request.text());
      return new Response('{}');
    }
    return new Response('not found', { status: 404 });
  },
};
