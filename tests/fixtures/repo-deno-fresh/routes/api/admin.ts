export const handler = {
  async GET(req, ctx) {
    if (!ctx.state.user) return new Response('no', { status: 401 });
    return new Response('{}');
  },
};
