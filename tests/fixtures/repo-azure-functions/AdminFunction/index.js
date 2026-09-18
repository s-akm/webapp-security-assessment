module.exports = async function (context, req) {
  const user = await requireAuth(req.headers.authorization);
  if (!user) { context.res = { status: 401 }; return; }
  context.res = { body: '{}' };
};
