const fastify = require('fastify')();

fastify.get('/api/admin', { preHandler: requireAuth }, async () => ({ ok: true }));
fastify.post('/api/report', async (req) => {
  await sendMail(req.body.email);
  return { ok: true };
});
module.exports = fastify;
