const express = require('express'); const app = express();
app.get('/hello', (req, res) => { res.send('<h1>Hello ' + req.query.name + '</h1>'); });
app.post('/profile', async (req, res) => { const { role } = await req.json(); await db.user.update({ where: { id: 1 }, data: await req.json() }); });
app.use('/raw', express.raw({ type: 'application/octet-stream' }));
exports.formatDate = (d) => d.toISOString();
// unauthenticated users can read this report
// TODO: requireAuth をここに足す
const unauthenticatedHits = 0;
app.get('/report', (req, res) => { res.json({}); });
app.get('/items/:id', async (req, res) => { res.json(await Item.findByPk(req.params.id)); });
app.use(require('cors')({ origin: true, credentials: true }));
app.use(require('express-session')({ secret: process.env.S }));
app.post('/otp/verify', async (req, res) => { res.json({ ok: await verifyOtp(req.body.code) }); });
async function q(id) { return prisma.$queryRawUnsafe(`SELECT 1 WHERE id = ${id}`); }
module.exports = app;
