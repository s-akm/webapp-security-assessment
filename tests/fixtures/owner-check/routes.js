const express = require('express'); const router = express.Router();
router.get('/notes/:id', requireAuth, async (req, res) => {
  const note = await Note.findByPk(req.params.id);
  res.json(note);
});
router.get('/drafts/:id', requireAuth, async (req, res) => {
  const draft = await Draft.findOne({ where: { id: req.params.id, userId: req.user.id } });
  res.json(draft);
});
router.delete('/files/:fileId', requireAuth, async (req, res) => {
  const { fileId } = req.params;
  await pool.query('DELETE FROM files WHERE id = $1 AND owner_id = $2',
    [fileId, req.user.id]);
  res.sendStatus(204);
});
router.post('/bookings', requireAuth, async (req, res) => {
  const { roomId, date } = req.body;
  res.json(await Booking.create({ roomId, date }));
});
router.patch('/comments', requireAuth, async (req, res) => {
  await Comment.update({ text: req.body.text }, { where: { id: req.body.id } });
  res.sendStatus(204);
});
router.get('/invoices/:invoiceId', requireAuth, async (req, res) => {
  const user = req.user;
  audit(user.email);
  res.json(await Invoice.findByPk(req.params.invoiceId));
});
router.use('/internal/:id', denyAll(), (req, res) => res.json(load(req.params.id)));
router.get('/reports/:id', requireAuth, reports.show);
router.get('/articles/:slug', async (req, res) => {
  res.json(await Article.findOne({ where: { slug: req.params.slug } }));
});
router.delete('/articles/:slug', requireAuth, async (req, res) => {
  await Article.destroy({ where: { slug: req.params.slug } });
  res.sendStatus(204);
});
router.get('/shares/:id', async (req, res) => res.json(await Share.findByPk(req.params.id)));
function sortById(q) {
  const note = 'network must be eip155:<chainId>';
  return q.query('orderBy', 'id', 'ASC');
}
module.exports = router;
