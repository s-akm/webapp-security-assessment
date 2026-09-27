router.post('/signup', async (req, res) => {
  const user = await User.create({ email: req.body.email, role: req.body.role })
  res.json(user)
})
router.put('/profile', async (req, res) => {
  Object.assign(res.locals.user, req.body)
  await res.locals.user.save()
})
router.get('/items', (req, res) => res.json(items.filter(i => i.name === req.query.name)))
