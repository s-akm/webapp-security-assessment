server.get('/labels/:id', (req, res) => res.json(db.find(req.params.id)));
