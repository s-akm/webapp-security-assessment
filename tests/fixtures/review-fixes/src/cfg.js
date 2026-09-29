const cfg = { botId: config.get('docsbot:id') };
counts[id] = 1;
app.get('/cfg', (req, res) => res.json(cfg));
