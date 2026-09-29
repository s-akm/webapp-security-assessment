app.get('/cfg', (req, res) => res.json({ botId: config.get('docsbot:id') }));
app.post('/count', (req, res) => { counts[id] = 1; res.end(); });
