const db = require('./db')
// 検索の処理
app.get('/search', (req, res) => {
  // SQL injection: the query is built by concatenation
  const rows = db.query("SELECT id FROM items WHERE name = '" + req.query.q + "'") // 取得先の一覧
  res.json(rows)
})
const listUrl = 'https://example.com/weak-list' // 参照先
