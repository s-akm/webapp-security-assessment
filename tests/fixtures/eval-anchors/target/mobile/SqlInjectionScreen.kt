package com.example.notes

import com.example.notes.vulnerable_cache.Store

class SqlInjectionScreen {
  fun search(db: Db, q: String) = db.rawQuery("SELECT * FROM notes WHERE title = '" + q + "'", null)
}
