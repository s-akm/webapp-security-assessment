package com.example.notes.vulnerable_cache

object Store {
  fun save(prefs: Prefs, token: String) = prefs.putString("token", token)
}
