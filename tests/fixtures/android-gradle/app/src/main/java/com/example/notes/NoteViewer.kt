package com.example.notes

import android.content.SharedPreferences
import android.util.Log
import android.webkit.WebView

// 架空のコード。動くアプリではない
class NoteViewer(private val prefs: SharedPreferences) {
    fun setup(view: WebView) {
        view.settings.allowFileAccessFromFileURLs = false
        view.settings.allowUniversalAccessFromFileURLs = false
        prefs.edit().putString("theme", "dark").apply()
        Log.d("NoteViewer", "viewer opened")
    }
}
