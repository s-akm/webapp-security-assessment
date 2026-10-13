package com.example.fixture;

import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;
import dalvik.system.DexClassLoader;

// 架空のコード。動くアプリではない
public class HelpActivity {
    private static final String TAG = "Help";

    void setup(WebView view, String sessionToken, String pluginPath) {
        WebSettings settings = view.getSettings();
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        // settings.setAllowUniversalAccessFromFileURLs(true);
        Log.d(TAG, "session token: " + sessionToken);
        Log.d(TAG, "help screen opened");
        DexClassLoader loader = new DexClassLoader(pluginPath, null, null, getClass().getClassLoader());
    }
}
