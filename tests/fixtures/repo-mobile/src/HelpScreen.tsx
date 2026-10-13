import React from 'react';
import { WebView } from 'react-native-webview';

// 架空の画面。端末内のファイルとして開いたページから任意のオリジンへ届く
export function HelpScreen() {
  return (
    <WebView
      source={{ uri: 'file:///android_asset/help.html' }}
      allowUniversalAccessFromFileURLs={true}
      mixedContentMode="always"
    />
  );
}
