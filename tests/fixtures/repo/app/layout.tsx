// 共通レイアウトに計測タグ。9 節で検出されるべき。
import { GoogleTagManager } from '@next/third-parties/google';
export default function L({ children }) {
  return (<html><body>{children}<GoogleTagManager gtmId="GTM-TEST" /></body></html>);
}
