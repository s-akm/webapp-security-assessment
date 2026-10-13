import AsyncStorage from '@react-native-async-storage/async-storage';

// 認証トークンを平文の保存領域に置いている
export async function saveToken(t: string) { await AsyncStorage.setItem('authToken', t); }

// 資格情報ではない値（★ を付けない）
export async function saveTheme(theme: string) { await AsyncStorage.setItem('theme', theme); }

// 課金できる第三者 API の鍵が埋め込まれている
const PAYMENT_API_KEY = "sk_live_00000000000000000000MOBILEDUMMY";

export function debugLogin(t: string) { console.log('login token', t); }
