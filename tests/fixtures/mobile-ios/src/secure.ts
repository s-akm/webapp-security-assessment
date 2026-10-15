import * as SecureStore from 'expo-secure-store';

// 架空の題材。端末のロック中も読める値で保存している
export async function keep(t: string) {
  await SecureStore.setItemAsync('session', t, { keychainAccessible: SecureStore.ALWAYS });
}

export async function keepSafe(t: string) {
  await SecureStore.setItemAsync('session', t, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY });
}

export const apiUrl = process.env.EXPO_PUBLIC_API_URL;
export const anonKey = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY;
export const publishable = process.env.EXPO_PUBLIC_STRIPE_PUBLISHABLE_KEY;
export const serviceRole = process.env.EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
export const hookSecret = process.env.EXPO_PUBLIC_WEBHOOK_SECRET;
