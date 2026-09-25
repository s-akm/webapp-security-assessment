import * as Sentry from '@sentry/nextjs';
Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  replaysSessionSampleRate: 0.1,
  replaysOnErrorSampleRate: 1.0,
  integrations: [
    Sentry.replayIntegration({ maskAllText: false, networkDetailAllowUrls: ['/api/'] }),
  ],
});
export function identify(email: string) {
  Sentry.setUser({ email });
}
