import { getSession } from '@solid-mediakit/auth';

export async function GET({ request }) {
  const session = await getSession(request);
  if (!session) return new Response('no', { status: 401 });
  return new Response('{}');
}
