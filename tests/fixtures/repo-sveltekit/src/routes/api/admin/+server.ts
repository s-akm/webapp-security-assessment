// ガードあり
export async function GET({ locals }) {
  if (!locals.user) return new Response('no', { status: 401 });
  return new Response('{}');
}
