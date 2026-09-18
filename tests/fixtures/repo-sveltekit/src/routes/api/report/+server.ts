// ガードなし
export async function POST({ request }) {
  const { email } = await request.json();
  await sendMail(email);
  return new Response('{}');
}
