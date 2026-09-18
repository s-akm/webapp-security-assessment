export const POST = async ({ request }) => {
  const { email } = await request.json();
  await sendMail(email);
  return new Response('{}');
};
