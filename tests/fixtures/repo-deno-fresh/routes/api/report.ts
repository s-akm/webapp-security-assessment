export const handler = {
  async POST(req) {
    const { email } = await req.json();
    await sendMail(email);
    return new Response('{}');
  },
};
