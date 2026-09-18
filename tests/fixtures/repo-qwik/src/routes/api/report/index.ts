export const onPost = async ({ parseBody, json }) => {
  const body = await parseBody();
  await sendMail(body.email);
  json(200, { ok: true });
};
