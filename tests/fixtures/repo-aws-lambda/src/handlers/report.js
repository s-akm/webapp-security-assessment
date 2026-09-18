// ガードなし
exports.handler = async (event) => {
  const { email } = JSON.parse(event.body);
  await sendMail(email);
  return { statusCode: 200, body: '{}' };
};
