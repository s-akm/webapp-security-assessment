module.exports = async function (context, req) {
  await sendMail(req.body.email);
  context.res = { body: '{}' };
};
