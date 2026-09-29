const jwt = require('jsonwebtoken'); const crypto = require('crypto');
function check(token) { return jwt.verify(token, "fake-jwt-secret-value-0001"); }
function sign(body) { return crypto.createHmac('sha256', 'fake-hmac-secret-value-0002').update(body).digest('hex'); }
const conf = { apiSecret: process.env.API_SECRET };
const admin = { password: "F@ke!#Passw0rd2024" };
const enabled = process.env.AUTH_ENABLED ?? true;
module.exports = { check, sign, conf, admin, enabled };
