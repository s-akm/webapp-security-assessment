// 署名を検証せず、中身だけ取り出している（audit_grep の 10 節で検出されるべき）。
import jwt from 'jsonwebtoken';
export function whoami(token: string) {
  const payload = jwt.decode(token);
  return payload.role;
}
// 例外の握りつぶし（12 節で検出されるべき）
export async function check(t: string) {
  try { return await verify(t); } catch (e) {}
  return true;
}
