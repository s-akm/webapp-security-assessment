export function listen(token: string) {
  return new EventSource(`/api/stream?token=${token}`);
}
