'use server';
// Server Actions。export した関数はすべてクライアントから直接呼べる。

// ガードあり。セッションから利用者を決めている
export async function addToCart(productId: string, qty: number) {
  const user = await getCurrentUser();
  if (!user) throw new Error('unauthorized');
  await db.from('cart').insert({ user_id: user.id, product_id: productId, qty });
}

// ガードなし。引数で受け取った利用者 ID をそのまま使っている（他人のカートを操作できる）
export async function clearCart(userId: string) {
  await db.from('cart').delete().eq('user_id', userId);
}

// export していない内部関数。入口にはならない
async function recalc(userId: string) { /* ... */ }
