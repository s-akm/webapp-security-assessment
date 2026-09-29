'use server';
export async function removeItem(id) { await db.item.delete({ where: { id } }); }
