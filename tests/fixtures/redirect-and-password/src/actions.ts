// 架空の題材: Next.js のサーバーアクション
'use server';
import { redirect } from 'next/navigation';
import { z } from 'zod';

const SignUp = z.object({
  email: z.string().email(),
  password: z.string().min(10),
  name: z.string().min(1),
});

export async function login(formData: FormData) {
  const after = formData.get('redirectTo') as string;
  await authenticate(formData);
  redirect(after);
}

export async function acceptInvite(formData: FormData) {
  const code = formData.get('code');
  const returnTo = formData.get('returnTo')?.toString() ?? '/';
  const invite = await findInvite(code);
  if (!invite) {
    return { error: 'not found' };
  }
  await markAccepted(invite);
  await addMember(invite.teamId, invite.email);
  await sendWelcome(invite.email);
  await writeAudit('invite.accepted', invite.id);
  await refreshTeamCache(invite.teamId);
  await refreshBilling(invite.teamId);
  await refreshSeats(invite.teamId);
  await scheduleOnboarding(invite.teamId);
  await clearPending(invite.id);
  await revalidateTeam(invite.teamId);
  await notifyAdmins(invite.teamId);
  await recordMetric("invite", invite.teamId);
  redirect(returnTo);
}
