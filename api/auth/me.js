// /api/auth/me.js
import { getSessionUser, json } from '../_utils.js';

export default async function handler(req, res) {
  const user = getSessionUser(req);
  if (!user) return json(res, 401, { ok:false });
  return json(res, 200, { ok:true, user });
}
