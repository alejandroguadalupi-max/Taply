// /api/auth/logout.js
import { clearCookie, json } from '../_utils.js';

export default async function handler(req, res) {
  clearCookie(res, 'taply_session');
  return json(res, 200, { ok:true });
}
