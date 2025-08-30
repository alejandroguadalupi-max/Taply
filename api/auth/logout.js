// /api/auth/logout.js
import { clearSession } from '../_utils';

export default async function handler(req,res){
  if(req.method!=='POST') return res.status(405).json({error:'Method not allowed'});
  clearSession(res);
  res.status(200).json({ok:true});
}
