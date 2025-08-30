// /api/auth/me.js
import { getSession } from '../_utils';

export default async function handler(req,res){
  const s = getSession(req);
  if(!s) return res.status(401).json({authenticated:false});
  res.status(200).json({authenticated:true, ...s});
}
