// /api/auth/start.js
import { sign } from './_session.js';

export default async function handler(req, res){
  if(req.method !== 'POST') return res.status(405).end();
  try{
    const { email } = await readJson(req);
    if(!email || !/.+@.+\..+/.test(email)) return res.status(400).json({error:'Email inválido'});

    const oneUse = sign({ email }, 15*60); // 15 min
    const link = `${process.env.BASE_URL}/api/auth/callback?token=${encodeURIComponent(oneUse)}`;

    // envía email con Resend
    const ok = await sendEmail({
      to: email,
      subject: 'Entra a tu cuenta Taply',
      html: `
        <p>Hola,</p>
        <p>Haz clic para entrar/crear tu cuenta en Taply:</p>
        <p><a href="${link}">${link}</a></p>
        <p>El enlace expira en 15 minutos.</p>`
    });
    if(!ok) return res.status(500).json({error:'No se pudo enviar el correo'});
    res.json({sent:true});
  }catch(e){
    console.error('auth/start', e);
    res.status(500).json({error:'Server error'});
  }
}

async function readJson(req){
  return await new Promise((resolve,reject)=>{
    let d=''; req.on('data',c=>d+=c);
    req.on('end',()=>{ try{ resolve(d?JSON.parse(d):{});}catch(e){reject(e)} });
    req.on('error',reject);
  });
}

async function sendEmail({to,subject,html}){
  try{
    const res = await fetch('https://api.resend.com/emails',{
      method:'POST',
      headers:{
        Authorization:`Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type':'application/json'
      },
      body:JSON.stringify({
        from: process.env.FROM_EMAIL || 'Taply <no-reply@taply.app>',
        to, subject, html
      })
    });
    return res.ok;
  }catch{ return false; }
}
