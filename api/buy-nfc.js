import Stripe from 'stripe';

async function readJson(req){
  return await new Promise((resolve, reject)=>{
    let data=''; req.on('data', c=>data+=c);
    req.on('end', ()=>{ try{ resolve(data?JSON.parse(data):{});} catch(e){ reject(e);} });
    req.on('error', reject);
  });
}

export default async function handler(req,res){
  if (req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });
  try{
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const body = await readJson(req);
    const q = Number(body.quantity);
    if (!Number.isInteger(q) || q < 1 || q > 500) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }
    if (!process.env.PRICE_ID_NFC) {
      return res.status(500).json({ error: 'PRICE_ID_NFC no configurado' });
    }
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: process.env.PRICE_ID_NFC, quantity: q }],
      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,
      phone_number_collection: { enabled: true },
      shipping_address_collection: { allowed_countries: ['ES'] },
      billing_address_collection: 'auto',
      custom_fields: [
        { key:'business_name', label:{type:'custom', custom:'Nombre del negocio'}, type:'text', optional:false, text:{maximum_length:120} },
        { key:'contact_name',  label:{type:'custom', custom:'Nombre y apellidos'}, type:'text', optional:false, text:{maximum_length:120} },
        { key:'contact_phone', label:{type:'custom', custom:'Teléfono (WhatsApp)'}, type:'text', optional:false, text:{maximum_length:30} },
      ],
      metadata: { nfc_quantity: String(q) },
    });
    return res.status(200).json({ url: session.url });
  }catch(e){
    console.error('buy-nfc error:', e);
    return res.status(500).json({ error: e?.message || 'No se pudo crear el checkout' });
  }
}
