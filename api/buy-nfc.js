import Stripe from 'stripe';
import { readJson, getSession } from './_utils';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    const { quantity } = await readJson(req);
    const q = Number(quantity);

    if (!Number.isInteger(q) || q < 1 || q > 500) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }

    const sess = getSession(req);

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{ price: process.env.PRICE_ID_NFC, quantity: q }],
      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,
      phone_number_collection: { enabled: true },
      shipping_address_collection: { allowed_countries: ['ES'] },
      custom_fields: [
        { key: 'business_name', label:{type:'custom', custom:'Nombre del negocio'}, type:'text', optional:false, text:{maximum_length:120} },
        { key: 'contact_name',  label:{type:'custom', custom:'Nombre de contacto'}, type:'text', optional:false, text:{maximum_length:120} }
      ],
      billing_address_collection: 'auto',
      custom_text:{
        shipping_address:{message:'Usaremos esta dirección para enviar tus dispositivos NFC.'},
        submit:{message:'El número de teléfono es clave: te contactaremos por WhatsApp ahí.'}
      },
      metadata: { nfc_quantity: String(q) },
      ...(sess?.customerId ? { customer: sess.customerId } : {})
    });

    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('buy-nfc error:', e);
    return res.status(500).json({ error: 'No se pudo crear el checkout' });
  }
}
