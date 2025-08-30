import Stripe from 'stripe';

// Lee el cuerpo JSON en funciones serverless de Vercel
async function readJson(req) {
  return await new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

    const body = await readJson(req);
    const q = Number(body.quantity);

    if (!Number.isInteger(q) || q < 1 || q > 500) {
      return res.status(400).json({ error: 'Cantidad inválida' });
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [
        { price: process.env.PRICE_ID_NFC, quantity: q }
        // Alternativa sin PRICE_ID_NFC:
        // {
        //   price_data: {
        //     currency: 'eur',
        //     unit_amount: 500, // 5,00 € en céntimos
        //     product_data: { name: 'NFC' }
        //   },
        //   quantity: q
        // }
      ],

      success_url: `${process.env.BASE_URL}/exito.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/cancelado.html`,

      // Teléfono (para WhatsApp)
      phone_number_collection: { enabled: true },

      // Dirección de envío OBLIGATORIA (ajusta países)
      shipping_address_collection: {
        allowed_countries: ['ES'] // añade ['PT','FR',...] si envías a más
      },

      // Nombre del negocio OBLIGATORIO
      custom_fields: [
        {
          key: 'business_name',
          label: { type: 'custom', custom: 'Nombre del negocio' },
          type: 'text',
          optional: false,
          text: { maximum_length: 120 }
        }
      ],

      // Dirección de facturación automática (opcional)
      billing_address_collection: 'auto',

      // Mensajes informativos en Checkout
      custom_text: {
        shipping_address: {
          message: 'Usaremos esta dirección para enviar tus dispositivos Taply.'
        },
        submit: {
          message: 'Te contactaremos por WhatsApp al número indicado.'
        }
      },

      // Útil para identificar la compra en tu webhook
      metadata: { nfc_quantity: String(q) }
    });

    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('buy-nfc error:', e);
    return res.status(500).json({ error: 'No se pudo crear el checkout' });
  }
}
