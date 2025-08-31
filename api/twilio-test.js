import twilio from 'twilio';

export default async function handler(req, res) {
  try {
    const to = (req.query.to || '').trim(); // /api/twilio-test?to=+34XXXXXXXXX
    if (!to) return res.status(400).json({ error: 'missing_to' });

    const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM } = process.env;
    const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    const msg = await client.messages.create({
      from: TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886',
      to: `whatsapp:${to}`,
      body: 'Ping Twilio OK ✅'
    });
    res.status(200).json({ sid: msg.sid });
  } catch (e) {
    console.error('twilio-test error', e);
    res.status(500).json({ error: e.message });
  }
}
