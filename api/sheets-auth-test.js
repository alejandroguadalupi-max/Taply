// /api/sheets-auth-test.js
import { google } from 'googleapis';

function loadSA() {
  // Prioridad 1: JSON en base64
  const b64 = process.env.GOOGLE_SERVICE_ACCOUNT_JSON_B64;
  if (b64) {
    const raw = Buffer.from(b64, 'base64').toString('utf8');
    const json = JSON.parse(raw);
    return {
      client_email: json.client_email,
      private_key: String(json.private_key || '').replace(/\\n/g, '\n').trim(),
    };
  }
  // Prioridad 2: JSON plano
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    const json = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    return {
      client_email: json.client_email,
      private_key: String(json.private_key || '').replace(/\\n/g, '\n').trim(),
    };
  }
  // Prioridad 3: EMAIL + KEY sueltas
  const client_email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const private_key = (process.env.GOOGLE_SERVICE_ACCOUNT_KEY || '')
    .replace(/\\n/g, '\n')
    .trim();
  if (!client_email || !private_key) throw new Error('ENV_MISSING_SA');
  return { client_email, private_key };
}

export default async function handler(req, res) {
  try {
    const { client_email, private_key } = loadSA();
    const auth = new google.auth.JWT(
      client_email,
      null,
      private_key,
      ['https://www.googleapis.com/auth/spreadsheets']
    );
    const sheets = google.sheets({ version: 'v4', auth });

    const spreadsheetId = process.env.GOOGLE_SHEETS_ID;
    if (!spreadsheetId) {
      return res.status(200).json({
        ok: true,
        email: client_email,
        note: 'Falta GOOGLE_SHEETS_ID (aun así auth OK)',
      });
    }

    const meta = await sheets.spreadsheets.get({ spreadsheetId });
    const titles = (meta.data.sheets || []).map(s => s.properties?.title);
    res.status(200).json({ ok: true, email: client_email, spreadsheetId, sheets: titles });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e.message || e) });
  }
}
