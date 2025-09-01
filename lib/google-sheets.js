// /api/google-sheets.js
import { google } from 'googleapis';

function loadServiceAccountFromEnv() {
  // 1) JSON en Base64 (recomendado)
  const b64 = process.env.GOOGLE_SERVICE_ACCOUNT_JSON_B64;
  if (b64) {
    try {
      const raw = Buffer.from(b64, 'base64').toString('utf8');
      const json = JSON.parse(raw);
      return {
        client_email: json.client_email,
        private_key: String(json.private_key || '').replace(/\\n/g, '\n').trim(),
      };
    } catch (e) {
      throw new Error('ENV_BAD_BASE64_OR_JSON');
    }
  }

  // 2) JSON en texto plano
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    const json = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    return {
      client_email: json.client_email,
      private_key: String(json.private_key || '').replace(/\\n/g, '\n').trim(),
    };
  }

  // 3) EMAIL + KEY sueltas
  const client_email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  const private_key = (process.env.GOOGLE_SERVICE_ACCOUNT_KEY || '')
    .replace(/\\n/g, '\n')
    .trim();

  if (!client_email || !private_key) {
    throw new Error('ENV_MISSING_SA');
  }
  return { client_email, private_key };
}

export async function getSheetsClient() {
  const { client_email, private_key } = loadServiceAccountFromEnv();
  const auth = new google.auth.JWT(
    client_email,
    null,
    private_key,
    ['https://www.googleapis.com/auth/spreadsheets']
  );
  const sheets = google.sheets({ version: 'v4', auth });
  return { sheets, email: client_email };
}

// Helpers básicos por si los quieres usar:
export async function getSpreadsheetTitles(spreadsheetId) {
  const { sheets } = await getSheetsClient();
  const meta = await sheets.spreadsheets.get({ spreadsheetId });
  return (meta.data.sheets || []).map(s => s.properties?.title);
}
