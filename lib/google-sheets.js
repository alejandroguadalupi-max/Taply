// TAPLY/lib/google-sheets.js
import { google } from 'googleapis';

let sheetsClient = null;

function getEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`ENV_MISSING:${name}`);
  return v;
}

function getAuth() {
  const client_email = getEnv('GOOGLE_SERVICE_ACCOUNT_EMAIL').trim();
  let private_key = getEnv('GOOGLE_SERVICE_ACCOUNT_KEY');

  // Soporta claves con "\n" o con saltos reales
  if (private_key.includes('\\n')) private_key = private_key.replace(/\\n/g, '\n');

  return new google.auth.JWT({
    email: client_email,
    key: private_key,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
}

export function getSheets() {
  if (!sheetsClient) {
    const auth = getAuth();
    sheetsClient = google.sheets({ version: 'v4', auth });
  }
  return sheetsClient;
}

export async function getSpreadsheetInfo() {
  const spreadsheetId = getEnv('GOOGLE_SHEETS_ID').trim();
  try {
    const sheets = getSheets();
    const res = await sheets.spreadsheets.get({ spreadsheetId });
    const titles = (res.data.sheets || []).map(s => s.properties.title);
    return { spreadsheetId, titles };
  } catch (e) {
    throw new Error(`SPREADSHEET_GET_ERROR:${e.message}`);
  }
}

export async function ensureHeaderRow(tab, headers) {
  const spreadsheetId = getEnv('GOOGLE_SHEETS_ID').trim();
  const sheets = getSheets();
  try {
    const read = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: `${tab}!1:1`,
      valueRenderOption: 'UNFORMATTED_VALUE'
    });
    const row = read.data.values?.[0] || [];
    const equal =
      row.length === headers.length &&
      row.every((v, i) => String(v).trim() === String(headers[i]).trim());
    if (equal) return;

    await sheets.spreadsheets.values.update({
      spreadsheetId,
      range: `${tab}!1:1`,
      valueInputOption: 'RAW',
      requestBody: { values: [headers] },
    });
  } catch (e) {
    throw new Error(`HEADER_ERROR:${tab}:${e.message}`);
  }
}

export async function appendRow(tab, values) {
  const spreadsheetId = getEnv('GOOGLE_SHEETS_ID').trim();
  const sheets = getSheets();
  try {
    await sheets.spreadsheets.values.append({
      spreadsheetId,
      range: `${tab}!A1`,
      valueInputOption: 'RAW',
      insertDataOption: 'INSERT_ROWS',
      requestBody: { values: [values] },
    });
  } catch (e) {
    throw new Error(`APPEND_ERROR:${tab}:${e.message}`);
  }
}
