/**
 * Zoho Books Integration for FWF Backend
 * Region: India (.in domains)
 * Handles: OAuth token management, contacts, invoices
 */

const ZOHO_BASE      = 'https://www.zohoapis.in/books/v3';
const ZOHO_AUTH_URL  = 'https://accounts.zoho.in/oauth/v2/auth';
const ZOHO_TOKEN_URL = 'https://accounts.zoho.in/oauth/v2/token';

// Zoho OAuth scopes (uppercase operation type per Zoho docs)
export const ZOHO_SCOPES = [
  'ZohoBooks.contacts.CREATE',
  'ZohoBooks.contacts.READ',
  'ZohoBooks.invoices.CREATE',
  'ZohoBooks.invoices.READ',
  'ZohoBooks.settings.READ',
].join(',');

// In-memory access token cache (expires in 1 hour)
let _cachedToken  = null;
let _tokenExpiry  = 0;

// ──────────────────────────────────────────────────────
// Token helpers
// ──────────────────────────────────────────────────────

/** Get stored refresh token (DB preferred over env) */
async function getRefreshToken() {
  // Try MongoDB first (set via OAuth callback)
  try {
    const { default: AppConfig } = await import('../models/AppConfig.js');
    const cfg = await AppConfig.findOne({ key: 'zoho_refresh_token' }).lean();
    if (cfg?.value) return cfg.value;
  } catch (_) { /* ignore if DB not ready */ }
  // Fallback to env var
  return process.env.ZOHO_REFRESH_TOKEN || null;
}

/** Exchange refresh token → access token (cached) */
export async function getAccessToken() {
  if (_cachedToken && Date.now() < _tokenExpiry - 60_000) return _cachedToken;

  const refreshToken = await getRefreshToken();
  if (!refreshToken) throw new Error('Zoho not connected. Complete OAuth setup from Admin → Invoices.');

  const res  = await fetch(ZOHO_TOKEN_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'refresh_token',
      client_id:     process.env.ZOHO_CLIENT_ID,
      client_secret: process.env.ZOHO_CLIENT_SECRET,
      refresh_token: refreshToken,
    }),
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Zoho token refresh failed: ' + JSON.stringify(data));

  _cachedToken = data.access_token;
  _tokenExpiry = Date.now() + (data.expires_in || 3600) * 1000;
  return _cachedToken;
}

/** Generate the OAuth authorization URL for first-time connect */
export function getAuthUrl() {
  const siteUrl = process.env.SITE_URL || 'https://fwfindia.org';
  const params = new URLSearchParams({
    scope:         ZOHO_SCOPES,
    client_id:     process.env.ZOHO_CLIENT_ID,
    response_type: 'code',
    redirect_uri:  `${siteUrl}/api/admin/zoho/callback`,
    access_type:   'offline',
    prompt:        'consent',
  });
  return `${ZOHO_AUTH_URL}?${params}`;
}

/** Exchange authorization code → tokens (called once during OAuth callback) */
export async function exchangeCodeForTokens(code) {
  const siteUrl = process.env.SITE_URL || 'https://fwfindia.org';
  const res  = await fetch(ZOHO_TOKEN_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     process.env.ZOHO_CLIENT_ID,
      client_secret: process.env.ZOHO_CLIENT_SECRET,
      redirect_uri:  `${siteUrl}/api/admin/zoho/callback`,
      code,
    }),
  });
  return res.json();
}

// ──────────────────────────────────────────────────────
// API request helpers
// ──────────────────────────────────────────────────────

const orgId = () => process.env.ZOHO_ORG_ID;

async function zohoGet(endpoint) {
  const token = await getAccessToken();
  const res = await fetch(`${ZOHO_BASE}${endpoint}?organization_id=${orgId()}`, {
    headers: { Authorization: `Zoho-oauthtoken ${token}` },
  });
  return res.json();
}

async function zohoPost(endpoint, body) {
  const token = await getAccessToken();
  const res = await fetch(`${ZOHO_BASE}${endpoint}?organization_id=${orgId()}`, {
    method:  'POST',
    headers: { Authorization: `Zoho-oauthtoken ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (data.code && data.code !== 0) {
    console.error(`❌ Zoho API error [${endpoint}]:`, JSON.stringify(data));
  }
  return data;
}

// ──────────────────────────────────────────────────────
// Contacts
// ──────────────────────────────────────────────────────

/** Find existing Zoho contact by email, or create a new one */
export async function findOrCreateContact({ name, email, mobile, pan }) {
  // Search by email first
  if (email) {
    const search = await zohoGet(`/contacts?contact_type=customer&email=${encodeURIComponent(email)}`);
    if (search.contacts?.length) return search.contacts[0].contact_id;
  }

  // Create new contact
  const body = { contact_name: name, contact_type: 'customer' };
  if (email)  body.email          = email;
  if (mobile) body.mobile         = mobile;
  if (pan)    body.pan_no         = pan;

  const result = await zohoPost('/contacts', { contact: body });
  if (result.contact?.contact_id) return result.contact.contact_id;
  throw new Error('Zoho contact creation failed: ' + JSON.stringify(result));
}

// ──────────────────────────────────────────────────────
// Invoices (used for donation/membership receipts)
// ──────────────────────────────────────────────────────

/**
 * Create an Invoice in Zoho Books (marked as paid)
 * Used for already-paid membership/donation transactions
 */
export async function createZohoInvoice({ contactId, receiptId, date, lineItems, total, paymentId, type, is80g }) {
  const dateStr = new Date(date).toISOString().split('T')[0]; // YYYY-MM-DD

  const body = {
    customer_id:      contactId,
    reference_number: receiptId,
    date:             dateStr,
    payment_terms:    0,
    payment_terms_label: 'Due on Receipt',
    notes:            `FWF ${type} payment${is80g ? ' – 80G Eligible' : ''}.${paymentId ? ` Razorpay: ${paymentId}` : ''}`,
    line_items: lineItems.map(li => ({
      name:        li.name,
      description: li.description || '',
      rate:        li.amount,
      quantity:    li.quantity || 1,
    })),
  };

  const result = await zohoPost('/invoices', body);
  if (result.invoice?.invoice_id) return result.invoice;
  throw new Error('Zoho invoice creation failed: ' + JSON.stringify(result));
}

// ──────────────────────────────────────────────────────
// Main sync function (called from createAndSendReceipt)
// ──────────────────────────────────────────────────────

/**
 * Sync a Receipt document to Zoho Books as an Invoice.
 * Returns { zoho_invoice_id, zoho_contact_id } or null on failure.
 */
export async function syncReceiptToZoho(receipt) {
  if (!process.env.ZOHO_CLIENT_ID || !process.env.ZOHO_ORG_ID) {
    console.warn('⚠️ Zoho: ZOHO_CLIENT_ID or ZOHO_ORG_ID env vars not set — skipping sync');
    return null;
  }

  const refreshToken = await getRefreshToken();
  if (!refreshToken) {
    console.warn('⚠️ Zoho: No refresh token found — OAuth not completed. Go to Admin → Invoices → Connect Zoho Books');
    return null;
  }

  console.log(`📊 Zoho: Starting sync for receipt ${receipt.receipt_id} (type: ${receipt.type}, total: ₹${receipt.total})`);

  const contactId = await findOrCreateContact({
    name:   receipt.customer_name,
    email:  receipt.customer_email,
    mobile: receipt.customer_mobile,
    pan:    receipt.customer_pan,
  });

  const items = receipt.line_items?.length
    ? receipt.line_items
    : [{ name: receipt.description || 'Payment', amount: receipt.total, quantity: 1 }];

  const inv = await createZohoInvoice({
    contactId,
    receiptId:  receipt.receipt_id,
    date:       receipt.created_at || new Date(),
    lineItems:  items,
    total:      receipt.total,
    paymentId:  receipt.payment_txn_id || receipt.razorpay_payment_id,
    type:       receipt.type,
    is80g:      receipt.is_80g,
  });

  console.log(`✅ Zoho: Invoice created → ${inv.invoice_id}`);
  return {
    zoho_salesreceipt_id: inv.invoice_id,
    zoho_contact_id:      contactId,
  };
}

/** Check if Zoho is properly connected (has refresh token + can get access token) */
export async function checkZohoConnection() {
  const refreshToken = await getRefreshToken();
  if (!refreshToken) return { connected: false, reason: 'No refresh token' };
  try {
    await getAccessToken();
    return { connected: true };
  } catch (err) {
    return { connected: false, reason: err.message };
  }
}
