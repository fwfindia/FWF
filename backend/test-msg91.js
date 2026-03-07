/**
 * MSG91 Integration Test
 * Run: node --env-file=.env test-msg91.js
 * Tests: SMS OTP (login + forgot), WhatsApp donation, WhatsApp credentials
 */

import { sendSmsOtp, sendWhatsAppDonation, sendWhatsAppCredentials,
         sendDonationReceiptSms, sendQuizParticipationSms } from './lib/msg91.js';

const TEST_MOBILE = '9580118412';
const PASS        = '\x1b[32m✅ PASS\x1b[0m';
const FAIL        = '\x1b[31m❌ FAIL\x1b[0m';
const SEP         = '─'.repeat(55);

function log(label, data) {
  const ok = data && (data.type === 'success' || data.status === 'success' || String(data.message || data.data || '').toLowerCase().includes('success') || data.request_id);
  console.log(`${ok ? PASS : FAIL}  ${label}`);
  // Always print full response for debugging
  console.log('     Raw response:', JSON.stringify(data, null, 2));
  return ok;
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  console.log('\n' + SEP);
  console.log(' MSG91 Integration Test  →  +91 ' + TEST_MOBILE);
  console.log(SEP + '\n');

  // ── 1. Login OTP SMS ──────────────────────────────────────────
  console.log('1. SMS OTP — Login (template: Lgoin_OTP)');
  const r1 = await sendSmsOtp({ mobile: TEST_MOBILE, otp: '123456', type: 'login' });
  log('Login OTP SMS', r1);
  await sleep(1500);

  // ── 2. Forgot Password OTP SMS ────────────────────────────────
  console.log('\n2. SMS OTP — Forgot Password (template: Forgot_password)');
  const r2 = await sendSmsOtp({ mobile: TEST_MOBILE, otp: '654321', type: 'forgot' });
  log('Forgot Password OTP SMS', r2);
  await sleep(1500);

  // ── 3. Donation Receipt SMS ───────────────────────────────────
  console.log('\n3. Transactional SMS — Donation Receipt');
  const r3 = await sendDonationReceiptSms({ mobile: TEST_MOBILE, name: 'Test User', amount: 500 });
  log('Donation Receipt SMS', r3);
  await sleep(1500);

  // ── 4. WhatsApp — Donation Confirmation ──────────────────────
  console.log('\n4. WhatsApp — Donation Confirmation (thank_you_for_donation_fwf)');
  const r4 = await sendWhatsAppDonation({
    mobile:    TEST_MOBILE,
    name:      'Test User',
    amount:    501,
    donationId: 'DON-TEST-001',
    paymentId:  'pay_TestPayId123'
  });
  log('WhatsApp Donation', r4);
  await sleep(1500);

  // ── 5. WhatsApp — Welcome Credentials ────────────────────────
  console.log('\n5. WhatsApp — Welcome Credentials (fwf_welcome_credentials)');
  const r5 = await sendWhatsAppCredentials({
    mobile:   TEST_MOBILE,
    name:     'Test User',
    userId:   'FWF-TEST-001',
    password: 'TestPass@123'
  });
  log('WhatsApp Credentials', r5);

  console.log('\n' + SEP);
  console.log(' Done. Check +91' + TEST_MOBILE + ' for messages.');
  console.log(SEP + '\n');
}

run().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
