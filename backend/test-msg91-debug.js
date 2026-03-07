/**
 * Check MSG91 delivery logs for the last test run
 */

const AUTH_KEY = '497148Arak0XxtpLER69a2e3cdP1';
const TEST_MOBILE = '9580118412';

// Request IDs from last test run
const SMS_OTP_IDS = [
  '3663666d4342746f76455351', // Login OTP
  '3663666d4344536559557a59', // Forgot OTP
];
const WA_IDS = [
  '3c725cd37c69402d912e671140922a93', // Donation WA
  'd02d3e8721f54f3691b4c0acfb72129d', // Credentials WA
];

async function checkOtpLog(requestId, label) {
  const url = `https://control.msg91.com/api/v5/otp?mobile=91${TEST_MOBILE}&request_id=${requestId}`;
  const res = await fetch(url, { headers: { authkey: AUTH_KEY } });
  const data = await res.json();
  console.log(`\n[${label}] OTP status:`);
  console.log(JSON.stringify(data, null, 2));
}

async function checkSmsLog() {
  // MSG91 SMS delivery report
  const url = `https://control.msg91.com/api/v5/report/report?recipientPhone=91${TEST_MOBILE}&pagesize=5&sortby=DESC`;
  const res = await fetch(url, { headers: { 'authkey': AUTH_KEY, 'Content-Type': 'application/json' } });
  const text = await res.text();
  console.log('\n[SMS Delivery Report] status:', res.status);
  try { console.log(JSON.stringify(JSON.parse(text), null, 2)); }
  catch { console.log(text.slice(0, 500)); }
}

async function checkWaLog(requestId, label) {
  const url = `https://api.msg91.com/api/v5/report/report?request_id=${requestId}`;
  const res = await fetch(url, { headers: { 'authkey': AUTH_KEY } });
  const data = await res.json();
  console.log(`\n[${label}] WA delivery:`);
  console.log(JSON.stringify(data, null, 2));
}

async function checkTemplateVars() {
  // Try sending WA to self with just 1 variable to test if template needs fewer vars
  console.log('\n[Template Test — 1 var only]:');
  const body = {
    integrated_number: '15558189243',
    content_type: 'template',
    payload: {
      messaging_product: 'whatsapp',
      type: 'template',
      template: {
        name: 'thank_you_for_donation_fwf',
        language: { code: 'en', policy: 'deterministic' },
        namespace: '08e35bb9_f5fd_49ae_b619_803d3b606cac',
        to_and_components: [{
          to: [`91${TEST_MOBILE}`],
          components: {
            body_1: { type: 'text', value: 'Test User' }
          }
        }]
      }
    }
  };
  const res = await fetch('https://api.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'authkey': AUTH_KEY },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  console.log(JSON.stringify(data, null, 2));
}

async function run() {
  console.log('─'.repeat(55));
  console.log(' MSG91 Delivery Debug');
  console.log('─'.repeat(55));

  await checkSmsLog();
  await checkTemplateVars();
}

run().catch(e => console.error('Fatal:', e.message));
