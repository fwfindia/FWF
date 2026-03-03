import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import Razorpay from 'razorpay';
import { initSentry, setUserContext, captureError, addBreadcrumb } from './lib/sentry.js';
import User from './models/User.js';
import Referral from './models/Referral.js';
import Donation from './models/Donation.js';
import QuizTicket from './models/QuizTicket.js';
import PointsLedger from './models/PointsLedger.js';
import SupportTicket from './models/SupportTicket.js';
import CsrPartner from './models/CsrPartner.js';
import MembershipFee from './models/MembershipFee.js';
import Product from './models/Product.js';
import Order from './models/Order.js';
import SocialTask from './models/SocialTask.js';
import TaskCompletion from './models/TaskCompletion.js';
import SocialPost from './models/SocialPost.js';
import Quiz from './models/Quiz.js';
import QuizParticipation from './models/QuizParticipation.js';
import ReferralClick from './models/ReferralClick.js';
import DonationOtp from './models/DonationOtp.js';
import PaymentLink from './models/PaymentLink.js';
import Receipt from './models/Receipt.js';
import AppConfig from './models/AppConfig.js';
import { syncReceiptToZoho, checkZohoConnection, getAuthUrl, exchangeCodeForTokens } from './lib/zoho.js';
import { getTransporter, send80GReceipt, sendMemberWelcome, sendSupporterWelcome, sendDonationConfirmation, sendAdminAlert } from './lib/mailer.js';
import { sendWhatsAppCredentials, sendWhatsAppDonation, sendQuizParticipationSms, sendQuizResultSms, sendDonationReceiptSms, sendDonationReceipt80GSms } from './lib/msg91.js';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Initialize Sentry BEFORE any other middleware
const { requestHandler, errorHandler } = initSentry(app);
app.use(requestHandler);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('❌ JWT_SECRET is required'); process.exit(1); }
const ORG_PREFIX = process.env.ORG_PREFIX || 'FWF';
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT === 'production';

// --- Razorpay instance ---
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.error('❌ RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are required');
  process.exit(1);
}
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Static site root one level up from backend/
const siteRoot = path.resolve(__dirname, '..');

// CORS configuration
const ALWAYS_ALLOWED = [
  'https://www.fwfindia.org',
  'https://fwfindia.org',
  'https://fwf-alpha.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173'
];
const extraOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : [];
const allowedOrigins = [...new Set([...ALWAYS_ALLOWED, ...extraOrigins])];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. curl, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: true
}));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// --- Simple rate limiter (in-memory) ---
const rateLimitMap = new Map();
function rateLimit(windowMs, maxRequests) {
  return (req, res, next) => {
    const key = req.ip + ':' + req.path;
    const now = Date.now();
    const record = rateLimitMap.get(key);
    if (!record || now - record.start > windowMs) {
      rateLimitMap.set(key, { start: now, count: 1 });
      return next();
    }
    record.count++;
    if (record.count > maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
    }
    next();
  };
}
// Clean up rate limit map every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitMap) {
    if (now - val.start > 300000) rateLimitMap.delete(key);
  }
}, 300000);

// --- Internal API middleware ---
const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY;
if (!INTERNAL_API_KEY) console.warn('⚠️ INTERNAL_API_KEY not set — internal endpoints will reject all requests');
function internalAuth(req, res, next) {
  const key = req.headers['x-internal-api-key'];
  if (key !== INTERNAL_API_KEY) {
    console.warn(`⚠️ Unauthorized internal API call to ${req.path} from ${req.ip}`);
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(siteRoot));

// --- MongoDB connection ---
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI environment variable is not set');
  process.exit(1);
}

async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI, {
      bufferCommands: false,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB connected successfully');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  }
}

// Point value: 1 point = ₹10
const POINT_VALUE = 10;
const DONATION_POINTS_PERCENT = 10;
const REFERRAL_POINTS_PERCENT = 50;
const QUIZ_TICKET_POINTS_PERCENT = 10;
const QUIZ_TICKET_PRICE = 100;

/**
 * Generate a unique random ID with auto-expanding digit width.
 * Starts at `baseDigits` length; when that pool fills up, moves to baseDigits+1, etc.
 * @param {string} prefix  - e.g. 'FWFM'
 * @param {number} baseDigits - starting digit count
 * @param {(id:string) => Promise<boolean>} existsFn - returns true if id already taken
 */
async function generateUniqueId(prefix, baseDigits, existsFn) {
  let digits = baseDigits;
  while (true) {
    const pool = Math.pow(10, digits);  // e.g. 1000 for 3 digits
    let found = false;
    // Try up to 3× the pool size — if >90% full, auto-expand
    const attempts = Math.min(pool * 3, 500);
    for (let i = 0; i < attempts; i++) {
      const n = Math.floor(Math.random() * pool).toString().padStart(digits, '0');
      const id = `${prefix}${n}`;
      const taken = await existsFn(id);
      if (!taken) return id;
    }
    // Pool appears exhausted — expand by one digit
    console.log(`⚠️  ${prefix} pool at ${digits} digits appears full — expanding to ${digits + 1} digits`);
    digits++;
  }
}

async function nextMemberId() {
  return generateUniqueId('FWFM', 3, (id) =>
    User.findOne({ member_id: id }).lean().then(Boolean)
  );
}

async function nextSupporterId() {
  return generateUniqueId('FWFS', 4, (id) =>
    User.findOne({ member_id: id }).lean().then(Boolean)
  );
}
async function nextDonationId() {
  const last = await Donation.findOne({ donation_id: { $regex: /^DON-\d{6}$/ } })
    .sort({ created_at: -1 }).select('donation_id').lean();
  let n = 0;
  if (last && last.donation_id) {
    const m = last.donation_id.match(/(\d{6})$/);
    if (m) n = parseInt(m[1], 10);
  }
  return `DON-${(n + 1).toString().padStart(6, '0')}`;
}
async function nextReceiptId() {
  const last = await Receipt.findOne({ receipt_id: { $regex: /^RCP-\d{6}$/ } })
    .sort({ created_at: -1 }).select('receipt_id').lean();
  let n = 0;
  if (last?.receipt_id) { const m = last.receipt_id.match(/(\d{6})$/); if (m) n = parseInt(m[1], 10); }
  return `RCP-${(n + 1).toString().padStart(6, '0')}`;
}
function genReceiptToken() {
  return crypto.randomBytes(24).toString('hex');
}
async function createAndSendReceipt({ type, userId, memberId, customerName, customerEmail, customerMobile, customerPan, customerAddress, lineItems, total, tax = 0, razorpayPaymentId, razorpayOrderId, razorpaySubscriptionId, referenceId, is80g = false, description }) {
  try {
    const receipt_id = await nextReceiptId();
    const token = genReceiptToken();
    const subtotal = lineItems.reduce((s, i) => s + (i.amount * (i.quantity || 1)), 0);
    const receipt = await Receipt.create({
      receipt_id, token, type,
      user_id: userId || null,
      member_id: memberId || null,
      customer_name: customerName,
      customer_email: customerEmail || null,
      customer_mobile: customerMobile || null,
      customer_pan: customerPan || null,
      customer_address: customerAddress || null,
      description: description || '',
      line_items: lineItems,
      subtotal, tax, total,
      razorpay_payment_id: razorpayPaymentId || null,
      razorpay_order_id: razorpayOrderId || null,
      razorpay_subscription_id: razorpaySubscriptionId || null,
      reference_id: referenceId || null,
      is_80g: !!is80g,
      status: 'generated'
    });
    // Optionally email receipt link — receipt URL passed to confirmation email instead
    // (avoids double email; receiptUrl added to sendDonationConfirmation / sendMemberWelcome)
    if (customerEmail) {
      await Receipt.updateOne({ _id: receipt._id }, { status: 'sent', email_sent: true, email_sent_at: new Date() });
    }
    // Sync to Zoho Books (non-blocking)
    syncReceiptToZoho(receipt.toObject()).then(zohoResult => {
      if (zohoResult?.zoho_salesreceipt_id) {
        Receipt.updateOne({ _id: receipt._id }, {
          $set: { zoho_salesreceipt_id: zohoResult.zoho_salesreceipt_id, zoho_synced_at: new Date() }
        }).catch(() => {});
        console.log(`📊 Zoho synced: ${receipt.receipt_id} → ${zohoResult.zoho_salesreceipt_id}`);
      } else {
        console.warn(`⚠️ Zoho: syncReceiptToZoho returned null for ${receipt.receipt_id}`);
      }
    }).catch(err => console.error('❌ Zoho sync error:', err.message, err.stack?.split('\n')[1]));
    return receipt;
  } catch (err) {
    console.error('⚠️ Receipt creation failed (non-fatal):', err.message);
    return null;
  }
}
function randPass(len = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%';
  let p = '';
  for (let i = 0; i < len; i++) p += chars[Math.floor(Math.random() * chars.length)];
  return p;
}
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function generateReferralCode(memberId) {
  return memberId.replace(/-/g, '') + Math.random().toString(36).substring(2, 6).toUpperCase();
}
function amountToPoints(amountInr) {
  return amountInr / POINT_VALUE;
}

// Seed admin if not exists
async function seedData() {
  const ADMIN_EMAIL = process.env.ADMIN_USER || 'admin@fwf';
  const ADMIN_PASS_VAL = process.env.ADMIN_PASS || 'Admin@12345';
  const findAdmin = await User.findOne({ role: 'admin' });
  if (!findAdmin) {
    const hash = bcrypt.hashSync(ADMIN_PASS_VAL, 10);
    const memberId = `${ORG_PREFIX}-ADMIN-001`;
    await User.create({
      member_id: memberId,
      name: 'FWF Admin',
      email: ADMIN_EMAIL,
      password_hash: hash,
      role: 'admin',
      membership_active: true,
      wallet: {}
    });
    console.log(`✅ Admin created -> user: ${ADMIN_EMAIL} | pass: ${ADMIN_PASS_VAL}`);
  } else {
    // Always sync admin email + password from env vars on every server start
    const hash = bcrypt.hashSync(ADMIN_PASS_VAL, 10);
    await User.updateOne({ role: 'admin' }, { email: ADMIN_EMAIL, password_hash: hash });
    console.log(`✅ Admin credentials synced from env -> user: ${ADMIN_EMAIL}`);
  }

  // Seed test member if not exists
  const findTestMember = await User.findOne({ member_id: `${ORG_PREFIX}-TEST-001` });
  if (!findTestMember) {
    const testPassword = 'Test@12345';
    const hash = bcrypt.hashSync(testPassword, 10);
    const memberId = `${ORG_PREFIX}-TEST-001`;
    const refCode = generateReferralCode(memberId);
    await User.create({
      member_id: memberId,
      name: 'Test Member',
      mobile: '9999999999',
      email: 'test@fwf.org',
      password_hash: hash,
      role: 'member',
      membership_active: true,
      referral_code: refCode,
      wallet: {
        balance_inr: 5000,
        lifetime_earned_inr: 5000,
        points_balance: 50,
        total_points_earned: 50
      }
    });
    console.log(`✅ Test member created -> ID: ${memberId} | pass: ${testPassword} | ref: ${refCode}`);
  }

  // Ensure existing members have referral codes
  const membersWithoutRef = await User.find({ role: 'member', $or: [{ referral_code: null }, { referral_code: '' }] }).select('member_id');
  for (const m of membersWithoutRef) {
    const refCode = generateReferralCode(m.member_id);
    await User.updateOne({ _id: m._id }, { referral_code: refCode });
  }
  if (membersWithoutRef.length > 0) console.log(`✅ Generated referral codes for ${membersWithoutRef.length} member(s)`);

  // Seed social tasks if not exist
  const existingTasks = await SocialTask.countDocuments();

  // Drop old unique index if it exists (migrated from per-week to per-task completion)
  try {
    await TaskCompletion.collection.dropIndex('user_id_1_year_week_1');
    console.log('✅ Dropped old year_week unique index');
  } catch(e) { /* index doesn't exist, ok */ }

  if (existingTasks === 0) {
    const socialTasks = [
      { task_id: 'TASK-01', week_number: 1, title: 'पौधारोपण / Tree Plantation', description: 'एक पौधा लगाएं या किसी पौधे की देखभाल करें। अपने पौधे के साथ सेल्फी लें।', photo_instruction: 'पौधा लगाते हुए या पौधे के साथ फोटो लें', icon: '🌱', points_reward: 10 },
      { task_id: 'TASK-02', week_number: 2, title: 'स्वच्छता अभियान / Cleanliness Drive', description: 'अपने आस-पास की जगह साफ करें - गली, पार्क, या सार्वजनिक स्थल।', photo_instruction: 'सफाई करते हुए या साफ जगह की before/after फोटो लें', icon: '🧹', points_reward: 10 },
      { task_id: 'TASK-03', week_number: 3, title: 'भोजन दान / Food Donation', description: 'किसी जरूरतमंद को भोजन या राशन दें। गरीबों, मजदूरों या बेसहारा लोगों की मदद करें।', photo_instruction: 'भोजन देते हुए फोटो लें (चेहरा छुपा सकते हैं)', icon: '🍱', points_reward: 10 },
      { task_id: 'TASK-04', week_number: 4, title: 'कपड़े वितरण / Clothes Distribution', description: 'पुराने या नए कपड़े जरूरतमंदों को दें। सर्दी/गर्मी के अनुसार कपड़े बांटें।', photo_instruction: 'कपड़े देते हुए या इकट्ठा किए कपड़ों की फोटो लें', icon: '👕', points_reward: 10 },
      { task_id: 'TASK-05', week_number: 5, title: 'किताबें/स्टेशनरी दान / Books & Stationery', description: 'गरीब बच्चों को किताबें, कॉपी, पेन या स्कूल सामग्री दें।', photo_instruction: 'बच्चों को किताबें/सामग्री देते हुए फोटो लें', icon: '📚', points_reward: 10 },
      { task_id: 'TASK-06', week_number: 6, title: 'प्लास्टिक-मुक्त / Plastic-Free Drive', description: 'कपड़े का थैला बांटें या प्लास्टिक इकट्ठा करके recycle करें।', photo_instruction: 'कपड़े का थैला या इकट्ठा किए प्लास्टिक की फोटो लें', icon: '♻️', points_reward: 10 },
      { task_id: 'TASK-07', week_number: 7, title: 'पक्षियों के लिए पानी / Water for Birds', description: 'छत या बालकनी पर पक्षियों के लिए पानी का बर्तन रखें। गर्मी में पक्षियों की मदद करें।', photo_instruction: 'पानी का बर्तन रखते हुए या पक्षियों को पानी पीते हुए फोटो लें', icon: '🐦', points_reward: 10 },
      { task_id: 'TASK-08', week_number: 8, title: 'रक्तदान / Health Camp / Blood Donation', description: 'रक्तदान करें या किसी health camp में हिस्सा लें। स्वास्थ्य जागरूकता फैलाएं।', photo_instruction: 'रक्तदान या health camp की फोटो लें', icon: '🩸', points_reward: 10 },
      { task_id: 'TASK-09', week_number: 9, title: 'आवारा जानवरों को खाना / Feed Strays', description: 'सड़क के कुत्तों, बिल्लियों या गायों को खाना-पानी दें।', photo_instruction: 'जानवरों को खाना देते हुए फोटो लें', icon: '🐕', points_reward: 10 },
      { task_id: 'TASK-10', week_number: 10, title: 'जागरूकता पोस्टर / Wall Awareness', description: 'शिक्षा, स्वच्छता, या सामाजिक जागरूकता का पोस्टर बनाएं और दीवार पर लगाएं।', photo_instruction: 'पोस्टर बनाते हुए या दीवार पर लगा हुआ पोस्टर दिखाएं', icon: '📋', points_reward: 10 }
    ];
    await SocialTask.insertMany(socialTasks);
    console.log('✅ Seeded 10 social tasks');
  }

  // Seed sample quizzes if not exist
  const existingQuizzes = await Quiz.countDocuments();
  if (existingQuizzes === 0) {
    const now = new Date();
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0); // last day of current month
    const halfYearEnd = new Date(now.getFullYear(), now.getMonth() + 6, 0);
    const yearEnd = new Date(now.getFullYear(), 11, 31);

    const sampleQuizzes = [
      {
        quiz_id: `M${String(now.getFullYear()).slice(2)}${String(now.getMonth()+1).padStart(2,'0')}`,
        title: 'Monthly GK Challenge',
        description: 'सामान्य ज्ञान का मासिक quiz — जीतें इनाम!',
        type: 'monthly',
        game_type: 'mcq',
        entry_fee: 100,
        start_date: now,
        end_date: monthEnd,
        result_date: new Date(monthEnd.getTime() + 3*86400000),
        status: 'active',
        prizes: { first: 5000, second: 2000, third: 1000 },
        questions: [
          { q_no: 1, question: 'भारत की राजधानी क्या है?', options: ['मुंबई', 'दिल्ली', 'कोलकाता', 'चेन्नई'], correct_answer: 1, points: 1 },
          { q_no: 2, question: 'गंगा नदी कहाँ से निकलती है?', options: ['गंगोत्री', 'यमुनोत्री', 'केदारनाथ', 'बद्रीनाथ'], correct_answer: 0, points: 1 },
          { q_no: 3, question: 'भारत का सबसे बड़ा राज्य कौन सा है?', options: ['मध्य प्रदेश', 'उत्तर प्रदेश', 'राजस्थान', 'महाराष्ट्र'], correct_answer: 2, points: 1 },
          { q_no: 4, question: 'हमारे राष्ट्रीय ध्वज में कितने रंग हैं?', options: ['2', '3', '4', '5'], correct_answer: 1, points: 1 },
          { q_no: 5, question: 'भारत के पहले राष्ट्रपति कौन थे?', options: ['महात्मा गांधी', 'जवाहरलाल नेहरू', 'डॉ. राजेंद्र प्रसाद', 'सरदार पटेल'], correct_answer: 2, points: 1 },
          { q_no: 6, question: 'TAJ MAHAL किसने बनवाया था?', options: ['अकबर', 'शाहजहाँ', 'जहाँगीर', 'औरंगज़ेब'], correct_answer: 1, points: 1 },
          { q_no: 7, question: 'भारत का राष्ट्रीय खेल कौन सा है?', options: ['क्रिकेट', 'कबड्डी', 'हॉकी', 'फुटबॉल'], correct_answer: 2, points: 1 },
          { q_no: 8, question: 'सूरज किस दिशा में उगता है?', options: ['पश्चिम', 'उत्तर', 'दक्षिण', 'पूर्व'], correct_answer: 3, points: 1 },
          { q_no: 9, question: '1 किलोमीटर में कितने मीटर होते हैं?', options: ['100', '500', '1000', '10000'], correct_answer: 2, points: 1 },
          { q_no: 10, question: 'भारत का सबसे लंबा नदी पुल कौन सा है?', options: ['हावड़ा ब्रिज', 'भूपेन हजारिका सेतु', 'महात्मा गांधी सेतु', 'राजीव गांधी सेतु'], correct_answer: 1, points: 1 }
        ]
      },
      {
        quiz_id: `M${String(now.getFullYear()).slice(2)}${String(now.getMonth()+1).padStart(2,'0')}-TF`,
        title: 'True or False — मज़ेदार तथ्य',
        description: 'सही या गलत बताओ — interesting facts quiz!',
        type: 'monthly',
        game_type: 'true_false',
        entry_fee: 100,
        start_date: now,
        end_date: monthEnd,
        result_date: new Date(monthEnd.getTime() + 3*86400000),
        status: 'active',
        prizes: { first: 5000, second: 2000, third: 1000 },
        questions: [
          { q_no: 1, question: 'चाँद पर पानी मिला है।', options: ['सही', 'गलत'], correct_answer: 0, points: 1 },
          { q_no: 2, question: 'शहद कभी खराब नहीं होता।', options: ['सही', 'गलत'], correct_answer: 0, points: 1 },
          { q_no: 3, question: 'ऑक्टोपस के 10 दिल होते हैं।', options: ['सही', 'गलत'], correct_answer: 1, points: 1 },
          { q_no: 4, question: 'भारत में सबसे ज़्यादा बोली जाने वाली भाषा हिंदी है।', options: ['सही', 'गलत'], correct_answer: 0, points: 1 },
          { q_no: 5, question: 'सूर्य एक तारा है।', options: ['सही', 'गलत'], correct_answer: 0, points: 1 },
          { q_no: 6, question: 'माउंट एवरेस्ट भारत में है।', options: ['सही', 'गलत'], correct_answer: 1, points: 1 },
          { q_no: 7, question: 'इंसानी शरीर में 206 हड्डियाँ होती हैं।', options: ['सही', 'गलत'], correct_answer: 0, points: 1 },
          { q_no: 8, question: 'बिजली की खोज थॉमस एडिसन ने की।', options: ['सही', 'गलत'], correct_answer: 1, points: 1 }
        ]
      },
      {
        quiz_id: `H${String(now.getFullYear()).slice(2)}01`,
        title: 'Half-Yearly Mega Quiz',
        description: '6 महीने का बड़ा quiz — बड़ा इनाम जीतने का मौका!',
        type: 'half_yearly',
        game_type: 'general',
        entry_fee: 500,
        start_date: now,
        end_date: halfYearEnd,
        result_date: new Date(halfYearEnd.getTime() + 5*86400000),
        status: 'active',
        prizes: { first: 25000, second: 10000, third: 5000 },
        questions: [
          { q_no: 1, question: 'विश्व का सबसे बड़ा महासागर कौन सा है?', options: ['अटलांटिक', 'हिंद महासागर', 'प्रशांत महासागर', 'आर्कटिक'], correct_answer: 2, points: 1 },
          { q_no: 2, question: 'भारतीय संविधान कब लागू हुआ?', options: ['15 Aug 1947', '26 Jan 1950', '2 Oct 1949', '26 Nov 1949'], correct_answer: 1, points: 1 },
          { q_no: 3, question: 'पृथ्वी सूर्य का चक्कर कितने दिन में लगाती है?', options: ['365', '360', '366', '364'], correct_answer: 0, points: 1 },
          { q_no: 4, question: 'विश्व का सबसे ऊँचा पर्वत शिखर कौन सा है?', options: ['K2', 'कंचनजंगा', 'माउंट एवरेस्ट', 'मकालू'], correct_answer: 2, points: 1 },
          { q_no: 5, question: 'RBI का मुख्यालय कहाँ है?', options: ['दिल्ली', 'मुंबई', 'कोलकाता', 'चेन्नई'], correct_answer: 1, points: 1 },
          { q_no: 6, question: 'भारत में कुल कितने राज्य हैं (2024)?', options: ['28', '29', '30', '31'], correct_answer: 0, points: 1 },
          { q_no: 7, question: 'चंद्रयान-3 किस साल लॉन्च हुआ?', options: ['2021', '2022', '2023', '2024'], correct_answer: 2, points: 1 },
          { q_no: 8, question: 'DNA का पूरा नाम क्या है?', options: ['Di Nucleic Acid', 'Deoxyribo Nucleic Acid', 'Data Nucleic Acid', 'Dual Nucleic Acid'], correct_answer: 1, points: 1 },
          { q_no: 9, question: 'भारत का सबसे बड़ा बांध कौन सा है?', options: ['भाखड़ा नांगल', 'हीराकुंड', 'टिहरी', 'सरदार सरोवर'], correct_answer: 2, points: 1 },
          { q_no: 10, question: 'IPL का पहला सीज़न कब हुआ?', options: ['2007', '2008', '2009', '2010'], correct_answer: 1, points: 1 }
        ]
      },
      {
        quiz_id: `Y${String(now.getFullYear()).slice(2)}01`,
        title: 'Yearly Grand Championship',
        description: '🏆 साल का सबसे बड़ा quiz — Grand Prize ₹1 लाख!',
        type: 'yearly',
        game_type: 'mcq',
        entry_fee: 1000,
        start_date: now,
        end_date: yearEnd,
        result_date: new Date(yearEnd.getTime() + 7*86400000),
        status: 'active',
        prizes: { first: 100000, second: 50000, third: 25000 },
        questions: [
          { q_no: 1, question: 'भारत रत्न पुरस्कार कब शुरू हुआ?', options: ['1950', '1952', '1954', '1956'], correct_answer: 2, points: 1 },
          { q_no: 2, question: 'ISRO का मुख्यालय कहाँ है?', options: ['दिल्ली', 'मुंबई', 'बेंगलुरु', 'हैदराबाद'], correct_answer: 2, points: 1 },
          { q_no: 3, question: 'भारतीय रुपये का चिह्न (₹) किसने डिज़ाइन किया?', options: ['डी. उदय कुमार', 'रघुराम राजन', 'अमर्त्य सेन', 'ए.पी.जे. अब्दुल कलाम'], correct_answer: 0, points: 1 },
          { q_no: 4, question: 'विश्व का सबसे बड़ा देश (क्षेत्रफल) कौन सा है?', options: ['चीन', 'अमेरिका', 'कनाडा', 'रूस'], correct_answer: 3, points: 1 },
          { q_no: 5, question: 'पहला कंप्यूटर वायरस कौन सा था?', options: ['ILOVEYOU', 'Creeper', 'Brain', 'MyDoom'], correct_answer: 1, points: 1 },
          { q_no: 6, question: 'UN Security Council में कितने स्थायी सदस्य हैं?', options: ['3', '4', '5', '6'], correct_answer: 2, points: 1 },
          { q_no: 7, question: 'ओलंपिक खेल कितने साल में होते हैं?', options: ['2', '3', '4', '5'], correct_answer: 2, points: 1 },
          { q_no: 8, question: 'भारतीय रेलवे की स्थापना कब हुई?', options: ['1843', '1853', '1863', '1873'], correct_answer: 1, points: 1 },
          { q_no: 9, question: 'विश्व स्वास्थ्य संगठन (WHO) का मुख्यालय कहाँ है?', options: ['न्यूयॉर्क', 'जिनेवा', 'लंदन', 'पेरिस'], correct_answer: 1, points: 1 },
          { q_no: 10, question: 'MangalyaanAan (Mars Orbiter) भारत ने कब लॉन्च किया?', options: ['2012', '2013', '2014', '2015'], correct_answer: 1, points: 1 },
          { q_no: 11, question: 'भारत में सबसे लंबी नदी कौन सी है?', options: ['यमुना', 'गोदावरी', 'गंगा', 'नर्मदा'], correct_answer: 2, points: 1 },
          { q_no: 12, question: 'LED का फ़ुल फ़ॉर्म क्या है?', options: ['Light Energy Diode', 'Light Emitting Diode', 'Laser Emitting Device', 'Low Energy Display'], correct_answer: 1, points: 1 }
        ]
      },
      {
        quiz_id: `M${String(now.getFullYear()).slice(2)}${String(now.getMonth()+1).padStart(2,'0')}-SP`,
        title: 'Speed Round — 60 Seconds!',
        description: '⚡ तेज़ सोचो, तेज़ जवाब दो! Speed quiz challenge.',
        type: 'monthly',
        game_type: 'speed',
        entry_fee: 100,
        start_date: now,
        end_date: monthEnd,
        result_date: new Date(monthEnd.getTime() + 3*86400000),
        status: 'active',
        prizes: { first: 3000, second: 1500, third: 500 },
        questions: [
          { q_no: 1, question: 'H2O क्या है?', options: ['ऑक्सीजन', 'पानी', 'हाइड्रोजन', 'नमक'], correct_answer: 1, points: 1 },
          { q_no: 2, question: '7 × 8 = ?', options: ['54', '56', '58', '64'], correct_answer: 1, points: 1 },
          { q_no: 3, question: 'भारत की मुद्रा क्या है?', options: ['डॉलर', 'रुपया', 'यूरो', 'पौंड'], correct_answer: 1, points: 1 },
          { q_no: 4, question: 'Rainbow में कितने रंग होते हैं?', options: ['5', '6', '7', '8'], correct_answer: 2, points: 1 },
          { q_no: 5, question: 'पानी का boiling point?', options: ['50°C', '100°C', '150°C', '200°C'], correct_answer: 1, points: 1 }
        ]
      }
    ];
    await Quiz.insertMany(sampleQuizzes);
    console.log('✅ Seeded 5 sample quizzes');
  }
}

// --- Auth middleware ---
function auth(requiredRole) {
  return (req, res, next) => {
    try {
      const token = req.cookies.token;
      if (!token) return res.status(401).json({ error: 'Unauthorized' });
      const data = jwt.verify(token, JWT_SECRET);
      req.user = data;
      if (requiredRole) {
        const allowed = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
        if (!allowed.includes(data.role)) return res.status(403).json({ error: 'Forbidden' });
      }
      next();
    } catch (e) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }
}

// --- Routes ---

// Health check
app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'FWF Backend API',
    status: 'online',
    database: 'MongoDB Atlas',
    version: '2.1.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: ['/api/auth/login', '/api/admin/login', '/api/auth/logout'],
      member: ['/api/member/me', '/api/member/invoices', '/api/member/apply-wallet', '/api/member/weekly-task', '/api/member/complete-task', '/api/member/all-tasks', '/api/member/task-history', '/api/member/feed', '/api/member/create-post', '/api/member/active-quizzes', '/api/member/quiz-enroll', '/api/member/quiz-submit', '/api/member/quiz-history', '/api/member/affiliate'],
      admin: ['/api/admin/overview', '/api/admin/invoices', '/api/admin/invoice/:id/resend', '/api/admin/invoice/:id', '/api/admin/zoho/status', '/api/admin/zoho/sync', '/api/admin/zoho/sync/:receiptId', '/api/admin/zoho/disconnect', '/api/admin/invoice/:id', '/api/admin/zoho/status', '/api/admin/zoho/sync', '/api/admin/zoho/sync/:receiptId', '/api/admin/zoho/disconnect', '/api/admin/create-quiz', '/api/admin/quiz-draw/:quizId', '/api/admin/quizzes', '/api/admin/quiz-auto-create', '/api/admin/quiz-auto-draw', '/api/admin/quiz-scheduler-status', '/api/admin/quiz-purge-all', '/api/admin/quiz-seed', '/api/admin/quiz/:quizId/detail', '/api/admin/quiz/:quizId/participants', '/api/admin/social-stats', '/api/admin/social-posts', '/api/admin/social-posts/:id/approve', '/api/admin/social-posts/:id/reject'],
      payment: ['/api/pay/check-member', '/api/pay/simulate-join', '/api/pay/create-order', '/api/pay/create-subscription', '/api/pay/create-donation-subscription', '/api/pay/verify', '/api/pay/membership', '/api/pay/donation'],
      referral: ['/api/referral/click'],
      debug: ['/api/debug/users (development only)']
    }
  });
});

// Debug endpoints - DISABLED in production
app.get('/api/debug/users', (req, res) => {
  if (IS_PRODUCTION) return res.status(404).json({ error: 'Not found' });
  User.find().sort({ created_at: -1 }).limit(10)
    .select('member_id name email mobile role membership_active created_at').lean()
    .then(users => res.json({ ok: true, totalUsers: users.length, users }))
    .catch(err => res.status(500).json({ error: err.message }));
});
app.get('/api/debug/user/:memberId', (req, res) => {
  if (IS_PRODUCTION) return res.status(404).json({ error: 'Not found' });
  User.findOne({ member_id: req.params.memberId })
    .select('member_id name email created_at').lean()
    .then(u => u ? res.json({ ok: true, ...u }) : res.status(404).json({ error: 'Not found' }))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Helper: precise duplicate-check error
async function checkDuplicateUser(email, mobile) {
  const emailUser = email ? await User.findOne({ email }) : null;
  const mobileUser = mobile ? await User.findOne({ mobile }) : null;
  if (!emailUser && !mobileUser) return null;
  const msgs = [];
  if (emailUser) {
    const role = emailUser.role === 'member' ? 'Member' : emailUser.role === 'supporter' ? 'Supporter' : emailUser.role;
    msgs.push(`Email "${email}" is already registered as ${role} (ID: ${emailUser.member_id})`);
  }
  if (mobileUser) {
    const role = mobileUser.role === 'member' ? 'Member' : mobileUser.role === 'supporter' ? 'Supporter' : mobileUser.role;
    msgs.push(`Mobile "${mobile}" is already registered as ${role} (ID: ${mobileUser.member_id})`);
  }
  return msgs.join(' | ') + '. Please login with your existing credentials.';
}

// Simulate join payment
app.post('/api/pay/simulate-join', internalAuth, async (req, res) => {
  const { name, mobile, email } = req.body;
  if (!name || !mobile) return res.status(400).json({ error: 'name & mobile required' });

  const dupError = await checkDuplicateUser(email, mobile);
  if (dupError) return res.status(400).json({ error: dupError });

  const memberId = await nextMemberId();
  const plain = randPass();
  const hash = bcrypt.hashSync(plain, 10);
  const refCode = generateReferralCode(memberId);

  await User.create({
    member_id: memberId,
    name,
    mobile,
    email: email || null,
    password_hash: hash,
    role: 'member',
    membership_active: true,
    referral_code: refCode,
    wallet: {}
  });

  // Send welcome + credentials email (non-blocking)
  sendMemberWelcome({ name, email: email || null, memberId, password: plain, mobile })
    .then(() => console.log(`✅ Member welcome email sent → ${email || mobile}`))
    .catch(e => console.error('⚠️ Member welcome email failed:', e.message));

  // Send WhatsApp credentials (non-blocking)
  if (mobile) {
    sendWhatsAppCredentials({ mobile, name, userId: memberId, password: plain })
      .catch(e => console.error('⚠️ WhatsApp credentials failed:', e.message));
  }

  // Admin alert (non-blocking)
  sendAdminAlert({
    subject: `New Member Registered: ${memberId} — ${name}`,
    rows: [['Member ID', memberId], ['Name', name], ['Mobile', mobile], ['Email', email || '—']]
  }).catch(() => {});

  res.json({ ok: true, memberId, password: plain });
});

// ═══════════════════════════════════════════════════════
// SUPPORTER REGISTRATION (public — from donation page)
// ═══════════════════════════════════════════════════════
app.post('/api/pay/register-supporter', async (req, res) => {
  try {
    const { name, mobile, email, project, message } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

    // Check if already registered
    const dupError = await checkDuplicateUser(email, mobile);
    if (dupError) return res.status(400).json({ error: dupError });

    const supporterId = await nextSupporterId();
    const plain = randPass();
    const hash = bcrypt.hashSync(plain, 10);
    const refCode = generateReferralCode(supporterId);

    await User.create({
      member_id: supporterId,
      name,
      mobile: mobile || null,
      email,
      password_hash: hash,
      role: 'supporter',
      membership_active: true,
      referral_code: refCode,
      bio: `Project: ${project || '-'} | ${message || ''}`.trim(),
      wallet: {}
    });

    // Send supporter welcome email (await so we can report success/failure)
    let emailSent = false;
    try {
      await sendSupporterWelcome({ name, email, supporterId, password: plain, project });
      emailSent = true;
      console.log(`✅ Supporter welcome email sent → ${email}`);
    } catch (e) {
      console.error(`⚠️ Supporter welcome email FAILED → ${email} | Error: ${e.message}`, e);
    }

    // Send WhatsApp credentials (non-blocking)
    if (mobile) {
      sendWhatsAppCredentials({ mobile, name, userId: supporterId, password: plain })
        .catch(e => console.error('⚠️ WhatsApp supporter credentials failed:', e.message));
    }

    // Admin alert (non-blocking)
    sendAdminAlert({
      subject: `New Supporter Registered: ${supporterId} — ${name}`,
      rows: [['Supporter ID', supporterId], ['Name', name], ['Email', email], ['Mobile', mobile || '—'], ['Project', project || '—'], ['Message', message || '—'], ['Email Sent', emailSent ? 'Yes ✅' : 'FAILED ❌']]
    }).catch(() => {});

    addBreadcrumb('registration', 'New supporter registered', { supporterId, name, email, emailSent });
    res.json({ ok: true, supporterId, emailSent, message: `Registration successful! Your Supporter ID is ${supporterId}.` });
  } catch (err) {
    console.error('Supporter registration error:', err);
    captureError(err, { context: 'supporter-registration' });
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// ═══════════════════════════════════════════════════════
// RAZORPAY PAYMENT GATEWAY
// ═══════════════════════════════════════════════════════

// Quick pre-check: is mobile/email already registered?
app.post('/api/pay/check-member', async (req, res) => {
  const { mobile, email } = req.body || {};
  if (!mobile && !email) return res.status(400).json({ error: 'mobile or email required' });
  const dupError = await checkDuplicateUser(email, mobile);
  if (dupError) return res.status(400).json({ error: dupError });
  res.json({ ok: true });
});

// Create Razorpay Subscription (monthly ₹500 — UPI AutoPay mandate)
app.post('/api/pay/create-subscription', async (req, res) => {
  try {
    const { name, email, mobile } = req.body || {};

    // Pre-check: reject if mobile/email already registered (before any payment)
    if (mobile || email) {
      const dupError = await checkDuplicateUser(email, mobile);
      if (dupError) return res.status(400).json({ error: dupError });
    }

    // Get or create a monthly plan (cache plan_id in env or DB)
    let planId = process.env.RAZORPAY_PLAN_ID;
    if (!planId) {
      // Create a new plan on-the-fly and ideally persist it
      const plan = await razorpay.plans.create({
        period: 'monthly',
        interval: 1,
        item: { name: 'FWF Monthly Membership', amount: 50000, currency: 'INR', description: 'Foundation for Women\'s Future — monthly membership fee' },
        notes: { org: 'FWF' }
      });
      planId = plan.id;
      console.log('✅ Razorpay plan created:', planId, '— set RAZORPAY_PLAN_ID in .env to reuse');
    }

    const subscription = await razorpay.subscriptions.create({
      plan_id:        planId,
      total_count:    120,       // 10 years max, member can cancel
      quantity:       1,
      customer_notify: 1,
      notes: { name: name || '', email: email || '', mobile: mobile || '', org: 'FWF' }
    });

    res.json({
      ok: true,
      subscription_id: subscription.id,
      key: process.env.RAZORPAY_KEY_ID
    });
  } catch (err) {
    console.error('Razorpay create-subscription error:', err);
    captureError(err, { context: 'razorpay-create-subscription' });
    res.status(500).json({ error: 'Failed to create subscription: ' + (err.error?.description || err.message) });
  }
});

// Create Razorpay Donation Subscription (variable monthly amount)
app.post('/api/pay/create-donation-subscription', async (req, res) => {
  try {
    const { amount, name, email, mobile } = req.body || {};
    if (!amount || Number(amount) < 1) return res.status(400).json({ error: 'Valid amount required (min ₹1)' });
    const amountPaise = Math.round(Number(amount) * 100);

    // Create a fresh plan for this donation amount
    const plan = await razorpay.plans.create({
      period: 'monthly',
      interval: 1,
      item: {
        name: `FWF Monthly Donation ₹${amount}`,
        amount: amountPaise,
        currency: 'INR',
        description: "Foundris Welfare Foundation — monthly donation"
      },
      notes: { org: 'FWF', type: 'recurring_donation' }
    });

    const subscription = await razorpay.subscriptions.create({
      plan_id:         plan.id,
      total_count:     120,   // up to 10 years; donor can cancel anytime
      quantity:        1,
      customer_notify: 1,
      notes: { name: name || '', email: email || '', mobile: mobile || '', org: 'FWF', type: 'recurring_donation' }
    });

    res.json({
      ok: true,
      subscription_id: subscription.id,
      key: process.env.RAZORPAY_KEY_ID
    });
  } catch (err) {
    console.error('Razorpay create-donation-subscription error:', err);
    captureError(err, { context: 'razorpay-create-donation-subscription' });
    res.status(500).json({ error: 'Failed to create subscription: ' + (err.error?.description || err.message) });
  }
});

// Create Razorpay Order
app.post('/api/pay/create-order', async (req, res) => {
  try {
    const { amount, currency = 'INR', type = 'membership', notes = {} } = req.body;
    if (!amount || amount < 1) return res.status(400).json({ error: 'Valid amount required (min ₹1)' });

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100), // Razorpay expects amount in paise
      currency,
      receipt: `fwf_${type}_${Date.now()}`,
      notes: {
        type,
        ...notes
      }
    });

    res.json({
      ok: true,
      order: {
        id: order.id,
        amount: order.amount,
        currency: order.currency,
        receipt: order.receipt
      },
      key: process.env.RAZORPAY_KEY_ID
    });
  } catch (err) {
    console.error('Razorpay create-order error:', err);
    captureError(err, { context: 'razorpay-create-order' });
    res.status(500).json({ error: 'Failed to create payment order' });
  }
});

// Verify Razorpay Payment Signature
app.post('/api/pay/verify', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: 'Missing payment verification fields' });
    }

    const keySecret = process.env.RAZORPAY_KEY_SECRET;
    const generated_signature = crypto
      .createHmac('sha256', keySecret)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');

    if (generated_signature !== razorpay_signature) {
      return res.status(400).json({ ok: false, error: 'Payment verification failed - invalid signature' });
    }

    res.json({ ok: true, message: 'Payment verified successfully', paymentId: razorpay_payment_id });
  } catch (err) {
    console.error('Razorpay verify error:', err);
    captureError(err, { context: 'razorpay-verify' });
    res.status(500).json({ error: 'Payment verification error' });
  }
});

// Razorpay Membership Payment: Create order + after verify → register member
app.post('/api/pay/membership', async (req, res) => {
  try {
    const { name, mobile, email, project, referrerCode,
            razorpay_payment_id, razorpay_order_id, razorpay_subscription_id, razorpay_signature } = req.body;
    if (!name || !mobile || !email) return res.status(400).json({ error: 'name, mobile & email required' });
    if (!razorpay_payment_id || !razorpay_signature) return res.status(400).json({ error: 'Payment details missing' });

    // Verify signature — subscription flow uses payment_id|subscription_id, order flow uses order_id|payment_id
    const keySecret = process.env.RAZORPAY_KEY_SECRET;
    let generated_signature;
    if (razorpay_subscription_id) {
      generated_signature = crypto
        .createHmac('sha256', keySecret)
        .update(razorpay_payment_id + '|' + razorpay_subscription_id)
        .digest('hex');
    } else if (razorpay_order_id) {
      generated_signature = crypto
        .createHmac('sha256', keySecret)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');
    } else {
      return res.status(400).json({ error: 'Missing order_id or subscription_id' });
    }

    if (generated_signature !== razorpay_signature) {
      return res.status(400).json({ ok: false, error: 'Payment verification failed' });
    }

    // Check if user already exists
    const dupError = await checkDuplicateUser(email, mobile);
    if (dupError) return res.status(400).json({ error: dupError });

    // Register member
    const memberId = await nextMemberId();
    const plain = randPass();
    const hash = bcrypt.hashSync(plain, 10);
    const refCode = generateReferralCode(memberId);

    await User.create({
      member_id: memberId,
      name,
      mobile,
      email,
      password_hash: hash,
      role: 'member',
      membership_active: true,
      referral_code: refCode,
      wallet: {},
      razorpay_subscription_id: razorpay_subscription_id || null,
      subscription_status: razorpay_subscription_id ? 'active' : 'pending'
    });

    // Record membership fee
    await MembershipFee.create({
      txn_id:      razorpay_payment_id,
      member_id:   memberId,
      member_name: name,
      amount:      500,
      fee_type:    'joining',
      payment_mode: 'razorpay',
      payment_ref:  razorpay_subscription_id || razorpay_order_id || '',
      status:      'verified',
      verified_at: new Date(),
      notes:       `Razorpay${razorpay_subscription_id ? ' subscription autopay' : ' order'} | Project: ${project || '-'}`
    });

    // Auto-register referral and credit referrer if referrerCode provided
    let referralPoints = 0;
    if (referrerCode) {
      try {
        const referrer = await User.findOne({ referral_code: referrerCode }).select('_id wallet');
        const newUser  = await User.findOne({ member_id: memberId }).select('_id');
        if (referrer && newUser) {
          const REFERRAL_PCT = REFERRAL_POINTS_PERCENT || 50; // % of payment as points
          const pointsRupees = 500 * (REFERRAL_PCT / 100);
          const points = amountToPoints(pointsRupees);
          referralPoints = points;

          await Referral.create({
            referrer_id:      referrer._id,
            referred_user_id: newUser._id,
            status:           'active',
            payment_amount:   500,
            referral_points:  points,
            activated_at:     new Date()
          });
          await User.updateOne({ _id: referrer._id }, {
            $inc: {
              'wallet.points_balance':        points,
              'wallet.points_from_referrals': points,
              'wallet.total_points_earned':   points
            },
            'wallet.updated_at': new Date()
          });
          await PointsLedger.create({
            user_id:     referrer._id,
            points,
            type:        'referral',
            description: `Referral: ${memberId} paid ₹500 → ${points} points`
          });
          await User.updateOne({ _id: newUser._id }, { referred_by: referrer._id });
        }
      } catch (refErr) {
        console.error('Referral credit error (non-fatal):', refErr.message);
      }
    }

    addBreadcrumb('payment', 'Membership payment successful', { memberId, paymentId: razorpay_payment_id, subscriptionId: razorpay_subscription_id });

    // Generate membership receipt first so we can include URL in welcome email
    const newUser2 = await User.findOne({ member_id: memberId }).select('_id').lean();
    const memberBackendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
    const memberRcpt = await createAndSendReceipt({
      type: 'membership',
      userId: newUser2?._id,
      memberId,
      customerName: name,
      customerEmail: email,
      customerMobile: mobile,
      lineItems: [{ name: 'FWF Membership Fee', description: 'Joining fee — Annual Membership (FWF India)', amount: 500, quantity: 1 }],
      total: 500,
      razorpayPaymentId: razorpay_payment_id,
      razorpayOrderId: razorpay_order_id,
      razorpaySubscriptionId: razorpay_subscription_id,
      referenceId: memberId,
      description: 'FWF Membership Joining Fee'
    });
    const memberReceiptUrl = memberRcpt ? `${memberBackendUrl}/receipt/${memberRcpt.token}` : null;
    if (memberRcpt) console.log(`🧾 Membership receipt created: ${memberRcpt.receipt_id}`);
    if (memberRcpt) syncReceiptToZoho(memberRcpt.toObject ? memberRcpt.toObject() : memberRcpt).catch(() => {});

    // Send member welcome email with receipt link (non-blocking)
    sendMemberWelcome({ name, email, memberId, password: plain, mobile, receiptUrl: memberReceiptUrl })
      .then(() => console.log(`✅ Member welcome email sent → ${email}`))
      .catch(e => console.error('⚠️ Member welcome email failed:', e.message));

    // Admin alert (non-blocking)
    sendAdminAlert({
      subject: `New Member via Payment: ${memberId} — ${name}`,
      rows: [['Member ID', memberId], ['Name', name], ['Mobile', mobile], ['Email', email], ['Amount', '₹500'], ['Payment ID', razorpay_payment_id]]
    }).catch(() => {});

    res.json({ ok: true, memberId, password: plain, paymentId: razorpay_payment_id, subscriptionId: razorpay_subscription_id, referralPoints });
  } catch (err) {
    console.error('Razorpay membership error:', err);
    captureError(err, { context: 'razorpay-membership' });
    res.status(500).json({ error: 'Registration failed: ' + err.message });
  }
});

// Razorpay Donation Payment: verify + record donation
app.post('/api/pay/donation', async (req, res) => {
  try {
    const {
      name, mobile, email, pan, address,
      amount, memberId: memberIdInput,
      want80g,
      razorpay_payment_id, razorpay_order_id, razorpay_signature,
      verified_token
    } = req.body;
    if (!amount || !razorpay_payment_id) return res.status(400).json({ error: 'Payment details required' });

    const numAmount = Number(amount);
    const kycRequired = numAmount >= 50000;

    // For donations ≥ ₹50,000 — verify OTP token from MongoDB
    let otpVerified = false;
    if (kycRequired) {
      if (!verified_token) {
        return res.status(400).json({ error: 'OTP verification is required for donations of ₹50,000 or more' });
      }
      const otpRecord = await DonationOtp.findOne({
        verified: true,
        verified_token,
        expires_at: { $gt: new Date(Date.now() - 30 * 60 * 1000) } // token valid for 30 mins after verify
      });
      if (!otpRecord) {
        return res.status(400).json({ error: 'OTP verification token is invalid or expired. Please verify again.' });
      }
      otpVerified = true;
    }

    // Verify Razorpay signature (order for one-time; subscription for recurring)
    const keySecret = process.env.RAZORPAY_KEY_SECRET;
    const { razorpay_subscription_id, recurring } = req.body;
    let sig_ok = false;
    if (recurring && razorpay_subscription_id) {
      // Subscription signature: HMAC(payment_id + '|' + subscription_id)
      const expected = crypto.createHmac('sha256', keySecret)
        .update(razorpay_payment_id + '|' + razorpay_subscription_id)
        .digest('hex');
      sig_ok = expected === razorpay_signature;
    } else {
      // Order signature: HMAC(order_id + '|' + payment_id)
      const expected = crypto.createHmac('sha256', keySecret)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');
      sig_ok = expected === razorpay_signature;
    }
    if (!sig_ok) {
      return res.status(400).json({ ok: false, error: 'Payment verification failed' });
    }

    // Award points if linked member
    let user = null;
    if (memberIdInput) user = await User.findOne({ member_id: memberIdInput });

    const donationId = await nextDonationId();
    const donationData = {
      donation_id:  donationId,
      amount:       numAmount,
      donor_name:   name  || 'Anonymous',
      donor_email:  email || null,
      donor_mobile: mobile || null,
      donor_pan:    pan   || null,
      donor_address: address || null,
      source:       recurring ? 'razorpay_recurring' : 'razorpay',
      payment_id:   razorpay_payment_id,
      order_id:     razorpay_order_id || null,
      subscription_id: razorpay_subscription_id || null,
      recurring:    !!recurring,
      kyc_required: kycRequired,
      otp_verified: otpVerified,
      kyc_status:   kycRequired ? (otpVerified ? 'otp_verified' : 'pending_docs') : 'not_required'
    };

    if (user) {
      donationData.member_id = user._id;
      const pointsRupees = numAmount * (DONATION_POINTS_PERCENT / 100);
      const points = amountToPoints(pointsRupees);
      donationData.points_earned = points;
      await User.updateOne({ _id: user._id }, {
        $inc: {
          'wallet.balance_inr': pointsRupees,
          'wallet.lifetime_earned_inr': pointsRupees,
          'wallet.points_balance': points,
          'wallet.total_points_earned': points,
          'wallet.points_from_donations': points
        }
      });
      await PointsLedger.create({
        user_id: user._id, points, type: 'donation',
        description: `₹${numAmount} donation via Razorpay → ${points} points`
      });
    }

    const donationRecord = await Donation.create(donationData);
    addBreadcrumb('payment', 'Donation recorded', { donationId, amount: numAmount, kycRequired, otpVerified });

    const backendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
    const rcpt = await createAndSendReceipt({
      type: 'donation',
      userId: user?._id,
      memberId: user?.member_id || null,
      customerName: name || 'Anonymous',
      customerEmail: email || null,
      customerMobile: mobile || null,
      customerPan: pan || null,
      customerAddress: address || null,
      lineItems: [{ name: `Donation to FWF${recurring ? ' (Monthly Recurring)' : ''}`, description: 'Charitable donation — Foundation for Women\'s Future', amount: numAmount, quantity: 1 }],
      total: numAmount,
      razorpayPaymentId: razorpay_payment_id,
      razorpayOrderId: razorpay_order_id || null,
      razorpaySubscriptionId: razorpay_subscription_id || null,
      referenceId: donationId,
      is80g: !!(want80g && pan),
      description: `Donation ₹${numAmount}${recurring ? ' (Recurring)' : ''}`
    });
    const receiptUrl = rcpt ? `${backendUrl}/receipt/${rcpt.token}` : null;
    if (rcpt) console.log(`🧾 Donation receipt created: ${rcpt.receipt_id}`);
    // Sync receipt to Zoho (non-blocking)
    if (rcpt) syncReceiptToZoho(rcpt.toObject ? rcpt.toObject() : rcpt).catch(err => console.warn('⚠️ Zoho sync:', err.message));

    // Send 80G receipt email if donor opted in and has PAN + email
    let receipt80GSent = false;
    if (want80g && email && pan) {
      try {
        await send80GReceipt({
          donationId,
          name: name || 'Donor',
          email,
          pan,
          address: address || '',
          amount: numAmount,
          paymentId: razorpay_payment_id,
          date: new Date()
        });
        receipt80GSent = true;
        addBreadcrumb('email', '80G receipt sent', { donationId, email });
      } catch (mailErr) {
        console.error('80G receipt email failed:', mailErr.message);
        captureError(mailErr, { context: '80g-receipt-email', donationId });
      }
    }

    // Always send donation confirmation email with receipt link
    if (email) {
      sendDonationConfirmation({
        name: name || 'Donor',
        email,
        amount: numAmount,
        donationId,
        paymentId: razorpay_payment_id,
        recurring: !!recurring,
        pointsEarned: donationData.points_earned || 0,
        receiptUrl
      })
        .then(() => console.log(`✅ Donation confirmation email sent → ${email}`))
        .catch(e => console.error('⚠️ Donation confirmation email failed:', e.message));
    }

    // Send WhatsApp donation confirmation (non-blocking)
    if (mobile) {
      sendWhatsAppDonation({
        mobile,
        name: name || 'Donor',
        amount: numAmount,
        donationId,
        paymentId: razorpay_payment_id
      }).catch(e => console.error('⚠️ WhatsApp donation confirmation failed:', e.message));

      // Send donation receipt SMS (based on 80G eligibility)
      const smsName = name || 'Donor';
      if (receipt80GSent) {
        sendDonationReceipt80GSms({ mobile, name: smsName, amount: numAmount })
          .catch(e => console.error('⚠️ 80G receipt SMS failed:', e.message));
      } else {
        sendDonationReceiptSms({ mobile, name: smsName, amount: numAmount })
          .catch(e => console.error('⚠️ Donation receipt SMS failed:', e.message));
      }
    }

    // Admin alert for donation (non-blocking)
    sendAdminAlert({
      subject: `New Donation: ₹${numAmount} — ${name || 'Anonymous'}`,
      rows: [
        ['Donation ID', donationId],
        ['Amount', `₹${numAmount.toLocaleString('en-IN')}`],
        ['Donor', name || 'Anonymous'],
        ['Email', email || '—'],
        ['Mobile', mobile || '—'],
        ['Type', recurring ? 'Recurring (Monthly)' : 'One-time'],
        ['Payment ID', razorpay_payment_id],
        ['80G Sent', receipt80GSent ? 'Yes' : 'No']
      ]
    }).catch(() => {});

    res.json({
      ok: true,
      donationId,
      message: `Thank you for your ₹${numAmount} donation!`,
      paymentId: razorpay_payment_id,
      pointsEarned: donationData.points_earned || 0,
      receipt80GSent
    });
  } catch (err) {
    console.error('Razorpay donation error:', err);
    captureError(err, { context: 'razorpay-donation' });
    res.status(500).json({ error: 'Donation recording failed: ' + err.message });
  }
});

// Razorpay Supporter Payment: verify + credit 10% points to referring member
app.post('/api/pay/supporter', auth('member'), async (req, res) => {
  try {
    const {
      supporterName, supporterContact, supporterNotes,
      amount,
      razorpay_payment_id, razorpay_order_id, razorpay_signature
    } = req.body;
    if (!amount || !razorpay_payment_id) return res.status(400).json({ error: 'Payment details required' });

    const numAmount = Number(amount);

    // Verify Razorpay signature
    const keySecret = process.env.RAZORPAY_KEY_SECRET;
    const generated_signature = crypto
      .createHmac('sha256', keySecret)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');
    if (generated_signature !== razorpay_signature) {
      return res.status(400).json({ ok: false, error: 'Payment verification failed' });
    }

    // Credit 10% of supporter amount as points to the member
    const pointsRupees = numAmount * (DONATION_POINTS_PERCENT / 100);
    const points = amountToPoints(pointsRupees);

    await User.updateOne({ _id: req.user.uid }, {
      $inc: {
        'wallet.points_balance':        points,
        'wallet.points_from_donations': points,
        'wallet.total_points_earned':   points
      },
      'wallet.updated_at': new Date()
    });

    await PointsLedger.create({
      user_id: req.user.uid, points, type: 'supporter',
      description: `₹${numAmount} supporter joined via ${req.user.memberId} → ${points} points`
    });

    // Record as donation for tracking
    await Donation.create({
      member_id:    req.user.uid,
      amount:       numAmount,
      points_earned: points,
      donor_name:   supporterName || null,
      donor_contact: supporterContact || null,
      source:       'supporter',
      payment_id:   razorpay_payment_id,
      order_id:     razorpay_order_id,
      kyc_status:   'not_required'
    });

    addBreadcrumb('payment', 'Supporter payment recorded', { memberId: req.user.memberId, amount: numAmount, points });
    res.json({ ok: true, points, pointsEarned: points, message: `Supporter added! You earned ${points} points (10% of ₹${numAmount}).` });
  } catch (err) {
    console.error('Supporter payment error:', err);
    captureError(err, { context: 'supporter-payment' });
    res.status(500).json({ error: 'Supporter payment recording failed: ' + err.message });
  }
});

// Admin: reset a member's password
app.post('/api/admin/reset-password', auth('admin'), async (req, res) => {
  const { memberId, newPassword } = req.body;
  if (!memberId || !newPassword) return res.status(400).json({ error: 'memberId & newPassword required' });
  const u = await User.findOne({ member_id: memberId });
  if (!u) return res.status(404).json({ error: 'Member not found' });
  u.password_hash = bcrypt.hashSync(newPassword, 10);
  await u.save();
  res.json({ ok: true, message: `Password reset for ${memberId}` });
});

app.post('/api/auth/login', rateLimit(60000, 5), async (req, res) => {
  const { memberId, password } = req.body;
  if (!memberId || !password) return res.status(400).json({ error: 'Member ID and password are required' });

  let u = await User.findOne({ member_id: memberId });
  if (!u) u = await User.findOne({ email: memberId });
  if (!u) {
    console.log(`Login failed: member_id/email "${memberId}" not found`);
    return res.status(400).json({ error: 'Invalid Member ID or password' });
  }
  if (!bcrypt.compareSync(password, u.password_hash)) {
    console.log(`Login failed: wrong password for "${memberId}"`);
    return res.status(400).json({ error: 'Invalid Member ID or password' });
  }
  const token = signToken({ uid: u._id.toString(), role: u.role, memberId: u.member_id, name: u.name });
  res.cookie('token', token, { httpOnly: true, sameSite: 'none', secure: true });
  addBreadcrumb('auth', 'Member logged in', { memberId: u.member_id });
  res.json({ ok: true, role: u.role });
});

app.post('/api/admin/login', rateLimit(60000, 5), async (req, res) => {
  const { username, password } = req.body;
  const u = await User.findOne({ email: username, role: 'admin' });
  if (!u) return res.status(400).json({ error: 'Invalid credentials' });
  if (!bcrypt.compareSync(password, u.password_hash)) return res.status(400).json({ error: 'Invalid credentials' });
  const token = signToken({ uid: u._id.toString(), role: u.role, memberId: u.member_id, name: u.name });
  res.cookie('token', token, { httpOnly: true, sameSite: 'none', secure: true });
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, sameSite: 'none', secure: true });
  res.json({ ok: true });
});

// Get user email by member ID — internal only
app.post('/api/auth/get-user-email', internalAuth, async (req, res) => {
  const { memberId } = req.body;
  if (!memberId) return res.status(400).json({ error: 'Member ID is required' });
  const u = await User.findOne({ member_id: memberId }).select('email mobile');
  if (!u) return res.status(404).json({ error: 'Member ID not found' });
  res.json({ email: u.email, mobile: u.mobile || null });
});

// Update password — internal only
app.post('/api/auth/update-password', internalAuth, async (req, res) => {
  const { memberId, newPassword } = req.body;
  if (!memberId || !newPassword) return res.status(400).json({ error: 'Member ID and new password are required' });

  const u = await User.findOne({ member_id: memberId }).select('password_hash');
  if (!u) return res.status(404).json({ error: 'Member ID not found' });

  const oldHashPreview = u.password_hash.substring(0, 15);
  u.password_hash = bcrypt.hashSync(newPassword, 10);
  await u.save();

  console.log(`✅ Password updated for ${memberId}:`, {
    oldHash: oldHashPreview + '...',
    newHash: u.password_hash.substring(0, 15) + '...',
    dbType: 'MongoDB'
  });

  addBreadcrumb('auth', 'Password reset', { memberId });
  res.json({ ok: true, message: 'Password updated successfully' });
});

app.get('/api/member/me', auth(['member','supporter']), async (req, res) => {
  const u = await User.findById(req.user.uid)
    .select('member_id name mobile email created_at first_login_done referral_code avatar_url bio wallet member_project').lean();
  if (!u) return res.status(404).json({ error: 'User not found' });

  const w = u.wallet || { balance_inr: 0, lifetime_earned_inr: 0, lifetime_applied_inr: 0, points_balance: 0, points_from_donations: 0, points_from_referrals: 0, points_from_quiz: 0, total_points_earned: 0 };
  const p = u.member_project || null;

  // Referral stats
  const referralAgg = await Referral.aggregate([
    { $match: { referrer_id: new mongoose.Types.ObjectId(req.user.uid) } },
    { $group: { _id: null, total: { $sum: 1 }, active: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } }, totalPoints: { $sum: '$referral_points' } } }
  ]);
  const referralStats = referralAgg[0] || { total: 0, active: 0, totalPoints: 0 };

  // Recent donations
  const recentDonations = await Donation.find({ member_id: req.user.uid })
    .sort({ created_at: -1 }).limit(5)
    .select('amount points_earned donor_name created_at').lean();

  // Quiz stats
  const quizAgg = await QuizTicket.aggregate([
    { $match: { seller_id: new mongoose.Types.ObjectId(req.user.uid) } },
    { $group: { _id: null, sold: { $sum: 1 }, totalPoints: { $sum: '$points_earned' } } }
  ]);
  const quizStats = quizAgg[0] || { sold: 0, totalPoints: 0 };

  // Recent points
  const recentPoints = await PointsLedger.find({ user_id: req.user.uid })
    .sort({ created_at: -1 }).limit(10)
    .select('points type description created_at').lean();

  // Membership fees
  const membershipFees = await MembershipFee.find({ user_id: req.user.uid })
    .sort({ created_at: -1 }).limit(10)
    .select('txn_id amount fee_type status created_at').lean();

  // Referrals list (with referred user details)
  const referralsRaw = await Referral.find({ referrer_id: req.user.uid })
    .sort({ created_at: -1 }).limit(20)
    .populate('referred_user_id', 'name member_id')
    .lean();
  const referrals = referralsRaw.map(r => ({
    referred_name: r.referred_user_id?.name || '—',
    referred_member_id: r.referred_user_id?.member_id || '—',
    amount: r.payment_amount || 0,
    points_earned: r.referral_points || 0,
    status: r.status,
    created_at: r.created_at
  }));

  const pointInfo = { pointValue: POINT_VALUE, donationPercent: DONATION_POINTS_PERCENT, referralPercent: REFERRAL_POINTS_PERCENT, quizPercent: QUIZ_TICKET_POINTS_PERCENT, ticketPrice: QUIZ_TICKET_PRICE };

  res.json({ user: u, wallet: w, project: p, referralStats, recentDonations, quizStats, recentPoints, membershipFees, referrals, pointInfo });
});

// Mark first login as done
app.post('/api/member/welcome-done', auth(['member','supporter']), async (req, res) => {
  await User.updateOne({ _id: req.user.uid }, { first_login_done: true });
  res.json({ ok: true });
});

// Update profile
app.post('/api/member/update-profile', auth(['member','supporter']), async (req, res) => {
  const { name, bio, avatar_url } = req.body;
  const update = {};
  if (name) update.name = name;
  if (bio !== undefined) update.bio = bio;
  if (avatar_url !== undefined) update.avatar_url = avatar_url;
  if (Object.keys(update).length === 0) return res.status(400).json({ error: 'Nothing to update' });
  await User.updateOne({ _id: req.user.uid }, update);
  res.json({ ok: true });
});

// Record donation → 10% as points
app.post('/api/member/record-donation', auth('member'), async (req, res) => {
  const { amount, donorName, donorContact } = req.body;
  const amt = parseFloat(amount);
  if (!amt || amt <= 0) return res.status(400).json({ error: 'Valid amount required' });

  const pointsRupees = amt * (DONATION_POINTS_PERCENT / 100);
  const points = amountToPoints(pointsRupees);

  await Donation.create({
    member_id: req.user.uid, amount: amt, points_earned: points,
    donor_name: donorName || null, donor_contact: donorContact || null
  });

  await User.updateOne({ _id: req.user.uid }, {
    $inc: {
      'wallet.points_balance': points,
      'wallet.points_from_donations': points,
      'wallet.total_points_earned': points
    },
    'wallet.updated_at': new Date()
  });

  await PointsLedger.create({
    user_id: req.user.uid, points, type: 'donation',
    description: `₹${amt} donation collected from ${donorName || 'anonymous'} → ${points} points`
  });

  res.json({ ok: true, points, message: `₹${amt} donation recorded. You earned ${points} points!` });
});

// Sell quiz ticket → 10% as points
app.post('/api/member/sell-ticket', auth('member'), async (req, res) => {
  const { buyerName, buyerContact, ticketPrice } = req.body;
  const price = parseFloat(ticketPrice) || QUIZ_TICKET_PRICE;

  const pointsRupees = price * (QUIZ_TICKET_POINTS_PERCENT / 100);
  const points = amountToPoints(pointsRupees);

  await QuizTicket.create({
    seller_id: req.user.uid, buyer_name: buyerName || null,
    buyer_contact: buyerContact || null, ticket_price: price, points_earned: points
  });

  await User.updateOne({ _id: req.user.uid }, {
    $inc: {
      'wallet.points_balance': points,
      'wallet.points_from_quiz': points,
      'wallet.total_points_earned': points
    },
    'wallet.updated_at': new Date()
  });

  await PointsLedger.create({
    user_id: req.user.uid, points, type: 'quiz',
    description: `Quiz ticket sold to ${buyerName || 'buyer'} (₹${price}) → ${points} points`
  });

  res.json({ ok: true, points, message: `Ticket sold! You earned ${points} points.` });
});

// Get referral info
app.get('/api/member/referrals', auth('member'), async (req, res) => {
  const u = await User.findById(req.user.uid).select('referral_code').lean();
  const referrals = await Referral.find({ referrer_id: req.user.uid })
    .sort({ created_at: -1 }).lean();

  // Populate referred user names
  for (const r of referrals) {
    const referred = await User.findById(r.referred_user_id).select('name member_id').lean();
    if (referred) {
      r.referred_name = referred.name;
      r.referred_member_id = referred.member_id;
    }
  }

  res.json({ ok: true, referralCode: u.referral_code, referrals });
});

// Register via referral
app.post('/api/member/register-referral', async (req, res) => {
  const { referralCode, newUserId } = req.body;
  if (!referralCode || !newUserId) return res.status(400).json({ error: 'referralCode & newUserId required' });

  const referrer = await User.findOne({ referral_code: referralCode }).select('_id');
  if (!referrer) return res.status(404).json({ error: 'Invalid referral code' });

  await Referral.create({ referrer_id: referrer._id, referred_user_id: newUserId, status: 'pending' });
  await User.updateOne({ _id: newUserId }, { referred_by: referrer._id });

  res.json({ ok: true });
});

// Activate referral
app.post('/api/member/activate-referral', auth('admin'), async (req, res) => {
  const { referredMemberId, paymentAmount } = req.body;
  const referred = await User.findOne({ member_id: referredMemberId }).select('referred_by');
  if (!referred || !referred.referred_by) return res.status(400).json({ error: 'No referral found' });

  const amt = parseFloat(paymentAmount) || 500;
  const pointsRupees = amt * (REFERRAL_POINTS_PERCENT / 100);
  const points = amountToPoints(pointsRupees);

  await Referral.updateOne(
    { referrer_id: referred.referred_by, referred_user_id: referred._id, status: 'pending' },
    { status: 'active', payment_amount: amt, referral_points: points, activated_at: new Date() }
  );

  await User.updateOne({ _id: referred.referred_by }, {
    $inc: {
      'wallet.points_balance': points,
      'wallet.points_from_referrals': points,
      'wallet.total_points_earned': points
    },
    'wallet.updated_at': new Date()
  });

  await PointsLedger.create({
    user_id: referred.referred_by, points, type: 'referral',
    description: `Referral activated: ${referredMemberId} paid ₹${amt} → ${points} points`
  });

  await User.updateOne({ _id: referred._id }, { membership_active: true });

  res.json({ ok: true, points });
});

// Points history
app.get('/api/member/points-history', auth('member'), async (req, res) => {
  const ledger = await PointsLedger.find({ user_id: req.user.uid })
    .sort({ created_at: -1 }).limit(50)
    .select('points type description created_at').lean();
  res.json({ ok: true, ledger });
});

// Apply wallet
app.post('/api/member/apply-wallet', auth('member'), async (req, res) => {
  const { amount } = req.body;
  const u = await User.findById(req.user.uid).select('wallet member_project');
  if (!u || !u.wallet || u.wallet.balance_inr <= 0) return res.status(400).json({ error: 'No wallet balance' });
  const amt = Math.min(parseFloat(amount || 0), u.wallet.balance_inr);
  if (amt <= 0) return res.status(400).json({ error: 'Invalid amount' });

  await User.updateOne({ _id: req.user.uid }, {
    $inc: {
      'wallet.balance_inr': -amt,
      'wallet.lifetime_applied_inr': amt,
      'member_project.wallet_applied_inr': amt
    },
    'wallet.updated_at': new Date()
  });

  // Create member_project if not exists
  const updated = await User.findById(req.user.uid).select('member_project');
  if (!updated.member_project) {
    await User.updateOne({ _id: req.user.uid }, {
      member_project: { project_name: 'Not Selected', wallet_applied_inr: amt }
    });
  }

  res.json({ ok: true });
});

// Admin overview
app.get('/api/admin/overview', auth('admin'), async (req, res) => {
  const [members, activeMembers, walletAgg, donationsCount, donationsSum, referralsTotal, referralsActive, ticketsSold, supportersCount] = await Promise.all([
    User.countDocuments({ role: 'member' }),
    User.countDocuments({ role: 'member', membership_active: true }),
    User.aggregate([{ $match: { role: 'member' } }, { $group: { _id: null, total: { $sum: '$wallet.total_points_earned' } } }]),
    Donation.countDocuments(),
    Donation.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]),
    Referral.countDocuments(),
    Referral.countDocuments({ status: 'active' }),
    QuizTicket.countDocuments(),
    User.countDocuments({ role: 'supporter' })
  ]);

  let csrPartners = 0, supportTickets = 0, pendingFees = 0, totalFeeCollected = 0;
  try {
    csrPartners = await CsrPartner.countDocuments();
    supportTickets = await SupportTicket.countDocuments({ status: 'open' });
    pendingFees = await MembershipFee.countDocuments({ status: 'pending' });
    const feeAgg = await MembershipFee.aggregate([{ $match: { status: 'verified' } }, { $group: { _id: null, total: { $sum: '$amount' } } }]);
    totalFeeCollected = feeAgg[0]?.total || 0;
  } catch (e) { }

  const totals = {
    members,
    active_members: activeMembers,
    supporters: supportersCount,
    total_points: walletAgg[0]?.total || 0,
    total_donations_count: donationsCount,
    total_donations_amount: donationsSum[0]?.total || 0,
    total_referrals: referralsTotal,
    active_referrals: referralsActive,
    total_tickets_sold: ticketsSold,
    csr_partners: csrPartners,
    support_tickets: supportTickets,
    pending_fees: pendingFees,
    total_fee_collected: totalFeeCollected
  };

  const latest = await User.find({ role: 'member' }).sort({ created_at: -1 }).limit(10)
    .select('member_id name mobile email membership_active created_at').lean();

  res.json({ totals, latest });
});

// Admin: get all members
app.get('/api/admin/members', auth('admin'), async (req, res) => {
  const members = await User.find({ role: 'member' }).sort({ created_at: -1 })
    .select('member_id name mobile email membership_active referral_code created_at wallet').lean();
  const mapped = members.map(m => ({
    id: m._id, member_id: m.member_id, name: m.name, mobile: m.mobile, email: m.email,
    membership_active: m.membership_active, referral_code: m.referral_code, created_at: m.created_at,
    balance_inr: m.wallet?.balance_inr || 0, points_balance: m.wallet?.points_balance || 0,
    total_points_earned: m.wallet?.total_points_earned || 0,
    points_from_donations: m.wallet?.points_from_donations || 0,
    points_from_referrals: m.wallet?.points_from_referrals || 0,
    points_from_quiz: m.wallet?.points_from_quiz || 0
  }));
  res.json({ ok: true, members: mapped });
});

// Admin: get single member detail
app.get('/api/admin/member/:memberId', auth('admin'), async (req, res) => {
  const u = await User.findOne({ member_id: req.params.memberId, role: 'member' }).lean();
  if (!u) return res.status(404).json({ error: 'Member not found' });
  const [donations, referrals, tickets, points] = await Promise.all([
    Donation.find({ member_id: u._id }).sort({ created_at: -1 }).limit(20).lean(),
    Referral.find({ referrer_id: u._id }).sort({ created_at: -1 }).lean(),
    QuizTicket.find({ seller_id: u._id }).sort({ sold_at: -1 }).limit(20).lean(),
    PointsLedger.find({ user_id: u._id }).sort({ created_at: -1 }).limit(30).lean()
  ]);

  // Populate referred names
  for (const r of referrals) {
    const ref = await User.findById(r.referred_user_id).select('name member_id').lean();
    if (ref) { r.referred_name = ref.name; r.referred_member_id = ref.member_id; }
  }

  res.json({ ok: true, user: u, wallet: u.wallet || {}, donations, referrals, tickets, points, project: u.member_project || null });
});

// Admin: toggle member active status
app.post('/api/admin/toggle-member', auth('admin'), async (req, res) => {
  const { memberId } = req.body;
  if (!memberId) return res.status(400).json({ error: 'memberId required' });
  const u = await User.findOne({ member_id: memberId }).select('membership_active');
  if (!u) return res.status(404).json({ error: 'Member not found' });
  u.membership_active = !u.membership_active;
  await u.save();
  res.json({ ok: true, membership_active: u.membership_active ? 1 : 0 });
});

// Admin: delete member (and all associated data)
app.delete('/api/admin/member/:memberId', auth('admin'), async (req, res) => {
  const u = await User.findOne({ member_id: req.params.memberId, role: 'member' });
  if (!u) return res.status(404).json({ error: 'Member not found' });
  await Promise.all([
    PointsLedger.deleteMany({ user_id: u._id }),
    Referral.deleteMany({ $or: [{ referrer_id: u._id }, { referred_user_id: u._id }] }),
    QuizTicket.deleteMany({ $or: [{ seller_id: u._id }, { buyer_id: u._id }] }),
    MembershipFee.deleteMany({ user_id: u._id }),
    Order.deleteMany({ user_id: u._id }),
    SupportTicket.deleteMany({ user_id: u._id }),
    TaskCompletion.deleteMany({ user_id: u._id }),
    SocialPost.deleteMany({ user_id: u._id }),
    QuizParticipation.deleteMany({ user_id: u._id }),
  ]);
  await User.deleteOne({ _id: u._id });
  res.json({ ok: true, message: `Member ${req.params.memberId} deleted` });
});

// Admin: get all supporters (volunteer signups)
app.get('/api/admin/supporters', auth('admin'), async (req, res) => {
  const supporters = await User.find({ role: 'supporter' }).sort({ created_at: -1 })
    .select('member_id name mobile email membership_active bio referral_code created_at').lean();
  res.json({ ok: true, supporters, total: supporters.length });
});

// Admin: delete supporter
app.delete('/api/admin/supporter/:supporterId', auth('admin'), async (req, res) => {
  const u = await User.findOne({ member_id: req.params.supporterId, role: 'supporter' });
  if (!u) return res.status(404).json({ error: 'Supporter not found' });
  await Promise.all([
    PointsLedger.deleteMany({ user_id: u._id }),
    SupportTicket.deleteMany({ user_id: u._id }),
    SocialPost.deleteMany({ user_id: u._id }),
    TaskCompletion.deleteMany({ user_id: u._id }),
  ]);
  await User.deleteOne({ _id: u._id });
  res.json({ ok: true, message: `Supporter ${req.params.supporterId} deleted` });
});

// Admin: search members
app.get('/api/admin/search-members', auth('admin'), async (req, res) => {
  const q = req.query.q || '';
  if (!q || q.length < 2) return res.json({ ok: true, members: [] });
  const regex = new RegExp(q, 'i');
  const members = await User.find({
    role: 'member',
    $or: [{ name: regex }, { member_id: regex }, { mobile: regex }, { email: regex }]
  }).sort({ created_at: -1 }).limit(20)
    .select('member_id name mobile email membership_active created_at wallet.points_balance').lean();
  const mapped = members.map(m => ({
    id: m._id, member_id: m.member_id, name: m.name, mobile: m.mobile, email: m.email,
    membership_active: m.membership_active, created_at: m.created_at,
    points_balance: m.wallet?.points_balance || 0
  }));
  res.json({ ok: true, members: mapped });
});

// Admin: get all donations (with stats)
app.get('/api/admin/donations', auth('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '', kyc = '' } = req.query;
    const skip = (Number(page) - 1) * Number(limit);

    // Stats
    const [totalCount, totalAmt, highValueCount, kycPending] = await Promise.all([
      Donation.countDocuments(),
      Donation.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]),
      Donation.countDocuments({ amount: { $gte: 50000 } }),
      Donation.countDocuments({ kyc_required: true, kyc_status: { $in: ['pending_docs', 'otp_verified'] } })
    ]);

    // Query
    const query = {};
    if (kyc) query.kyc_status = kyc;
    if (search) {
      query.$or = [
        { donor_name: { $regex: search, $options: 'i' } },
        { donor_email: { $regex: search, $options: 'i' } },
        { donor_mobile: { $regex: search, $options: 'i' } },
        { donor_pan: { $regex: search, $options: 'i' } },
        { donation_id: { $regex: search, $options: 'i' } },
        { payment_id: { $regex: search, $options: 'i' } }
      ];
    }

    const donations = await Donation.find(query)
      .sort({ created_at: -1 })
      .skip(skip)
      .limit(Number(limit))
      .lean();

    // Attach member display ID
    for (const d of donations) {
      if (d.member_id) {
        const u = await User.findById(d.member_id).select('name member_id').lean();
        if (u) { d.member_name = u.name; d.member_display_id = u.member_id; }
      }
    }

    res.json({
      ok: true,
      stats: {
        total:        totalCount,
        totalAmount:  totalAmt[0]?.total || 0,
        highValue:    highValueCount,
        kycPending:   kycPending
      },
      donations,
      total: totalCount
    });
  } catch (err) {
    captureError(err, { context: 'admin-donations' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: get single donation detail (KYC view)
app.get('/api/admin/donation/:donationId', auth('admin'), async (req, res) => {
  const d = await Donation.findOne({ donation_id: req.params.donationId }).lean();
  if (!d) return res.status(404).json({ error: 'Donation not found' });
  if (d.member_id) {
    const u = await User.findById(d.member_id).select('name member_id email mobile').lean();
    if (u) { d.member_name = u.name; d.member_display_id = u.member_id; }
  }
  res.json({ ok: true, donation: d });
});

// Admin: update donation KYC status / admin notes
app.post('/api/admin/donation-kyc/:donationId', auth('admin'), async (req, res) => {
  const { kyc_status, receipt_issued, admin_notes } = req.body;
  const update = {};
  if (kyc_status)  update.kyc_status = kyc_status;
  if (admin_notes !== undefined) update.admin_notes = admin_notes;
  if (receipt_issued !== undefined) update.receipt_issued = !!receipt_issued;
  await Donation.updateOne({ donation_id: req.params.donationId }, { $set: update });
  res.json({ ok: true, message: 'Donation updated' });
});

// Admin: delete donation
app.delete('/api/admin/donation/:donationId', auth('admin'), async (req, res) => {
  const result = await Donation.deleteOne({ donation_id: req.params.donationId });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Donation not found' });
  res.json({ ok: true, message: 'Donation deleted' });
});

// Admin: get all referrals
app.get('/api/admin/referrals', auth('admin'), async (req, res) => {
  const referrals = await Referral.find().sort({ created_at: -1 }).limit(50).lean();
  for (const r of referrals) {
    const referrer = await User.findById(r.referrer_id).select('name member_id').lean();
    const referred = await User.findById(r.referred_user_id).select('name member_id').lean();
    if (referrer) { r.referrer_name = referrer.name; r.referrer_member_id = referrer.member_id; }
    if (referred) { r.referred_name = referred.name; r.referred_member_id = referred.member_id; }
  }
  res.json({ ok: true, referrals });
});

// Admin: get all quiz tickets
app.get('/api/admin/tickets', auth('admin'), async (req, res) => {
  const tickets = await QuizTicket.find().sort({ sold_at: -1 }).limit(50).lean();
  for (const t of tickets) {
    const u = await User.findById(t.seller_id).select('name member_id').lean();
    if (u) { t.seller_name = u.name; t.seller_member_id = u.member_id; }
  }
  res.json({ ok: true, tickets });
});

// ===== SUPPORT TICKETS SYSTEM =====

async function nextTicketId() {
  const last = await SupportTicket.findOne().sort({ created_at: -1 }).select('ticket_id');
  let n = 0;
  if (last && last.ticket_id) {
    const m = last.ticket_id.match(/(\d+)$/);
    if (m) n = parseInt(m[1], 10);
  }
  return `FWF-TKT-${(n + 1).toString().padStart(4, '0')}`;
}

// Member: submit support ticket
app.post('/api/member/support-ticket', auth(['member','supporter']), async (req, res) => {
  const { subject, message, category } = req.body;
  if (!subject || !message) return res.status(400).json({ error: 'Subject and message required' });
  const u = await User.findById(req.user.uid).select('name email');
  const ticketId = await nextTicketId();
  await SupportTicket.create({
    ticket_id: ticketId, user_id: req.user.uid, user_name: u.name, user_email: u.email,
    subject, message, category: category || 'general'
  });
  res.json({ ok: true, ticketId, message: 'Support ticket submitted!' });
});

// Member: get my tickets
app.get('/api/member/support-tickets', auth(['member','supporter']), async (req, res) => {
  const tickets = await SupportTicket.find({ user_id: req.user.uid }).sort({ created_at: -1 }).lean();
  res.json({ ok: true, tickets });
});

// Admin: get all support tickets
app.get('/api/admin/support-tickets', auth('admin'), async (req, res) => {
  const tickets = await SupportTicket.find().sort({ status: 1, created_at: -1 }).lean();
  const [total, open, inProgress, resolved, closed] = await Promise.all([
    SupportTicket.countDocuments(),
    SupportTicket.countDocuments({ status: 'open' }),
    SupportTicket.countDocuments({ status: 'in-progress' }),
    SupportTicket.countDocuments({ status: 'resolved' }),
    SupportTicket.countDocuments({ status: 'closed' })
  ]);
  res.json({ ok: true, tickets, stats: { total, open, inProgress, resolved, closed } });
});

// Admin: reply to / update support ticket
app.post('/api/admin/support-ticket/:ticketId', auth('admin'), async (req, res) => {
  const { status, adminReply } = req.body;
  const update = { updated_at: new Date() };
  if (status) update.status = status;
  if (adminReply) { update.admin_reply = adminReply; update.replied_at = new Date(); }
  const result = await SupportTicket.updateOne({ ticket_id: req.params.ticketId }, update);
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Ticket not found' });
  res.json({ ok: true, message: 'Ticket updated' });
});

// ===== CSR PARTNERS SYSTEM =====

async function nextPartnerId() {
  return generateUniqueId('FWFC', 2, (id) =>
    CsrPartner.findOne({ partner_id: id }).lean().then(Boolean)
  );
}

// Admin: get all CSR partners
app.get('/api/admin/csr-partners', auth('admin'), async (req, res) => {
  const partners = await CsrPartner.find().sort({ created_at: -1 }).lean();
  const [total, active, leads] = await Promise.all([
    CsrPartner.countDocuments(),
    CsrPartner.countDocuments({ status: 'active' }),
    CsrPartner.countDocuments({ status: 'lead' })
  ]);
  const commitAgg = await CsrPartner.aggregate([{ $group: { _id: null, commitment: { $sum: '$commitment_amount' }, paid: { $sum: '$paid_amount' } } }]);
  const stats = {
    total, active, leads,
    totalCommitment: commitAgg[0]?.commitment || 0,
    totalPaid: commitAgg[0]?.paid || 0
  };
  res.json({ ok: true, partners, stats });
});

// Admin: add CSR partner
app.post('/api/admin/csr-partner', auth('admin'), async (req, res) => {
  const { companyName, contactPerson, email, phone, industry, partnershipType, commitmentAmount, notes } = req.body;
  if (!companyName) return res.status(400).json({ error: 'Company name required' });
  const partnerId = await nextPartnerId();
  await CsrPartner.create({
    partner_id: partnerId, company_name: companyName,
    contact_person: contactPerson || null, email: email || null, phone: phone || null,
    industry: industry || null, partnership_type: partnershipType || 'funding',
    commitment_amount: parseFloat(commitmentAmount) || 0, notes: notes || null
  });
  res.json({ ok: true, partnerId, message: 'CSR Partner added!' });
});

// Admin: update CSR partner
app.post('/api/admin/csr-partner/:partnerId', auth('admin'), async (req, res) => {
  const { status, paidAmount, notes, commitmentAmount, contactPerson, email, phone } = req.body;
  const update = { updated_at: new Date() };
  if (status) update.status = status;
  if (paidAmount !== undefined) update.paid_amount = parseFloat(paidAmount) || 0;
  if (notes !== undefined) update.notes = notes;
  if (commitmentAmount !== undefined) update.commitment_amount = parseFloat(commitmentAmount) || 0;
  if (contactPerson !== undefined) update.contact_person = contactPerson;
  if (email !== undefined) update.email = email;
  if (phone !== undefined) update.phone = phone;
  const result = await CsrPartner.updateOne({ partner_id: req.params.partnerId }, update);
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Partner not found' });
  res.json({ ok: true, message: 'Partner updated' });
});

// Admin: delete CSR partner
app.delete('/api/admin/csr-partner/:partnerId', auth('admin'), async (req, res) => {
  await CsrPartner.deleteOne({ partner_id: req.params.partnerId });
  res.json({ ok: true, message: 'Partner deleted' });
});

// ===== MEMBERSHIP FEE TRANSACTIONS =====

async function nextTxnId() {
  const last = await MembershipFee.findOne().sort({ created_at: -1 }).select('txn_id');
  let n = 0;
  if (last && last.txn_id) {
    const m = last.txn_id.match(/(\d+)$/);
    if (m) n = parseInt(m[1], 10);
  }
  return `FWF-TXN-${(n + 1).toString().padStart(5, '0')}`;
}

// Admin: get all membership fee transactions
app.get('/api/admin/membership-fees', auth('admin'), async (req, res) => {
  const fees = await MembershipFee.find().sort({ created_at: -1 }).lean();
  const [total, pending, verified, rejected] = await Promise.all([
    MembershipFee.countDocuments(),
    MembershipFee.countDocuments({ status: 'pending' }),
    MembershipFee.countDocuments({ status: 'verified' }),
    MembershipFee.countDocuments({ status: 'rejected' })
  ]);
  const amtAgg = await MembershipFee.aggregate([
    { $group: { _id: '$status', total: { $sum: '$amount' } } }
  ]);
  const totalAmount = amtAgg.find(a => a._id === 'verified')?.total || 0;
  const pendingAmount = amtAgg.find(a => a._id === 'pending')?.total || 0;
  res.json({ ok: true, fees, stats: { total, pending, verified, rejected, totalAmount, pendingAmount } });
});

// Admin: add membership fee record
app.post('/api/admin/membership-fee', auth('admin'), async (req, res) => {
  const { memberId, amount, feeType, paymentMode, paymentRef, status, notes } = req.body;
  if (!memberId || !amount) return res.status(400).json({ error: 'Member ID and amount required' });
  const u = await User.findOne({ member_id: memberId }).select('name');
  if (!u) return res.status(404).json({ error: 'Member not found' });

  const txnId = await nextTxnId();
  const finalStatus = status || 'pending';
  await MembershipFee.create({
    txn_id: txnId, member_id: memberId, user_id: u._id, member_name: u.name,
    amount: parseFloat(amount), fee_type: feeType || 'joining',
    payment_mode: paymentMode || 'online', payment_ref: paymentRef || null,
    status: finalStatus, notes: notes || null,
    ...(finalStatus === 'verified' ? { verified_by: req.user.name || 'Admin', verified_at: new Date() } : {})
  });

  if (finalStatus === 'verified') {
    await User.updateOne({ _id: u._id }, { membership_active: true });
  }

  res.json({ ok: true, txnId, message: 'Fee record added!' });
});

// Admin: update fee status
app.post('/api/admin/membership-fee/:txnId', auth('admin'), async (req, res) => {
  const { status, notes, paymentRef } = req.body;
  const f = await MembershipFee.findOne({ txn_id: req.params.txnId });
  if (!f) return res.status(404).json({ error: 'Transaction not found' });

  const update = { updated_at: new Date() };
  if (status) {
    update.status = status;
    if (status === 'verified') {
      update.verified_by = req.user.name || 'Admin';
      update.verified_at = new Date();
      if (f.user_id) await User.updateOne({ _id: f.user_id }, { membership_active: true });
    }
    if ((status === 'rejected' || status === 'refunded') && f.user_id && f.fee_type === 'joining') {
      await User.updateOne({ _id: f.user_id }, { membership_active: false });
    }
  }
  if (notes !== undefined) update.notes = notes;
  if (paymentRef !== undefined) update.payment_ref = paymentRef;

  await MembershipFee.updateOne({ txn_id: req.params.txnId }, update);
  res.json({ ok: true, message: 'Transaction updated' });
});

// Admin: get fees for specific member
app.get('/api/admin/membership-fees/:memberId', auth('admin'), async (req, res) => {
  const fees = await MembershipFee.find({ member_id: req.params.memberId }).sort({ created_at: -1 }).lean();
  res.json({ ok: true, fees });
});

// ===== MARKETPLACE / PRODUCTS SYSTEM =====

const PRODUCT_CATEGORIES = {
  'electronics': { label: 'Electronics', icon: 'fa-laptop', subs: ['Mobile Phones', 'Laptops', 'Tablets', 'Cameras', 'Headphones', 'Speakers', 'Smartwatches', 'Accessories', 'Chargers & Cables', 'Power Banks'] },
  'fashion-women': { label: "Women's Fashion", icon: 'fa-person-dress', subs: ['Sarees', 'Kurtis & Kurtas', 'Dress Materials', 'Lehengas', 'Tops & T-Shirts', 'Jeans & Pants', 'Dupatta', 'Jewellery', 'Footwear', 'Bags & Clutches'] },
  'fashion-men': { label: "Men's Fashion", icon: 'fa-shirt', subs: ['Shirts', 'T-Shirts', 'Kurtas', 'Jeans & Trousers', 'Shoes', 'Wallets', 'Belts', 'Caps & Hats'] },
  'home-kitchen': { label: 'Home & Kitchen', icon: 'fa-house', subs: ['Cookware', 'Storage & Containers', 'Kitchen Tools', 'Dinnerware', 'Home Decor', 'Bedsheets & Curtains', 'Cleaning Supplies', 'Pooja Items', 'Handloom Textiles'] },
  'beauty-health': { label: 'Beauty & Health', icon: 'fa-spa', subs: ['Skincare', 'Haircare', 'Makeup', 'Perfumes', 'Ayurvedic Products', 'Essential Oils', 'Herbal Supplements', 'Personal Care'] },
  'handicraft': { label: 'Handicraft & Art', icon: 'fa-palette', subs: ['Madhubani Painting', 'Pottery', 'Bamboo Craft', 'Jute Products', 'Embroidery', 'Wood Carving', 'Metal Art', 'Handloom', 'Paper Craft', 'Block Print'] },
  'organic-natural': { label: 'Organic & Natural', icon: 'fa-leaf', subs: ['Organic Honey', 'Organic Spices', 'Herbal Tea', 'Cold-Pressed Oil', 'Natural Soaps', 'Incense Sticks', 'Dry Fruits', 'Organic Grains'] },
  'food-beverages': { label: 'Food & Beverages', icon: 'fa-utensils', subs: ['Pickles & Chutneys', 'Sweets & Namkeen', 'Papad & Chips', 'Jams & Preserves', 'Ready to Cook', 'Beverages', 'Masalas'] },
  'books-stationery': { label: 'Books & Stationery', icon: 'fa-book', subs: ['Books', 'Notebooks', 'Handmade Paper', 'Art Supplies', 'Office Supplies'] },
  'toys-kids': { label: 'Toys & Kids', icon: 'fa-baby', subs: ['Wooden Toys', 'Educational Toys', 'Kids Clothing', 'School Bags', 'Baby Care'] },
  'agriculture': { label: 'Agriculture & Garden', icon: 'fa-seedling', subs: ['Seeds', 'Fertilizers', 'Garden Tools', 'Plants & Saplings', 'Organic Compost', 'Farm Equipment'] },
  'services': { label: 'Services', icon: 'fa-hands-helping', subs: ['Tailoring', 'Mehendi', 'Beauty Services', 'Home Repair', 'Tutoring', 'Cooking Classes'] }
};

async function nextProductId() {
  const last = await Product.findOne().sort({ created_at: -1 }).select('product_id');
  let n = 0;
  if (last && last.product_id) {
    const m = last.product_id.match(/(\d+)$/);
    if (m) n = parseInt(m[1], 10);
  }
  return `PROD-${(n + 1).toString().padStart(5, '0')}`;
}

async function nextOrderId() {
  const last = await Order.findOne().sort({ created_at: -1 }).select('order_id');
  let n = 0;
  if (last && last.order_id) {
    const m = last.order_id.match(/(\d+)$/);
    if (m) n = parseInt(m[1], 10);
  }
  return `ORD-${(n + 1).toString().padStart(5, '0')}`;
}

// Image validation
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const MAX_IMAGE_SIZE = 5 * 1024 * 1024;
const MAX_IMAGES = 8;

function validateImage(base64Str) {
  if (!base64Str) return { valid: false, error: 'No image data' };
  const match = base64Str.match(/^data:(image\/[a-z+]+);base64,/i);
  if (!match) return { valid: false, error: 'Invalid image format' };
  const mimeType = match[1].toLowerCase();
  if (!ALLOWED_IMAGE_TYPES.includes(mimeType)) return { valid: false, error: `File type ${mimeType} not allowed. Use JPEG, PNG, WebP, or GIF.` };
  const base64Data = base64Str.replace(/^data:image\/[a-z+]+;base64,/i, '');
  const sizeBytes = Math.ceil(base64Data.length * 3 / 4);
  if (sizeBytes > MAX_IMAGE_SIZE) return { valid: false, error: `Image too large (${(sizeBytes / 1024 / 1024).toFixed(1)}MB). Max 5MB.` };
  const decodedSample = Buffer.from(base64Data.substring(0, 200), 'base64').toString('utf8');
  if (/<script|javascript:|onerror|onload|eval\(/i.test(decodedSample)) return { valid: false, error: 'Image contains suspicious content' };
  const bytes = Buffer.from(base64Data.substring(0, 12), 'base64');
  const isJPEG = bytes[0] === 0xFF && bytes[1] === 0xD8;
  const isPNG = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47;
  const isGIF = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46;
  const isWEBP = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46;
  if (!isJPEG && !isPNG && !isGIF && !isWEBP) return { valid: false, error: 'Image file signature mismatch.' };
  return { valid: true, mimeType, sizeBytes };
}

// GET categories
app.get('/api/store/categories', (req, res) => {
  res.json({ ok: true, categories: PRODUCT_CATEGORIES });
});

// GET all approved products (public store)
app.get('/api/store/products', async (req, res) => {
  const { category, subcategory, search, sort, page: pg, limit: lim } = req.query;
  const filter = { status: 'approved' };
  if (category) filter.category = category;
  if (subcategory) filter.subcategory = subcategory;
  if (search) {
    const regex = new RegExp(search, 'i');
    filter.$or = [{ title: regex }, { description: regex }, { tags: regex }, { brand: regex }];
  }

  let sortOpt = { featured: -1, created_at: -1 };
  if (sort === 'price-low') sortOpt = { price: 1 };
  else if (sort === 'price-high') sortOpt = { price: -1 };
  else if (sort === 'rating') sortOpt = { rating_avg: -1 };
  else if (sort === 'popular') sortOpt = { total_sold: -1 };
  else if (sort === 'newest') sortOpt = { created_at: -1 };

  const page = parseInt(pg) || 1;
  const limit = Math.min(parseInt(lim) || 24, 100);
  const skip = (page - 1) * limit;

  const [products, total, catStats] = await Promise.all([
    Product.find(filter).sort(sortOpt).skip(skip).limit(limit)
      .select('product_id title description category subcategory brand price mrp discount_percent stock unit images thumbnail condition rating_avg rating_count total_sold seller_name seller_member_id created_at').lean(),
    Product.countDocuments(filter),
    Product.aggregate([{ $match: { status: 'approved' } }, { $group: { _id: '$category', count: { $sum: 1 } } }])
  ]);

  const categoryStats = catStats.map(c => ({ category: c._id, count: c.count }));

  res.json({ ok: true, products, total, page, limit, pages: Math.ceil(total / limit), categoryStats });
});

// GET single product
app.get('/api/store/product/:productId', async (req, res) => {
  const p = await Product.findOne({ product_id: req.params.productId, status: 'approved' }).lean();
  if (!p) return res.status(404).json({ error: 'Product not found' });
  await Product.updateOne({ product_id: req.params.productId }, { $inc: { views: 1 } });
  res.json({ ok: true, product: p });
});

// Member: add product
app.post('/api/member/add-product', auth('member'), async (req, res) => {
  const { title, description, category, subcategory, brand, price, mrp, stock, unit, weight, dimensions, material, color, size, tags, images, condition } = req.body;
  if (!title || !price || !category) return res.status(400).json({ error: 'Title, price, and category required' });

  let validatedImages = [];
  if (images && Array.isArray(images)) {
    if (images.length > MAX_IMAGES) return res.status(400).json({ error: `Maximum ${MAX_IMAGES} images allowed` });
    for (let i = 0; i < images.length; i++) {
      const result = validateImage(images[i]);
      if (!result.valid) return res.status(400).json({ error: `Image ${i + 1}: ${result.error}` });
      validatedImages.push(images[i]);
    }
  }

  const u = await User.findById(req.user.uid).select('name member_id');
  const productId = await nextProductId();
  const discountPct = mrp && mrp > price ? Math.round(((mrp - price) / mrp) * 100) : 0;

  await Product.create({
    product_id: productId, seller_user_id: req.user.uid, seller_name: u.name, seller_member_id: u.member_id,
    title, description: description || null, category, subcategory: subcategory || null,
    brand: brand || null, price: parseFloat(price), mrp: parseFloat(mrp) || null,
    discount_percent: discountPct, stock: parseInt(stock) || 1, unit: unit || 'piece',
    weight: weight || null, dimensions: dimensions || null, material: material || null,
    color: color || null, size: size || null, tags: tags || null,
    images: validatedImages, thumbnail: validatedImages[0] || null, condition: condition || 'new'
  });

  res.json({ ok: true, productId, message: 'Product submitted for approval!' });
});

// Member: get my products
app.get('/api/member/my-products', auth('member'), async (req, res) => {
  const products = await Product.find({ seller_user_id: req.user.uid }).sort({ created_at: -1 }).lean();
  const stats = {
    total: products.length,
    approved: products.filter(p => p.status === 'approved').length,
    pending: products.filter(p => p.status === 'pending').length,
    totalSold: products.reduce((s, p) => s + (p.total_sold || 0), 0)
  };
  res.json({ ok: true, products, stats });
});

// Member: update own product
app.post('/api/member/update-product/:productId', auth('member'), async (req, res) => {
  const p = await Product.findOne({ product_id: req.params.productId, seller_user_id: req.user.uid });
  if (!p) return res.status(404).json({ error: 'Product not found or not yours' });

  const { title, description, category, subcategory, brand, price, mrp, stock, unit, weight, dimensions, material, color, size, tags, images, condition } = req.body;
  const update = { updated_at: new Date(), status: 'pending' };

  if (images && Array.isArray(images)) {
    if (images.length > MAX_IMAGES) return res.status(400).json({ error: `Maximum ${MAX_IMAGES} images allowed` });
    let validatedImages = [];
    for (let i = 0; i < images.length; i++) {
      const result = validateImage(images[i]);
      if (!result.valid) return res.status(400).json({ error: `Image ${i + 1}: ${result.error}` });
      validatedImages.push(images[i]);
    }
    update.images = validatedImages;
    update.thumbnail = validatedImages[0] || null;
  }

  if (title) update.title = title;
  if (description !== undefined) update.description = description;
  if (category) update.category = category;
  if (subcategory !== undefined) update.subcategory = subcategory;
  if (brand !== undefined) update.brand = brand;
  if (price) update.price = parseFloat(price);
  if (mrp !== undefined) update.mrp = parseFloat(mrp) || null;
  if (stock !== undefined) update.stock = parseInt(stock) || 0;
  if (condition) update.condition = condition;
  if (tags !== undefined) update.tags = tags;

  await Product.updateOne({ product_id: req.params.productId }, update);
  res.json({ ok: true, message: 'Product updated & sent for re-approval' });
});

// Member: delete own product
app.delete('/api/member/product/:productId', auth('member'), async (req, res) => {
  await Product.deleteOne({ product_id: req.params.productId, seller_user_id: req.user.uid });
  res.json({ ok: true, message: 'Product deleted' });
});

// Place order
app.post('/api/store/order', async (req, res) => {
  const { productId, quantity, buyerName, buyerContact, buyerEmail, buyerAddress, paymentMode } = req.body;
  if (!productId || !buyerName || !buyerContact) return res.status(400).json({ error: 'Product, name & contact required' });
  const p = await Product.findOne({ product_id: productId, status: 'approved' });
  if (!p) return res.status(404).json({ error: 'Product not found or unavailable' });
  const qty = parseInt(quantity) || 1;
  if (p.stock < qty) return res.status(400).json({ error: 'Insufficient stock' });

  const total = p.price * qty;
  const orderId = await nextOrderId();

  await Order.create({
    order_id: orderId, product_id: productId, product_title: p.title,
    buyer_name: buyerName, buyer_contact: buyerContact,
    buyer_email: buyerEmail || null, buyer_address: buyerAddress || null,
    seller_user_id: p.seller_user_id, seller_member_id: p.seller_member_id,
    quantity: qty, unit_price: p.price, total_amount: total,
    payment_mode: paymentMode || 'online'
  });

  p.stock -= qty;
  p.total_sold += qty;
  if (p.stock <= 0) p.status = 'out-of-stock';
  await p.save();

  res.json({ ok: true, orderId, total, message: 'Order placed successfully!' });
});

// Member: seller orders
app.get('/api/member/seller-orders', auth('member'), async (req, res) => {
  const orders = await Order.find({ seller_user_id: req.user.uid }).sort({ created_at: -1 }).lean();
  const stats = {
    total: orders.length,
    pending: orders.filter(o => o.status === 'pending').length,
    totalEarnings: orders.filter(o => ['confirmed', 'processing', 'shipped', 'delivered'].includes(o.status))
      .reduce((s, o) => s + (o.total_amount || 0), 0)
  };
  res.json({ ok: true, orders, stats });
});

// Admin: all products
app.get('/api/admin/products', auth('admin'), async (req, res) => {
  const products = await Product.find().sort({ status: 1, created_at: -1 }).lean();
  const stats = {
    total: products.length,
    pending: products.filter(p => p.status === 'pending').length,
    approved: products.filter(p => p.status === 'approved').length,
    rejected: products.filter(p => p.status === 'rejected').length,
    sellers: new Set(products.map(p => p.seller_user_id?.toString())).size
  };
  res.json({ ok: true, products, stats });
});

// Admin: approve/reject product
app.post('/api/admin/product/:productId', auth('admin'), async (req, res) => {
  const { status, adminNotes, featured } = req.body;
  const update = { updated_at: new Date() };
  if (status) update.status = status;
  if (adminNotes !== undefined) update.admin_notes = adminNotes;
  if (featured !== undefined) update.featured = featured ? true : false;
  const result = await Product.updateOne({ product_id: req.params.productId }, update);
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Product not found' });
  res.json({ ok: true, message: 'Product updated' });
});

// Admin: all orders
app.get('/api/admin/orders', auth('admin'), async (req, res) => {
  const orders = await Order.find().sort({ created_at: -1 }).lean();
  const stats = {
    total: orders.length,
    pending: orders.filter(o => o.status === 'pending').length,
    totalRevenue: orders.filter(o => ['delivered', 'confirmed', 'processing', 'shipped'].includes(o.status))
      .reduce((s, o) => s + (o.total_amount || 0), 0)
  };
  res.json({ ok: true, orders, stats });
});

// Admin: update order status
app.post('/api/admin/order/:orderId', auth('admin'), async (req, res) => {
  const { status, trackingInfo, notes } = req.body;
  const update = { updated_at: new Date() };
  if (status) update.status = status;
  if (trackingInfo !== undefined) update.tracking_info = trackingInfo;
  if (notes !== undefined) update.notes = notes;
  const result = await Order.updateOne({ order_id: req.params.orderId }, update);
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Order not found' });
  res.json({ ok: true, message: 'Order updated' });
});

// ========================
// SOCIAL TASKS APIs
// ========================

// Get current week's task + completion status
app.get('/api/member/weekly-task', auth(['member','supporter']), async (req, res) => {
  try {
    // Calculate current week (1-10 repeating cycle)
    const now = new Date();
    const startOfYear = new Date(now.getFullYear(), 0, 1);
    const weekOfYear = Math.ceil(((now - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);
    const cycleWeek = ((weekOfYear - 1) % 10) + 1; // 1-10 repeating
    const yearWeek = `${now.getFullYear()}-W${String(weekOfYear).padStart(2, '0')}`;

    const task = await SocialTask.findOne({ week_number: cycleWeek, is_active: true }).lean();
    if (!task) return res.json({ ok: true, task: null, message: 'इस हफ्ते कोई task नहीं है' });

    // Check if user already completed this week
    const completion = await TaskCompletion.findOne({ user_id: req.user.uid, year_week: yearWeek }).lean();

    res.json({
      ok: true,
      task,
      cycleWeek,
      yearWeek,
      completed: !!completion,
      completion: completion || null
    });
  } catch (err) {
    captureError(err, { context: 'weekly-task' });
    res.status(500).json({ error: 'Failed to fetch weekly task' });
  }
});

// Get all 10 tasks
app.get('/api/member/all-tasks', auth(['member','supporter']), async (req, res) => {
  try {
    const tasks = await SocialTask.find({ is_active: true }).sort({ week_number: 1 }).lean();
    // Get user's completions
    const completions = await TaskCompletion.find({ user_id: req.user.uid })
      .sort({ completed_at: -1 }).lean();
    res.json({ ok: true, tasks, completions });
  } catch (err) {
    captureError(err, { context: 'all-tasks' });
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Complete a task (with photo upload)
app.post('/api/member/complete-task', auth(['member','supporter']), async (req, res) => {
  try {
    const { task_id, photo_url, latitude, longitude, location_address } = req.body;
    if (!task_id || !photo_url) return res.status(400).json({ error: 'task_id और photo_url ज़रूरी है' });

    const task = await SocialTask.findOne({ task_id, is_active: true });
    if (!task) return res.status(404).json({ error: 'Task नहीं मिला' });

    // Calculate year_week
    const now = new Date();
    const startOfYear = new Date(now.getFullYear(), 0, 1);
    const weekOfYear = Math.ceil(((now - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);
    const yearWeek = `${now.getFullYear()}-W${String(weekOfYear).padStart(2, '0')}`;

    // Check if already completed this specific task
    const existing = await TaskCompletion.findOne({ user_id: req.user.uid, task_id });
    if (existing) return res.status(400).json({ error: 'यह task पहले ही पूरा हो चुका है!' });

    const user = await User.findById(req.user.uid).select('member_id name avatar_url').lean();

    // Create social post automatically
    const post = await SocialPost.create({
      user_id: req.user.uid,
      member_id: user.member_id,
      user_name: user.name,
      user_avatar: user.avatar_url,
      post_type: 'task_completion',
      content: `✅ ${task.title} — ${task.description}`,
      images: [photo_url],
      location: { latitude, longitude, address: location_address },
      is_auto_generated: true
    });

    // Create completion record
    const completion = await TaskCompletion.create({
      user_id: req.user.uid,
      member_id: user.member_id,
      task_id,
      week_number: task.week_number,
      year_week: yearWeek,
      photo_url,
      latitude,
      longitude,
      location_address,
      points_earned: task.points_reward,
      social_post_id: post._id
    });

    // Award points
    await User.updateOne({ _id: req.user.uid }, {
      $inc: {
        'wallet.points_balance': task.points_reward,
        'wallet.points_from_social_tasks': task.points_reward,
        'wallet.total_points_earned': task.points_reward
      },
      'wallet.updated_at': new Date()
    });

    await PointsLedger.create({
      user_id: req.user.uid,
      points: task.points_reward,
      type: 'social_task',
      description: `${task.title} पूरा किया → ${task.points_reward} points`,
      reference_id: completion._id
    });

    addBreadcrumb('social-task', 'Task completed', { memberId: user.member_id, taskId: task_id });
    res.json({
      ok: true,
      points: task.points_reward,
      message: `🎉 बधाई! Task पूरा हुआ — ${task.points_reward} points मिले!`,
      completion,
      post
    });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'यह task पहले ही पूरा हो चुका है!' });
    captureError(err, { context: 'complete-task' });
    res.status(500).json({ error: 'Task पूरा करने में error: ' + err.message });
  }
});

// Get task completion history
app.get('/api/member/task-history', auth(['member','supporter']), async (req, res) => {
  try {
    const completions = await TaskCompletion.find({ user_id: req.user.uid })
      .sort({ completed_at: -1 }).limit(50).lean();
    const totalPoints = completions.reduce((s, c) => s + (c.points_earned || 0), 0);
    res.json({ ok: true, completions, totalTasks: completions.length, totalPoints });
  } catch (err) {
    captureError(err, { context: 'task-history' });
    res.status(500).json({ error: 'History fetch failed' });
  }
});

// ========================
// SOCIAL POSTS / FEED APIs
// ========================

// Get social feed
app.get('/api/member/feed', auth(['member','supporter']), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const posts = await SocialPost.find({ status: 'active' })
      .sort({ created_at: -1 }).skip(skip).limit(limit).lean();

    const total = await SocialPost.countDocuments({ status: 'active' });
    res.json({ ok: true, posts, total, page, hasMore: skip + posts.length < total });
  } catch (err) {
    captureError(err, { context: 'social-feed' });
    res.status(500).json({ error: 'Feed load failed' });
  }
});

// Create a social post
app.post('/api/member/create-post', auth(['member','supporter']), async (req, res) => {
  try {
    const { content, images, post_type, location } = req.body;
    if (!content) return res.status(400).json({ error: 'Post content required' });

    const user = await User.findById(req.user.uid).select('member_id name avatar_url').lean();
    const post = await SocialPost.create({
      user_id: req.user.uid,
      member_id: user.member_id,
      user_name: user.name,
      user_avatar: user.avatar_url,
      post_type: post_type || 'other',
      content,
      images: images || [],
      location: location || {},
      status: 'pending'  // requires admin approval before appearing in feed
    });

    res.json({ ok: true, post });
  } catch (err) {
    captureError(err, { context: 'create-post' });
    res.status(500).json({ error: 'Post creation failed' });
  }
});

// Like/unlike a post
app.post('/api/member/like-post', auth('member'), async (req, res) => {
  try {
    const { postId } = req.body;
    const post = await SocialPost.findById(postId);
    if (!post) return res.status(404).json({ error: 'Post not found' });

    const userId = new mongoose.Types.ObjectId(req.user.uid);
    const alreadyLiked = post.likes.some(id => id.equals(userId));

    if (alreadyLiked) {
      post.likes.pull(userId);
      post.likes_count = Math.max(0, post.likes_count - 1);
    } else {
      post.likes.push(userId);
      post.likes_count += 1;
    }
    await post.save();

    res.json({ ok: true, liked: !alreadyLiked, likes_count: post.likes_count });
  } catch (err) {
    captureError(err, { context: 'like-post' });
    res.status(500).json({ error: 'Like failed' });
  }
});

// ========================
// QUIZ / FUND RAISER APIs
// ========================

// Get active quizzes
app.get('/api/member/active-quizzes', auth(['member','supporter']), async (req, res) => {
  try {
    const quizzes = await Quiz.find({ status: { $in: ['upcoming', 'active'] } })
      .sort({ start_date: 1 })
      .select('-questions') // Don't send questions yet
      .lean();

    // Check user's participation for each quiz
    const participations = await QuizParticipation.find({
      user_id: req.user.uid,
      quiz_ref: { $in: quizzes.map(q => q.quiz_id) }
    }).lean();

    const participationMap = {};
    participations.forEach(p => { participationMap[p.quiz_ref] = p; });

    const result = quizzes.map(q => ({
      ...q,
      enrolled: !!participationMap[q.quiz_id],
      enrollment: participationMap[q.quiz_id] || null
    }));

    res.json({ ok: true, quizzes: result });
  } catch (err) {
    captureError(err, { context: 'active-quizzes' });
    res.status(500).json({ error: 'Failed to fetch quizzes' });
  }
});

// Enroll in quiz (after Razorpay payment)
app.post('/api/member/quiz-enroll', auth(['member','supporter']), async (req, res) => {
  try {
    const { quiz_id, razorpay_payment_id, razorpay_order_id, razorpay_signature, referred_by } = req.body;
    if (!quiz_id || !razorpay_payment_id) return res.status(400).json({ error: 'Quiz ID and payment required' });

    const quiz = await Quiz.findOne({ quiz_id, status: { $in: ['upcoming', 'active'] } });
    if (!quiz) return res.status(404).json({ error: 'Quiz नहीं मिला या enrollment बंद है' });

    // Verify payment signature
    if (razorpay_order_id && razorpay_signature) {
      const keySecret = process.env.RAZORPAY_KEY_SECRET;
      const generated = crypto.createHmac('sha256', keySecret)
        .update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
      if (generated !== razorpay_signature) {
        return res.status(400).json({ error: 'Payment verification failed' });
      }
    }

    // Check duplicate enrollment
    const existing = await QuizParticipation.findOne({ quiz_id: quiz._id, user_id: req.user.uid });
    if (existing) return res.status(400).json({ error: 'आप पहले ही enrolled हैं!', enrollment: existing.enrollment_number });

    const user = await User.findById(req.user.uid).select('member_id name').lean();

    // Generate enrollment number: FWF-{quizId}-{5 random digits}
    const randomDigits = Math.floor(10000 + Math.random() * 90000);
    const enrollmentNumber = `FWF-${quiz.quiz_id}-${randomDigits}`;

    // Find referrer
    let referrerId = null;
    if (referred_by) {
      const referrer = await User.findOne({ referral_code: referred_by }).select('_id').lean();
      if (referrer) referrerId = referrer._id;
    }

    const participation = await QuizParticipation.create({
      quiz_id: quiz._id,
      quiz_ref: quiz.quiz_id,
      user_id: req.user.uid,
      member_id: user.member_id,
      name: user.name,
      enrollment_number: enrollmentNumber,
      payment_id: razorpay_payment_id,
      amount_paid: quiz.entry_fee,
      referred_by: referred_by || null,
      referrer_id: referrerId
    });

    // Update quiz stats
    await Quiz.updateOne({ _id: quiz._id }, {
      $inc: { total_participants: 1, total_collection: quiz.entry_fee }
    });

    // Award referral points if referred (10% for quiz referrals)
    if (referrerId) {
      const refPoints = amountToPoints(quiz.entry_fee * (QUIZ_TICKET_POINTS_PERCENT / 100));
      await User.updateOne({ _id: referrerId }, {
        $inc: {
          'wallet.points_balance': refPoints,
          'wallet.points_from_referrals': refPoints,
          'wallet.total_points_earned': refPoints
        },
        'wallet.updated_at': new Date()
      });
      await PointsLedger.create({
        user_id: referrerId, points: refPoints, type: 'referral',
        description: `Quiz referral — ${user.name} enrolled in ${quiz.title} → ${refPoints} points`
      });
      // Record referral click conversion
      await ReferralClick.updateOne(
        { referral_code: referred_by, converted: false },
        { converted: true, converted_user_id: req.user.uid, conversion_type: 'quiz_enrollment', conversion_amount: quiz.entry_fee },
        { sort: { created_at: -1 } }
      );
    }

    // Award quiz participation points (10% of entry fee)
    const quizPoints = amountToPoints(quiz.entry_fee * (QUIZ_TICKET_POINTS_PERCENT / 100));
    if (quizPoints > 0) {
      await User.updateOne({ _id: req.user.uid }, {
        $inc: {
          'wallet.points_balance': quizPoints,
          'wallet.points_from_quiz': quizPoints,
          'wallet.total_points_earned': quizPoints
        },
        'wallet.updated_at': new Date()
      });
      await PointsLedger.create({
        user_id: req.user.uid, points: quizPoints, type: 'quiz',
        description: `${quiz.title} enrollment → ${quizPoints} points`,
        reference_id: participation._id
      });
    }

    addBreadcrumb('quiz', 'Quiz enrollment', { memberId: user.member_id, quizId: quiz.quiz_id, enrollment: enrollmentNumber });

    // Non-blocking SMS confirmation
    const enrolledUser = await User.findById(req.user.uid).select('mobile').lean();
    if (enrolledUser?.mobile) {
      sendQuizParticipationSms({ mobile: enrolledUser.mobile, name: user.name, quizId: quiz.quiz_id })
        .catch(e => console.error('\u26a0\ufe0f Quiz participation SMS failed:', e.message));
    }

    res.json({
      ok: true,
      enrollment_number: enrollmentNumber,
      quiz_title: quiz.title,
      points_earned: quizPoints,
      message: `🎉 Enrollment successful! आपका नंबर: ${enrollmentNumber}`
    });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'आप पहले ही इस quiz में enrolled हैं!' });
    captureError(err, { context: 'quiz-enroll' });
    res.status(500).json({ error: 'Enrollment failed: ' + err.message });
  }
});

// Get quiz questions (only if enrolled and quiz is active)
app.get('/api/member/quiz-questions/:quizId', auth(['member','supporter']), async (req, res) => {
  try {
    const quiz = await Quiz.findOne({ quiz_id: req.params.quizId, status: 'active' });
    if (!quiz) return res.status(404).json({ error: 'Quiz active नहीं है' });

    const participation = await QuizParticipation.findOne({ quiz_id: quiz._id, user_id: req.user.uid });
    if (!participation) return res.status(403).json({ error: 'पहले enroll करें' });
    if (participation.quiz_submitted) return res.status(400).json({ error: 'Quiz पहले ही submit हो चुका है' });

    // Send questions without correct answers
    const questions = quiz.questions.map(q => ({
      q_no: q.q_no,
      question: q.question,
      options: q.options
    }));

    res.json({ ok: true, questions, quizTitle: quiz.title, gameType: quiz.game_type || 'mcq', enrollmentNumber: participation.enrollment_number });
  } catch (err) {
    captureError(err, { context: 'quiz-questions' });
    res.status(500).json({ error: 'Failed to fetch questions' });
  }
});

// Submit quiz answers
app.post('/api/member/quiz-submit', auth(['member','supporter']), async (req, res) => {
  try {
    const { quiz_id, answers } = req.body;
    if (!quiz_id || !answers) return res.status(400).json({ error: 'quiz_id and answers required' });

    const quiz = await Quiz.findOne({ quiz_id, status: 'active' });
    if (!quiz) return res.status(404).json({ error: 'Quiz active नहीं है' });

    const participation = await QuizParticipation.findOne({ quiz_id: quiz._id, user_id: req.user.uid });
    if (!participation) return res.status(403).json({ error: 'पहले enroll करें' });
    if (participation.quiz_submitted) return res.status(400).json({ error: 'Quiz पहले ही submit हो चुका है' });

    // Score the answers
    let score = 0;
    const scoredAnswers = answers.map(ans => {
      const q = quiz.questions.find(qq => qq.q_no === ans.q_no);
      const isCorrect = q && q.correct_answer === ans.selected;
      if (isCorrect) score += (q.points || 1);
      return { q_no: ans.q_no, selected: ans.selected, is_correct: isCorrect };
    });

    participation.answers = scoredAnswers;
    participation.score = score;
    participation.quiz_submitted = true;
    participation.submitted_at = new Date();
    participation.status = 'submitted';
    await participation.save();

    const totalQ = quiz.questions.length;
    const passed = score === totalQ;
    res.json({
      ok: true,
      score,
      totalQuestions: totalQ,
      passed,
      enrollment_number: participation.enrollment_number,
      result_date: quiz.result_date,
      quiz_title: quiz.title,
      message: passed
        ? `🎉 शानदार! सभी ${totalQ} जवाब सही हैं! Result ${quiz.result_date.toLocaleDateString('hi-IN')} को आएगा।`
        : `Quiz submit हो गया! Score: ${score}/${totalQ}. Result ${quiz.result_date.toLocaleDateString('hi-IN')} को आएगा।`
    });
  } catch (err) {
    captureError(err, { context: 'quiz-submit' });
    res.status(500).json({ error: 'Quiz submit failed' });
  }
});

// Quiz history for user
app.get('/api/member/quiz-history', auth(['member','supporter']), async (req, res) => {
  try {
    const participations = await QuizParticipation.find({ user_id: req.user.uid })
      .sort({ created_at: -1 }).lean();

    // Enrich with quiz details
    for (const p of participations) {
      const quiz = await Quiz.findById(p.quiz_id).select('title type entry_fee result_date status prizes').lean();
      if (quiz) p.quiz_details = quiz;
    }

    res.json({ ok: true, participations });
  } catch (err) {
    captureError(err, { context: 'quiz-history' });
    res.status(500).json({ error: 'History fetch failed' });
  }
});

// Quiz results (after result_declared)
app.get('/api/member/quiz-results/:quizId', auth('member'), async (req, res) => {
  try {
    const quiz = await Quiz.findOne({ quiz_id: req.params.quizId, status: 'result_declared' })
      .select('quiz_id title type winners result_date prizes total_participants total_collection').lean();
    if (!quiz) return res.status(404).json({ error: 'Results not declared yet' });

    const myEntry = await QuizParticipation.findOne({
      quiz_ref: req.params.quizId, user_id: req.user.uid
    }).lean();

    res.json({ ok: true, quiz, myEntry });
  } catch (err) {
    captureError(err, { context: 'quiz-results' });
    res.status(500).json({ error: 'Results fetch failed' });
  }
});

// ========================
// QUIZ SELL TICKET APIs
// ========================

// Generate sell ticket link (member sells to a buyer)
app.post('/api/member/quiz/generate-ticket', auth(['member','supporter']), async (req, res) => {
  try {
    const { quiz_id, buyer_name, buyer_contact, buyer_email } = req.body;
    if (!quiz_id || !buyer_name || !buyer_contact) {
      return res.status(400).json({ error: 'quiz_id, buyer_name, buyer_contact required' });
    }

    const quiz = await Quiz.findOne({ quiz_id, status: { $in: ['upcoming', 'active'] } })
      .select('quiz_id title type entry_fee end_date result_date prizes').lean();
    if (!quiz) return res.status(404).json({ error: 'Quiz नहीं मिला या enrollment बंद है' });

    // Generate token only — support ID assigned after buyer pays + submits quiz
    const token = crypto.randomBytes(16).toString('hex');

    const ticket = await QuizTicket.create({
      seller_id: req.user.uid,
      quiz_ref: quiz.quiz_id,
      quiz_id: quiz._id,
      token,
      buyer_name,
      buyer_contact,
      buyer_email: buyer_email || null,
      ticket_price: quiz.entry_fee,
      ticket_status: 'pending'
    });

    const seller = await User.findById(req.user.uid).select('name member_id').lean();
    const link = `${process.env.FRONTEND_URL || req.protocol + '://' + req.get('host')}/quiz-ticket?token=${token}`;

    res.json({
      ok: true,
      ticket_id: ticket._id,
      token,
      link,
      quiz_title: quiz.title,
      entry_fee: quiz.entry_fee
    });
  } catch (err) {
    captureError(err, { context: 'generate-quiz-ticket' });
    res.status(500).json({ error: 'Ticket generation failed: ' + err.message });
  }
});

// GET seller's own quiz tickets (for tracking in Referral & Earn tab)
app.get('/api/member/my-quiz-tickets', auth(['member','supporter']), async (req, res) => {
  try {
    const tickets = await QuizTicket.find({ seller_id: req.user.uid })
      .sort({ sold_at: -1 }).limit(100).lean();
    res.json({ ok: true, tickets });
  } catch(err) {
    captureError(err, { context: 'my-quiz-tickets' });
    res.status(500).json({ error: err.message });
  }
});

// Public: Get ticket info for buyer
app.get('/api/quiz-ticket/:token', async (req, res) => {
  try {
    const ticket = await QuizTicket.findOne({ token: req.params.token }).lean();
    if (!ticket) return res.status(404).json({ error: 'Invalid or expired ticket link' });
    if (ticket.ticket_status === 'converted') {
      return res.status(400).json({ error: 'यह link पहले ही use हो चुकी है', converted: true });
    }

    const quiz = await Quiz.findOne({ quiz_id: ticket.quiz_ref })
      .select('quiz_id title description type entry_fee end_date result_date status prizes').lean();
    if (!quiz || !['upcoming','active'].includes(quiz.status)) {
      return res.status(404).json({ error: 'Quiz अब available नहीं है' });
    }

    const seller = await User.findById(ticket.seller_id).select('name member_id').lean();

    const tierConfig = {
      monthly:     { programName: 'Udaan Scholarship', scholarshipAmount: 5000 },
      half_yearly: { programName: 'Saksham Program',   scholarshipAmount: 25000 },
      yearly:      { programName: 'Divya Yatra Sahyog', scholarshipAmount: 50000 }
    };
    const tc = tierConfig[quiz.type] || {};

    res.json({
      ok: true,
      ticket: {
        token: ticket.token,
        buyer_name: ticket.buyer_name,
        buyer_contact: ticket.buyer_contact,
        ticket_price: ticket.ticket_price,
        support_id: ticket.seller_support_id,
        seller_name: seller?.name || 'FWF Member',
        seller_member_id: seller?.member_id || ''
      },
      quiz: {
        ...quiz,
        program_name: tc.programName || quiz.title,
        scholarship_amount: (quiz.prizes?.first) || tc.scholarshipAmount || 0,
        end_date_fmt: new Date(quiz.end_date).toLocaleDateString('hi-IN', {day:'numeric',month:'long',year:'numeric'}),
        result_date_fmt: new Date(quiz.result_date).toLocaleDateString('hi-IN', {day:'numeric',month:'long',year:'numeric'})
      }
    });
  } catch (err) {
    captureError(err, { context: 'quiz-ticket-get' });
    res.status(500).json({ error: 'Ticket load failed' });
  }
});

// Public: Create Razorpay order for buyer
app.post('/api/quiz-ticket/:token/create-order', async (req, res) => {
  try {
    const ticket = await QuizTicket.findOne({ token: req.params.token, ticket_status: 'pending' }).lean();
    if (!ticket) return res.status(404).json({ error: 'Invalid or already used ticket' });

    if (!ticket.ticket_price || ticket.ticket_price < 1) {
      return res.status(400).json({ error: `Invalid ticket price: ${ticket.ticket_price}` });
    }

    const order = await razorpay.orders.create({
      amount: ticket.ticket_price * 100,
      currency: 'INR',
      receipt: `qt_${ticket._id.toString().slice(-8)}_${Date.now().toString().slice(-8)}`
    });

    res.json({ ok: true, order, key: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    const rzpMsg = err?.error?.description || err?.message || 'Unknown error';
    console.error('quiz-ticket-order error:', rzpMsg, JSON.stringify(err?.error || {}));
    captureError(err, { context: 'quiz-ticket-order' });
    res.status(500).json({ error: `Order creation failed: ${rzpMsg}` });
  }
});

// Public: Buyer payment verify + enroll
app.post('/api/quiz-ticket/:token/enroll', async (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;
    if (!razorpay_payment_id) return res.status(400).json({ error: 'Payment details required' });

    const ticket = await QuizTicket.findOne({ token: req.params.token, ticket_status: 'pending' });
    if (!ticket) return res.status(404).json({ error: 'Invalid or already used ticket' });

    // Verify payment
    if (razorpay_order_id && razorpay_signature) {
      const keySecret = process.env.RAZORPAY_KEY_SECRET;
      const generated = crypto.createHmac('sha256', keySecret)
        .update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
      if (generated !== razorpay_signature) {
        return res.status(400).json({ error: 'Payment verification failed' });
      }
    }

    const quiz = await Quiz.findOne({ quiz_id: ticket.quiz_ref, status: { $in: ['upcoming','active','closed'] } });
    if (!quiz) return res.status(404).json({ error: 'Quiz enrollment closed. Please contact support.' });

    // Generate enrollment number for buyer
    const randomDigits = Math.floor(10000 + Math.random() * 90000);
    const enrollmentNumber = `FWF-${quiz.quiz_id}-${randomDigits}`;

    // Create participation for buyer (buyer is anonymous — stored with buyer contact)
    const participation = await QuizParticipation.create({
      quiz_id: quiz._id,
      quiz_ref: quiz.quiz_id,
      user_id: ticket.seller_id, // linked to seller's account for tracking; buyer is external
      member_id: ticket.buyer_contact,
      name: ticket.buyer_name,
      enrollment_number: enrollmentNumber,
      payment_id: razorpay_payment_id,
      amount_paid: ticket.ticket_price,
      referrer_id: ticket.seller_id,
      status: 'enrolled'
    });

    // Update quiz participant count
    await Quiz.updateOne({ _id: quiz._id }, {
      $inc: { total_participants: 1, total_collection: ticket.ticket_price }
    });

    // Mark ticket as converted (commission points awarded after buyer submits quiz)
    await QuizTicket.updateOne({ _id: ticket._id }, {
      ticket_status: 'converted',
      participation_id: participation._id,
      converted_at: new Date()
    });

    addBreadcrumb('quiz-ticket', 'Ticket converted', {
      seller: ticket.seller_id, buyer: ticket.buyer_name, quiz: quiz.quiz_id
    });

    // Return questions for buyer to play quiz immediately
    const questions = quiz.questions.map(q => ({ q_no: q.q_no, question: q.question, options: q.options }));
    res.json({
      ok: true,
      enrollment_number: enrollmentNumber,
      quiz_title: quiz.title,
      questions,
      total_questions: questions.length,
      result_date_fmt: quiz.result_date
        ? new Date(quiz.result_date).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' })
        : 'TBD',
      message: `🎓 Payment successful! Quiz शुरू करें.`
    });
  } catch (err) {
    captureError(err, { context: 'quiz-ticket-enroll' });
    res.status(500).json({ error: 'Enrollment failed: ' + err.message });
  }
});

// Public: Buyer submits quiz answers (after enrollment)
app.post('/api/quiz-ticket/:token/submit-quiz', async (req, res) => {
  try {
    const { answers } = req.body;
    if (!answers) return res.status(400).json({ error: 'answers required' });

    const ticket = await QuizTicket.findOne({ token: req.params.token, ticket_status: 'converted' });
    if (!ticket) return res.status(404).json({ error: 'Ticket not found or quiz not started' });

    const participation = await QuizParticipation.findById(ticket.participation_id);
    if (!participation) return res.status(404).json({ error: 'Participation record not found' });
    if (participation.quiz_submitted) return res.status(400).json({ error: 'Quiz already submitted' });

    const quiz = await Quiz.findById(ticket.quiz_id);
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

    // Score answers
    let score = 0;
    const scoredAnswers = answers.map(ans => {
      const q = quiz.questions.find(qq => qq.q_no === ans.q_no);
      const isCorrect = q && q.correct_answer === ans.selected;
      if (isCorrect) score += (q.points || 1);
      return { q_no: ans.q_no, selected: ans.selected, is_correct: isCorrect };
    });

    const totalQ = quiz.questions.length;
    const passed = score === totalQ;

    participation.answers = scoredAnswers;
    participation.score = score;
    participation.quiz_submitted = true;
    participation.submitted_at = new Date();
    participation.status = 'submitted';
    await participation.save();

    // Generate seller support ID now (after buyer paid + submitted quiz)
    let supportId = ticket.seller_support_id;
    if (!supportId) {
      const supportNum = Math.floor(10000 + Math.random() * 90000);
      supportId = `FWF-ST-${supportNum}`;
    }

    // Award seller commission points
    const commPoints = amountToPoints(ticket.ticket_price * (QUIZ_TICKET_POINTS_PERCENT / 100));
    if (commPoints > 0 && ticket.seller_id) {
      await User.updateOne({ _id: ticket.seller_id }, {
        $inc: { 'wallet.points_balance': commPoints, 'wallet.points_from_quiz': commPoints, 'wallet.total_points_earned': commPoints },
        'wallet.updated_at': new Date()
      });
      await PointsLedger.create({
        user_id: ticket.seller_id, points: commPoints, type: 'quiz',
        description: `Buyer ${ticket.buyer_name} submitted quiz (${score}/${totalQ}) — ${quiz.title} → ${commPoints} pts`,
        reference_id: ticket._id
      });
    }

    // Update ticket with support_id and points
    await QuizTicket.updateOne({ _id: ticket._id }, { seller_support_id: supportId, points_earned: commPoints });

    // Create or find buyer supporter account
    let buyerAccount = null;
    const rawContact = (ticket.buyer_contact || '').replace(/\D/g, '').slice(-10);
    if (rawContact.length === 10) {
      const existingUser = await User.findOne({ mobile: rawContact }).select('member_id name').lean();
      if (existingUser) {
        buyerAccount = { user_id: existingUser.member_id, is_new: false };
      } else {
        const supporterId = await nextSupporterId();
        const plain = randPass();
        const hash = bcrypt.hashSync(plain, 10);
        const refCode = generateReferralCode(supporterId);
        await User.create({
          member_id: supporterId, name: ticket.buyer_name, mobile: rawContact,
          password_hash: hash, role: 'supporter', membership_active: true,
          referral_code: refCode, wallet: {}
        });
        sendWhatsAppCredentials({ mobile: rawContact, name: ticket.buyer_name, userId: supporterId, password: plain })
          .catch(e => console.error('⚠️ Buyer credentials WhatsApp failed:', e.message));
        buyerAccount = { user_id: supporterId, password: plain, is_new: true };
      }
    }

    addBreadcrumb('quiz-ticket', 'Quiz submitted by buyer', { buyer: ticket.buyer_name, score, totalQ, passed });

    res.json({
      ok: true,
      score,
      totalQuestions: totalQ,
      passed,
      enrollment_number: participation.enrollment_number,
      support_id: supportId,
      buyer_account: buyerAccount,
      result_date_fmt: quiz.result_date
        ? new Date(quiz.result_date).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' })
        : 'TBD',
      message: passed
        ? `🎉 Congratulations! All ${totalQ} answers correct!`
        : `Quiz submitted! Score: ${score}/${totalQ}`
    });
  } catch (err) {
    captureError(err, { context: 'quiz-ticket-submit-quiz' });
    res.status(500).json({ error: 'Quiz submit failed: ' + err.message });
  }
});

// ========================
// REFERRAL TRACKING APIs
// ========================

// Track referral link click
app.post('/api/referral/click', async (req, res) => {
  try {
    const { referral_code, link_type, quiz_id } = req.body;
    if (!referral_code) return res.status(400).json({ error: 'Referral code required' });

    const referrer = await User.findOne({ referral_code }).select('_id').lean();
    if (!referrer) return res.status(404).json({ error: 'Invalid referral code' });

    await ReferralClick.create({
      referrer_id: referrer._id,
      referral_code,
      link_type: link_type || 'general',
      quiz_id: quiz_id || null,
      ip_address: req.ip || req.headers['x-forwarded-for'],
      user_agent: req.headers['user-agent']
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Click tracking failed' });
  }
});

// Get affiliate/referral dashboard data
app.get('/api/member/affiliate', auth('member'), async (req, res) => {
  try {
    const user = await User.findById(req.user.uid).select('referral_code member_id').lean();

    // Click stats
    const clickStats = await ReferralClick.aggregate([
      { $match: { referral_code: user.referral_code } },
      { $group: {
        _id: null,
        totalClicks: { $sum: 1 },
        conversions: { $sum: { $cond: ['$converted', 1, 0] } },
        quizClicks: { $sum: { $cond: [{ $eq: ['$link_type', 'quiz'] }, 1, 0] } },
        joinClicks: { $sum: { $cond: [{ $eq: ['$link_type', 'join'] }, 1, 0] } },
        totalRevenue: { $sum: '$conversion_amount' }
      }}
    ]);

    // Referral history
    const referrals = await Referral.find({ referrer_id: req.user.uid })
      .sort({ created_at: -1 }).lean();
    for (const r of referrals) {
      const referred = await User.findById(r.referred_user_id).select('name member_id').lean();
      if (referred) { r.referred_name = referred.name; r.referred_member_id = referred.member_id; }
    }

    // Quiz referral earnings
    const quizRefEarnings = await PointsLedger.find({
      user_id: req.user.uid, type: 'referral',
      description: /Quiz referral/i
    }).sort({ created_at: -1 }).lean();

    // Recent clicks
    const recentClicks = await ReferralClick.find({ referral_code: user.referral_code })
      .sort({ created_at: -1 }).limit(20)
      .select('link_type converted conversion_type conversion_amount created_at').lean();

    res.json({
      ok: true,
      referralCode: user.referral_code,
      memberId: user.member_id,
      stats: clickStats[0] || { totalClicks: 0, conversions: 0, quizClicks: 0, joinClicks: 0, totalRevenue: 0 },
      referrals,
      quizRefEarnings,
      recentClicks
    });
  } catch (err) {
    captureError(err, { context: 'affiliate-dashboard' });
    res.status(500).json({ error: 'Affiliate data fetch failed' });
  }
});

// Member: my invoices / receipts
app.get('/api/member/invoices', auth(['member', 'supporter']), async (req, res) => {
  try {
    const receipts = await Receipt.find({ user_id: req.user.uid })
      .sort({ created_at: -1 })
      .select('receipt_id token type customer_name total status is_80g email_sent razorpay_payment_id reference_id created_at')
      .lean();
    const backendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
    const withUrls = receipts.map(r => ({ ...r, receipt_url: `${backendUrl}/receipt/${r.token}` }));
    res.json({ ok: true, invoices: withUrls });
  } catch (err) {
    captureError(err, { context: 'member-invoices' });
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ADMIN QUIZ MANAGEMENT
// ========================

// Admin: create quiz
app.post('/api/admin/create-quiz', auth('admin'), async (req, res) => {
  try {
    const { quiz_id, title, description, type, game_type, entry_fee, questions, start_date, end_date, result_date, prizes } = req.body;
    if (!quiz_id || !title || !type || !entry_fee) return res.status(400).json({ error: 'Required fields missing' });

    const quiz = await Quiz.create({
      quiz_id, title, description, type, game_type: game_type || 'mcq', entry_fee,
      questions: questions || [],
      start_date: new Date(start_date),
      end_date: new Date(end_date),
      result_date: new Date(result_date),
      prizes: prizes || {},
      status: new Date(start_date) <= new Date() ? 'active' : 'upcoming'
    });

    res.json({ ok: true, quiz });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Quiz ID already exists' });
    captureError(err, { context: 'admin-create-quiz' });
    res.status(500).json({ error: 'Quiz creation failed' });
  }
});

// Admin: declare quiz results (lucky draw)
app.post('/api/admin/quiz-draw/:quizId', auth('admin'), async (req, res) => {
  try {
    const quiz = await Quiz.findOne({ quiz_id: req.params.quizId });
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });
    if (quiz.status === 'result_declared') return res.status(400).json({ error: 'Results already declared' });

    // Get all paid participants (lucky draw — no score needed)
    // Note: all QuizParticipation records are already paid (verified at enrollment)
    const participants = await QuizParticipation.find({ quiz_id: quiz._id }).lean();

    if (participants.length === 0) return res.status(400).json({ error: 'No paid participants yet' });

    // Random lucky draw — pick 1 winner
    const luckyIndex = Math.floor(Math.random() * participants.length);
    const luckyOne = participants[luckyIndex];
    const prizeAmount = quiz.prizes?.first || 0;

    const winner = {
      rank: 1,
      user_id: luckyOne.user_id,
      member_id: luckyOne.member_id,
      name: luckyOne.name,
      enrollment_number: luckyOne.enrollment_number,
      prize_amount: prizeAmount,
      score: luckyOne.score || 0
    };

    // Update winner participation
    await QuizParticipation.updateOne({ _id: luckyOne._id }, { status: 'won', prize_won: prizeAmount });

    // Credit prize to wallet
    if (prizeAmount > 0) {
      await User.updateOne({ _id: luckyOne.user_id }, {
        $inc: { 'wallet.balance_inr': prizeAmount, 'wallet.lifetime_earned_inr': prizeAmount },
        'wallet.updated_at': new Date()
      });
    }

    // Mark others as lost
    await QuizParticipation.updateMany(
      { quiz_id: quiz._id, user_id: { $ne: luckyOne.user_id } },
      { status: 'lost' }
    );

    quiz.winners = [winner];
    quiz.status = 'result_declared';
    await quiz.save();

    // Non-blocking SMS to winner
    if (luckyOne.user_id) {
      const winnerUser = await User.findById(luckyOne.user_id).select('mobile').lean();
      if (winnerUser?.mobile) {
        sendQuizResultSms({ mobile: winnerUser.mobile, name: luckyOne.name, quizId: quiz.quiz_id })
          .catch(e => console.error('\u26a0\ufe0f Quiz result SMS failed:', e.message));
      }
    }

    res.json({ ok: true, winners: [winner], totalParticipants: participants.length });
  } catch (err) {
    captureError(err, { context: 'admin-quiz-draw' });
    res.status(500).json({ error: 'Draw failed: ' + err.message });
  }
});

// Admin: get all quizzes
app.get('/api/admin/quizzes', auth('admin'), async (req, res) => {
  try {
    const quizzes = await Quiz.find().sort({ created_at: -1 }).lean();
    res.json({ ok: true, quizzes });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch quizzes' });
  }
});

// Admin: Full quiz detail (questions + stats)
app.get('/api/admin/quiz/:quizId/detail', auth('admin'), async (req, res) => {
  try {
    const quiz = await Quiz.findOne({ quiz_id: req.params.quizId }).lean();
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });
    const participantCount = await QuizParticipation.countDocuments({ quiz_ref: quiz.quiz_id });
    const submittedCount  = await QuizParticipation.countDocuments({ quiz_ref: quiz.quiz_id, quiz_submitted: true });
    const paidCount       = await QuizParticipation.countDocuments({ quiz_ref: quiz.quiz_id, payment_status: 'paid' });
    // Answer distribution per question
    const participations  = await QuizParticipation.find({ quiz_ref: quiz.quiz_id, quiz_submitted: true }).select('answers score').lean();
    const questionStats   = (quiz.questions || []).map(q => {
      const dist = [0, 0, 0, 0];
      participations.forEach(p => {
        const ans = (p.answers || []).find(a => a.q_no === q.q_no);
        if (ans && typeof ans.selected === 'number') dist[ans.selected] = (dist[ans.selected] || 0) + 1;
      });
      return { q_no: q.q_no, question: q.question, options: q.options, correct_answer: q.correct_answer, distribution: dist };
    });
    const scores = participations.map(p => p.score || 0);
    const avgScore = scores.length ? (scores.reduce((a,b)=>a+b,0) / scores.length).toFixed(1) : 0;
    res.json({ ok: true, quiz, stats: { participantCount, submittedCount, paidCount, avgScore, questionStats } });
  } catch (err) {
    captureError(err, { context: 'admin-quiz-detail' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: List participants for a quiz
app.get('/api/admin/quiz/:quizId/participants', auth('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 50, search = '', status = '' } = req.query;
    const quiz = await Quiz.findOne({ quiz_id: req.params.quizId }).select('quiz_id title type entry_fee prizes status winners').lean();
    if (!quiz) return res.status(404).json({ error: 'Quiz not found' });
    const filter = { quiz_ref: quiz.quiz_id };
    if (status) filter.status = status;
    if (search) filter.$or = [
      { name: { $regex: search, $options: 'i' } },
      { member_id: { $regex: search, $options: 'i' } },
      { enrollment_number: { $regex: search, $options: 'i' } }
    ];
    const total = await QuizParticipation.countDocuments(filter);
    const participants = await QuizParticipation.find(filter)
      .sort({ created_at: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .select('name member_id user_id enrollment_number payment_id amount_paid payment_status score quiz_submitted submitted_at status prize_won created_at answers')
      .lean();
    // Enrich with user mobile & email for admin contact
    const userIds = participants.map(p => p.user_id).filter(Boolean);
    const users = userIds.length ? await User.find({ _id: { $in: userIds } }).select('_id mobile email').lean() : [];
    const userMap = {};
    users.forEach(u => { userMap[u._id.toString()] = { mobile: u.mobile, email: u.email }; });
    participants.forEach(p => {
      const u = p.user_id ? userMap[p.user_id.toString()] : null;
      p.mobile = u?.mobile || '';
      p.email = u?.email || '';
    });
    // Revenue stats
    const allPaid = await QuizParticipation.find({ quiz_ref: quiz.quiz_id, payment_status: 'paid' }).select('amount_paid score quiz_submitted').lean();
    const totalCollection = allPaid.reduce((s, p) => s + (p.amount_paid || 0), 0);
    const submittedCount  = allPaid.filter(p => p.quiz_submitted).length;
    res.json({
      ok: true, quiz,
      participants,
      pagination: { total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / limit) },
      stats: { total: allPaid.length, totalCollection, submittedCount, avgScore: allPaid.length ? (allPaid.reduce((s,p)=>s+(p.score||0),0)/allPaid.length).toFixed(1) : 0 }
    });
  } catch (err) {
    captureError(err, { context: 'admin-quiz-participants' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: Manually trigger quiz auto-create
app.post('/api/admin/quiz-auto-create', auth('admin'), async (req, res) => {
  try {
    await autoCreateQuizzes();
    const quizzes = await Quiz.find({ status: { $in: ['upcoming', 'active'] } })
      .sort({ type: 1 }).select('quiz_id title type status start_date end_date result_date entry_fee prizes total_participants').lean();
    res.json({ ok: true, message: 'Auto-create ran successfully', quizzes });
  } catch (err) {
    captureError(err, { context: 'admin-quiz-auto-create' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: Manually trigger result draw
app.post('/api/admin/quiz-auto-draw', auth('admin'), async (req, res) => {
  try {
    await autoDrawResults();
    const drawn = await Quiz.find({ status: 'result_declared' })
      .sort({ result_date: -1 }).limit(10)
      .select('quiz_id title type status winners result_date').lean();
    res.json({ ok: true, message: 'Auto-draw ran successfully', recentResults: drawn });
  } catch (err) {
    captureError(err, { context: 'admin-quiz-auto-draw' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: Quiz scheduler health check
app.get('/api/admin/quiz-scheduler-status', auth('admin'), async (req, res) => {
  try {
    const now = new Date();
    const activeQuizzes = await Quiz.find({ status: { $in: ['upcoming', 'active'] } })
      .select('quiz_id title type status start_date end_date result_date entry_fee prizes total_participants total_collection').lean();
    const closedPending = await Quiz.find({ status: 'closed', 'winners.0': { $exists: false } })
      .select('quiz_id title type result_date').lean();
    const recentResults = await Quiz.find({ status: 'result_declared' })
      .sort({ result_date: -1 }).limit(5)
      .select('quiz_id title type winners result_date').lean();
    
    res.json({
      ok: true,
      serverTime: now.toISOString(),
      activeQuizzes,
      pendingDraw: closedPending,
      recentResults,
      summary: {
        active: activeQuizzes.length,
        pendingDraw: closedPending.length,
        recentDrawn: recentResults.length
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ADMIN INVOICE MANAGEMENT
// ========================

// Admin: list all receipts/invoices (paginated + filterable)
app.get('/api/admin/invoices', auth('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 50, type = '', search = '' } = req.query;
    const filter = {};
    if (type) filter.type = type;
    if (search) filter.$or = [
      { receipt_id: { $regex: search, $options: 'i' } },
      { customer_name: { $regex: search, $options: 'i' } },
      { member_id: { $regex: search, $options: 'i' } },
      { razorpay_payment_id: { $regex: search, $options: 'i' } }
    ];
    const total = await Receipt.countDocuments(filter);
    const invoices = await Receipt.find(filter)
      .sort({ created_at: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .select('-line_items')
      .lean();
    const totalAgg = await Receipt.aggregate([{ $group: { _id: null, sum: { $sum: '$total' } } }]);
    const stats = {
      total: await Receipt.countDocuments(),
      membership: await Receipt.countDocuments({ type: 'membership' }),
      donation: await Receipt.countDocuments({ type: 'donation' }),
      is80g: await Receipt.countDocuments({ is_80g: true }),
      totalAmount: totalAgg[0]?.sum || 0
    };
    const backendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
    const withUrls = invoices.map(r => ({ ...r, receipt_url: `${backendUrl}/receipt/${r.token}` }));
    res.json({ ok: true, invoices: withUrls, pagination: { total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / limit) }, stats });
  } catch (err) {
    captureError(err, { context: 'admin-invoices-list' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: get single receipt details
app.get('/api/admin/invoice/:receiptId', auth('admin'), async (req, res) => {
  try {
    const receipt = await Receipt.findOne({ receipt_id: req.params.receiptId }).lean();
    if (!receipt) return res.status(404).json({ error: 'Receipt not found' });
    const backendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
    res.json({ ok: true, receipt: { ...receipt, receipt_url: `${backendUrl}/receipt/${receipt.token}` } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: resend receipt email
app.post('/api/admin/invoice/:receiptId/resend', auth('admin'), async (req, res) => {
  try {
    const receipt = await Receipt.findOne({ receipt_id: req.params.receiptId }).lean();
    if (!receipt) return res.status(404).json({ error: 'Receipt not found' });
    if (!receipt.customer_email) return res.status(400).json({ error: 'No email address on file for this receipt' });

    const backendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
    const receiptUrl = `${backendUrl}/receipt/${receipt.token}`;
    const typeLabel = receipt.type === 'membership' ? 'Membership Fee' : receipt.type === 'donation' ? 'Donation' : 'Payment';
    const transporter = await getTransporter();
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: receipt.customer_email,
      subject: `[Resent] Your FWF ${typeLabel} Receipt – ${receipt.receipt_id}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
          <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:32px;border-radius:12px 12px 0 0;text-align:center">
            <div style="font-size:40px;margin-bottom:8px">🧾</div>
            <h1 style="color:#fff;margin:0;font-size:24px">Payment Receipt</h1>
            <p style="color:#a0a0c0;margin:8px 0 0">Foundris Welfare Foundation</p>
          </div>
          <div style="background:#fff;padding:32px;border:1px solid #e5e7eb;border-top:none">
            <p style="color:#374151">Dear ${receipt.customer_name},</p>
            <p style="color:#374151">This is a resent copy of your payment receipt. Please find the details below:</p>
            <table style="width:100%;border-collapse:collapse;margin:20px 0">
              <tr style="background:#f9fafb"><td style="padding:10px 14px;color:#6b7280;font-size:13px">Receipt No.</td><td style="padding:10px 14px;font-weight:600;color:#111827">${receipt.receipt_id}</td></tr>
              <tr><td style="padding:10px 14px;color:#6b7280;font-size:13px">Date</td><td style="padding:10px 14px;color:#374151">${new Date(receipt.created_at).toLocaleDateString('en-IN', { day:'2-digit', month:'long', year:'numeric' })}</td></tr>
              ${receipt.member_id ? `<tr style="background:#f9fafb"><td style="padding:10px 14px;color:#6b7280;font-size:13px">Member ID</td><td style="padding:10px 14px;color:#374151">${receipt.member_id}</td></tr>` : ''}
              <tr ${receipt.member_id ? '' : 'style="background:#f9fafb"'}><td style="padding:10px 14px;color:#6b7280;font-size:13px">Amount Paid</td><td style="padding:10px 14px;font-weight:700;color:#059669;font-size:18px">₹${receipt.total?.toLocaleString('en-IN')}</td></tr>
              ${receipt.razorpay_payment_id ? `<tr style="background:#f9fafb"><td style="padding:10px 14px;color:#6b7280;font-size:13px">Payment ID</td><td style="padding:10px 14px;color:#374151;font-family:monospace;font-size:12px">${receipt.razorpay_payment_id}</td></tr>` : ''}
            </table>
            <div style="text-align:center;margin:28px 0">
              <a href="${receiptUrl}" style="background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;text-decoration:none;padding:14px 28px;border-radius:8px;font-weight:600;display:inline-block">View / Download Receipt</a>
            </div>
            ${receipt.is_80g ? '<p style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:14px;color:#166534;font-size:13px">✅ This receipt is eligible for <strong>80G tax deduction</strong> under the Income Tax Act, 1961.</p>' : ''}
          </div>
          <div style="background:#f9fafb;padding:20px;text-align:center;font-size:12px;color:#9ca3af">Foundris Welfare Foundation (FWF) | support@fwfindia.org</div>
        </div>`
    });

    await Receipt.updateOne({ receipt_id: req.params.receiptId }, { $set: { email_sent: true, email_sent_at: new Date(), status: 'sent' } });
    res.json({ ok: true, message: 'Receipt email resent successfully' });
  } catch (err) {
    captureError(err, { context: 'admin-resend-receipt' });
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ZOHO BOOKS INTEGRATION
// ========================

// Step 1: Redirect admin to Zoho OAuth (open in browser)
app.get('/api/admin/zoho/auth', auth('admin'), (req, res) => {
  const url = getAuthUrl();
  res.redirect(url);
});

// Step 2: Zoho OAuth callback — exchange code for refresh token, store in DB
app.get('/api/admin/zoho/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:60px">
      <h2 style="color:#ef4444">Zoho OAuth Failed</h2>
      <p>${error || 'No authorization code received'}</p>
      <a href="https://fwfindia.org/admin-dashboard.html#invoices">Back to Dashboard</a>
    </body></html>`);
  }
  try {
    const tokens = await exchangeCodeForTokens(code);
    if (!tokens.refresh_token) throw new Error('No refresh token returned: ' + JSON.stringify(tokens));
    // Store refresh token in MongoDB
    await AppConfig.findOneAndUpdate(
      { key: 'zoho_refresh_token' },
      { key: 'zoho_refresh_token', value: tokens.refresh_token, meta: { access_token: tokens.access_token, set_at: new Date() }, updated_at: new Date() },
      { upsert: true }
    );
    console.log('✅ Zoho Books connected successfully. Refresh token stored.');
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:60px">
      <h2 style="color:#16a34a">✅ Zoho Books Connected!</h2>
      <p>FWF is now syncing receipts to Zoho Books automatically.</p>
      <p style="margin-top:20px"><a href="https://fwfindia.org/admin/dashboard#invoices" style="color:#2563eb;font-weight:600">Return to Dashboard</a></p>
      <script>
        // Notify opener tab to refresh status
        if (window.opener) { try { window.opener.postMessage('zoho-connected','*'); } catch(e){} }
        setTimeout(()=>{ window.close(); }, 3000);
      </script>
    </body></html>`);
  } catch (err) {
    captureError(err, { context: 'zoho-callback' });
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:60px">
      <h2 style="color:#ef4444">Error</h2><p>${err.message}</p>
      <a href="https://fwfindia.org/admin-dashboard.html#invoices">Back to Dashboard</a>
    </body></html>`);
  }
});

// Check Zoho connection status
app.get('/api/admin/zoho/status', auth('admin'), async (req, res) => {
  try {
    const status = await checkZohoConnection();
    const cfg = await AppConfig.findOne({ key: 'zoho_refresh_token' }).lean();
    res.json({ ok: true, ...status, configured_at: cfg?.updated_at || null });
  } catch (err) {
    res.json({ ok: true, connected: false, reason: err.message });
  }
});

// Sync ALL unsynced receipts to Zoho Books (manual bulk sync)
app.post('/api/admin/zoho/sync', auth('admin'), async (req, res) => {
  try {
    const status = await checkZohoConnection();
    if (!status.connected) return res.status(400).json({ error: 'Zoho not connected: ' + status.reason });

    const unsynced = await Receipt.find({ zoho_salesreceipt_id: { $exists: false }, status: { $ne: 'cancelled' } })
      .sort({ created_at: -1 }).limit(100).lean();

    let synced = 0, failed = 0, errors = [];
    for (const receipt of unsynced) {
      try {
        const result = await syncReceiptToZoho(receipt);
        if (result?.zoho_salesreceipt_id) {
          await Receipt.updateOne({ _id: receipt._id }, {
            $set: { zoho_salesreceipt_id: result.zoho_salesreceipt_id, zoho_synced_at: new Date() }
          });
          synced++;
        } else { failed++; }
      } catch (err) {
        failed++;
        errors.push({ receipt_id: receipt.receipt_id, error: err.message });
      }
    }
    res.json({ ok: true, total: unsynced.length, synced, failed, errors: errors.slice(0, 5) });
  } catch (err) {
    captureError(err, { context: 'zoho-bulk-sync' });
    res.status(500).json({ error: err.message });
  }
});

// Sync single receipt to Zoho Books
app.post('/api/admin/zoho/sync/:receiptId', auth('admin'), async (req, res) => {
  try {
    const receipt = await Receipt.findOne({ receipt_id: req.params.receiptId }).lean();
    if (!receipt) return res.status(404).json({ error: 'Receipt not found' });
    const result = await syncReceiptToZoho(receipt);
    if (!result?.zoho_salesreceipt_id) return res.status(500).json({ error: 'Zoho sync returned no ID' });
    await Receipt.updateOne({ _id: receipt._id }, {
      $set: { zoho_salesreceipt_id: result.zoho_salesreceipt_id, zoho_synced_at: new Date() }
    });
    res.json({ ok: true, zoho_salesreceipt_id: result.zoho_salesreceipt_id });
  } catch (err) {
    captureError(err, { context: 'zoho-sync-single' });
    res.status(500).json({ error: err.message });
  }
});

// Disconnect Zoho (remove stored token)
app.post('/api/admin/zoho/disconnect', auth('admin'), async (req, res) => {
  try {
    await AppConfig.deleteOne({ key: 'zoho_refresh_token' });
    res.json({ ok: true, message: 'Zoho Books disconnected' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Zoho debug/test — verify connection and API response
app.get('/api/admin/zoho/test', auth('admin'), async (req, res) => {
  const result = { env: {}, auth: {}, api: {} };
  result.env.ZOHO_CLIENT_ID  = process.env.ZOHO_CLIENT_ID ? '✅ set' : '❌ missing';
  result.env.ZOHO_CLIENT_SECRET = process.env.ZOHO_CLIENT_SECRET ? '✅ set' : '❌ missing';
  result.env.ZOHO_ORG_ID     = process.env.ZOHO_ORG_ID   ? `✅ ${process.env.ZOHO_ORG_ID}` : '❌ missing';
  result.env.ZOHO_REGION     = process.env.ZOHO_REGION   || 'not set (default: in)';
  try {
    const cfg = await AppConfig.findOne({ key: 'zoho_refresh_token' }).lean();
    result.auth.refresh_token_in_db = cfg?.value ? '✅ stored' : '❌ not found';
    result.auth.stored_at = cfg?.updated_at || null;
  } catch (e) { result.auth.db_error = e.message; }
  try {
    const { getAccessToken } = await import('./lib/zoho.js');
    const token = await getAccessToken();
    result.auth.access_token = token ? `✅ obtained (${token.slice(0,12)}...)` : '❌ null';
    // Test API — list contacts (1 result)
    const { default: nodeFetch } = await import('node-fetch').catch(() => ({ default: fetch }));
    const apiRes = await fetch(`https://www.zohoapis.in/books/v3/contacts?organization_id=${process.env.ZOHO_ORG_ID}&per_page=1`, {
      headers: { Authorization: `Zoho-oauthtoken ${token}` }
    });
    const apiData = await apiRes.json();
    result.api.contacts_test = apiData.code === 0 ? `✅ OK (${apiData.contacts?.length || 0} contacts returned)` : `❌ Error: ${JSON.stringify(apiData)}`;
  } catch (e) {
    result.auth.error = e.message;
  }
  res.json(result);
});

// Admin: get social task stats

// Admin: Purge ALL quiz data (quizzes, participations, related points ledger)
app.post('/api/admin/quiz-purge-all', auth('admin'), async (req, res) => {
  try {
    const deletedQ = await Quiz.deleteMany({});
    const deletedP = await QuizParticipation.deleteMany({});
    const deletedPL = await PointsLedger.deleteMany({ description: { $regex: /quiz|lucky draw/i } });
    const deletedT = await QuizTicket.deleteMany({});
    res.json({
      ok: true,
      message: 'All quiz data purged.',
      deleted: {
        quizzes: deletedQ.deletedCount,
        participations: deletedP.deletedCount,
        pointsLedger: deletedPL.deletedCount,
        tickets: deletedT.deletedCount
      }
    });
  } catch (err) {
    captureError(err, { context: 'quiz-purge-all' });
    res.status(500).json({ error: err.message });
  }
});

// Admin: Seed a quiz with N fake participants
app.post('/api/admin/quiz-seed', auth('admin'), async (req, res) => {
  try {
    const { type, participantCount, result_date } = req.body;
    const qType = type || 'monthly';
    const numP = Math.min(Number(participantCount) || 100, 500);
    const now = new Date();

    const typeConfig = {
      monthly:     { title: 'Monthly Lucky Draw — March 2026', fee: 100, prize: 5000 },
      half_yearly: { title: 'Half-Yearly Lucky Draw — H1 2026', fee: 500, prize: 25000 },
      yearly:      { title: 'Yearly Grand Lucky Draw — 2026', fee: 1000, prize: 100000 }
    };
    const cfg = typeConfig[qType] || typeConfig.monthly;

    const resultDate = result_date ? new Date(result_date) : new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const endDate = new Date(resultDate.getTime() - 60 * 60 * 1000); // 1 hour before result

    const quizId = `FWF-${qType.charAt(0).toUpperCase()}${qType.slice(1).replace('_','')}` + '-' + now.getFullYear() + String(now.getMonth()+1).padStart(2,'0');

    const quiz = await Quiz.create({
      quiz_id: quizId,
      title: cfg.title,
      description: `Lucky draw with ${numP} participants. Result on ${resultDate.toLocaleDateString('en-IN')}.`,
      type: qType,
      game_type: 'mcq',
      entry_fee: cfg.fee,
      start_date: now,
      end_date: endDate,
      result_date: resultDate,
      status: 'active',
      prizes: { first: cfg.prize, second: 0, third: 0 },
      total_participants: numP,
      total_collection: numP * cfg.fee,
      questions: [
        { q_no: 1, question: 'भारत की राजधानी क्या है?', options: ['मुम्बई', 'दिल्ली', 'चेन्नई', 'कोलकाता'], correct_answer: 1, points: 1 },
        { q_no: 2, question: '2 + 2 = ?', options: ['3', '4', '5', '6'], correct_answer: 1, points: 1 },
        { q_no: 3, question: 'सूर्य किस दिशा में उगता है?', options: ['पश्चिम', 'उत्तर', 'दक्षिण', 'पूर्व'], correct_answer: 3, points: 1 },
        { q_no: 4, question: 'भारत का राष्ट्रीय पशु कौन है?', options: ['शेर', 'बाघ', 'हाथी', 'मोर'], correct_answer: 1, points: 1 },
        { q_no: 5, question: 'गंगा नदी कहाँ से निकलती है?', options: ['अमरनाथ', 'गंगोत्री', 'केदारनाथ', 'बद्रीनाथ'], correct_answer: 1, points: 1 }
      ]
    });

    // Generate fake participants
    const femaleNames = [
      'Priya Sharma', 'Anita Verma', 'Sunita Devi', 'Rekha Gupta', 'Savita Singh',
      'Meena Kumari', 'Pooja Yadav', 'Kavita Pandey', 'Rani Patel', 'Geeta Mishra',
      'Suman Joshi', 'Lata Chauhan', 'Usha Tiwari', 'Nirmala Rawat', 'Kamla Dubey',
      'Bina Agarwal', 'Pushpa Soni', 'Kiran Bano', 'Seema Rathore', 'Neha Kapoor',
      'Ritu Saxena', 'Shanti Bisht', 'Mamta Jain', 'Aarti Thakur', 'Deepa Negi',
      'Rashmi Tomar', 'Sangeeta Rana', 'Preeti Chauhan', 'Babita Kumari', 'Indu Rawat',
      'Manisha Pandey', 'Archana Srivastava', 'Dimple Gupta', 'Komal Verma', 'Sapna Patel',
      'Rinku Devi', 'Sonia Singh', 'Ramina Khan', 'Poonam Joshi', 'Nisha Tripathi',
      'Kusum Devi', 'Vineeta Agrawal', 'Anjali Mishra', 'Shakuntala Devi', 'Radha Kumari',
      'Manju Sharma', 'Saroj Yadav', 'Parvati Devi', 'Guddi Singh', 'Champa Kumari',
      'Chandni Bano', 'Fatima Khan', 'Shabnam Begum', 'Rubina Sheikh', 'Tabassum Ali',
      'Asha Devi', 'Leela Kumari', 'Durga Sahu', 'Meera Rajput', 'Kausalya Mahto',
      'Sudha Mishra', 'Tulsi Devi', 'Hema Rawat', 'Shobha Sharma', 'Pramila Devi',
      'Madhuri Thakur', 'Janki Devi', 'Bhavna Verma', 'Alka Singh', 'Sushila Kumari',
      'Gayatri Devi', 'Hemlata Chauhan', 'Kamini Tiwari', 'Vanita Joshi', 'Pallavi Pandey',
      'Sheetal Gupta', 'Amrita Verma', 'Payal Patel', 'Divya Mishra', 'Chanda Devi',
      'Swati Yadav', 'Garima Sharma', 'Namrata Singh', 'Priyanshi Dubey', 'Kriti Agarwal',
      'Tanvi Chauhan', 'Sakshi Rawat', 'Nikita Jain', 'Muskan Khan', 'Deepika Thakur',
      'Anjali Kumari', 'Yogita Soni', 'Ranjana Devi', 'Bharti Verma', 'Anupama Singh',
      'Radhika Sharma', 'Soniya Patel', 'Kaveri Mishra', 'Anamika Gupta', 'Tara Devi'
    ];

    const participations = [];
    for (let i = 0; i < numP; i++) {
      const fakeName = femaleNames[i % femaleNames.length] + (i >= femaleNames.length ? ` (${Math.floor(i/femaleNames.length)+1})` : '');
      const score = Math.floor(Math.random() * 6); // 0-5
      const enrollNum = `${quizId}-${String(i+1).padStart(4,'0')}`;
      const joined = new Date(now.getTime() - Math.random() * 7 * 24 * 60 * 60 * 1000); // random within last 7 days

      participations.push({
        quiz_id: quiz._id,
        quiz_ref: quiz.quiz_id,
        user_id: new mongoose.Types.ObjectId(),
        member_id: `FWF-${String(100001 + i)}`,
        name: fakeName,
        enrollment_number: enrollNum,
        payment_id: `pay_seed_${Date.now()}_${i}`,
        amount_paid: cfg.fee,
        payment_status: 'paid',
        score,
        quiz_submitted: true,
        submitted_at: joined,
        status: 'enrolled',
        created_at: joined,
        answers: quiz.questions.map((q, qi) => {
          const sel = Math.floor(Math.random() * q.options.length);
          return { q_no: q.q_no, selected: sel, is_correct: sel === q.correct_answer };
        })
      });
    }

    await QuizParticipation.insertMany(participations);

    res.json({
      ok: true,
      message: `Quiz "${cfg.title}" created with ${numP} participants.`,
      quiz_id: quizId,
      type: qType,
      participants: numP,
      collection: numP * cfg.fee,
      result_date: resultDate.toISOString()
    });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Quiz with this ID already exists. Purge first.' });
    captureError(err, { context: 'quiz-seed' });
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ADMIN SOCIAL POST ROUTES
// ========================

// Get all social posts (filter by status)
app.get('/api/admin/social-posts', auth('admin'), async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const query = status === 'all' ? {} : { status };
    const posts = await SocialPost.find(query)
      .sort({ created_at: -1 }).limit(100).lean();
    const pending = await SocialPost.countDocuments({ status: 'pending' });
    res.json({ ok: true, posts, pending });
  } catch (err) {
    captureError(err, { context: 'admin-social-posts' });
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// Approve a social post
app.post('/api/admin/social-posts/:id/approve', auth('admin'), async (req, res) => {
  try {
    const post = await SocialPost.findByIdAndUpdate(
      req.params.id,
      { status: 'active' },
      { new: true }
    );
    if (!post) return res.status(404).json({ error: 'Post not found' });
    res.json({ ok: true, post });
  } catch (err) {
    captureError(err, { context: 'approve-post' });
    res.status(500).json({ error: 'Approve failed' });
  }
});

// Reject / remove a social post
app.post('/api/admin/social-posts/:id/reject', auth('admin'), async (req, res) => {
  try {
    const post = await SocialPost.findByIdAndUpdate(
      req.params.id,
      { status: 'removed' },
      { new: true }
    );
    if (!post) return res.status(404).json({ error: 'Post not found' });
    res.json({ ok: true, post });
  } catch (err) {
    captureError(err, { context: 'reject-post' });
    res.status(500).json({ error: 'Reject failed' });
  }
});

app.get('/api/admin/social-stats', auth('admin'), async (req, res) => {
  try {
    const totalCompletions = await TaskCompletion.countDocuments();
    const thisWeek = await TaskCompletion.countDocuments({
      completed_at: { $gte: new Date(Date.now() - 7 * 86400000) }
    });
    const activeMembers = await TaskCompletion.distinct('user_id');
    const recentCompletions = await TaskCompletion.find()
      .sort({ completed_at: -1 }).limit(20).lean();

    res.json({ ok: true, totalCompletions, thisWeek, activeMembers: activeMembers.length, recentCompletions });
  } catch (err) {
    res.status(500).json({ error: 'Stats fetch failed' });
  }
});

// Sentry error handler
app.use(errorHandler);

// Global error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  captureError(err, { url: req.url, method: req.method, user: req.user });
  res.status(500).json({ error: 'Internal server error' });
});

// ─── TEST EMAIL (admin only) ─────────────────────────────────────────────────
app.post('/api/admin/test-email', auth('admin'), async (req, res) => {
  const { to } = req.body || {};
  const target = to || req.user?.email;
  if (!target) return res.status(400).json({ error: 'Provide a "to" email in body' });

  // Pre-flight env check
  if (!process.env.RESEND_API_KEY) return res.status(500).json({ ok: false, error: 'RESEND_API_KEY is not set in Railway variables' });
  if (!process.env.MAIL_FROM)      return res.status(500).json({ ok: false, error: 'MAIL_FROM is not set in Railway variables' });

  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from: process.env.MAIL_FROM,
      to: target,
      subject: '✅ FWF Email Test — Resend is working!',
      html: `<p>This is a test email sent from FWF backend at <strong>${new Date().toISOString()}</strong>.<br>If you received this, Resend is configured correctly.<br>Reply-To: ${process.env.REPLY_TO_EMAIL || 'not set'}</p>`
    });
    res.json({ ok: true, message: `Test email sent to ${target}` });
  } catch (e) {
    console.error('Test email error:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT LINK ROUTES
// ─────────────────────────────────────────────────────────────────────────────

/** Generate a unique link_id like  PL-FWFM001-x7k2  */
function genLinkId(memberId) {
  const slug = memberId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  const rand = Math.random().toString(36).substring(2, 7);
  return `PL-${slug}-${rand}`;
}

// Create a new shareable payment link
app.post('/api/member/create-payment-link', auth(['member', 'supporter']), async (req, res) => {
  try {
    const { type, title, amount } = req.body;
    if (!type || !['donation', 'quiz_ticket'].includes(type))
      return res.status(400).json({ error: 'type must be donation or quiz_ticket' });

    const user = await User.findById(req.user.uid).select('name member_id').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Limit to 5 active links per user
    const activeCount = await PaymentLink.countDocuments({ created_by: req.user.uid, active: true });
    if (activeCount >= 5)
      return res.status(400).json({ error: 'Maximum 5 active links allowed. Deactivate an existing link first.' });

    let link_id;
    // Ensure uniqueness
    let tries = 0;
    do {
      link_id = genLinkId(user.member_id);
      tries++;
    } while ((await PaymentLink.findOne({ link_id }).lean()) && tries < 10);

    const preset = type === 'quiz_ticket' ? (Number(amount) || QUIZ_TICKET_PRICE) : (amount ? Number(amount) : null);

    const link = await PaymentLink.create({
      link_id,
      created_by: req.user.uid,
      member_id: user.member_id,
      member_name: user.name,
      type,
      title: title?.trim() || (type === 'donation' ? 'Donation for FWF' : 'Quiz Ticket'),
      amount: preset
    });

    const baseUrl = process.env.SITE_URL || 'https://www.fwfindia.org';
    res.json({ ok: true, linkId: link_id, url: `${baseUrl}/pay/${link_id}`, link });
  } catch (err) {
    captureError(err, { context: 'create-payment-link' });
    res.status(500).json({ error: err.message });
  }
});

// List my payment links
app.get('/api/member/payment-links', auth(['member', 'supporter']), async (req, res) => {
  try {
    const links = await PaymentLink.find({ created_by: req.user.uid })
      .sort({ created_at: -1 }).lean();
    const baseUrl = process.env.SITE_URL || 'https://www.fwfindia.org';
    const result = links.map(l => ({ ...l, url: `${baseUrl}/pay/${l.link_id}` }));
    res.json({ ok: true, links: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deactivate a link
app.delete('/api/member/payment-link/:linkId', auth(['member', 'supporter']), async (req, res) => {
  try {
    const { linkId } = req.params;
    const link = await PaymentLink.findOne({ link_id: linkId, created_by: req.user.uid });
    if (!link) return res.status(404).json({ error: 'Link not found' });
    link.active = false;
    await link.save();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUBLIC: get link details (no auth) ──
app.get('/api/pay/link/:linkId', async (req, res) => {
  try {
    const link = await PaymentLink.findOne({ link_id: req.params.linkId }).lean();
    if (!link) return res.status(404).json({ error: 'Payment link not found' });
    if (!link.active) return res.status(410).json({ error: 'This payment link has been deactivated' });
    res.json({
      ok: true,
      linkId: link.link_id,
      type: link.type,
      title: link.title,
      memberName: link.member_name,
      memberId: link.member_id,
      amount: link.amount,
      paymentCount: link.payment_count,
      totalCollected: link.total_collected
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── PUBLIC: create a Razorpay order for a payment link ──
app.post('/api/pay/link/:linkId/order', async (req, res) => {
  try {
    const link = await PaymentLink.findOne({ link_id: req.params.linkId, active: true }).lean();
    if (!link) return res.status(404).json({ error: 'Payment link not found or inactive' });

    const amount = link.amount || Number(req.body.amount);
    if (!amount || amount < 1) return res.status(400).json({ error: 'Valid amount required' });

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100),
      currency: 'INR',
      receipt: `pl_${link.link_id}_${Date.now()}`,
      notes: { link_id: link.link_id, type: link.type, member_id: link.member_id }
    });
    res.json({ ok: true, order, key: process.env.RAZORPAY_KEY_ID, amount });
  } catch (err) {
    captureError(err, { context: 'pay-link-order' });
    res.status(500).json({ error: err.message });
  }
});

// ── PUBLIC: verify payment & credit creator ──
app.post('/api/pay/link/:linkId/confirm', async (req, res) => {
  try {
    const link = await PaymentLink.findOne({ link_id: req.params.linkId, active: true });
    if (!link) return res.status(404).json({ error: 'Payment link not found or inactive' });

    const {
      razorpay_payment_id, razorpay_order_id, razorpay_signature,
      payerName, payerEmail, payerMobile, amount
    } = req.body;

    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature)
      return res.status(400).json({ error: 'Payment details required' });

    // Verify Razorpay signature
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');
    if (expected !== razorpay_signature)
      return res.status(400).json({ ok: false, error: 'Payment verification failed' });

    const numAmount = link.amount || Number(amount);
    const creator = await User.findById(link.created_by).lean();
    if (!creator) return res.status(404).json({ error: 'Link creator not found' });

    // Points = 10% of amount
    const pointsRupees = numAmount * (DONATION_POINTS_PERCENT / 100);
    const points = amountToPoints(pointsRupees);
    const pointsField = link.type === 'quiz_ticket' ? 'points_from_quiz' : 'points_from_donations';
    const ledgerType  = link.type === 'quiz_ticket' ? 'quiz' : 'donation';

    // Credit points to link creator
    await User.updateOne({ _id: link.created_by }, {
      $inc: {
        [`wallet.${pointsField}`]:        points,
        'wallet.points_balance':           points,
        'wallet.total_points_earned':      points
      },
      'wallet.updated_at': new Date()
    });

    await PointsLedger.create({
      user_id: link.created_by,
      points,
      type: ledgerType,
      description: `Payment link ${link.link_id}: ₹${numAmount} via ${payerName || 'visitor'} → ${points} pts`
    });

    // Record in appropriate collection
    if (link.type === 'donation') {
      const donationId = await nextDonationId();
      await Donation.create({
        donation_id:  donationId,
        member_id:    link.created_by,
        amount:       numAmount,
        points_earned: points,
        donor_name:   payerName  || 'Anonymous',
        donor_email:  payerEmail || null,
        donor_mobile: payerMobile || null,
        source:       'payment_link',
        payment_id:   razorpay_payment_id,
        order_id:     razorpay_order_id,
        kyc_status:   'not_required'
      });
    } else {
      await QuizTicket.create({
        seller_id:     link.created_by,
        buyer_name:    payerName    || null,
        buyer_contact: payerMobile  || payerEmail || null,
        ticket_price:  numAmount,
        points_earned: points
      });
    }

    // Update link stats
    await PaymentLink.updateOne({ _id: link._id }, {
      $inc: { payment_count: 1, total_collected: numAmount, total_points_earned: points }
    });

    addBreadcrumb('payment', 'PaymentLink paid', { linkId: link.link_id, amount: numAmount, type: link.type });

    // Non-blocking: send thank-you email to payer
    if (payerEmail) {
      sendDonationConfirmation({
        name: payerName || 'Supporter',
        email: payerEmail,
        amount: numAmount,
        donationId: link.link_id,
        paymentId: razorpay_payment_id,
        recurring: false,
        pointsEarned: 0
      }).catch(e => console.error('PaymentLink confirmation email failed:', e.message));
    }

    res.json({
      ok: true,
      transactionId: razorpay_payment_id,
      message: `Payment of ₹${numAmount} received! ${creator.name} has been credited ${points} points.`,
      pointsEarned: points,
      memberName: link.member_name
    });
  } catch (err) {
    captureError(err, { context: 'pay-link-confirm' });
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// AUTO QUIZ MANAGEMENT — Automated creation + result draw
// ══════════════════════════════════════════════════════════════

// Quiz templates for auto-creation
const quizTemplates = {
  monthly: {
    titlePrefix: 'Monthly Lucky Draw',
    description: 'Monthly lucky draw — 1 random winner wins the prize!',
    game_type: 'mcq',
    entry_fee: 100,
    prizes: { first: 5000, second: 0, third: 0 },
    questions: [
      { q_no: 1, question: 'भारत की राजधानी क्या है?', options: ['मुंबई', 'दिल्ली', 'कोलकाता', 'चेन्नई'], correct_answer: 1, points: 1 },
      { q_no: 2, question: 'गंगा नदी कहाँ से निकलती है?', options: ['गंगोत्री', 'यमुनोत्री', 'केदारनाथ', 'बद्रीनाथ'], correct_answer: 0, points: 1 },
      { q_no: 3, question: 'भारत का सबसे बड़ा राज्य कौन सा है?', options: ['मध्य प्रदेश', 'उत्तर प्रदेश', 'राजस्थान', 'महाराष्ट्र'], correct_answer: 2, points: 1 },
      { q_no: 4, question: 'हमारे राष्ट्रीय ध्वज में कितने रंग हैं?', options: ['2', '3', '4', '5'], correct_answer: 1, points: 1 },
      { q_no: 5, question: 'भारत के पहले राष्ट्रपति कौन थे?', options: ['महात्मा गांधी', 'जवाहरलाल नेहरू', 'डॉ. राजेंद्र प्रसाद', 'सरदार पटेल'], correct_answer: 2, points: 1 },
      { q_no: 6, question: 'TAJ MAHAL किसने बनवाया था?', options: ['अकबर', 'शाहजहाँ', 'जहाँगीर', 'औरंगज़ेब'], correct_answer: 1, points: 1 },
      { q_no: 7, question: 'भारत का राष्ट्रीय खेल कौन सा है?', options: ['क्रिकेट', 'कबड्डी', 'हॉकी', 'फुटबॉल'], correct_answer: 2, points: 1 },
      { q_no: 8, question: 'सूरज किस दिशा में उगता है?', options: ['पश्चिम', 'उत्तर', 'दक्षिण', 'पूर्व'], correct_answer: 3, points: 1 },
      { q_no: 9, question: '1 किलोमीटर में कितने मीटर होते हैं?', options: ['100', '500', '1000', '10000'], correct_answer: 2, points: 1 },
      { q_no: 10, question: 'भारत का सबसे लंबा नदी पुल कौन सा है?', options: ['हावड़ा ब्रिज', 'भूपेन हजारिका सेतु', 'महात्मा गांधी सेतु', 'राजीव गांधी सेतु'], correct_answer: 1, points: 1 }
    ]
  },
  half_yearly: {
    titlePrefix: 'Half-Yearly Lucky Draw',
    description: 'Half-yearly lucky draw — 1 random winner wins big!',
    game_type: 'general',
    entry_fee: 500,
    prizes: { first: 25000, second: 0, third: 0 },
    questions: [
      { q_no: 1, question: 'विश्व का सबसे बड़ा महासागर कौन सा है?', options: ['अटलांटिक', 'हिंद महासागर', 'प्रशांत महासागर', 'आर्कटिक'], correct_answer: 2, points: 1 },
      { q_no: 2, question: 'भारतीय संविधान कब लागू हुआ?', options: ['15 Aug 1947', '26 Jan 1950', '2 Oct 1949', '26 Nov 1949'], correct_answer: 1, points: 1 },
      { q_no: 3, question: 'पृथ्वी सूर्य का चक्कर कितने दिन में लगाती है?', options: ['365', '360', '366', '364'], correct_answer: 0, points: 1 },
      { q_no: 4, question: 'विश्व का सबसे ऊँचा पर्वत शिखर कौन सा है?', options: ['K2', 'कंचनजंगा', 'माउंट एवरेस्ट', 'मकालू'], correct_answer: 2, points: 1 },
      { q_no: 5, question: 'RBI का मुख्यालय कहाँ है?', options: ['दिल्ली', 'मुंबई', 'कोलकाता', 'चेन्नई'], correct_answer: 1, points: 1 }
    ]
  },
  yearly: {
    titlePrefix: 'Yearly Grand Lucky Draw',
    description: 'Annual grand lucky draw — 1 lucky winner takes it all!',
    game_type: 'mcq',
    entry_fee: 1000,
    prizes: { first: 100000, second: 0, third: 0 },
    questions: [
      { q_no: 1, question: 'भारत रत्न पुरस्कार कब शुरू हुआ?', options: ['1950', '1952', '1954', '1956'], correct_answer: 2, points: 1 },
      { q_no: 2, question: 'ISRO का मुख्यालय कहाँ है?', options: ['दिल्ली', 'मुंबई', 'बेंगलुरु', 'हैदराबाद'], correct_answer: 2, points: 1 },
      { q_no: 3, question: 'भारतीय रुपये का चिह्न (₹) किसने डिज़ाइन किया?', options: ['डी. उदय कुमार', 'रघुराम राजन', 'अमर्त्य सेन', 'ए.पी.जे. अब्दुल कलाम'], correct_answer: 0, points: 1 },
      { q_no: 4, question: 'विश्व का सबसे बड़ा देश (क्षेत्रफल) कौन सा है?', options: ['चीन', 'अमेरिका', 'कनाडा', 'रूस'], correct_answer: 3, points: 1 },
      { q_no: 5, question: 'पहला कंप्यूटर वायरस कौन सा था?', options: ['ILOVEYOU', 'Creeper', 'Brain', 'MyDoom'], correct_answer: 1, points: 1 }
    ]
  }
};

// Auto-create quiz for next period if not exists (max 1 active per type)
async function autoCreateQuizzes() {
  try {
    const now = new Date();
    const yr = now.getFullYear();
    const mo = now.getMonth(); // 0-based

    // Check existing active quizzes per type
    const activeMonthly = await Quiz.findOne({ type: 'monthly', status: { $in: ['active', 'upcoming'] } });
    const activeHalf    = await Quiz.findOne({ type: 'half_yearly', status: { $in: ['active', 'upcoming'] } });
    const activeYearly  = await Quiz.findOne({ type: 'yearly', status: { $in: ['active', 'upcoming'] } });

    // --- Monthly Quiz (only if no active monthly exists) ---
    const monthId = `M${String(yr).slice(2)}${String(mo+1).padStart(2,'0')}`;
    const existsMonthly = await Quiz.findOne({ quiz_id: monthId });
    if (!existsMonthly && !activeMonthly) {
      const monthStart = new Date(yr, mo, 1);
      const monthEnd = new Date(yr, mo+1, 0); // last day
      const monthResult = new Date(yr, mo+1, 10); // 10th of next month
      const t = quizTemplates.monthly;
      await Quiz.create({
        quiz_id: monthId,
        title: `${t.titlePrefix} — ${new Date(yr, mo).toLocaleString('en',{month:'long'})} ${yr}`,
        description: t.description,
        type: 'monthly',
        game_type: t.game_type,
        entry_fee: t.entry_fee,
        start_date: monthStart,
        end_date: monthEnd,
        result_date: monthResult,
        status: 'active',
        prizes: t.prizes,
        questions: t.questions
      });
      console.log(`✅ Auto-created monthly quiz: ${monthId}`);
    }

    // --- Half-Yearly Quiz (only if no active half-yearly exists) ---
    const half = mo < 6 ? 'H1' : 'H2';
    const halfId = `H${String(yr).slice(2)}${half}`;
    const existsHalf = await Quiz.findOne({ quiz_id: halfId });
    if (!existsHalf && !activeHalf) {
      const halfStart = mo < 6 ? new Date(yr, 0, 1) : new Date(yr, 6, 1);
      const halfEnd = mo < 6 ? new Date(yr, 5, 30) : new Date(yr, 11, 31);
      const halfResult = mo < 6 ? new Date(yr, 6, 10) : new Date(yr+1, 0, 10);
      const t = quizTemplates.half_yearly;
      await Quiz.create({
        quiz_id: halfId,
        title: `${t.titlePrefix} — ${half === 'H1' ? 'Jan-Jun' : 'Jul-Dec'} ${yr}`,
        description: t.description,
        type: 'half_yearly',
        game_type: t.game_type,
        entry_fee: t.entry_fee,
        start_date: halfStart,
        end_date: halfEnd,
        result_date: halfResult,
        status: 'active',
        prizes: t.prizes,
        questions: t.questions
      });
      console.log(`✅ Auto-created half-yearly quiz: ${halfId}`);
    }

    // --- Yearly Quiz (only if no active yearly exists) ---
    const yearId = `Y${String(yr).slice(2)}`;
    const existsYearly = await Quiz.findOne({ quiz_id: yearId });
    if (!existsYearly && !activeYearly) {
      const yearStart = new Date(yr, 0, 1);
      const yearEnd = new Date(yr, 11, 31);
      const yearResult = new Date(yr+1, 0, 10);
      const t = quizTemplates.yearly;
      await Quiz.create({
        quiz_id: yearId,
        title: `${t.titlePrefix} ${yr}`,
        description: t.description,
        type: 'yearly',
        game_type: t.game_type,
        entry_fee: t.entry_fee,
        start_date: yearStart,
        end_date: yearEnd,
        result_date: yearResult,
        status: 'active',
        prizes: t.prizes,
        questions: t.questions
      });
      console.log(`✅ Auto-created yearly quiz: ${yearId}`);
    }
  } catch(err) {
    console.error('❌ Auto-create quizzes error:', err.message);
    captureError(err, { context: 'auto-create-quizzes' });
  }
}

// Auto-draw results: random winner selection on result_date
async function autoDrawResults() {
  try {
    const now = new Date();
    // Find quizzes where result_date has passed and status is still 'active' or 'closed'
    const readyQuizzes = await Quiz.find({
      result_date: { $lte: now },
      status: { $in: ['active', 'closed'] },
      'winners.0': { $exists: false } // no winners yet
    });

    for (const quiz of readyQuizzes) {
      // Close enrollment first
      if (quiz.status === 'active') {
        quiz.status = 'closed';
      }

      // Get all participants (all are paid — payment verified at enrollment time)
      const participants = await QuizParticipation.find({
        quiz_ref: quiz.quiz_id
      }).lean();

      if (participants.length === 0) {
        quiz.status = 'result_declared';
        quiz.winners = [];
        await quiz.save();
        console.log(`📋 Quiz ${quiz.quiz_id}: No participants, result declared (no winners)`);
        continue;
      }

      // Random lucky draw — pick 1 winner from paid participants
      const luckyIndex = Math.floor(Math.random() * participants.length);
      const luckyOne = participants[luckyIndex];
      const prizeAmount = quiz.prizes?.first || 0;
      const user = await User.findById(luckyOne.user_id).lean();

      const winner = {
        rank: 1,
        user_id: luckyOne.user_id,
        member_id: user?.member_id || luckyOne.member_id || '',
        name: user?.name || luckyOne.name || 'Unknown',
        enrollment_number: luckyOne.enrollment_number || '',
        prize_amount: prizeAmount,
        score: luckyOne.score || 0
      };

      // Update winner participation
      await QuizParticipation.updateOne({ _id: luckyOne._id }, { status: 'won', prize_won: prizeAmount });

      // Credit prize to winner's points ledger
      if (prizeAmount > 0 && user) {
        await PointsLedger.create({
          user_id: user._id,
          type: 'quiz_prize',
          points: prizeAmount,
          description: `🎉 Lucky Draw Winner — ${quiz.title}`,
          reference_id: quiz.quiz_id
        });
        await User.findByIdAndUpdate(user._id, {
          $inc: { wallet_balance: prizeAmount, lifetime_earned: prizeAmount }
        });
      }

      // Mark others as lost
      await QuizParticipation.updateMany(
        { quiz_ref: quiz.quiz_id, user_id: { $ne: luckyOne.user_id } },
        { status: 'lost' }
      );

      quiz.winners = [winner];
      quiz.status = 'result_declared';
      await quiz.save();

      // Send SMS to lucky draw winner
      if (user?.mobile) {
        sendQuizResultSms({ mobile: user.mobile, name: winner.name, quizId: quiz.quiz_id })
          .catch(e => console.error('⚠️ SMS quiz result (auto-draw):', e.message));
      }

      console.log(`� Quiz ${quiz.quiz_id}: Lucky draw result! Winner: ${winner.name} (₹${prizeAmount})`);
    }

    // Also close quizzes past end_date that are still 'active'
    await Quiz.updateMany(
      { end_date: { $lt: now }, status: 'active' },
      { $set: { status: 'closed' } }
    );
  } catch(err) {
    console.error('❌ Auto-draw results error:', err.message);
    captureError(err, { context: 'auto-draw-results' });
  }
}

// ========================
// PUBLIC RECEIPT VIEW
// ========================

// Helper: generate branded HTML receipt page
function receiptHTML(r) {
  const backendUrl = process.env.BACKEND_URL || 'https://api.fwfindia.org';
  const typeLabel = r.type === 'membership' ? 'Membership Fee' : r.type === 'donation' ? 'Donation' : r.type === 'renewal' ? 'Membership Renewal' : r.type === 'quiz' ? 'Quiz Entry' : 'Payment';
  const dateStr = new Date(r.created_at).toLocaleDateString('en-IN', { day: '2-digit', month: 'long', year: 'numeric' });
  const lineItemsHtml = (r.line_items || []).map(li => `
    <tr>
      <td style="padding:10px 14px;color:#374151">${li.name}${li.description ? `<br><span style="color:#9ca3af;font-size:12px">${li.description}</span>` : ''}</td>
      <td style="padding:10px 14px;text-align:center;color:#374151">${li.quantity || 1}</td>
      <td style="padding:10px 14px;text-align:right;color:#374151">₹${(li.amount || 0).toLocaleString('en-IN')}</td>
    </tr>`).join('');
  const taxRow = r.tax ? `<tr style="background:#f9fafb"><td colspan="2" style="padding:10px 14px;color:#6b7280;text-align:right">Tax (GST)</td><td style="padding:10px 14px;text-align:right;color:#374151">₹${r.tax.toLocaleString('en-IN')}</td></tr>` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Receipt ${r.receipt_id} – FWF</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',sans-serif;background:#f1f5f9;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:32px 16px}
    .page{max-width:680px;width:100%;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.12)}
    .header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);padding:40px 32px;text-align:center}
    .header .icon{font-size:48px;margin-bottom:12px}
    .header h1{color:#fff;font-size:26px;font-weight:700;margin-bottom:4px}
    .header .sub{color:#a0a0c0;font-size:14px}
    .badge{display:inline-block;background:rgba(255,255,255,.1);color:#a0c4ff;border:1px solid rgba(160,196,255,.3);border-radius:20px;padding:4px 14px;font-size:12px;margin-top:10px}
    .body{padding:32px}
    .receipt-id{color:#6b7280;font-size:13px;margin-bottom:20px}
    .receipt-id strong{color:#111827;font-size:16px;font-family:monospace}
    .info-table{width:100%;border-collapse:collapse;margin-bottom:24px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden}
    .info-table tr:nth-child(even){background:#f9fafb}
    .info-table td{padding:11px 16px;font-size:14px}
    .info-table td:first-child{color:#6b7280;width:40%}
    .info-table td:last-child{color:#111827;font-weight:500}
    .section-title{font-size:13px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;margin:24px 0 10px}
    .items-table{width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:16px}
    .items-table thead tr{background:#f9fafb}
    .items-table thead td{padding:10px 14px;font-size:12px;color:#6b7280;font-weight:600;text-transform:uppercase}
    .items-table tbody tr{border-top:1px solid #e5e7eb}
    .total-row td{padding:12px 14px;font-weight:700;font-size:16px;border-top:2px solid #e5e7eb;background:#f0fdf4}
    .total-row td:last-child{color:#059669;font-size:18px}
    .stamp{margin:28px 0;text-align:center}
    .stamp .paid-stamp{display:inline-block;border:3px solid #059669;color:#059669;border-radius:8px;padding:8px 28px;font-size:20px;font-weight:800;letter-spacing:.08em;opacity:.85;transform:rotate(-3deg)}
    .note-80g{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:16px;margin:20px 0;color:#166534;font-size:13px;line-height:1.6}
    .actions{display:flex;gap:12px;justify-content:center;margin:28px 0 8px;flex-wrap:wrap}
    .btn{padding:12px 24px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;border:none;text-decoration:none;display:inline-block}
    .btn-print{background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff}
    .btn-outline{background:#fff;color:#374151;border:1px solid #d1d5db}
    .footer{background:#f9fafb;padding:20px 32px;text-align:center;font-size:12px;color:#9ca3af;border-top:1px solid #e5e7eb}
    .footer a{color:#6b7280;text-decoration:none}
    @media print{
      body{background:#fff;padding:0}
      .page{box-shadow:none;border-radius:0}
      .actions{display:none}
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="header">
      <div class="icon">🧾</div>
      <h1>Payment Receipt</h1>
      <div class="sub">Foundris Welfare Foundation</div>
      <div class="badge">${typeLabel}</div>
    </div>
    <div class="body">
      <div class="receipt-id">Receipt No: <strong>${r.receipt_id}</strong></div>
      <div class="section-title">Customer Details</div>
      <table class="info-table">
        <tr><td>Name</td><td>${r.customer_name || '—'}</td></tr>
        ${r.customer_email ? `<tr><td>Email</td><td>${r.customer_email}</td></tr>` : ''}
        ${r.customer_mobile ? `<tr><td>Mobile</td><td>${r.customer_mobile}</td></tr>` : ''}
        ${r.member_id ? `<tr><td>Member ID</td><td>${r.member_id}</td></tr>` : ''}
        ${r.customer_pan ? `<tr><td>PAN</td><td>${r.customer_pan}</td></tr>` : ''}
        ${r.customer_address ? `<tr><td>Address</td><td>${r.customer_address}</td></tr>` : ''}
      </table>
      <div class="section-title">Payment Details</div>
      <table class="info-table">
        <tr><td>Receipt Date</td><td>${dateStr}</td></tr>
        <tr><td>Payment Type</td><td>${typeLabel}</td></tr>
        ${r.razorpay_payment_id ? `<tr><td>Transaction ID</td><td style="font-family:monospace;font-size:12px">${r.razorpay_payment_id}</td></tr>` : ''}
        ${r.razorpay_order_id ? `<tr><td>Order ID</td><td style="font-family:monospace;font-size:12px">${r.razorpay_order_id}</td></tr>` : ''}
      </table>
      ${(r.line_items && r.line_items.length > 0) ? `
      <div class="section-title">Items</div>
      <table class="items-table">
        <thead><tr><td>Description</td><td style="text-align:center">Qty</td><td style="text-align:right">Amount</td></tr></thead>
        <tbody>
          ${lineItemsHtml}
          ${taxRow}
          <tr class="total-row"><td colspan="2" style="text-align:right">Total Paid</td><td>₹${(r.total || 0).toLocaleString('en-IN')}</td></tr>
        </tbody>
      </table>` : `
      <div class="stamp"><div class="paid-stamp">✓ PAID — ₹${(r.total || 0).toLocaleString('en-IN')}</div></div>`}
      ${r.is_80g ? `<div class="note-80g">✅ <strong>80G Tax Deduction Eligible</strong><br>This donation is eligible for tax deduction under Section 80G of the Income Tax Act, 1961. Please retain this receipt for your tax records.<br><span style="color:#359e6c">• FWF is a registered NGO under FCRA and Section 80G</span></div>` : ''}
      <div class="actions">
        <button class="btn btn-print" onclick="window.print()">🖨 Print / Save PDF</button>
        <a class="btn btn-outline" href="https://fwfindia.org">Visit FWF</a>
      </div>
    </div>
    <div class="footer">
      Foundris Welfare Foundation (FWF) &nbsp;|&nbsp; <a href="mailto:support@fwfindia.org">support@fwfindia.org</a> &nbsp;|&nbsp; <a href="https://fwfindia.org">fwfindia.org</a>
    </div>
  </div>
</body>
</html>`;
}

// Public: view receipt by token (no auth required)
app.get('/receipt/:token', async (req, res) => {
  try {
    const receipt = await Receipt.findOneAndUpdate(
      { token: req.params.token },
      { $inc: { views: 1 }, $set: { viewed_at: new Date(), status: 'viewed' } },
      { new: true }
    ).lean();
    if (!receipt) return res.status(404).send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:60px">
        <h2 style="color:#ef4444">Receipt Not Found</h2>
        <p>This receipt link may be invalid or expired.</p>
        <a href="https://fwfindia.org" style="color:#2563eb">Return to FWF</a>
      </body></html>`);
    res.setHeader('Content-Type', 'text/html');
    res.send(receiptHTML(receipt));
  } catch (err) {
    captureError(err, { context: 'receipt-view' });
    res.status(500).send('<h2>Error loading receipt</h2>');
  }
});

// Schedule: Run every hour
function startQuizScheduler() {
  // Run immediately on start
  autoCreateQuizzes();
  autoDrawResults();
  
  // Then every hour (3600000 ms)
  setInterval(() => {
    autoCreateQuizzes();
    autoDrawResults();
  }, 60 * 60 * 1000);
  console.log('⏰ Quiz scheduler started (runs every hour)');
}

// Start server
async function startServer() {
  await connectDB();
  await seedData();
  startQuizScheduler();
  app.listen(PORT, () => {
    console.log(`🚀 FWF backend running on http://localhost:${PORT}`);
    console.log(`📦 Database: MongoDB Atlas`);
    console.log(`🌐 Site served from: ${siteRoot}`);
    // ── Email config check ──
    const resendKey = process.env.RESEND_API_KEY;
    const mailFrom  = process.env.MAIL_FROM;
    console.log(`📧 RESEND_API_KEY : ${resendKey  ? '✅ SET (' + resendKey.slice(0,8) + '...)' : '❌ MISSING'}`);
    console.log(`📧 MAIL_FROM      : ${mailFrom   ? '✅ ' + mailFrom : '❌ MISSING'}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

