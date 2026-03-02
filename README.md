# FWF - Foundris Welfare Foundation

> Skills to Livelihood Platform - Connecting training, projects, and earning opportunities

## 🎯 Overview

FWF is a comprehensive skills-to-livelihood platform that bridges the gap between skill training and sustainable income. We connect individuals with market-ready training programs and real business projects, enabling them to earn with dignity.

**Mission**: Link Skills → Work → Income with a clear pathway

## 🏗️ Architecture

The project uses a **dual-backend architecture** to separate concerns:

### Frontend
- Static HTML/CSS/JS site
- Bilingual support (English + Hindi)
- Deployed to Vercel

### Backend Systems

#### 1. Express Server (`/backend/`)
- **Database**: SQLite (better-sqlite3)
- **Purpose**: Member authentication, user management, wallet system
- **Tech**: Express.js + JWT auth in httpOnly cookies
- **Port**: 3000 (local development)

#### 2. Vercel Serverless Functions (`/api/`)
- **Database**: MongoDB Atlas
- **Purpose**: Contact forms, subscriptions, member registration
- **Tech**: Vercel Functions + Mongoose + Nodemailer
- **Deployment**: Auto-deployed by Vercel

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ (22.x recommended)
- npm or yarn
- MongoDB Atlas account (for serverless functions)
- SMTP credentials (for email)

### Installation

1. **Clone and Install**
```bash
git clone https://github.com/learn20441/fwf-site.git
cd fwf-site

# Install root dependencies (for Vercel functions)
npm install

# Install backend dependencies
cd backend
npm install
cd ..
```

2. **Environment Setup**

Create `.env` in project root:
```env
MONGODB_URI=your_mongodb_atlas_uri
MAIL_FROM="FWF Support <support@yourdomain.com>"
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
BACKEND_URL=http://localhost:3000
```

Create `backend/.env`:
```env
PORT=3000
JWT_SECRET=your_long_random_secret_here
ORG_PREFIX=FWF
ADMIN_USER=admin@fwf
ADMIN_PASS=Admin@12345
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

3. **Run Development Server**
```bash
cd backend
npm start
```

Server will be available at `http://localhost:3000`

## 📁 Project Structure

```
/
├── index.html              # Main landing page
├── join.html               # Membership registration form
├── join-payment.html       # Payment completion page
├── member-login.html       # Member login
├── member-dashboard.html   # Member dashboard
├── admin-login.html        # Admin login
├── admin-dashboard.html    # Admin panel
├── auth.js                 # Client-side auth helper
├── package.json            # Vercel functions dependencies
├── vercel.json             # Vercel configuration
│
├── api/                    # Vercel serverless functions
│   ├── contact.js          # Contact form handler
│   ├── join.js             # Member registration
│   ├── subscribe.js        # Newsletter subscription
│   ├── privacy.js          # Privacy policy acceptance
│   └── terms.js            # Terms acceptance
│
├── backend/                # Express server
│   ├── server.js           # Main server file
│   ├── package.json        # Backend dependencies
│   ├── .env.example        # Backend env template
│   └── data/
│       └── fwf.db          # SQLite database (auto-created)
│
├── lib/                    # Shared utilities
│   ├── db.js               # MongoDB connection
│   └── mailer.js           # Email transporter
│
├── models/                 # Mongoose schemas
│   ├── Contact.js
│   ├── Member.js
│   └── Subscription.js
│
└── assets/                 # Static assets
    ├── css/
    ├── images/
    └── js/
```

## 🔐 Authentication Flow

### Member Registration
1. User fills form at `/join.html`
2. User completes payment at `/join-payment.html`
3. Form submits to `/api/join` (serverless function)
4. Function calls backend `/api/pay/simulate-join`
5. Backend creates user in SQLite + generates credentials
6. MongoDB stores additional details
7. Email sent with Member ID and Password

### Login
- Members: `/member-login.html` → JWT cookie → `/member-dashboard.html`
- Admin: `/admin-login.html` → JWT cookie → `/admin-dashboard.html`

### Protected Routes
Backend uses `auth(role)` middleware to protect routes:
```javascript
app.get('/api/member/me', auth('member'), handler);
app.get('/api/admin/overview', auth('admin'), handler);
```

## 🗄️ Database Schema

### SQLite (Backend)
```sql
users:
  - id, member_id, name, mobile, email
  - password_hash, role, membership_active
  - created_at

wallets:
  - user_id, balance_inr
  - lifetime_earned_inr, lifetime_applied_inr
  - updated_at

member_projects:
  - user_id, project_name, project_cost
  - target60_inr, wallet_applied_inr
  - eligible_flag
```

### MongoDB (Serverless)
```javascript
Member: { fullName, mobile, email, aadhar, pan, project, paymentRef }
Contact: { name, email, phone, message }
Subscription: { email, isActive, subscribedAt }
```

## 🌐 API Endpoints

### Backend (Express)
- `POST /api/pay/simulate-join` - Register new member
- `POST /api/auth/login` - Member login
- `POST /api/admin/login` - Admin login
- `POST /api/auth/logout` - Logout
- `GET /api/member/me` - Get member data (protected)
- `POST /api/member/apply-wallet` - Apply wallet to project (protected)
- `GET /api/admin/overview` - Admin dashboard (protected)

### Serverless Functions
- `POST /api/join` - Member registration (calls backend)
- `POST /api/contact` - Contact form
- `POST /api/subscribe` - Newsletter subscription
- `POST /api/privacy` - Privacy policy acceptance
- `POST /api/terms` - Terms acceptance

## 🚢 Deployment

### Vercel (Frontend + Serverless)
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel
```

### Backend Server
Deploy to your preferred hosting (Railway, Render, AWS, etc.)

Update `BACKEND_URL` in root `.env` to point to your deployed backend.

## 🔧 Development

### Start Backend
```bash
cd backend
npm start
```

### Test Serverless Functions Locally
```bash
vercel dev
```

## 📝 Environment Variables

### Required for Root (Serverless)
- `MONGODB_URI` - MongoDB Atlas connection string
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` - Email credentials
- `MAIL_FROM` - Email sender
- `BACKEND_URL` - Backend Express server URL

### Required for Backend
- `JWT_SECRET` - Secret for JWT signing (use strong random string)
- `ADMIN_USER`, `ADMIN_PASS` - Admin credentials
- `ORG_PREFIX` - Member ID prefix (default: FWF)
- `ALLOWED_ORIGINS` - CORS allowed origins

## 🛡️ Security

- JWT tokens stored in httpOnly cookies
- CORS configured for allowed origins
- Security headers (CSP, XSS protection, etc.)
- Input validation on all forms
- SQL injection prevention via prepared statements
- Rate limiting (to be implemented)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

## 📄 License

This project is private and proprietary to Foundris Welfare Foundation.

## 📞 Contact

- **Email**: info@fwfindia.org
- **Phone**: +91-9580118412
- **Address**: 1398/1850 Sagarpuri Gallamandi, Kanpur - 208021 U.P India
- **Registration**: 12A • 80G • CSR-1

---

Built with ❤️ for empowering communities through skills and livelihood
