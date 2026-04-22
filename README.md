# NestFinder CUK 🏠

> **Safe, verified student housing near the Cooperative University of Kenya — and Airbnb-style short stays.**

Live at → **[nestfindercuk.rocks](https://nestfindercuk.rocks)**

---

## What It Does

NestFinder CUK is a full-stack housing platform built specifically for CUK students. It solves the problem of students arriving in Gataka and Rongai with nowhere to stay — by listing verified, photo-verified rooms with real caretaker contacts unlocked through a one-time M-Pesa payment.

It also supports **Airbnb-style short-stay listings** for guests, visitors, and students who need temporary accommodation.

---

## Features

### For Students / Guests
- Browse verified listings with real photos — free, no sign-in required
- Filter by room type, price, amenities (water, WiFi), availability
- Filter by listing type — Student Rental or Airbnb / Short Stay
- View approximate location map per listing
- Save favourites (persisted locally)
- Pay via M-Pesa to unlock caretaker contact (one-time fee)
- Promo/referral code system — refer a friend, they unlock contact free
- Rate and review listings after moving in
- Report suspicious listings
- Submit and track M-Pesa payment status in real time

### For Airbnb Listings
- Per-night pricing, max guests, minimum nights
- Date picker (check-in / check-out) at booking
- 🌙 Short Stay badge on listing cards
- Booking fee: Ksh 150 (vs Ksh 250+ for rentals)

### For Admin
- Secure admin panel (role-based access)
- Add, edit, delete listings with photo upload
- Set listing type: Student Rental or Airbnb / Short Stay
- Search & pin location (Nominatim geocoding → saves lat/lng)
- Confirm or deny M-Pesa payments
- View all student profiles and payment history
- Generate referral promo codes on payment confirmation
- Receive email notification (Resend) on new payment submission
- M-Pesa STK push integration (Safaricom Daraja API)
- Report management

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla HTML, CSS, JS — no framework |
| Backend DB | Supabase (PostgreSQL + Auth + Storage) |
| API Routes | Vercel Serverless Functions (Node.js) |
| Payments | M-Pesa Daraja API (STK Push + Callback) |
| Email | Resend (admin notifications) |
| Maps | Leaflet + OpenStreetMap |
| Hosting | Vercel |
| CDN / Assets | Supabase Storage (house photos) |

---

## Project Structure

```
NestFinder-CUK/
├── index.html          # Main public listing page
├── admin.html          # Admin panel (role-gated)
├── login.html          # Auth page
├── api/
│   ├── mpesa-stk.js        # Initiate STK push
│   ├── mpesa-callback.js   # Safaricom callback handler
│   ├── mpesa-check.js      # Poll payment status
│   ├── notify.js           # Email admin on payment
│   ├── notify-student.js   # Email student on confirm
│   ├── generate-promo.js   # Generate referral code
│   ├── redeem-promo.js     # Validate & redeem promo
│   ├── report.js           # Submit listing report
│   └── security.js         # Security utilities
├── sw.js               # Service worker (cache, offline)
├── vercel.json         # Vercel config + CSP headers
└── README.md
```

---

## Database Schema (Supabase)

### `listings`
| Column | Type | Notes |
|--------|------|-------|
| id | uuid | PK |
| title | text | |
| type | text | single / bedsitter / one-bedroom |
| listing_type | text | rental / airbnb |
| price | int | Monthly rent (rentals) |
| price_per_night | int | Nightly rate (Airbnb) |
| max_guests | int | Airbnb only |
| min_nights | int | Airbnb only |
| contact_fee | int | One-time unlock fee |
| location | text | Human-readable address |
| latitude | float | Pinned coordinates |
| longitude | float | Pinned coordinates |
| description | text | |
| water_included | bool | |
| wifi_available | bool | |
| available | bool | |
| photos | text[] | Supabase storage URLs |

### `payments`
| Column | Type | Notes |
|--------|------|-------|
| id | uuid | PK |
| user_id | uuid | FK → profiles |
| listing_id | uuid | FK → listings |
| amount | int | Ksh |
| mpesa_ref | text | M-Pesa confirmation code |
| status | text | pending / confirmed / denied |
| checkin_date | date | Airbnb bookings |
| checkout_date | date | Airbnb bookings |

### `promo_codes`
| Column | Type | Notes |
|--------|------|-------|
| id | uuid | PK |
| code | text | e.g. NEST-A3X9K2 |
| owner_user_id | uuid | Who earned it |
| is_used | bool | |
| used_by_user_id | uuid | Who redeemed it |

### Other tables
- `profiles` — user roles, full name, phone
- `caretaker_contacts` — unlocked per listing per user
- `reviews` — star ratings + comments
- `reports` — flagged listings

---

## Environment Variables

Set these in Vercel → Settings → Environment Variables:

```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_KEY=your_service_role_key   # server-side only
MPESA_CONSUMER_KEY=your_daraja_consumer_key
MPESA_CONSUMER_SECRET=your_daraja_secret
MPESA_SHORTCODE=your_till_or_paybill
MPESA_PASSKEY=your_lipa_na_mpesa_passkey
MPESA_CALLBACK_URL=https://nestfindercuk.rocks/api/mpesa-callback
RESEND_API_KEY=your_resend_key
ADMIN_EMAIL=your_admin_email
```

> ⚠️ Never commit `.env` files. Never expose `SUPABASE_SERVICE_KEY` in frontend code.

---

## Local Development

```bash
git clone https://github.com/waren23greg-stack/NestFinderCuk.git
cd NestFinderCuk

# Install Vercel CLI
npm i -g vercel

# Run locally (serverless functions work too)
vercel dev
```

Open `http://localhost:3000`

---

## Deployment

Pushes to `main` auto-deploy via Vercel GitHub integration.

```bash
git add .
git commit -m "your message"
git push origin main
```

---

## Security

See `SECURITY.md` for full security audit and recommendations.

Key measures currently in place:
- Content Security Policy (CSP) via `vercel.json`
- Service worker intercepts same-origin requests only
- `SUPABASE_SERVICE_KEY` server-side only (never in browser)
- Promo codes generated server-side after DB-verified payment
- Payment references checked for duplicates before insert
- Admin panel role-gated (profile.role === 'admin')
- RLS enabled on Supabase tables

---

## Contributing

This is a private project for Cooperative University of Kenya students. Contact the maintainer via WhatsApp: **0704 285 315**

---

## License

Private — © 2025 NestFinder CUK. All rights reserved.
