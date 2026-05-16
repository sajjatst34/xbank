# X Bank — Complete Banking System with Admin Panel

A full-featured Django banking application with a custom admin panel built for XAMPP/MySQL.

---

## 📁 Project Structure

```
Bank_System/
└── xbank/
    ├── banking/
    │   ├── models.py          ← All database models
    │   ├── views.py           ← User-facing banking views
    │   ├── admin_views.py     ← ✅ NEW: Admin panel views
    │   ├── admin_urls.py      ← ✅ NEW: Admin panel URL routes
    │   ├── urls.py            ← User-facing URLs
    │   ├── forms.py           ← Django forms
    │   ├── utils.py           ← OTP, TOTP, helpers
    │   └── middleware.py      ← Security middleware
    ├── xbank/
    │   ├── settings.py        ← Django settings
    │   └── urls.py            ← ✅ UPDATED: includes /panel/
    ├── templates/
    │   ├── banking/           ← User-facing templates
    │   └── admin_panel/       ← ✅ NEW: 17 admin templates
    ├── manage.py
    └── requirements.txt
```

---

## ⚡ Quick Setup (XAMPP)

### Step 1 — Start XAMPP (Apache + MySQL)

### Step 2 — Create Database in phpMyAdmin
```sql
CREATE DATABASE xbank_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Step 3 — Install Dependencies
```bash
cd Bank_System/xbank
pip install -r requirements.txt
```

### Step 4 — Run Migrations
```bash
python manage.py migrate
```

### Step 5 — Create Superuser (for Admin Panel)
```bash
python manage.py createsuperuser
```

### Step 6 — Run Server
```bash
python manage.py runserver
```

---

## 🌐 Access URLs

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:8000/` | Home page |
| `http://127.0.0.1:8000/register/` | User registration |
| `http://127.0.0.1:8000/login/` | User login |
| `http://127.0.0.1:8000/dashboard/` | User dashboard |
| `http://127.0.0.1:8000/panel/` | ✅ ADMIN PANEL |
| `http://127.0.0.1:8000/django-admin/` | Django built-in admin |

---

## 🛡️ Admin Panel Features

Access `/panel/` with any staff or superuser account.

- **Dashboard** — Stats, pending items, recent activity
- **Users** — Activate/deactivate, KYC verify, make staff, reset 2FA
- **KYC Verification** — Review pending identity documents
- **Accounts** — Freeze/activate/close, adjust balance
- **Transactions** — Full log, filter by type/date/status, reverse transactions
- **Loans** — Approve/reject/disburse loan applications
- **Savings** — View all FD/RD/DPS plans
- **Cards** — Block/activate cards
- **Bill Payments** — Full payment history
- **Mobile Recharges** — Recharge history
- **Donations** — Donation records
- **Audit Logs** — Security trail with IP tracking

---

## 🔑 Promote Existing User to Admin

```bash
python manage.py shell
```
```python
from banking.models import User
u = User.objects.get(username='your_username')
u.is_staff = True
u.is_superuser = True
u.save()
```
