# 📚 Attendance Management System

A secure, enterprise-grade attendance management system built with Node.js and Express.js, featuring advanced encryption, role-based access control, and comprehensive audit logging.

## ✨ Key Features

- **🔐 End-to-End Encryption**: All user data encrypted with asymmetric cryptography (RSA-2048 & ECC P-256)
- **👥 Role-Based Access Control**: Student and Admin/Faculty roles with granular permissions
- **🔑 Key Management**: Automatic key generation, secure storage, and rotation mechanisms
- **� Email Verification**: Two-step verification via Mailjet with 24-hour token expiration
- **�📝 Attendance Tracking**: Student submission and admin review workflows
- **🛡️ Security Audit Logging**: Complete audit trails for all operations
- **🔄 Session Management**: Secure sessions with remember-me functionality
- **✅ Data Integrity**: HMAC-SHA256 validation for all sensitive data
- **☁️ Cloud Ready**: Deployed on Vercel serverless platform

## 🛠 Tech Stack

**Backend:**
- Node.js with Express.js
- MySQL 8.0+ database
- Asymmetric Encryption (RSA-2048, ECC P-256)
- Session Management (express-session with MySQL store)
- Password Hashing (bcrypt)

**Frontend:**
- HTML5 with vanilla JavaScript
- Responsive design for mobile & desktop
- Secure cookie-based authentication

**Deployment:**
- Vercel serverless platform
- Environment-based configuration
- MySQL database on cloud hosting

## 📋 Requirements Met

| Requirement | Status | Implementation |
|-------------|--------|-----------------|
| User Authentication & Registration | ✅ | Email domain validation, bcrypt hashing, encryption at registration |
| Two-Step Email Verification | ✅ | Mailjet API, 24-hour token expiration, auto-verification link |
| Data Encryption - Asymmetric Only | ✅ | RSA-2048 for names/IDs, ECC P-256 for emails |
| Password Security | ✅ | bcrypt with 10 salt rounds |
| Two Different Algorithms | ✅ | RSA-2048 + ECC P-256 |
| Key Management | ✅ | Per-user keys, rotation, audit logging |
| RBAC System | ✅ | 2 roles, 17 total permissions |
| Secure Sessions | ✅ | httpOnly secure cookies, 24-hour expiration |
| Message Authentication | ✅ | HMAC-SHA256 with timing-attack resistance |
| Audit Logging | ✅ | Complete operation trails |
| No Plaintext Storage | ✅ | All PII encrypted before DB storage |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/C-Holt-1K92R9/cse423_attendence.git
cd "attendence project"

# Install dependencies
npm install

# Create .env file with your configuration
cp .env.example .env
```

### Environment Variables

```env
# Database
DB_HOST=your_mysql_host
DB_USER=your_mysql_user
DB_PASSWORD=your_mysql_password
DB_NAME=attendance_db

# Session
SESSION_SECRET=your_random_secret_key

# Email Service (Mailjet)
MJ_APIKEY_PUBLIC=your_mailjet_public_key
MJ_APIKEY_PRIVATE=your_mailjet_private_key
FROM_EMAIL=noreply@yourdomain.com
BASE_URL=http://localhost:3000

# Server
PORT=3000
NODE_ENV=development
```

### Database Setup

```bash
# Run database initialization
mysql -h $DB_HOST -u $DB_USER -p $DB_NAME < database-update.sql
```

### Running Locally

```bash
# Start the server
npm start

# Server runs on http://localhost:3000
```

## 📚 API Documentation

### Authentication Endpoints

**POST /api/register**
- Register new user with email domain validation
- Automatically generates encryption keys
- Sends verification email via Mailjet
- Returns: `{ userId, encryptionEnabled: true, verificationRequired: true }`

**POST /api/login**
- Login with email and password
- Checks if email is verified (blocks unverified users)
- Sets secure session cookie
- Returns: `{ success: true, userType }`

**POST /api/logout**
- Clears session and remember-me tokens
- Returns: `{ success: true }`

**POST /api/verify-email**
- Verify user email with token from verification email
- Accepts: `{ token: "verification_token" }`
- Validates token expiration (24 hours)
- Updates `verified = 1` on success
- Returns: `{ success: true, userEmail: "user@domain.com" }`

**GET /verify-email**
- HTML verification page (called from email link)
- Auto-submits verification token to `/api/verify-email`
- Displays success/error message with redirect to login

### Profile Endpoints

**GET /api/profile**
- Fetch decrypted user profile data
- Returns: `{ name, email, student_id, encrypted, integrityValid }`

**POST /api/profile/update**
- Update user profile with new encrypted data
- Optional password change via bcrypt
- Returns: Success/error message

### Attendance Endpoints

**GET /api/attendance**
- Get student's attendance records
- Returns: Array of attendance entries

**POST /api/attendance/submit**
- Submit attendance for current session
- Returns: `{ success: true, submissionId }`

### Security Endpoints

**GET /api/security/key-status**
- Check encryption key status and rotation needs
- Returns: Key metadata and rotation schedule

**GET /api/security/access-log**
- View access control audit log (admin only)
- Returns: Array of access attempts

**GET /api/security/permissions**
- Check current user's permissions
- Returns: List of allowed operations

### Debug Endpoints (Development Only)

**GET /debug/test-keys/:userId**
- Test key retrieval for a user
- Shows key formats and validation status

**POST /debug/test-encrypt**
- Test full encryption cycle
- Returns encryption results for debugging

See [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for detailed endpoint specifications.

## 🔐 Security Architecture

### Data Encryption

**User Names & Student IDs:**
- Algorithm: RSA-2048 with OAEP padding
- Encoding: Base64 for safe transport
- Usage: User identification data

**Email Addresses:**
- Algorithm: ECC P-256 with HKDF-SHA256
- Key Derivation: HKDF-SHA256 with random salt
- Stream Cipher: XOR with derived key
- Usage: Communication and contact data

### Key Management

```
Registration Flow:
1. User account created (get user ID)
2. RSA-2048 & ECC P-256 keys generated
3. Keys stored in encryption_keys table
4. HMAC secrets generated for integrity
5. User data encrypted with public keys
6. Encrypted data stored with HMAC tags
```

**Key Storage:**
- Private keys: Encrypted in database (PEM format)
- Public keys: Available for encryption operations
- HMAC Secrets: 32-byte random values
- All keys are per-user (unique to each user)

### Database Security

```sql
-- Key Storage
encryption_keys(user_id, key_type, public_key, private_key, status, created_at)

-- Integrity Verification
hmac_secrets(user_id, secret_key, is_active, status, created_at)

-- Audit Trail
key_audit_log(user_id, action, key_type, details, created_at)
access_control_log(user_id, action, resource, result, created_at)
data_integrity_log(user_id, operation, data_hash, verified, created_at)
```

**Encrypted User Data:**
- `name_encrypted`: RSA-encrypted user full name
- `email_encrypted`: ECC-encrypted email address
- `student_id_encrypted`: RSA-encrypted student ID
- `data_integrity_tag`: HMAC-SHA256 tag for verification

### Authentication & Sessions

- **Password Hashing**: bcrypt with 10 salt rounds
- **Session Storage**: MySQL-backed express-session
- **Cookie Security**: httpOnly, Secure (in production), SameSite flags
- **Session Duration**: 24 hours with automatic expiration
- **Remember-Me**: Optional persistent tokens with salted hashing

### Access Control

**Student Permissions (type 0):**
- `view_own_profile` - View personal data
- `edit_own_profile` - Update personal information
- `submit_attendance` - Record attendance
- `view_attendance_records` - View personal records

**Admin/Faculty Permissions (type 1):**
- `view_all_users` - Browse all user accounts
- `edit_any_user` - Modify any user data
- `delete_user` - Remove user accounts
- `manage_permissions` - Configure access control
- `view_audit_logs` - Access security logs
- `manage_keys` - Handle encryption keys
- `manage_attendance` - Review attendance data
- `export_data` - Generate reports
- `rotate_keys` - Trigger key rotation

## 📁 Project Structure

```
attendence project/
├── server.js                    # Main Express application
├── encryption.js                # RSA & ECC implementations
├── key-management.js            # Key generation & storage
├── hmac.js                       # HMAC validation
├── rbac.js                       # Role-based access control
├── check_isp.js                  # Email domain validation
├── asn.js                        # Helper utilities
├── package.json                  # Dependencies & scripts
├── database-update.sql           # Database schema & tables
├── vercel.json                   # Vercel configuration
├── IMPLEMENTATION_SUMMARY.md     # Detailed technical documentation
├── VERCEL_DEPLOYMENT.md          # Deployment instructions
├── requirements.md               # Original requirements
│
├── public/                       # Frontend files
│   ├── index.html                # Login page
│   ├── register.html             # Registration page
│   ├── student.html              # Student dashboard
│   ├── profile.html              # User profile management
│   ├── admin.html                # Admin dashboard
│   ├── id_submission.html        # Attendance submission
│   └── manual.html               # User manual
│
└── Backup/
    ├── server copy.js            # Backup of server code
    ├── database.sql              # Initial schema
    └── database-update.sql       # Schema updates
```

## 🧪 Testing

### Manual Testing

**Test User Registration:**
```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullname": "Test User",
    "email": "test@g.bracu.ac.bd",
    "student_id": "A12345",
    "password": "TestPass123!"
  }'
```

**Test Profile Retrieval:**
```bash
curl -X GET http://localhost:3000/api/profile \
  -H "Cookie: remember_me=your_token" \
  -H "Content-Type: application/json"
```

**Test Encryption Debug:**
```bash
curl -X POST http://localhost:3000/debug/test-encrypt \
  -H "Content-Type: application/json"
```

### Verification Checklist

- ✅ User registration generates keys successfully
- ✅ Encrypted fields stored in database
- ✅ Profile retrieval decrypts data correctly
- ✅ HMAC integrity verification passes
- ✅ Access logs record all operations
- ✅ Session management maintains authentication
- ✅ Role permissions enforced on endpoints

## 🚢 Deployment

### Vercel Deployment

```bash
# Login to Vercel
vercel login

# Configure environment variables in Vercel dashboard
# DATABASE_URL, SESSION_SECRET, etc.

# Deploy
vercel deploy

# Production URL: your-project.vercel.app
```

### Database on Cloud

Recommended:
- **AWS RDS** for MySQL
- **DigitalOcean Managed Database**
- **Azure Database for MySQL**
- **Heroku Postgres** (if migrating to PostgreSQL)

### Pre-Deployment Checklist

- [ ] All environment variables configured
- [ ] Database schema initialized
- [ ] Encryption keys generated for initial users
- [ ] SSL/TLS enabled on database connection
- [ ] CORS properly configured
- [ ] Error logging enabled
- [ ] Backup strategy in place
- [ ] Rate limiting configured (optional)

## 📖 Documentation

- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Complete technical documentation
- **[VERCEL_DEPLOYMENT.md](VERCEL_DEPLOYMENT.md)** - Deployment guide
- **[requirements.md](requirements.md)** - Original project requirements

## 🐛 Troubleshooting

### Common Issues

**"Failed to encrypt user data"**
- Check if encryption keys were generated successfully
- Verify database connection is working
- Check `/debug/test-encrypt` endpoint for detailed error info

**"HMAC verification failed"**
- Ensure data integrity hasn't been compromised
- Check if user's HMAC secret is stored correctly
- Verify no data modification between encryption and verification

**"Cannot retrieve private key"**
- Confirm user exists in encryption_keys table
- Check if key status is 'active'
- Verify no PEM format corruption

**"Session expired unexpectedly"**
- Check session store is connected to MySQL
- Verify SESSION_SECRET environment variable is set
- Check browser cookie settings allow httpOnly cookies

**"Verification email not received"**
- Verify Mailjet API keys are set correctly in environment variables
- Check spam/junk folder for verification email
- Verify sender email (`FROM_EMAIL`) is registered with Mailjet
- Check Mailjet account for email delivery logs

**"Cannot log in - 'Please verify your email' error"**
- User hasn't clicked verification link yet
- Check spam folder for verification email
- Verify token hasn't expired (24 hours)
- If expired, user must register again

**"Invalid verification token"**
- Token has expired (24-hour limit)
- User already verified this email
- Token is incorrect or tampered
- User must register again if token expired

For more troubleshooting, see Testing & Troubleshooting Guide in [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md#-testing--troubleshooting-guide).

## 🔄 Recent Updates (May 2026)

- ✅ Fixed registration key ordering (generate keys FIRST, then encrypt)
- ✅ Implemented profile data decryption (GET /api/profile)
- ✅ Implemented profile data re-encryption (POST /api/profile/update)
- ✅ Added PEM format validation in encryption module
- ✅ Added private key leak detection
- ✅ Improved error messages with debugging information
- ✅ Added debug endpoints for testing encryption cycle
- ✅ Fixed ECC KeyObject conversion for crypto operations

## 📝 License

This project is part of the CSE 423 course at BRACU.

## 👨‍💻 Contributors

- **Project Lead**: C-Holt-1K92R9

## 📞 Support

For issues, questions, or feature requests:
1. Check [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for detailed documentation
2. Review debug endpoints at `/debug/test-keys/:userId` and `/debug/test-encrypt`
3. Check Vercel logs for production errors
4. Inspect database tables for data integrity issues

## 🔒 Security Notice

This system implements enterprise-grade security with:
- ✅ No plaintext user data stored in database
- ✅ Asymmetric encryption for all PII
- ✅ Two different encryption algorithms (RSA + ECC)
- ✅ HMAC integrity verification
- ✅ Audit logging for all operations
- ✅ Role-based access control
- ✅ Secure session management

**Important**: Keep your `.env` file and database credentials secure. Never commit sensitive information to version control.

---

**Last Updated**: May 2026 | **Version**: 1.0.0
