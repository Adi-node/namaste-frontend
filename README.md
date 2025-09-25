# NAMASTE FHIR R4 Backend - Secure Healthcare Terminology Microservice

A production-ready, FHIR R4–compliant terminology micro-service built to India's 2016 EHR Standards with comprehensive authentication, role-based access control, and audit logging capabilities.

## 🏗️ Enhanced Architecture Overview

### Core Features
- **FHIR R4 compliant** terminology services
- **JWT-based authentication** with secure session management
- **Role-Based Access Control** (Admin & User roles)
- **Comprehensive audit logging** with full traceability
- **NAMASTE ↔ ICD-11** code mapping and translation
- **Electronic Health Records** management with dual coding
- **CSV/JSON conversion** for terminology data
- **Real-time audit dashboard** for administrators

### Technology Stack
- **Runtime**: Node.js with Express.js framework
- **Database**: Supabase (PostgreSQL with RLS policies)
- **Authentication**: JWT tokens with bcrypt password hashing
- **Authorization**: Role-based access control middleware
- **Logging**: Winston with structured audit trails
- **Security**: Helmet, express-rate-limit, CORS protection
- **Standards**: FHIR R4, India EHR 2016, OAuth 2.0 patterns

## 🔐 Security & Authentication Model

### User Roles
- **Admin**: Full system access + audit log viewing + user management
- **User**: Standard healthcare operations (no admin or audit access)

### Authentication Flow
1. User registration/login with email & password
2. Server generates JWT token with role claims
3. Client stores token securely (httpOnly cookie + localStorage fallback)
4. All API calls include Authorization header
5. Middleware validates token & checks permissions
6. All actions logged to audit trail

## 📋 Enhanced Database Schema

### Authentication & Authorization Tables

#### 1. `users` table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create default admin user
INSERT INTO users (email, password_hash, full_name, role) VALUES 
('admin@namaste.health', '$2b$12$hashedpassword', 'System Administrator', 'admin');
```

#### 2. `audit_logs` table
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,           -- e.g., 'CREATE_PATIENT', 'SEARCH_CODES'
    resource_type VARCHAR(50),              -- e.g., 'patient', 'namaste_code'
    resource_id UUID,                       -- ID of affected resource
    old_values JSONB,                       -- Previous state (for updates)
    new_values JSONB,                       -- New state
    ip_address INET,                        -- Client IP address
    user_agent TEXT,                        -- Browser/client info
    endpoint VARCHAR(255),                  -- API endpoint called
    http_method VARCHAR(10),                -- GET, POST, PUT, DELETE
    response_status INTEGER,                -- HTTP response code
    execution_time INTEGER,                 -- Response time in ms
    additional_data JSONB,                  -- Extra context data
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
```

#### 3. `sessions` table (optional - for enhanced session management)
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_accessed TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Original Healthcare Tables (Enhanced with audit triggers)

#### Enhanced `patient_records` table
```sql
CREATE TABLE patient_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_name VARCHAR(200) NOT NULL,
    age INTEGER,
    contact_number VARCHAR(20),
    diagnosis TEXT,
    namaste_code VARCHAR(50),
    icd11_code VARCHAR(50),
    treatment_summary TEXT,
    prescription TEXT,
    hospital_name VARCHAR(200),
    doctor_name VARCHAR(200),
    report_date DATE,
    created_by UUID REFERENCES users(id),    -- Track who created
    updated_by UUID REFERENCES users(id),    -- Track who modified
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 🔌 Enhanced API Endpoints

### Authentication Endpoints
```
POST   /api/auth/register              # User registration
POST   /api/auth/login                 # User login
POST   /api/auth/logout                # User logout
POST   /api/auth/refresh               # Refresh JWT token
GET    /api/auth/me                    # Get current user info
PUT    /api/auth/profile               # Update user profile
POST   /api/auth/change-password       # Change password
```

### User Management (Admin Only)
```
GET    /api/admin/users                # List all users
GET    /api/admin/users/:id            # Get specific user
PUT    /api/admin/users/:id/role       # Change user role
PUT    /api/admin/users/:id/status     # Activate/deactivate user
DELETE /api/admin/users/:id            # Delete user account
```

### Audit Log Endpoints (Admin Only)
```
GET    /api/admin/audit                # Get audit logs (paginated)
GET    /api/admin/audit/search         # Search audit logs
GET    /api/admin/audit/user/:id       # Get logs for specific user
GET    /api/admin/audit/stats          # Audit statistics
GET    /api/admin/audit/export         # Export audit logs (CSV/JSON)
```

### Protected Healthcare APIs (Require Authentication)
```
# All existing endpoints now require authentication
Authorization: Bearer <jwt-token>

# Code Management (User + Admin)
GET    /api/codes/search               # Search codes
GET    /api/codes/mappings             # View mappings
POST   /api/codes/map                  # Create mapping (logged)

# Patient Records (User + Admin)
GET    /api/patients                   # List patients
POST   /api/patients                   # Create patient (logged)
PUT    /api/patients/:id               # Update patient (logged)
DELETE /api/patients/:id               # Delete patient (logged)

# File Operations (User + Admin)
POST   /api/files/upload               # Upload CSV (logged)
POST   /api/files/convert              # Convert format (logged)
```

### FHIR R4 Endpoints (Authentication Required)
```
GET    /fhir/CodeSystem/NAMASTE        # FHIR CodeSystem
POST   /fhir/ConceptMap/$translate     # Code translation (logged)
POST   /fhir/Bundle                    # Bundle upload (logged)
```

## 🛡️ Security Implementation

### Authentication Middleware
```javascript
// JWT validation and user extraction
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};
```

### Authorization Middleware
```javascript
// Role-based access control
const requireRole = (roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};
```

### Audit Logging Middleware
```javascript
// Comprehensive action logging
const auditLog = (action) => {
    return (req, res, next) => {
        const originalSend = res.send;
        
        res.send = function(body) {
            // Log the action with full context
            logAuditEvent({
                userId: req.user?.id,
                action,
                endpoint: req.originalUrl,
                method: req.method,
                // ... more details
            });
            
            originalSend.call(this, body);
        };
        
        next();
    };
};
```

## 🎨 Enhanced Frontend Features

### New Authentication Components
1. **Login/Register Forms**
   - Secure authentication UI
   - Form validation and error handling
   - Remember me functionality

2. **Role-Based Navigation**
   - Dynamic menu based on user role
   - Admin-only sections hidden for users
   - User profile management

3. **Admin Audit Dashboard** (New Tab)
   - Real-time audit log viewer
   - Advanced search and filtering
   - Export functionality
   - User activity analytics

### Updated Frontend Structure
```
src/
├── components/
│   ├── auth/
│   │   ├── LoginForm.jsx
│   │   ├── RegisterForm.jsx
│   │   └── ProfileManager.jsx
│   ├── admin/
│   │   ├── AuditDashboard.jsx      # New audit log viewer
│   │   ├── UserManagement.jsx      # User admin panel
│   │   └── SystemStats.jsx         # System analytics
│   ├── common/
│   │   ├── ProtectedRoute.jsx      # Route guards
│   │   ├── RoleBasedAccess.jsx     # Component-level auth
│   │   └── LoadingSpinner.jsx
│   └── [existing components...]
├── hooks/
│   ├── useAuth.js                   # Authentication hook
│   ├── useAudit.js                  # Audit log management
│   └── useRBAC.js                   # Role-based access
└── services/
    ├── authService.js               # Auth API calls
    ├── auditService.js              # Audit API calls
    └── [existing services...]
```

## 🚀 Enhanced Setup Instructions

### Environment Configuration
```env
# Database
SUPABASE_URL=your_supabase_project_url
SUPABASE_ANON_KEY=your_supabase_anon_key

# Authentication
JWT_SECRET=your_super_secret_jwt_key_min_256_bits
JWT_EXPIRES_IN=24h
REFRESH_TOKEN_SECRET=your_refresh_token_secret

# Security
BCRYPT_ROUNDS=12
SESSION_SECRET=your_session_secret
RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
RATE_LIMIT_MAX=100           # 100 requests per window

# Server
PORT=3001
NODE_ENV=production
CORS_ORIGIN=http://localhost:5173

# Logging
LOG_LEVEL=info
LOG_FILE=./logs/app.log
AUDIT_LOG_RETENTION_DAYS=365
```

### Enhanced Dependencies
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "@supabase/supabase-js": "^2.38.0",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "joi": "^17.11.0",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "express-rate-limit": "^7.1.5",
    "winston": "^3.11.0",
    "multer": "^1.4.5-lts.1",
    "csv-parser": "^3.0.0",
    "uuid": "^9.0.1",
    "dotenv": "^16.3.1"
  }
}
```

## 📊 Audit Dashboard Features

### Admin Audit Dashboard
- **Real-time Activity Feed**: Live view of user actions
- **Advanced Search**: Filter by user, action type, date range, IP address
- **User Analytics**: Activity patterns and usage statistics  
- **Security Monitoring**: Failed login attempts, suspicious activity
- **Export Capabilities**: CSV/JSON export with date ranges
- **Performance Metrics**: API response times and usage patterns

### Audit Log Examples
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "userId": "user-uuid",
  "action": "CREATE_PATIENT",
  "resourceType": "patient",
  "resourceId": "patient-uuid",
  "oldValues": null,
  "newValues": {
    "patientName": "John Doe",
    "age": 45,
    "diagnosis": "Hypertension"
  },
  "ipAddress": "192.168.1.100",
  "endpoint": "/api/patients",
  "httpMethod": "POST",
  "responseStatus": 201,
  "executionTime": 245,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## 🔄 Development Phases

### Phase 1: Authentication Foundation ✅
- User registration/login system
- JWT token management  
- Password security (bcrypt)
- Basic middleware setup

### Phase 2: Authorization & RBAC ✅
- Role-based access control
- Route protection middleware
- Permission validation
- Admin/user role separation

### Phase 3: Audit System ✅
- Comprehensive logging middleware
- Audit database design
- Action tracking implementation
- Performance monitoring

### Phase 4: Admin Dashboard ✅
- Audit log viewer interface
- User management panel
- Search and filtering
- Real-time updates

### Phase 5: Security Hardening ✅
- Rate limiting implementation
- Security headers (Helmet)
- Session management
- Input validation (Joi)

### Phase 6: Testing & Deployment 🔄
- Authentication flow testing
- Role-based access testing
- Audit log verification
- Security penetration testing

## 🛡️ Security Best Practices Implemented

1. **Password Security**
   - Bcrypt with 12 salt rounds
   - Password complexity requirements
   - Secure password reset flow

2. **JWT Security**
   - Short expiration times
   - Secure secret management
   - Refresh token rotation

3. **API Protection**
   - Rate limiting per IP/user
   - Request size limits
   - SQL injection prevention

4. **Audit Security**
   - Tamper-proof log entries
   - Encrypted sensitive data
   - Retention policies

5. **Session Management**
   - Secure cookie settings
   - Session timeout handling
   - Concurrent session limits

## 📈 Production Considerations

### Monitoring & Alerting
- Failed authentication attempts monitoring
- Unusual audit log patterns
- Performance degradation alerts
- Security breach detection

### Compliance & Governance
- GDPR-compliant audit logs
- Healthcare data protection (HIPAA considerations)
- Data retention policies
- Regular security audits

This enhanced system provides enterprise-grade security while maintaining the healthcare terminology functionality, making it suitable for production deployment in healthcare environments.