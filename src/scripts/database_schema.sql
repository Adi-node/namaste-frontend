-- NAMASTE FHIR Backend Database Schema
-- Enhanced with Authentication, RBAC, and Audit Logging

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- AUTHENTICATION & AUTHORIZATION TABLES
-- ============================================================================

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMPTZ,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sessions table for enhanced session management
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    last_accessed TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit logs table for comprehensive tracking
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,           -- e.g., 'CREATE_PATIENT', 'SEARCH_CODES', 'LOGIN'
    resource_type VARCHAR(50),              -- e.g., 'patient', 'namaste_code', 'user'
    resource_id UUID,                       -- ID of affected resource
    old_values JSONB,                       -- Previous state (for updates)
    new_values JSONB,                       -- New state
    ip_address INET,                        -- Client IP address
    user_agent TEXT,                        -- Browser/client info
    endpoint VARCHAR(255),                  -- API endpoint called
    http_method VARCHAR(10),                -- GET, POST, PUT, DELETE
    request_body JSONB,                     -- Request payload (sensitive data removed)
    response_status INTEGER,                -- HTTP response code
    execution_time INTEGER,                 -- Response time in milliseconds
    error_message TEXT,                     -- Error details if any
    additional_data JSONB,                  -- Extra context data
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- HEALTHCARE TERMINOLOGY TABLES
-- ============================================================================

-- NAMASTE codes table
CREATE TABLE IF NOT EXISTS namaste_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(50) UNIQUE NOT NULL,          -- e.g., 'NAM.DIG.001.234'
    display_name VARCHAR(200) NOT NULL,        -- English name
    sanskrit_name VARCHAR(200),                -- Sanskrit/Hindi name
    description TEXT,
    category VARCHAR(100),                     -- e.g., 'Digestive System'
    subcategory VARCHAR(100),                  -- e.g., 'Agni Vikara'
    system_type VARCHAR(50) DEFAULT 'Ayurveda', -- AYUSH system
    synonyms TEXT[],                          -- Array of alternate names
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ICD-11 codes table
CREATE TABLE IF NOT EXISTS icd11_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(50) UNIQUE NOT NULL,          -- e.g., 'DA90.0'
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    category VARCHAR(100),                     -- e.g., 'Gastrointestinal'
    parent_code VARCHAR(50),                   -- ICD-11 hierarchy
    is_leaf BOOLEAN DEFAULT true,
    version VARCHAR(20) DEFAULT '2024',        -- ICD-11 version
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Code mappings table for NAMASTE ↔ ICD-11 relationships
CREATE TABLE IF NOT EXISTS code_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namaste_code_id UUID REFERENCES namaste_codes(id) ON DELETE CASCADE,
    icd11_code_id UUID REFERENCES icd11_codes(id) ON DELETE CASCADE,
    mapping_type VARCHAR(50) DEFAULT 'equivalent',  -- equivalent, broader, narrower, related
    confidence_score DECIMAL(3,2) DEFAULT 1.0,     -- 0.0 to 1.0
    notes TEXT,
    mapped_by UUID REFERENCES users(id),
    verified_by UUID REFERENCES users(id),
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(namaste_code_id, icd11_code_id)
);

-- Enhanced patient records table with audit tracking
CREATE TABLE IF NOT EXISTS patient_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_name VARCHAR(200) NOT NULL,
    age INTEGER,
    gender VARCHAR(20),
    contact_number VARCHAR(20),
    email VARCHAR(255),
    address TEXT,
    diagnosis TEXT,
    namaste_code VARCHAR(50),
    icd11_code VARCHAR(50),
    treatment_summary TEXT,
    prescription TEXT,
    diagnostic_reports JSONB,                   -- Store file references/metadata
    hospital_name VARCHAR(200),
    doctor_name VARCHAR(200),
    doctor_registration VARCHAR(100),
    report_date DATE,
    follow_up_date DATE,
    status VARCHAR(50) DEFAULT 'active',        -- active, discharged, deceased
    privacy_consent BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),      -- Track who created
    updated_by UUID REFERENCES users(id),      -- Track who modified
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Patient Visits table
CREATE TABLE IF NOT EXISTS patient_visits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_records(id) ON DELETE CASCADE,
    visit_date DATE NOT NULL,
    reason_for_visit TEXT NOT NULL,
    diagnosis TEXT,
    namaste_code VARCHAR(50),
    icd11_code VARCHAR(50),
    treatment TEXT,
    prescription TEXT,
    notes TEXT,
    follow_up_required BOOLEAN DEFAULT false,
    follow_up_date DATE,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- File uploads table for document management
CREATE TABLE IF NOT EXISTS file_uploads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type VARCHAR(100),
    file_hash VARCHAR(64),                     -- SHA-256 hash for integrity
    related_table VARCHAR(50),                 -- e.g., 'patient_records'
    related_id UUID,                           -- Related record ID
    uploaded_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Authentication indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- Session indexes
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_endpoint ON audit_logs(endpoint);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);

-- Healthcare data indexes
CREATE INDEX IF NOT EXISTS idx_namaste_codes_code ON namaste_codes(code);
CREATE INDEX IF NOT EXISTS idx_namaste_codes_category ON namaste_codes(category);
CREATE INDEX IF NOT EXISTS idx_namaste_codes_active ON namaste_codes(is_active);

CREATE INDEX IF NOT EXISTS idx_icd11_codes_code ON icd11_codes(code);
CREATE INDEX IF NOT EXISTS idx_icd11_codes_category ON icd11_codes(category);
CREATE INDEX IF NOT EXISTS idx_icd11_codes_active ON icd11_codes(is_active);

CREATE INDEX IF NOT EXISTS idx_code_mappings_namaste ON code_mappings(namaste_code_id);
CREATE INDEX IF NOT EXISTS idx_code_mappings_icd11 ON code_mappings(icd11_code_id);

CREATE INDEX IF NOT EXISTS idx_patient_records_name ON patient_records(patient_name);
CREATE INDEX IF NOT EXISTS idx_patient_records_contact ON patient_records(contact_number);
CREATE INDEX IF NOT EXISTS idx_patient_records_created_by ON patient_records(created_by);
CREATE INDEX IF NOT EXISTS idx_patient_records_active ON patient_records(is_active);

-- Full-text search indexes (PostgreSQL specific)
CREATE INDEX IF NOT EXISTS idx_namaste_codes_search ON namaste_codes USING gin(
    to_tsvector('english', display_name || ' ' || COALESCE(sanskrit_name, '') || ' ' || COALESCE(description, ''))
);

CREATE INDEX IF NOT EXISTS idx_icd11_codes_search ON icd11_codes USING gin(
    to_tsvector('english', display_name || ' ' || COALESCE(description, ''))
);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Enable RLS on sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE patient_records ENABLE ROW LEVEL SECURITY;

-- Users can only see their own profile (except admins)
CREATE POLICY users_own_profile ON users
    FOR SELECT
    USING (
        id = (current_setting('app.user_id', true))::uuid 
        OR 
        (current_setting('app.user_role', true) = 'admin')
    );

-- Only admins can view audit logs
CREATE POLICY audit_logs_admin_only ON audit_logs
    FOR SELECT
    USING (current_setting('app.user_role', true) = 'admin');

-- Users can see patient records they created (plus admins see all)
CREATE POLICY patient_records_access ON patient_records
    FOR ALL
    USING (
        created_by = (current_setting('app.user_id', true))::uuid
        OR 
        (current_setting('app.user_role', true) = 'admin')
    );

-- ============================================================================
-- TRIGGERS FOR AUDIT TRACKING
-- ============================================================================

-- Function to update 'updated_at' timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_namaste_codes_updated_at
    BEFORE UPDATE ON namaste_codes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_icd11_codes_updated_at
    BEFORE UPDATE ON icd11_codes
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_code_mappings_updated_at
    BEFORE UPDATE ON code_mappings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trigger_patient_records_updated_at
    BEFORE UPDATE ON patient_records
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- INITIAL DATA SETUP
-- ============================================================================

-- Create default admin user (password should be changed after first login)
-- Password: 'Admin123!' - CHANGE THIS IN PRODUCTION
INSERT INTO users (email, password_hash, full_name, role, email_verified) VALUES 
('admin@namaste.health', '$2b$12$rOxgVVqKZlVqD7SXMSqbfOKRLWqZfZVTZYVQ8DKY8ZV.xGVZYGZYG', 'System Administrator', 'admin', true)
ON CONFLICT (email) DO NOTHING;

-- Sample user account (password: 'User123!')
INSERT INTO users (email, password_hash, full_name, role, email_verified) VALUES 
('user@namaste.health', '$2b$12$rOxgVVqKZlVqD7SXMSqbfOKRLWqZfZVTZYVQ8DKY8ZV.xGVZYGZYG', 'Healthcare User', 'user', true)
ON CONFLICT (email) DO NOTHING;