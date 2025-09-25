import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'JWT_SECRET'
];

const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
    console.error('❌ Missing required environment variables:', missingEnvVars.join(', '));
    console.log('Please copy .env.template to .env and fill in the required values.');
    process.exit(1);
}

// Application configuration object
const config = {
    // Server configuration
    server: {
        port: parseInt(process.env.PORT) || 3001,
        env: process.env.NODE_ENV || 'development',
        corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173'
    },

    // Database configuration (Supabase)
    database: {
        url: process.env.SUPABASE_URL,
        anonKey: process.env.SUPABASE_ANON_KEY,
        serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        poolMin: parseInt(process.env.DB_POOL_MIN) || 2,
        poolMax: parseInt(process.env.DB_POOL_MAX) || 10
    },

    // Authentication configuration
    auth: {
        jwtSecret: process.env.JWT_SECRET,
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
        refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET + '_refresh',
        refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN || '7d',
        bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
        sessionSecret: process.env.SESSION_SECRET || 'fallback-session-secret',
        maxFailedAttempts: 5,
        lockoutDuration: 15 * 60 * 1000 // 15 minutes in milliseconds
    },

    // Rate limiting configuration
    rateLimiting: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX) || 100, // requests per window
        loginWindowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 5 * 60 * 1000, // 5 minutes
        loginMax: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 5, // login attempts per window
        skipSuccessfulRequests: false,
        skipFailedRequests: false
    },

    // File upload configuration
    fileUpload: {
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
        uploadPath: process.env.UPLOAD_PATH || './uploads',
        allowedMimeTypes: [
            'text/csv',
            'application/json',
            'application/pdf',
            'image/jpeg',
            'image/png',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        ]
    },

    // Logging configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        file: process.env.LOG_FILE || './logs/app.log',
        auditFile: process.env.AUDIT_LOG_FILE || './logs/audit.log',
        errorFile: process.env.ERROR_LOG_FILE || './logs/error.log',
        auditRetentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS) || 365,
        maxFileSize: '10MB',
        maxFiles: 10
    },

    // Security configuration
    security: {
        hstsMaxAge: parseInt(process.env.HSTS_MAX_AGE) || 31536000, // 1 year
        contentSecurityPolicy: process.env.CONTENT_SECURITY_POLICY || "default-src 'self'",
        trustProxy: process.env.NODE_ENV === 'production',
        cookieSecret: process.env.SESSION_SECRET || 'fallback-cookie-secret',
        cookieMaxAge: 24 * 60 * 60 * 1000, // 24 hours
        cookieSecure: process.env.NODE_ENV === 'production',
        cookieHttpOnly: true,
        cookieSameSite: 'strict'
    },

    // FHIR configuration
    fhir: {
        version: 'R4',
        baseUrl: process.env.FHIR_BASE_URL || 'http://localhost:3001/fhir',
        namespaces: {
            namaste: 'http://namaste.health/fhir/CodeSystem/NAMASTE',
            icd11: 'http://id.who.int/icd/release/11/2024-01'
        },
        supportedResources: [
            'CodeSystem',
            'ConceptMap',
            'ValueSet',
            'Bundle',
            'Patient',
            'Condition',
            'Observation'
        ]
    },

    // Health check configuration
    healthCheck: {
        interval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 5 * 60 * 1000, // 5 minutes
        timeout: 5000, // 5 seconds
        endpoints: ['database', 'memory', 'disk']
    },

    // Pagination defaults
    pagination: {
        defaultLimit: 20,
        maxLimit: 100,
        defaultOffset: 0
    },

    // Cache configuration (future enhancement)
    cache: {
        ttl: 5 * 60 * 1000, // 5 minutes
        maxSize: 1000,
        enabled: process.env.CACHE_ENABLED === 'true'
    }
};

// Environment-specific overrides
if (config.server.env === 'production') {
    // Production-specific settings
    config.logging.level = 'warn';
    config.security.trustProxy = true;
    config.security.cookieSecure = true;
} else if (config.server.env === 'development') {
    // Development-specific settings
    config.logging.level = 'debug';
    config.security.cookieSecure = false;
} else if (config.server.env === 'test') {
    // Test-specific settings
    config.logging.level = 'error';
    config.database.poolMin = 1;
    config.database.poolMax = 2;
}

// Validation function for configuration
export const validateConfig = () => {
    const errors = [];

    // Validate JWT secret strength
    if (config.auth.jwtSecret.length < 32) {
        errors.push('JWT_SECRET must be at least 32 characters long');
    }

    // Validate database URL format
    if (!config.database.url.startsWith('http')) {
        errors.push('SUPABASE_URL must be a valid HTTP URL');
    }

    // Validate bcrypt rounds
    if (config.auth.bcryptRounds < 10 || config.auth.bcryptRounds > 15) {
        errors.push('BCRYPT_ROUNDS should be between 10 and 15');
    }

    // Validate rate limiting
    if (config.rateLimiting.max < 10) {
        errors.push('RATE_LIMIT_MAX should be at least 10');
    }

    if (errors.length > 0) {
        console.error('❌ Configuration validation errors:');
        errors.forEach(error => console.error(`  - ${error}`));
        throw new Error('Invalid configuration');
    }

    console.log('✅ Configuration validation passed');
    return true;
};

// Export configuration
export default config;