import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import config from '../config/config.js';
import { logSecurityIncident, logSystem } from '../config/logger.js';
import { getClientIP } from '../utils/auth.js';

// CORS configuration
export const corsMiddleware = cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);

        const allowedOrigins = config.server.corsOrigin.split(',').map(o => o.trim());
        
        if (allowedOrigins.includes(origin) || config.server.env === 'development') {
            callback(null, true);
        } else {
            logSecurityIncident('CORS_VIOLATION', 'medium', null, {
                origin,
                allowedOrigins,
                userAgent: 'Unknown' // Will be updated in middleware
            });
            
            callback(new Error('CORS policy violation'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Origin',
        'X-Requested-With', 
        'Content-Type',
        'Accept',
        'Authorization',
        'Cache-Control',
        'X-HTTP-Method-Override'
    ]
});

// Security headers using Helmet
export const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", config.database.url],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: config.security.hstsMaxAge,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});

// General API rate limiting
export const generalRateLimit = rateLimit({
    windowMs: config.rateLimiting.windowMs,
    max: config.rateLimiting.max,
    message: {
        error: 'Too many requests',
        message: `Rate limit exceeded. Try again in ${config.rateLimiting.windowMs / 60000} minutes.`,
        retryAfter: Math.ceil(config.rateLimiting.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return getClientIP(req) + ':' + (req.user?.id || 'anonymous');
    },
    handler: (req, res) => {
        const clientIP = getClientIP(req);
        const userId = req.user?.id || null;

        logSecurityIncident('RATE_LIMIT_EXCEEDED', 'medium', userId, {
            ip: clientIP,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            method: req.method,
            limit: config.rateLimiting.max,
            window: config.rateLimiting.windowMs
        });

        res.status(429).json({
            error: 'Too many requests',
            message: `Rate limit exceeded. Try again in ${config.rateLimiting.windowMs / 60000} minutes.`,
            retryAfter: Math.ceil(config.rateLimiting.windowMs / 1000)
        });
    }
});

// Strict rate limiting for authentication endpoints
export const authRateLimit = rateLimit({
    windowMs: config.rateLimiting.loginWindowMs,
    max: config.rateLimiting.loginMax,
    message: {
        error: 'Too many login attempts',
        message: `Too many login attempts. Try again in ${config.rateLimiting.loginWindowMs / 60000} minutes.`,
        retryAfter: Math.ceil(config.rateLimiting.loginWindowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
        return getClientIP(req);
    },
    handler: (req, res) => {
        const clientIP = getClientIP(req);

        logSecurityIncident('AUTH_RATE_LIMIT_EXCEEDED', 'high', null, {
            ip: clientIP,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            method: req.method,
            attemptedEmail: req.body?.email,
            limit: config.rateLimiting.loginMax,
            window: config.rateLimiting.loginWindowMs
        });

        res.status(429).json({
            error: 'Too many login attempts',
            message: `Too many login attempts from this IP. Try again in ${config.rateLimiting.loginWindowMs / 60000} minutes.`,
            retryAfter: Math.ceil(config.rateLimiting.loginWindowMs / 1000)
        });
    }
});

// Admin endpoints rate limiting (more restrictive)
export const adminRateLimit = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 50, // 50 requests per 10 minutes for admin operations
    message: {
        error: 'Admin rate limit exceeded',
        message: 'Too many admin operations. Try again in 10 minutes.',
        retryAfter: 600
    },
    keyGenerator: (req) => {
        return 'admin:' + getClientIP(req) + ':' + (req.user?.id || 'unknown');
    },
    handler: (req, res) => {
        logSecurityIncident('ADMIN_RATE_LIMIT_EXCEEDED', 'high', req.user?.id, {
            ip: getClientIP(req),
            endpoint: req.originalUrl,
            method: req.method
        });

        res.status(429).json({
            error: 'Admin rate limit exceeded',
            message: 'Too many admin operations. Try again in 10 minutes.'
        });
    }
});

// File upload rate limiting
export const uploadRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 file uploads per 15 minutes
    message: {
        error: 'Upload rate limit exceeded',
        message: 'Too many file uploads. Try again in 15 minutes.',
        retryAfter: 900
    },
    keyGenerator: (req) => {
        return 'upload:' + getClientIP(req) + ':' + (req.user?.id || 'anonymous');
    }
});

// Request size limiting middleware
export const requestSizeLimit = (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const maxSize = config.fileUpload.maxFileSize;

    if (contentLength > maxSize) {
        logSecurityIncident('REQUEST_SIZE_EXCEEDED', 'medium', req.user?.id, {
            ip: getClientIP(req),
            contentLength,
            maxSize,
            endpoint: req.originalUrl
        });

        return res.status(413).json({
            error: 'Request too large',
            message: `Request size ${contentLength} bytes exceeds maximum allowed ${maxSize} bytes`
        });
    }

    next();
};

// IP whitelist middleware (for production environments)
export const ipWhitelist = (allowedIPs = []) => {
    return (req, res, next) => {
        if (allowedIPs.length === 0) {
            return next(); // Skip if no whitelist configured
        }

        const clientIP = getClientIP(req);
        
        if (!allowedIPs.includes(clientIP)) {
            logSecurityIncident('IP_BLOCKED', 'high', req.user?.id, {
                ip: clientIP,
                allowedIPs: allowedIPs.length,
                endpoint: req.originalUrl
            });

            return res.status(403).json({
                error: 'Access denied',
                message: 'Your IP address is not allowed to access this resource'
            });
        }

        next();
    };
};

// Suspicious activity detection middleware
export const suspiciousActivityDetector = (req, res, next) => {
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent') || '';
    const endpoint = req.originalUrl;

    // Common attack patterns
    const suspiciousPatterns = [
        /[<>'"]/,  // XSS attempt
        /(\bor\b|\band\b).*[=<>]/i, // SQL injection
        /\.\./,    // Directory traversal
        /__proto__|constructor|prototype/i, // Prototype pollution
        /eval\(|function\(|javascript:/i, // Code injection
    ];

    // Check URL and query parameters
    const urlToCheck = decodeURIComponent(endpoint + '?' + new URLSearchParams(req.query).toString());
    const bodyToCheck = req.body ? JSON.stringify(req.body) : '';

    const isSuspicious = suspiciousPatterns.some(pattern =>
        pattern.test(urlToCheck) || pattern.test(bodyToCheck)
    );

    if (isSuspicious) {
        logSecurityIncident('SUSPICIOUS_REQUEST_PATTERN', 'high', req.user?.id, {
            ip: clientIP,
            userAgent,
            endpoint,
            method: req.method,
            query: req.query,
            bodyExists: !!req.body,
            suspiciousContent: urlToCheck.substring(0, 200) // First 200 chars
        });

        // Log but don't block in development
        if (config.server.env === 'production') {
            return res.status(400).json({
                error: 'Invalid request',
                message: 'Request contains suspicious content'
            });
        }
    }

    next();
};

// Trust proxy setup for production
export const trustProxySetup = (app) => {
    if (config.security.trustProxy) {
        app.set('trust proxy', 1); // Trust first proxy
        logSystem('Trust proxy enabled for production environment');
    }
};

// Security middleware logger
export const securityLogger = (req, res, next) => {
    const securityHeaders = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    };

    // Add security headers
    Object.entries(securityHeaders).forEach(([key, value]) => {
        res.setHeader(key, value);
    });

    next();
};

export default {
    corsMiddleware,
    securityHeaders,
    generalRateLimit,
    authRateLimit,
    adminRateLimit,
    uploadRateLimit,
    requestSizeLimit,
    ipWhitelist,
    suspiciousActivityDetector,
    trustProxySetup,
    securityLogger
};