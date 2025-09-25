import { verifyToken, verifyRefreshToken, extractTokenFromHeader, getClientIP } from '../utils/auth.js';
import { logAuth, logSecurityIncident } from '../config/logger.js';
import { getSupabaseClient } from '../config/database.js';

// Authentication middleware - validates JWT token
export const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = extractTokenFromHeader(authHeader);

        if (!token) {
            logAuth('AUTH_FAILED', null, {
                reason: 'No token provided',
                ip: getClientIP(req),
                userAgent: req.get('User-Agent'),
                endpoint: req.originalUrl
            });

            return res.status(401).json({
                error: 'Access denied',
                message: 'Authentication token required'
            });
        }

        // Verify the token
        const decoded = verifyToken(token);

        // Check if user exists and is active in database
        const supabase = getSupabaseClient();
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, role, is_active, email_verified, failed_login_attempts, locked_until')
            .eq('id', decoded.id)
            .eq('is_active', true)
            .single();

        if (error || !user) {
            logAuth('AUTH_FAILED', decoded.id, {
                reason: 'User not found or inactive',
                ip: getClientIP(req),
                error: error?.message
            });

            return res.status(401).json({
                error: 'Access denied',
                message: 'Invalid or expired token'
            });
        }

        // Check if account is locked
        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            logSecurityIncident('LOCKED_ACCOUNT_ACCESS_ATTEMPT', 'high', user.id, {
                ip: getClientIP(req),
                lockedUntil: user.locked_until
            });

            return res.status(423).json({
                error: 'Account locked',
                message: 'Account is temporarily locked due to security reasons',
                lockedUntil: user.locked_until
            });
        }

        // Add user information to request object
        req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            isActive: user.is_active,
            emailVerified: user.email_verified,
            tokenId: decoded.tokenId
        };

        // Update last access time
        await supabase
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id);

        next();
    } catch (error) {
        let reason = 'Token verification failed';
        let statusCode = 401;

        if (error.message.includes('expired')) {
            reason = 'Token expired';
            statusCode = 401;
        } else if (error.message.includes('invalid')) {
            reason = 'Invalid token';
            statusCode = 401;
        }

        logAuth('AUTH_FAILED', null, {
            reason,
            error: error.message,
            ip: getClientIP(req),
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl
        });

        return res.status(statusCode).json({
            error: 'Authentication failed',
            message: reason
        });
    }
};

// Optional authentication middleware (doesn't fail if no token)
export const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = extractTokenFromHeader(authHeader);

        if (!token) {
            req.user = null;
            return next();
        }

        // Try to verify token but don't fail if invalid
        const decoded = verifyToken(token);
        
        const supabase = getSupabaseClient();
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, role, is_active, email_verified')
            .eq('id', decoded.id)
            .eq('is_active', true)
            .single();

        if (!error && user) {
            req.user = {
                id: user.id,
                email: user.email,
                role: user.role,
                isActive: user.is_active,
                emailVerified: user.email_verified
            };
        } else {
            req.user = null;
        }

        next();
    } catch (error) {
        // If token verification fails, just continue without user
        req.user = null;
        next();
    }
};

// Check if user is authenticated (for routes that need authentication)
export const requireAuth = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please log in to access this resource'
        });
    }
    next();
};

// Check if user's email is verified
export const requireEmailVerification = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please log in to access this resource'
        });
    }

    if (!req.user.emailVerified) {
        return res.status(403).json({
            error: 'Email verification required',
            message: 'Please verify your email address to access this resource'
        });
    }

    next();
};

// Check if user account is active
export const requireActiveAccount = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please log in to access this resource'
        });
    }

    if (!req.user.isActive) {
        logSecurityIncident('INACTIVE_ACCOUNT_ACCESS', 'medium', req.user.id, {
            ip: getClientIP(req),
            endpoint: req.originalUrl
        });

        return res.status(403).json({
            error: 'Account inactive',
            message: 'Your account has been deactivated. Please contact support.'
        });
    }

    next();
};

// Refresh token authentication
export const authenticateRefreshToken = (req, res, next) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(401).json({
                error: 'Refresh token required',
                message: 'Please provide a valid refresh token'
            });
        }

        const decoded = verifyRefreshToken(refreshToken);
        req.refreshTokenData = decoded;
        
        next();
    } catch (error) {
        logAuth('REFRESH_TOKEN_FAILED', null, {
            error: error.message,
            ip: getClientIP(req)
        });

        return res.status(401).json({
            error: 'Invalid refresh token',
            message: 'Please log in again to get a new token'
        });
    }
};

export default {
    authenticateToken,
    optionalAuth,
    requireAuth,
    requireEmailVerification,
    requireActiveAccount,
    authenticateRefreshToken
};