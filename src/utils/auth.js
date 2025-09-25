import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import config from '../config/config.js';
import { logAuth, logSecurityIncident, logError } from '../config/logger.js';

// Generate JWT token with user payload
export const generateToken = (user) => {
    try {
        const payload = {
            id: user.id,
            email: user.email,
            role: user.role,
            fullName: user.full_name,
            isActive: user.is_active,
            emailVerified: user.email_verified,
            tokenId: uuidv4() // Unique token identifier
        };

        const token = jwt.sign(payload, config.auth.jwtSecret, {
            expiresIn: config.auth.jwtExpiresIn,
            issuer: 'namaste-backend',
            audience: 'namaste-frontend'
        });

        logAuth('TOKEN_GENERATED', user.id, {
            tokenId: payload.tokenId,
            expiresIn: config.auth.jwtExpiresIn
        });

        return token;
    } catch (error) {
        logError(error, { context: 'generateToken', userId: user.id });
        throw new Error('Failed to generate authentication token');
    }
};

// Generate refresh token
export const generateRefreshToken = (user) => {
    try {
        const payload = {
            id: user.id,
            email: user.email,
            tokenId: uuidv4(),
            type: 'refresh'
        };

        const refreshToken = jwt.sign(payload, config.auth.refreshTokenSecret, {
            expiresIn: config.auth.refreshTokenExpiresIn,
            issuer: 'namaste-backend',
            audience: 'namaste-frontend'
        });

        logAuth('REFRESH_TOKEN_GENERATED', user.id, {
            tokenId: payload.tokenId,
            expiresIn: config.auth.refreshTokenExpiresIn
        });

        return refreshToken;
    } catch (error) {
        logError(error, { context: 'generateRefreshToken', userId: user.id });
        throw new Error('Failed to generate refresh token');
    }
};

// Verify JWT token
export const verifyToken = (token) => {
    try {
        const decoded = jwt.verify(token, config.auth.jwtSecret, {
            issuer: 'namaste-backend',
            audience: 'namaste-frontend'
        });

        // Check if token is not expired
        if (decoded.exp && decoded.exp < Date.now() / 1000) {
            throw new Error('Token has expired');
        }

        return decoded;
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('Token has expired');
        } else if (error.name === 'JsonWebTokenError') {
            throw new Error('Invalid token');
        } else if (error.name === 'NotBeforeError') {
            throw new Error('Token not active yet');
        } else {
            logError(error, { context: 'verifyToken' });
            throw new Error('Token verification failed');
        }
    }
};

// Verify refresh token
export const verifyRefreshToken = (token) => {
    try {
        const decoded = jwt.verify(token, config.auth.refreshTokenSecret, {
            issuer: 'namaste-backend',
            audience: 'namaste-frontend'
        });

        if (decoded.type !== 'refresh') {
            throw new Error('Invalid refresh token type');
        }

        return decoded;
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            throw new Error('Refresh token has expired');
        } else if (error.name === 'JsonWebTokenError') {
            throw new Error('Invalid refresh token');
        } else {
            logError(error, { context: 'verifyRefreshToken' });
            throw new Error('Refresh token verification failed');
        }
    }
};

// Hash password using bcrypt
export const hashPassword = async (password) => {
    try {
        // Validate password strength
        if (!isPasswordStrong(password)) {
            throw new Error('Password does not meet security requirements');
        }

        const salt = await bcrypt.genSalt(config.auth.bcryptRounds);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        return hashedPassword;
    } catch (error) {
        if (error.message.includes('security requirements')) {
            throw error;
        }
        logError(error, { context: 'hashPassword' });
        throw new Error('Failed to hash password');
    }
};

// Verify password against hash
export const verifyPassword = async (password, hashedPassword) => {
    try {
        const isMatch = await bcrypt.compare(password, hashedPassword);
        return isMatch;
    } catch (error) {
        logError(error, { context: 'verifyPassword' });
        return false;
    }
};

// Check password strength
export const isPasswordStrong = (password) => {
    if (!password || password.length < 8) {
        return false;
    }

    // At least one uppercase letter, one lowercase letter, one number, one special character
    const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    
    return strongPasswordRegex.test(password);
};

// Generate secure random token (for password reset, email verification, etc.)
export const generateSecureToken = (length = 32) => {
    try {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let token = '';
        
        for (let i = 0; i < length; i++) {
            token += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        return token;
    } catch (error) {
        logError(error, { context: 'generateSecureToken' });
        throw new Error('Failed to generate secure token');
    }
};

// Extract token from Authorization header
export const extractTokenFromHeader = (authHeader) => {
    if (!authHeader) {
        return null;
    }

    const parts = authHeader.split(' ');
    
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return null;
    }

    return parts[1];
};

// Check if user account is locked
export const isAccountLocked = (user) => {
    if (!user.locked_until) {
        return false;
    }

    const now = new Date();
    const lockedUntil = new Date(user.locked_until);
    
    return now < lockedUntil;
};

// Calculate account lockout time
export const calculateLockoutTime = (failedAttempts) => {
    if (failedAttempts < config.auth.maxFailedAttempts) {
        return null;
    }

    // Progressive lockout: 15min, 30min, 1hr, 2hr, 24hr
    const lockoutMinutes = [15, 30, 60, 120, 1440];
    const lockoutIndex = Math.min(failedAttempts - config.auth.maxFailedAttempts, lockoutMinutes.length - 1);
    
    const lockoutDuration = lockoutMinutes[lockoutIndex] * 60 * 1000; // Convert to milliseconds
    const lockedUntil = new Date(Date.now() + lockoutDuration);
    
    logSecurityIncident('ACCOUNT_LOCKED', 'medium', null, {
        failedAttempts,
        lockoutDuration: lockoutMinutes[lockoutIndex],
        lockedUntil: lockedUntil.toISOString()
    });
    
    return lockedUntil;
};

// Sanitize user data for token payload
export const sanitizeUserForToken = (user) => {
    return {
        id: user.id,
        email: user.email,
        role: user.role,
        full_name: user.full_name,
        is_active: user.is_active,
        email_verified: user.email_verified
    };
};

// Check if token is close to expiration (within 5 minutes)
export const isTokenNearExpiry = (decoded) => {
    if (!decoded.exp) {
        return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const timeUntilExpiry = decoded.exp - now;
    
    // Return true if token expires within 5 minutes (300 seconds)
    return timeUntilExpiry <= 300;
};

// Generate session fingerprint for additional security
export const generateSessionFingerprint = (req) => {
    const userAgent = req.get('User-Agent') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    
    const fingerprint = `${userAgent}|${acceptLanguage}|${acceptEncoding}`;
    
    return Buffer.from(fingerprint).toString('base64');
};

// Validate session fingerprint
export const validateSessionFingerprint = (req, storedFingerprint) => {
    const currentFingerprint = generateSessionFingerprint(req);
    return currentFingerprint === storedFingerprint;
};

// Get user's IP address (considering proxies)
export const getClientIP = (req) => {
    return req.ip || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress ||
           (req.connection.socket ? req.connection.socket.remoteAddress : null) ||
           '0.0.0.0';
};

// Check for suspicious login patterns
export const detectSuspiciousActivity = (loginHistory) => {
    if (!loginHistory || loginHistory.length < 2) {
        return { suspicious: false };
    }

    const recentLogins = loginHistory.slice(-5); // Last 5 logins
    const ipAddresses = recentLogins.map(login => login.ip_address);
    const userAgents = recentLogins.map(login => login.user_agent);
    
    // Check for multiple IP addresses
    const uniqueIPs = new Set(ipAddresses);
    const multipleIPs = uniqueIPs.size > 3;
    
    // Check for multiple user agents
    const uniqueUserAgents = new Set(userAgents);
    const multipleUserAgents = uniqueUserAgents.size > 2;
    
    // Check for rapid login attempts
    const firstLogin = new Date(recentLogins[0].created_at);
    const lastLogin = new Date(recentLogins[recentLogins.length - 1].created_at);
    const timeDifference = (lastLogin - firstLogin) / 1000 / 60; // Minutes
    const rapidAttempts = timeDifference < 10 && recentLogins.length >= 3;
    
    const suspicious = multipleIPs || multipleUserAgents || rapidAttempts;
    
    if (suspicious) {
        logSecurityIncident('SUSPICIOUS_LOGIN_PATTERN', 'medium', null, {
            multipleIPs,
            multipleUserAgents,
            rapidAttempts,
            uniqueIPCount: uniqueIPs.size,
            uniqueUserAgentCount: uniqueUserAgents.size,
            loginTimeSpan: timeDifference
        });
    }
    
    return {
        suspicious,
        reasons: {
            multipleIPs,
            multipleUserAgents,
            rapidAttempts
        }
    };
};

export default {
    generateToken,
    generateRefreshToken,
    verifyToken,
    verifyRefreshToken,
    hashPassword,
    verifyPassword,
    isPasswordStrong,
    generateSecureToken,
    extractTokenFromHeader,
    isAccountLocked,
    calculateLockoutTime,
    sanitizeUserForToken,
    isTokenNearExpiry,
    generateSessionFingerprint,
    validateSessionFingerprint,
    getClientIP,
    detectSuspiciousActivity
};