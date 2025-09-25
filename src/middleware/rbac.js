import { logAuthorization, logSecurityIncident } from '../config/logger.js';
import { getClientIP } from '../utils/auth.js';

// Role-based access control middleware
export const requireRole = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            logAuthorization('ACCESS_DENIED', null, 'unknown', 'role_check', false, {
                reason: 'No user in request',
                requiredRoles: allowedRoles,
                ip: getClientIP(req),
                endpoint: req.originalUrl
            });

            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please log in to access this resource'
            });
        }

        // Ensure allowedRoles is an array
        const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

        if (!roles.includes(req.user.role)) {
            logAuthorization('ACCESS_DENIED', req.user.id, 'role_check', req.originalUrl, false, {
                userRole: req.user.role,
                requiredRoles: roles,
                ip: getClientIP(req),
                endpoint: req.originalUrl
            });

            // Log potential privilege escalation attempt
            if (req.user.role === 'user' && roles.includes('admin')) {
                logSecurityIncident('PRIVILEGE_ESCALATION_ATTEMPT', 'high', req.user.id, {
                    attemptedRole: 'admin',
                    currentRole: req.user.role,
                    ip: getClientIP(req),
                    endpoint: req.originalUrl,
                    userAgent: req.get('User-Agent')
                });
            }

            return res.status(403).json({
                error: 'Access forbidden',
                message: 'You do not have permission to access this resource'
            });
        }

        logAuthorization('ACCESS_GRANTED', req.user.id, 'role_check', req.originalUrl, true, {
            userRole: req.user.role,
            requiredRoles: roles
        });

        next();
    };
};

// Admin only access
export const requireAdmin = requireRole('admin');

// User or Admin access
export const requireUserOrAdmin = requireRole(['user', 'admin']);

// Owner or Admin access (for resources that belong to specific users)
export const requireOwnerOrAdmin = (getOwnerId) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please log in to access this resource'
            });
        }

        // Admin can access anything
        if (req.user.role === 'admin') {
            logAuthorization('ACCESS_GRANTED', req.user.id, 'owner_check', req.originalUrl, true, {
                reason: 'Admin access',
                ip: getClientIP(req)
            });
            return next();
        }

        try {
            // Get the owner ID of the resource
            const ownerId = await getOwnerId(req);

            if (!ownerId) {
                logAuthorization('ACCESS_DENIED', req.user.id, 'owner_check', req.originalUrl, false, {
                    reason: 'Resource owner not found',
                    ip: getClientIP(req)
                });

                return res.status(404).json({
                    error: 'Resource not found',
                    message: 'The requested resource does not exist'
                });
            }

            if (req.user.id !== ownerId) {
                logAuthorization('ACCESS_DENIED', req.user.id, 'owner_check', req.originalUrl, false, {
                    reason: 'Not resource owner',
                    resourceOwner: ownerId,
                    ip: getClientIP(req)
                });

                return res.status(403).json({
                    error: 'Access forbidden',
                    message: 'You can only access your own resources'
                });
            }

            logAuthorization('ACCESS_GRANTED', req.user.id, 'owner_check', req.originalUrl, true, {
                reason: 'Resource owner',
                resourceOwner: ownerId
            });

            next();
        } catch (error) {
            logAuthorization('ACCESS_ERROR', req.user.id, 'owner_check', req.originalUrl, false, {
                error: error.message,
                ip: getClientIP(req)
            });

            return res.status(500).json({
                error: 'Authorization check failed',
                message: 'Unable to verify resource ownership'
            });
        }
    };
};

// Check specific permissions for granular access control
export const requirePermission = (permission, resource) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please log in to access this resource'
            });
        }

        // Define role-based permissions
        const rolePermissions = {
            admin: {
                users: ['create', 'read', 'update', 'delete'],
                patients: ['create', 'read', 'update', 'delete'],
                codes: ['create', 'read', 'update', 'delete'],
                mappings: ['create', 'read', 'update', 'delete'],
                audit: ['read'],
                files: ['create', 'read', 'update', 'delete'],
                system: ['read', 'update']
            },
            user: {
                patients: ['create', 'read', 'update', 'delete'], // Only their own
                codes: ['read'],
                mappings: ['read'],
                files: ['create', 'read', 'update'], // Only their own
                profile: ['read', 'update'] // Only their own profile
            }
        };

        const userPermissions = rolePermissions[req.user.role] || {};
        const resourcePermissions = userPermissions[resource] || [];

        if (!resourcePermissions.includes(permission)) {
            logAuthorization('PERMISSION_DENIED', req.user.id, resource, permission, false, {
                userRole: req.user.role,
                requiredPermission: permission,
                resource,
                ip: getClientIP(req),
                endpoint: req.originalUrl
            });

            return res.status(403).json({
                error: 'Insufficient permissions',
                message: `You do not have '${permission}' permission for '${resource}'`
            });
        }

        logAuthorization('PERMISSION_GRANTED', req.user.id, resource, permission, true, {
            userRole: req.user.role,
            permission,
            resource
        });

        next();
    };
};

// Rate limiting by role
export const roleBasedRateLimit = (limits) => {
    return (req, res, next) => {
        if (!req.user) {
            return next();
        }

        const userRole = req.user.role;
        const roleLimit = limits[userRole];

        if (roleLimit) {
            // Store rate limit info in request for rate limiting middleware
            req.roleRateLimit = {
                windowMs: roleLimit.windowMs || 15 * 60 * 1000, // 15 minutes default
                max: roleLimit.max || 100, // 100 requests default
                message: roleLimit.message || `Rate limit exceeded for ${userRole} role`
            };
        }

        next();
    };
};

// Conditional access based on user attributes
export const conditionalAccess = (conditions) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please log in to access this resource'
            });
        }

        for (const condition of conditions) {
            const result = condition(req.user, req);
            
            if (!result.allowed) {
                logAuthorization('CONDITIONAL_ACCESS_DENIED', req.user.id, 'condition_check', req.originalUrl, false, {
                    condition: condition.name || 'unknown',
                    reason: result.reason,
                    ip: getClientIP(req)
                });

                return res.status(403).json({
                    error: 'Access denied',
                    message: result.reason || 'Conditional access requirements not met'
                });
            }
        }

        logAuthorization('CONDITIONAL_ACCESS_GRANTED', req.user.id, 'condition_check', req.originalUrl, true, {
            conditionsCount: conditions.length
        });

        next();
    };
};

// Common conditional access functions
export const accessConditions = {
    // Require email verification
    emailVerified: (user) => ({
        allowed: user.emailVerified,
        reason: 'Email verification required'
    }),

    // Require account to be active
    activeAccount: (user) => ({
        allowed: user.isActive,
        reason: 'Account is not active'
    }),

    // Time-based access (e.g., business hours only)
    businessHours: (user, req) => {
        const now = new Date();
        const hour = now.getHours();
        const isBusinessHour = hour >= 9 && hour < 17; // 9 AM to 5 PM
        
        return {
            allowed: isBusinessHour || user.role === 'admin', // Admins can access anytime
            reason: 'Access restricted to business hours (9 AM - 5 PM)'
        };
    },

    // IP-based access restriction
    allowedIPs: (allowedIPs) => (user, req) => {
        const clientIP = getClientIP(req);
        return {
            allowed: allowedIPs.includes(clientIP) || user.role === 'admin',
            reason: 'Access restricted from your IP address'
        };
    }
};

// Security headers middleware based on user role
export const roleBasedSecurityHeaders = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        // More restrictive headers for admin users
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    next();
};

export default {
    requireRole,
    requireAdmin,
    requireUserOrAdmin,
    requireOwnerOrAdmin,
    requirePermission,
    roleBasedRateLimit,
    conditionalAccess,
    accessConditions,
    roleBasedSecurityHeaders
};