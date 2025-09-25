import { getSupabaseClient, getSupabaseServiceClient } from '../config/database.js';
import { 
    generateToken, 
    generateRefreshToken, 
    hashPassword, 
    verifyPassword,
    isPasswordStrong,
    getClientIP,
    isAccountLocked,
    calculateLockoutTime
} from '../utils/auth.js';
import { logAuth, logError } from '../config/logger.js';
import { auditLogin, auditLogout } from '../middleware/audit.js';
import Joi from 'joi';

// Validation schemas
const registerSchema = Joi.object({
    email: Joi.string().email().required().messages({
        'string.email': 'Please provide a valid email address',
        'any.required': 'Email is required'
    }),
    password: Joi.string().min(8).required().messages({
        'string.min': 'Password must be at least 8 characters long',
        'any.required': 'Password is required'
    }),
    fullName: Joi.string().min(2).max(100).required().messages({
        'string.min': 'Full name must be at least 2 characters',
        'string.max': 'Full name cannot exceed 100 characters',
        'any.required': 'Full name is required'
    }),
    role: Joi.string().valid('user', 'admin').default('user')
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const changePasswordSchema = Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(8).required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required().messages({
        'any.only': 'Password confirmation does not match new password'
    })
});

// Register new user
export const register = async (req, res) => {
    try {
        // Validate input
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                message: error.details[0].message
            });
        }

        const { email, password, fullName, role } = value;

        // Check password strength
        if (!isPasswordStrong(password)) {
            return res.status(400).json({
                error: 'Weak password',
                message: 'Password must contain at least 8 characters with uppercase, lowercase, number, and special character'
            });
        }

        const supabase = getSupabaseServiceClient();

        // Check if user already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email.toLowerCase())
            .single();

        if (existingUser) {
            logAuth('REGISTRATION_FAILED', null, {
                reason: 'Email already exists',
                email,
                ip: getClientIP(req)
            });

            return res.status(409).json({
                error: 'Email already registered',
                message: 'An account with this email address already exists'
            });
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Create user
        const { data: newUser, error: createError } = await supabase
            .from('users')
            .insert([{
                email: email.toLowerCase(),
                password_hash: passwordHash,
                full_name: fullName,
                role,
                email_verified: false // In production, require email verification
            }])
            .select()
            .single();

        if (createError) {
            logError(createError, { context: 'register', email });
            return res.status(500).json({
                error: 'Registration failed',
                message: 'Unable to create user account'
            });
        }

        // Generate tokens
        const token = generateToken(newUser);
        const refreshToken = generateRefreshToken(newUser);

        logAuth('REGISTRATION_SUCCESS', newUser.id, {
            email: newUser.email,
            role: newUser.role,
            ip: getClientIP(req)
        });

        res.status(201).json({
            message: 'Registration successful',
            user: {
                id: newUser.id,
                email: newUser.email,
                fullName: newUser.full_name,
                role: newUser.role,
                emailVerified: newUser.email_verified
            },
            token,
            refreshToken
        });

    } catch (error) {
        logError(error, { context: 'register', body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Registration failed due to server error'
        });
    }
};

// User login
export const login = async (req, res) => {
    try {
        // Validate input
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            await auditLogin(req.body.email || 'unknown', false, 'Invalid input format', req);
            return res.status(400).json({
                error: 'Validation failed',
                message: error.details[0].message
            });
        }

        const { email, password } = value;
        const supabase = getSupabaseServiceClient();

        // Find user
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('email', email.toLowerCase())
            .single();

        if (userError || !user) {
            await auditLogin(email, false, 'User not found', req);
            return res.status(401).json({
                error: 'Invalid credentials',
                message: 'Email or password is incorrect'
            });
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            await auditLogin(email, false, 'Account locked', req);
            return res.status(423).json({
                error: 'Account locked',
                message: 'Account is temporarily locked due to multiple failed login attempts',
                lockedUntil: user.locked_until
            });
        }

        // Check if account is active
        if (!user.is_active) {
            await auditLogin(email, false, 'Account inactive', req);
            return res.status(403).json({
                error: 'Account inactive',
                message: 'Your account has been deactivated. Please contact support.'
            });
        }

        // Verify password
        const isPasswordValid = await verifyPassword(password, user.password_hash);

        if (!isPasswordValid) {
            // Increment failed login attempts
            const failedAttempts = (user.failed_login_attempts || 0) + 1;
            const lockedUntil = calculateLockoutTime(failedAttempts);

            await supabase
                .from('users')
                .update({
                    failed_login_attempts: failedAttempts,
                    locked_until: lockedUntil
                })
                .eq('id', user.id);

            await auditLogin(email, false, 'Invalid password', req);

            if (lockedUntil) {
                return res.status(423).json({
                    error: 'Account locked',
                    message: `Too many failed login attempts. Account locked until ${lockedUntil}`,
                    lockedUntil
                });
            }

            return res.status(401).json({
                error: 'Invalid credentials',
                message: 'Email or password is incorrect'
            });
        }

        // Successful login - reset failed attempts and update last login
        await supabase
            .from('users')
            .update({
                failed_login_attempts: 0,
                locked_until: null,
                last_login: new Date().toISOString()
            })
            .eq('id', user.id);

        // Generate tokens
        const token = generateToken(user);
        const refreshToken = generateRefreshToken(user);

        await auditLogin(email, true, 'Login successful', req);

        logAuth('LOGIN_SUCCESS', user.id, {
            email: user.email,
            role: user.role,
            ip: getClientIP(req),
            userAgent: req.get('User-Agent')
        });

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                emailVerified: user.email_verified
            },
            token,
            refreshToken
        });

    } catch (error) {
        logError(error, { context: 'login', email: req.body.email });
        await auditLogin(req.body.email || 'unknown', false, 'Server error', req);
        
        res.status(500).json({
            error: 'Internal server error',
            message: 'Login failed due to server error'
        });
    }
};

// User logout
export const logout = async (req, res) => {
    try {
        await auditLogout(req.user.id, req);
        
        logAuth('LOGOUT', req.user.id, {
            ip: getClientIP(req),
            userAgent: req.get('User-Agent')
        });

        res.json({
            message: 'Logout successful'
        });
    } catch (error) {
        logError(error, { context: 'logout', userId: req.user.id });
        res.status(500).json({
            error: 'Logout failed',
            message: 'Unable to complete logout'
        });
    }
};

// Refresh token
export const refreshToken = async (req, res) => {
    try {
        const userId = req.refreshTokenData.id;
        const supabase = getSupabaseServiceClient();

        // Get current user data
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .eq('is_active', true)
            .single();

        if (error || !user) {
            logAuth('REFRESH_TOKEN_FAILED', userId, {
                reason: 'User not found or inactive',
                ip: getClientIP(req)
            });

            return res.status(401).json({
                error: 'Invalid refresh token',
                message: 'Unable to refresh authentication token'
            });
        }

        // Generate new tokens
        const newToken = generateToken(user);
        const newRefreshToken = generateRefreshToken(user);

        logAuth('REFRESH_TOKEN_SUCCESS', user.id, {
            ip: getClientIP(req)
        });

        res.json({
            message: 'Token refreshed successfully',
            token: newToken,
            refreshToken: newRefreshToken
        });

    } catch (error) {
        logError(error, { context: 'refreshToken' });
        res.status(500).json({
            error: 'Token refresh failed',
            message: 'Unable to refresh authentication token'
        });
    }
};

// Get current user profile
export const getProfile = async (req, res) => {
    try {
        const supabase = getSupabaseClient();
        
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, full_name, role, is_active, email_verified, created_at, last_login')
            .eq('id', req.user.id)
            .single();

        if (error || !user) {
            return res.status(404).json({
                error: 'User not found',
                message: 'Unable to retrieve user profile'
            });
        }

        res.json({
            user: {
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                isActive: user.is_active,
                emailVerified: user.email_verified,
                createdAt: user.created_at,
                lastLogin: user.last_login
            }
        });

    } catch (error) {
        logError(error, { context: 'getProfile', userId: req.user.id });
        res.status(500).json({
            error: 'Profile retrieval failed',
            message: 'Unable to retrieve user profile'
        });
    }
};

// Update user profile
export const updateProfile = async (req, res) => {
    try {
        const { fullName } = req.body;

        if (!fullName || fullName.trim().length < 2) {
            return res.status(400).json({
                error: 'Invalid input',
                message: 'Full name must be at least 2 characters long'
            });
        }

        const supabase = getSupabaseServiceClient();

        const { data: updatedUser, error } = await supabase
            .from('users')
            .update({
                full_name: fullName.trim(),
                updated_at: new Date().toISOString()
            })
            .eq('id', req.user.id)
            .select('id, email, full_name, role, email_verified')
            .single();

        if (error) {
            logError(error, { context: 'updateProfile', userId: req.user.id });
            return res.status(500).json({
                error: 'Profile update failed',
                message: 'Unable to update user profile'
            });
        }

        logAuth('PROFILE_UPDATED', req.user.id, {
            ip: getClientIP(req),
            changes: { fullName }
        });

        res.json({
            message: 'Profile updated successfully',
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                fullName: updatedUser.full_name,
                role: updatedUser.role,
                emailVerified: updatedUser.email_verified
            }
        });

    } catch (error) {
        logError(error, { context: 'updateProfile', userId: req.user.id });
        res.status(500).json({
            error: 'Profile update failed',
            message: 'Unable to update user profile'
        });
    }
};

// Change password
export const changePassword = async (req, res) => {
    try {
        // Validate input
        const { error, value } = changePasswordSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                message: error.details[0].message
            });
        }

        const { currentPassword, newPassword } = value;

        // Check new password strength
        if (!isPasswordStrong(newPassword)) {
            return res.status(400).json({
                error: 'Weak password',
                message: 'New password must contain at least 8 characters with uppercase, lowercase, number, and special character'
            });
        }

        const supabase = getSupabaseServiceClient();

        // Get current user
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('password_hash')
            .eq('id', req.user.id)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                error: 'User not found',
                message: 'Unable to verify current user'
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await verifyPassword(currentPassword, user.password_hash);

        if (!isCurrentPasswordValid) {
            logAuth('PASSWORD_CHANGE_FAILED', req.user.id, {
                reason: 'Invalid current password',
                ip: getClientIP(req)
            });

            return res.status(401).json({
                error: 'Invalid password',
                message: 'Current password is incorrect'
            });
        }

        // Hash new password
        const newPasswordHash = await hashPassword(newPassword);

        // Update password
        const { error: updateError } = await supabase
            .from('users')
            .update({
                password_hash: newPasswordHash,
                updated_at: new Date().toISOString()
            })
            .eq('id', req.user.id);

        if (updateError) {
            logError(updateError, { context: 'changePassword', userId: req.user.id });
            return res.status(500).json({
                error: 'Password change failed',
                message: 'Unable to update password'
            });
        }

        logAuth('PASSWORD_CHANGED', req.user.id, {
            ip: getClientIP(req),
            userAgent: req.get('User-Agent')
        });

        res.json({
            message: 'Password changed successfully'
        });

    } catch (error) {
        logError(error, { context: 'changePassword', userId: req.user.id });
        res.status(500).json({
            error: 'Password change failed',
            message: 'Unable to change password due to server error'
        });
    }
};

export default {
    register,
    login,
    logout,
    refreshToken,
    getProfile,
    updateProfile,
    changePassword
};