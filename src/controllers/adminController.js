import { getSupabaseServiceClient } from '../config/database.js';
import { logAuth, logError } from '../config/logger.js';
import { getClientIP } from '../utils/auth.js';
import config from '../config/config.js';
import Joi from 'joi';

// Validation schemas
const updateUserRoleSchema = Joi.object({
    role: Joi.string().valid('user', 'admin').required()
});

const updateUserStatusSchema = Joi.object({
    isActive: Joi.boolean().required()
});

// Get all users (admin only)
export const getUsers = async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '', role = '' } = req.query;
        const offset = (page - 1) * limit;
        
        const supabase = getSupabaseServiceClient();
        let query = supabase
            .from('users')
            .select('id, email, full_name, role, is_active, email_verified, created_at, last_login, failed_login_attempts', { count: 'exact' });

        // Add search filter
        if (search) {
            query = query.or(`email.ilike.%${search}%,full_name.ilike.%${search}%`);
        }

        // Add role filter
        if (role) {
            query = query.eq('role', role);
        }

        // Add pagination
        query = query.range(offset, offset + limit - 1).order('created_at', { ascending: false });

        const { data: users, error, count } = await query;

        if (error) {
            logError(error, { context: 'getUsers', userId: req.user.id });
            return res.status(500).json({
                error: 'Failed to retrieve users',
                message: 'Unable to fetch user list'
            });
        }

        const totalPages = Math.ceil(count / limit);

        res.json({
            users: users.map(user => ({
                id: user.id,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                isActive: user.is_active,
                emailVerified: user.email_verified,
                createdAt: user.created_at,
                lastLogin: user.last_login,
                failedLoginAttempts: user.failed_login_attempts
            })),
            pagination: {
                currentPage: parseInt(page),
                totalPages,
                totalCount: count,
                limit: parseInt(limit),
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        logError(error, { context: 'getUsers', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to retrieve users'
        });
    }
};

// Get specific user details (admin only)
export const getUserById = async (req, res) => {
    try {
        const { userId } = req.params;

        const supabase = getSupabaseServiceClient();
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, full_name, role, is_active, email_verified, created_at, last_login, failed_login_attempts, locked_until')
            .eq('id', userId)
            .single();

        if (error || !user) {
            return res.status(404).json({
                error: 'User not found',
                message: 'The requested user does not exist'
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
                lastLogin: user.last_login,
                failedLoginAttempts: user.failed_login_attempts,
                lockedUntil: user.locked_until
            }
        });

    } catch (error) {
        logError(error, { context: 'getUserById', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to retrieve user details'
        });
    }
};

// Update user role (admin only)
export const updateUserRole = async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Validate input
        const { error, value } = updateUserRoleSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                message: error.details[0].message
            });
        }

        const { role } = value;

        // Prevent admin from demoting themselves
        if (userId === req.user.id && role !== 'admin') {
            return res.status(400).json({
                error: 'Cannot modify own role',
                message: 'You cannot change your own admin role'
            });
        }

        const supabase = getSupabaseServiceClient();

        // Check if user exists
        const { data: existingUser, error: userError } = await supabase
            .from('users')
            .select('id, email, role')
            .eq('id', userId)
            .single();

        if (userError || !existingUser) {
            return res.status(404).json({
                error: 'User not found',
                message: 'The requested user does not exist'
            });
        }

        // Update user role
        const { data: updatedUser, error: updateError } = await supabase
            .from('users')
            .update({
                role,
                updated_at: new Date().toISOString()
            })
            .eq('id', userId)
            .select('id, email, full_name, role')
            .single();

        if (updateError) {
            logError(updateError, { context: 'updateUserRole', userId: req.user.id, targetUserId: userId });
            return res.status(500).json({
                error: 'Update failed',
                message: 'Unable to update user role'
            });
        }

        logAuth('USER_ROLE_UPDATED', req.user.id, {
            targetUserId: userId,
            oldRole: existingUser.role,
            newRole: role,
            ip: getClientIP(req)
        });

        res.json({
            message: 'User role updated successfully',
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                fullName: updatedUser.full_name,
                role: updatedUser.role
            }
        });

    } catch (error) {
        logError(error, { context: 'updateUserRole', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to update user role'
        });
    }
};

// Update user status (activate/deactivate) - admin only
export const updateUserStatus = async (req, res) => {
    try {
        const { userId } = req.params;
        
        // Validate input
        const { error, value } = updateUserStatusSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation failed',
                message: error.details[0].message
            });
        }

        const { isActive } = value;

        // Prevent admin from deactivating themselves
        if (userId === req.user.id && !isActive) {
            return res.status(400).json({
                error: 'Cannot deactivate own account',
                message: 'You cannot deactivate your own admin account'
            });
        }

        const supabase = getSupabaseServiceClient();

        // Check if user exists
        const { data: existingUser, error: userError } = await supabase
            .from('users')
            .select('id, email, is_active')
            .eq('id', userId)
            .single();

        if (userError || !existingUser) {
            return res.status(404).json({
                error: 'User not found',
                message: 'The requested user does not exist'
            });
        }

        // Update user status
        const { data: updatedUser, error: updateError } = await supabase
            .from('users')
            .update({
                is_active: isActive,
                updated_at: new Date().toISOString()
            })
            .eq('id', userId)
            .select('id, email, full_name, is_active')
            .single();

        if (updateError) {
            logError(updateError, { context: 'updateUserStatus', userId: req.user.id, targetUserId: userId });
            return res.status(500).json({
                error: 'Update failed',
                message: 'Unable to update user status'
            });
        }

        logAuth('USER_STATUS_UPDATED', req.user.id, {
            targetUserId: userId,
            oldStatus: existingUser.is_active,
            newStatus: isActive,
            ip: getClientIP(req)
        });

        res.json({
            message: `User account ${isActive ? 'activated' : 'deactivated'} successfully`,
            user: {
                id: updatedUser.id,
                email: updatedUser.email,
                fullName: updatedUser.full_name,
                isActive: updatedUser.is_active
            }
        });

    } catch (error) {
        logError(error, { context: 'updateUserStatus', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to update user status'
        });
    }
};

// Delete user account (admin only)
export const deleteUser = async (req, res) => {
    try {
        const { userId } = req.params;

        // Prevent admin from deleting themselves
        if (userId === req.user.id) {
            return res.status(400).json({
                error: 'Cannot delete own account',
                message: 'You cannot delete your own admin account'
            });
        }

        const supabase = getSupabaseServiceClient();

        // Check if user exists
        const { data: existingUser, error: userError } = await supabase
            .from('users')
            .select('id, email, full_name')
            .eq('id', userId)
            .single();

        if (userError || !existingUser) {
            return res.status(404).json({
                error: 'User not found',
                message: 'The requested user does not exist'
            });
        }

        // Delete user (this will cascade delete related records due to foreign key constraints)
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('id', userId);

        if (deleteError) {
            logError(deleteError, { context: 'deleteUser', userId: req.user.id, targetUserId: userId });
            return res.status(500).json({
                error: 'Delete failed',
                message: 'Unable to delete user account'
            });
        }

        logAuth('USER_DELETED', req.user.id, {
            deletedUserId: userId,
            deletedUserEmail: existingUser.email,
            ip: getClientIP(req)
        });

        res.json({
            message: 'User account deleted successfully',
            deletedUser: {
                id: existingUser.id,
                email: existingUser.email,
                fullName: existingUser.full_name
            }
        });

    } catch (error) {
        logError(error, { context: 'deleteUser', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to delete user account'
        });
    }
};

// Get audit logs (admin only)
export const getAuditLogs = async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 50, 
            userId = '', 
            action = '', 
            resourceType = '',
            startDate = '',
            endDate = '',
            search = ''
        } = req.query;
        
        const offset = (page - 1) * limit;
        
        const supabase = getSupabaseServiceClient();
        let query = supabase
            .from('audit_logs')
            .select(`
                id,
                user_id,
                action,
                resource_type,
                resource_id,
                ip_address,
                endpoint,
                http_method,
                response_status,
                execution_time,
                error_message,
                timestamp,
                users(email, full_name)
            `, { count: 'exact' });

        // Add filters
        if (userId) {
            query = query.eq('user_id', userId);
        }

        if (action) {
            query = query.eq('action', action);
        }

        if (resourceType) {
            query = query.eq('resource_type', resourceType);
        }

        if (startDate) {
            query = query.gte('timestamp', startDate);
        }

        if (endDate) {
            query = query.lte('timestamp', endDate);
        }

        if (search) {
            query = query.or(`action.ilike.%${search}%,endpoint.ilike.%${search}%,error_message.ilike.%${search}%`);
        }

        // Add pagination and ordering
        query = query.range(offset, offset + limit - 1).order('timestamp', { ascending: false });

        const { data: auditLogs, error, count } = await query;

        if (error) {
            logError(error, { context: 'getAuditLogs', userId: req.user.id });
            return res.status(500).json({
                error: 'Failed to retrieve audit logs',
                message: 'Unable to fetch audit log data'
            });
        }

        const totalPages = Math.ceil(count / limit);

        res.json({
            auditLogs: auditLogs.map(log => ({
                id: log.id,
                userId: log.user_id,
                userEmail: log.users?.email || 'Unknown',
                userFullName: log.users?.full_name || 'Unknown',
                action: log.action,
                resourceType: log.resource_type,
                resourceId: log.resource_id,
                ipAddress: log.ip_address,
                endpoint: log.endpoint,
                httpMethod: log.http_method,
                responseStatus: log.response_status,
                executionTime: log.execution_time,
                errorMessage: log.error_message,
                timestamp: log.timestamp
            })),
            pagination: {
                currentPage: parseInt(page),
                totalPages,
                totalCount: count,
                limit: parseInt(limit),
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        logError(error, { context: 'getAuditLogs', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to retrieve audit logs'
        });
    }
};

// Get audit log statistics (admin only)
export const getAuditStats = async (req, res) => {
    try {
        const supabase = getSupabaseServiceClient();
        
        // Get basic counts
        const { data: totalLogs, error: totalError } = await supabase
            .from('audit_logs')
            .select('id', { count: 'exact', head: true });

        // Get logs from last 24 hours
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        
        const { data: recentLogs, error: recentError } = await supabase
            .from('audit_logs')
            .select('id', { count: 'exact', head: true })
            .gte('timestamp', yesterday.toISOString());

        // Get failed operations
        const { data: failedOps, error: failedError } = await supabase
            .from('audit_logs')
            .select('id', { count: 'exact', head: true })
            .gte('response_status', 400);

        // Get unique users count
        const { data: uniqueUsers, error: usersError } = await supabase
            .from('audit_logs')
            .select('user_id')
            .not('user_id', 'is', null);

        const uniqueUserCount = uniqueUsers ? new Set(uniqueUsers.map(log => log.user_id)).size : 0;

        // Get top actions
        const { data: topActions, error: actionsError } = await supabase
            .from('audit_logs')
            .select('action')
            .order('timestamp', { ascending: false })
            .limit(1000);

        let actionCounts = {};
        if (topActions) {
            topActions.forEach(log => {
                actionCounts[log.action] = (actionCounts[log.action] || 0) + 1;
            });
        }

        const topActionsList = Object.entries(actionCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([action, count]) => ({ action, count }));

        if (totalError || recentError || failedError || usersError) {
            logError(totalError || recentError || failedError || usersError, { 
                context: 'getAuditStats', 
                userId: req.user.id 
            });
            return res.status(500).json({
                error: 'Failed to retrieve audit statistics',
                message: 'Unable to generate audit statistics'
            });
        }

        res.json({
            statistics: {
                totalLogs: totalLogs,
                logsLast24Hours: recentLogs,
                failedOperations: failedOps,
                uniqueUsers: uniqueUserCount,
                topActions: topActionsList
            }
        });

    } catch (error) {
        logError(error, { context: 'getAuditStats', userId: req.user.id });
        res.status(500).json({
            error: 'Internal server error',
            message: 'Failed to retrieve audit statistics'
        });
    }
};

export default {
    getUsers,
    getUserById,
    updateUserRole,
    updateUserStatus,
    deleteUser,
    getAuditLogs,
    getAuditStats
};