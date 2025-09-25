import { getSupabaseServiceClient } from '../config/database.js';
import { logAudit, logError } from '../config/logger.js';
import { getClientIP } from '../utils/auth.js';

// Audit middleware to log all user actions
export const auditLogger = (action, resourceType = null) => {
    return async (req, res, next) => {
        const startTime = Date.now();
        let requestBody = null;
        let oldValues = null;
        let resourceId = null;

        // Capture request body (excluding sensitive data)
        try {
            requestBody = sanitizeRequestBody(req.body);
        } catch (error) {
            // If body parsing fails, continue without it
        }

        // Extract resource ID from various sources
        resourceId = req.params.id || req.params.patientId || req.params.userId || null;

        // For update operations, capture old values
        if (req.method === 'PUT' || req.method === 'PATCH') {
            try {
                oldValues = await captureOldValues(resourceType, resourceId);
            } catch (error) {
                // Continue without old values if capture fails
                logError(error, { context: 'captureOldValues', resourceType, resourceId });
            }
        }

        // Override res.send to capture response and log audit trail
        const originalSend = res.send;
        const originalJson = res.json;

        let responseData = null;
        let isJsonResponse = false;

        res.send = function(body) {
            responseData = body;
            return originalSend.call(this, body);
        };

        res.json = function(obj) {
            responseData = obj;
            isJsonResponse = true;
            return originalJson.call(this, obj);
        };

        // Call next middleware
        next();

        // After response is sent, log the audit trail
        res.on('finish', async () => {
            try {
                const endTime = Date.now();
                const executionTime = endTime - startTime;
                
                // Extract new values from response if it's a create/update operation
                let newValues = null;
                if (isJsonResponse && responseData && typeof responseData === 'object') {
                    newValues = sanitizeResponseBody(responseData);
                }

                // Only log for authenticated users
                if (!req.user) return;

                const auditData = {
                    user_id: req.user.id,
                    session_id: null, // TODO: Implement session tracking
                    action: action || generateActionFromRequest(req),
                    resource_type: resourceType || extractResourceTypeFromPath(req.path),
                    resource_id: resourceId,
                    old_values: oldValues,
                    new_values: newValues,
                    ip_address: getClientIP(req),
                    user_agent: req.get('User-Agent') || null,
                    endpoint: req.originalUrl,
                    http_method: req.method,
                    request_body: requestBody,
                    response_status: res.statusCode,
                    execution_time: executionTime,
                    error_message: res.statusCode >= 400 ? getErrorMessage(responseData) : null,
                    additional_data: {
                        query: req.query,
                        params: req.params,
                        headers: sanitizeHeaders(req.headers),
                        responseSize: getResponseSize(responseData)
                    }
                };

                // Save to database
                await saveAuditLog(auditData);

                // Also log to audit logger
                logAudit(
                    auditData.action,
                    auditData.user_id,
                    auditData.resource_type,
                    auditData.resource_id,
                    { old: oldValues, new: newValues },
                    {
                        endpoint: auditData.endpoint,
                        method: auditData.http_method,
                        status: auditData.response_status,
                        executionTime: auditData.execution_time,
                        ip: auditData.ip_address
                    }
                );

            } catch (error) {
                logError(error, {
                    context: 'auditLogger',
                    userId: req.user?.id,
                    endpoint: req.originalUrl
                });
            }
        });
    };
};

// Save audit log to database
const saveAuditLog = async (auditData) => {
    try {
        const supabase = getSupabaseServiceClient();
        
        const { error } = await supabase
            .from('audit_logs')
            .insert([auditData]);

        if (error) {
            throw error;
        }
    } catch (error) {
        logError(error, { context: 'saveAuditLog', auditData });
        // Don't throw error here to avoid breaking the request flow
    }
};

// Capture old values before update operations
const captureOldValues = async (resourceType, resourceId) => {
    if (!resourceType || !resourceId) return null;

    try {
        const supabase = getSupabaseServiceClient();
        let tableName = '';

        // Map resource types to table names
        switch (resourceType) {
            case 'patient':
            case 'patient_record':
                tableName = 'patient_records';
                break;
            case 'user':
                tableName = 'users';
                break;
            case 'namaste_code':
                tableName = 'namaste_codes';
                break;
            case 'icd11_code':
                tableName = 'icd11_codes';
                break;
            case 'code_mapping':
                tableName = 'code_mappings';
                break;
            default:
                return null;
        }

        const { data, error } = await supabase
            .from(tableName)
            .select('*')
            .eq('id', resourceId)
            .single();

        if (error) {
            return null;
        }

        // Remove sensitive data from old values
        return sanitizeDataForAudit(data);
    } catch (error) {
        return null;
    }
};

// Generate action name from request details
const generateActionFromRequest = (req) => {
    const method = req.method;
    const path = req.path.toLowerCase();

    // Extract action from path and method
    if (method === 'GET' && path.includes('search')) return 'SEARCH';
    if (method === 'GET' && path.includes('export')) return 'EXPORT';
    if (method === 'GET') return 'READ';
    if (method === 'POST' && path.includes('login')) return 'LOGIN';
    if (method === 'POST' && path.includes('logout')) return 'LOGOUT';
    if (method === 'POST' && path.includes('register')) return 'REGISTER';
    if (method === 'POST' && path.includes('upload')) return 'UPLOAD_FILE';
    if (method === 'POST') return 'CREATE';
    if (method === 'PUT' || method === 'PATCH') return 'UPDATE';
    if (method === 'DELETE') return 'DELETE';

    return 'UNKNOWN_ACTION';
};

// Extract resource type from URL path
const extractResourceTypeFromPath = (path) => {
    const pathSegments = path.split('/').filter(segment => segment);
    
    // Common resource patterns
    if (path.includes('/patients')) return 'patient';
    if (path.includes('/users')) return 'user';
    if (path.includes('/codes')) return 'code';
    if (path.includes('/mappings')) return 'mapping';
    if (path.includes('/audit')) return 'audit';
    if (path.includes('/files')) return 'file';
    if (path.includes('/fhir')) return 'fhir_resource';
    
    // Try to extract from path segments
    if (pathSegments.length >= 2) {
        return pathSegments[1]; // Usually the resource type is the second segment
    }
    
    return 'unknown';
};

// Sanitize request body by removing sensitive information
const sanitizeRequestBody = (body) => {
    if (!body || typeof body !== 'object') return body;

    const sensitiveFields = [
        'password',
        'token',
        'refresh_token',
        'authorization',
        'secret',
        'key',
        'hash'
    ];

    const sanitized = { ...body };
    
    for (const field of sensitiveFields) {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    }

    return sanitized;
};

// Sanitize response body
const sanitizeResponseBody = (body) => {
    if (!body || typeof body !== 'object') return body;

    const sensitiveFields = [
        'password_hash',
        'token',
        'refresh_token',
        'secret',
        'hash'
    ];

    let sanitized = { ...body };
    
    // Handle arrays
    if (Array.isArray(sanitized)) {
        sanitized = sanitized.map(item => {
            if (typeof item === 'object') {
                const sanitizedItem = { ...item };
                for (const field of sensitiveFields) {
                    if (sanitizedItem[field]) {
                        sanitizedItem[field] = '[REDACTED]';
                    }
                }
                return sanitizedItem;
            }
            return item;
        });
    } else {
        // Handle single object
        for (const field of sensitiveFields) {
            if (sanitized[field]) {
                sanitized[field] = '[REDACTED]';
            }
        }
    }

    return sanitized;
};

// Sanitize headers by removing sensitive information
const sanitizeHeaders = (headers) => {
    const sensitiveHeaders = [
        'authorization',
        'cookie',
        'x-api-key',
        'x-auth-token'
    ];

    const sanitized = { ...headers };
    
    for (const header of sensitiveHeaders) {
        if (sanitized[header]) {
            sanitized[header] = '[REDACTED]';
        }
    }

    return sanitized;
};

// Sanitize data for audit logging
const sanitizeDataForAudit = (data) => {
    if (!data || typeof data !== 'object') return data;

    const sensitiveFields = [
        'password_hash',
        'token',
        'refresh_token',
        'secret',
        'hash',
        'private_key'
    ];

    const sanitized = { ...data };
    
    for (const field of sensitiveFields) {
        if (sanitized[field]) {
            sanitized[field] = '[REDACTED]';
        }
    }

    return sanitized;
};

// Extract error message from response
const getErrorMessage = (responseData) => {
    if (!responseData) return null;
    
    if (typeof responseData === 'string') return responseData;
    
    if (typeof responseData === 'object') {
        return responseData.error || responseData.message || 'Unknown error';
    }
    
    return null;
};

// Get response size for metrics
const getResponseSize = (data) => {
    if (!data) return 0;
    
    try {
        return Buffer.byteLength(JSON.stringify(data), 'utf8');
    } catch (error) {
        return 0;
    }
};

// Specific audit functions for common operations

// Audit login attempts
export const auditLogin = async (email, success, reason = null, req) => {
    try {
        const auditData = {
            user_id: null, // Will be set if login succeeds
            action: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
            resource_type: 'authentication',
            ip_address: getClientIP(req),
            user_agent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            http_method: req.method,
            response_status: success ? 200 : 401,
            error_message: reason,
            additional_data: {
                email,
                timestamp: new Date().toISOString()
            }
        };

        await saveAuditLog(auditData);
    } catch (error) {
        logError(error, { context: 'auditLogin', email, success });
    }
};

// Audit logout
export const auditLogout = async (userId, req) => {
    try {
        const auditData = {
            user_id: userId,
            action: 'LOGOUT',
            resource_type: 'authentication',
            ip_address: getClientIP(req),
            user_agent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            http_method: req.method,
            response_status: 200,
            additional_data: {
                timestamp: new Date().toISOString()
            }
        };

        await saveAuditLog(auditData);
    } catch (error) {
        logError(error, { context: 'auditLogout', userId });
    }
};

// Audit failed access attempts
export const auditAccessDenied = async (userId, resource, reason, req) => {
    try {
        const auditData = {
            user_id: userId,
            action: 'ACCESS_DENIED',
            resource_type: resource,
            ip_address: getClientIP(req),
            user_agent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            http_method: req.method,
            response_status: 403,
            error_message: reason,
            additional_data: {
                timestamp: new Date().toISOString()
            }
        };

        await saveAuditLog(auditData);
    } catch (error) {
        logError(error, { context: 'auditAccessDenied', userId, resource });
    }
};

export default {
    auditLogger,
    auditLogin,
    auditLogout,
    auditAccessDenied
};