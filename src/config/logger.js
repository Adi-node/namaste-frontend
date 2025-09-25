import winston from 'winston';
import path from 'path';
import fs from 'fs';
import config from './config.js';

// Ensure logs directory exists
const logsDir = path.dirname(config.logging.file);
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for log entries
const logFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss.SSS'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
        let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
        
        // Add stack trace for errors
        if (stack) {
            log += `\n${stack}`;
        }
        
        // Add metadata if present
        if (Object.keys(meta).length > 0) {
            log += `\n${JSON.stringify(meta, null, 2)}`;
        }
        
        return log;
    })
);

// Console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({
        format: 'HH:mm:ss'
    }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        let log = `${timestamp} ${level}: ${message}`;
        
        if (Object.keys(meta).length > 0 && config.server.env === 'development') {
            log += `\n${JSON.stringify(meta, null, 2)}`;
        }
        
        return log;
    })
);

// Main application logger
const logger = winston.createLogger({
    level: config.logging.level,
    format: logFormat,
    defaultMeta: { service: 'namaste-backend' },
    transports: [
        // File transport for all logs
        new winston.transports.File({
            filename: config.logging.file,
            maxsize: 10 * 1024 * 1024, // 10MB
            maxFiles: config.logging.maxFiles,
            tailable: true
        }),
        
        // Separate file for errors only
        new winston.transports.File({
            filename: config.logging.errorFile,
            level: 'error',
            maxsize: 10 * 1024 * 1024,
            maxFiles: 5
        })
    ]
});

// Add console transport for all environments
logger.add(new winston.transports.Console({
    format: consoleFormat,
    level: config.server.env === 'development' ? 'debug' : 'info'
}));

// Separate logger for audit trails
const auditLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { type: 'audit' },
    transports: [
        new winston.transports.Console({ format: consoleFormat })
    ]
});

// Security logger for authentication and authorization events
const securityLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { type: 'security' },
    transports: [
        new winston.transports.Console({ format: consoleFormat })
    ]
});

// Performance logger for monitoring response times
const performanceLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { type: 'performance' },
    transports: [
        new winston.transports.Console({ format: consoleFormat })
    ]
});


// Add file transports only if not in production
if (config.server.env !== 'production') {
    // Ensure logs directory exists for non-production environments
    const logsDir = path.dirname(config.logging.file);
    if (!fs.existsSync(logsDir)) {
        fs.mkdirSync(logsDir, { recursive: true });
    }

    logger.add(new winston.transports.File({
        filename: config.logging.file,
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: config.logging.maxFiles,
        tailable: true
    }));
    logger.add(new winston.transports.File({
        filename: config.logging.errorFile,
        level: 'error',
        maxsize: 10 * 1024 * 1024,
        maxFiles: 5
    }));
    auditLogger.add(new winston.transports.File({
        filename: config.logging.auditFile,
        maxsize: 50 * 1024 * 1024, // 50MB for audit logs
        maxFiles: 10,
        tailable: true
    }));
    securityLogger.add(new winston.transports.File({
        filename: path.join(logsDir, 'security.log'),
        maxsize: 20 * 1024 * 1024, // 20MB
        maxFiles: 5
    }));
    performanceLogger.add(new winston.transports.File({
        filename: path.join(logsDir, 'performance.log'),
        maxsize: 10 * 1024 * 1024,
        maxFiles: 3
    }));
}

// Helper functions for structured logging

// Log authentication events
export const logAuth = (event, userId, details = {}) => {
    securityLogger.info('Authentication Event', {
        event,
        userId,
        timestamp: new Date().toISOString(),
        ...details
    });
};

// Log authorization events
export const logAuthorization = (event, userId, resource, action, allowed, details = {}) => {
    securityLogger.info('Authorization Event', {
        event,
        userId,
        resource,
        action,
        allowed,
        timestamp: new Date().toISOString(),
        ...details
    });
};

// Log audit trail events
export const logAudit = (action, userId, resourceType, resourceId, changes = {}, metadata = {}) => {
    auditLogger.info('User Action', {
        action,
        userId,
        resourceType,
        resourceId,
        changes,
        metadata,
        timestamp: new Date().toISOString()
    });
};

// Log performance metrics
export const logPerformance = (endpoint, method, responseTime, statusCode, userId = null) => {
    performanceLogger.info('API Performance', {
        endpoint,
        method,
        responseTime,
        statusCode,
        userId,
        timestamp: new Date().toISOString()
    });
};

// Log database operations
export const logDatabase = (operation, table, duration, recordsAffected, error = null) => {
    const logData = {
        operation,
        table,
        duration,
        recordsAffected,
        timestamp: new Date().toISOString()
    };
    
    if (error) {
        logData.error = error.message;
        logger.error('Database Operation Failed', logData);
    } else {
        logger.debug('Database Operation', logData);
    }
};

// Log file operations
export const logFileOperation = (operation, filename, userId, size = null, error = null) => {
    const logData = {
        operation,
        filename,
        userId,
        size,
        timestamp: new Date().toISOString()
    };
    
    if (error) {
        logData.error = error.message;
        logger.error('File Operation Failed', logData);
    } else {
        logger.info('File Operation', logData);
    }
};

// Log system events
export const logSystem = (event, details = {}) => {
    logger.info('System Event', {
        event,
        ...details,
        timestamp: new Date().toISOString()
    });
};

// Log security incidents
export const logSecurityIncident = (incident, severity, userId = null, details = {}) => {
    securityLogger.error('Security Incident', {
        incident,
        severity,
        userId,
        ...details,
        timestamp: new Date().toISOString()
    });
    
    // Also log to main logger for immediate attention
    logger.error('SECURITY INCIDENT', { incident, severity, userId, ...details });
};

// Error logging helper with context
export const logError = (error, context = {}) => {
    logger.error('Application Error', {
        message: error.message,
        stack: error.stack,
        ...context,
        timestamp: new Date().toISOString()
    });
};

// Request logging helper
export const logRequest = (req, res, responseTime) => {
    const logData = {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        responseTime,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        userId: req.user?.id || null,
        timestamp: new Date().toISOString()
    };
    
    // Log different levels based on status code
    if (res.statusCode >= 500) {
        logger.error('HTTP Request Error', logData);
    } else if (res.statusCode >= 400) {
        logger.warn('HTTP Request Warning', logData);
    } else {
        logger.info('HTTP Request', logData);
    }
};

// Health check logging
export const logHealthCheck = (component, status, responseTime, details = {}) => {
    logger.info('Health Check', {
        component,
        status,
        responseTime,
        ...details,
        timestamp: new Date().toISOString()
    });
};

// Cleanup old log files
export const cleanupLogs = () => {
    const retentionDays = config.logging.auditRetentionDays;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
    
    logger.info('Log Cleanup', {
        retentionDays,
        cutoffDate: cutoffDate.toISOString(),
        message: 'Starting log cleanup process'
    });
    
    // Note: Winston handles file rotation automatically
    // This is a placeholder for any custom cleanup logic
};

// Graceful shutdown
export const closeLoggers = () => {
    return new Promise((resolve) => {
        logger.end();
        auditLogger.end();
        securityLogger.end();
        performanceLogger.end();
        setTimeout(resolve, 100); // Give loggers time to finish writing
    });
};

// Export the main logger and specialized loggers
export {
    logger as default,
    auditLogger,
    securityLogger,
    performanceLogger
};