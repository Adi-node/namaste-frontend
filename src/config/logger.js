import winston from 'winston';
import path from 'path';
import fs from 'fs';
import config from './config.js';

// Custom format for log entries
const logFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss.SSS'
    }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
        let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
        if (stack) {
            log += `\n${stack}`;
        }
        if (Object.keys(meta).length > 0) {
            log += `\n${JSON.stringify(meta, null, 2)}`;
        }
        return log;
    })
);

// Console format for all environments
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

// --- Logger Initialization ---

const consoleTransport = new winston.transports.Console({
    format: consoleFormat,
    level: config.server.env === 'development' ? 'debug' : 'info'
});

const createLoggerWithOptions = (defaultMeta) => {
    const logger = winston.createLogger({
        level: config.logging.level,
        format: logFormat,
        defaultMeta: { service: 'namaste-backend', ...defaultMeta },
        transports: [consoleTransport]
    });

    // Add file transports only if not in production
    if (config.server.env !== 'production') {
        const logsDir = path.dirname(config.logging.file);
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }

        logger.add(new winston.transports.File({
            filename: config.logging.file,
            maxsize: 10 * 1024 * 1024,
            maxFiles: config.logging.maxFiles,
            tailable: true
        }));
        logger.add(new winston.transports.File({
            filename: config.logging.errorFile,
            level: 'error',
            maxsize: 10 * 1024 * 1024,
            maxFiles: 5
        }));
    }
    return logger;
};

const mainLogger = createLoggerWithOptions({});
const auditLogger = createLoggerWithOptions({ type: 'audit' });
const securityLogger = createLoggerWithOptions({ type: 'security' });
const performanceLogger = createLoggerWithOptions({ type: 'performance' });

// --- Helper Functions ---

export const logAuth = (event, userId, details = {}) => securityLogger.info('Authentication Event', { event, userId, ...details });
export const logAuthorization = (event, userId, resource, action, allowed, details = {}) => securityLogger.info('Authorization Event', { event, userId, resource, action, allowed, ...details });
export const logAudit = (action, userId, resourceType, resourceId, changes = {}, metadata = {}) => auditLogger.info('User Action', { action, userId, resourceType, resourceId, changes, metadata });
export const logPerformance = (endpoint, method, responseTime, statusCode, userId = null) => performanceLogger.info('API Performance', { endpoint, method, responseTime, statusCode, userId });
export const logDatabase = (operation, table, duration, recordsAffected, error = null) => {
    const logData = { operation, table, duration, recordsAffected };
    if (error) mainLogger.error('Database Operation Failed', { ...logData, error: error.message });
    else mainLogger.debug('Database Operation', logData);
};
export const logFileOperation = (operation, filename, userId, size = null, error = null) => {
    const logData = { operation, filename, userId, size };
    if (error) mainLogger.error('File Operation Failed', { ...logData, error: error.message });
    else mainLogger.info('File Operation', logData);
};
export const logSystem = (event, details = {}) => mainLogger.info('System Event', { event, ...details });
export const logSecurityIncident = (incident, severity, userId = null, details = {}) => {
    securityLogger.error('Security Incident', { incident, severity, userId, ...details });
    mainLogger.error('SECURITY INCIDENT', { incident, severity, userId, ...details });
};
export const logError = (error, context = {}) => mainLogger.error('Application Error', { message: error.message, stack: error.stack, ...context });
export const logRequest = (req, res, responseTime) => {
    const logData = { method: req.method, url: req.originalUrl, statusCode: res.statusCode, responseTime, userAgent: req.get('User-Agent'), ip: req.ip, userId: req.user?.id || null };
    if (res.statusCode >= 500) mainLogger.error('HTTP Request Error', logData);
    else if (res.statusCode >= 400) mainLogger.warn('HTTP Request Warning', logData);
    else mainLogger.info('HTTP Request', logData);
};
export const logHealthCheck = (component, status, responseTime, details = {}) => mainLogger.info('Health Check', { component, status, responseTime, ...details });

export const closeLoggers = () => new Promise(resolve => {
    mainLogger.on('finish', () => auditLogger.on('finish', () => securityLogger.on('finish', () => performanceLogger.on('finish', resolve))));
    mainLogger.end();
    auditLogger.end();
    securityLogger.end();
    performanceLogger.end();
});

export {
    mainLogger as default,
    auditLogger,
    securityLogger,
    performanceLogger
};
